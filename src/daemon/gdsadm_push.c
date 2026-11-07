/* gdsadm over OPC UA: the Administration Component of OPC 10000-12 (OpenGDS
 * plan, "Manual push now"). It talks to the GDS and to devices only through
 * standard Part 12 methods, as any vendor's admin tool could:
 *
 *   gdsadm apps register --uri URI --name NAME --type Server|Client|ClientAndServer
 *                        [--discovery-url URL]... CONNECTION
 *       RegisterApplication (12 §6.5.5) as DiscoveryAdmin
 *
 *   gdsadm push now URI [--server-url URL] [--server-cert DER]
 *                       [--device-user NAME --device-password-file FILE]
 *                       [--poll-seconds N] CONNECTION
 *       1. FindApplications (§6.5.4): the device's record and DiscoveryUrl
 *       2. GetTrustList (§7.9.8): the trust list the GDS keeps for it
 *       3. connect to the device. It maps gdsadm's certificate to SecurityAdmin
 *          (Annex G.3), or the administrator in --device-user (§7.4). The
 *          device is trusted through the GDS CA, or --server-cert for a device
 *          that still has its first self-signed certificate
 *       4. Update TrustList, then CreateSigningRequest -> StartSigningRequest
 *          and FinishRequest on the GDS as CertificateAuthorityAdmin (§7.9.4,
 *          §7.9.6) -> UpdateCertificate, then ApplyChanges (§7.7.2)
 *       5. check the device now presents the issued certificate
 *
 *   gdsadm apps import FILE [--dry-run] [CONNECTION]
 *       one RegisterApplication per record of a CSV or JSON file
 *       (gdsadm_import.h), with a report line per record. A record whose
 *       ApplicationUri is registered already (Bad_AlreadyExists) is reported
 *       and left as it is, so an import can be run again. --dry-run checks
 *       the file only and needs no CONNECTION.
 *
 *   gdsadm apps unregister URI CONNECTION
 *       UnregisterApplication (§6.5.8) as DiscoveryAdmin; the GDS revokes the
 *       application's certificates
 *
 *   gdsadm certs revoke URI --revoke-cert DER CONNECTION
 *       RevokeCertificate (§7.9.6) as CertificateAuthorityAdmin; the
 *       certificate goes on the CRL of every trust list
 *
 *   CONNECTION: --gds URL --cert DER --key DER --trust DER [--trust DER]...
 *               [--crl DER]... --user NAME --password-file FILE
 *
 * The GDS is trusted only through --trust (no trust on first use). The
 * password is read from a file, never from argv.
 * SPDX-License-Identifier: MPL-2.0 */
#include "gdsadm_push.h"

#include <open62541/nodeids_gds.h>

#include <stdio.h>
#include <string.h>

#include "gds_internal.h" /* gds_validate_record */
#include "gdsadm_import.h"
#include "client/gdsc_gds.h"
#include "client/gdsc_push.h"
#include "client/gdsc_session.h"
#include "common/limits.h"
#include "common/safeint.h"
#include "push/push_workflows.h"
#include "common/banned.h"

#define MAX_FILES 8
#define MAX_URLS 8
#define DEFAULT_POLL_SECONDS 60
#define PRESENT_TIMEOUT_MS 30000u

typedef struct {
    const char *gdsUrl, *certFile, *keyFile, *user, *passwordFile;
    const char *trustFiles[MAX_FILES], *crlFiles[MAX_FILES];
    size_t trustN, crlN;
    /* apps register */
    const char *uri, *name, *type;
    const char *urls[MAX_URLS];
    size_t urlN;
    /* push now */
    const char *serverUrl, *serverCertFile, *deviceUser, *devicePasswordFile;
    long pollSeconds;
    /* certs revoke */
    const char *revokeCertFile;
} adm_args;

typedef struct {
    gds_buf cert, key, password, serverCert, devicePassword;
    gds_buf trust[MAX_FILES + 1], crls[MAX_FILES];
    size_t trustN, crlN;
} adm_files;

static void files_clear(adm_files *f) {
    gds_buf_free(&f->cert);
    gds_buf_free_secret(&f->key);
    gds_buf_free_secret(&f->password);
    gds_buf_free(&f->serverCert);
    gds_buf_free_secret(&f->devicePassword);
    for(size_t i = 0; i < f->trustN; i++)
        gds_buf_free(&f->trust[i]);
    for(size_t i = 0; i < f->crlN; i++)
        gds_buf_free(&f->crls[i]);
}

static bool add_file(const char **arr, size_t *n, const char *v) {
    if(*n >= MAX_FILES)
        return false;
    arr[(*n)++] = v;
    return true;
}

/* One option with a value. false: unknown option or too many values */
static bool parse_opt(adm_args *a, const char *opt, const char *v) {
    const struct {
        const char *name;
        const char **field;
    } single[] = {
        {"--gds", &a->gdsUrl},
        {"--cert", &a->certFile},
        {"--key", &a->keyFile},
        {"--user", &a->user},
        {"--password-file", &a->passwordFile},
        {"--uri", &a->uri},
        {"--name", &a->name},
        {"--type", &a->type},
        {"--server-url", &a->serverUrl},
        {"--server-cert", &a->serverCertFile},
        {"--device-user", &a->deviceUser},
        {"--device-password-file", &a->devicePasswordFile},
        {"--revoke-cert", &a->revokeCertFile},
    };
    for(size_t i = 0; i < GDS_ARRAY_SIZE(single); i++) {
        if(strcmp(opt, single[i].name) == 0) {
            if(*single[i].field)
                return false; /* given twice */
            *single[i].field = v;
            return true;
        }
    }
    if(strcmp(opt, "--trust") == 0)
        return add_file(a->trustFiles, &a->trustN, v);
    if(strcmp(opt, "--crl") == 0)
        return add_file(a->crlFiles, &a->crlN, v);
    if(strcmp(opt, "--discovery-url") == 0 && a->urlN < MAX_URLS) {
        a->urls[a->urlN++] = v;
        return true;
    }
    if(strcmp(opt, "--poll-seconds") == 0)
        return gds_parse_long(v, 0, 3600, &a->pollSeconds);
    return false;
}

static bool parse_args(int argc, char **argv, int first, adm_args *a) {
    memset(a, 0, sizeof(*a));
    a->pollSeconds = DEFAULT_POLL_SECONDS;
    for(int i = first; i < argc; i += 2) {
        if(i + 1 >= argc || !parse_opt(a, argv[i], argv[i + 1])) {
            fprintf(stderr, "gdsadm: bad or repeated option %s\n", argv[i]);
            return false;
        }
    }
    if(!a->gdsUrl || !a->certFile || !a->keyFile || !a->user || !a->passwordFile ||
       a->trustN == 0) {
        fprintf(stderr, "gdsadm: --gds, --cert, --key, --trust, --user and --password-file "
                        "are required\n");
        return false;
    }
    return true;
}

static gds_status read_password(const char *path, gds_buf *out) {
    gds_status s = gds_file_read(path, GDS_MAX_STRING, out);
    while(s == GDS_OK && out->len > 0 &&
          (out->data[out->len - 1] == '\n' || out->data[out->len - 1] == '\r'))
        out->len--;
    if(s == GDS_OK && out->len == 0)
        s = GDS_EINVAL;
    return s;
}

static gds_status load_files(const adm_args *a, adm_files *f) {
    gds_status s;
    if((s = gds_file_read(a->certFile, GDS_MAX_CERT_SIZE, &f->cert)) != GDS_OK ||
       (s = gds_file_read(a->keyFile, GDS_MAX_KEY_SIZE, &f->key)) != GDS_OK ||
       (s = read_password(a->passwordFile, &f->password)) != GDS_OK)
        return s;
    for(size_t i = 0; i < a->trustN; i++, f->trustN++)
        if((s = gds_file_read(a->trustFiles[i], GDS_MAX_CERT_SIZE, &f->trust[i])) != GDS_OK)
            return s;
    for(size_t i = 0; i < a->crlN; i++, f->crlN++)
        if((s = gds_file_read(a->crlFiles[i], GDS_MAX_CRL_SIZE, &f->crls[i])) != GDS_OK)
            return s;
    if(a->serverCertFile &&
       (s = gds_file_read(a->serverCertFile, GDS_MAX_CERT_SIZE, &f->serverCert)) != GDS_OK)
        return s;
    if(a->devicePasswordFile)
        s = read_password(a->devicePasswordFile, &f->devicePassword);
    return s;
}

static gdsc_session_cfg gds_cfg(const adm_args *a, const adm_files *f) {
    gdsc_session_cfg c;
    memset(&c, 0, sizeof(c));
    c.endpointUrl = a->gdsUrl;
    c.applicationUri = NULL; /* the SAN URI of --cert */
    c.cert = &f->cert;
    c.key = &f->key;
    c.trust = f->trust;
    c.trustN = f->trustN;
    c.crls = f->crls;
    c.crlN = f->crlN;
    c.identity = GDSC_IDENTITY_USERNAME;
    c.userName = a->user;
    c.password = &f->password;
    return c;
}

static int report(const char *what, UA_StatusCode r) {
    fprintf(stderr, "gdsadm: %s: %s\n", what, UA_StatusCode_name(r));
    return 1;
}

static int reportg(const char *what, gds_status s) {
    fprintf(stderr, "gdsadm: %s: %s\n", what, gds_status_name(s));
    return 1;
}

/* Open a GDS session and bind the GDS namespace */
static int open_gds(const adm_args *a, adm_files *f, gdsc_session **gds, UA_UInt16 *ns) {
    gds_status s = load_files(a, f);
    if(s != GDS_OK)
        return reportg("reading the certificate, key, password or trust files", s);
    gdsc_session_cfg c = gds_cfg(a, f);
    UA_StatusCode r = gdsc_session_open(&c, gds);
    if(r != UA_STATUSCODE_GOOD)
        return report("connect to the GDS", r);
    r = gdsc_gds_bind(gdsc_session_client(*gds), ns);
    if(r != UA_STATUSCODE_GOOD)
        return report("GDS namespace", r);
    return 0;
}

/* ---- apps register ---- */

static bool parse_type(const char *t, UA_ApplicationType *out) {
    if(!t)
        return false;
    if(strcmp(t, "Server") == 0)
        *out = UA_APPLICATIONTYPE_SERVER;
    else if(strcmp(t, "Client") == 0)
        *out = UA_APPLICATIONTYPE_CLIENT;
    else if(strcmp(t, "ClientAndServer") == 0)
        *out = UA_APPLICATIONTYPE_CLIENTANDSERVER;
    else
        return false;
    return true;
}

int gdsadm_apps_register(int argc, char **argv) {
    adm_args a;
    UA_ApplicationType type = UA_APPLICATIONTYPE_SERVER;
    if(!parse_args(argc, argv, 3, &a) || !a.uri || !a.name || !parse_type(a.type, &type)) {
        fprintf(stderr, "usage: gdsadm apps register --uri URI --name NAME --type "
                        "Server|Client|ClientAndServer [--discovery-url URL]... CONNECTION\n");
        return 2;
    }
    adm_files f;
    memset(&f, 0, sizeof(f));
    gdsc_session *gds = NULL;
    UA_UInt16 ns = 0;
    int rc = open_gds(&a, &f, &gds, &ns);
    if(rc == 0) {
        UA_String urls[MAX_URLS];
        for(size_t i = 0; i < a.urlN; i++)
            urls[i] = UA_STRING((char *)(uintptr_t)a.urls[i]);
        UA_LocalizedText name = UA_LOCALIZEDTEXT("en", (char *)(uintptr_t)a.name);
        UA_ApplicationRecordDataType rec;
        UA_ApplicationRecordDataType_init(&rec);
        rec.applicationUri = UA_STRING((char *)(uintptr_t)a.uri);
        rec.applicationType = type;
        rec.applicationNames = &name;
        rec.applicationNamesSize = 1;
        rec.productUri = UA_STRING((char *)(uintptr_t)a.uri);
        rec.discoveryUrls = a.urlN ? urls : NULL;
        rec.discoveryUrlsSize = a.urlN;
        UA_NodeId id;
        UA_StatusCode r = gdsc_register_application(gdsc_session_client(gds), ns, &rec, &id);
        if(r == UA_STATUSCODE_GOOD) {
            UA_String s = UA_STRING_NULL;
            if(UA_NodeId_print(&id, &s) == UA_STATUSCODE_GOOD)
                printf("registered %s as %.*s\n", a.uri, (int)s.length, (const char *)s.data);
            UA_String_clear(&s);
        } else {
            rc = report("RegisterApplication", r);
        }
        UA_NodeId_clear(&id);
    }
    gdsc_session_close(gds);
    files_clear(&f);
    return rc;
}

/* ---- apps import ---- */

typedef struct {
    size_t registered, exists, failed;
} import_counts;

static void print_uri(const UA_ApplicationRecordDataType *rec) {
    printf("%.*s", (int)(rec->applicationUri.length > 200 ? 200 : rec->applicationUri.length),
           rec->applicationUri.data ? (const char *)rec->applicationUri.data : "");
}

/* One record: checked here first, then RegisterApplication when gds is set */
static void import_one(UA_Client *gds, UA_UInt16 ns, const gdsadm_import *im, size_t i,
                       import_counts *n) {
    const UA_ApplicationRecordDataType *rec = &im->recs[i];
    printf("%zu\t", im->lines[i]);
    print_uri(rec);
    UA_StatusCode r = gds_validate_record(rec);
    if(r != UA_STATUSCODE_GOOD) {
        printf("\tinvalid (a required field is missing, too long, or a Server without "
               "DiscoveryUrls)\n");
        n->failed++;
        return;
    }
    if(!gds) {
        printf("\tok\n");
        n->registered++;
        return;
    }
    UA_NodeId id;
    UA_NodeId_init(&id);
    r = gdsc_register_application(gds, ns, rec, &id);
    if(r == UA_STATUSCODE_GOOD) {
        UA_String s = UA_STRING_NULL;
        (void)UA_NodeId_print(&id, &s);
        printf("\tregistered\t%.*s\n", (int)s.length, s.data ? (const char *)s.data : "");
        UA_String_clear(&s);
        n->registered++;
    } else if(r == UA_STATUSCODE_BADALREADYEXISTS) {
        printf("\texists\n");
        n->exists++;
    } else {
        printf("\tfailed\t%s\n", UA_StatusCode_name(r));
        n->failed++;
    }
    UA_NodeId_clear(&id);
}

static int import_usage(void) {
    fprintf(stderr, "usage: gdsadm apps import FILE --dry-run\n"
                    "       gdsadm apps import FILE CONNECTION\n");
    return 2;
}

int gdsadm_apps_import(int argc, char **argv) {
    if(argc < 4 || argv[3][0] == '-')
        return import_usage();
    bool dry = argc == 5 && strcmp(argv[4], "--dry-run") == 0;
    adm_args a;
    if(!dry && !parse_args(argc, argv, 4, &a))
        return import_usage();
    gds_buf file = {NULL, 0};
    gds_status s = gds_file_read(argv[3], GDSADM_IMPORT_MAX_FILE, &file);
    if(s != GDS_OK)
        return reportg(argv[3], s);
    gdsadm_import im;
    char err[256];
    s = gdsadm_import_parse(&file, &im, err, sizeof(err));
    gds_buf_free(&file);
    if(s != GDS_OK) {
        fprintf(stderr, "gdsadm: %s: %s\n", argv[3], err[0] ? err : gds_status_name(s));
        return 1;
    }
    adm_files f;
    memset(&f, 0, sizeof(f));
    gdsc_session *gds = NULL;
    UA_UInt16 ns = 0;
    int rc = dry ? 0 : open_gds(&a, &f, &gds, &ns);
    import_counts n = {0, 0, 0};
    if(rc == 0) {
        printf("# line\tApplicationUri\tresult\n");
        for(size_t i = 0; i < im.n; i++)
            import_one(dry ? NULL : gdsc_session_client(gds), ns, &im, i, &n);
        if(dry)
            printf("# %zu record(s) ok, %zu invalid (dry run: nothing registered)\n",
                   n.registered, n.failed);
        else
            printf("# %zu registered, %zu already registered, %zu failed\n", n.registered,
                   n.exists, n.failed);
        rc = n.failed ? 1 : 0;
    }
    gdsc_session_close(gds);
    files_clear(&f);
    gdsadm_import_clear(&im);
    return rc;
}

/* ---- push now ---- */

typedef struct {
    UA_Client *gds;
    UA_UInt16 ns;
    UA_NodeId appId;
    unsigned pollSeconds;
} sign_ctx;

/* The device's CSR goes to the GDS, which builds the certificate from the
 * registered record (decision G5) */
static gds_status sign_via_gds(void *ctx, const gds_buf *csr, gds_buf *certOut,
                               gds_buf *issuersOut, size_t *issuersN) {
    sign_ctx *sc = ctx;
    UA_NodeId group = gdsc_gds_default_group(sc->ns), type = GDSC_RSA_SHA256_APP_CERT;
    UA_StatusCode r = gdsc_sign_csr(sc->gds, sc->ns, &sc->appId, &group, &type, csr,
                                    sc->pollSeconds, certOut, issuersOut, issuersN);
    if(r != UA_STATUSCODE_GOOD) {
        report("signing on the GDS (StartSigningRequest/FinishRequest)", r);
        return GDS_EREMOTE;
    }
    return GDS_OK;
}

static bool is_server(UA_ApplicationType t) {
    return t == UA_APPLICATIONTYPE_SERVER || t == UA_APPLICATIONTYPE_CLIENTANDSERVER;
}

/* The device's record: exactly one, a Server, with an opc.tcp DiscoveryUrl
 * unless --server-url is given. url points into the record or a. */
static int find_device(UA_Client *gds, UA_UInt16 ns, const adm_args *a,
                       UA_ApplicationRecordDataType *rec, char *url, size_t urlLen) {
    UA_ApplicationRecordDataType *recs = NULL;
    size_t n = 0;
    UA_StatusCode r = gdsc_find_applications(gds, ns, a->uri, &recs, &n);
    if(r != UA_STATUSCODE_GOOD)
        return report("FindApplications", r);
    int rc = 0;
    if(n != 1 || !is_server(recs[0].applicationType)) {
        fprintf(stderr, "gdsadm: %s: %zu record(s), need exactly one Server\n", a->uri, n);
        rc = 1;
    } else if(UA_ApplicationRecordDataType_copy(&recs[0], rec) != UA_STATUSCODE_GOOD) {
        rc = 1;
    }
    UA_Array_delete(recs, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    if(rc != 0)
        return rc;
    if(a->serverUrl)
        return gds_path(url, urlLen, "%s", a->serverUrl) == GDS_OK ? 0 : 1;
    for(size_t i = 0; i < rec->discoveryUrlsSize; i++) {
        const UA_String *u = &rec->discoveryUrls[i];
        if(u->length > 10 && u->length < urlLen && memcmp(u->data, "opc.tcp://", 10) == 0) {
            memcpy(url, u->data, u->length);
            url[u->length] = '\0';
            return 0;
        }
    }
    fprintf(stderr, "gdsadm: %s has no opc.tcp DiscoveryUrl; give --server-url\n", a->uri);
    return 1;
}

static void print_report(const push_report *rep, const char *url) {
    printf("trust list %s, certificate %s, ApplyChanges %s\n",
           rep->trustListUpdated ? "updated" : "unchanged",
           rep->certificateUpdated ? "updated" : "unchanged",
           rep->applied ? "done" : "not called");
    if(rep->failedStep != PUSH_STEP_NONE)
        printf("failed at %s: %s%s\n", push_step_name(rep->failedStep),
               UA_StatusCode_name(rep->failedCode), rep->cancelled ? " (CancelChanges called)" : "");
    else
        printf("pushed to %s\n", url);
}

/* Steps 3-5 with the device's record and trust list in hand */
static int push_to_device(const adm_args *a, adm_files *f, sign_ctx *sc, const char *url,
                          const UA_TrustListDataType *tl) {
    /* The device is trusted through the GDS CA, or its pinned certificate */
    if(f->serverCert.data) {
        f->trust[f->trustN++] = f->serverCert; /* files_clear frees it there */
        memset(&f->serverCert, 0, sizeof(f->serverCert));
    }
    gdsc_session_cfg c = gds_cfg(a, f);
    c.endpointUrl = url;
    c.serverUri = a->uri;
    if(a->deviceUser) {
        /* 12 §7.4: SecurityAdmin mapped to an administrator's credentials */
        c.identity = GDSC_IDENTITY_USERNAME;
        c.userName = a->deviceUser;
        c.password = &f->devicePassword;
    } else {
        /* Annex G.3: gdsadm's certificate carries SecurityAdmin */
        c.identity = GDSC_IDENTITY_APP_CERT;
        c.userName = NULL;
        c.password = NULL;
    }
    gdsc_session *dev = NULL;
    UA_StatusCode r = gdsc_session_open(&c, &dev);
    if(r != UA_STATUSCODE_GOOD)
        return report("connect to the device", r);
    push_job job;
    memset(&job, 0, sizeof(job));
    job.certificateGroup = GDSC_DEFAULT_APP_GROUP;
    job.trustListNode = GDSC_DEFAULT_APP_TRUSTLIST;
    job.certificateType = GDSC_RSA_SHA256_APP_CERT;
    job.trustList = tl;
    job.sign = sign_via_gds;
    job.signCtx = sc;
    push_report rep;
    gds_status s = push_run(gdsc_session_client(dev), &job, &rep);
    gdsc_session_close(dev);
    print_report(&rep, url);
    int rc = s == GDS_OK ? 0 : 1;
    if(rc == 0 && rep.certificateUpdated) {
        r = gdsc_wait_presents(url, &job.certificateType, &rep.issued, PRESENT_TIMEOUT_MS);
        if(r == UA_STATUSCODE_GOOD)
            printf("the device presents the issued certificate\n");
        else
            rc = report("the device does not present the issued certificate", r);
    }
    push_report_clear(&rep);
    return rc;
}

int gdsadm_push_now(int argc, char **argv) {
    adm_args a;
    if(argc < 4 || argv[3][0] == '-' || !parse_args(argc, argv, 4, &a) ||
       !a.deviceUser != !a.devicePasswordFile) {
        fprintf(stderr, "usage: gdsadm push now URI [--server-url URL] [--server-cert DER] "
                        "[--device-user NAME --device-password-file FILE] [--poll-seconds N] "
                        "CONNECTION\n");
        return 2;
    }
    a.uri = argv[3];
    adm_files f;
    memset(&f, 0, sizeof(f));
    gdsc_session *gds = NULL;
    sign_ctx sc;
    memset(&sc, 0, sizeof(sc));
    sc.pollSeconds = (unsigned)a.pollSeconds;
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    char url[GDS_MAX_PATH];
    int rc = open_gds(&a, &f, &gds, &sc.ns);
    if(rc == 0) {
        sc.gds = gdsc_session_client(gds);
        rc = find_device(sc.gds, sc.ns, &a, &rec, url, sizeof(url));
    }
    if(rc == 0) {
        sc.appId = rec.applicationId; /* borrowed from rec */
        UA_NodeId group = gdsc_gds_default_group(sc.ns);
        UA_StatusCode r = gdsc_get_trust_list(sc.gds, sc.ns, &rec.applicationId, &group, &tl);
        rc = r == UA_STATUSCODE_GOOD ? 0 : report("GetTrustList", r);
    }
    if(rc == 0)
        rc = push_to_device(&a, &f, &sc, url, &tl);
    UA_TrustListDataType_clear(&tl);
    UA_ApplicationRecordDataType_clear(&rec);
    gdsc_session_close(gds);
    files_clear(&f);
    return rc;
}

/* ---- apps unregister, certs revoke ---- */

/* The one record with this ApplicationUri; *id is a copy. */
static int find_app_id(UA_Client *gds, UA_UInt16 ns, const char *uri, UA_NodeId *id) {
    UA_ApplicationRecordDataType *recs = NULL;
    size_t n = 0;
    UA_StatusCode r = gdsc_find_applications(gds, ns, uri, &recs, &n);
    if(r != UA_STATUSCODE_GOOD)
        return report("FindApplications", r);
    int rc = 0;
    if(n != 1) {
        fprintf(stderr, "gdsadm: %s: %zu record(s), need exactly one\n", uri, n);
        rc = 1;
    } else if(UA_NodeId_copy(&recs[0].applicationId, id) != UA_STATUSCODE_GOOD) {
        rc = 1;
    }
    UA_Array_delete(recs, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    return rc;
}

/* argv[3] is the ApplicationUri, options from argv[4] */
static bool uri_args(int argc, char **argv, adm_args *a) {
    if(argc < 4 || argv[3][0] == '-' || !parse_args(argc, argv, 4, a))
        return false;
    a->uri = argv[3];
    return true;
}

int gdsadm_apps_unregister(int argc, char **argv) {
    adm_args a;
    if(!uri_args(argc, argv, &a)) {
        fprintf(stderr, "usage: gdsadm apps unregister URI CONNECTION\n");
        return 2;
    }
    adm_files f;
    memset(&f, 0, sizeof(f));
    gdsc_session *gds = NULL;
    UA_UInt16 ns = 0;
    UA_NodeId id = UA_NODEID_NULL;
    int rc = open_gds(&a, &f, &gds, &ns);
    if(rc == 0)
        rc = find_app_id(gdsc_session_client(gds), ns, a.uri, &id);
    if(rc == 0) {
        UA_StatusCode r = gdsc_unregister_application(gdsc_session_client(gds), ns, &id);
        if(r == UA_STATUSCODE_GOOD)
            printf("unregistered %s; its certificates are revoked\n", a.uri);
        else
            rc = report("UnregisterApplication", r);
    }
    UA_NodeId_clear(&id);
    gdsc_session_close(gds);
    files_clear(&f);
    return rc;
}

int gdsadm_certs_revoke(int argc, char **argv) {
    adm_args a;
    if(!uri_args(argc, argv, &a) || !a.revokeCertFile) {
        fprintf(stderr, "usage: gdsadm certs revoke URI --revoke-cert DER CONNECTION\n");
        return 2;
    }
    gds_buf cert = {0};
    gds_status s = gds_file_read(a.revokeCertFile, GDS_MAX_CERT_SIZE, &cert);
    if(s != GDS_OK)
        return reportg("reading --revoke-cert", s);
    adm_files f;
    memset(&f, 0, sizeof(f));
    gdsc_session *gds = NULL;
    UA_UInt16 ns = 0;
    UA_NodeId id = UA_NODEID_NULL;
    int rc = open_gds(&a, &f, &gds, &ns);
    if(rc == 0)
        rc = find_app_id(gdsc_session_client(gds), ns, a.uri, &id);
    if(rc == 0) {
        UA_StatusCode r = gdsc_revoke_certificate(gdsc_session_client(gds), ns, &id, &cert);
        if(r == UA_STATUSCODE_GOOD)
            printf("revoked; the certificate is on the GDS CRL\n");
        else
            rc = report("RevokeCertificate", r);
    }
    UA_NodeId_clear(&id);
    gdsc_session_close(gds);
    files_clear(&f);
    gds_buf_free(&cert);
    return rc;
}
