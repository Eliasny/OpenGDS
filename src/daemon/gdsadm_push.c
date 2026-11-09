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
 *   gdsadm push now ... --reverse-port PORT
 *       the same over Reverse Connect (OPC 10000-6 §7.1.3): gdsadm listens on
 *       PORT and the device, behind a firewall, connects to it
 *
 *   gdsadm push setup --server-uri URI --server-cert DER
 *                     (--server-url URL | --reverse-port PORT)
 *                     [--setup-user NAME --setup-password-file FILE]
 *                     [--poll-seconds N] CONNECTION
 *       Annex G.2 application setup of a new device (push_setup.h): connect
 *       with the device's setup credentials, trusting only its
 *       pre-authorized certificate; check it is in the application setup
 *       state; RegisterApplication from what it says about itself (an
 *       existing record with its ApplicationUri is reused); push the trust
 *       list and a certificate as in push now; add gdsadm's ApplicationUri
 *       to its SecurityAdmin Role (OPC 10000-18); check it left setup.
 *       Without --setup-user the device must give SecurityAdmin to gdsadm's
 *       certificate while in setup.
 *
 *   gdsadm push keycred URI --service NAME [--endpoint-url URL]...
 *                           [device options as in push now] CONNECTION
 *       a KeyCredential for the device (12 §8.4, push_keycred.h): find the
 *       service NAME under the GDS's KeyCredentialManagement; connect to
 *       the device and find its KeyCredentialConfiguration Object for the
 *       service's ResourceUri, or CreateCredential (§8.6.3) with the
 *       --endpoint-url URLs; StartRequest and FinishRequest on the GDS as
 *       KeyCredentialAdmin for the device's ApplicationUri (§8.5.5,
 *       §8.5.6); GetEncryptingKey and UpdateCredential with the secret
 *       encrypted for the device's certificate (§8.6.6, §8.6.7)
 *
 *   gdsadm push keycred-delete URI --service NAME [device options] CONNECTION
 *       DeleteCredential on the device's Object for the service (§8.6.8),
 *       then Revoke of its CredentialId on the GDS (§8.5.7)
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

#include <open62541/client_highlevel.h>
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
#include "push/push_keycred.h"
#include "push/push_setup.h"
#include "push/push_workflows.h"
#include "common/banned.h"

#define MAX_FILES 8
#define MAX_URLS 8
#define DEFAULT_POLL_SECONDS 60
#define PRESENT_TIMEOUT_MS 30000u
#define REVERSE_WAIT_MS 60000u

typedef struct {
    const char *gdsUrl, *certFile, *keyFile, *user, *passwordFile;
    const char *trustFiles[MAX_FILES], *crlFiles[MAX_FILES];
    size_t trustN, crlN;
    /* apps register */
    const char *uri, *name, *type;
    const char *urls[MAX_URLS];
    size_t urlN;
    /* push now, push setup */
    const char *serverUrl, *serverCertFile, *deviceUser, *devicePasswordFile;
    long pollSeconds, reversePort;
    const char *serverUri, *setupUser, *setupPasswordFile;
    /* certs revoke */
    const char *revokeCertFile;
    /* push keycred */
    const char *service;
    const char *kcUrls[MAX_URLS];
    size_t kcUrlN;
} adm_args;

typedef struct {
    gds_buf cert, key, password, serverCert, devicePassword;
    gds_buf trust[MAX_FILES + 1], crls[MAX_FILES];
    size_t trustN, crlN;
    const UA_Byte *serverCertPinned; /* trust[] entry that is the pinned device cert */
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
        {"--server-uri", &a->serverUri},
        {"--setup-user", &a->setupUser},
        {"--setup-password-file", &a->setupPasswordFile},
        {"--service", &a->service},
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
    if(strcmp(opt, "--endpoint-url") == 0 && a->kcUrlN < MAX_URLS) {
        a->kcUrls[a->kcUrlN++] = v;
        return true;
    }
    if(strcmp(opt, "--poll-seconds") == 0)
        return gds_parse_long(v, 0, 3600, &a->pollSeconds);
    if(strcmp(opt, "--reverse-port") == 0 && a->reversePort == 0)
        return gds_parse_long(v, 1, 65535, &a->reversePort);
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
    if(s == GDS_OK && a->setupPasswordFile)
        s = read_password(a->setupPasswordFile, &f->devicePassword);
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
    if(a->reversePort) /* the device connects to us: no DiscoveryUrl needed */
        return gds_path(url, urlLen, "Reverse Connect on port %ld", a->reversePort) == GDS_OK
                   ? 0
                   : 1;
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

/* Over Reverse Connect the device cannot be reached for GetEndpoints: wait
 * for its next connection, trusting only the GDS CA, and compare the
 * certificate it presents on the channel */
static UA_StatusCode reverse_presents(const gdsc_session_cfg *dev, const adm_files *f,
                                      const gds_buf *issued) {
    gdsc_session_cfg c = *dev;
    c.trust = f->trust;
    c.trustN = f->trustN - (f->trust[f->trustN - 1].data == f->serverCertPinned ? 1 : 0);
    gdsc_session *s = NULL;
    UA_StatusCode r = gdsc_session_open(&c, &s);
    if(r == UA_STATUSCODE_GOOD) {
        gds_buf seen = {0};
        if(gdsc_session_server_cert(s, &seen) != GDS_OK || seen.len < issued->len ||
           memcmp(seen.data, issued->data, issued->len) != 0)
            r = UA_STATUSCODE_BADCERTIFICATEINVALID;
        gds_buf_free(&seen);
    }
    gdsc_session_close(s);
    return r;
}

/* The device's session: trusted through the GDS CA or its pinned
 * certificate, with SecurityAdmin from gdsadm's certificate (Annex G.3) or
 * from --device-user (12 §7.4) */
static gdsc_session_cfg device_cfg(const adm_args *a, adm_files *f, const char *url) {
    /* The device is trusted through the GDS CA, or its pinned certificate */
    if(f->serverCert.data) {
        f->serverCertPinned = f->serverCert.data;
        f->trust[f->trustN++] = f->serverCert; /* files_clear frees it there */
        memset(&f->serverCert, 0, sizeof(f->serverCert));
    }
    gdsc_session_cfg c = gds_cfg(a, f);
    c.endpointUrl = a->reversePort ? NULL : url;
    c.serverUri = a->uri;
    c.reversePort = (UA_UInt16)a->reversePort;
    c.reverseWaitMs = REVERSE_WAIT_MS;
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
    return c;
}

/* Steps 3-5 with the device's record and trust list in hand */
static int push_to_device(const adm_args *a, adm_files *f, sign_ctx *sc, const char *url,
                          const UA_TrustListDataType *tl) {
    gdsc_session_cfg c = device_cfg(a, f, url);
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
    if(rc == 0 && rep.certificateUpdated && a->reversePort) {
        r = reverse_presents(&c, f, &rep.issued);
        if(r == UA_STATUSCODE_GOOD)
            printf("the device presents the issued certificate\n");
        else
            rc = report("the device does not present the issued certificate", r);
    } else if(rc == 0 && rep.certificateUpdated) {
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
       !a.deviceUser != !a.devicePasswordFile || a.setupUser || a.setupPasswordFile ||
       a.serverUri || (a.reversePort && a.serverUrl)) {
        fprintf(stderr, "usage: gdsadm push now URI [--server-url URL | --reverse-port PORT] "
                        "[--server-cert DER] [--device-user NAME --device-password-file FILE] "
                        "[--poll-seconds N] CONNECTION\n");
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

/* ---- push keycred (12 §8.4, §8.6) ---- */

typedef struct {
    UA_Client *gds;
    const gdsc_kc_service *svc;
    const char *appUri;
    unsigned pollSeconds;
} kc_ctx;

/* The credential comes from the GDS, which keeps only its hash */
static gds_status issue_via_gds(void *ctx, char credentialId[GDSC_KC_ID_MAX + 1],
                                gds_buf *secret) {
    kc_ctx *k = ctx;
    UA_StatusCode r =
        gdsc_kc_request(k->gds, k->svc, k->appUri, k->pollSeconds, credentialId, secret);
    if(r != UA_STATUSCODE_GOOD) {
        report("KeyCredential StartRequest/FinishRequest on the GDS", r);
        return GDS_EREMOTE;
    }
    return GDS_OK;
}

static void print_kc_report(const push_kc_report *rep, const char *url, bool del) {
    if(rep->failedStep != PUSH_KC_STEP_NONE)
        printf("failed at %s: %s\n", push_kc_step_name(rep->failedStep),
               UA_StatusCode_name(rep->failedCode));
    else if(del)
        printf("credential %s deleted on %s\n", rep->credentialId[0] ? rep->credentialId : "(no id)",
               url);
    else
        printf("credential %s pushed to %s (%s, %s)\n", rep->credentialId, url,
               rep->created ? "new Object" : "existing Object", rep->policy);
}

/* After DeleteCredential: Revoke the CredentialId the device held */
static int revoke_deleted(const kc_ctx *k, const push_kc_report *rep) {
    if(!rep->credentialId[0]) {
        printf("the device held no CredentialId; nothing to revoke on the GDS\n");
        return 0;
    }
    UA_StatusCode r = gdsc_kc_revoke(k->gds, k->svc, rep->credentialId);
    if(r != UA_STATUSCODE_GOOD)
        return report("Revoke on the GDS", r);
    printf("credential %s revoked on the GDS\n", rep->credentialId);
    return 0;
}

static int kc_to_device(const adm_args *a, adm_files *f, kc_ctx *k, const char *url, bool del) {
    gdsc_session_cfg c = device_cfg(a, f, url);
    gdsc_session *dev = NULL;
    UA_StatusCode r = gdsc_session_open(&c, &dev);
    if(r != UA_STATUSCODE_GOOD)
        return report("connect to the device", r);
    gds_buf seen = {0};
    if(gdsc_session_server_cert(dev, &seen) != GDS_OK)
        gds_buf_free(&seen); /* GetEncryptingKey must then return the certificate */
    push_kc_report rep;
    gds_status s;
    if(del) {
        s = push_keycred_delete(gdsc_session_client(dev), k->svc->resourceUri, &rep);
    } else {
        push_kc_job job;
        memset(&job, 0, sizeof(job));
        job.name = a->service;
        job.resourceUri = k->svc->resourceUri;
        job.profileUri = k->svc->profileUri;
        job.endpointUrls = a->kcUrls;
        job.endpointUrlsN = a->kcUrlN;
        job.issue = issue_via_gds;
        job.issueCtx = k;
        job.serverCert = seen.len ? &seen : NULL;
        s = push_keycred_run(gdsc_session_client(dev), &job, &rep);
    }
    gdsc_session_close(dev);
    gds_buf_free(&seen);
    print_kc_report(&rep, url, del);
    if(s != GDS_OK)
        return 1;
    return del ? revoke_deleted(k, &rep) : 0;
}

static int keycred_cmd(int argc, char **argv, bool del) {
    adm_args a;
    if(argc < 4 || argv[3][0] == '-' || !parse_args(argc, argv, 4, &a) || !a.service ||
       !a.deviceUser != !a.devicePasswordFile || a.setupUser || a.setupPasswordFile ||
       a.serverUri || (a.reversePort && a.serverUrl) || (del && a.kcUrlN)) {
        fprintf(stderr, "usage: gdsadm push %s URI --service NAME%s "
                        "[--server-url URL | --reverse-port PORT] [--server-cert DER] "
                        "[--device-user NAME --device-password-file FILE] "
                        "[--poll-seconds N] CONNECTION\n",
                del ? "keycred-delete" : "keycred", del ? "" : " [--endpoint-url URL]...");
        return 2;
    }
    a.uri = argv[3];
    adm_files f;
    memset(&f, 0, sizeof(f));
    gdsc_session *gds = NULL;
    UA_UInt16 ns = 0;
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    gdsc_kc_service svc;
    memset(&svc, 0, sizeof(svc));
    char url[GDS_MAX_PATH];
    int rc = open_gds(&a, &f, &gds, &ns);
    if(rc == 0)
        rc = find_device(gdsc_session_client(gds), ns, &a, &rec, url, sizeof(url));
    if(rc == 0) {
        UA_StatusCode r = gdsc_kc_service_find(gdsc_session_client(gds), ns, a.service, &svc);
        rc = r == UA_STATUSCODE_GOOD ? 0 : report("KeyCredentialService on the GDS", r);
    }
    if(rc == 0) {
        kc_ctx k = {gdsc_session_client(gds), &svc, a.uri, (unsigned)a.pollSeconds};
        rc = kc_to_device(&a, &f, &k, url, del);
    }
    gdsc_kc_service_clear(&svc);
    UA_ApplicationRecordDataType_clear(&rec);
    gdsc_session_close(gds);
    files_clear(&f);
    return rc;
}

int gdsadm_push_keycred(int argc, char **argv) {
    return keycred_cmd(argc, argv, false);
}

int gdsadm_push_keycred_delete(int argc, char **argv) {
    return keycred_cmd(argc, argv, true);
}

/* ---- push setup (Annex G.2) ---- */

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


typedef struct {
    sign_ctx *sc;
} enroll_ctx;

/* The record from what the device says about itself: names, type and
 * ProductUri from its ApplicationDescription, its DiscoveryUrls (or the URL
 * we reached it at) */
static UA_StatusCode register_device(UA_Client *gds, UA_UInt16 ns,
                                     const UA_ApplicationDescription *ad, const char *url,
                                     UA_NodeId *id) {
    UA_String u = UA_STRING((char *)(uintptr_t)(url ? url : ""));
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    rec.applicationUri = ad->applicationUri;
    rec.applicationType = ad->applicationType;
    rec.applicationNames = (UA_LocalizedText *)(uintptr_t)&ad->applicationName;
    rec.applicationNamesSize = 1;
    rec.productUri = ad->productUri.length ? ad->productUri : ad->applicationUri;
    rec.discoveryUrls = ad->discoveryUrlsSize ? ad->discoveryUrls : (url ? &u : NULL);
    rec.discoveryUrlsSize = ad->discoveryUrlsSize ? ad->discoveryUrlsSize : (url ? 1 : 0);
    UA_StatusCode r = gdsc_register_application(gds, ns, &rec, id);
    if(r == UA_STATUSCODE_GOOD)
        printf("registered %.*s\n", (int)ad->applicationUri.length,
               (const char *)ad->applicationUri.data);
    return r;
}

static gds_status enroll_via_gds(void *ctx, const UA_ApplicationDescription *ad,
                                 const char *url, const UA_ByteString *serverCert,
                                 UA_TrustListDataType *tl) {
    (void)serverCert; /* the session checked it against the pre-authorized one */
    sign_ctx *sc = ((enroll_ctx *)ctx)->sc;
    if(ad->applicationUri.length == 0 || ad->applicationUri.length >= GDS_MAX_APPLICATION_URI)
        return GDS_EINVAL;
    char uri[GDS_MAX_APPLICATION_URI];
    memcpy(uri, ad->applicationUri.data, ad->applicationUri.length);
    uri[ad->applicationUri.length] = '\0';
    UA_NodeId_clear(&sc->appId);
    UA_StatusCode r = register_device(sc->gds, sc->ns, ad, url, &sc->appId);
    if(r == UA_STATUSCODE_BADALREADYEXISTS) {
        /* set up again (e.g. after ResetToServerDefaults): the same record */
        printf("%s is registered already; using that record\n", uri);
        r = find_app_id(sc->gds, sc->ns, uri, &sc->appId) == 0 ? UA_STATUSCODE_GOOD
                                                              : UA_STATUSCODE_BADNOTFOUND;
    }
    if(r != UA_STATUSCODE_GOOD) {
        report("RegisterApplication", r);
        return GDS_EREMOTE;
    }
    UA_NodeId group = gdsc_gds_default_group(sc->ns);
    r = gdsc_get_trust_list(sc->gds, sc->ns, &sc->appId, &group, tl);
    if(r != UA_STATUSCODE_GOOD) {
        report("GetTrustList", r);
        return GDS_EREMOTE;
    }
    return GDS_OK;
}

static const char *state_name(UA_ServerState s) {
    switch((int)s) { /* -Wswitch-enum: the enum has a FORCE32BIT member */
    case UA_SERVERSTATE_RUNNING: return "Running";
    case UA_SERVERSTATE_FAILED: return "Failed";
    case UA_SERVERSTATE_NOCONFIGURATION: return "NoConfiguration";
    case UA_SERVERSTATE_SUSPENDED: return "Suspended";
    case UA_SERVERSTATE_SHUTDOWN: return "Shutdown";
    case UA_SERVERSTATE_TEST: return "Test";
    case UA_SERVERSTATE_COMMUNICATIONFAULT: return "CommunicationFault";
    case UA_SERVERSTATE_UNKNOWN: return "Unknown";
    case __UA_SERVERSTATE_FORCE32BIT:
    default: return "?";
    }
}

static int setup_usage(void) {
    fprintf(stderr, "usage: gdsadm push setup --server-uri URI --server-cert DER\n"
                    "         (--server-url URL | --reverse-port PORT)\n"
                    "         [--setup-user NAME --setup-password-file FILE] [--poll-seconds N]\n"
                    "         CONNECTION\n");
    return 2;
}

int gdsadm_push_setup(int argc, char **argv) {
    adm_args a;
    if(!parse_args(argc, argv, 3, &a) || !a.serverUri || !a.serverCertFile ||
       !a.serverUrl == !a.reversePort || !a.setupUser != !a.setupPasswordFile ||
       a.deviceUser || a.devicePasswordFile || strlen(a.serverUri) >= GDS_MAX_APPLICATION_URI)
        return setup_usage();
    adm_files f;
    memset(&f, 0, sizeof(f));
    gdsc_session *gds = NULL;
    sign_ctx sc;
    memset(&sc, 0, sizeof(sc));
    sc.pollSeconds = (unsigned)a.pollSeconds;
    int rc = open_gds(&a, &f, &gds, &sc.ns);
    if(rc != 0) {
        gdsc_session_close(gds);
        files_clear(&f);
        return rc;
    }
    sc.gds = gdsc_session_client(gds);
    enroll_ctx ec = {&sc};
    push_setup_job j;
    memset(&j, 0, sizeof(j));
    j.conn.endpointUrl = a.serverUrl;
    j.conn.reversePort = (UA_UInt16)a.reversePort;
    j.conn.reverseWaitMs = REVERSE_WAIT_MS;
    j.conn.cert = &f.cert;
    j.conn.key = &f.key;
    j.serverUri = a.serverUri;
    j.deviceCert = &f.serverCert;
    j.trust = f.trust;
    j.trustN = f.trustN;
    j.crls = f.crls;
    j.crlN = f.crlN;
    j.setupIdentity = a.setupUser ? GDSC_IDENTITY_USERNAME : GDSC_IDENTITY_APP_CERT;
    j.setupUser = a.setupUser;
    j.setupPassword = a.setupUser ? &f.devicePassword : NULL;
    j.enroll = enroll_via_gds;
    j.enrollCtx = &ec;
    j.sign = sign_via_gds;
    j.signCtx = &sc;
    j.certificateGroup = GDSC_DEFAULT_APP_GROUP;
    j.trustListNode = GDSC_DEFAULT_APP_TRUSTLIST;
    j.certificateType = GDSC_RSA_SHA256_APP_CERT;
    push_setup_report rep;
    gds_status s = push_setup_run(&j, &rep);
    printf("before: State %s, InApplicationSetup %s\n", state_name(rep.before.state),
           !rep.before.hasInSetup ? "absent" : rep.before.inSetup ? "TRUE" : "FALSE");
    if(rep.failedStep != PUSH_SETUP_STEP_NONE || s != GDS_OK) {
        if(rep.failedStep == PUSH_SETUP_STEP_PUSH)
            print_report(&rep.push, a.serverUri);
        fprintf(stderr, "gdsadm: push setup failed at '%s': %s%s\n",
                push_setup_step_name(rep.failedStep), UA_StatusCode_name(rep.failedCode),
                rep.failedStep == PUSH_SETUP_STEP_STATE &&
                        rep.failedCode == UA_STATUSCODE_BADINVALIDSTATE
                    ? " (the device is not in the application setup state; use push now)"
                    : "");
        rc = 1;
    } else {
        print_report(&rep.push, a.serverUri);
        printf("SecurityAdmin Role: our ApplicationUri added%s\n",
               rep.anonymousRemoved ? ", Anonymous removed" : "");
        printf("after: State %s; the device left the application setup state\n",
               state_name(rep.after.state));
    }
    push_setup_report_clear(&rep);
    UA_NodeId_clear(&sc.appId);
    gdsc_session_close(gds);
    files_clear(&f);
    return rc;
}

/* ---- apps unregister, certs revoke ---- */

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

/* ---- roles (OPC 10000-18 §4.4) ----
 * gdsadm roles list CONNECTION
 * gdsadm roles add-identity|remove-identity ROLE TYPE CRITERIA CONNECTION
 * gdsadm roles add-app|remove-app ROLE APPLICATION_URI CONNECTION
 * The Roles are the Objects under Server.ServerCapabilities.RoleSet, found
 * by BrowseName; the methods are those of the RoleType (§4.4.5 - §4.4.8),
 * which the GDS lets only a SecurityAdmin over SignAndEncrypt call. */

static const char *const criteriaNames[] = {
    NULL, "UserName", "Thumbprint", "Role", "GroupId", "Anonymous",
    "AuthenticatedUser", "Application", "X509Subject", "TrustedApplication"};

static bool parse_criteria_type(const char *t, UA_IdentityCriteriaType *out) {
    for(size_t i = 1; i < GDS_ARRAY_SIZE(criteriaNames); i++) {
        if(strcmp(t, criteriaNames[i]) == 0) {
            *out = (UA_IdentityCriteriaType)i;
            return true;
        }
    }
    return false;
}

/* The forward hierarchical child of parent whose BrowseName name is name */
static UA_StatusCode child_by_name(UA_Client *c, const UA_NodeId *parent, const char *name,
                                   UA_NodeId *out) {
    UA_BrowseRequest req;
    UA_BrowseRequest_init(&req);
    UA_BrowseDescription d;
    UA_BrowseDescription_init(&d);
    d.nodeId = *parent;
    d.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    d.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
    d.includeSubtypes = true;
    d.resultMask = UA_BROWSERESULTMASK_BROWSENAME;
    req.nodesToBrowse = &d;
    req.nodesToBrowseSize = 1;
    UA_BrowseResponse resp = UA_Client_Service_browse(c, req);
    UA_StatusCode r = resp.responseHeader.serviceResult;
    if(r == UA_STATUSCODE_GOOD && resp.resultsSize == 1)
        r = resp.results[0].statusCode;
    if(r == UA_STATUSCODE_GOOD) {
        r = UA_STATUSCODE_BADNOTFOUND;
        size_t len = strlen(name);
        for(size_t i = 0; i < resp.results[0].referencesSize; i++) {
            const UA_ReferenceDescription *rd = &resp.results[0].references[i];
            if(rd->browseName.name.length == len &&
               memcmp(rd->browseName.name.data, name, len) == 0) {
                r = UA_NodeId_copy(&rd->nodeId.nodeId, out);
                break;
            }
        }
    }
    UA_BrowseResponse_clear(&resp);
    return r;
}

static void print_text(const UA_String *s) {
    printf("%.*s", (int)s->length, s->data ? (const char *)s->data : "");
}

static UA_StatusCode print_rules(UA_Client *c, const UA_NodeId *role, const char *prop) {
    UA_NodeId id = UA_NODEID_NULL;
    UA_StatusCode r = child_by_name(c, role, prop, &id);
    if(r == UA_STATUSCODE_BADNOTFOUND)
        return UA_STATUSCODE_GOOD; /* Applications and Endpoints are Optional */
    UA_Variant v;
    UA_Variant_init(&v);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_readValueAttribute(c, id, &v);
    UA_NodeId_clear(&id);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE])) {
        const UA_IdentityMappingRuleType *a = v.data;
        for(size_t i = 0; i < v.arrayLength; i++) {
            int t = (int)a[i].criteriaType;
            printf("  identity %s ", t > 0 && t < (int)GDS_ARRAY_SIZE(criteriaNames)
                                         ? criteriaNames[t] : "?");
            print_text(&a[i].criteria);
            printf("\n");
        }
    } else if(UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_STRING])) {
        const UA_String *a = v.data;
        for(size_t i = 0; i < v.arrayLength; i++) {
            printf("  application ");
            print_text(&a[i]);
            printf("\n");
        }
    } else if(UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_ENDPOINTTYPE])) {
        const UA_EndpointType *a = v.data;
        for(size_t i = 0; i < v.arrayLength; i++) {
            printf("  endpoint ");
            print_text(&a[i].endpointUrl);
            printf(" %d ", (int)a[i].securityMode);
            print_text(&a[i].securityPolicyUri);
            printf(" ");
            print_text(&a[i].transportProfileUri);
            printf("\n");
        }
    }
    UA_Variant_clear(&v);
    return UA_STATUSCODE_GOOD;
}

static int roles_list(UA_Client *c) {
    const UA_NodeId roleSet = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET);
    UA_BrowseRequest req;
    UA_BrowseRequest_init(&req);
    UA_BrowseDescription d;
    UA_BrowseDescription_init(&d);
    d.nodeId = roleSet;
    d.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    d.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);
    d.includeSubtypes = true;
    d.nodeClassMask = UA_NODECLASS_OBJECT;
    d.resultMask = UA_BROWSERESULTMASK_BROWSENAME;
    req.nodesToBrowse = &d;
    req.nodesToBrowseSize = 1;
    UA_BrowseResponse resp = UA_Client_Service_browse(c, req);
    UA_StatusCode r = resp.responseHeader.serviceResult;
    if(r == UA_STATUSCODE_GOOD && resp.resultsSize == 1)
        r = resp.results[0].statusCode;
    int rc = 0;
    if(r != UA_STATUSCODE_GOOD) {
        rc = report("browse RoleSet", r);
    } else {
        static const char *const props[] = {"Identities", "Applications", "Endpoints"};
        for(size_t i = 0; i < resp.results[0].referencesSize; i++) {
            const UA_ReferenceDescription *rd = &resp.results[0].references[i];
            print_text(&rd->browseName.name);
            printf("\n");
            for(size_t p = 0; p < GDS_ARRAY_SIZE(props); p++) {
                r = print_rules(c, &rd->nodeId.nodeId, props[p]);
                if(r != UA_STATUSCODE_GOOD) {
                    rc = report(props[p], r);
                    break;
                }
            }
            if(rc != 0)
                break;
        }
    }
    UA_BrowseResponse_clear(&resp);
    return rc;
}

static int roles_usage(void) {
    fprintf(stderr, "usage: gdsadm roles list CONNECTION\n"
                    "       gdsadm roles add-identity|remove-identity ROLE TYPE CRITERIA "
                    "CONNECTION\n"
                    "       gdsadm roles add-app|remove-app ROLE APPLICATION_URI CONNECTION\n"
                    "  TYPE: UserName Thumbprint Role GroupId Anonymous AuthenticatedUser\n"
                    "        Application X509Subject TrustedApplication\n");
    return 2;
}

int gdsadm_roles(int argc, char **argv) {
    /* argv: gdsadm roles VERB ... */
    if(argc < 3)
        return roles_usage();
    const char *verb = argv[2];
    bool identity = strcmp(verb, "add-identity") == 0 || strcmp(verb, "remove-identity") == 0;
    bool app = strcmp(verb, "add-app") == 0 || strcmp(verb, "remove-app") == 0;
    bool list = strcmp(verb, "list") == 0;
    int first = list ? 3 : identity ? 6 : app ? 5 : -1;
    if(first < 0 || argc < first)
        return roles_usage();
    for(int i = 3; i < first; i++)
        if(argv[i][0] == '-')
            return roles_usage();
    UA_IdentityMappingRuleType rule;
    UA_IdentityMappingRuleType_init(&rule);
    if(identity) {
        if(!parse_criteria_type(argv[4], &rule.criteriaType)) {
            fprintf(stderr, "gdsadm: unknown identity type %s\n", argv[4]);
            return roles_usage();
        }
        rule.criteria = UA_STRING(argv[5]);
    }
    adm_args a;
    if(!parse_args(argc, argv, first, &a))
        return roles_usage();
    adm_files f;
    memset(&f, 0, sizeof(f));
    gdsc_session *gds = NULL;
    UA_UInt16 ns = 0;
    int rc = open_gds(&a, &f, &gds, &ns);
    UA_Client *c = rc == 0 ? gdsc_session_client(gds) : NULL;
    if(rc == 0 && list) {
        rc = roles_list(c);
    } else if(rc == 0) {
        const UA_NodeId roleSet =
            UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET);
        const char *method = strcmp(verb, "add-identity") == 0      ? "AddIdentity"
                             : strcmp(verb, "remove-identity") == 0 ? "RemoveIdentity"
                             : strcmp(verb, "add-app") == 0         ? "AddApplication"
                                                                    : "RemoveApplication";
        UA_NodeId role = UA_NODEID_NULL, m = UA_NODEID_NULL;
        UA_StatusCode r = child_by_name(c, &roleSet, argv[3], &role);
        if(r != UA_STATUSCODE_GOOD) {
            rc = report(argv[3], r);
        } else if((r = child_by_name(c, &role, method, &m)) != UA_STATUSCODE_GOOD) {
            rc = report(method, r);
        } else {
            UA_Variant in;
            UA_String uri = UA_STRING(argv[4]);
            if(identity)
                UA_Variant_setScalar(&in, &rule,
                                     &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]);
            else
                UA_Variant_setScalar(&in, &uri, &UA_TYPES[UA_TYPES_STRING]);
            size_t outN = 0;
            UA_Variant *out = NULL;
            r = UA_Client_call(c, role, m, 1, &in, &outN, &out);
            UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
            if(r == UA_STATUSCODE_GOOD)
                printf("%s %s: done\n", argv[3], method);
            else
                rc = report(method, r);
        }
        UA_NodeId_clear(&role);
        UA_NodeId_clear(&m);
    }
    gdsc_session_close(gds);
    files_clear(&f);
    return rc;
}
