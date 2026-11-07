/* gdsadm: OpenGDS administration on the GDS host.
 *
 *   gdsadm hash-password [--iterations N]   password on stdin -> users-file credential
 *   gdsadm apps list --store PATH           registered applications (read-only)
 *   gdsadm certs status --store PATH        latest certificate of each application
 *   gdsadm approvals list --store PATH      certificate requests waiting for approval
 *   gdsadm approvals approve|reject --url URL --user NAME --password-file F
 *          --trust CA.der [--crl CA.crl] [--comment TEXT] REQUEST_ID
 *
 * Over OPC UA, as a standard Administration Component (gdsadm_push.c):
 *   gdsadm apps register ...                RegisterApplication on the GDS
 *   gdsadm apps import FILE ...             RegisterApplication per CSV/JSON record
 *   gdsadm apps unregister URI ...          UnregisterApplication (revokes its certificates)
 *   gdsadm certs revoke URI ...             RevokeCertificate
 *   gdsadm push now URI ...                 push trust list + certificate to a device
 *
 * Passwords are read from stdin or a file, never argv. The store is opened read-only
 * and may be read while opengdsd runs. approve and reject answer the request's
 * dialog with Respond2 over SignAndEncrypt, as the RegistrationAuthorityAdmin
 * `--user` (docs/opengdsd.md, "Approving certificate requests"); the store is
 * never written here.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>
#include <open62541/nodeids.h>
#include <open62541/nodeids_gds.h>
#include <openssl/crypto.h>

#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "common/limits.h"
#include "common/safeint.h"
#include "client/gdsc_connect.h"
#include "gds_access.h"
#include "gdsadm_push.h"
#include "store.h"
#include "common/banned.h"

#define MAX_PASSWORD 1024
#define CRED_LEN 256

static int usage(void) {
    fprintf(stderr, "usage: gdsadm hash-password [--iterations N]\n"
                    "       gdsadm apps list --store PATH\n"
                    "       gdsadm certs status --store PATH\n"
                    "       gdsadm approvals list --store PATH\n"
                    "       gdsadm approvals approve|reject --url URL --user NAME "
                    "--password-file F --trust CA.der [--crl CA.crl] [--comment TEXT] "
                    "REQUEST_ID\n"
                    "       gdsadm apps register --uri URI --name NAME --type TYPE ... CONNECTION\n"
                    "       gdsadm apps import FILE --dry-run | CONNECTION\n"
                    "       gdsadm apps unregister URI CONNECTION\n"
                    "       gdsadm certs revoke URI --revoke-cert DER CONNECTION\n"
                    "       gdsadm push now URI [--server-url URL] [--server-cert DER]\n"
                    "                       [--device-user NAME --device-password-file FILE] CONNECTION\n"
                    "  CONNECTION: --gds URL --cert DER --key DER --trust DER... [--crl DER]...\n"
                    "              --user NAME --password-file FILE\n");
    return 2;
}

static int hash_password(int argc, char **argv) {
    long iter = GDS_PBKDF2_DEFAULT_ITER;
    if(argc == 4 && strcmp(argv[2], "--iterations") == 0) {
        if(!gds_parse_long(argv[3], 10000, 10000000, &iter))
            return usage();
    } else if(argc != 2) {
        return usage();
    }
    bool tty = isatty(STDIN_FILENO) == 1;
    struct termios old, quiet;
    if(tty && tcgetattr(STDIN_FILENO, &old) == 0) {
        quiet = old;
        quiet.c_lflag &= ~(tcflag_t)ECHO;
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
        fprintf(stderr, "password: ");
    } else {
        tty = false;
    }
    char pw[MAX_PASSWORD + 2];
    bool got = fgets(pw, sizeof(pw), stdin) != NULL;
    if(tty) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
        fprintf(stderr, "\n");
    }
    size_t n = got ? strlen(pw) : 0;
    while(n > 0 && (pw[n - 1] == '\n' || pw[n - 1] == '\r'))
        n--;
    char out[CRED_LEN];
    gds_status r = n > 0 && n <= MAX_PASSWORD
                       ? gds_password_hash((const uint8_t *)pw, n, (uint32_t)iter, out, sizeof(out))
                       : GDS_EINVAL;
    OPENSSL_cleanse(pw, sizeof(pw));
    if(r != GDS_OK) {
        fprintf(stderr, "gdsadm: %s\n", gds_status_name(r));
        return 1;
    }
    printf("%s\n", out);
    return 0;
}

static void print_guid(const UA_Guid *g) {
    UA_String s = UA_STRING_NULL;
    if(UA_Guid_print(g, &s) == UA_STATUSCODE_GOOD)
        printf("%.*s", (int)s.length, (const char *)s.data);
    UA_String_clear(&s);
}

static const char *type_name(UA_ApplicationType t) {
    switch(t) {
    case UA_APPLICATIONTYPE_SERVER:
        return "Server";
    case UA_APPLICATIONTYPE_CLIENT:
        return "Client";
    case UA_APPLICATIONTYPE_CLIENTANDSERVER:
        return "ClientAndServer";
    case UA_APPLICATIONTYPE_DISCOVERYSERVER:
        return "DiscoveryServer";
    case __UA_APPLICATIONTYPE_FORCE32BIT:
    default:
        return "?";
    }
}

static bool list_cb(void *ctx, int64_t recordId, const UA_ApplicationRecordDataType *rec) {
    (void)ctx;
    printf("%lld\t", (long long)recordId);
    print_guid(&rec->applicationId.identifier.guid);
    printf("\t%s\t%.*s\n", type_name(rec->applicationType), (int)rec->applicationUri.length,
           (const char *)rec->applicationUri.data);
    return true;
}

static bool status_cb(void *ctx, int64_t recordId, const UA_ApplicationRecordDataType *rec) {
    gds_store *st = ctx;
    gds_buf der = {0};
    int64_t notAfter = 0;
    gds_status r = gds_store_cert_latest(
        st, &rec->applicationId.identifier.guid,
        UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP,
        UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE, &der, &notAfter);
    printf("%lld\t%.*s\t", (long long)recordId, (int)rec->applicationUri.length,
           (const char *)rec->applicationUri.data);
    if(r == GDS_OK) {
        /* the store keeps Unix seconds */
        UA_DateTimeStruct t = UA_DateTime_toStruct(UA_DateTime_fromUnixTime(notAfter));
        bool expired = notAfter < (int64_t)time(NULL);
        printf("%s %04u-%02u-%02u\n", expired ? "expired" : "valid until", (unsigned)t.year,
               (unsigned)t.month, (unsigned)t.day);
    } else {
        printf("%s\n", r == GDS_ENOTFOUND ? "no certificate" : gds_status_name(r));
    }
    gds_buf_free(&der);
    return true;
}

static int store_cmd(int argc, char **argv, gds_store_scan_cb cb, bool passStore) {
    if(argc != 5 || strcmp(argv[3], "--store") != 0)
        return usage();
    gds_store *st = NULL;
    gds_status r = gds_store_open_readonly(argv[4], &st);
    if(r == GDS_OK)
        r = gds_store_app_scan(st, 0, cb, passStore ? st : NULL);
    gds_store_close(st);
    if(r != GDS_OK) {
        fprintf(stderr, "gdsadm: %s: %s\n", argv[4], gds_status_name(r));
        return 1;
    }
    return 0;
}

/* ---- approvals ---- */

static bool pending_cb(void *ctx, const gds_request *q) {
    gds_store *st = ctx;
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    print_guid(&q->id);
    if(gds_store_app_get(st, &q->appId, &rec) == GDS_OK)
        printf("\t%.*s\n", (int)rec.applicationUri.length, (const char *)rec.applicationUri.data);
    else
        printf("\t?\n");
    UA_ApplicationRecordDataType_clear(&rec);
    return true;
}

static int approvals_list(int argc, char **argv) {
    if(argc != 5 || strcmp(argv[3], "--store") != 0)
        return usage();
    gds_store *st = NULL;
    gds_status r = gds_store_open_readonly(argv[4], &st);
    if(r == GDS_OK)
        r = gds_store_req_scan(st, GDS_REQ_PENDING, pending_cb, st);
    gds_store_close(st);
    if(r != GDS_OK) {
        fprintf(stderr, "gdsadm: %s: %s\n", argv[4], gds_status_name(r));
        return 1;
    }
    return 0;
}

typedef struct {
    const char *url, *user, *passwordFile, *trust, *crl, *comment, *requestId;
} respond_args;

static bool parse_respond(int argc, char **argv, respond_args *a) {
    memset(a, 0, sizeof(*a));
    int i = 3;
    for(; i + 1 < argc; i += 2) {
        const char *k = argv[i], *v = argv[i + 1];
        if(strcmp(k, "--url") == 0)
            a->url = v;
        else if(strcmp(k, "--user") == 0)
            a->user = v;
        else if(strcmp(k, "--password-file") == 0)
            a->passwordFile = v;
        else if(strcmp(k, "--trust") == 0)
            a->trust = v;
        else if(strcmp(k, "--crl") == 0)
            a->crl = v;
        else if(strcmp(k, "--comment") == 0)
            a->comment = v;
        else
            break;
    }
    if(i == argc - 1)
        a->requestId = argv[i];
    return a->url && a->user && a->passwordFile && a->trust && a->requestId;
}

static gds_status read_secret(const char *path, gds_buf *out) {
    gds_status r = gds_file_read(path, 1024, out);
    while(r == GDS_OK && out->len > 0 &&
          (out->data[out->len - 1] == '\n' || out->data[out->len - 1] == '\r'))
        out->len--;
    if(r == GDS_OK && out->len == 0) {
        gds_buf_free_secret(out);
        r = GDS_EINVAL;
    }
    return r;
}

/* Respond2 on ns=1;g=<RequestId>: 0 Approve, 1 Reject. */
static UA_StatusCode respond2(UA_Client *c, const UA_Guid *reqId, UA_Int32 resp,
                              const char *comment) {
    UA_LocalizedText lt = comment ? UA_LOCALIZEDTEXT("", (char *)(uintptr_t)comment)
                                  : (UA_LocalizedText){UA_STRING_NULL, UA_STRING_NULL};
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &resp, &UA_TYPES[UA_TYPES_INT32]);
    UA_Variant_setScalar(&in[1], &lt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(c, UA_NODEID_GUID(1, *reqId),
                                     UA_NODEID_NUMERIC(0, UA_NS0ID_DIALOGCONDITIONTYPE_RESPOND2), 2,
                                     in, &outN, &out);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

static int approvals_respond(int argc, char **argv, UA_Int32 resp) {
    respond_args a;
    if(!parse_respond(argc, argv, &a))
        return usage();
    UA_Guid reqId;
    UA_String idStr = UA_STRING((char *)(uintptr_t)a.requestId);
    if(UA_Guid_parse(&reqId, idStr) != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "gdsadm: %s is not a request id (a GUID)\n", a.requestId);
        return 2;
    }
    if(a.comment && strlen(a.comment) > 1024) {
        fprintf(stderr, "gdsadm: --comment is longer than 1024 characters\n");
        return 2;
    }
    gds_buf pw = {0}, ca = {0}, crl = {0};
    gds_status st = read_secret(a.passwordFile, &pw);
    if(st == GDS_OK)
        st = gds_file_read(a.trust, GDS_MAX_CERT_SIZE, &ca);
    if(st == GDS_OK && a.crl)
        st = gds_file_read(a.crl, GDS_MAX_CRL_SIZE, &crl);
    if(st != GDS_OK) {
        fprintf(stderr, "gdsadm: reading the password, --trust or --crl: %s\n",
                gds_status_name(st));
        gds_buf_free_secret(&pw);
        gds_buf_free(&ca);
        return 1;
    }
    gdsc_admin_cfg cfg = {a.url, a.user, &pw, &ca, 1, a.crl ? &crl : NULL, a.crl ? 1u : 0u, 0};
    UA_Client *c = NULL;
    UA_StatusCode r = gdsc_admin_connect(&cfg, &c);
    gds_buf_free_secret(&pw);
    if(r == UA_STATUSCODE_GOOD)
        r = respond2(c, &reqId, resp, a.comment);
    else
        fprintf(stderr, "gdsadm: connecting to %s: %s\n", a.url, UA_StatusCode_name(r));
    gdsc_admin_close(c);
    gds_buf_free(&ca);
    gds_buf_free(&crl);
    if(r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "gdsadm: %s: %s\n", resp == 0 ? "approve" : "reject",
                UA_StatusCode_name(r));
        return 1;
    }
    printf("%s %s\n", a.requestId, resp == 0 ? "approved" : "rejected");
    return 0;
}

int main(int argc, char **argv) {
    if(argc >= 2 && strcmp(argv[1], "hash-password") == 0)
        return hash_password(argc, argv);
    if(argc >= 3 && strcmp(argv[1], "apps") == 0 && strcmp(argv[2], "list") == 0)
        return store_cmd(argc, argv, list_cb, false);
    if(argc >= 3 && strcmp(argv[1], "apps") == 0 && strcmp(argv[2], "register") == 0)
        return gdsadm_apps_register(argc, argv);
    if(argc >= 3 && strcmp(argv[1], "apps") == 0 && strcmp(argv[2], "import") == 0)
        return gdsadm_apps_import(argc, argv);
    if(argc >= 3 && strcmp(argv[1], "apps") == 0 && strcmp(argv[2], "unregister") == 0)
        return gdsadm_apps_unregister(argc, argv);
    if(argc >= 3 && strcmp(argv[1], "certs") == 0 && strcmp(argv[2], "revoke") == 0)
        return gdsadm_certs_revoke(argc, argv);
    if(argc >= 3 && strcmp(argv[1], "push") == 0 && strcmp(argv[2], "now") == 0)
        return gdsadm_push_now(argc, argv);
    if(argc >= 3 && strcmp(argv[1], "certs") == 0 && strcmp(argv[2], "status") == 0)
        return store_cmd(argc, argv, status_cb, true);
    if(argc >= 3 && strcmp(argv[1], "approvals") == 0) {
        if(strcmp(argv[2], "list") == 0)
            return approvals_list(argc, argv);
        if(strcmp(argv[2], "approve") == 0)
            return approvals_respond(argc, argv, 0);
        if(strcmp(argv[2], "reject") == 0)
            return approvals_respond(argc, argv, 1);
    }
    return usage();
}
