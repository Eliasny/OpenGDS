/* gdsadm: OpenGDS administration on the GDS host.
 *
 *   gdsadm hash-password [--iterations N]   password on stdin -> users-file credential
 *   gdsadm apps list --store PATH           registered applications (read-only)
 *   gdsadm certs status --store PATH        latest certificate of each application
 *
 * Passwords are read from stdin, never argv. The store is opened read-only
 * and may be read while opengdsd runs.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <open62541/nodeids_gds.h>
#include <openssl/crypto.h>

#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "common/safeint.h"
#include "gds_access.h"
#include "store.h"
#include "common/banned.h"

#define MAX_PASSWORD 1024
#define CRED_LEN 256

static int usage(void) {
    fprintf(stderr, "usage: gdsadm hash-password [--iterations N]\n"
                    "       gdsadm apps list --store PATH\n"
                    "       gdsadm certs status --store PATH\n");
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

int main(int argc, char **argv) {
    if(argc >= 2 && strcmp(argv[1], "hash-password") == 0)
        return hash_password(argc, argv);
    if(argc >= 3 && strcmp(argv[1], "apps") == 0 && strcmp(argv[2], "list") == 0)
        return store_cmd(argc, argv, list_cb, false);
    if(argc >= 3 && strcmp(argv[1], "certs") == 0 && strcmp(argv[2], "status") == 0)
        return store_cmd(argc, argv, status_cb, true);
    return usage();
}
