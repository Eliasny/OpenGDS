/* OpenGDS Auditor - command line (Auditor plan cli/main.c).
 *
 *   gdsaudit gds --url opc.tcp://host:4840 --trust ca.der [--trust ...]
 *                [--crl ca.crl] [--user admin --password-file FILE]
 *                [--work DIR] [--allow-changes] [--only PREFIX]
 *                [--expect FILE.csv] [--poll-seconds N] [--list]
 *
 *   gdsaudit client [options] -- TRIGGER ARGV...   (profile_client/client_main.c)
 *
 * Runs the GDS profile (the T0 spec tests) against a GDS and prints TAP.
 * Exit codes: 0 all passed, 1 a test failed (or, with --expect, a verdict
 * differs from the file), 2 the run could not be done, 3 some Not tested.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <string.h>

#include "common/limits.h"
#include "common/safeint.h"
#include "client_profile.h"
#include "gds_target.h"
#include "spec_tests.h"
#include "common/banned.h"

#define APP_URI "urn:opengds:auditor"
#define MAX_TESTS 64

static int usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s gds --url URL --trust CA.der [--trust ...] [--crl CRL] [--user U\n"
            "       --password-file F] [--work DIR] [--allow-changes] [--only PREFIX]\n"
            "       [--expect FILE.csv] [--poll-seconds N] [--list]\n"
            "       %s client --help\n",
            argv0, argv0);
    return 2;
}

static gds_status read_password(const char *path, char *out, size_t outLen) {
    gds_buf b = {0};
    gds_status r = gds_file_read(path, outLen - 1, &b);
    if(r != GDS_OK)
        return r;
    size_t n = b.len;
    while(n > 0 && (b.data[n - 1] == '\n' || b.data[n - 1] == '\r'))
        n--;
    if(n == 0 || memchr(b.data, '\0', n)) {
        gds_buf_free_secret(&b);
        return GDS_EINVAL;
    }
    memcpy(out, b.data, n);
    out[n] = '\0';
    gds_buf_free_secret(&b);
    return GDS_OK;
}

/* The Auditor's own application identity: self-signed, kept in DIR/own so
 * the operator can add it to the GDS trust list once. */
static gds_status load_identity(const char *dir, gds_buf *cert, gds_buf *key) {
    char cp[GDS_MAX_PATH], kp[GDS_MAX_PATH], own[GDS_MAX_PATH];
    gds_status r;
    if((r = gds_path(own, sizeof(own), "%s/own", dir)) != GDS_OK ||
       (r = gds_path(cp, sizeof(cp), "%s/cert.der", own)) != GDS_OK ||
       (r = gds_path(kp, sizeof(kp), "%s/key.der", own)) != GDS_OK)
        return r;
    if(gds_file_read(cp, GDS_MAX_CERT_SIZE, cert) == GDS_OK &&
       gds_file_read(kp, GDS_MAX_KEY_SIZE, key) == GDS_OK && x509_key_matches(cert, key))
        return GDS_OK;
    gds_buf_free(cert);
    gds_buf_free_secret(key);
    UA_String subject[2] = {UA_STRING_STATIC("O=OpenGDS Auditor"),
                            UA_STRING_STATIC("CN=OpenGDS Auditor")};
    UA_String san[2] = {UA_STRING_STATIC("URI:" APP_URI), UA_STRING_STATIC("DNS:localhost")};
    UA_ByteString c = UA_BYTESTRING_NULL, k = UA_BYTESTRING_NULL;
    if(UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER, NULL,
                            &k, &c) != UA_STATUSCODE_GOOD)
        return GDS_ECRYPTO;
    cert->data = c.data;
    cert->len = c.length;
    key->data = k.data;
    key->len = k.length;
    if((r = gds_mkdirs(own, 0700)) != GDS_OK ||
       (r = gds_file_write_atomic(kp, key->data, key->len, 0600)) != GDS_OK ||
       (r = gds_file_write_atomic(cp, cert->data, cert->len, 0644)) != GDS_OK) {
        gds_buf_free(cert);
        gds_buf_free_secret(key);
        return r;
    }
    fprintf(stderr, "created the Auditor identity %s (add it to the GDS trust list)\n", cp);
    return GDS_OK;
}

static size_t collect(ga_test *all) {
    const struct {
        const ga_test *t;
        size_t n;
    } sets[] = {{spec_access_tests, spec_access_count},
                {spec_directory_tests, spec_directory_count},
                {spec_certmgr_tests, spec_certmgr_count},
                {spec_trustlist_tests, spec_trustlist_count}};
    size_t n = 0;
    for(size_t s = 0; s < GDS_ARRAY_SIZE(sets); s++)
        for(size_t i = 0; i < sets[s].n && n < MAX_TESTS; i++)
            all[n++] = sets[s].t[i];
    return n;
}

static gds_status load_file(const char *path, size_t max, gds_buf *list, size_t *n) {
    if(*n >= GT_MAX_TRUST)
        return GDS_ETOOBIG;
    gds_status r = gds_file_read(path, max, &list[*n]);
    if(r == GDS_OK)
        (*n)++;
    return r;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat option parsing
int main(int argc, char **argv) {
    if(argc >= 2 && strcmp(argv[1], "client") == 0)
        return gdsaudit_client_main(argc - 1, argv + 1);
    if(argc < 2 || strcmp(argv[1], "gds") != 0)
        return usage(argv[0]);
    static ga_test all[MAX_TESTS];
    size_t nTests = collect(all);
    static gds_target t; /* zeroed */
    t.appUri = APP_URI;
    t.pollSeconds = 30;
    const char *work = "./gdsaudit-work", *passwordFile = NULL;
    ga_run_options opt = {NULL, false, NULL, false};
    int rc = 2;
    for(int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if(!strcmp(a, "--allow-changes")) {
            opt.allowChanges = true;
            continue;
        }
        if(!strcmp(a, "--list")) {
            for(size_t k = 0; k < nTests; k++)
                printf("%-32s %-28s %s%s\n", all[k].id, all[k].clause, all[k].title,
                       all[k].needsWrite ? " [changes]" : "");
            return 0;
        }
        if(i + 1 >= argc)
            return usage(argv[0]);
        const char *v = argv[++i];
        long n = 0;
        gds_status s = GDS_OK;
        if(!strcmp(a, "--url")) t.url = v;
        else if(!strcmp(a, "--user")) t.user = v;
        else if(!strcmp(a, "--password-file")) passwordFile = v;
        else if(!strcmp(a, "--work")) work = v;
        else if(!strcmp(a, "--only")) opt.only = v;
        else if(!strcmp(a, "--expect")) opt.expectCsv = v;
        else if(!strcmp(a, "--trust")) s = load_file(v, GDS_MAX_CERT_SIZE, t.trust, &t.trustN);
        else if(!strcmp(a, "--crl")) s = load_file(v, GDS_MAX_CRL_SIZE, t.crls, &t.crlN);
        else if(!strcmp(a, "--poll-seconds") && gds_parse_long(v, 0, 3600, &n)) t.pollSeconds = (unsigned)n;
        else return usage(argv[0]);
        if(s != GDS_OK) {
            fprintf(stderr, "%s %s: %s\n", a, v, gds_status_name(s));
            goto cleanup;
        }
    }
    if(!t.url || t.trustN == 0) {
        fprintf(stderr, "--url and at least one --trust are needed: the GDS is trusted explicitly\n");
        goto cleanup;
    }
    if(t.user && (!passwordFile || read_password(passwordFile, t.password, sizeof(t.password)) != GDS_OK)) {
        fprintf(stderr, "--user needs a readable, non-empty --password-file\n");
        goto cleanup;
    }
    unsigned char tag[8];
    if(RAND_bytes(tag, sizeof(tag)) != 1 || gds_hex(tag, sizeof(tag), t.runTag, sizeof(t.runTag)) != GDS_OK) {
        fprintf(stderr, "no random run tag\n");
        goto cleanup;
    }
    gds_status s = load_identity(work, &t.cert, &t.key);
    if(s != GDS_OK) {
        fprintf(stderr, "Auditor identity in %s: %s\n", work, gds_status_name(s));
        goto cleanup;
    }
    uac_set_quiet(true);
    printf("# target %s, run tag %s%s\n", t.url, t.runTag,
           opt.allowChanges ? "" : " (read-only: tests that change the target are Not tested)");
    rc = ga_run(all, nTests, &t, &opt);
cleanup:
    gt_clear(&t);
    return rc;
}
