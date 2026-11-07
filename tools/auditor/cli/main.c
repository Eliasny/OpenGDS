/* OpenGDS Auditor - command line (Auditor plan cli/main.c).
 *
 *   gdsaudit gds --url opc.tcp://host:4840 --trust ca.der [--trust ...]
 *                [--crl ca.crl] [--user admin --password-file FILE]
 *                [--work DIR] [--allow-changes] [--only PREFIX]
 *                [--expect FILE.csv] [--poll-seconds N] [--list]
 *
 *   gdsaudit client [options] -- TRIGGER ARGV...   (profile_client/client_main.c)
 *
 *   gdsaudit server --url opc.tcp://host:4840 (--server-cert srv.der | --tofu)
 *                [--admin-cert C --admin-key K | --admin-user U --admin-password-file F]
 *                [--user U --user-password-file F] [--work DIR]
 *                [--allow-changes] [--only PREFIX] [--expect FILE.csv] [--list]
 *
 * Every subcommand also takes, before any "--":
 *   --events FILE  the engine's event stream as JSON Lines (engine.h)
 *   --report DIR   DIR/report.html and DIR/junit.xml at the end of the run
 * SIGINT and SIGTERM abort the run: later tests are Not tested and the
 * server profile still restores the target; a second signal kills.
 * SIGUSR1 pauses before the next test, SIGUSR2 resumes.
 *
 * gds runs the GDS profile (the T0 spec tests) against a GDS; server runs
 * the server profile (docs/auditor/server-profile.md) against a push-managed
 * Server, playing its CertificateManager. Both print TAP.
 * Exit codes: 0 all passed, 1 a test failed (or, with --expect, a verdict
 * differs from the file), 2 the run could not be done, 3 some Not tested.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "common/limits.h"
#include "common/safeint.h"
#include "client_profile.h"
#include "gds_target.h"
#include "results.h"
#include "spec_tests.h"
#include "srv_target.h"
#include "srv_tests.h"
#include "common/banned.h"

#define APP_URI "urn:opengds:auditor"
#define MAX_TESTS 160
#define MAX_SERVER_TESTS 128

static int usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s gds --url URL --trust CA.der [--trust ...] [--crl CRL] [--user U\n"
            "       --password-file F] [--work DIR] [--allow-changes] [--only PREFIX]\n"
            "       [--expect FILE.csv] [--poll-seconds N] [--list]\n"
            "   or: %s server --url URL (--server-cert SRV.der | --tofu)\n"
            "       [--admin-cert C --admin-key K | --admin-user U --admin-password-file F]\n"
            "       [--user U --user-password-file F] [--work DIR] [--allow-changes] [--only PREFIX]\n"
            "       [--target-trust CA.der]... [--target-crl CRL]...\n"
            "       [--expect FILE.csv] [--list] [--init-only] [--slow] [--stop-after ID]\n"
            "       %s client --help\n"
            "Every subcommand also takes --events FILE (JSON Lines) and --report DIR.\n",
            argv0, argv0, argv0);
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
                {spec_trustlist_tests, spec_trustlist_count},
                {spec_query_tests, spec_query_count},
                {spec_revoke_tests, spec_revoke_count},
                {spec_keypair_tests, spec_keypair_count},
                {spec_tlwrite_tests, spec_tlwrite_count},
                {spec_keycred_tests, spec_keycred_count},
                {spec_authz_tests, spec_authz_count},
                {spec_events_tests, spec_events_count},
                {spec_roles_tests, spec_roles_count},
                {spec_model_tests, spec_model_count}};
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
static int gds_main(int argc, char **argv) {
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

static size_t collect_server(ga_test *all) {
    const struct {
        const ga_test *t;
        size_t n;
    } sets[] = {{srv_security_tests, srv_security_count},
                {srv_capabilities_tests, srv_capabilities_count},
                {srv_trustlist_tests, srv_trustlist_count},
                {srv_csr_tests, srv_csr_count},
                {srv_update_tests, srv_update_count},
                {srv_transaction_tests, srv_transaction_count},
                {srv_wire_tests, srv_wire_count},
                {srv_restore_tests, srv_restore_count}}; /* restore stays last */
    size_t n = 0;
    for(size_t s = 0; s < GDS_ARRAY_SIZE(sets); s++)
        for(size_t i = 0; i < sets[s].n && n < MAX_SERVER_TESTS; i++)
            all[n++] = sets[s].t[i];
    return n;
}

/* The run's test PKI: ca (with CRL) and peer-good, under DIR/ca. */
static gds_status load_test_pki(srv_target *t, const char *work) {
    char dir[GDS_MAX_PATH];
    gds_status r = gds_path(dir, sizeof(dir), "%s/ca", work);
    if(r == GDS_OK)
        r = testca_load_or_create(&t->ca, dir, "OpenGDS Auditor TEST CA");
    if(r == GDS_OK)
        r = testca_cert_der(&t->ca, &t->caDer);
    if(r == GDS_OK)
        r = testca_crl_der(&t->ca, &t->caCrl);
    if(r == GDS_OK)
        r = testca_identity(&t->ca, dir, "peer-good", "OpenGDS Auditor TEST peer",
                            "urn:opengds:auditor:peer-good", &t->peerCert, &t->peerKey);
    return r;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat option parsing
static int server_main(int argc, char **argv) {
    static ga_test all[MAX_SERVER_TESTS];
    size_t nTests = collect_server(all);
    static srv_target t; /* zeroed */
    t.appUri = APP_URI;
    const char *work = "./gdsaudit-work", *adminPwFile = NULL, *userPwFile = NULL;
    const char *serverCert = NULL, *adminCert = NULL, *adminKey = NULL;
    bool tofu = false, initOnly = false;
    ga_run_options opt = {NULL, false, NULL, false};
    int rc = 2;
    for(int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if(!strcmp(a, "--allow-changes")) {
            opt.allowChanges = true;
            continue;
        }
        if(!strcmp(a, "--tofu")) {
            tofu = true;
            continue;
        }
        if(!strcmp(a, "--slow")) { /* run the tests flagged slow (catalogue Flags) */
            t.slow = true;
            continue;
        }
        if(!strcmp(a, "--init-only")) { /* create the identity and test PKI, then stop */
            initOnly = true;
            continue;
        }
        if(!strcmp(a, "--list")) {
            for(size_t k = 0; k < nTests; k++)
                printf("%-14s %-34s %s%s\n", all[k].id, all[k].clause, all[k].title,
                       all[k].needsWrite ? " [changes]" : "");
            return 0;
        }
        if(i + 1 >= argc)
            return usage(argv[0]);
        const char *v = argv[++i];
        if(!strcmp(a, "--url")) t.url = v;
        else if(!strcmp(a, "--admin-user")) t.adminUser = v;
        else if(!strcmp(a, "--admin-password-file")) adminPwFile = v;
        else if(!strcmp(a, "--admin-cert")) adminCert = v;
        else if(!strcmp(a, "--admin-key")) adminKey = v;
        else if(!strcmp(a, "--user")) t.userName = v;
        else if(!strcmp(a, "--user-password-file")) userPwFile = v;
        else if(!strcmp(a, "--server-cert")) serverCert = v;
        else if(!strcmp(a, "--target-trust") || !strcmp(a, "--target-crl")) {
            bool crl = !strcmp(a, "--target-crl");
            gds_buf *list = crl ? t.targetCrl : t.targetTrust;
            size_t *n = crl ? &t.targetCrlN : &t.targetTrustN;
            if(*n >= ST_MAX_TARGET_TRUST ||
               gds_file_read(v, crl ? GDS_MAX_CRL_SIZE : GDS_MAX_CERT_SIZE, &list[*n]) != GDS_OK) {
                fprintf(stderr, "%s %s: cannot read (at most %d)\n", a, v, ST_MAX_TARGET_TRUST);
                goto cleanup;
            }
            (*n)++;
        }
        else if(!strcmp(a, "--work")) work = v;
        else if(!strcmp(a, "--only")) opt.only = t.only = v;
        else if(!strcmp(a, "--expect")) opt.expectCsv = v;
        else if(!strcmp(a, "--stop-after")) { /* the self-test's mutant runs */
            size_t k = 0;
            while(k < nTests && strcmp(all[k].id, v) != 0)
                k++;
            if(k == nTests)
                return usage(argv[0]);
            nTests = k + 1;
        } else return usage(argv[0]);
    }
    if(!initOnly && (!t.url || (!serverCert == !tofu))) {
        fprintf(stderr, "--url and one of --server-cert or --tofu (test setups only) are needed\n");
        goto cleanup;
    }
    if(t.adminUser && (!adminPwFile ||
                       read_password(adminPwFile, t.adminPassword, sizeof(t.adminPassword)) != GDS_OK)) {
        fprintf(stderr, "--admin-user needs a readable, non-empty --admin-password-file\n");
        goto cleanup;
    }
    if(t.userName && (!userPwFile ||
                      read_password(userPwFile, t.userPassword, sizeof(t.userPassword)) != GDS_OK)) {
        fprintf(stderr, "--user needs a readable, non-empty --user-password-file\n");
        goto cleanup;
    }
    if(!adminCert != !adminKey) {
        fprintf(stderr, "--admin-cert and --admin-key go together\n");
        goto cleanup;
    }
    gds_status s = load_identity(work, &t.cert, &t.key);
    if(s != GDS_OK) {
        fprintf(stderr, "Auditor identity in %s: %s\n", work, gds_status_name(s));
        goto cleanup;
    }
    if(adminCert) {
        s = gds_file_read(adminCert, GDS_MAX_CERT_SIZE, &t.adminCert);
        if(s == GDS_OK)
            s = gds_file_read(adminKey, GDS_MAX_KEY_SIZE, &t.adminKey);
        if(s == GDS_OK && !x509_key_matches(&t.adminCert, &t.adminKey))
            s = GDS_EINVAL;
    } else {
        /* <work>/admin/own: the identity the target maps to SecurityAdmin */
        char dir[GDS_MAX_PATH];
        s = gds_path(dir, sizeof(dir), "%s/admin", work);
        if(s == GDS_OK)
            s = load_identity(dir, &t.adminCert, &t.adminKey);
    }
    if(s != GDS_OK) {
        fprintf(stderr, "admin identity: %s\n", gds_status_name(s));
        goto cleanup;
    }
    if((s = load_test_pki(&t, work)) != GDS_OK) {
        fprintf(stderr, "test PKI in %s/ca: %s\n", work, gds_status_name(s));
        goto cleanup;
    }
    if(initOnly) {
        printf("Auditor identity %s/own/cert.der, admin identity %s/admin/own/cert.der and "
               "test PKI %s/ca ready\n", work, work, work);
        rc = 0;
        goto cleanup;
    }
    uac_set_quiet(true);
    if(serverCert) {
        s = gds_file_read(serverCert, GDS_MAX_CERT_SIZE, &t.pinned);
    } else {
        UA_ByteString b = UA_BYTESTRING_NULL;
        s = uac_fetch_server_cert(t.url, &b) == UA_STATUSCODE_GOOD ? GDS_OK : GDS_ENOTFOUND;
        t.pinned.data = b.data;
        t.pinned.len = b.length;
    }
    if(s != GDS_OK) {
        fprintf(stderr, "target certificate: %s\n", gds_status_name(s));
        goto cleanup;
    }
    printf("# target %s%s%s\n", t.url, tofu ? " (trusted on first use: test setups only)" : "",
           opt.allowChanges ? "" : " (read-only: tests that change the target are Not tested)");
    rc = ga_run(all, nTests, &t, &opt);
    /* --only can leave SRV-RESTORE out: never leave the target changed */
    if(t.snapTaken && !t.restored) {
        char why[384];
        if(st_restore(&t, why, sizeof(why)) == UA_STATUSCODE_GOOD) {
            printf("# restore: %s\n", why[0] ? why : "snapshot pushed back and applied");
        } else {
            printf("# restore FAILED: %s\n", why);
            rc = 1;
        }
    }
cleanup:
    st_clear(&t);
    return rc;
}

/* Front-end options every subcommand takes (engine.h): taken out of argv
 * before the subcommand parses the rest. */
typedef struct {
    const char *events, *report, *target;
    FILE *eventsFile;
    ga_results results;
} front_end;

static bool take_front_end_options(int *argc, char **argv, front_end *fe) {
    int out = 1;
    bool ok = true, rest = false;
    for(int i = 1; i < *argc; i++) {
        const char *a = argv[i];
        if(rest || !strcmp(a, "--")) {
            rest = true;
            argv[out++] = argv[i];
            continue;
        }
        bool ev = !strcmp(a, "--events"), rep = !strcmp(a, "--report");
        if(ev || rep) {
            if(i + 1 >= *argc) {
                fprintf(stderr, "%s needs a value\n", a);
                ok = false;
                break;
            }
            *(ev ? &fe->events : &fe->report) = argv[++i];
            continue;
        }
        if((!strcmp(a, "--url") || !strcmp(a, "--listen")) && i + 1 < *argc)
            fe->target = argv[i + 1];
        argv[out++] = argv[i];
    }
    argv[out] = NULL;
    *argc = out;
    return ok;
}

static void on_signal(int sig) {
    if(sig == SIGUSR1)
        ga_request_pause(true);
    else if(sig == SIGUSR2)
        ga_request_pause(false);
    else
        ga_request_abort();
}

static void install_abort_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sa.sa_flags = (int)SA_RESETHAND; /* a second signal kills */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_flags = 0; /* pause and resume may come many times */
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}

static bool start_front_end(front_end *fe, const char *profile) {
    char listen[64];
    const char *target = fe->target;
    if(!strcmp(profile, "client")) {
        snprintf(listen, sizeof(listen), "fake GDS on port %s", target ? target : "4850");
        target = listen;
    }
    ga_set_run_info(profile, target);
    if(fe->events) {
        fe->eventsFile = fopen(fe->events, "we"); /* e: not inherited by triggers */
        if(!fe->eventsFile) {
            perror(fe->events);
            return false;
        }
        (void)ga_add_event_sink(ga_jsonl_sink, fe->eventsFile);
    }
    if(fe->report)
        (void)ga_add_event_sink(ga_results_sink, &fe->results);
    install_abort_handler();
    return true;
}

/* Reports after the run; a failed report makes the run unfinished (2). */
static int finish_front_end(front_end *fe, int rc) {
    if(fe->eventsFile && fclose(fe->eventsFile) != 0) {
        fprintf(stderr, "%s: write failed\n", fe->events);
        rc = 2;
    }
    if(fe->report && fe->results.profile) {
        char err[512];
        if(ga_report_write_dir(fe->report, &fe->results, err, sizeof(err)))
            printf("# report: %s/report.html, %s/junit.xml\n", fe->report, fe->report);
        else {
            fprintf(stderr, "report: %s\n", err);
            rc = 2;
        }
    }
    ga_results_free(&fe->results);
    ga_clear_event_sinks();
    return rc;
}

int main(int argc, char **argv) {
    static front_end fe;
    if(argc < 2)
        return usage(argv[0]);
    const char *profile = argv[1];
    if(strcmp(profile, "client") != 0 && strcmp(profile, "gds") != 0 &&
       strcmp(profile, "server") != 0)
        return usage(argv[0]);
    if(!take_front_end_options(&argc, argv, &fe) || !start_front_end(&fe, profile))
        return 2;
    int rc;
    if(strcmp(profile, "client") == 0)
        rc = gdsaudit_client_main(argc - 1, argv + 1);
    else if(strcmp(profile, "gds") == 0)
        rc = gds_main(argc, argv);
    else
        rc = server_main(argc, argv);
    return finish_front_end(&fe, rc);
}
