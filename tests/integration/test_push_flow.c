/* OpenGDS integration test - the T2 push tracer gate (OpenGDS plan, T2):
 * the OpenGDS push engine (src/push, src/client) replaces the demo's
 * push_driver against the Auditor's push_test_server.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Usage: test_push_flow <push_test_server> <work-dir> <port>
 *
 * Cases (OPC 10000-12 v1.05.07):
 *   untrusted-server  a Server whose certificate is not trusted is refused (no TOFU)
 *   wrong-server-uri  a Server with another ApplicationUri is refused
 *   not-admin         a CertificateManager without SecurityAdmin is refused (§7.4)
 *   cancel            signing fails after the TrustList was accepted: CancelChanges
 *                     discards it and the TrustList is unchanged (§7.10.2)
 *   push              TrustList, then certificate, then ApplyChanges (§7.7.2);
 *                     the Server presents the issued certificate and a session
 *                     trusting only the CA works; the TrustList reads back as sent
 *
 * PUSH_IDENTITY_X509 is not run here: push_test_server advertises the
 * Certificate UserTokenType but has no user-token PKI, so it rejects every
 * X509IdentityToken. The push against a .NET reference Server (next T2
 * step) covers it.
 *
 * Signing uses the Auditor's test CA until the T2 daemon hook signs through
 * the OpenGDS CA (src/ca). */
#include <open62541/plugin/log_stdout.h>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

#include "client/gdsc_push.h"
#include "common/limits.h"
#include "push/push_session.h"
#include "push/push_workflows.h"
#include "test_ca.h"
#include "common/banned.h"

extern char **environ;

#define GDS_URI "urn:opengds:test:gds"
#define SERVER_URI "urn:opengds:test:pushserver"

static int failures = 0;

static void result(const char *name, bool ok, const char *detail) {
    printf("%s %s%s%s\n", ok ? "ok" : "not ok", name, detail ? " # " : "", detail ? detail : "");
    if(!ok)
        failures++;
}

/* Everything the cases share; freed once at exit */
static struct {
    const char *work;
    char url[64];
    pid_t server;
    testca_t ca, ca2;
    gds_buf caDer, crlDer, ca2Der, gdsCert, gdsKey, badCert, badKey, serverCert;
} F;

static void release(void) {
    if(F.server > 0) {
        kill(F.server, SIGTERM);
        waitpid(F.server, NULL, 0);
    }
    gds_buf_free(&F.caDer);
    gds_buf_free(&F.crlDer);
    gds_buf_free(&F.ca2Der);
    gds_buf_free(&F.gdsCert);
    gds_buf_free_secret(&F.gdsKey);
    gds_buf_free(&F.badCert);
    gds_buf_free_secret(&F.badKey);
    gds_buf_free(&F.serverCert);
    testca_free(&F.ca);
    testca_free(&F.ca2);
}

static gds_status make_pki(void) {
    char d[GDS_MAX_PATH], d2[GDS_MAX_PATH];
    gds_status s;
    if((s = gds_path(d, sizeof(d), "%s/ca", F.work)) != GDS_OK ||
       (s = gds_path(d2, sizeof(d2), "%s/ca2", F.work)) != GDS_OK ||
       (s = testca_load_or_create(&F.ca, d, "OpenGDS Auditor TEST CA")) != GDS_OK ||
       (s = testca_load_or_create(&F.ca2, d2, "OpenGDS Auditor TEST CA 2")) != GDS_OK ||
       (s = testca_cert_der(&F.ca, &F.caDer)) != GDS_OK ||
       (s = testca_crl_der(&F.ca, &F.crlDer)) != GDS_OK ||
       (s = testca_cert_der(&F.ca2, &F.ca2Der)) != GDS_OK)
        return s;
    /* The GDS's own certificate (Annex G.3) and one the Server does not map
     * to SecurityAdmin, both from the CA the Server trusts */
    if((s = testca_identity(&F.ca, d, "gds", "OpenGDS TEST GDS", GDS_URI, &F.gdsCert,
                            &F.gdsKey)) != GDS_OK)
        return s;
    return testca_identity(&F.ca, d, "intruder", "OpenGDS TEST intruder",
                           "urn:opengds:test:intruder", &F.badCert, &F.badKey);
}

static gds_status start_server(const char *bin, const char *port) {
    char pki[GDS_MAX_PATH], caf[GDS_MAX_PATH], crlf[GDS_MAX_PATH], gdsf[GDS_MAX_PATH],
        log[GDS_MAX_PATH];
    gds_status s;
    if((s = gds_path(pki, sizeof(pki), "%s/pki-push", F.work)) != GDS_OK ||
       (s = gds_path(caf, sizeof(caf), "%s/ca.der", F.work)) != GDS_OK ||
       (s = gds_path(crlf, sizeof(crlf), "%s/ca.crl", F.work)) != GDS_OK ||
       (s = gds_path(gdsf, sizeof(gdsf), "%s/ca/gds.der", F.work)) != GDS_OK ||
       (s = gds_path(log, sizeof(log), "%s/push_server.log", F.work)) != GDS_OK ||
       (s = gds_file_write_atomic(caf, F.caDer.data, F.caDer.len, 0644)) != GDS_OK ||
       (s = gds_file_write_atomic(crlf, F.crlDer.data, F.crlDer.len, 0644)) != GDS_OK)
        return s;
    posix_spawn_file_actions_t fa;
    if(posix_spawn_file_actions_init(&fa) != 0)
        return GDS_ENOMEM;
    int rc = posix_spawn_file_actions_addopen(&fa, 1, log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if(rc == 0)
        rc = posix_spawn_file_actions_adddup2(&fa, 1, 2);
    char *argv[] = {(char *)(uintptr_t)bin, "--port", (char *)(uintptr_t)port, "--pki", pki,
                    "--trust", caf, "--crl", crlf, "--admin-cert", gdsf, NULL};
    if(rc == 0)
        rc = posix_spawn(&F.server, bin, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    return rc == 0 ? GDS_OK : GDS_EIO;
}

/* The Server's own self-signed certificate, read from its store: the
 * out-of-band pin a real deployment gets at registration (no TOFU) */
static gds_status read_server_cert(void) {
    char dir[GDS_MAX_PATH], p[GDS_MAX_PATH];
    gds_status s = gds_path(dir, sizeof(dir), "%s/pki-push/ApplCerts/own/certs", F.work);
    if(s != GDS_OK)
        return s;
    DIR *d = opendir(dir);
    if(!d)
        return GDS_ENOTFOUND;
    s = GDS_ENOTFOUND;
    const struct dirent *e;
    while(s == GDS_ENOTFOUND && (e = readdir(d))) {
        if(strncmp(e->d_name, "selfsigned", 10) != 0)
            continue;
        if(gds_path(p, sizeof(p), "%s/%s", dir, e->d_name) == GDS_OK)
            s = gds_file_read(p, GDS_MAX_CERT_SIZE, &F.serverCert);
    }
    closedir(d);
    return s;
}

static gds_status wait_server(void) {
    const struct timespec step = {0, 100L * 1000L * 1000L};
    for(int i = 0; i < 100; i++) {
        if(read_server_cert() == GDS_OK && push_wait_presents(F.url, &F.serverCert, 0) ==
                                                UA_STATUSCODE_GOOD)
            return GDS_OK;
        gds_buf_free(&F.serverCert);
        nanosleep(&step, NULL);
    }
    return GDS_ENOTFOUND;
}

static push_session_cfg session_cfg(const gds_buf *trust, size_t trustN) {
    push_session_cfg c;
    memset(&c, 0, sizeof(c));
    c.endpointUrl = F.url;
    c.serverUri = SERVER_URI;
    c.applicationUri = GDS_URI;
    c.cert = &F.gdsCert;
    c.key = &F.gdsKey;
    c.trust = trust;
    c.trustN = trustN;
    c.crls = &F.crlDer;
    c.crlN = 1;
    c.identity = PUSH_IDENTITY_APP_CERT;
    return c;
}

static gds_status sign_ok(void *ctx, const gds_buf *csr, gds_buf *out) {
    (void)ctx;
    return testca_sign_csr(&F.ca, csr, SERVER_URI, TESTCA_MAX_DAYS, out);
}

static gds_status sign_refuses(void *ctx, const gds_buf *csr, gds_buf *out) {
    (void)ctx;
    (void)csr;
    (void)out;
    return GDS_ECRYPTO;
}

static push_job job_for(const UA_TrustListDataType *tl, push_sign_fn sign) {
    push_job j;
    memset(&j, 0, sizeof(j));
    j.certificateGroup = GDSC_DEFAULT_APP_GROUP;
    j.trustListNode = GDSC_DEFAULT_APP_TRUSTLIST;
    j.certificateType = GDSC_RSA_SHA256_APP_CERT;
    j.trustList = tl;
    j.sign = sign;
    j.issuers = &F.caDer;
    j.issuersN = 1;
    return j;
}

static void case_untrusted_server(void) {
    push_session_cfg c = session_cfg(&F.ca2Der, 1); /* nothing that vouches for the Server */
    push_session *s = NULL;
    UA_StatusCode r = push_session_open(&c, &s);
    result("untrusted-server", r != UA_STATUSCODE_GOOD, UA_StatusCode_name(r));
    push_session_close(s);
}

static void case_wrong_uri(void) {
    push_session_cfg c = session_cfg(&F.serverCert, 1);
    c.serverUri = "urn:opengds:test:someone-else";
    push_session *s = NULL;
    UA_StatusCode r = push_session_open(&c, &s);
    result("wrong-server-uri", r == UA_STATUSCODE_BADSERVERURIINVALID, UA_StatusCode_name(r));
    push_session_close(s);
}

static void case_not_admin(const UA_TrustListDataType *tl) {
    push_session_cfg c = session_cfg(&F.serverCert, 1);
    c.cert = &F.badCert;
    c.key = &F.badKey;
    c.applicationUri = "urn:opengds:test:intruder";
    push_session *s = NULL;
    UA_StatusCode r = push_session_open(&c, &s);
    push_report rep;
    memset(&rep, 0, sizeof(rep));
    if(r == UA_STATUSCODE_GOOD) {
        push_job j = job_for(tl, sign_ok);
        gds_status gs = push_run(push_session_client(s), &j, &rep);
        r = gs == GDS_OK ? UA_STATUSCODE_GOOD : rep.failedCode;
    }
    result("not-admin", r == UA_STATUSCODE_BADUSERACCESSDENIED && !rep.trustListUpdated,
           UA_StatusCode_name(r));
    push_report_clear(&rep);
    push_session_close(s);
}

static size_t trusted_count(UA_Client *c) {
    UA_TrustListDataType now;
    const UA_NodeId tln = GDSC_DEFAULT_APP_TRUSTLIST;
    if(gdsc_trustlist_read(c, &tln, &now) != UA_STATUSCODE_GOOD)
        return SIZE_MAX;
    size_t n = now.trustedCertificatesSize;
    UA_TrustListDataType_clear(&now);
    return n;
}

static void case_cancel(void) {
    push_session_cfg c = session_cfg(&F.serverCert, 1);
    push_session *s = NULL;
    UA_StatusCode r = push_session_open(&c, &s);
    if(r != UA_STATUSCODE_GOOD) {
        result("cancel", false, UA_StatusCode_name(r));
        return;
    }
    UA_Client *cl = push_session_client(s);
    size_t before = trusted_count(cl);
    UA_ByteString certs[2] = {{F.caDer.len, F.caDer.data}, {F.ca2Der.len, F.ca2Der.data}};
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    tl.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES;
    tl.trustedCertificates = certs;
    tl.trustedCertificatesSize = 2;
    push_job j = job_for(&tl, sign_refuses);
    push_report rep;
    gds_status gs = push_run(cl, &j, &rep);
    size_t after = trusted_count(cl);
    char d[160];
    snprintf(d, sizeof(d), "step=%s cancel=%s trusted %zu -> %zu", push_step_name(rep.failedStep),
             UA_StatusCode_name(rep.cancelCode), before, after);
    result("cancel",
           gs == GDS_ECRYPTO && rep.failedStep == PUSH_STEP_SIGN && rep.trustListUpdated &&
               rep.cancelled && rep.cancelCode == UA_STATUSCODE_GOOD && !rep.applied &&
               before != SIZE_MAX && after == before,
           d);
    push_report_clear(&rep);
    push_session_close(s);
}

static bool same_list(const UA_TrustListDataType *a, const UA_TrustListDataType *b) {
    return a->trustedCertificatesSize == b->trustedCertificatesSize &&
           a->trustedCrlsSize == b->trustedCrlsSize && a->trustedCertificatesSize == 1 &&
           a->trustedCrlsSize == 1 &&
           UA_ByteString_equal(&a->trustedCertificates[0], &b->trustedCertificates[0]) &&
           UA_ByteString_equal(&a->trustedCrls[0], &b->trustedCrls[0]);
}

/* After the push: trust only the CA, and read the TrustList back */
static void verify_after_push(const UA_TrustListDataType *sent, const char *name) {
    push_session_cfg c = session_cfg(&F.caDer, 1);
    push_session *s = NULL;
    UA_StatusCode r = push_session_open(&c, &s);
    UA_TrustListDataType back;
    UA_TrustListDataType_init(&back);
    const UA_NodeId tln = GDSC_DEFAULT_APP_TRUSTLIST;
    if(r == UA_STATUSCODE_GOOD)
        r = gdsc_trustlist_read(push_session_client(s), &tln, &back);
    result(name, r == UA_STATUSCODE_GOOD && same_list(sent, &back), UA_StatusCode_name(r));
    UA_TrustListDataType_clear(&back);
    push_session_close(s);
}

static void case_push(const UA_TrustListDataType *tl) {
    push_session_cfg c = session_cfg(&F.serverCert, 1);
    push_session *s = NULL;
    UA_StatusCode r = push_session_open(&c, &s);
    push_report rep;
    memset(&rep, 0, sizeof(rep));
    gds_status gs = GDS_EREMOTE;
    if(r == UA_STATUSCODE_GOOD) {
        push_job j = job_for(tl, sign_ok);
        gs = push_run(push_session_client(s), &j, &rep);
        r = rep.failedCode;
    }
    push_session_close(s);
    char d[160];
    snprintf(d, sizeof(d), "failed step=%s %s", push_step_name(rep.failedStep),
             UA_StatusCode_name(r));
    result("push", gs == GDS_OK && rep.trustListUpdated && rep.certificateUpdated && rep.applied,
           d);
    if(gs == GDS_OK) {
        r = push_wait_presents(F.url, &rep.issued, 10000);
        result("push-presents-issued", r == UA_STATUSCODE_GOOD, UA_StatusCode_name(r));
        verify_after_push(tl, "push-ca-trust-only");
    }
    push_report_clear(&rep);
}

static void run_cases(void) {
    UA_ByteString caBs = {F.caDer.len, F.caDer.data}, crlBs = {F.crlDer.len, F.crlDer.data};
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    tl.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    tl.trustedCertificates = &caBs;
    tl.trustedCertificatesSize = 1;
    tl.trustedCrls = &crlBs;
    tl.trustedCrlsSize = 1;
    case_untrusted_server();
    case_wrong_uri();
    case_not_admin(&tl);
    case_cancel();
    case_push(&tl);
}

int main(int argc, char **argv) {
    if(argc != 4 || strlen(argv[3]) > 5) {
        fprintf(stderr, "usage: %s <push_test_server> <work-dir> <port>\n", argv[0]);
        return 2;
    }
    F.work = argv[2];
    atexit(release);
    if(gds_path(F.url, sizeof(F.url), "opc.tcp://127.0.0.1:%s", argv[3]) != GDS_OK ||
       gds_mkdirs(F.work, 0700) != GDS_OK)
        return 2;
    gds_status s = make_pki();
    if(s == GDS_OK)
        s = start_server(argv[1], argv[3]);
    if(s == GDS_OK)
        s = wait_server();
    if(s != GDS_OK) {
        fprintf(stderr, "setup failed: %s (see %s/push_server.log)\n", gds_status_name(s),
                F.work);
        return 1;
    }
    run_cases();
    if(failures)
        fprintf(stderr, "%d case(s) failed; server log in %s/push_server.log\n", failures,
                F.work);
    return failures ? 1 : 0;
}
