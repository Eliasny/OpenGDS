/* OpenGDS spec tests - OPC 10000-12 v1.05.07 Annex G "Application Setup"
 * (OpenGDS plan W3: tests/spec/test_spec_annex_g.c), with Reverse Connect
 * (OPC 10000-6 v1.05.07 §7.1.3) for devices behind firewalls.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Usage: test_spec_annex_g <push_test_server> <mock_gds> <work-dir> <port>
 * Ports port .. port+4 are used.
 *
 * G.2 PushManagement setup (src/push/push_setup.c) against the Auditor's
 * push_test_server --setup (setup credentials setup:secret):
 *   annexg.g2.state             a new device: State NoConfiguration,
 *                               InApplicationSetup TRUE (G.2 ¶2, ¶4)
 *   annexg.g2.not-preauthorized a device whose certificate is not the
 *                               pre-authorized one is refused before any
 *                               credential or registration (G.2 last ¶; §7.5)
 *   annexg.g2.cancel-in-setup   a push that fails is cancelled (§7.10.11) and
 *                               the device stays in setup (G.2 ¶9)
 *   annexg.g2.setup             register, push, configure the SecurityAdmin
 *                               Role, leave setup (G.2 ¶9); the device then
 *                               presents the issued certificate
 *   annexg.g2.admin-rule        the Role holds an Application rule with our
 *                               ApplicationUri (OPC 10000-18 §4.4.3), and our
 *                               certificate alone is SecurityAdmin (G.3)
 *   annexg.g2.not-in-setup      a configured device is not set up again
 * Reverse Connect (the setup device connects out to the GDS):
 *   annexg.rc.wrong-uri         a Server announcing another ApplicationUri is
 *                               refused (6 §7.1.3 Table 78 "Reverse Hello")
 *   annexg.rc.setup             the whole G.2 setup over Reverse Connect
 * G.1 PullManagement setup (src/client/gdsc_pull_agent.c) against the
 * Auditor's mock_gds:
 *   annexg.g1.untrusted-gds     no connection to a GDS the application does
 *                               not trust, so no secret is sent (G.1 ¶2, ¶4)
 *   annexg.g1.first             register with ApplicationAdmin credentials,
 *                               new key pair + CSR, certificate, trust list,
 *                               persisted together (G.1; §7.6 Table 21)
 *   annexg.g1.renew-check       the next run uses the issued certificate in
 *                               lieu of the credentials (G.1 last ¶) and
 *                               finds nothing to update
 *   annexg.g1.pending           FinishRequest still pending after the repeat
 *                               count: the RequestId is persisted and the next
 *                               run finishes it (Table 21 SigningRequestPending)
 */
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>

#include <openssl/x509.h>

#include "client/gdsc_gds.h"
#include "client/gdsc_pull_agent.h"
#include "client/gdsc_push.h"
#include "client/gdsc_session.h"
#include "common/limits.h"
#include "push/push_setup.h"
#include "test_ca.h"
#include "common/banned.h"

extern char **environ;

#define GDS_URI "urn:opengds:test:gds"
#define SERVER_URI "urn:opengds:test:pushserver"
#define APP_URI "urn:opengds:test:pull-agent"
#define APP2_URI "urn:opengds:test:pull-agent-pending"
#define MAX_PROCS 4

static int failures = 0;

static void result(const char *name, bool ok, const char *detail) {
    printf("%s %s%s%s\n", ok ? "ok" : "not ok", name, detail ? " # " : "", detail ? detail : "");
    fflush(stdout);
    if(!ok)
        failures++;
}

static struct {
    const char *work;
    long port;
    char urlSetup[64], urlReverseDevice[64], urlMock[64], urlMock2[64];
    UA_UInt16 reversePort;
    pid_t procs[MAX_PROCS];
    size_t procsN;
    testca_t ca, ca2;
    gds_buf caDer, crlDer, ca2Der, gdsCert, gdsKey;
    gds_buf setupDeviceCert, reverseDeviceCert, password;
} F;

static void release(void) {
    for(size_t i = 0; i < F.procsN; i++) {
        kill(F.procs[i], SIGTERM);
        waitpid(F.procs[i], NULL, 0);
    }
    gds_buf_free(&F.caDer);
    gds_buf_free(&F.crlDer);
    gds_buf_free(&F.ca2Der);
    gds_buf_free(&F.gdsCert);
    gds_buf_free_secret(&F.gdsKey);
    gds_buf_free(&F.setupDeviceCert);
    gds_buf_free(&F.reverseDeviceCert);
    gds_buf_free(&F.password);
    testca_free(&F.ca);
    testca_free(&F.ca2);
}

/* ---------------- fixtures ---------------- */

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
    if((s = gds_buf_dup("secret", 6, &F.password)) != GDS_OK)
        return s;
    /* The GDS's own certificate, from the CA every device will trust */
    return testca_identity(&F.ca, d, "gds", "OpenGDS TEST GDS", GDS_URI, &F.gdsCert, &F.gdsKey);
}

static gds_status spawn(char *const argv[], const char *logName) {
    if(F.procsN == MAX_PROCS)
        return GDS_ENOMEM;
    char log[GDS_MAX_PATH];
    gds_status s = gds_path(log, sizeof(log), "%s/%s.log", F.work, logName);
    if(s != GDS_OK)
        return s;
    posix_spawn_file_actions_t fa;
    if(posix_spawn_file_actions_init(&fa) != 0)
        return GDS_ENOMEM;
    int rc = posix_spawn_file_actions_addopen(&fa, 1, log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if(rc == 0)
        rc = posix_spawn_file_actions_adddup2(&fa, 1, 2);
    if(rc == 0)
        rc = posix_spawn(&F.procs[F.procsN], argv[0], &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    if(rc != 0)
        return GDS_EIO;
    F.procsN++;
    return GDS_OK;
}

/* push_test_server --setup on `port`; reverse: also Reverse Connect to us */
static gds_status start_device(const char *bin, long port, const char *name, bool reverse) {
    char pki[GDS_MAX_PATH], p[8], rc[64];
    if(gds_path(pki, sizeof(pki), "%s/pki-%s", F.work, name) != GDS_OK ||
       gds_path(p, sizeof(p), "%ld", port) != GDS_OK ||
       gds_path(rc, sizeof(rc), "opc.tcp://127.0.0.1:%u", (unsigned)F.reversePort) != GDS_OK)
        return GDS_EINVAL;
    char *argv[] = {(char *)(uintptr_t)bin, "--port", p, "--pki", pki, "--setup",
                    "--admin", "setup:secret", reverse ? "--reverse-connect" : NULL, rc, NULL};
    return spawn(argv, name);
}

static gds_status start_mock(const char *bin, long port, const char *approveAfter,
                             const char *name) {
    char ca[GDS_MAX_PATH], p[8];
    if(gds_path(ca, sizeof(ca), "%s/ca", F.work) != GDS_OK ||
       gds_path(p, sizeof(p), "%ld", port) != GDS_OK)
        return GDS_EINVAL;
    char *argv[] = {(char *)(uintptr_t)bin, "--port", p, "--ca-dir", ca, "--user",
                    "registrar:secret", "--approve-after", (char *)(uintptr_t)approveAfter,
                    "--anonymous", NULL};
    return spawn(argv, name);
}

/* The device's first self-signed certificate, read from its store: what the
 * installer registers as pre-authorized (Annex G.2, last paragraph) */
static gds_status read_device_cert(const char *name, gds_buf *out) {
    char dir[GDS_MAX_PATH], p[GDS_MAX_PATH];
    if(gds_path(dir, sizeof(dir), "%s/pki-%s/ApplCerts/own/certs", F.work, name) != GDS_OK)
        return GDS_EINVAL;
    const struct timespec step = {0, 100L * 1000L * 1000L};
    for(int i = 0; i < 100; i++) {
        DIR *d = opendir(dir);
        const struct dirent *e;
        gds_status s = GDS_ENOTFOUND;
        while(d && s == GDS_ENOTFOUND && (e = readdir(d))) {
            if(strncmp(e->d_name, "selfsigned", 10) == 0 &&
               gds_path(p, sizeof(p), "%s/%s", dir, e->d_name) == GDS_OK)
                s = gds_file_read(p, GDS_MAX_CERT_SIZE, out);
        }
        if(d)
            closedir(d);
        if(s == GDS_OK)
            return s;
        nanosleep(&step, NULL);
    }
    return GDS_ENOTFOUND;
}

/* GetEndpoints answers: the server is up */
static gds_status wait_up(const char *url) {
    const struct timespec step = {0, 100L * 1000L * 1000L};
    for(int i = 0; i < 150; i++) {
        UA_Client *c = UA_Client_new();
        size_t n = 0;
        UA_EndpointDescription *eps = NULL;
        UA_StatusCode r = UA_Client_getEndpoints(c, url, &n, &eps);
        UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
        UA_Client_delete(c);
        /* a cert-less client gets Bad_IdentityTokenRejected from a Server
         * with secured endpoints only: it answered, so it is up */
        if(r == UA_STATUSCODE_GOOD || r == UA_STATUSCODE_BADIDENTITYTOKENREJECTED)
            return GDS_OK;
        nanosleep(&step, NULL);
    }
    return GDS_ENOTFOUND;
}

/* ---------------- G.2 push setup ---------------- */

typedef struct {
    int calls;
    char uri[GDS_MAX_APPLICATION_URI];
} enroll_rec;

/* The GDS side of the setup, played by the test: the device's record, and
 * the trust list of the test CA */
static gds_status enroll_stub(void *ctx, const UA_ApplicationDescription *ad, const char *url,
                              const UA_ByteString *serverCert, UA_TrustListDataType *tl) {
    (void)url;
    enroll_rec *e = ctx;
    e->calls++;
    if(ad->applicationUri.length >= sizeof(e->uri) || serverCert->length == 0)
        return GDS_EINVAL;
    memcpy(e->uri, ad->applicationUri.data, ad->applicationUri.length);
    e->uri[ad->applicationUri.length] = '\0';
    UA_TrustListDataType_init(tl);
    UA_ByteString c = {F.caDer.len, F.caDer.data}, l = {F.crlDer.len, F.crlDer.data};
    tl->specifiedLists = UA_TRUSTLISTMASKS_ALL;
    UA_StatusCode r = UA_Array_copy(&c, 1, (void **)&tl->trustedCertificates,
                                    &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD) {
        tl->trustedCertificatesSize = 1;
        r = UA_Array_copy(&l, 1, (void **)&tl->trustedCrls, &UA_TYPES[UA_TYPES_BYTESTRING]);
    }
    if(r == UA_STATUSCODE_GOOD)
        tl->trustedCrlsSize = 1;
    return r == UA_STATUSCODE_GOOD ? GDS_OK : GDS_ENOMEM;
}

static gds_status sign_ok(void *ctx, const gds_buf *csr, gds_buf *out, gds_buf *iss,
                          size_t *issN) {
    (void)ctx;
    (void)iss;
    *issN = 0;
    return testca_sign_csr(&F.ca, csr, SERVER_URI, TESTCA_MAX_DAYS, out);
}

static gds_status sign_refuses(void *ctx, const gds_buf *csr, gds_buf *out, gds_buf *iss,
                               size_t *issN) {
    (void)ctx, (void)csr, (void)out, (void)iss, (void)issN;
    return GDS_ECRYPTO;
}

static push_setup_job setup_job(const char *url, const gds_buf *deviceCert, enroll_rec *e,
                                push_sign_fn sign) {
    push_setup_job j;
    memset(&j, 0, sizeof(j));
    j.conn.endpointUrl = url;
    j.conn.applicationUri = GDS_URI;
    j.conn.cert = &F.gdsCert;
    j.conn.key = &F.gdsKey;
    j.serverUri = SERVER_URI;
    j.deviceCert = deviceCert;
    j.trust = &F.caDer;
    j.trustN = 1;
    j.crls = &F.crlDer;
    j.crlN = 1;
    j.setupIdentity = GDSC_IDENTITY_USERNAME;
    j.setupUser = "setup";
    j.setupPassword = &F.password;
    j.enroll = enroll_stub;
    j.enrollCtx = e;
    j.sign = sign;
    j.certificateGroup = GDSC_DEFAULT_APP_GROUP;
    j.trustListNode = GDSC_DEFAULT_APP_TRUSTLIST;
    j.certificateType = GDSC_RSA_SHA256_APP_CERT;
    j.settleMs = 15000;
    return j;
}

static UA_StatusCode probe(const char *url, const gds_buf *trust, gdsc_identity id,
                           push_setup_state *st) {
    gdsc_session_cfg c;
    memset(&c, 0, sizeof(c));
    c.endpointUrl = url;
    c.serverUri = SERVER_URI;
    c.applicationUri = GDS_URI;
    c.cert = &F.gdsCert;
    c.key = &F.gdsKey;
    c.trust = trust;
    c.trustN = 1;
    c.identity = id;
    c.userName = id == GDSC_IDENTITY_USERNAME ? "setup" : NULL;
    c.password = id == GDSC_IDENTITY_USERNAME ? &F.password : NULL;
    gdsc_session *s = NULL;
    UA_StatusCode r = gdsc_session_open(&c, &s);
    if(r == UA_STATUSCODE_GOOD)
        r = push_setup_probe(gdsc_session_client(s), st);
    gdsc_session_close(s);
    return r;
}

static void describe(char *d, size_t len, const push_setup_report *rep, gds_status s) {
    snprintf(d, len, "%s; step %s: %s; push step %s", gds_status_name(s),
             push_setup_step_name(rep->failedStep), UA_StatusCode_name(rep->failedCode),
             push_step_name(rep->push.failedStep));
}

static void case_g2_state(void) {
    push_setup_state st;
    memset(&st, 0, sizeof(st));
    UA_StatusCode r = probe(F.urlSetup, &F.setupDeviceCert, GDSC_IDENTITY_USERNAME, &st);
    char d[96];
    snprintf(d, sizeof(d), "%s state=%d hasInSetup=%d inSetup=%d", UA_StatusCode_name(r),
             (int)st.state, st.hasInSetup, st.inSetup);
    result("annexg.g2.state", r == UA_STATUSCODE_GOOD && push_setup_in_setup(&st), d);
}

static void case_g2_not_preauthorized(void) {
    enroll_rec e = {0, ""};
    push_setup_job j = setup_job(F.urlSetup, &F.ca2Der, &e, sign_ok);
    push_setup_report rep;
    gds_status s = push_setup_run(&j, &rep);
    char d[200];
    describe(d, sizeof(d), &rep, s);
    result("annexg.g2.not-preauthorized",
           s != GDS_OK && rep.failedStep == PUSH_SETUP_STEP_CONNECT && e.calls == 0, d);
    push_setup_report_clear(&rep);
}

static void case_g2_cancel(void) {
    enroll_rec e = {0, ""};
    push_setup_job j = setup_job(F.urlSetup, &F.setupDeviceCert, &e, sign_refuses);
    push_setup_report rep;
    gds_status s = push_setup_run(&j, &rep);
    push_setup_state st;
    memset(&st, 0, sizeof(st));
    memset(&st, 0, sizeof(st));
    UA_StatusCode r = probe(F.urlSetup, &F.setupDeviceCert, GDSC_IDENTITY_USERNAME, &st);
    char d[240];
    describe(d, sizeof(d), &rep, s);
    result("annexg.g2.cancel-in-setup",
           s != GDS_OK && rep.failedStep == PUSH_SETUP_STEP_PUSH && rep.push.cancelled &&
               rep.push.cancelCode == UA_STATUSCODE_GOOD && !rep.push.applied &&
               r == UA_STATUSCODE_GOOD && push_setup_in_setup(&st),
           d);
    push_setup_report_clear(&rep);
}

/* The full G.2 setup on url; the rest of the checks when it worked */
static bool run_setup(const char *name, push_setup_job *j, enroll_rec *e, gds_buf *issued) {
    push_setup_report rep;
    gds_status s = push_setup_run(j, &rep);
    char d[240];
    describe(d, sizeof(d), &rep, s);
    bool ok = s == GDS_OK && rep.done && rep.adminAdded && rep.push.trustListUpdated &&
              rep.push.certificateUpdated && rep.push.applied && e->calls == 1 &&
              strcmp(e->uri, SERVER_URI) == 0 && push_setup_in_setup(&rep.before) &&
              rep.after.state == UA_SERVERSTATE_RUNNING && !rep.after.inSetup;
    result(name, ok, d);
    if(ok && issued)
        ok = gds_buf_dup(rep.push.issued.data, rep.push.issued.len, issued) == GDS_OK;
    push_setup_report_clear(&rep);
    return ok;
}

static void case_g2_setup(void) {
    enroll_rec e = {0, ""};
    push_setup_job j = setup_job(F.urlSetup, &F.setupDeviceCert, &e, sign_ok);
    gds_buf issued = {0};
    if(!run_setup("annexg.g2.setup", &j, &e, &issued))
        return;
    const UA_NodeId t = GDSC_RSA_SHA256_APP_CERT;
    UA_StatusCode r = gdsc_wait_presents(F.urlSetup, &t, &issued, 10000);
    result("annexg.g2.presents-issued", r == UA_STATUSCODE_GOOD, UA_StatusCode_name(r));

    /* Our certificate alone, through the CA: SecurityAdmin via the rule */
    gdsc_session_cfg c;
    memset(&c, 0, sizeof(c));
    c.endpointUrl = F.urlSetup;
    c.serverUri = SERVER_URI;
    c.applicationUri = GDS_URI;
    c.cert = &F.gdsCert;
    c.key = &F.gdsKey;
    c.trust = &F.caDer;
    c.trustN = 1;
    c.crls = &F.crlDer;
    c.crlN = 1;
    c.identity = GDSC_IDENTITY_APP_CERT;
    gdsc_session *s = NULL;
    r = gdsc_session_open(&c, &s);
    UA_IdentityMappingRuleType *rules = NULL;
    size_t n = 0;
    bool found = false;
    if(r == UA_STATUSCODE_GOOD)
        r = push_setup_admin_identities(gdsc_session_client(s), &rules, &n);
    UA_String want = UA_STRING(GDS_URI);
    for(size_t i = 0; i < n; i++)
        found = found || (rules[i].criteriaType == UA_IDENTITYCRITERIATYPE_APPLICATION &&
                          UA_String_equal(&rules[i].criteria, &want));
    UA_Array_delete(rules, n, &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]);
    /* SecurityAdmin may read the TrustList (12 §7.8.2.1) */
    UA_TrustListDataType back;
    UA_TrustListDataType_init(&back);
    const UA_NodeId tln = GDSC_DEFAULT_APP_TRUSTLIST;
    if(r == UA_STATUSCODE_GOOD)
        r = gdsc_trustlist_read(gdsc_session_client(s), &tln, &back);
    UA_TrustListDataType_clear(&back);
    gdsc_session_close(s);
    result("annexg.g2.admin-rule", r == UA_STATUSCODE_GOOD && found, UA_StatusCode_name(r));

    /* Set up again: the device is configured now (it presents the issued
     * certificate, trusted through the CA) */
    enroll_rec e2 = {0, ""};
    push_setup_job j2 = setup_job(F.urlSetup, &F.setupDeviceCert, &e2, sign_ok);
    push_setup_report rep;
    gds_status gs = push_setup_run(&j2, &rep);
    char d[240];
    describe(d, sizeof(d), &rep, gs);
    result("annexg.g2.not-in-setup",
           gs != GDS_OK && rep.failedStep == PUSH_SETUP_STEP_STATE &&
               rep.failedCode == UA_STATUSCODE_BADINVALIDSTATE && e2.calls == 0,
           d);
    push_setup_report_clear(&rep);
    gds_buf_free(&issued);
}

/* ---------------- Reverse Connect ---------------- */

static void case_rc_wrong_uri(void) {
    gdsc_session_cfg c;
    memset(&c, 0, sizeof(c));
    c.reversePort = F.reversePort;
    c.reverseHost = "127.0.0.1";
    c.reverseWaitMs = 15000;
    c.serverUri = "urn:opengds:test:someone-else";
    c.applicationUri = GDS_URI;
    c.cert = &F.gdsCert;
    c.key = &F.gdsKey;
    c.trust = &F.reverseDeviceCert;
    c.trustN = 1;
    c.identity = GDSC_IDENTITY_USERNAME;
    c.userName = "setup";
    c.password = &F.password;
    gdsc_session *s = NULL;
    UA_StatusCode r = gdsc_session_open(&c, &s);
    gdsc_session_close(s);
    result("annexg.rc.wrong-uri", r == UA_STATUSCODE_BADSERVERURIINVALID, UA_StatusCode_name(r));
}

static void case_rc_setup(void) {
    enroll_rec e = {0, ""};
    push_setup_job j = setup_job(NULL, &F.reverseDeviceCert, &e, sign_ok);
    j.conn.reversePort = F.reversePort;
    j.conn.reverseHost = "127.0.0.1";
    j.conn.reverseWaitMs = 15000;
    (void)run_setup("annexg.rc.setup", &j, &e, NULL);
}

/* ---------------- G.1 pull agent ---------------- */

typedef struct {
    int calls;
    bool sawPending;
} persist_rec;

static gds_status persist_stub(void *ctx, const gdsc_pull_state *st) {
    persist_rec *p = ctx;
    p->calls++;
    p->sawPending = p->sawPending || !UA_NodeId_isNull(&st->pendingRequest);
    return GDS_OK;
}

/* A fresh application: its own self-signed certificate */
static gds_status new_app(const char *uri, gdsc_pull_state *st) {
    memset(st, 0, sizeof(*st));
    char san[128];
    if(gds_path(san, sizeof(san), "URI:%s", uri) != GDS_OK)
        return GDS_EINVAL;
    UA_String subject[2] = {UA_STRING_STATIC("O=OpenGDS Auditor TEST"),
                            UA_STRING_STATIC("CN=OpenGDS TEST pull agent")};
    UA_String sans[1] = {UA_STRING(san)};
    UA_ByteString key = UA_BYTESTRING_NULL, cert = UA_BYTESTRING_NULL;
    if(UA_CreateCertificate(UA_Log_Stdout, subject, 2, sans, 1, UA_CERTIFICATEFORMAT_DER, NULL,
                            &key, &cert) != UA_STATUSCODE_GOOD)
        return GDS_ECRYPTO;
    gds_status s = gds_buf_dup(cert.data, cert.length, &st->cert);
    if(s == GDS_OK)
        s = gds_buf_dup(key.data, key.length, &st->key);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    return s;
}

static gdsc_pull_cfg pull_cfg(const char *url, const UA_ApplicationRecordDataType *rec,
                              persist_rec *p) {
    gdsc_pull_cfg c;
    memset(&c, 0, sizeof(c));
    c.gdsUrl = url;
    c.gdsUri = "urn:opengds:test:mockgds";
    c.trust = &F.caDer;
    c.trustN = 1;
    c.crls = &F.crlDer;
    c.crlN = 1;
    c.record = rec;
    c.userName = "registrar";
    c.password = &F.password;
    c.finishDelayMs = 100;
    c.persist = persist_stub;
    c.persistCtx = p;
    return c;
}

static void record_for(const char *uri, UA_ApplicationRecordDataType *rec,
                       UA_LocalizedText *name, UA_String *url) {
    UA_ApplicationRecordDataType_init(rec);
    *name = UA_LOCALIZEDTEXT("en", "OpenGDS TEST pull agent");
    *url = UA_STRING("opc.tcp://127.0.0.1:4999");
    rec->applicationUri = UA_STRING((char *)(uintptr_t)uri);
    rec->applicationType = UA_APPLICATIONTYPE_SERVER;
    rec->applicationNames = name;
    rec->applicationNamesSize = 1;
    rec->productUri = UA_STRING("urn:opengds:test:product");
    rec->discoveryUrls = url;
    rec->discoveryUrlsSize = 1;
}

/* The issued certificate names the ApplicationUri and goes with the key */
static bool cert_matches(const gdsc_pull_state *st, const char *uri) {
    char got[GDS_MAX_APPLICATION_URI];
    if(gdsc_cert_uri(&st->cert, got, sizeof(got)) != GDS_OK || strcmp(got, uri) != 0)
        return false;
    const unsigned char *pc = st->cert.data, *pk = st->key.data;
    X509 *x = d2i_X509(NULL, &pc, (long)st->cert.len);
    EVP_PKEY *k = d2i_AutoPrivateKey(NULL, &pk, (long)st->key.len);
    bool ok = x && k && X509_check_private_key(x, k) == 1;
    X509_free(x);
    EVP_PKEY_free(k);
    return ok;
}

static void case_g1(void) {
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    UA_String url;
    record_for(APP_URI, &rec, &name, &url);
    gdsc_pull_state st;
    if(new_app(APP_URI, &st) != GDS_OK) {
        result("annexg.g1.first", false, "cannot create the application certificate");
        return;
    }
    gdsc_pull_result res;
    char d[200];

    persist_rec p0 = {0, false};
    gdsc_pull_cfg c = pull_cfg(F.urlMock, &rec, &p0);
    c.trust = &F.ca2Der; /* not the GDS's CA */
    UA_StatusCode r = gdsc_pull_agent_run(&c, &st, &res);
    snprintf(d, sizeof(d), "%s at %s", UA_StatusCode_name(r), gdsc_pull_step_name(res.failedStep));
    result("annexg.g1.untrusted-gds",
           r != UA_STATUSCODE_GOOD && res.failedStep == GDSC_PULL_STEP_CONNECT && p0.calls == 0,
           d);

    persist_rec p1 = {0, false};
    c = pull_cfg(F.urlMock, &rec, &p1);
    r = gdsc_pull_agent_run(&c, &st, &res);
    snprintf(d, sizeof(d), "%s at %s registered=%d update=%d issued=%d tl=%d persisted=%d",
             UA_StatusCode_name(r), gdsc_pull_step_name(res.failedStep), res.registered,
             res.updateRequired, res.certificateIssued, res.trustListDownloaded, p1.calls);
    result("annexg.g1.first",
           r == UA_STATUSCODE_GOOD && res.registered && res.updateRequired &&
               res.certificateIssued && res.trustListDownloaded && !res.pending &&
               p1.calls == 1 && st.issuersN == 1 && cert_matches(&st, APP_URI) &&
               st.trustList.trustedCertificatesSize == 1 &&
               UA_NodeId_isNull(&st.pendingRequest),
           d);

    persist_rec p2 = {0, false};
    c = pull_cfg(F.urlMock, &rec, &p2);
    c.userName = NULL; /* not needed any more */
    c.password = NULL;
    r = gdsc_pull_agent_run(&c, &st, &res);
    snprintf(d, sizeof(d), "%s at %s registered=%d update=%d issued=%d", UA_StatusCode_name(r),
             gdsc_pull_step_name(res.failedStep), res.registered, res.updateRequired,
             res.certificateIssued);
    result("annexg.g1.renew-check",
           r == UA_STATUSCODE_GOOD && !res.registered && !res.updateRequired &&
               !res.certificateIssued && cert_matches(&st, APP_URI),
           d);
    gdsc_pull_state_clear(&st);
}

static void case_g1_pending(void) {
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    UA_String url;
    record_for(APP2_URI, &rec, &name, &url);
    gdsc_pull_state st;
    if(new_app(APP2_URI, &st) != GDS_OK) {
        result("annexg.g1.pending", false, "cannot create the application certificate");
        return;
    }
    gdsc_pull_result res1, res2;
    persist_rec p1 = {0, false}, p2 = {0, false};
    gdsc_pull_cfg c = pull_cfg(F.urlMock2, &rec, &p1);
    UA_StatusCode r1 = gdsc_pull_agent_run(&c, &st, &res1);
    bool pendingKept = !UA_NodeId_isNull(&st.pendingRequest) && st.pendingKey.len > 0 &&
                       st.issuersN == 0;
    c = pull_cfg(F.urlMock2, &rec, &p2);
    UA_StatusCode r2 = gdsc_pull_agent_run(&c, &st, &res2);
    char d[200];
    snprintf(d, sizeof(d), "run1 %s pending=%d kept=%d; run2 %s at %s issued=%d",
             UA_StatusCode_name(r1), res1.pending, pendingKept, UA_StatusCode_name(r2),
             gdsc_pull_step_name(res2.failedStep), res2.certificateIssued);
    result("annexg.g1.pending",
           r1 == UA_STATUSCODE_GOOD && res1.pending && !res1.certificateIssued && pendingKept &&
               p1.sawPending && r2 == UA_STATUSCODE_GOOD && res2.certificateIssued &&
               !res2.pending && UA_NodeId_isNull(&st.pendingRequest) &&
               cert_matches(&st, APP2_URI),
           d);
    gdsc_pull_state_clear(&st);
}

int main(int argc, char **argv) {
    F.port = argc == 5 ? strtol(argv[4], NULL, 10) : 0;
    if(argc != 5 || F.port <= 0 || F.port >= 65530) {
        fprintf(stderr, "usage: %s <push_test_server> <mock_gds> <work-dir> <port>\n", argv[0]);
        return 2;
    }
    F.work = argv[3];
    F.reversePort = (UA_UInt16)(F.port + 1);
    atexit(release);
    if(gds_path(F.urlSetup, sizeof(F.urlSetup), "opc.tcp://127.0.0.1:%ld", F.port) != GDS_OK ||
       gds_path(F.urlReverseDevice, sizeof(F.urlReverseDevice), "opc.tcp://127.0.0.1:%ld",
                F.port + 2) != GDS_OK ||
       gds_path(F.urlMock, sizeof(F.urlMock), "opc.tcp://127.0.0.1:%ld", F.port + 3) != GDS_OK ||
       gds_path(F.urlMock2, sizeof(F.urlMock2), "opc.tcp://127.0.0.1:%ld", F.port + 4) !=
           GDS_OK ||
       gds_mkdirs(F.work, 0700) != GDS_OK)
        return 2;
    gds_status s = make_pki();
    if(s == GDS_OK)
        s = start_device(argv[1], F.port, "setup", false);
    if(s == GDS_OK)
        s = start_device(argv[1], F.port + 2, "reverse", true);
    if(s == GDS_OK)
        s = start_mock(argv[2], F.port + 3, "0", "mock");
    /* the two mocks share one CA dir: the second starts once the first
     * has written the CA and its CRL, or both write ca.crl at once */
    if(s == GDS_OK)
        s = wait_up(F.urlMock);
    if(s == GDS_OK)
        s = start_mock(argv[2], F.port + 4, "3", "mock2");
    if(s == GDS_OK)
        s = read_device_cert("setup", &F.setupDeviceCert);
    if(s == GDS_OK)
        s = read_device_cert("reverse", &F.reverseDeviceCert);
    if(s == GDS_OK)
        s = wait_up(F.urlSetup);
    if(s == GDS_OK)
        s = wait_up(F.urlMock2);
    if(s != GDS_OK) {
        fprintf(stderr, "setup failed: %s (see %s/*.log)\n", gds_status_name(s), F.work);
        return 1;
    }
    case_g2_state();
    case_g2_not_preauthorized();
    case_g2_cancel();
    case_g2_setup();
    case_rc_wrong_uri();
    case_rc_setup();
    case_g1();
    case_g1_pending();
    if(failures)
        fprintf(stderr, "%d case(s) failed; logs in %s/*.log\n", failures, F.work);
    return failures ? 1 : 0;
}
