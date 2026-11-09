/* OpenGDS integration test - the push scheduler (OpenGDS plan W3,
 * push_engine.c) inside an in-process GDS against the Auditor's
 * push_test_server (OPC 10000-12 v1.05.07 §7.7, §7.10).
 * SPDX-License-Identifier: MPL-2.0
 *
 * Usage: test_push_engine <push_test_server> <work-dir> <port>
 * (port: the device; port + 1: the GDS)
 *
 * The device is first set up as `gdsadm push now --server-cert` would: its
 * self-signed certificate pinned, the GDS's trust list written and a
 * certificate from ANOTHER CA (the Auditor's test CA, which the GDS trust
 * list also trusts). Then, with the push engine running:
 *   renew-foreign  the engine replaces a certificate the GDS CA did not
 *                  issue at once (CreateSigningRequest, the GDS CA,
 *                  UpdateCertificate, ApplyChanges, §7.7.2) and leaves the
 *                  trust list alone: the device holds it already
 *   trust-list     a certificate added to the GDS trust list reaches the
 *                  device without anyone asking (§7.7.3)
 *   rejected       a client the device refused shows up as a "Register and
 *                  trust?" DialogCondition (GetRejectedList, §7.10.12;
 *                  Part 9 §5.6); a DiscoveryAdmin's Respond2 registers it
 *                  and trusts it, and the new list is pushed
 *   back-off       an unreachable target fails with growing delays and
 *                  nothing is pushed
 *   standby        a STANDBY node runs no jobs; back to primary, the engine
 *                  looks at the device again and finds nothing to push
 *   slot           the jobs went through a replaced scheduler (next_jobs,
 *                  job_done) */
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/nodeids_gds.h>

#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ca.h"
#include "client/gdsc_push.h"
#include "client/gdsc_session.h"
#include "common/limits.h"
#include "common/safeint.h"
#include "gds_access.h"
#include "gds_plugin.h"
#include "gds_server.h"
#include "own_cert.h"
#include "push/push_workflows.h"
#include "push_engine.h"
#include "push_rejected.h"
#include "store.h"
#include "test_ca.h"
#include "common/banned.h"

extern char **environ;

#define GDS_URI "urn:opengds:test:engine-gds"
#define SERVER_URI "urn:opengds:test:pushserver" /* push_test_server's own */
#define DEAD_URI "urn:opengds:test:engine-dead"
#define STRANGER_URI "urn:opengds:test:engine-stranger"
#define FRIEND_URI "urn:opengds:test:engine-friend"
#define CLIENT_URI "urn:opengds:test:engine-admin"
#define PASSWORD "engine-test-password"
#define WAIT_S 90

static int failures = 0;

static bool result(const char *name, bool ok, const char *detail) {
    printf("%s %s%s%s\n", ok ? "ok" : "not ok", name, detail ? " # " : "", detail ? detail : "");
    fflush(stdout);
    if(!ok)
        failures++;
    return ok;
}

static struct {
    const char *work;
    char devUrl[64], gdsUrl[64];
    UA_UInt16 gdsPort;
    pid_t device;
    testca_t testca;
    gds_store *store;
    gds_ca *ca;
    gds_users users;
    gds_server *server;
    pthread_t serverThread;
    bool serverStarted;
    UA_Boolean running; /* written by the server thread's stop callback */
    push_engine *engine;
    gds_buf gdsCert, gdsKey, caDer, crlDer, testcaDer, testcaCrl, devSelf;
    /* the scheduler slot */
    unsigned long nextCalls, doneCalls;
} F;

/* ---- the scheduler slot: the built-in order, counted ---- */

static size_t counting_next(void *ctx, UA_DateTime now, size_t budget, const gds_push_job *due,
                            size_t nDue, size_t *picked) {
    (void)ctx;
    __atomic_add_fetch(&F.nextCalls, 1, __ATOMIC_RELAXED);
    return gds_push_next_jobs_default(NULL, now, budget, due, nDue, picked);
}

static void counting_done(void *ctx, const gds_push_job *job, UA_StatusCode r) {
    (void)ctx, (void)job, (void)r;
    __atomic_add_fetch(&F.doneCalls, 1, __ATOMIC_RELAXED);
}

/* ---- helpers ---- */

static void nap_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&t, NULL);
}

static push_target_status status_of(const char *uri) {
    push_target_status s;
    if(push_engine_status(F.engine, uri, &s) != GDS_OK)
        memset(&s, 0, sizeof(s));
    return s;
}

typedef bool (*cond_fn)(void);

static bool wait_for(cond_fn c, int seconds) {
    for(int i = 0; i < seconds * 10; i++) {
        if(c())
            return true;
        push_engine_kick(F.engine);
        nap_ms(100);
    }
    return c();
}

static gds_status write_file(const char *name, const gds_buf *b, char *path, size_t len) {
    gds_status s = gds_path(path, len, "%s/%s", F.work, name);
    return s == GDS_OK ? gds_file_write_atomic(path, b->data, b->len, 0644) : s;
}

static bool self_signed(const char *cn, const char *uri, UA_ByteString *cert,
                        UA_ByteString *key) {
    char subj[128], sanUri[256];
    (void)snprintf(subj, sizeof(subj), "CN=%s", cn);
    (void)snprintf(sanUri, sizeof(sanUri), "URI:%s", uri);
    UA_String subject[] = {UA_STRING(subj)};
    UA_String san[] = {UA_STRING(sanUri), UA_STRING_STATIC("DNS:localhost")};
    return UA_CreateCertificate(UA_Log_Stdout, subject, 1, san, 2, UA_CERTIFICATEFORMAT_DER,
                                NULL, key, cert) == UA_STATUSCODE_GOOD;
}

/* ---- the device ---- */

static gds_status start_device(const char *bin, const char *port) {
    char pki[GDS_MAX_PATH], caf[GDS_MAX_PATH], crlf[GDS_MAX_PATH], gdsf[GDS_MAX_PATH],
        log[GDS_MAX_PATH];
    gds_status s;
    if((s = gds_path(pki, sizeof(pki), "%s/pki-dev", F.work)) != GDS_OK ||
       (s = gds_path(log, sizeof(log), "%s/device.log", F.work)) != GDS_OK ||
       (s = write_file("gdsca.der", &F.caDer, caf, sizeof(caf))) != GDS_OK ||
       (s = write_file("gdsca.crl", &F.crlDer, crlf, sizeof(crlf))) != GDS_OK ||
       (s = write_file("gds.der", &F.gdsCert, gdsf, sizeof(gdsf))) != GDS_OK)
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
        rc = posix_spawn(&F.device, bin, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    return rc == 0 ? GDS_OK : GDS_EIO;
}

static gds_status read_self_signed(void) {
    char dir[GDS_MAX_PATH], p[GDS_MAX_PATH];
    gds_status s = gds_path(dir, sizeof(dir), "%s/pki-dev/ApplCerts/own/certs", F.work);
    DIR *d = s == GDS_OK ? opendir(dir) : NULL;
    if(!d)
        return GDS_ENOTFOUND;
    s = GDS_ENOTFOUND;
    const struct dirent *e;
    while(s == GDS_ENOTFOUND && (e = readdir(d)))
        if(strncmp(e->d_name, "selfsigned", 10) == 0 &&
           gds_path(p, sizeof(p), "%s/%s", dir, e->d_name) == GDS_OK)
            s = gds_file_read(p, GDS_MAX_CERT_SIZE, &F.devSelf);
    closedir(d);
    return s;
}

static const UA_NodeId *rsa_type(void) {
    static UA_NodeId t;
    t = GDSC_RSA_SHA256_APP_CERT;
    return &t;
}

static bool wait_device(void) {
    for(int i = 0; i < 100; i++) {
        if(read_self_signed() == GDS_OK &&
           gdsc_wait_presents(F.devUrl, rsa_type(), &F.devSelf, 0) == UA_STATUSCODE_GOOD)
            return true;
        gds_buf_free(&F.devSelf);
        nap_ms(100);
    }
    return false;
}

/* A session to the device as the GDS, trusting `trust` */
static gdsc_session *open_device(const gds_buf *trust, size_t trustN) {
    gdsc_session_cfg c;
    memset(&c, 0, sizeof(c));
    c.endpointUrl = F.devUrl;
    c.serverUri = SERVER_URI;
    c.cert = &F.gdsCert;
    c.key = &F.gdsKey;
    c.trust = trust;
    c.trustN = trustN;
    gds_buf crls[2] = {F.crlDer, F.testcaCrl};
    c.crls = crls;
    c.crlN = 2;
    c.identity = GDSC_IDENTITY_APP_CERT;
    gdsc_session *s = NULL;
    UA_StatusCode r = gdsc_session_open(&c, &s);
    if(r != UA_STATUSCODE_GOOD)
        fprintf(stderr, "device session: %s\n", UA_StatusCode_name(r));
    return s;
}

static gds_status sign_testca(void *ctx, const gds_buf *csr, gds_buf *out, gds_buf *iss,
                              size_t *issN) {
    (void)ctx;
    gds_status s = testca_sign_csr(&F.testca, csr, SERVER_URI, TESTCA_MAX_DAYS, out);
    *issN = 0;
    if(s == GDS_OK && (s = testca_cert_der(&F.testca, &iss[0])) == GDS_OK)
        *issN = 1;
    return s;
}

/* What `gdsadm push now --server-cert` does, with another CA's certificate */
static bool first_push(void) {
    UA_TrustListDataType tl;
    if(gds_server_get_trust_list(F.server, NULL, &tl) != GDS_OK)
        return false;
    gdsc_session *dev = open_device(&F.devSelf, 1);
    bool ok = false;
    if(dev) {
        push_job j;
        memset(&j, 0, sizeof(j));
        j.certificateGroup = GDSC_DEFAULT_APP_GROUP;
        j.trustListNode = GDSC_DEFAULT_APP_TRUSTLIST;
        j.certificateType = GDSC_RSA_SHA256_APP_CERT;
        j.trustList = &tl;
        j.sign = sign_testca;
        push_report rep;
        ok = push_run(gdsc_session_client(dev), &j, &rep) == GDS_OK && rep.certificateUpdated;
        gdsc_session_close(dev);
        ok = ok && gdsc_wait_presents(F.devUrl, rsa_type(), &rep.issued, 20000) ==
                       UA_STATUSCODE_GOOD;
        push_report_clear(&rep);
    }
    UA_TrustListDataType_clear(&tl);
    return ok;
}

static bool device_trusts(const UA_ByteString *cert) {
    gdsc_session *dev = open_device(&F.caDer, 1);
    if(!dev)
        return false;
    UA_TrustListDataType tl;
    UA_NodeId node = GDSC_DEFAULT_APP_TRUSTLIST;
    bool found = false;
    if(gdsc_trustlist_read(gdsc_session_client(dev), &node, &tl) == UA_STATUSCODE_GOOD) {
        for(size_t i = 0; i < tl.trustedCertificatesSize; i++)
            found = found || UA_ByteString_equal(&tl.trustedCertificates[i], cert);
        UA_TrustListDataType_clear(&tl);
    }
    gdsc_session_close(dev);
    return found;
}

static bool gds_trusts(const UA_ByteString *cert) {
    UA_TrustListDataType tl;
    if(gds_server_get_trust_list(F.server, NULL, &tl) != GDS_OK)
        return false;
    bool found = false;
    for(size_t i = 0; i < tl.trustedCertificatesSize; i++)
        found = found || UA_ByteString_equal(&tl.trustedCertificates[i], cert);
    UA_TrustListDataType_clear(&tl);
    return found;
}

/* ---- a client of the device that the device refuses ---- */

static void knock(const UA_ByteString *cert, const UA_ByteString *key) {
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(UA_LOGLEVEL_FATAL);
    UA_Client *c = NULL;
    if(UA_ClientConfig_setDefault(&cfg) == UA_STATUSCODE_GOOD &&
       UA_ClientConfig_setDefaultEncryption(&cfg, *cert, *key, NULL, 0, NULL, 0) ==
           UA_STATUSCODE_GOOD) {
        cfg.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        UA_String_clear(&cfg.securityPolicyUri);
        cfg.securityPolicyUri =
            UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
        UA_String_clear(&cfg.clientDescription.applicationUri);
        cfg.clientDescription.applicationUri = UA_STRING_ALLOC(STRANGER_URI);
        c = UA_Client_newWithConfig(&cfg);
    }
    if(!c) {
        UA_ClientConfig_clear(&cfg);
        return;
    }
    (void)UA_Client_connect(c, F.devUrl); /* refused: the certificate is unknown */
    (void)UA_Client_disconnect(c);
    UA_Client_delete(c);
}

/* ---- a DiscoveryAdmin on the GDS ---- */

static UA_Client *connect_disco(void) {
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    UA_Client *c = NULL;
    UA_ByteString ca = {F.caDer.len, F.caDer.data}, crl = {F.crlDer.len, F.crlDer.data};
    if(self_signed("engine test admin", CLIENT_URI, &cert, &key) &&
       UA_ClientConfig_setDefault(&cfg) == UA_STATUSCODE_GOOD &&
       UA_ClientConfig_setDefaultEncryption(&cfg, cert, key, &ca, 1, &crl, 1) ==
           UA_STATUSCODE_GOOD) {
        cfg.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        UA_String_clear(&cfg.securityPolicyUri);
        cfg.securityPolicyUri =
            UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
        UA_String_clear(&cfg.clientDescription.applicationUri);
        cfg.clientDescription.applicationUri = UA_STRING_ALLOC(CLIENT_URI);
        c = UA_Client_newWithConfig(&cfg);
    }
    if(!c)
        UA_ClientConfig_clear(&cfg);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    UA_StatusCode r = UA_STATUSCODE_BADINTERNALERROR;
    for(int i = 0; c && i < 50 && r != UA_STATUSCODE_GOOD; i++) {
        r = UA_Client_connectUsername(c, F.gdsUrl, "disco", PASSWORD);
        if(r != UA_STATUSCODE_GOOD)
            nap_ms(100);
    }
    if(c && r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "connect to the GDS: %s\n", UA_StatusCode_name(r));
        UA_Client_delete(c);
        c = NULL;
    }
    return c;
}

/* The one "Rejected_..." dialog under the Push object */
static bool find_dialog(UA_Client *c, UA_NodeId *out) {
    UA_UInt16 ns = 0;
    if(UA_Client_NamespaceGetIndex(c, (UA_String[]){UA_STRING_STATIC(PUSH_NS_URI)}, &ns) !=
       UA_STATUSCODE_GOOD)
        return false;
    UA_BrowseRequest req;
    UA_BrowseRequest_init(&req);
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = UA_NODEID_NUMERIC(ns, PUSH_NODE_PUSH);
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);
    bd.includeSubtypes = true;
    bd.resultMask = UA_BROWSERESULTMASK_ALL;
    req.nodesToBrowse = &bd;
    req.nodesToBrowseSize = 1;
    UA_BrowseResponse res = UA_Client_Service_browse(c, req);
    bool found = false;
    for(size_t i = 0; res.resultsSize == 1 && i < res.results[0].referencesSize && !found; i++) {
        const UA_ReferenceDescription *r = &res.results[0].references[i];
        if(r->browseName.name.length > 9 && memcmp(r->browseName.name.data, "Rejected_", 9) == 0)
            found = UA_NodeId_copy(&r->nodeId.nodeId, out) == UA_STATUSCODE_GOOD;
    }
    UA_BrowseResponse_clear(&res);
    return found;
}

static UA_StatusCode respond2(UA_Client *c, const UA_NodeId *d, UA_Int32 resp) {
    UA_Variant in[2];
    UA_LocalizedText lt = UA_LOCALIZEDTEXT("en", "known contractor laptop");
    UA_Variant_setScalar(&in[0], &resp, &UA_TYPES[UA_TYPES_INT32]);
    UA_Variant_setScalar(&in[1], &lt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    size_t nOut = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(c, *d, UA_NODEID_NUMERIC(0, UA_NS0ID_DIALOGCONDITIONTYPE_RESPOND2),
                                     2, in, &nOut, &out);
    UA_Array_delete(out, nOut, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

/* ---- the cases ---- */

static bool renewed(void) {
    push_target_status s = status_of(SERVER_URI);
    return s.certificatePushes >= 1 && s.certOurs && s.lastResult == UA_STATUSCODE_GOOD;
}

static void case_renew_foreign(void) {
    bool ok = wait_for(renewed, WAIT_S);
    push_target_status s = status_of(SERVER_URI);
    char d[160];
    (void)snprintf(d, sizeof(d), "jobs %llu, certificate pushes %llu, trust list pushes %llu, %s",
                   (unsigned long long)s.jobs, (unsigned long long)s.certificatePushes,
                   (unsigned long long)s.trustListPushes, UA_StatusCode_name(s.lastResult));
    /* The device starts with the GDS CA; its first look may still push the
     * full trust list once. open62541's file store does not keep every CRL it
     * is given (one of the three GDS CA CRLs is lost), so the device's list
     * never matches and the first look of every primary term pushes it. */
    result("renew-foreign", ok && s.known && s.certificatePushes == 1 && s.trustListPushes <= 1 &&
                                s.trustListCurrent,
           d);
}

static unsigned long long tlPushesWanted;

static bool tl_pushed(void) {
    push_target_status s = status_of(SERVER_URI);
    return s.trustListPushes >= tlPushesWanted && s.trustListCurrent;
}

static void case_trust_list(void) {
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    bool ok = self_signed("engine test friend", FRIEND_URI, &cert, &key) &&
              gds_server_trust_certificate(F.server, "test", &cert, 10000) == GDS_OK;
    tlPushesWanted = status_of(SERVER_URI).trustListPushes + 1;
    ok = ok && wait_for(tl_pushed, WAIT_S) && device_trusts(&cert);
    result("trust-list", ok && status_of(SERVER_URI).certificatePushes == 1, NULL);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
}

static bool dialog_open(void) {
    return push_engine_open_dialogs(F.engine) == 1;
}

static bool dialog_gone(void) {
    return push_engine_open_dialogs(F.engine) == 0;
}

static void case_rejected(void) {
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    if(!result("rejected-setup", self_signed("engine test stranger", STRANGER_URI, &cert, &key),
               NULL))
        return;
    knock(&cert, &key);
    bool opened = wait_for(dialog_open, WAIT_S);
    result("rejected-dialog", opened, NULL);
    UA_Client *c = opened ? connect_disco() : NULL;
    UA_NodeId d = UA_NODEID_NULL;
    bool found = c && find_dialog(c, &d);
    result("rejected-browse", found, NULL);
    tlPushesWanted = status_of(SERVER_URI).trustListPushes + 1;
    UA_StatusCode r = found ? respond2(c, &d, 0) : UA_STATUSCODE_BADNOTFOUND;
    result("rejected-respond", r == UA_STATUSCODE_GOOD, UA_StatusCode_name(r));
    /* registered as a Client, trusted, and pushed */
    UA_LocalizedText name = UA_LOCALIZEDTEXT("", "x");
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    rec.applicationUri = UA_STRING(STRANGER_URI);
    rec.applicationType = UA_APPLICATIONTYPE_CLIENT;
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    UA_NodeId id = UA_NODEID_NULL;
    bool created = true;
    bool registered = gds_server_register_application(F.server, "test", &rec, &id, &created) ==
                          GDS_OK &&
                      !created;
    bool pushed = gds_trusts(&cert) && wait_for(tl_pushed, WAIT_S) && device_trusts(&cert);
    result("rejected-trusted", registered && pushed, NULL);
    result("rejected-closed", wait_for(dialog_gone, WAIT_S), NULL);
    UA_NodeId_clear(&id);
    UA_NodeId_clear(&d);
    if(c) {
        (void)UA_Client_disconnect(c);
        UA_Client_delete(c);
    }
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
}

static bool dead_failed_twice(void) {
    return status_of(DEAD_URI).failures >= 2;
}

static void case_backoff(void) {
    bool ok = wait_for(dead_failed_twice, WAIT_S);
    push_target_status s = status_of(DEAD_URI);
    char d[120];
    (void)snprintf(d, sizeof(d), "jobs %llu, failures %u, %s", (unsigned long long)s.jobs,
                   s.failures, UA_StatusCode_name(s.lastResult));
    result("back-off", ok && !s.known && s.jobs == s.failures &&
                           s.lastResult != UA_STATUSCODE_GOOD && s.certificatePushes == 0,
           d);
}

static unsigned long long jobsBefore;

static bool looked_again(void) {
    push_target_status s = status_of(SERVER_URI);
    return s.jobs > jobsBefore && s.known && s.lastResult == UA_STATUSCODE_GOOD;
}

static void case_standby(void) {
    if(!result("standby-role", gds_server_set_role(F.server, GDS_NODE_STANDBY, 100, 0) == GDS_OK,
               NULL))
        return;
    nap_ms(500); /* a job that started before may still finish */
    unsigned long long dead = status_of(DEAD_URI).jobs, dev = status_of(SERVER_URI).jobs;
    for(int i = 0; i < 40; i++) { /* 4 s: the dead target would have been retried */
        push_engine_kick(F.engine);
        nap_ms(100);
    }
    result("standby-idle", status_of(DEAD_URI).jobs == dead && status_of(SERVER_URI).jobs == dev,
           NULL);
    push_target_status before = status_of(SERVER_URI);
    jobsBefore = before.jobs;
    bool ok = gds_server_set_role(F.server, GDS_NODE_PRIMARY, 255, 0) == GDS_OK &&
              wait_for(looked_again, WAIT_S);
    push_target_status after = status_of(SERVER_URI);
    result("primary-again", ok && after.certificatePushes == before.certificatePushes &&
                                after.trustListPushes <= before.trustListPushes + 1 &&
                                after.trustListCurrent && after.certOurs,
           NULL);
}

/* ---- set-up ---- */

static bool write_users(void) {
    char path[GDS_MAX_PATH], cred[256], text[1024];
    static const uint8_t pw[] = PASSWORD;
    if(gds_path(path, sizeof(path), "%s/users", F.work) != GDS_OK ||
       gds_password_hash(pw, sizeof(pw) - 1, 10000, cred, sizeof(cred)) != GDS_OK)
        return false;
    int n = snprintf(text, sizeof(text), "disco DiscoveryAdmin %s\n", cred);
    return n > 0 && (size_t)n < sizeof(text) &&
           gds_file_write_atomic(path, text, (size_t)n, 0600) == GDS_OK &&
           gds_users_load(path, &F.users) == GDS_OK;
}

/* The GDS trust list also trusts the Auditor's test CA */
static bool seed_trust_list(void) {
    UA_ByteString certs[1] = {{F.testcaDer.len, F.testcaDer.data}};
    UA_ByteString crls[1] = {{F.testcaCrl.len, F.testcaCrl.data}};
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    tl.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    tl.trustedCertificates = certs;
    tl.trustedCertificatesSize = 1;
    tl.trustedCrls = crls;
    tl.trustedCrlsSize = 1;
    UA_ByteString enc = UA_BYTESTRING_NULL;
    if(UA_encodeBinary(&tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &enc, NULL) !=
       UA_STATUSCODE_GOOD)
        return false;
    gds_buf b = {enc.data, enc.length};
    bool ok = gds_store_tl_put(F.store, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP,
                               &b, UA_DateTime_now()) == GDS_OK;
    UA_ByteString_clear(&enc);
    return ok;
}

static bool target(const char *uri, const char *url) {
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "Engine test device");
    UA_String disc = UA_STRING((char *)(uintptr_t)url);
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    rec.applicationUri = UA_STRING((char *)(uintptr_t)uri);
    rec.applicationType = UA_APPLICATIONTYPE_SERVER;
    rec.productUri = UA_STRING("urn:opengds:test:product");
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    rec.discoveryUrls = &disc;
    rec.discoveryUrlsSize = 1;
    UA_NodeId id = UA_NODEID_NULL;
    bool created = false;
    bool ok = gds_server_register_application(F.server, "test", &rec, &id, &created) == GDS_OK &&
              gds_store_push_target_put(F.store, &id.identifier.guid, url, true) == GDS_OK;
    UA_NodeId_clear(&id);
    return ok;
}

static void *server_main(void *p) {
    (void)p;
    if(gds_server_run(F.server, &F.running) != GDS_OK)
        fprintf(stderr, "gds_server_run failed\n");
    return NULL;
}

static void stop_cb(UA_Server *ua, void *data) {
    (void)ua;
    *(UA_Boolean *)data = false;
}

static bool setup(const char *bin, const char *devPort) {
    char db[GDS_MAX_PATH], caDir[GDS_MAX_PATH], tcaDir[GDS_MAX_PATH], data[GDS_MAX_PATH];
    if(gds_mkdirs(F.work, 0700) != GDS_OK ||
       gds_path(db, sizeof(db), "%s/store.db", F.work) != GDS_OK ||
       gds_path(caDir, sizeof(caDir), "%s/ca", F.work) != GDS_OK ||
       gds_path(tcaDir, sizeof(tcaDir), "%s/testca", F.work) != GDS_OK ||
       gds_path(data, sizeof(data), "%s/gds-data", F.work) != GDS_OK)
        return false;
    (void)unlink(db);
    static uint8_t pw[] = "engine-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gdsd_own_params op = {data, GDS_URI, "OpenGDS engine test", "urn:opengds:test", "localhost",
                          F.gdsPort};
    if(!result("setup-pki",
               gds_store_open(db, &F.store) == GDS_OK && gds_ca_openssl_open(&cc, &F.ca) == GDS_OK &&
                   gds_ca_get_ca_cert(F.ca, &F.caDer) == GDS_OK &&
                   gds_ca_get_crl(F.ca, &F.crlDer) == GDS_OK &&
                   gdsd_own_cert(&op, F.store, F.ca, &F.gdsCert, &F.gdsKey) == GDS_OK &&
                   testca_load_or_create(&F.testca, tcaDir, "OpenGDS Auditor TEST engine CA") ==
                       GDS_OK &&
                   testca_cert_der(&F.testca, &F.testcaDer) == GDS_OK &&
                   testca_crl_der(&F.testca, &F.testcaCrl) == GDS_OK && seed_trust_list() &&
                   write_users(),
               NULL))
        return false;
    gds_server_config cfg = {0};
    cfg.port = F.gdsPort;
    cfg.loopbackOnly = true;
    cfg.applicationUri = GDS_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS engine test";
    cfg.ownCert = F.gdsCert;
    cfg.ownKey = F.gdsKey;
    cfg.store = F.store;
    cfg.ca = F.ca;
    cfg.users = &F.users;
    cfg.approval = GDS_APPROVE_MANUAL; /* the engine's requests need no approval */
    gds_push_scheduler sched;
    memset(&sched, 0, sizeof(sched));
    sched.abi_major = GDS_PLUGIN_ABI_MAJOR;
    sched.abi_minor = GDS_PLUGIN_ABI_MINOR;
    sched.struct_size = sizeof(sched);
    sched.next_jobs = counting_next;
    sched.job_done = counting_done;
    char deadUrl[64];
    (void)snprintf(deadUrl, sizeof(deadUrl), "opc.tcp://127.0.0.1:%u", (unsigned)F.gdsPort + 1u);
    if(!result("setup-gds",
               gds_server_new(&cfg, &F.server) == GDS_OK &&
                   gds_server_set_push_scheduler(F.server, &sched) == GDS_OK &&
                   target(SERVER_URI, F.devUrl) && target(DEAD_URI, deadUrl),
               NULL))
        return false;
    if(!result("setup-device",
               start_device(bin, devPort) == GDS_OK && wait_device() && first_push(), NULL))
        return false;
    F.running = true;
    if(pthread_create(&F.serverThread, NULL, server_main, NULL) != 0)
        return false;
    F.serverStarted = true;
    push_engine_cfg pc;
    memset(&pc, 0, sizeof(pc));
    pc.server = F.server;
    pc.cert = F.gdsCert;
    pc.key = F.gdsKey;
    pc.issuers = &F.caDer;
    pc.issuersN = 1;
    pc.tickMs = 200;
    pc.concurrency = 2;
    pc.jitterS = 0;
    pc.backoffMinS = 1;
    pc.backoffMaxS = 2;
    pc.rejectedS = 1;
    pc.timeoutMs = 5000;
    pc.presentTimeoutMs = 20000;
    return result("setup-engine", push_engine_start(&pc, &F.engine) == GDS_OK, NULL);
}

static void teardown(void) {
    push_engine_stop(F.engine);
    if(F.serverStarted) {
        (void)UA_Server_addTimedCallback(gds_server_ua(F.server), stop_cb, &F.running,
                                         UA_DateTime_nowMonotonic(), NULL);
        (void)pthread_join(F.serverThread, NULL);
    }
    gds_server_delete(F.server);
    if(F.device > 0) {
        kill(F.device, SIGTERM);
        waitpid(F.device, NULL, 0);
    }
    gds_store_close(F.store);
    gds_ca_close(F.ca);
    testca_free(&F.testca);
    gds_buf_free(&F.gdsCert);
    gds_buf_free_secret(&F.gdsKey);
    gds_buf_free(&F.caDer);
    gds_buf_free(&F.crlDer);
    gds_buf_free(&F.testcaDer);
    gds_buf_free(&F.testcaCrl);
    gds_buf_free(&F.devSelf);
}

int main(int argc, char **argv) {
    if(argc != 4) {
        fprintf(stderr, "usage: %s <push_test_server> <work-dir> <port>\n", argv[0]);
        return 2;
    }
    /* clients and server share this process (see tests/unit/test_audit.c) */
    (void)setenv("TZ", "UTC", 1);
    tzset();
    F.work = argv[2];
    long port = 0;
    if(!gds_parse_long(argv[3], 1, 65533, &port))
        return 2;
    F.gdsPort = (UA_UInt16)(port + 1);
    (void)snprintf(F.devUrl, sizeof(F.devUrl), "opc.tcp://localhost:%ld", port);
    (void)snprintf(F.gdsUrl, sizeof(F.gdsUrl), "opc.tcp://127.0.0.1:%u", (unsigned)F.gdsPort);
    if(setup(argv[1], argv[3])) {
        case_renew_foreign();
        case_trust_list();
        case_rejected();
        case_backoff();
        case_standby();
        result("slot", __atomic_load_n(&F.nextCalls, __ATOMIC_RELAXED) > 0 &&
                           __atomic_load_n(&F.doneCalls, __ATOMIC_RELAXED) > 0,
               NULL);
    }
    teardown();
    printf("%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
