/* OpenGDS Auditor self-test target: the application setup state of
 * push_test_server --setup (see push_setup.h).
 * SPDX-License-Identifier: MPL-2.0
 *
 * Single-threaded like push_mgmt.c: callbacks run with the server lock
 * held. Every input is checked for type and size before use. */
#include "push_setup.h"

#include <open62541/plugin/log_stdout.h>

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>

#include "common/buf.h"
#include "common/compiler.h"
#include "common/limits.h"
#include "x509util.h"
#include "common/banned.h"

#define PS_MAX_IDENTITIES 16
#define PS_MAX_CRITERIA 256
#define PS_NOTICE_MS 1500
#define SECADMIN UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN

static struct {
    UA_Server *server;
    ps_admin_fn isAdmin;
    pm_mode_fn modeOf;
    char dir[GDS_MAX_PATH]; /* <pki>/push */
    char pki[GDS_MAX_PATH];
    bool inSetup;
    bool shuttingDown; /* ResetToServerDefaults: State Shutdown until the stop */
    bool resetRequested;
    UA_IdentityMappingRuleType ids[PS_MAX_IDENTITIES];
    size_t idsN;
    UA_StatusCode (*libVerify)(UA_CertificateGroup *, const UA_ByteString *);
} S;

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

static gds_status file_path(char *out, size_t len, const char *name) {
    return gds_path(out, len, "%s/%s", S.dir, name);
}

/* ---------------- Persisted state ---------------- */

static void save_identities(void) {
    UA_Variant v;
    UA_Variant_setArray(&v, S.ids, S.idsN, &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]);
    UA_ByteString b = UA_BYTESTRING_NULL;
    char p[GDS_MAX_PATH];
    if(UA_encodeBinary(&v, &UA_TYPES[UA_TYPES_VARIANT], &b, NULL) != UA_STATUSCODE_GOOD ||
       file_path(p, sizeof(p), "identities") != GDS_OK ||
       gds_file_write_atomic(p, b.data, b.length, 0600) != GDS_OK)
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "cannot store the identities");
    UA_ByteString_clear(&b);
}

static void load_identities(void) {
    char p[GDS_MAX_PATH];
    gds_buf b = {0};
    if(file_path(p, sizeof(p), "identities") != GDS_OK || gds_file_read(p, 65536, &b) != GDS_OK)
        return;
    UA_ByteString bs = {b.len, b.data};
    UA_Variant v;
    UA_Variant_init(&v);
    if(UA_decodeBinary(&bs, &v, &UA_TYPES[UA_TYPES_VARIANT], NULL) == UA_STATUSCODE_GOOD &&
       v.type == &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE] && !UA_Variant_isScalar(&v)) {
        const UA_IdentityMappingRuleType *r = v.data;
        for(size_t i = 0; i < v.arrayLength && S.idsN < PS_MAX_IDENTITIES; i++)
            if(UA_IdentityMappingRuleType_copy(&r[i], &S.ids[S.idsN]) == UA_STATUSCODE_GOOD)
                S.idsN++;
    }
    UA_Variant_clear(&v);
    gds_buf_free(&b);
}

static bool setup_done_stored(void) {
    char p[GDS_MAX_PATH];
    return file_path(p, sizeof(p), "setup-done") == GDS_OK && access(p, F_OK) == 0;
}

static void end_setup(const char *why) {
    if(!S.inSetup)
        return;
    S.inSetup = false;
    char p[GDS_MAX_PATH];
    if(file_path(p, sizeof(p), "setup-done") != GDS_OK ||
       gds_file_write_atomic(p, "1\n", 2, 0600) != GDS_OK)
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "cannot store setup-done");
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Application setup ended (%s)", why);
}

/* setup-exit-no-role: an applied push ends setup, with no SecurityAdmin */
static void on_applied(void) {
    if(pm_breaking("setup-exit-no-role"))
        end_setup("mutant setup-exit-no-role: ApplyChanges");
}

/* ---------------- InApplicationSetup and ServerStatus.State ---------------- */

static UA_StatusCode read_in_setup(UA_Server *server, const UA_NodeId *sessionId,
                                   void *sessionContext, const UA_NodeId *nodeId,
                                   void *nodeContext, UA_Boolean includeSourceTimeStamp,
                                   const UA_NumericRange *range, UA_DataValue *value) {
    (void)server, (void)sessionId, (void)sessionContext, (void)nodeId, (void)nodeContext;
    (void)includeSourceTimeStamp;
    if(range)
        return UA_STATUSCODE_BADINDEXRANGEINVALID;
    UA_Boolean b = S.inSetup;
    value->hasValue = true;
    return UA_Variant_setScalarCopy(&value->value, &b, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

/* Only ServerStatus.State: the ServerStatus structure keeps Running */
static UA_StatusCode read_state(UA_Server *server, const UA_NodeId *sessionId,
                                void *sessionContext, const UA_NodeId *nodeId, void *nodeContext,
                                UA_Boolean includeSourceTimeStamp, const UA_NumericRange *range,
                                UA_DataValue *value) {
    (void)server, (void)sessionId, (void)sessionContext, (void)nodeId, (void)nodeContext;
    (void)includeSourceTimeStamp;
    if(range)
        return UA_STATUSCODE_BADINDEXRANGEINVALID;
    UA_ServerState s = UA_SERVERSTATE_RUNNING;
    if(S.shuttingDown)
        s = UA_SERVERSTATE_SHUTDOWN;
    else if(S.inSetup && !pm_breaking("setup-state-running"))
        s = UA_SERVERSTATE_NOCONFIGURATION;
    value->hasValue = true;
    return UA_Variant_setScalarCopy(&value->value, &s, &UA_TYPES[UA_TYPES_SERVERSTATE]);
}

/* ---------------- SecurityAdmin identities (OPC 10000-18) ---------------- */

static UA_StatusCode access_check(const UA_NodeId *sessionId) {
    if(!S.modeOf || S.modeOf(sessionId) < UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;
    return S.isAdmin(sessionId) ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADUSERACCESSDENIED;
}

static UA_StatusCode publish_identities(void) {
    UA_Variant v;
    UA_Variant_setArray(&v, S.idsN ? (void *)S.ids : UA_EMPTY_ARRAY_SENTINEL, S.idsN,
                        &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]);
    UA_UInt32 dim = (UA_UInt32)S.idsN;
    v.arrayDimensions = &dim;
    v.arrayDimensionsSize = 1;
    return UA_Server_writeValue(S.server, ns0(UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN_IDENTITIES), v);
}

static bool needs_criteria(UA_IdentityCriteriaType t) {
    return t != UA_IDENTITYCRITERIATYPE_ANONYMOUS && t != UA_IDENTITYCRITERIATYPE_AUTHENTICATEDUSER;
}

static UA_StatusCode addIdentity(UA_Server *server, const UA_NodeId *sessionId,
                                 void *sessionContext, const UA_NodeId *methodId,
                                 void *methodContext, const UA_NodeId *objectId,
                                 void *objectContext, size_t inputSize, const UA_Variant *input,
                                 size_t outputSize, UA_Variant *output) {
    (void)server, (void)sessionContext, (void)methodId, (void)methodContext, (void)objectId;
    (void)objectContext, (void)outputSize, (void)output;
    UA_StatusCode r = access_check(sessionId);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(inputSize != 1 || !UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    const UA_IdentityMappingRuleType *rule = input[0].data;
    if(rule->criteriaType < UA_IDENTITYCRITERIATYPE_USERNAME ||
       rule->criteriaType > UA_IDENTITYCRITERIATYPE_TRUSTEDAPPLICATION ||
       rule->criteria.length > PS_MAX_CRITERIA ||
       (needs_criteria(rule->criteriaType) && rule->criteria.length == 0))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    /* 18 §4.4.5: refuse what would open SecurityAdmin to everyone */
    if(rule->criteriaType == UA_IDENTITYCRITERIATYPE_ANONYMOUS ||
       rule->criteriaType == UA_IDENTITYCRITERIATYPE_AUTHENTICATEDUSER)
        return UA_STATUSCODE_BADREQUESTNOTALLOWED;
    if(rule->criteriaType != UA_IDENTITYCRITERIATYPE_USERNAME &&
       rule->criteriaType != UA_IDENTITYCRITERIATYPE_APPLICATION)
        return UA_STATUSCODE_BADNOTSUPPORTED; /* this test target maps only these two */
    for(size_t i = 0; i < S.idsN; i++)
        if(S.ids[i].criteriaType == rule->criteriaType &&
           UA_String_equal(&S.ids[i].criteria, &rule->criteria))
            return UA_STATUSCODE_BADALREADYEXISTS;
    if(S.idsN == PS_MAX_IDENTITIES)
        return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
    r = UA_IdentityMappingRuleType_copy(rule, &S.ids[S.idsN]);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    S.idsN++;
    save_identities();
    r = publish_identities();
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "AddIdentity to SecurityAdmin (criteria type %d) -> %s", (int)rule->criteriaType,
                UA_StatusCode_name(r));
    if(r == UA_STATUSCODE_GOOD && !pm_breaking("setup-sticky"))
        end_setup("the SecurityAdmin Role has an identity");
    return r;
}

bool ps_identity_admin(const UA_String *userName, bool anonymous, const UA_ByteString *clientCert) {
    char uri[GDS_MAX_APPLICATION_URI + 1] = "";
    if(clientCert && clientCert->length) {
        gds_buf b = {clientCert->data, clientCert->length};
        if(x509_san_uri(&b, uri, sizeof(uri)) != GDS_OK)
            uri[0] = '\0';
        ERR_clear_error();
    }
    UA_String app = UA_STRING(uri);
    for(size_t i = 0; i < S.idsN; i++) {
        const UA_IdentityMappingRuleType *r = &S.ids[i];
        if(r->criteriaType == UA_IDENTITYCRITERIATYPE_USERNAME && userName &&
           UA_String_equal(&r->criteria, userName))
            return true;
        /* 18 §4.4.3: Application is for an Anonymous token on a trusted
         * client certificate (the channel's verification) */
        if(r->criteriaType == UA_IDENTITYCRITERIATYPE_APPLICATION && anonymous && uri[0] &&
           UA_String_equal(&r->criteria, &app))
            return true;
    }
    return false;
}

/* ---------------- Client certificates in setup (12 §7.5) ---------------- */

static UA_StatusCode verify_setup(UA_CertificateGroup *g, const UA_ByteString *cert) {
    if(S.inSetup || pm_breaking("setup-open-after"))
        return UA_STATUSCODE_GOOD;
    return S.libVerify(g, cert);
}

/* ---------------- ResetToServerDefaults (12 §7.10.13) ---------------- */

/* Remove the files in <pki>/<sub>, except those starting with keep. */
static void wipe(const char *sub, const char *keep) {
    char dir[GDS_MAX_PATH];
    if(gds_path(dir, sizeof(dir), "%s/%s", S.pki, sub) != GDS_OK)
        return;
    DIR *d = opendir(dir);
    if(!d)
        return;
    struct dirent *e;
    while((e = readdir(d))) {
        char p[GDS_MAX_PATH];
        if(e->d_name[0] == '.' || (keep && strncmp(e->d_name, keep, strlen(keep)) == 0) ||
           gds_path(p, sizeof(p), "%s/%s", dir, e->d_name) != GDS_OK)
            continue;
        if(unlink(p) != 0 && errno != ENOENT)
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "cannot remove %s/%s", sub,
                           e->d_name);
    }
    closedir(d);
}

/* After the notice: back to the defaults (the initial self-signed
 * certificate, the command line's trust list, setup state), then stop;
 * push_test_server starts again. */
static void reset_due(UA_Server *server, void *data) {
    (void)server, (void)data;
    static const char *const dirs[] = {"ApplCerts/trusted/certs", "ApplCerts/trusted/crl",
                                       "ApplCerts/issuer/certs", "ApplCerts/issuer/crl", "push"};
    for(size_t i = 0; i < GDS_ARRAY_SIZE(dirs); i++)
        wipe(dirs[i], NULL);
    wipe("ApplCerts/own/certs", "selfsigned[");
    wipe("ApplCerts/own/private", "selfsigned[");
    S.resetRequested = true;
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "ResetToServerDefaults: defaults restored, stopping to start again");
    if(raise(SIGINT) != 0) /* UA_Server_runUntilInterrupt stops */
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "cannot stop the server");
}

static UA_StatusCode resetToServerDefaults(UA_Server *server, const UA_NodeId *sessionId,
                                           void *sessionContext, const UA_NodeId *methodId,
                                           void *methodContext, const UA_NodeId *objectId,
                                           void *objectContext, size_t inputSize,
                                           const UA_Variant *input, size_t outputSize,
                                           UA_Variant *output) {
    (void)sessionContext, (void)methodId, (void)methodContext, (void)objectId;
    (void)objectContext, (void)input, (void)outputSize, (void)output;
    UA_StatusCode r = access_check(sessionId);
    if(r == UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT &&
       S.modeOf(sessionId) >= UA_MESSAGESECURITYMODE_SIGN)
        r = S.isAdmin(sessionId) ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADUSERACCESSDENIED;
    if(r != UA_STATUSCODE_GOOD)
        return r; /* §7.10.13: an authenticated channel and SecurityAdmin */
    if(inputSize != 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(pm_breaking("reset-no-shutdown")) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "mutant reset-no-shutdown: ResetToServerDefaults does nothing");
        return UA_STATUSCODE_GOOD;
    }
    if(S.shuttingDown)
        return UA_STATUSCODE_GOOD;
    UA_EventLoop *el = UA_Server_getConfig(server)->eventLoop;
    UA_DateTime due = el->dateTime_nowMonotonic(el) + PS_NOTICE_MS * UA_DATETIME_MSEC;
    r = UA_Server_addTimedCallback(server, reset_due, NULL, due, NULL);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    S.shuttingDown = true;
    UA_LocalizedText t = UA_LOCALIZEDTEXT(
        "en", "Reset to server defaults: client credentials may not work after the restart");
    UA_Variant v;
    UA_Variant_setScalar(&v, &t, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    if(UA_Server_writeValue(server, ns0(UA_NS0ID_SERVER_SERVERSTATUS_SHUTDOWNREASON), v) !=
       UA_STATUSCODE_GOOD)
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "ShutdownReason not written");
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "ResetToServerDefaults: State Shutdown, stopping in %d ms", PS_NOTICE_MS);
    return UA_STATUSCODE_GOOD;
}

/* setup-no-cert: the endpoints present no certificate (GetEndpoints copies
 * each SecurityPolicy's localCertificate) */
static void drop_endpoint_certs(UA_ServerConfig *c) {
    for(size_t i = 0; i < c->securityPoliciesSize; i++)
        UA_ByteString_clear(&c->securityPolicies[i].localCertificate);
}

/* The Optional nodes this server adds when the namespace lacks them:
 * InApplicationSetup (12 §7.10.3) and ResetToServerDefaults (§7.10.13). */
static UA_StatusCode optional_nodes(UA_Server *server) {
    UA_VariableAttributes va = UA_VariableAttributes_default;
    UA_Boolean f = false;
    UA_Variant_setScalar(&va.value, &f, &UA_TYPES[UA_TYPES_BOOLEAN]);
    va.dataType = UA_TYPES[UA_TYPES_BOOLEAN].typeId;
    va.valueRank = UA_VALUERANK_SCALAR;
    va.displayName = UA_LOCALIZEDTEXT("", "InApplicationSetup");
    UA_StatusCode r = UA_Server_addVariableNode(
        server, ns0(UA_NS0ID_SERVERCONFIGURATION_INAPPLICATIONSETUP),
        ns0(UA_NS0ID_SERVERCONFIGURATION), ns0(UA_NS0ID_HASPROPERTY),
        UA_QUALIFIEDNAME(0, "InApplicationSetup"), ns0(UA_NS0ID_PROPERTYTYPE), va, NULL, NULL);
    if(r != UA_STATUSCODE_GOOD && r != UA_STATUSCODE_BADNODEIDEXISTS)
        return r;
    UA_MethodAttributes ma = UA_MethodAttributes_default;
    ma.executable = true;
    ma.userExecutable = true;
    ma.displayName = UA_LOCALIZEDTEXT("", "ResetToServerDefaults");
    r = UA_Server_addMethodNode(server, ns0(UA_NS0ID_SERVERCONFIGURATION_RESETTOSERVERDEFAULTS),
                                ns0(UA_NS0ID_SERVERCONFIGURATION), ns0(UA_NS0ID_HASCOMPONENT),
                                UA_QUALIFIEDNAME(0, "ResetToServerDefaults"), ma,
                                resetToServerDefaults, 0, NULL, 0, NULL, NULL, NULL);
    return r == UA_STATUSCODE_BADNODEIDEXISTS ? UA_STATUSCODE_GOOD : r;
}

UA_StatusCode ps_install(UA_Server *server, const char *pki, ps_admin_fn isAdmin,
                         pm_mode_fn modeOf) {
    memset(&S, 0, sizeof(S));
    S.server = server;
    S.isAdmin = isAdmin;
    S.modeOf = modeOf;
    if(gds_path(S.dir, sizeof(S.dir), "%s/push", pki) != GDS_OK ||
       gds_mkdirs(S.dir, 0700) != GDS_OK ||
       gds_path(S.pki, sizeof(S.pki), "%s", pki) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    load_identities();
    S.inSetup = !setup_done_stored();
    UA_ServerConfig *c = UA_Server_getConfig(server);
    UA_CallbackValueSource inSetup = {read_in_setup, NULL}, state = {read_state, NULL};
    if(optional_nodes(server) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINTERNALERROR;
    const struct {
        const char *what;
        UA_StatusCode r;
    } steps[] = {
        {"InApplicationSetup", UA_Server_setVariableNode_callbackValueSource(
                                   server, ns0(UA_NS0ID_SERVERCONFIGURATION_INAPPLICATIONSETUP), inSetup)},
        {"ServerStatus.State", UA_Server_setVariableNode_callbackValueSource(
                                   server, ns0(UA_NS0ID_SERVER_SERVERSTATUS_STATE), state)},
        {"AddIdentity", UA_Server_setMethodNodeCallback(
                            server, ns0(UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN_ADDIDENTITY), addIdentity)},
        {"ResetToServerDefaults",
         UA_Server_setMethodNodeCallback(server, ns0(UA_NS0ID_SERVERCONFIGURATION_RESETTOSERVERDEFAULTS),
                                         resetToServerDefaults)},
        {"Identities", publish_identities()},
    };
    for(size_t i = 0; i < GDS_ARRAY_SIZE(steps); i++) {
        if(steps[i].r != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "setup state: %s -> %s",
                         steps[i].what, UA_StatusCode_name(steps[i].r));
            return UA_STATUSCODE_BADINTERNALERROR;
        }
    }
    pm_on_applied(on_applied);
    S.libVerify = c->secureChannelPKI.verifyCertificate;
    c->secureChannelPKI.verifyCertificate = verify_setup;
    if(pm_breaking("setup-no-cert"))
        drop_endpoint_certs(c);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Application setup state: %s (%zu SecurityAdmin identities)",
                S.inSetup ? "in setup" : "set up", S.idsN);
    return UA_STATUSCODE_GOOD;
}

bool ps_reset_requested(void) {
    return S.resetRequested;
}

void ps_clear(void) {
    for(size_t i = 0; i < S.idsN; i++)
        UA_IdentityMappingRuleType_clear(&S.ids[i]);
    S.idsN = 0;
}
