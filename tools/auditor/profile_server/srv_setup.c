/* OpenGDS Auditor server profile: push setup (srv_setup.c).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "Push setup".
 *
 * The target must be in its application setup state (12 Annex G.2), so
 * these tests run only when selected with --only SRV-SET; --setup-cmd (or
 * the operator at a terminal) resets the target first (st_setup_hook).
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <open62541/client_highlevel.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "x509util.h"
#include "common/banned.h"

#define IAS UA_NS0ID_SERVERCONFIGURATION_INAPPLICATIONSETUP
#define SETUP_PREFIX "SRV-SET"
#define APPLY_WAIT_MS 10000
#define SHUTDOWN_WAIT_MS 10000
#define PEER_UNKNOWN_URI "urn:opengds:auditor:peer-unknown"

static void nap_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static bool same(const gds_buf *a, const gds_buf *b) {
    return a->len == b->len && a->len && memcmp(a->data, b->data, a->len) == 0;
}

static bool absent(UA_StatusCode r) {
    return r == UA_STATUSCODE_BADNODEIDUNKNOWN || r == UA_STATUSCODE_BADMETHODINVALID ||
           r == UA_STATUSCODE_BADATTRIBUTEIDINVALID || r == UA_STATUSCODE_BADNOTIMPLEMENTED ||
           r == UA_STATUSCODE_BADNOTSUPPORTED;
}

/* Selected with --only SRV-SET..., and the target reset by the hook. A
 * test that opens sessions (session) also needs a secure endpoint that
 * presents a certificate: without one the client stack would build a
 * SecureChannel on an empty certificate (SRV-SET-02 reports it). */
static bool selected(ga_ctx *ctx, srv_target *t, bool session) {
    if(!t->only || strncmp(t->only, SETUP_PREFIX, strlen(SETUP_PREFIX)) != 0) {
        ga_not_tested(ctx, "runs only with --only " SETUP_PREFIX
                           ": the target must be in application setup first");
        return false;
    }
    UA_StatusCode r = st_setup_hook(t, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "--setup-cmd failed or the target did not come back within %ld s (%s)",
                      t->settleSec, UA_StatusCode_name(r));
        return false;
    }
    if(!session)
        return true;
    gds_buf presented = {0};
    r = st_presented(t, &presented);
    gds_buf_free(&presented);
    if(r == UA_STATUSCODE_BADNOTFOUND) {
        ga_not_tested(ctx, "no secure endpoint presents a certificate, so no secure session "
                           "(SRV-SET-02 checks it)");
        return false;
    }
    return true;
}

/* ServerStatus.State: an Enumeration, Int32 on the wire */
static UA_StatusCode read_state(UA_Client *c, UA_ServerState *out);

static UA_StatusCode read_scalar(UA_Client *c, UA_UInt32 id, const UA_DataType *type, void *out) {
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode r = UA_Client_readValueAttribute(c, UA_NODEID_NUMERIC(0, id), &v);
    if(r == UA_STATUSCODE_GOOD && !UA_Variant_hasScalarType(&v, type))
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_copy(v.data, out, type);
    UA_Variant_clear(&v);
    return r;
}

static UA_StatusCode read_state(UA_Client *c, UA_ServerState *out) {
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode r =
        UA_Client_readValueAttribute(c, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_STATE), &v);
    if(r == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_INT32]))
        *out = (UA_ServerState) * (const UA_Int32 *)v.data;
    else if(r == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_SERVERSTATE]))
        *out = *(const UA_ServerState *)v.data;
    else if(r == UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    UA_Variant_clear(&v);
    return r;
}

/* InApplicationSetup and ServerStatus.State as admin. */
static UA_StatusCode setup_state(srv_target *t, bool *inSetup, UA_ServerState *state) {
    UA_StatusCode r = st_admin(t);
    if(r == UA_STATUSCODE_GOOD)
        r = read_scalar(t->client, IAS, &UA_TYPES[UA_TYPES_BOOLEAN], inSetup);
    if(r == UA_STATUSCODE_GOOD)
        r = read_state(t->client, state);
    return r;
}

static const char *state_name(UA_ServerState s) {
    static const char *const names[] = {"Running", "Failed", "NoConfiguration", "Suspended",
                                        "Shutdown", "Test", "CommunicationFault", "Unknown"};
    return (unsigned)s < GDS_ARRAY_SIZE(names) ? names[s] : "?";
}

/* SRV-SET-01 (12 Annex G.2): in application setup ServerStatus.State is
 * NoConfiguration. */
static void t_set_state(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!selected(ctx, t, true))
        return;
    bool inSetup = false;
    UA_ServerState s = UA_SERVERSTATE_UNKNOWN;
    UA_StatusCode r = setup_state(t, &inSetup, &s);
    if(absent(r))
        ga_not_supported(ctx, "InApplicationSetup -> %s", UA_StatusCode_name(r));
    else if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: read InApplicationSetup and State as admin -> %s",
                      UA_StatusCode_name(r));
    else if(!inSetup)
        ga_not_tested(ctx, "InApplicationSetup is FALSE: reset the target to its application "
                           "setup state first (--setup-cmd)");
    else if(s == UA_SERVERSTATE_NOCONFIGURATION)
        ga_pass(ctx, "InApplicationSetup TRUE and State NoConfiguration");
    else
        ga_fail(ctx, "InApplicationSetup TRUE but State is %s, not NoConfiguration", state_name(s));
}

/* SRV-SET-02 (12 Annex G.2): in setup every secure endpoint presents a
 * certificate (the default one), so a client can open a secure channel. */
static void t_set_cert(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!selected(ctx, t, false))
        return;
    UA_EndpointDescription *eps = NULL;
    size_t n = 0, secure = 0, bare = 0;
    UA_StatusCode r = st_endpoints(t, &eps, &n);
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && i < n; i++) {
        if(eps[i].securityMode == UA_MESSAGESECURITYMODE_NONE)
            continue;
        secure++;
        if(eps[i].serverCertificate.length == 0)
            bare++;
    }
    UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "GetEndpoints -> %s", UA_StatusCode_name(r));
    else if(secure == 0)
        ga_fail(ctx, "no secure endpoint in setup (%zu endpoints)", n);
    else if(bare)
        ga_fail(ctx, "%zu of %zu secure endpoints present no certificate", bare, secure);
    else
        ga_pass(ctx, "all %zu secure endpoints present a certificate", secure);
}

/* Push the snapshot plus the test CA and t-good (from a CSR), then apply. */
static UA_StatusCode push_and_apply(srv_target *t, ga_ctx *ctx) {
    UA_StatusCode r = st_learn(t, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = st_snapshot(t, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = st_admin(t);
    UA_TrustListDataType l;
    UA_TrustListDataType_init(&l);
    bool acr = false;
    if(r == UA_STATUSCODE_GOOD)
        r = st_list_copy_add(&t->snap, &t->caDer, &t->caCrl, &l);
    if(r == UA_STATUSCODE_GOOD) {
        l.specifiedLists = ST_MASK_ALL;
        r = st_write_trustlist(t->client, &l, 16384, &acr, ctx);
    }
    UA_TrustListDataType_clear(&l);
    gds_buf csr = {0};
    if(r == UA_STATUSCODE_GOOD)
        r = st_csr(t, t->client, false, NULL, &csr);
    if(r == UA_STATUSCODE_GOOD) {
        gds_buf_free(&t->tGood);
        r = gds_status_to_ua(testca_sign_csr(&t->ca, &csr, t->targetUri, TESTCA_MAX_DAYS, &t->tGood));
    }
    gds_buf_free(&csr);
    if(r == UA_STATUSCODE_GOOD)
        r = st_update_cert(t, t->client, &t->tGood, &t->caDer, 1, &acr);
    if(r == UA_STATUSCODE_GOOD)
        r = st_apply(t->client);
    ga_note(ctx, "trust list with the test CA, t-good and ApplyChanges -> %s",
            UA_StatusCode_name(r));
    st_close(t); /* a new certificate closes the channels (12 §7.10.9) */
    if(r != UA_STATUSCODE_GOOD)
        return r;
    gds_buf now = {0};
    for(long waited = 0;; waited += 200) {
        gds_buf_free(&now);
        r = st_presented(t, &now);
        if((r == UA_STATUSCODE_GOOD && same(&now, &t->tGood)) || waited >= APPLY_WAIT_MS)
            break;
        nap_ms(200);
    }
    bool inUse = r == UA_STATUSCODE_GOOD && same(&now, &t->tGood);
    gds_buf_free(&now);
    return inUse ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINVALIDSTATE;
}

/* SRV-SET-03 (12 Annex G.2): a pushed trust list and certificate do not
 * end setup while the SecurityAdmin Role has no identity. */
static void t_set_no_role(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!selected(ctx, t, true))
        return;
    bool inSetup = false;
    UA_ServerState s = UA_SERVERSTATE_UNKNOWN;
    UA_StatusCode r = setup_state(t, &inSetup, &s);
    if(absent(r)) {
        ga_not_supported(ctx, "InApplicationSetup -> %s", UA_StatusCode_name(r));
        return;
    }
    if(r != UA_STATUSCODE_GOOD || !inSetup) {
        ga_not_tested(ctx, "the target is not in application setup (%s)", UA_StatusCode_name(r));
        return;
    }
    r = push_and_apply(t, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: push and apply the test CA and t-good -> %s (the trust list "
                           "and update tests check it)",
                      UA_StatusCode_name(r));
        return;
    }
    t->setupPushed = true;
    r = setup_state(t, &inSetup, &s);
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "after ApplyChanges InApplicationSetup cannot be read as admin: %s",
                UA_StatusCode_name(r));
    else if(!inSetup)
        ga_fail(ctx, "the target left application setup without a SecurityAdmin identity");
    else
        ga_pass(ctx, "t-good in use and InApplicationSetup still TRUE (State %s)", state_name(s));
}

/* AddIdentity(rule) on WellKnownRole_SecurityAdmin. */
static UA_StatusCode add_identity(UA_Client *c, const UA_IdentityMappingRuleType *rule) {
    UA_Variant in;
    UA_Variant_setScalar(&in, (void *)(uintptr_t)rule, &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(c, UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN),
                                     UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN_ADDIDENTITY),
                                     1, &in, &outN, &out);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

/* SRV-SET-04 (12 Annex G.2; OPC 10000-18): the Auditor's admin identity
 * added to SecurityAdmin ends setup: InApplicationSetup FALSE, State
 * Running. The rule is the admin user name, or the ApplicationUri of the
 * admin application certificate. */
static void t_set_role(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!selected(ctx, t, true))
        return;
    if(!t->setupPushed) {
        ga_not_tested(ctx, "builds on SRV-SET-03 (trust list and t-good applied in setup)");
        return;
    }
    char uri[GDS_MAX_APPLICATION_URI + 1] = "";
    UA_IdentityMappingRuleType rule;
    UA_IdentityMappingRuleType_init(&rule);
    if(t->adminUser) {
        rule.criteriaType = UA_IDENTITYCRITERIATYPE_USERNAME;
        rule.criteria = UA_STRING((char *)(uintptr_t)t->adminUser);
    } else {
        if(x509_san_uri(&t->adminCert, uri, sizeof(uri)) != GDS_OK || !uri[0]) {
            ERR_clear_error();
            ga_not_tested(ctx, "setup: the admin certificate has no ApplicationUri");
            return;
        }
        rule.criteriaType = UA_IDENTITYCRITERIATYPE_APPLICATION;
        rule.criteria = UA_STRING(uri);
    }
    UA_StatusCode r = st_admin(t);
    if(r == UA_STATUSCODE_GOOD)
        r = add_identity(t->client, &rule);
    ga_note(ctx, "AddIdentity(%s %s) -> %s", t->adminUser ? "UserName" : "Application",
            t->adminUser ? t->adminUser : uri, UA_StatusCode_name(r));
    if(r == UA_STATUSCODE_BADALREADYEXISTS) /* 18 §4.4.5: configured before this run */
        r = UA_STATUSCODE_GOOD;
    if(absent(r)) {
        ga_not_supported(ctx, "SecurityAdmin AddIdentity -> %s", UA_StatusCode_name(r));
        return;
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "AddIdentity to SecurityAdmin as admin -> %s", UA_StatusCode_name(r));
        return;
    }
    st_close(t); /* read on a new session */
    bool inSetup = true;
    UA_ServerState s = UA_SERVERSTATE_UNKNOWN;
    r = setup_state(t, &inSetup, &s);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "after AddIdentity InApplicationSetup cannot be read as admin: %s",
                UA_StatusCode_name(r));
    } else if(inSetup || s != UA_SERVERSTATE_RUNNING) {
        ga_fail(ctx, "after AddIdentity to SecurityAdmin InApplicationSetup is %s and State %s",
                inSetup ? "TRUE" : "FALSE", state_name(s));
    } else {
        t->setupEnded = true;
        ga_pass(ctx, "InApplicationSetup FALSE and State Running");
    }
}

/* SRV-SET-05 (12 §7.5): once set up, the server restricts access to the
 * clients its trust list allows. */
static void t_set_closed(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!selected(ctx, t, true))
        return;
    if(!t->setupEnded) {
        ga_not_tested(ctx, "builds on SRV-SET-04 (setup ended)");
        return;
    }
    gds_buf cert = {0}, key = {0};
    EVP_PKEY *k = EVP_RSA_gen(2048);
    gds_status gs = k ? st_make_leaf(NULL, k, "peer-unknown", PEER_UNKNOWN_URI, -3600, 7 * 86400L,
                                     false, 0, &cert)
                      : GDS_ECRYPTO;
    if(gs == GDS_OK)
        gs = x509_key_to_der(k, &key);
    EVP_PKEY_free(k);
    ERR_clear_error();
    if(gs != GDS_OK) {
        gds_buf_free(&cert);
        gds_buf_free_secret(&key);
        ga_not_tested(ctx, "setup: peer-unknown: %s", gds_status_name(gs));
        return;
    }
    UA_Client *c = NULL;
    UA_StatusCode r = st_peer_connect(t, &cert, &key, &c);
    st_client_free(c);
    gds_buf_free(&cert);
    gds_buf_free_secret(&key);
    ga_note(ctx, "session as peer-unknown -> %s", UA_StatusCode_name(r));
    if(r == UA_STATUSCODE_GOOD)
        ga_warn(ctx, "after setup the untrusted peer-unknown is accepted (12 §7.5: access should "
                     "be restricted once the server has its trust list)");
    else if(st_cert_refusal(r))
        ga_pass(ctx, "peer-unknown refused after setup (%s)", UA_StatusCode_name(r));
    else
        ga_not_tested(ctx, "peer-unknown -> %s, not a certificate refusal", UA_StatusCode_name(r));
}

/* Poll State and ShutdownReason until the session is lost or the wait
 * ends. *shutdown: State Shutdown seen with a ShutdownReason text. */
static void watch_shutdown(srv_target *t, bool *shutdown, ga_ctx *ctx) {
    *shutdown = false;
    for(long waited = 0; waited < SHUTDOWN_WAIT_MS; waited += 100) {
        UA_ServerState s = UA_SERVERSTATE_UNKNOWN;
        UA_LocalizedText why;
        UA_LocalizedText_init(&why);
        UA_StatusCode r = read_state(t->client, &s);
        if(r == UA_STATUSCODE_GOOD)
            r = read_scalar(t->client, UA_NS0ID_SERVER_SERVERSTATUS_SHUTDOWNREASON,
                            &UA_TYPES[UA_TYPES_LOCALIZEDTEXT], &why);
        if(r == UA_STATUSCODE_GOOD && s == UA_SERVERSTATE_SHUTDOWN && why.text.length && !*shutdown) {
            *shutdown = true;
            ga_note(ctx, "State Shutdown, ShutdownReason \"%.*s\"", (int)why.text.length,
                    (const char *)why.text.data);
        }
        UA_LocalizedText_clear(&why);
        if(r != UA_STATUSCODE_GOOD) {
            ga_note(ctx, "session lost after %ld ms (%s)", waited, UA_StatusCode_name(r));
            return;
        }
        if(!*shutdown && waited >= 2000) /* no notice: the server is not shutting down */
            return;
        nap_ms(100);
    }
}

/* After the reset: InApplicationSetup once the target is back. */
static UA_StatusCode setup_after_reset(srv_target *t, bool shutdown, bool *inSetup,
                                       ga_ctx *ctx) {
    st_close(t);
    UA_ServerState s = UA_SERVERSTATE_UNKNOWN;
    time_t start = time(NULL);
    UA_StatusCode r;
    for(;;) {
        r = setup_state(t, inSetup, &s);
        if(r == UA_STATUSCODE_GOOD || !shutdown || (long)(time(NULL) - start) > t->settleSec)
            break;
        st_close(t);
        nap_ms(500);
    }
    if(r != UA_STATUSCODE_GOOD && shutdown && (t->restartCmd || isatty(0))) {
        ga_note(ctx, "the target did not come back by itself within %ld s", t->settleSec);
        r = st_restart(t, ctx);
        if(r == UA_STATUSCODE_GOOD)
            r = setup_state(t, inSetup, &s);
    }
    return r;
}

/* SRV-SET-06 (12 §7.10.13): ResetToServerDefaults shuts the server down
 * with a ShutdownReason, and it comes back in application setup. */
static void t_set_reset(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!selected(ctx, t, true))
        return;
    if(!t->allowReset) {
        ga_not_tested(ctx, "needs --allow-reset: ResetToServerDefaults wipes the target's "
                           "configuration");
        return;
    }
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = st_admin(t);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_call(t->client, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION),
                           UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_RESETTOSERVERDEFAULTS),
                           0, NULL, &outN, &out);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    ga_note(ctx, "ResetToServerDefaults -> %s", UA_StatusCode_name(r));
    if(absent(r)) {
        ga_not_supported(ctx, "ResetToServerDefaults -> %s", UA_StatusCode_name(r));
        return;
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "ResetToServerDefaults as SecurityAdmin -> %s", UA_StatusCode_name(r));
        return;
    }
    /* the defaults: what this run pushed is gone, the snapshot stays */
    t->setupPushed = t->setupEnded = false;
    bool shutdown = false, inSetup = false;
    watch_shutdown(t, &shutdown, ctx);
    r = setup_after_reset(t, shutdown, &inSetup, ctx);
    if(r != UA_STATUSCODE_GOOD && shutdown)
        ga_fail(ctx, "after the shutdown the target did not come back within %ld s (%s)",
                t->settleSec, UA_StatusCode_name(r));
    else if(!shutdown && (r != UA_STATUSCODE_GOOD || !inSetup))
        ga_fail(ctx, "after ResetToServerDefaults neither a Shutdown with a ShutdownReason nor "
                     "application setup (InApplicationSetup %s)",
                r == UA_STATUSCODE_GOOD ? "FALSE" : UA_StatusCode_name(r));
    else if(!shutdown)
        ga_fail(ctx, "in application setup again, but State never went to Shutdown with a "
                     "ShutdownReason");
    else if(!inSetup)
        ga_fail(ctx, "State went to Shutdown, but after the restart InApplicationSetup is FALSE");
    else
        ga_pass(ctx, "State Shutdown with a ShutdownReason; back in application setup");
}

const ga_test srv_setup_tests[] = {
    {"SRV-SET-01", "12 Annex G.2", "In application setup State is NoConfiguration", false, true,
     t_set_state},
    {"SRV-SET-02", "12 Annex G.2", "In application setup the endpoints present a certificate",
     false, true, t_set_cert},
    {"SRV-SET-03", "12 Annex G.2", "A push without a SecurityAdmin identity does not end setup",
     true, true, t_set_no_role},
    {"SRV-SET-04", "12 Annex G.2; OPC 10000-18", "A SecurityAdmin identity ends setup", true,
     true, t_set_role},
    {"SRV-SET-05", "12 §7.5", "After setup an untrusted client is refused", true, true,
     t_set_closed},
    {"SRV-SET-06", "12 §7.10.13", "ResetToServerDefaults shuts down and returns to setup", true,
     true, t_set_reset},
};
const size_t srv_setup_count = GDS_ARRAY_SIZE(srv_setup_tests);
