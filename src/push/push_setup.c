/* OpenGDS push engine - application setup with PushManagement (OPC 10000-12
 * v1.05.07 Annex G.2). See push_setup.h for the sequence.
 * SPDX-License-Identifier: MPL-2.0 */
#include "push_setup.h"

#include <open62541/client_highlevel.h>

#include <string.h>
#include <time.h>

#include "client/gdsc_push.h"
#include "common/limits.h"
#include "common/ua_args.h"
#include "common/banned.h"

#define DEFAULT_SETTLE_MS 30000u
#define RETRY_MS 500u

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

bool push_setup_in_setup(const push_setup_state *st) {
    return st->state == UA_SERVERSTATE_NOCONFIGURATION && st->hasInSetup && st->inSetup;
}

/* ServerStatus.State is a ServerState enumeration; on the wire an Int32 */
static UA_StatusCode read_state(UA_Client *c, UA_ServerState *out) {
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode r = UA_Client_readValueAttribute(c, ns0(UA_NS0ID_SERVER_SERVERSTATUS_STATE), &v);
    const void *p = NULL;
    if(r == UA_STATUSCODE_GOOD) {
        if(gds_arg_scalar(&v, &UA_TYPES[UA_TYPES_SERVERSTATE], &p) == UA_STATUSCODE_GOOD ||
           gds_arg_scalar(&v, &UA_TYPES[UA_TYPES_INT32], &p) == UA_STATUSCODE_GOOD) {
            UA_Int32 s = *(const UA_Int32 *)p;
            if(s < UA_SERVERSTATE_RUNNING || s > UA_SERVERSTATE_UNKNOWN)
                r = UA_STATUSCODE_BADUNEXPECTEDERROR;
            else
                *out = (UA_ServerState)s;
        } else {
            r = UA_STATUSCODE_BADTYPEMISMATCH;
        }
    }
    UA_Variant_clear(&v);
    return r;
}

UA_StatusCode push_setup_probe(UA_Client *c, push_setup_state *out) {
    memset(out, 0, sizeof(*out));
    out->state = UA_SERVERSTATE_UNKNOWN;
    UA_StatusCode r = read_state(c, &out->state);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    /* By browse path: the Property is Optional and not every Server has it
     * at the standard NodeId */
    UA_NodeId sc = ns0(UA_NS0ID_SERVERCONFIGURATION), prop;
    r = gdsc_find_child(c, &sc, "InApplicationSetup", &prop);
    if(r == UA_STATUSCODE_BADNOMATCH || r == UA_STATUSCODE_BADNODEIDUNKNOWN ||
       r == UA_STATUSCODE_BADNOTFOUND)
        return UA_STATUSCODE_GOOD; /* absent */
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Variant v;
    UA_Variant_init(&v);
    r = UA_Client_readValueAttribute(c, prop, &v);
    const void *p = NULL;
    if(r == UA_STATUSCODE_GOOD) {
        r = gds_arg_scalar(&v, &UA_TYPES[UA_TYPES_BOOLEAN], &p);
        if(r == UA_STATUSCODE_GOOD) {
            out->hasInSetup = true;
            out->inSetup = *(const UA_Boolean *)p;
        }
    }
    UA_Variant_clear(&v);
    UA_NodeId_clear(&prop);
    return r;
}

/* ---- the SecurityAdmin Role (OPC 10000-18 §4.4) ---- */

static UA_NodeId secadmin(void) {
    return ns0(UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN);
}

UA_StatusCode push_setup_admin_identities(UA_Client *c, UA_IdentityMappingRuleType **rules,
                                          size_t *n) {
    *rules = NULL;
    *n = 0;
    UA_NodeId role = secadmin(), prop;
    UA_StatusCode r = gdsc_find_child(c, &role, "Identities", &prop);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Variant v;
    UA_Variant_init(&v);
    r = UA_Client_readValueAttribute(c, prop, &v);
    UA_NodeId_clear(&prop);
    const void *arr = NULL;
    size_t len = 0;
    const UA_DataType *t = &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE];
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_array(&v, t, PUSH_SETUP_MAX_RULES, &arr, &len);
    if(r == UA_STATUSCODE_GOOD && len > 0)
        r = UA_Array_copy(arr, len, (void **)rules, t);
    if(r == UA_STATUSCODE_GOOD)
        *n = len;
    UA_Variant_clear(&v);
    return r;
}

static UA_StatusCode role_call(UA_Client *c, const char *method,
                               const UA_IdentityMappingRuleType *rule) {
    UA_NodeId role = secadmin(), m;
    UA_StatusCode r = gdsc_find_child(c, &role, method, &m);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Variant in, *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in, (void *)(uintptr_t)rule, &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]);
    r = UA_Client_call(c, role, m, 1, &in, &outN, &out);
    if(out)
        UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    UA_NodeId_clear(&m);
    return r;
}

UA_StatusCode push_setup_add_admin(UA_Client *c, const char *applicationUri) {
    if(!applicationUri || applicationUri[0] == '\0' ||
       strlen(applicationUri) >= GDS_MAX_APPLICATION_URI)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_IdentityMappingRuleType rule;
    UA_IdentityMappingRuleType_init(&rule);
    rule.criteriaType = UA_IDENTITYCRITERIATYPE_APPLICATION;
    rule.criteria = UA_STRING((char *)(uintptr_t)applicationUri);
    UA_StatusCode r = role_call(c, "AddIdentity", &rule);
    return r == UA_STATUSCODE_BADALREADYEXISTS ? UA_STATUSCODE_GOOD : r;
}

UA_StatusCode push_setup_remove_anonymous(UA_Client *c, size_t *removed) {
    *removed = 0;
    UA_IdentityMappingRuleType *rules = NULL;
    size_t n = 0;
    UA_StatusCode r = push_setup_admin_identities(c, &rules, &n);
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && i < n; i++) {
        if(rules[i].criteriaType != UA_IDENTITYCRITERIATYPE_ANONYMOUS)
            continue;
        r = role_call(c, "RemoveIdentity", &rules[i]);
        if(r == UA_STATUSCODE_GOOD)
            (*removed)++;
    }
    UA_Array_delete(rules, n, &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]);
    return r;
}

/* ---- the sequence ---- */

void push_setup_report_clear(push_setup_report *r) {
    push_report_clear(&r->push);
    memset(r, 0, sizeof(*r));
}

const char *push_setup_step_name(push_setup_step s) {
    switch(s) {
    case PUSH_SETUP_STEP_NONE: return "none";
    case PUSH_SETUP_STEP_CONNECT: return "connect in setup";
    case PUSH_SETUP_STEP_STATE: return "application setup state";
    case PUSH_SETUP_STEP_ENROLL: return "register with the GDS";
    case PUSH_SETUP_STEP_PUSH: return "push";
    case PUSH_SETUP_STEP_RECONNECT: return "reconnect through the GDS CA";
    case PUSH_SETUP_STEP_ROLE: return "configure the SecurityAdmin Role";
    case PUSH_SETUP_STEP_VERIFY: return "verify the setup state ended";
    }
    return "?";
}

static gds_status fail(push_setup_report *rep, push_setup_step step, UA_StatusCode code) {
    rep->failedStep = step;
    rep->failedCode = code;
    return GDS_EREMOTE;
}

static bool job_valid(const push_setup_job *j) {
    return j && j->serverUri && j->deviceCert && j->deviceCert->data && j->deviceCert->len &&
           j->trustN > 0 && j->trustN <= GDS_MAX_CHAIN_LEN && j->trust && (j->crlN == 0 || j->crls) && j->enroll && j->sign &&
           (j->setupIdentity != GDSC_IDENTITY_USERNAME || (j->setupUser && j->setupPassword)) &&
           j->setupIdentity != GDSC_IDENTITY_X509 && j->conn.cert && j->conn.key &&
           (j->conn.endpointUrl || j->conn.reversePort);
}

/* The connection with the given trust and identity */
static gdsc_session_cfg session_cfg(const push_setup_job *j, const gds_buf *trust, size_t trustN,
                                    bool withCrls, gdsc_identity id) {
    gdsc_session_cfg c = j->conn;
    c.serverUri = j->serverUri;
    c.trust = trust;
    c.trustN = trustN;
    c.crls = withCrls ? j->crls : NULL;
    c.crlN = withCrls ? j->crlN : 0;
    c.identity = id;
    c.identityCert = NULL;
    c.identityKey = NULL;
    c.userName = id == GDSC_IDENTITY_USERNAME ? j->setupUser : NULL;
    c.password = id == GDSC_IDENTITY_USERNAME ? j->setupPassword : NULL;
    return c;
}

/* After ApplyChanges the device may restart its endpoints (§7.7.2): retry
 * until settleMs passes */
static UA_StatusCode open_settled(const push_setup_job *j, const gdsc_session_cfg *c,
                                  gdsc_session **s) {
    const UA_UInt32 settle = j->settleMs ? j->settleMs : DEFAULT_SETTLE_MS;
    const struct timespec step = {0, (long)RETRY_MS * 1000L * 1000L};
    UA_StatusCode r;
    for(UA_UInt32 waited = 0;; waited += RETRY_MS) {
        r = gdsc_session_open(c, s);
        if(r == UA_STATUSCODE_GOOD || waited >= settle)
            return r;
        nanosleep(&step, NULL);
    }
}

/* Steps 1-3 on the setup session. The device is trusted through its
 * pre-authorized certificate, or through the GDS CA once the GDS issued it a
 * certificate (then it is found configured and refused in step 1). */
static gds_status setup_and_push(const push_setup_job *j, push_setup_report *rep) {
    gds_buf trust[GDS_MAX_CHAIN_LEN + 1];
    size_t trustN = 0;
    trust[trustN++] = *j->deviceCert;
    for(size_t i = 0; i < j->trustN && trustN < GDS_ARRAY_SIZE(trust); i++)
        trust[trustN++] = j->trust[i];
    gdsc_session_cfg c = session_cfg(j, trust, trustN, true, j->setupIdentity);
    gdsc_session *s = NULL;
    UA_StatusCode r = gdsc_session_open(&c, &s);
    if(r != UA_STATUSCODE_GOOD)
        return fail(rep, PUSH_SETUP_STEP_CONNECT, r);
    gds_status st = GDS_OK;
    UA_Client *cl = gdsc_session_client(s);
    r = push_setup_probe(cl, &rep->before);
    if(r != UA_STATUSCODE_GOOD)
        st = fail(rep, PUSH_SETUP_STEP_STATE, r);
    else if(!push_setup_in_setup(&rep->before))
        st = fail(rep, PUSH_SETUP_STEP_STATE, UA_STATUSCODE_BADINVALIDSTATE);
    UA_ApplicationDescription ad;
    UA_ApplicationDescription_init(&ad);
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    if(st == GDS_OK) {
        r = gdsc_session_server_description(s, &ad);
        if(r != UA_STATUSCODE_GOOD)
            st = fail(rep, PUSH_SETUP_STEP_ENROLL, r);
    }
    if(st == GDS_OK) {
        gds_buf seen = {0};
        UA_ByteString cert = UA_BYTESTRING_NULL;
        if(gdsc_session_server_cert(s, &seen) == GDS_OK) {
            cert.data = seen.data;
            cert.length = seen.len;
        }
        st = j->enroll(j->enrollCtx, &ad, j->conn.reversePort ? NULL : j->conn.endpointUrl,
                       &cert, &tl);
        gds_buf_free(&seen);
        if(st != GDS_OK) {
            rep->failedStep = PUSH_SETUP_STEP_ENROLL;
            rep->failedCode = UA_STATUSCODE_GOOD;
        }
    }
    if(st == GDS_OK) {
        push_job pj;
        memset(&pj, 0, sizeof(pj));
        pj.certificateGroup = j->certificateGroup;
        pj.trustListNode = j->trustListNode;
        pj.certificateType = j->certificateType;
        pj.trustList = &tl;
        pj.sign = j->sign;
        pj.signCtx = j->signCtx;
        pj.issuers = j->trust;
        pj.issuersN = j->trustN;
        st = push_run(cl, &pj, &rep->push);
        if(st != GDS_OK) {
            rep->failedStep = PUSH_SETUP_STEP_PUSH;
            rep->failedCode = rep->push.failedCode;
        }
    }
    UA_TrustListDataType_clear(&tl);
    UA_ApplicationDescription_clear(&ad);
    gdsc_session_close(s);
    return st;
}

/* Step 4 */
static gds_status configure_role(const push_setup_job *j, const char *adminUri,
                                 push_setup_report *rep) {
    gdsc_session_cfg c = session_cfg(j, j->trust, j->trustN, true, j->setupIdentity);
    gdsc_session *s = NULL;
    UA_StatusCode r = open_settled(j, &c, &s);
    if(r != UA_STATUSCODE_GOOD)
        return fail(rep, PUSH_SETUP_STEP_RECONNECT, r);
    r = push_setup_add_admin(gdsc_session_client(s), adminUri);
    if(r == UA_STATUSCODE_GOOD) {
        rep->adminAdded = true;
        r = push_setup_remove_anonymous(gdsc_session_client(s), &rep->anonymousRemoved);
    }
    gdsc_session_close(s);
    return r == UA_STATUSCODE_GOOD ? GDS_OK : fail(rep, PUSH_SETUP_STEP_ROLE, r);
}

/* Step 5: our certificate alone is SecurityAdmin (Annex G.3), and the
 * device is out of the setup state */
static gds_status verify(const push_setup_job *j, push_setup_report *rep) {
    gdsc_session_cfg c = session_cfg(j, j->trust, j->trustN, true, GDSC_IDENTITY_APP_CERT);
    gdsc_session *s = NULL;
    UA_StatusCode r = open_settled(j, &c, &s);
    if(r != UA_STATUSCODE_GOOD)
        return fail(rep, PUSH_SETUP_STEP_VERIFY, r);
    r = push_setup_probe(gdsc_session_client(s), &rep->after);
    /* Reading the Identities needs SecurityAdmin on a Server that restricts
     * them; any answer but access denied shows the mapping works */
    if(r == UA_STATUSCODE_GOOD) {
        UA_IdentityMappingRuleType *rules = NULL;
        size_t n = 0;
        UA_StatusCode ri = push_setup_admin_identities(gdsc_session_client(s), &rules, &n);
        UA_Array_delete(rules, n, &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]);
        if(ri == UA_STATUSCODE_BADUSERACCESSDENIED)
            r = ri;
    }
    gdsc_session_close(s);
    if(r != UA_STATUSCODE_GOOD)
        return fail(rep, PUSH_SETUP_STEP_VERIFY, r);
    if(rep->after.state != UA_SERVERSTATE_RUNNING || (rep->after.hasInSetup && rep->after.inSetup))
        return fail(rep, PUSH_SETUP_STEP_VERIFY, UA_STATUSCODE_BADINVALIDSTATE);
    rep->done = true;
    return GDS_OK;
}

gds_status push_setup_run(const push_setup_job *j, push_setup_report *rep) {
    memset(rep, 0, sizeof(*rep));
    if(!job_valid(j))
        return GDS_EINVAL;
    char uri[GDS_MAX_APPLICATION_URI];
    const char *adminUri = j->adminUri;
    if(!adminUri) {
        if(gdsc_cert_uri(j->conn.cert, uri, sizeof(uri)) != GDS_OK)
            return GDS_EINVAL;
        adminUri = uri;
    }
    gds_status s = setup_and_push(j, rep);
    if(s == GDS_OK)
        s = configure_role(j, adminUri, rep);
    if(s == GDS_OK)
        s = verify(j, rep);
    return s;
}
