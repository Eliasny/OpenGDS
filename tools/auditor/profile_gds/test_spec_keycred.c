/* OpenGDS spec tests: KeyCredential Service, pull model (OPC 10000-12 §8.5:
 * KeyCredentialManagement §8.5.3, KeyCredentialServiceType §8.5.4,
 * StartRequest §8.5.5, FinishRequest §8.5.6, Revoke §8.5.7).
 * The service is Optional: with no KeyCredentialService Object every test is
 * Not supported.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>
#include <open62541/nodeids_gds.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common/limits.h"
#include "gds_target.h"
#include "spec_tests.h"
#include "common/banned.h"

#define URI_LEN    (GDS_MAX_APPLICATION_URI + 1)
#define POLICY_RSA "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"

typedef struct {
    UA_NodeId svc;
    char policy[256];
} kc_svc;

static bool find_svc(ga_ctx *ctx, gds_target *t, kc_svc *k) {
    memset(k, 0, sizeof(*k));
    UA_StatusCode r = gt_service(t, gt_node(t, UA_GDSID_KEYCREDENTIALMANAGEMENT), "StartRequest",
                                 &k->svc);
    if(r == UA_STATUSCODE_BADNOTFOUND || r == UA_STATUSCODE_BADNODEIDUNKNOWN) {
        ga_not_supported(ctx, "no KeyCredentialService Object under KeyCredentialManagement");
        return false;
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "browsing KeyCredentialManagement -> %s", UA_StatusCode_name(r));
        return false;
    }
    /* SecurityPolicyUris (Optional): absent means every policy of GetEndpoints */
    UA_NodeId pn;
    (void)snprintf(k->policy, sizeof(k->policy), "%s", POLICY_RSA);
    if(gt_find(t->client, k->svc, t->ns, "SecurityPolicyUris", &pn) == UA_STATUSCODE_GOOD) {
        UA_Variant v;
        UA_Variant_init(&v);
        if(UA_Client_readValueAttribute(t->client, pn, &v) == UA_STATUSCODE_GOOD &&
           v.type == &UA_TYPES[UA_TYPES_STRING] && v.arrayLength > 0) {
            for(size_t i = 0; i < v.arrayLength; i++) {
                const UA_String *s = &((const UA_String *)v.data)[i];
                if(s->length == 0 || s->length >= sizeof(k->policy))
                    continue;
                char cand[256];
                memcpy(cand, s->data, s->length);
                cand[s->length] = '\0';
                if(!strstr(cand, "Rsa") && !strstr(cand, "Basic256"))
                    continue; /* our key is RSA */
                memcpy(k->policy, cand, s->length + 1);
                break;
            }
        }
        UA_Variant_clear(&v);
        UA_NodeId_clear(&pn);
    }
    return true;
}

static UA_StatusCode kc_call(gds_target *t, const kc_svc *k, const char *name, size_t inN,
                             const UA_Variant *in, size_t minOut, size_t *outN,
                             UA_Variant **out) {
    UA_NodeId m;
    UA_StatusCode r = gt_find(t->client, k->svc, t->ns, name, &m);
    if(r != UA_STATUSCODE_GOOD) {
        *outN = 0;
        *out = NULL;
        return r == UA_STATUSCODE_BADNOTFOUND ? UA_STATUSCODE_BADMETHODINVALID : r;
    }
    r = gt_call_obj(t, k->svc, m, inN, in, minOut, outN, out);
    UA_NodeId_clear(&m);
    return r;
}

/* StartRequest(applicationUri, publicKey, securityPolicyUri, requestedRoles) */
static UA_StatusCode start_req(gds_target *t, UA_Client *via, const kc_svc *k, const char *uri,
                               bool withKey, bool withPolicy, UA_NodeId *req) {
    UA_NodeId_init(req);
    UA_String u = UA_STRING((char *)(uintptr_t)uri);
    UA_ByteString pk = withKey ? (UA_ByteString){t->cert.len, t->cert.data} : UA_BYTESTRING_NULL;
    UA_String pol = withPolicy ? UA_STRING((char *)(uintptr_t)k->policy) : UA_STRING_NULL;
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], &u, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &pk, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[2], &pol, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&in[3], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r;
    if(via) {
        UA_NodeId m;
        r = gt_find(via, k->svc, t->ns, "StartRequest", &m);
        if(r == UA_STATUSCODE_GOOD) {
            r = UA_Client_call(via, k->svc, m, 4, in, &outN, &out);
            UA_NodeId_clear(&m);
        }
    } else {
        r = kc_call(t, k, "StartRequest", 4, in, 1, &outN, &out);
    }
    if(r == UA_STATUSCODE_GOOD) {
        const UA_NodeId *id = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_NODEID]);
        r = id ? UA_NodeId_copy(id, req) : UA_STATUSCODE_BADTYPEMISMATCH;
    }
    gt_free_out(out, outN);
    return r;
}

typedef struct {
    char id[256];
    size_t secretLen;
    char thumb[64];
} kc_cred;

/* FinishRequest(requestId, cancelRequest); polls while not complete. Both
 * Bad_NothingToDo (§8.5.4 text) and Bad_RequestNotComplete (§8.5.6 table)
 * are read as "not yet". */
static UA_StatusCode finish_req(gds_target *t, ga_ctx *ctx, const kc_svc *k, const UA_NodeId *req,
                                bool cancel, kc_cred *c) {
    memset(c, 0, sizeof(*c));
    UA_Boolean cn = cancel;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)req, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &cn, &UA_TYPES[UA_TYPES_BOOLEAN]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r;
    unsigned waited = 0;
    for(;;) {
        r = kc_call(t, k, "FinishRequest", 2, in, 0, &outN, &out);
        if((r != UA_STATUSCODE_BADNOTHINGTODO && r != UA_STATUSCODE_BADREQUESTNOTCOMPLETE) ||
           waited >= t->pollSeconds || cancel)
            break;
        waited++;
        sleep(1);
    }
    ga_note(ctx, "FinishRequest(cancel=%d) -> %s after %u poll(s)", cancel,
            UA_StatusCode_name(r), waited);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_String *id = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_STRING]);
    const UA_ByteString *sec = uac_out_scalar(out, outN, 1, &UA_TYPES[UA_TYPES_BYTESTRING]);
    const UA_String *tp = uac_out_scalar(out, outN, 2, &UA_TYPES[UA_TYPES_STRING]);
    if(id && id->length < sizeof(c->id)) {
        memcpy(c->id, id->data, id->length);
        c->id[id->length] = '\0';
    }
    c->secretLen = sec ? sec->length : 0;
    if(tp && tp->length < sizeof(c->thumb)) {
        memcpy(c->thumb, tp->data, tp->length);
        c->thumb[tp->length] = '\0';
    }
    gt_free_out(out, outN);
    return r;
}

static UA_StatusCode revoke_cred(gds_target *t, const kc_svc *k, const char *id) {
    UA_String s = UA_STRING((char *)(uintptr_t)id);
    UA_Variant in;
    UA_Variant_setScalar(&in, &s, &UA_TYPES[UA_TYPES_STRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = kc_call(t, k, "Revoke", 1, &in, 0, &outN, &out);
    gt_free_out(out, outN);
    return r;
}

static bool register_app(ga_ctx *ctx, gds_target *t, char *uri, size_t len, UA_NodeId *id) {
    UA_StatusCode r = gt_register(t, UA_APPLICATIONTYPE_CLIENT, uri, len, id);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: RegisterApplication -> %s", UA_StatusCode_name(r));
        return false;
    }
    return true;
}

static bool admin(ga_ctx *ctx, gds_target *t) {
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
        return false;
    }
    return true;
}

/* Run the request flow for a fresh application; on Good *c is the credential */
static UA_StatusCode full_flow(ga_ctx *ctx, gds_target *t, const kc_svc *k, kc_cred *c) {
    char uri[URI_LEN];
    UA_NodeId id, req;
    if(!register_app(ctx, t, uri, sizeof(uri), &id))
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_StatusCode r = start_req(t, NULL, k, uri, true, true, &req);
    ga_note(ctx, "StartRequest(%s) -> %s", k->policy, UA_StatusCode_name(r));
    if(r == UA_STATUSCODE_GOOD)
        r = finish_req(t, ctx, k, &req, false, c);
    UA_NodeId_clear(&req);
    UA_NodeId_clear(&id);
    return r;
}

static void t_service(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    kc_svc k;
    if(!admin(ctx, t) || !find_svc(ctx, t, &k))
        return;
    const char *need[] = {"ResourceUri", "ProfileUris", "FinishRequest"};
    for(size_t i = 0; i < GDS_ARRAY_SIZE(need); i++) {
        UA_NodeId n;
        if(gt_find(t->client, k.svc, t->ns, need[i], &n) != UA_STATUSCODE_GOOD) {
            ga_fail(ctx, "KeyCredentialService lacks the Mandatory %s", need[i]);
            UA_NodeId_clear(&k.svc);
            return;
        }
        UA_NodeId_clear(&n);
    }
    ga_pass(ctx, "KeyCredentialService with ResourceUri, ProfileUris, StartRequest, FinishRequest");
    UA_NodeId_clear(&k.svc);
}

static void t_start_unknown_uri(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    kc_svc k;
    if(!admin(ctx, t) || !find_svc(ctx, t, &k))
        return;
    char uri[URI_LEN];
    gt_unique_uri(t, uri, sizeof(uri)); /* never registered */
    UA_NodeId req;
    UA_StatusCode r = start_req(t, NULL, &k, uri, true, true, &req);
    UA_NodeId_clear(&req);
    if(r == UA_STATUSCODE_BADNOTFOUND)
        ga_pass(ctx, "BadNotFound");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "StartRequest accepted an ApplicationUri the GDS does not know");
    else
        ga_warn(ctx, "refused with %s; the spec names BadNotFound", UA_StatusCode_name(r));
    UA_NodeId_clear(&k.svc);
}

static unsigned char upper(char c) {
    unsigned char u = (unsigned char)c;
    return (u >= 'a' && u <= 'z') ? (unsigned char)(u - 0x20u) : u;
}

/* The thumbprint, in any letter case, is the SHA1 of the certificate */
static bool thumb_is(const gds_buf *cert, const char *thumb) {
    char want[X509_THUMBPRINT_LEN];
    if(x509_thumbprint(cert, want) != GDS_OK || strlen(thumb) != strlen(want))
        return false;
    for(size_t i = 0; want[i]; i++)
        if(upper(thumb[i]) != upper(want[i]))
            return false;
    return true;
}

static void t_request_flow(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    kc_svc k;
    if(!admin(ctx, t) || !find_svc(ctx, t, &k))
        return;
    kc_cred c;
    memset(&c, 0, sizeof(c));
    UA_StatusCode r = full_flow(ctx, t, &k, &c);
    bool tpOk = thumb_is(&t->cert, c.thumb);
    if(r == UA_STATUSCODE_BADNOTHINGTODO || r == UA_STATUSCODE_BADREQUESTNOTCOMPLETE)
        ga_not_tested(ctx, "request still pending after %u s (manual approval?)", t->pollSeconds);
    else if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "StartRequest/FinishRequest -> %s", UA_StatusCode_name(r));
    else if(c.id[0] == '\0' || c.secretLen == 0)
        ga_fail(ctx, "FinishRequest returned no CredentialId or no CredentialSecret");
    else if(!tpOk)
        ga_fail(ctx, "CertificateThumbprint '%s' is not the SHA1 of the certificate given", c.thumb);
    else
        ga_pass(ctx, "credential '%s' delivered encrypted for the given certificate", c.id);
    if(r == UA_STATUSCODE_GOOD && c.id[0] && revoke_cred(t, &k, c.id) != UA_STATUSCODE_GOOD)
        ga_note(ctx, "could not revoke the test credential");
    UA_NodeId_clear(&k.svc);
}

/* "If SecurityPolicyUri is provided, PublicKey shall also be provided" */
static void t_policy_without_key(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    kc_svc k;
    if(!admin(ctx, t) || !find_svc(ctx, t, &k))
        return;
    char uri[URI_LEN];
    UA_NodeId id, req;
    if(register_app(ctx, t, uri, sizeof(uri), &id)) {
        UA_StatusCode r = start_req(t, NULL, &k, uri, false, true, &req);
        UA_NodeId_clear(&req);
        if(r == UA_STATUSCODE_GOOD)
            ga_fail(ctx, "StartRequest accepted a SecurityPolicyUri without a PublicKey");
        else
            ga_pass(ctx, "refused with %s", UA_StatusCode_name(r));
        UA_NodeId_clear(&id);
    }
    UA_NodeId_clear(&k.svc);
}

static void t_finish_unknown(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    kc_svc k;
    if(!admin(ctx, t) || !find_svc(ctx, t, &k))
        return;
    UA_NodeId req = UA_NODEID_GUID(t->ns, UA_Guid_random());
    kc_cred c;
    UA_StatusCode r = finish_req(t, ctx, &k, &req, false, &c);
    if(r == UA_STATUSCODE_BADINVALIDARGUMENT)
        ga_pass(ctx, "BadInvalidArgument");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "FinishRequest delivered a credential for an unknown RequestId");
    else if(r == UA_STATUSCODE_BADNOTHINGTODO || r == UA_STATUSCODE_BADREQUESTNOTCOMPLETE)
        ga_fail(ctx, "%s for an unknown request: a client would poll forever",
                UA_StatusCode_name(r));
    else
        ga_warn(ctx, "refused with %s; the spec names BadInvalidArgument", UA_StatusCode_name(r));
    UA_NodeId_clear(&k.svc);
}

static void t_cancel(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    kc_svc k;
    if(!admin(ctx, t) || !find_svc(ctx, t, &k))
        return;
    char uri[URI_LEN];
    UA_NodeId id, req;
    if(!register_app(ctx, t, uri, sizeof(uri), &id)) {
        UA_NodeId_clear(&k.svc);
        return;
    }
    UA_StatusCode r = start_req(t, NULL, &k, uri, true, true, &req);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "StartRequest -> %s", UA_StatusCode_name(r));
    } else {
        kc_cred c1, c2;
        UA_StatusCode r1 = finish_req(t, ctx, &k, &req, true, &c1);
        UA_StatusCode r2 = finish_req(t, ctx, &k, &req, false, &c2);
        if(r1 == UA_STATUSCODE_GOOD && c1.secretLen > 0)
            ga_fail(ctx, "FinishRequest(cancel=TRUE) returned a CredentialSecret");
        else if(r2 == UA_STATUSCODE_GOOD)
            ga_fail(ctx, "the cancelled request still delivers a credential");
        else
            ga_pass(ctx, "cancel -> %s, later FinishRequest -> %s", UA_StatusCode_name(r1),
                    UA_StatusCode_name(r2));
        if(r2 == UA_STATUSCODE_GOOD && c2.id[0])
            (void)revoke_cred(t, &k, c2.id);
    }
    UA_NodeId_clear(&req);
    UA_NodeId_clear(&id);
    UA_NodeId_clear(&k.svc);
}

/* Revoke (Optional): the credential is deleted, a second Revoke fails */
static void t_revoke(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    kc_svc k;
    if(!admin(ctx, t) || !find_svc(ctx, t, &k))
        return;
    UA_NodeId m;
    if(gt_find(t->client, k.svc, t->ns, "Revoke", &m) != UA_STATUSCODE_GOOD) {
        ga_not_supported(ctx, "the KeyCredentialService has no Revoke Method (Optional)");
        UA_NodeId_clear(&k.svc);
        return;
    }
    UA_NodeId_clear(&m);
    kc_cred c;
    UA_StatusCode r = full_flow(ctx, t, &k, &c);
    if(r != UA_STATUSCODE_GOOD || !c.id[0]) {
        ga_not_tested(ctx, "setup: request flow -> %s", UA_StatusCode_name(r));
        UA_NodeId_clear(&k.svc);
        return;
    }
    UA_StatusCode r1 = revoke_cred(t, &k, c.id);
    UA_StatusCode r2 = revoke_cred(t, &k, c.id);
    if(r1 != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "Revoke -> %s", UA_StatusCode_name(r1));
    else if(r2 == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "a second Revoke succeeded: the credential was not deleted");
    else if(r2 == UA_STATUSCODE_BADINVALIDARGUMENT)
        ga_pass(ctx, "revoked; a second Revoke -> BadInvalidArgument");
    else
        ga_warn(ctx, "revoked; a second Revoke -> %s, the spec names BadInvalidArgument",
                UA_StatusCode_name(r2));
    UA_NodeId_clear(&k.svc);
}

static void t_revoke_unknown(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    kc_svc k;
    if(!admin(ctx, t) || !find_svc(ctx, t, &k))
        return;
    UA_StatusCode r = revoke_cred(t, &k, "opengds-auditor-no-such-credential");
    if(gt_absent(ctx, r, true, "Revoke"))
        (void)0;
    else if(r == UA_STATUSCODE_BADINVALIDARGUMENT)
        ga_pass(ctx, "BadInvalidArgument");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "Revoke succeeded for a CredentialId that does not exist");
    else
        ga_warn(ctx, "refused with %s; the spec names BadInvalidArgument", UA_StatusCode_name(r));
    UA_NodeId_clear(&k.svc);
}

/* "This Method shall be called from an encrypted SecureChannel" (§8.5.5) */
static void t_sign_only(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    kc_svc k;
    if(!admin(ctx, t) || !find_svc(ctx, t, &k))
        return;
    char uri[URI_LEN];
    UA_NodeId id, req;
    if(!register_app(ctx, t, uri, sizeof(uri), &id)) {
        UA_NodeId_clear(&k.svc);
        return;
    }
    UA_StatusCode rc;
    UA_Client *c = gt_sign_only_session(t, &rc);
    if(!c) {
        ga_pass(ctx, "no Sign-only session possible (%s): requests are always encrypted",
                UA_StatusCode_name(rc));
    } else {
        UA_StatusCode r = start_req(t, c, &k, uri, true, true, &req);
        UA_NodeId_clear(&req);
        if(r == UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT)
            ga_pass(ctx, "BadSecurityModeInsufficient");
        else if(r == UA_STATUSCODE_GOOD)
            ga_fail(ctx, "StartRequest accepted over a Sign-only SecureChannel");
        else
            ga_warn(ctx, "refused with %s; the spec names BadSecurityModeInsufficient",
                    UA_StatusCode_name(r));
        gt_drop(c);
    }
    UA_NodeId_clear(&id);
    UA_NodeId_clear(&k.svc);
}

const ga_test spec_keycred_tests[] = {
    {"gds.kc.service", "12 §8.5.3, §8.5.4", "KeyCredentialManagement holds a KeyCredentialService with its Mandatory members",
     false, false, t_service},
    {"gds.kc.start_unknown_uri", "12 §8.5.5", "StartRequest for an unknown ApplicationUri returns BadNotFound",
     false, false, t_start_unknown_uri},
    {"gds.kc.request_flow", "12 §8.5.5, §8.5.6", "StartRequest and FinishRequest deliver a credential for the given certificate",
     true, false, t_request_flow},
    {"gds.kc.policy_without_key", "12 §8.5.5", "StartRequest refuses a SecurityPolicyUri without a PublicKey",
     true, false, t_policy_without_key},
    {"gds.kc.finish_unknown", "12 §8.5.6", "FinishRequest refuses an unknown RequestId",
     false, false, t_finish_unknown},
    {"gds.kc.cancel", "12 §8.5.6", "FinishRequest with CancelRequest TRUE ends the request without a credential",
     true, false, t_cancel},
    {"gds.kc.revoke", "12 §8.5.7", "Revoke deletes the KeyCredential",
     true, false, t_revoke},
    {"gds.kc.revoke_unknown", "12 §8.5.7", "Revoke of an unknown CredentialId returns BadInvalidArgument",
     false, false, t_revoke_unknown},
    {"gds.kc.sign_only", "12 §8.5.5", "StartRequest is refused over a SecureChannel that is not encrypted",
     true, false, t_sign_only},
};
const size_t spec_keycred_count = GDS_ARRAY_SIZE(spec_keycred_tests);
