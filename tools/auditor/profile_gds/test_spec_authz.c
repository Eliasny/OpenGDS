/* OpenGDS spec tests: AuthorizationServices (OPC 10000-12 §9.6:
 * AuthorizationServiceType §9.6.4, StartRequestToken §9.6.6,
 * FinishRequestToken §9.6.7, RefreshToken §9.6.8, GetServiceDescription
 * §9.6.9). RequestAccessToken (§9.6.5) is deprecated and not tested.
 * The services are Optional: with no AuthorizationService Object every test
 * is Not supported.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>
#include <open62541/nodeids_gds.h>

#include <limits.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/x509.h>

#include "common/limits.h"
#include "gds_target.h"
#include "spec_tests.h"
#include "common/banned.h"

#define NO_RESOURCE "urn:opengds:auditor:no-such-resource"

static bool find_svc(ga_ctx *ctx, gds_target *t, UA_NodeId *svc) {
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
        return false;
    }
    r = gt_service(t, gt_node(t, UA_GDSID_AUTHORIZATIONSERVICES), "GetServiceDescription", svc);
    if(r == UA_STATUSCODE_BADNOTFOUND || r == UA_STATUSCODE_BADNODEIDUNKNOWN) {
        ga_not_supported(ctx, "no AuthorizationService Object under AuthorizationServices");
        return false;
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "browsing AuthorizationServices -> %s", UA_StatusCode_name(r));
        return false;
    }
    return true;
}

static UA_StatusCode az_call(gds_target *t, UA_Client *via, UA_NodeId svc, const char *name,
                             size_t inN, const UA_Variant *in, size_t minOut, size_t *outN,
                             UA_Variant **out) {
    *outN = 0;
    *out = NULL;
    UA_Client *c = via ? via : t->client;
    UA_NodeId m;
    UA_StatusCode r = gt_find(c, svc, t->ns, name, &m);
    if(r != UA_STATUSCODE_GOOD)
        return r == UA_STATUSCODE_BADNOTFOUND ? UA_STATUSCODE_BADMETHODINVALID : r;
    if(via) {
        r = UA_Client_call(via, svc, m, inN, in, outN, out);
        if(r == UA_STATUSCODE_GOOD && *outN < minOut)
            r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    } else {
        r = gt_call_obj(t, svc, m, inN, in, minOut, outN, out);
    }
    UA_NodeId_clear(&m);
    return r;
}

static UA_StatusCode read_prop(gds_target *t, UA_NodeId svc, const char *name, UA_Variant *v) {
    UA_Variant_init(v);
    UA_NodeId n;
    UA_StatusCode r = gt_find(t->client, svc, t->ns, name, &n);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_readValueAttribute(t->client, n, v);
    UA_NodeId_clear(&n);
    return r;
}

static void t_service(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_NodeId svc;
    if(!find_svc(ctx, t, &svc))
        return;
    const char *need[] = {"ServiceUri", "ServiceCertificate"};
    for(size_t i = 0; i < GDS_ARRAY_SIZE(need); i++) {
        UA_NodeId n;
        if(gt_find(t->client, svc, t->ns, need[i], &n) != UA_STATUSCODE_GOOD) {
            ga_fail(ctx, "AuthorizationService lacks the Mandatory %s", need[i]);
            UA_NodeId_clear(&svc);
            return;
        }
        UA_NodeId_clear(&n);
    }
    ga_pass(ctx, "AuthorizationService with ServiceUri, ServiceCertificate, GetServiceDescription");
    UA_NodeId_clear(&svc);
}

static void t_description(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_NodeId svc;
    if(!find_svc(ctx, t, &svc))
        return;
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = az_call(t, NULL, svc, "GetServiceDescription", 0, NULL, 3, &outN, &out);
    UA_Variant pUri, pCert;
    UA_StatusCode ru = read_prop(t, svc, "ServiceUri", &pUri);
    UA_StatusCode rc = read_prop(t, svc, "ServiceCertificate", &pCert);
    const UA_String *uri = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_STRING]);
    const UA_ByteString *cert = uac_out_scalar(out, outN, 1, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "GetServiceDescription -> %s", UA_StatusCode_name(r));
    } else if(!uri || !cert || uri->length == 0) {
        ga_fail(ctx, "GetServiceDescription returned no ServiceUri or ServiceCertificate");
    } else if(ru != UA_STATUSCODE_GOOD || !UA_Variant_hasScalarType(&pUri, &UA_TYPES[UA_TYPES_STRING]) ||
              !UA_String_equal(uri, (const UA_String *)pUri.data)) {
        ga_fail(ctx, "ServiceUri differs from the ServiceUri Property");
    } else if(rc != UA_STATUSCODE_GOOD ||
              !UA_Variant_hasScalarType(&pCert, &UA_TYPES[UA_TYPES_BYTESTRING]) ||
              !UA_ByteString_equal(cert, (const UA_ByteString *)pCert.data)) {
        ga_fail(ctx, "ServiceCertificate differs from the ServiceCertificate Property");
    } else {
        /* "The ServiceCertificate may be a complete chain" (§9.6.4): DER
         * certificates back to back, the service's own first */
        size_t n = 0;
        bool ok = cert->length > 0 && cert->length <= LONG_MAX;
        const unsigned char *pp = cert->data, *end = cert->data + cert->length;
        while(ok && pp < end) {
            X509 *x = d2i_X509(NULL, &pp, (long)(end - pp));
            ok = x != NULL;
            n += ok;
            X509_free(x);
        }
        ERR_clear_error();
        if(cert->length == 0)
            ga_fail(ctx, "ServiceCertificate is empty; §9.6.4 says it contains the Certificate "
                         "that checks the AccessToken signatures");
        else if(!ok)
            ga_fail(ctx, "ServiceCertificate (%zu bytes) is not DER X.509 certificates "
                         "(entry %zu does not parse)", cert->length, n + 1);
        else
            ga_pass(ctx, "description matches the Properties; %zu certificate(s) parse", n);
    }
    UA_Variant_clear(&pUri);
    UA_Variant_clear(&pCert);
    gt_free_out(out, outN);
    UA_NodeId_clear(&svc);
}

/* StartRequestToken(resourceId, policyId, requestorData) */
static UA_StatusCode start_token(gds_target *t, UA_Client *via, UA_NodeId svc, const char *res,
                                 const char *policy) {
    UA_String r1 = UA_STRING((char *)(uintptr_t)res), p1 = UA_STRING((char *)(uintptr_t)policy);
    UA_ByteString data = UA_BYTESTRING_NULL;
    UA_Variant in[3];
    UA_Variant_setScalar(&in[0], &r1, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &p1, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[2], &data, &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = az_call(t, via, svc, "StartRequestToken", 3, in, 2, &outN, &out);
    gt_free_out(out, outN);
    return r;
}

static void t_start_unknown_resource(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_NodeId svc;
    if(!find_svc(ctx, t, &svc))
        return;
    UA_StatusCode r = start_token(t, NULL, svc, NO_RESOURCE, "opengds-auditor-policy");
    if(gt_absent(ctx, r, true, "StartRequestToken"))
        (void)0;
    else if(r == UA_STATUSCODE_BADNOTFOUND)
        ga_pass(ctx, "BadNotFound");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "StartRequestToken accepted a ResourceId the service does not know");
    else
        ga_warn(ctx, "refused with %s; the spec names BadNotFound", UA_StatusCode_name(r));
    UA_NodeId_clear(&svc);
}

static void t_finish_unknown(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_NodeId svc;
    if(!find_svc(ctx, t, &svc))
        return;
    UA_Guid req = UA_Guid_random();
    UA_AnonymousIdentityToken anon;
    UA_AnonymousIdentityToken_init(&anon);
    UA_ExtensionObject tok;
    UA_ExtensionObject_setValue(&tok, &anon, &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN]);
    UA_SignatureData sig;
    UA_SignatureData_init(&sig);
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], &req, &UA_TYPES[UA_TYPES_GUID]);
    UA_Variant_setArray(&in[1], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[2], &tok, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
    UA_Variant_setScalar(&in[3], &sig, &UA_TYPES[UA_TYPES_SIGNATUREDATA]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = az_call(t, NULL, svc, "FinishRequestToken", 4, in, 0, &outN, &out);
    gt_free_out(out, outN);
    if(gt_absent(ctx, r, true, "FinishRequestToken"))
        (void)0;
    else if(r == UA_STATUSCODE_BADNOTFOUND)
        ga_pass(ctx, "BadNotFound");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "FinishRequestToken issued a token for an unknown RequestId");
    else
        ga_warn(ctx, "refused with %s; the spec names BadNotFound", UA_StatusCode_name(r));
    UA_NodeId_clear(&svc);
}

static void t_refresh_rejected(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_NodeId svc;
    if(!find_svc(ctx, t, &svc))
        return;
    UA_String res = UA_STRING(NO_RESOURCE), tok = UA_STRING("opengds-auditor-not-a-token");
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &res, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &tok, &UA_TYPES[UA_TYPES_STRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = az_call(t, NULL, svc, "RefreshToken", 2, in, 0, &outN, &out);
    gt_free_out(out, outN);
    if(gt_absent(ctx, r, true, "RefreshToken"))
        (void)0;
    else if(r == UA_STATUSCODE_BADNOTFOUND || r == UA_STATUSCODE_BADIDENTITYTOKENREJECTED)
        ga_pass(ctx, "%s", UA_StatusCode_name(r));
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "RefreshToken issued a token for a refresh token it never issued");
    else
        ga_warn(ctx, "refused with %s; the spec names BadNotFound or BadIdentityTokenRejected",
                UA_StatusCode_name(r));
    UA_NodeId_clear(&svc);
}

static void t_sign_only(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_NodeId svc;
    if(!find_svc(ctx, t, &svc))
        return;
    UA_StatusCode rc;
    UA_Client *c = gt_sign_only_session(t, &rc);
    if(!c) {
        ga_pass(ctx, "no Sign-only session possible (%s): requests are always encrypted",
                UA_StatusCode_name(rc));
    } else {
        UA_StatusCode r = start_token(t, c, svc, NO_RESOURCE, "opengds-auditor-policy");
        if(gt_absent(ctx, r, true, "StartRequestToken"))
            (void)0;
        else if(r == UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT)
            ga_pass(ctx, "BadSecurityModeInsufficient");
        else if(r == UA_STATUSCODE_GOOD)
            ga_fail(ctx, "StartRequestToken accepted over a Sign-only SecureChannel");
        else
            ga_warn(ctx, "refused with %s; the encrypted-channel check should come first "
                         "(BadSecurityModeInsufficient)", UA_StatusCode_name(r));
        gt_drop(c);
    }
    UA_NodeId_clear(&svc);
}

const ga_test spec_authz_tests[] = {
    {"gds.az.service", "12 §9.6.3, §9.6.4", "AuthorizationServices holds an AuthorizationService with its Mandatory members",
     false, false, t_service},
    {"gds.az.description", "12 §9.6.9", "GetServiceDescription matches the ServiceUri and ServiceCertificate Properties",
     false, false, t_description},
    {"gds.az.start_unknown_resource", "12 §9.6.6", "StartRequestToken for an unknown ResourceId returns BadNotFound",
     false, false, t_start_unknown_resource},
    {"gds.az.finish_unknown", "12 §9.6.7", "FinishRequestToken refuses an unknown RequestId",
     false, false, t_finish_unknown},
    {"gds.az.refresh_rejected", "12 §9.6.8", "RefreshToken refuses a refresh token it never issued",
     false, false, t_refresh_rejected},
    {"gds.az.sign_only", "12 §9.6.6", "StartRequestToken is refused over a SecureChannel that is not encrypted",
     false, false, t_sign_only},
};
const size_t spec_authz_count = GDS_ARRAY_SIZE(spec_authz_tests);
