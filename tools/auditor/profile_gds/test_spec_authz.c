/* OpenGDS spec tests: AuthorizationServices (OPC 10000-12 §9.6:
 * AuthorizationServiceType §9.6.4, StartRequestToken §9.6.6,
 * FinishRequestToken §9.6.7, RefreshToken §9.6.8, GetServiceDescription
 * §9.6.9). RequestAccessToken (§9.6.5) is deprecated and not tested.
 * The services are Optional: with no AuthorizationService Object every test
 * is Not supported.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <open62541/nodeids_gds.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "common/limits.h"
#include "gds_target.h"
#include "spec_tests.h"
#include "common/banned.h"

#define NO_RESOURCE "urn:opengds:auditor:no-such-resource"
#define URI_LEN (GDS_MAX_APPLICATION_URI + 1)
/* OPC 10000-12 v1.05.07 (Opc.Ua.Gds.NodeIds.csv); the pinned NodeSet of
 * open62541 v1.5.10 predates it */
#define ID_ACCESSTOKENREQUESTEDAUDITEVENTTYPE 111
#define EV_WAIT 3000 /* ms */

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

/* ---- the token flow ---- */

typedef struct {
    UA_NodeId svc;
    UA_String serviceUri;
    UA_ByteString serviceCert;
    UA_String policyId;
    char resource[URI_LEN];
    char clientUri[URI_LEN];
    UA_NodeId resourceApp, clientApp;
    gds_buf cert, issuer, key;
    UA_Client *c; /* the Session of the Auditor's Client application */
    UA_String access, refresh;
    UA_DateTime accessExpiry;
} az_flow;

static void flow_clear(gds_target *t, az_flow *f) {
    if(f->c)
        gt_drop(f->c);
    UA_Variant in;
    const UA_NodeId *apps[2] = {&f->resourceApp, &f->clientApp};
    for(size_t i = 0; i < 2; i++) {
        if(UA_NodeId_isNull(apps[i]) || !t->client)
            continue;
        UA_Variant_setScalar(&in, (void *)(uintptr_t)apps[i], &UA_TYPES[UA_TYPES_NODEID]);
        size_t outN = 0;
        UA_Variant *out = NULL;
        /* Clean-up: a record already gone is fine. */
        if(gt_call(t, UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION, 1, &in, 0, &outN, &out) !=
           UA_STATUSCODE_GOOD)
            fprintf(stderr, "# clean-up: UnregisterApplication failed\n");
        gt_free_out(out, outN);
    }
    UA_NodeId_clear(&f->svc);
    UA_NodeId_clear(&f->resourceApp);
    UA_NodeId_clear(&f->clientApp);
    UA_String_clear(&f->serviceUri);
    UA_ByteString_clear(&f->serviceCert);
    UA_String_clear(&f->policyId);
    UA_String_clear(&f->access);
    UA_String_clear(&f->refresh);
    gds_buf_free(&f->cert);
    gds_buf_free(&f->issuer);
    gds_buf_free_secret(&f->key);
    memset(f, 0, sizeof(*f));
}

/* The description and the first Anonymous UserTokenPolicy. */
static bool flow_describe(ga_ctx *ctx, gds_target *t, az_flow *f) {
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = az_call(t, NULL, f->svc, "GetServiceDescription", 0, NULL, 3, &outN, &out);
    const UA_String *uri = r == UA_STATUSCODE_GOOD
                               ? uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_STRING])
                               : NULL;
    const UA_ByteString *cert =
        r == UA_STATUSCODE_GOOD ? uac_out_scalar(out, outN, 1, &UA_TYPES[UA_TYPES_BYTESTRING])
                                : NULL;
    const UA_UserTokenPolicy *pol = NULL;
    size_t nPol = 0;
    if(r == UA_STATUSCODE_GOOD && out[2].type == &UA_TYPES[UA_TYPES_USERTOKENPOLICY]) {
        pol = out[2].data;
        nPol = UA_Variant_isScalar(&out[2]) ? 1 : out[2].arrayLength;
    }
    bool ok = false;
    if(!uri || !cert || cert->length == 0) {
        ga_not_tested(ctx, "setup: GetServiceDescription -> %s, no ServiceUri or certificate",
                      UA_StatusCode_name(r));
    } else {
        for(size_t i = 0; i < nPol && !ok; i++) {
            if(pol[i].tokenType != UA_USERTOKENTYPE_ANONYMOUS)
                continue;
            ok = UA_String_copy(&pol[i].policyId, &f->policyId) == UA_STATUSCODE_GOOD &&
                 UA_String_copy(uri, &f->serviceUri) == UA_STATUSCODE_GOOD &&
                 UA_ByteString_copy(cert, &f->serviceCert) == UA_STATUSCODE_GOOD;
        }
        if(!ok)
            ga_not_tested(ctx, "the service offers no Anonymous UserTokenPolicy (the Session's "
                               "own identity); %zu policies", nPol);
    }
    gt_free_out(out, outN);
    return ok;
}

/* StartRequestToken for a ResourceId nobody registered: Bad_NotSupported
 * or Bad_NotImplemented means no token requests at all. */
static bool flow_supported(ga_ctx *ctx, gds_target *t, const UA_NodeId svc) {
    UA_StatusCode r = start_token(t, NULL, svc, NO_RESOURCE, "opengds-auditor-policy");
    if(gt_absent(ctx, r, true, "StartRequestToken"))
        return false;
    if(r == UA_STATUSCODE_BADNOTSUPPORTED || r == UA_STATUSCODE_BADNOTIMPLEMENTED) {
        ga_not_supported(ctx, "StartRequestToken -> %s: the service issues no tokens",
                         UA_StatusCode_name(r));
        return false;
    }
    return true;
}

/* Up to a live Session of a Client application the GDS issued. */
static bool flow_setup(ga_ctx *ctx, gds_target *t, az_flow *f) {
    memset(f, 0, sizeof(*f));
    if(!find_svc(ctx, t, &f->svc) || !flow_supported(ctx, t, f->svc) ||
       !flow_describe(ctx, t, f))
        return false;
    UA_StatusCode r = gt_register(t, UA_APPLICATIONTYPE_SERVER, f->resource,
                                  sizeof(f->resource), &f->resourceApp);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: registering the resource Server -> %s", UA_StatusCode_name(r));
        return false;
    }
    r = gt_issue_key(t, ctx, f->clientUri, sizeof(f->clientUri), &f->clientApp, &f->cert,
                     &f->issuer, &f->key);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: a certificate for a Client application -> %s",
                      UA_StatusCode_name(r));
        return false;
    }
    f->c = gt_new_client_as(t, &f->cert, &f->key, f->clientUri);
    r = f->c ? UA_Client_connect(f->c, t->url) : UA_STATUSCODE_BADOUTOFMEMORY;
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: Session with the GDS-issued certificate -> %s",
                      UA_StatusCode_name(r));
        return false;
    }
    return true;
}

/* StartRequestToken and FinishRequestToken on the Client's Session. */
static UA_StatusCode flow_token(gds_target *t, az_flow *f, const char **step) {
    UA_String res = UA_STRING(f->resource);
    UA_ByteString none = UA_BYTESTRING_NULL;
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], &res, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &f->policyId, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[2], &none, &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    *step = "StartRequestToken";
    UA_StatusCode r = az_call(t, f->c, f->svc, "StartRequestToken", 3, in, 2, &outN, &out);
    const UA_Guid *id = r == UA_STATUSCODE_GOOD
                            ? uac_out_scalar(out, outN, 1, &UA_TYPES[UA_TYPES_GUID])
                            : NULL;
    UA_Guid req;
    if(r == UA_STATUSCODE_GOOD && !id)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(id)
        req = *id;
    gt_free_out(out, outN);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_AnonymousIdentityToken anon;
    UA_AnonymousIdentityToken_init(&anon);
    anon.policyId = f->policyId;
    UA_ExtensionObject tok;
    UA_ExtensionObject_setValue(&tok, &anon, &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN]);
    UA_SignatureData sig;
    UA_SignatureData_init(&sig);
    UA_Variant_setScalar(&in[0], &req, &UA_TYPES[UA_TYPES_GUID]);
    UA_Variant_setArray(&in[1], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[2], &tok, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
    UA_Variant_setScalar(&in[3], &sig, &UA_TYPES[UA_TYPES_SIGNATUREDATA]);
    *step = "FinishRequestToken";
    r = az_call(t, f->c, f->svc, "FinishRequestToken", 4, in, 4, &outN, &out);
    const UA_String *at =
        r == UA_STATUSCODE_GOOD ? uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_STRING]) : NULL;
    const UA_DateTime *ae =
        r == UA_STATUSCODE_GOOD ? uac_out_scalar(out, outN, 1, &UA_TYPES[UA_TYPES_DATETIME]) : NULL;
    const UA_String *rt =
        r == UA_STATUSCODE_GOOD ? uac_out_scalar(out, outN, 2, &UA_TYPES[UA_TYPES_STRING]) : NULL;
    if(r == UA_STATUSCODE_GOOD && (!at || !ae || at->length == 0))
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(r == UA_STATUSCODE_GOOD) {
        f->accessExpiry = *ae;
        r = UA_String_copy(at, &f->access);
        if(r == UA_STATUSCODE_GOOD && rt)
            r = UA_String_copy(rt, &f->refresh);
    }
    gt_free_out(out, outN);
    return r;
}

/* ---- JWT checks (OPC 10000-6 §6.5.2) ---- */

static bool b64url_decode(const uint8_t *in, size_t n, gds_buf *out) {
    *out = (gds_buf){0};
    if(n % 4 == 1 || n > 65536)
        return false;
    size_t padded = (n + 3) / 4 * 4;
    unsigned char *tmp = malloc(padded + 1);
    unsigned char *bin = malloc(padded / 4 * 3 + 1);
    bool ok = tmp && bin;
    for(size_t i = 0; ok && i < padded; i++) {
        uint8_t ch = i < n ? in[i] : '=';
        ok = ch != '+' && ch != '/' && ch != '=' ? true : i >= n;
        tmp[i] = ch == '-' ? '+' : ch == '_' ? '/' : ch;
    }
    int len = ok ? EVP_DecodeBlock(bin, tmp, (int)padded) : -1;
    free(tmp);
    if(len < 0) {
        free(bin);
        return false;
    }
    out->data = bin;
    out->len = (size_t)len - (padded - n); /* EVP_DecodeBlock counts the padding */
    return true;
}

/* The JSON string member `key` of a flat object, unescaped (\" \\ \/). */
static bool json_str(const gds_buf *json, const char *key, char *out, size_t cap) {
    char pat[64];
    (void)snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    size_t pl = strlen(pat);
    for(size_t i = 0; i + pl <= json->len; i++) {
        if(memcmp(json->data + i, pat, pl) != 0)
            continue;
        size_t o = 0;
        for(size_t j = i + pl; j < json->len && o + 1 < cap; j++) {
            char ch = (char)json->data[j];
            if(ch == '"') {
                out[o] = '\0';
                return true;
            }
            if(ch == '\\' && j + 1 < json->len)
                ch = (char)json->data[++j];
            out[o++] = ch;
        }
        return false;
    }
    return false;
}

static bool json_num(const gds_buf *json, const char *key, long long *v) {
    char pat[64];
    (void)snprintf(pat, sizeof(pat), "\"%s\":", key);
    size_t pl = strlen(pat);
    for(size_t i = 0; i + pl < json->len; i++) {
        if(memcmp(json->data + i, pat, pl) != 0)
            continue;
        char num[24];
        size_t o = 0;
        for(size_t j = i + pl; j < json->len && o + 1 < sizeof(num) &&
                               json->data[j] >= '0' && json->data[j] <= '9';
            j++)
            num[o++] = (char)json->data[j];
        num[o] = '\0';
        if(o == 0)
            return false;
        *v = strtoll(num, NULL, 10);
        return true;
    }
    return false;
}

/* aud may be a string or an array of strings (RFC 7519 §4.1.3). */
static bool aud_has(const gds_buf *json, const char *want) {
    char got[URI_LEN];
    if(json_str(json, "aud", got, sizeof(got)))
        return strcmp(got, want) == 0;
    char pat[URI_LEN + 16];
    (void)snprintf(pat, sizeof(pat), "\"%s\"", want);
    const char *a = "\"aud\":[";
    size_t al = strlen(a), pl = strlen(pat);
    for(size_t i = 0; i + al <= json->len; i++) {
        if(memcmp(json->data + i, a, al) != 0)
            continue;
        for(size_t j = i + al; j + pl <= json->len && json->data[j] != ']'; j++)
            if(memcmp(json->data + j, pat, pl) == 0)
                return true;
        return false;
    }
    return false;
}

/* Signature over header.payload with the key of the first certificate. */
static bool jws_verifies(const char *alg, const UA_ByteString *chain, const uint8_t *in,
                         size_t inLen, const gds_buf *sig) {
    const unsigned char *p = chain->data;
    X509 *x = chain->length <= LONG_MAX ? d2i_X509(NULL, &p, (long)chain->length) : NULL;
    EVP_PKEY *k = x ? X509_get0_pubkey(x) : NULL;
    const EVP_MD *md = strcmp(alg, "RS256") == 0 || strcmp(alg, "ES256") == 0 ? EVP_sha256()
                       : strcmp(alg, "ES384") == 0                            ? EVP_sha384()
                                                                              : NULL;
    gds_buf der = {0};
    const gds_buf *s = sig;
    bool ok = k && md;
    if(ok && alg[0] == 'E') { /* R || S -> DER (RFC 7518 §3.4) */
        size_t half = sig->len / 2;
        ECDSA_SIG *es = ECDSA_SIG_new();
        BIGNUM *r = BN_bin2bn(sig->data, (int)half, NULL);
        BIGNUM *sv = BN_bin2bn(sig->data + half, (int)half, NULL);
        ok = es && r && sv && sig->len % 2 == 0 && ECDSA_SIG_set0(es, r, sv) == 1;
        if(ok)
            r = sv = NULL;
        unsigned char *d = NULL;
        int n = ok ? i2d_ECDSA_SIG(es, &d) : -1;
        ok = n > 0;
        if(ok) {
            der.data = d;
            der.len = (size_t)n;
            s = &der;
        }
        BN_free(r);
        BN_free(sv);
        ECDSA_SIG_free(es);
    }
    EVP_MD_CTX *mc = ok ? EVP_MD_CTX_new() : NULL;
    ok = mc && EVP_DigestVerifyInit(mc, NULL, md, NULL, k) == 1 &&
         EVP_DigestVerify(mc, s->data, s->len, in, inLen) == 1;
    EVP_MD_CTX_free(mc);
    OPENSSL_free(der.data);
    X509_free(x);
    ERR_clear_error();
    return ok;
}

/* NULL: the token is fine; else what is wrong with it. */
static const char *jwt_problem(const az_flow *f, const UA_String *tok, char *why, size_t cap) {
    const uint8_t *d = tok->data;
    size_t n = tok->length, d1 = n, d2 = n;
    for(size_t i = 0; i < n; i++) {
        if(d[i] != '.')
            continue;
        if(d1 == n)
            d1 = i;
        else if(d2 == n)
            d2 = i;
        else
            return "the AccessToken has more than three parts";
    }
    if(d2 == n)
        return "the AccessToken is not a JWS Compact Serialization (header.payload.signature)";
    gds_buf h = {0}, pl = {0}, sig = {0};
    const char *bad = NULL;
    char alg[16], iss[URI_LEN];
    long long exp = 0;
    if(!b64url_decode(d, d1, &h) || !b64url_decode(d + d1 + 1, d2 - d1 - 1, &pl) ||
       !b64url_decode(d + d2 + 1, n - d2 - 1, &sig))
        bad = "a part of the AccessToken is not base64url";
    else if(!json_str(&h, "alg", alg, sizeof(alg)))
        bad = "the JWT header has no alg";
    else if(!jws_verifies(alg, &f->serviceCert, d, d2, &sig))
        bad = (snprintf(why, cap, "the %s signature does not verify with the ServiceCertificate",
                        alg), why);
    else if(!json_str(&pl, "iss", iss, sizeof(iss)) || f->serviceUri.length != strlen(iss) ||
            memcmp(iss, f->serviceUri.data, f->serviceUri.length) != 0)
        bad = "iss is not the ServiceUri (OPC 10000-6 §6.5.2.3)";
    else if(!aud_has(&pl, f->resource))
        bad = "aud is not the ResourceId (OPC 10000-6 §6.5.2.3)";
    else if(!json_num(&pl, "exp", &exp) || exp <= (long long)time(NULL))
        bad = "exp is missing or already past";
    gds_buf_free(&h);
    gds_buf_free(&pl);
    gds_buf_free(&sig);
    return bad;
}

static void t_token_flow(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    az_flow f;
    if(flow_setup(ctx, t, &f)) {
        const char *step = "";
        UA_StatusCode r = flow_token(t, &f, &step);
        char why[128];
        const char *bad = r == UA_STATUSCODE_GOOD ? jwt_problem(&f, &f.access, why, sizeof(why))
                                                  : NULL;
        if(r != UA_STATUSCODE_GOOD)
            ga_fail(ctx, "%s for a registered Server, from a Client the GDS issued -> %s", step,
                    UA_StatusCode_name(r));
        else if(bad)
            ga_fail(ctx, "%s", bad);
        else
            ga_pass(ctx, "a JWT AccessToken for the resource, signed with the ServiceCertificate "
                         "key (%zu bytes)", f.access.length);
    }
    flow_clear(t, &f);
}

static void t_token_refresh(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    az_flow f;
    if(flow_setup(ctx, t, &f)) {
        const char *step = "";
        UA_StatusCode r = flow_token(t, &f, &step);
        if(r != UA_STATUSCODE_GOOD) {
            ga_not_tested(ctx, "setup: %s -> %s", step, UA_StatusCode_name(r));
        } else if(f.refresh.length == 0) {
            ga_not_supported(ctx, "FinishRequestToken returned no RefreshToken");
        } else {
            UA_String res = UA_STRING(f.resource);
            UA_Variant in[2];
            UA_Variant_setScalar(&in[0], &res, &UA_TYPES[UA_TYPES_STRING]);
            UA_Variant_setScalar(&in[1], &f.refresh, &UA_TYPES[UA_TYPES_STRING]);
            size_t outN = 0;
            UA_Variant *out = NULL;
            r = az_call(t, f.c, f.svc, "RefreshToken", 2, in, 4, &outN, &out);
            const UA_String *at = r == UA_STATUSCODE_GOOD
                                      ? uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_STRING])
                                      : NULL;
            char why[128];
            const char *bad = at && at->length ? jwt_problem(&f, at, why, sizeof(why)) : NULL;
            if(r != UA_STATUSCODE_GOOD)
                ga_fail(ctx, "RefreshToken with the RefreshToken just issued -> %s",
                        UA_StatusCode_name(r));
            else if(!at || at->length == 0)
                ga_fail(ctx, "RefreshToken returned no AccessToken");
            else if(bad)
                ga_fail(ctx, "the refreshed AccessToken: %s", bad);
            else
                ga_pass(ctx, "a new AccessToken for the RefreshToken");
            gt_free_out(out, outN);
        }
    }
    flow_clear(t, &f);
}

/* ---- audit events (§9.6.10, §9.6.11) ---- */

typedef struct {
    size_t hits, good;
} az_sink;

static void on_event(UA_Client *c, UA_UInt32 subId, void *subCtx, UA_UInt32 monId, void *monCtx,
                     const UA_KeyValueMap fields) {
    (void)c, (void)subId, (void)subCtx, (void)monId;
    az_sink *s = monCtx;
    s->hits++;
    if(fields.mapSize > 0 &&
       UA_Variant_hasScalarType(&fields.map[0].value, &UA_TYPES[UA_TYPES_BOOLEAN]) &&
       *(UA_Boolean *)fields.map[0].value.data)
        s->good++;
}

/* Events of `type` on the Server Object, on the admin Session; *sub is
 * the subscription. */
static UA_StatusCode az_watch(gds_target *t, UA_NodeId type, az_sink *sink, UA_UInt32 *sub) {
    UA_CreateSubscriptionRequest sreq = UA_CreateSubscriptionRequest_default();
    sreq.requestedPublishingInterval = 50;
    UA_CreateSubscriptionResponse sresp =
        UA_Client_Subscriptions_create(t->client, sreq, NULL, NULL, NULL);
    UA_StatusCode r = sresp.responseHeader.serviceResult;
    *sub = sresp.subscriptionId;
    UA_CreateSubscriptionResponse_clear(&sresp);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_QualifiedName qStatus = UA_QUALIFIEDNAME(0, "Status");
    UA_SimpleAttributeOperand sel;
    UA_SimpleAttributeOperand_init(&sel);
    sel.typeDefinitionId = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE);
    sel.attributeId = UA_ATTRIBUTEID_VALUE;
    sel.browsePath = &qStatus;
    sel.browsePathSize = 1;
    UA_LiteralOperand lit;
    UA_LiteralOperand_init(&lit);
    UA_Variant_setScalar(&lit.value, &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_ExtensionObject op;
    UA_ExtensionObject_setValue(&op, &lit, &UA_TYPES[UA_TYPES_LITERALOPERAND]);
    UA_ContentFilterElement el;
    UA_ContentFilterElement_init(&el);
    el.filterOperator = UA_FILTEROPERATOR_OFTYPE;
    el.filterOperands = &op;
    el.filterOperandsSize = 1;
    UA_EventFilter filter;
    UA_EventFilter_init(&filter);
    filter.selectClauses = &sel;
    filter.selectClausesSize = 1;
    filter.whereClause.elements = &el;
    filter.whereClause.elementsSize = 1;
    UA_MonitoredItemCreateRequest item;
    UA_MonitoredItemCreateRequest_init(&item);
    item.itemToMonitor.nodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    item.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
    item.monitoringMode = UA_MONITORINGMODE_REPORTING;
    UA_ExtensionObject_setValue(&item.requestedParameters.filter, &filter,
                                &UA_TYPES[UA_TYPES_EVENTFILTER]);
    item.requestedParameters.queueSize = 64;
    item.requestedParameters.discardOldest = true;
    UA_MonitoredItemCreateResult res = UA_Client_MonitoredItems_createEvent(
        t->client, *sub, UA_TIMESTAMPSTORETURN_NEITHER, item, sink, on_event, NULL);
    r = res.statusCode;
    UA_MonitoredItemCreateResult_clear(&res);
    if(r != UA_STATUSCODE_GOOD)
        (void)UA_Client_Subscriptions_deleteSingle(t->client, *sub);
    else
        (void)UA_Client_run_iterate(t->client, 100);
    return r;
}

static void audit_test(ga_ctx *ctx, gds_target *t, UA_UInt32 typeId, const char *what) {
    az_flow f;
    if(!flow_setup(ctx, t, &f)) {
        flow_clear(t, &f);
        return;
    }
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode r =
        UA_Client_readValueAttribute(t->client, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_AUDITING), &v);
    bool on = r == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_BOOLEAN]) &&
              *(UA_Boolean *)v.data;
    UA_Variant_clear(&v);
    az_sink sink = {0, 0};
    UA_UInt32 sub = 0;
    r = az_watch(t, gt_node(t, typeId), &sink, &sub);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "event subscription -> %s", UA_StatusCode_name(r));
        flow_clear(t, &f);
        return;
    }
    const char *step = "";
    r = flow_token(t, &f, &step);
    for(int waited = 0; waited < EV_WAIT && sink.hits == 0; waited += 50)
        (void)UA_Client_run_iterate(t->client, 50);
    (void)UA_Client_Subscriptions_deleteSingle(t->client, sub);
    if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: %s -> %s", step, UA_StatusCode_name(r));
    else if(!on && sink.hits == 0)
        ga_not_supported(ctx, "Server.Auditing is FALSE and no audit event was raised");
    else if(sink.hits == 0)
        ga_fail(ctx, "no %s event for an issued AccessToken", what);
    else if(sink.good == 0)
        ga_fail(ctx, "%zu %s event(s), none with Status TRUE", sink.hits, what);
    else
        ga_pass(ctx, "%zu %s event(s) with Status TRUE", sink.hits, what);
    flow_clear(t, &f);
}

static void t_audit_requested(ga_ctx *ctx, void *p) {
    audit_test(ctx, p, ID_ACCESSTOKENREQUESTEDAUDITEVENTTYPE, "AccessTokenRequestedAuditEventType");
}

static void t_audit_issued(ga_ctx *ctx, void *p) {
    audit_test(ctx, p, UA_GDSID_ACCESSTOKENISSUEDAUDITEVENTTYPE, "AccessTokenIssuedAuditEventType");
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
    {"gds.az.token_flow", "12 §9.6.6, §9.6.7; 6 §6.5.2", "A Client the GDS issued gets a JWT AccessToken for a registered Server, signed with the ServiceCertificate key",
     true, false, t_token_flow},
    {"gds.az.token_refresh", "12 §9.6.8", "RefreshToken returns a new AccessToken for the RefreshToken just issued",
     true, false, t_token_refresh},
    {"gds.az.audit_requested", "12 §9.6.10", "FinishRequestToken raises an AccessTokenRequestedAuditEventType",
     true, false, t_audit_requested},
    {"gds.az.audit_issued", "12 §9.6.11", "An issued AccessToken raises an AccessTokenIssuedAuditEventType",
     true, false, t_audit_issued},
};
const size_t spec_authz_count = GDS_ARRAY_SIZE(spec_authz_tests);
