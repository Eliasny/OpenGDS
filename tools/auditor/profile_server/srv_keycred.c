/* OpenGDS Auditor server profile: KeyCredential push (srv_keycred.c).
 * ConformanceUnit: Push Model for KeyCredential Service (OPC 10000-12 §8.6).
 * Catalogue: docs/auditor/server-profile.md, "KeyCredential push".
 *
 * The Auditor plays the administration component of §8.4: it creates a
 * KeyCredentialConfiguration Object (§8.6.3), asks for the encrypting key
 * (§8.6.6), hands over a secret encrypted for the target's certificate as
 * an RsaEncryptedSecret (§8.6.7, OPC 10000-4 §7.40.2.4) and deletes the
 * Object again (§8.6.8). Methods and Properties of the Object are found by
 * BrowseName, so a target may give its instances their own NodeIds.
 * SPDX-License-Identifier: MPL-2.0 */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <open62541/client_highlevel.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "common/enc_secret.h"
#include "common/banned.h"

#define KC_FOLDER UA_NS0ID_KEYCREDENTIALCONFIGURATION
#define KC_CREATE UA_NS0ID_KEYCREDENTIALCONFIGURATION_CREATECREDENTIAL
#define KC_TYPE UA_NS0ID_KEYCREDENTIALCONFIGURATIONTYPE
#define KC_RESOURCE "urn:opengds:auditor:kc-resource"
#define KC_PROFILE "http://opcfoundation.org/UA-Profile/Authentication/mqtt-username"
/* port 1 on loopback: nothing listens there (SRV-KC-10) */
#define KC_ENDPOINT "mqtts://127.0.0.1:1"
#define KC_CREDID "gdsaudit-kc"
#define KC_POLICY_PREFIX "http://opcfoundation.org/UA/SecurityPolicy#"
#define KC_SECRET_LEN 32
#define KC_STATUS_WAIT_S 30L

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

static void nap_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static bool absent(UA_StatusCode r) {
    return r == UA_STATUSCODE_BADMETHODINVALID || r == UA_STATUSCODE_BADNODEIDUNKNOWN ||
           r == UA_STATUSCODE_BADNOTIMPLEMENTED || r == UA_STATUSCODE_BADNOTSUPPORTED ||
           r == UA_STATUSCODE_BADNOTFOUND || r == UA_STATUSCODE_BADNOMATCH;
}

/* A BrowseName no earlier run used */
static void kc_name(char *out, size_t len, const char *what) {
    (void)snprintf(out, len, "gdsaudit-%s-%llx", what,
                   (unsigned long long)(UA_DateTime_now() / UA_DATETIME_MSEC));
}

/* CreateCredential(Name, ResourceUri, ProfileUri, EndpointUrls) on the
 * KeyCredentialConfiguration Object (12 §8.6.3). */
static UA_StatusCode kc_create(UA_Client *c, const char *name, const char *res,
                               const char *prof, const char *url, UA_NodeId *node) {
    UA_NodeId_init(node);
    UA_String s[3] = {UA_STRING((char *)(uintptr_t)name), UA_STRING((char *)(uintptr_t)res),
                      UA_STRING((char *)(uintptr_t)prof)};
    UA_String urls[1] = {UA_STRING((char *)(uintptr_t)url)};
    UA_Variant in[4];
    for(size_t i = 0; i < 3; i++)
        UA_Variant_setScalar(&in[i], &s[i], &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&in[3], urls, 1, &UA_TYPES[UA_TYPES_STRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r =
        uac_call(c, "CreateCredential", ns0(KC_FOLDER), ns0(KC_CREATE), 4, in, 1, &outN, &out);
    if(r == UA_STATUSCODE_GOOD) {
        const UA_NodeId *n = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_NODEID]);
        r = n ? UA_NodeId_copy(n, node) : UA_STATUSCODE_BADTYPEMISMATCH;
    }
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

/* Call the method `name` of the credential Object */
static UA_StatusCode kc_call(UA_Client *c, const UA_NodeId *node, const char *name, size_t inN,
                             const UA_Variant *in, size_t minOut, size_t *outN,
                             UA_Variant **out) {
    *outN = 0;
    *out = NULL;
    UA_NodeId m;
    UA_StatusCode r = uac_find_child(c, *node, name, &m);
    if(r == UA_STATUSCODE_GOOD)
        r = uac_call(c, name, *node, m, inN, in, minOut, outN, out);
    UA_NodeId_clear(&m);
    return r;
}

static UA_StatusCode kc_delete(UA_Client *c, const UA_NodeId *node) {
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = kc_call(c, node, "DeleteCredential", 0, NULL, 0, &outN, &out);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

/* UpdateCredential(CredentialId, CredentialSecret, CertificateThumbprint,
 * SecurityPolicyUri) (12 §8.6.7) */
static UA_StatusCode kc_update(UA_Client *c, const UA_NodeId *node, const gds_buf *secret,
                               const char *thumb, const char *policy) {
    UA_String id = UA_STRING(KC_CREDID);
    UA_ByteString sec = {secret->len, secret->data};
    UA_String tp = UA_STRING((char *)(uintptr_t)thumb);
    UA_String pol = UA_STRING((char *)(uintptr_t)policy);
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], &id, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &sec, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[2], &tp, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[3], &pol, &UA_TYPES[UA_TYPES_STRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = kc_call(c, node, "UpdateCredential", 4, in, 0, &outN, &out);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

/* GetEncryptingKey(CredentialId, RequestedSecurityPolicyUri) (12 §8.6.6):
 * the PublicKey and the RevisedSecurityPolicyUri */
static UA_StatusCode kc_get_key(UA_Client *c, const UA_NodeId *node, gds_buf *key,
                                char *policy, size_t policyLen) {
    UA_String id = UA_STRING(KC_CREDID);
    UA_String req = UA_STRING_NULL;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &id, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &req, &UA_TYPES[UA_TYPES_STRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = kc_call(c, node, "GetEncryptingKey", 2, in, 2, &outN, &out);
    const UA_ByteString *k = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
    const UA_String *p = uac_out_scalar(out, outN, 1, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD && (!k || !p))
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    else if(r == UA_STATUSCODE_GOOD && (k->length > GDS_MAX_CERT_SIZE || p->length >= policyLen))
        r = UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    if(r == UA_STATUSCODE_GOOD && gds_buf_dup(k->data, k->length, key) != GDS_OK)
        r = UA_STATUSCODE_BADOUTOFMEMORY;
    if(r == UA_STATUSCODE_GOOD) {
        if(p->length)
            memcpy(policy, p->data, p->length);
        policy[p->length] = '\0';
    }
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

/* A Property of the Object, read as its Value */
static UA_StatusCode kc_read(UA_Client *c, const UA_NodeId *node, const char *prop,
                             UA_Variant *v) {
    UA_Variant_init(v);
    UA_NodeId n;
    UA_StatusCode r = uac_find_child(c, *node, prop, &n);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_readValueAttribute(c, n, v);
    UA_NodeId_clear(&n);
    return r;
}

static bool kc_string_is(const UA_Variant *v, const char *want) {
    if(!UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_STRING]))
        return false;
    const UA_String *s = v->data;
    return s->length == strlen(want) && (!s->length || memcmp(s->data, want, s->length) == 0);
}

/* Is the HasTypeDefinition of node KeyCredentialConfigurationType? */
static bool kc_typed(UA_Client *c, const UA_NodeId *node) {
    UA_BrowseRequest req;
    UA_BrowseRequest_init(&req);
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = *node;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.referenceTypeId = ns0(UA_NS0ID_HASTYPEDEFINITION);
    bd.resultMask = UA_BROWSERESULTMASK_NONE;
    req.nodesToBrowse = &bd;
    req.nodesToBrowseSize = 1;
    UA_BrowseResponse resp = UA_Client_Service_browse(c, req);
    bool ok = resp.responseHeader.serviceResult == UA_STATUSCODE_GOOD && resp.resultsSize == 1 &&
              resp.results[0].referencesSize == 1 &&
              UA_NodeId_equal(&resp.results[0].references[0].nodeId.nodeId, &(UA_NodeId){
                                  0, UA_NODEIDTYPE_NUMERIC, {KC_TYPE}});
    UA_BrowseResponse_clear(&resp);
    return ok;
}

/* The Object of a Good CreateCredential: why says what is wrong (empty: fine) */
static void kc_check_object(UA_Client *c, const UA_NodeId *node, char *why, size_t len) {
    why[0] = '\0';
    UA_Variant v;
    UA_StatusCode r = kc_read(c, node, "ResourceUri", &v);
    if(r != UA_STATUSCODE_GOOD)
        (void)snprintf(why, len, "ResourceUri of the new Object -> %s", UA_StatusCode_name(r));
    else if(!kc_string_is(&v, KC_RESOURCE))
        (void)snprintf(why, len, "ResourceUri is not the one given");
    UA_Variant_clear(&v);
    if(why[0])
        return;
    r = kc_read(c, node, "ProfileUri", &v);
    if(r != UA_STATUSCODE_GOOD)
        (void)snprintf(why, len, "ProfileUri of the new Object -> %s", UA_StatusCode_name(r));
    else if(!kc_string_is(&v, KC_PROFILE))
        (void)snprintf(why, len, "ProfileUri is not the one given");
    UA_Variant_clear(&v);
    if(!why[0] && !kc_typed(c, node))
        (void)snprintf(why, len, "the TypeDefinition is not KeyCredentialConfigurationType");
}

static bool admin_ready(ga_ctx *ctx, srv_target *t) {
    if(t->kcAbsent) {
        ga_not_supported(ctx, "the target offers no CreateCredential (SRV-KC-01)");
        return false;
    }
    UA_StatusCode r = st_admin(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
        return false;
    }
    return true;
}

static bool have_object(ga_ctx *ctx, srv_target *t) {
    if(!admin_ready(ctx, t))
        return false;
    if(!t->kcCreated) {
        ga_not_tested(ctx, "no credential Object (SRV-KC-01 did not pass)");
        return false;
    }
    return true;
}

/* SRV-KC-01 (12 §8.6.3, §8.6.5) */
static void t_kc_create(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_StatusCode r = st_admin(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
        return;
    }
    char name[64], why[160];
    kc_name(name, sizeof(name), "kc");
    UA_NodeId node;
    r = kc_create(t->client, name, KC_RESOURCE, KC_PROFILE, KC_ENDPOINT, &node);
    ga_note(ctx, "CreateCredential(%s) -> %s", name, UA_StatusCode_name(r));
    if(absent(r)) {
        t->kcAbsent = true;
        ga_not_supported(ctx, "CreateCredential -> %s", UA_StatusCode_name(r));
        return;
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "CreateCredential with valid arguments -> %s", UA_StatusCode_name(r));
        return;
    }
    kc_check_object(t->client, &node, why, sizeof(why));
    if(why[0]) {
        ga_fail(ctx, "CreateCredential returned Good, but %s", why);
        UA_NodeId_clear(&node);
        return;
    }
    UA_NodeId_clear(&t->kcNode);
    t->kcNode = node;
    t->kcCreated = true;
    ga_pass(ctx, "a KeyCredentialConfigurationType Object with the ResourceUri and ProfileUri given");
}

/* SRV-KC-02 (12 §8.6.3): each argument checked */
static void t_kc_invalid(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t))
        return;
    static const struct {
        const char *what, *res, *prof, *url;
    } cases[3] = {
        {"ResourceUri", "not a uri", KC_PROFILE, KC_ENDPOINT},
        {"ProfileUri", KC_RESOURCE, "::not-a-uri", KC_ENDPOINT},
        {"EndpointUrl", KC_RESOURCE, KC_PROFILE, "127.0.0.1:1883"},
    };
    const char *good = NULL, *other = NULL;
    UA_StatusCode otherCode = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < 3; i++) {
        char name[64];
        kc_name(name, sizeof(name), "kc-bad");
        UA_NodeId node;
        UA_StatusCode r =
            kc_create(t->client, name, cases[i].res, cases[i].prof, cases[i].url, &node);
        ga_note(ctx, "CreateCredential with an invalid %s -> %s", cases[i].what,
                UA_StatusCode_name(r));
        if(r == UA_STATUSCODE_GOOD) {
            if(!good)
                good = cases[i].what;
            UA_StatusCode d = kc_delete(t->client, &node);
            ga_note(ctx, "DeleteCredential of it -> %s", UA_StatusCode_name(d));
        } else if(r != UA_STATUSCODE_BADINVALIDARGUMENT && !other) {
            other = cases[i].what;
            otherCode = r;
        }
        UA_NodeId_clear(&node);
    }
    if(good)
        ga_fail(ctx, "CreateCredential accepted an invalid %s", good);
    else if(other)
        ga_warn(ctx, "an invalid %s -> %s, not Bad_InvalidArgument", other,
                UA_StatusCode_name(otherCode));
    else
        ga_pass(ctx, "each invalid argument -> Bad_InvalidArgument");
}

/* SRV-KC-03 (12 §8.6.3, §8.6.7, §8.6.8): SecurityAdmin only */
static void t_kc_user(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t))
        return;
    if(!t->userName) {
        ga_not_tested(ctx, "no user fixture (--user)");
        return;
    }
    UA_Client *c = NULL;
    UA_StatusCode r = st_open(t, ST_USER, NULL, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT, &c);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: session as user over SignAndEncrypt -> %s",
                      UA_StatusCode_name(r));
        return;
    }
    char name[64];
    kc_name(name, sizeof(name), "kc-user");
    UA_NodeId node;
    UA_StatusCode rc[3];
    rc[0] = kc_create(c, name, KC_RESOURCE, KC_PROFILE, KC_ENDPOINT, &node);
    if(rc[0] == UA_STATUSCODE_GOOD)
        (void)kc_delete(t->client, &node); /* the admin cleans up */
    UA_NodeId_clear(&node);
    gds_buf secret = {(uint8_t *)(uintptr_t)"user-secret", 11};
    rc[1] = t->kcCreated ? kc_update(c, &t->kcNode, &secret, "", "") : UA_STATUSCODE_BADUSERACCESSDENIED;
    rc[2] = t->kcCreated ? kc_delete(c, &t->kcNode) : UA_STATUSCODE_BADUSERACCESSDENIED;
    st_client_free(c);
    static const char *const what[3] = {"CreateCredential", "UpdateCredential", "DeleteCredential"};
    size_t good = 3, other = 3;
    for(size_t i = 0; i < 3; i++) {
        ga_note(ctx, "%s as user -> %s", what[i], UA_StatusCode_name(rc[i]));
        if(rc[i] == UA_STATUSCODE_GOOD && good == 3)
            good = i;
        else if(rc[i] != UA_STATUSCODE_GOOD && rc[i] != UA_STATUSCODE_BADUSERACCESSDENIED &&
                other == 3)
            other = i;
    }
    if(good < 3)
        ga_fail(ctx, "%s as a user without SecurityAdmin -> Good", what[good]);
    else if(other < 3)
        ga_warn(ctx, "%s as user -> %s, not Bad_UserAccessDenied", what[other],
                UA_StatusCode_name(rc[other]));
    else if(!t->kcCreated)
        ga_pass(ctx, "CreateCredential as user -> Bad_UserAccessDenied (no Object for the others)");
    else
        ga_pass(ctx, "Create-, Update- and DeleteCredential as user -> Bad_UserAccessDenied");
}

/* SRV-KC-04 (12 §8.6.6) */
static void t_kc_key(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!have_object(ctx, t))
        return;
    gds_buf_free(&t->kcKey);
    t->kcPolicy[0] = '\0';
    UA_StatusCode r =
        kc_get_key(t->client, &t->kcNode, &t->kcKey, t->kcPolicy, sizeof(t->kcPolicy));
    ga_note(ctx, "GetEncryptingKey(%s, \"\") -> %s", KC_CREDID, UA_StatusCode_name(r));
    if(absent(r))
        ga_not_supported(ctx, "GetEncryptingKey -> %s", UA_StatusCode_name(r));
    else if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "GetEncryptingKey -> %s", UA_StatusCode_name(r));
    else if(!t->kcKey.len)
        ga_fail(ctx, "GetEncryptingKey returned an empty PublicKey");
    else if(strncmp(t->kcPolicy, KC_POLICY_PREFIX, strlen(KC_POLICY_PREFIX)) != 0 ||
            strcmp(t->kcPolicy, KC_POLICY_PREFIX "None") == 0)
        ga_fail(ctx, "RevisedSecurityPolicyUri \"%s\" is not a known SecurityPolicy",
                t->kcPolicy);
    else
        ga_pass(ctx, "PublicKey of %zu bytes for %s", t->kcKey.len, t->kcPolicy);
}

/* A fresh secret encrypted to the key of SRV-KC-04, and the SHA1
 * thumbprint of that certificate. why says why not (empty: done). */
static void kc_encrypt(const srv_target *t, gds_buf *secret, gds_buf *blob,
                       char thumb[GDS_SHA1_HEX], char *why, size_t whyLen) {
    why[0] = '\0';
    if(!t->kcKey.len) {
        (void)snprintf(why, whyLen, "no encrypting key (SRV-KC-04 did not pass)");
        return;
    }
    if(!gds_enc_secret_policy_ok(t->kcPolicy, strlen(t->kcPolicy))) {
        (void)snprintf(why, whyLen, "the Auditor cannot encrypt for %s", t->kcPolicy);
        return;
    }
    uint8_t raw[KC_SECRET_LEN];
    bool ok = RAND_bytes(raw, KC_SECRET_LEN) == 1 && gds_buf_dup(raw, KC_SECRET_LEN, secret) == GDS_OK;
    OPENSSL_cleanse(raw, sizeof(raw));
    if(!ok) {
        (void)snprintf(why, whyLen, "no random secret");
        return;
    }
    gds_status gs = gds_sha1_hex(&t->kcKey, thumb);
    if(gs == GDS_OK)
        gs = gds_enc_secret_rsa(t->kcPolicy, strlen(t->kcPolicy), &t->kcKey, secret, blob);
    if(gs != GDS_OK)
        (void)snprintf(why, whyLen, "the PublicKey is not an RSA certificate for %s (%s)",
                       t->kcPolicy, gds_status_name(gs));
}

/* SRV-KC-05 (12 §8.6.7) */
static void t_kc_update(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!have_object(ctx, t))
        return;
    gds_buf secret = {0}, blob = {0};
    char thumb[GDS_SHA1_HEX] = "", why[160];
    kc_encrypt(t, &secret, &blob, thumb, why, sizeof(why));
    if(why[0]) {
        ga_not_tested(ctx, "%s", why);
    } else {
        UA_StatusCode r = kc_update(t->client, &t->kcNode, &blob, thumb, t->kcPolicy);
        ga_note(ctx, "UpdateCredential(%s, RsaEncryptedSecret, %s, %s) -> %s", KC_CREDID, thumb,
                t->kcPolicy, UA_StatusCode_name(r));
        if(absent(r))
            ga_not_supported(ctx, "UpdateCredential -> %s", UA_StatusCode_name(r));
        else if(r != UA_STATUSCODE_GOOD)
            ga_fail(ctx, "UpdateCredential with a secret encrypted to the target's key -> %s",
                    UA_StatusCode_name(r));
        else
            ga_pass(ctx, "UpdateCredential with an RsaEncryptedSecret for %s -> Good",
                    t->kcPolicy);
    }
    gds_buf_free_secret(&secret);
    gds_buf_free(&blob);
}

/* SRV-KC-06 and SRV-KC-07: UpdateCredential with one argument wrong must
 * return `want`. */
static void kc_update_wrong(ga_ctx *ctx, srv_target *t, const char *thumbOverride,
                            const char *policyOverride, UA_StatusCode want, const char *what) {
    if(!have_object(ctx, t))
        return;
    gds_buf secret = {0}, blob = {0};
    char thumb[GDS_SHA1_HEX] = "", why[160];
    kc_encrypt(t, &secret, &blob, thumb, why, sizeof(why));
    if(why[0]) {
        ga_not_tested(ctx, "%s", why);
    } else {
        const char *tp = thumbOverride ? thumbOverride : thumb;
        const char *pol = policyOverride ? policyOverride : t->kcPolicy;
        UA_StatusCode r = kc_update(t->client, &t->kcNode, &blob, tp, pol);
        ga_note(ctx, "UpdateCredential(%s, RsaEncryptedSecret, %s, %s) -> %s", KC_CREDID, tp,
                pol, UA_StatusCode_name(r));
        if(absent(r))
            ga_not_supported(ctx, "UpdateCredential -> %s", UA_StatusCode_name(r));
        else if(r == UA_STATUSCODE_GOOD)
            ga_fail(ctx, "UpdateCredential with %s -> Good", what);
        else if(r != want)
            ga_warn(ctx, "UpdateCredential with %s -> %s, not %s", what, UA_StatusCode_name(r),
                    UA_StatusCode_name(want));
        else
            ga_pass(ctx, "UpdateCredential with %s -> %s", what, UA_StatusCode_name(r));
    }
    gds_buf_free_secret(&secret);
    gds_buf_free(&blob);
}

static void t_kc_policy(ga_ctx *ctx, void *p) {
    kc_update_wrong(ctx, p, NULL, KC_POLICY_PREFIX "Unknown_Policy",
                    UA_STATUSCODE_BADSECURITYPOLICYREJECTED, "an unknown SecurityPolicyUri");
}

static void t_kc_thumbprint(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    char own[GDS_SHA1_HEX] = "";
    if(gds_sha1_hex(&t->cert, own) != GDS_OK) {
        ga_not_tested(ctx, "setup: no thumbprint of the Auditor's certificate");
        return;
    }
    kc_update_wrong(ctx, t, own, NULL, UA_STATUSCODE_BADCERTIFICATEINVALID,
                    "the thumbprint of a certificate that is not the target's");
}

/* SRV-KC-08 (12 §8.6.7): a plaintext secret */
static void t_kc_plaintext(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!have_object(ctx, t))
        return;
    gds_buf secret = {(uint8_t *)(uintptr_t)"gdsaudit-plaintext-secret", 25};
    UA_StatusCode r = kc_update(t->client, &t->kcNode, &secret, "", "");
    ga_note(ctx, "UpdateCredential(%s, plaintext, \"\", \"\") -> %s", KC_CREDID,
            UA_StatusCode_name(r));
    if(absent(r))
        ga_not_supported(ctx, "UpdateCredential -> %s", UA_StatusCode_name(r));
    else if(r == UA_STATUSCODE_GOOD)
        ga_warn(ctx, "a plaintext secret was accepted; it is protected only by the channel");
    else
        ga_pass(ctx, "a plaintext secret was refused (%s)", UA_StatusCode_name(r));
}

/* SRV-KC-09 (12 §8.6.8) */
static void t_kc_delete(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!have_object(ctx, t))
        return;
    UA_StatusCode r = kc_delete(t->client, &t->kcNode);
    ga_note(ctx, "DeleteCredential -> %s", UA_StatusCode_name(r));
    if(absent(r)) {
        ga_not_supported(ctx, "DeleteCredential -> %s", UA_StatusCode_name(r));
        return;
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "DeleteCredential -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_QualifiedName bn;
    UA_QualifiedName_init(&bn);
    UA_StatusCode rb = UA_Client_readBrowseNameAttribute(t->client, t->kcNode, &bn);
    UA_QualifiedName_clear(&bn);
    ga_note(ctx, "Read BrowseName of the Object -> %s", UA_StatusCode_name(rb));
    if(rb == UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "DeleteCredential returned Good, but the Object is still there");
        return;
    }
    t->kcCreated = false;
    ga_pass(ctx, "DeleteCredential -> Good and the Object is gone");
}

/* SRV-KC-10 (12 §8.6.5): ServiceStatus of a credential whose endpoint is
 * unreachable */
static UA_StatusCode kc_status(UA_Client *c, const UA_NodeId *node, UA_StatusCode *st) {
    UA_Variant v;
    UA_StatusCode r = kc_read(c, node, "ServiceStatus", &v);
    if(r == UA_STATUSCODE_GOOD && !UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_STATUSCODE]))
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    if(r == UA_STATUSCODE_GOOD)
        *st = *(const UA_StatusCode *)v.data;
    UA_Variant_clear(&v);
    return r;
}

static void t_kc_status(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->slow) {
        ga_not_tested(ctx, "slow test (up to %ld s): run with --slow", KC_STATUS_WAIT_S);
        return;
    }
    if(!admin_ready(ctx, t))
        return;
    char name[64];
    kc_name(name, sizeof(name), "kc-status");
    UA_NodeId node;
    UA_StatusCode r = kc_create(t->client, name, KC_RESOURCE, KC_PROFILE, KC_ENDPOINT, &node);
    ga_note(ctx, "CreateCredential(%s, %s) -> %s", name, KC_ENDPOINT, UA_StatusCode_name(r));
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: CreateCredential -> %s", UA_StatusCode_name(r));
        return;
    }
    /* a credential, if the Auditor can make one: a target may try only then */
    gds_buf secret = {0}, blob = {0};
    char thumb[GDS_SHA1_HEX] = "", why[160];
    kc_encrypt(t, &secret, &blob, thumb, why, sizeof(why));
    if(!why[0])
        ga_note(ctx, "UpdateCredential -> %s",
                UA_StatusCode_name(kc_update(t->client, &node, &blob, thumb, t->kcPolicy)));
    gds_buf_free_secret(&secret);
    gds_buf_free(&blob);
    UA_StatusCode st = UA_STATUSCODE_GOOD;
    for(long i = 0; i <= KC_STATUS_WAIT_S; i++) {
        r = kc_status(t->client, &node, &st);
        if(r != UA_STATUSCODE_GOOD || st == UA_STATUSCODE_BADNOCOMMUNICATION)
            break;
        nap_ms(1000);
    }
    ga_note(ctx, "ServiceStatus -> %s, value %s", UA_StatusCode_name(r), UA_StatusCode_name(st));
    if(absent(r) || r == UA_STATUSCODE_BADATTRIBUTEIDINVALID)
        ga_not_supported(ctx, "no ServiceStatus Property (%s)", UA_StatusCode_name(r));
    else if(r != UA_STATUSCODE_GOOD)
        ga_warn(ctx, "ServiceStatus read -> %s", UA_StatusCode_name(r));
    else if(st != UA_STATUSCODE_BADNOCOMMUNICATION)
        ga_warn(ctx, "after %ld s ServiceStatus is %s, not Bad_NoCommunication", KC_STATUS_WAIT_S,
                UA_StatusCode_name(st));
    else
        ga_pass(ctx, "ServiceStatus Bad_NoCommunication for an unreachable endpoint");
    ga_note(ctx, "DeleteCredential -> %s", UA_StatusCode_name(kc_delete(t->client, &node)));
    UA_NodeId_clear(&node);
}

const ga_test srv_keycred_tests[] = {
    {"SRV-KC-01", "12 §8.6.3, §8.6.5", "CreateCredential makes a KeyCredentialConfiguration Object",
     true, false, t_kc_create},
    {"SRV-KC-02", "12 §8.6.3", "CreateCredential checks ResourceUri, ProfileUri and EndpointUrls",
     true, false, t_kc_invalid},
    {"SRV-KC-03", "12 §8.6.3, §8.6.7, §8.6.8",
     "KeyCredential methods need SecurityAdmin", true, false, t_kc_user},
    {"SRV-KC-04", "12 §8.6.6", "GetEncryptingKey returns a key and a known SecurityPolicy", true,
     false, t_kc_key},
    {"SRV-KC-05", "12 §8.6.7", "UpdateCredential accepts a secret encrypted to that key", true,
     false, t_kc_update},
    {"SRV-KC-06", "12 §8.6.7", "UpdateCredential refuses an unknown SecurityPolicyUri", true,
     false, t_kc_policy},
    {"SRV-KC-07", "12 §8.6.7", "UpdateCredential refuses a thumbprint of another certificate",
     true, false, t_kc_thumbprint},
    {"SRV-KC-08", "12 §8.6.7", "UpdateCredential refuses a plaintext secret", true, false,
     t_kc_plaintext},
    {"SRV-KC-09", "12 §8.6.8", "DeleteCredential removes the Object", true, false, t_kc_delete},
    {"SRV-KC-10", "12 §8.6.5", "ServiceStatus reports an unreachable endpoint", true, false,
     t_kc_status},
};
const size_t srv_keycred_count = GDS_ARRAY_SIZE(srv_keycred_tests);
