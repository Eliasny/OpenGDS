/* OpenGDS unit test: KeyCredential management (OPC 10000-12 §8.5,
 * gds_keycred.c), the RsaEncryptedSecret (enc_secret.c, OPC 10000-4
 * §7.40.2.4) and the store's KeyCredential calls (migration 005).
 *
 * A KeyCredentialService object per configured service; StartRequest
 * refusals (§8.5.5); manual approval through the dialog; FinishRequest
 * pending, rejected, cancelled, from another certificate, delivered with a
 * secret only the requester can decrypt, and only once (§8.5.6); the store
 * keeps a salted hash, not the secret; a new delivery replaces the old
 * credential; Revoke (§8.5.7); the renewals policy; restarts raise the
 * pending dialogs again.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "common/enc_secret.h"
#include "common/ids.h"
#include "common/safeint.h"
#include "gds_internal.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:keycred"
#define APP_URI TEST_URI ":app"
#define BROKER "urn:opengds:test:broker"
#define MQTT_PROFILE "http://opcfoundation.org/UA/Profile/Transport/pubsub-mqtt-uadp"

static gds_session admin, approver, outsider, plain, app, appOther;

/* the requester's key pair: certificate DER and private key */
static UA_ByteString reqCert, reqKeyDer;
static EVP_PKEY *reqKey;

/* ---- helpers ---- */

static UA_CallMethodResult call_on(gds_server *s, gds_session *as, UA_NodeId obj, UA_NodeId method,
                                   UA_Variant *in, size_t n) {
    UA_Server_setAdminSessionContext(gds_server_ua(s), as);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = obj;
    req.methodId = method;
    req.inputArguments = in;
    req.inputArgumentsSize = n;
    UA_CallMethodResult res = UA_Server_call(gds_server_ua(s), &req);
    UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
    return res;
}

static UA_NodeId svc_node(gds_server *s) {
    return UA_NODEID_STRING(s->ns, "KeyCredentialManagement/mqtt");
}

static UA_NodeId child(gds_server *s, const char *name) {
    UA_QualifiedName qn = UA_QUALIFIEDNAME(s->ns, (char *)(uintptr_t)name);
    UA_BrowsePathResult b = UA_Server_browseSimplifiedBrowsePath(gds_server_ua(s), svc_node(s), 1, &qn);
    UA_NodeId id = UA_NODEID_NULL;
    if(b.statusCode == UA_STATUSCODE_GOOD && b.targetsSize >= 1)
        (void)UA_NodeId_copy(&b.targets[0].targetId.nodeId, &id);
    UA_BrowsePathResult_clear(&b);
    return id;
}

static UA_StatusCode start_full(gds_server *s, gds_session *as, const char *uri,
                                const UA_ByteString *key, const char *policy, UA_NodeId *reqId) {
    UA_String u = UA_STRING((char *)(uintptr_t)uri);
    UA_ByteString k = key ? *key : UA_BYTESTRING_NULL;
    UA_String p = policy ? UA_STRING((char *)(uintptr_t)policy) : UA_STRING_NULL;
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], &u, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &k, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[2], &p, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&in[3], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_NODEID]);
    UA_NodeId m = child(s, "StartRequest");
    UA_CallMethodResult res = call_on(s, as, svc_node(s), m, in, 4);
    UA_NodeId_clear(&m);
    UA_StatusCode r = res.statusCode;
    if(r == UA_STATUSCODE_GOOD && reqId &&
       !(res.outputArgumentsSize == 1 &&
         UA_Variant_hasScalarType(&res.outputArguments[0], &UA_TYPES[UA_TYPES_NODEID]) &&
         UA_NodeId_copy(res.outputArguments[0].data, reqId) == UA_STATUSCODE_GOOD))
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    UA_CallMethodResult_clear(&res);
    return r;
}

static UA_StatusCode start(gds_server *s, gds_session *as, UA_NodeId *reqId) {
    return start_full(s, as, APP_URI, &reqCert, GDS_POLICY_BASIC256SHA256, reqId);
}

typedef struct {
    char id[GDS_MAX_KC_ID + 1];
    char secret[256];
    char thumb[64];
    char policy[128];
} delivered;

static void copy_str(const UA_Variant *v, char *out, size_t outLen) {
    out[0] = '\0';
    if(UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_STRING])) {
        const UA_String *x = v->data;
        if(x->length < outLen) {
            if(x->length)
                memcpy(out, x->data, x->length);
            out[x->length] = '\0';
        }
    }
}

/* FinishRequest; on Good with a credential, the decrypted secret in *d. */
static UA_StatusCode finish_as(gds_server *s, gds_session *as, const UA_NodeId *reqId, bool cancel,
                               delivered *d) {
    UA_Boolean c = cancel;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)reqId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &c, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_NodeId m = child(s, "FinishRequest");
    UA_CallMethodResult res = call_on(s, as, svc_node(s), m, in, 2);
    UA_NodeId_clear(&m);
    UA_StatusCode r = res.statusCode;
    if(r == UA_STATUSCODE_GOOD && d) {
        memset(d, 0, sizeof(*d));
        if(!CHECK_EQ_INT(res.outputArgumentsSize, 5) ||
           !UA_Variant_hasScalarType(&res.outputArguments[1], &UA_TYPES[UA_TYPES_BYTESTRING])) {
            r = UA_STATUSCODE_BADUNEXPECTEDERROR;
        } else {
            copy_str(&res.outputArguments[0], d->id, sizeof(d->id));
            copy_str(&res.outputArguments[2], d->thumb, sizeof(d->thumb));
            copy_str(&res.outputArguments[3], d->policy, sizeof(d->policy));
            const UA_ByteString *blob = res.outputArguments[1].data;
            gds_buf b = {blob->data, blob->length}, sec = {0};
            gds_buf cert = {reqCert.data, reqCert.length};
            if(d->policy[0] &&
               gds_enc_secret_rsa_decrypt(d->policy, strlen(d->policy), &cert, reqKey, &b, &sec) ==
                   GDS_OK &&
               sec.len < sizeof(d->secret)) {
                memcpy(d->secret, sec.data, sec.len);
            } else if(!d->policy[0] && blob->length < sizeof(d->secret)) {
                memcpy(d->secret, blob->data, blob->length);
            } else {
                r = UA_STATUSCODE_BADUNEXPECTEDERROR;
            }
            gds_buf_free_secret(&sec);
        }
    }
    UA_CallMethodResult_clear(&res);
    return r;
}

static UA_StatusCode finish(gds_server *s, const UA_NodeId *reqId, delivered *d) {
    return finish_as(s, &admin, reqId, false, d);
}

static UA_StatusCode kc_revoke(gds_server *s, gds_session *as, const char *id) {
    UA_String i = UA_STRING((char *)(uintptr_t)id);
    UA_Variant in;
    UA_Variant_setScalar(&in, &i, &UA_TYPES[UA_TYPES_STRING]);
    UA_NodeId m = child(s, "Revoke");
    UA_CallMethodResult res = call_on(s, as, svc_node(s), m, &in, 1);
    UA_NodeId_clear(&m);
    UA_StatusCode r = res.statusCode;
    UA_CallMethodResult_clear(&res);
    return r;
}

static UA_StatusCode respond2(gds_server *s, const UA_NodeId *reqId, UA_Int32 resp) {
    UA_LocalizedText c = UA_LOCALIZEDTEXT("en", "test");
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &resp, &UA_TYPES[UA_TYPES_INT32]);
    UA_Variant_setScalar(&in[1], &c, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    UA_CallMethodResult res = call_on(s, &approver, UA_NODEID_GUID(1, reqId->identifier.guid),
                                      UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND2), in, 2);
    UA_StatusCode r = res.statusCode;
    UA_CallMethodResult_clear(&res);
    return r;
}

static bool dialog_exists(gds_server *s, const UA_NodeId *reqId) {
    UA_NodeClass nc;
    return UA_Server_readNodeClass(gds_server_ua(s), UA_NODEID_GUID(1, reqId->identifier.guid),
                                   &nc) == UA_STATUSCODE_GOOD;
}

static bool register_app(gds_server *s, const char *uri) {
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "KeyCredential app");
    UA_String disc = UA_STRING("opc.tcp://localhost:4840");
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    rec.applicationUri = UA_STRING((char *)(uintptr_t)uri);
    rec.applicationType = UA_APPLICATIONTYPE_CLIENT;
    rec.productUri = UA_STRING("urn:opengds:test:product");
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    rec.discoveryUrls = &disc;
    rec.discoveryUrlsSize = 1;
    UA_Variant in;
    UA_Variant_setScalar(&in, &rec, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    UA_CallMethodResult res =
        call_on(s, &admin, UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY),
                UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_REGISTERAPPLICATION), &in, 1);
    bool ok = CHECK_EQ_INT(res.statusCode, UA_STATUSCODE_GOOD);
    UA_CallMethodResult_clear(&res);
    return ok;
}

/* The verifier is mosquitto's "$7$<iter>$<salt>$<hash>" of the secret. */
static bool verifier_matches(const char *verifier, const char *secret) {
    long iter = 0;
    char salt64[64] = "", hash64[128] = "";
    const char *p = verifier;
    if(strncmp(p, "$7$", 3) != 0)
        return false;
    const char *a = strchr(p + 3, '$');
    char num[16] = "";
    if(!a || (size_t)(a - p - 3) >= sizeof(num))
        return false;
    memcpy(num, p + 3, (size_t)(a - p - 3));
    if(!gds_parse_long(num, 1, 1000000, &iter))
        return false;
    const char *b = a ? strchr(a + 1, '$') : NULL;
    if(!a || !b || (size_t)(b - a - 1) >= sizeof(salt64) || strlen(b + 1) >= sizeof(hash64))
        return false;
    memcpy(salt64, a + 1, (size_t)(b - a - 1));
    memcpy(hash64, b + 1, strlen(b + 1));
    unsigned char salt[64], hash[128], want[64];
    int sl = EVP_DecodeBlock(salt, (const unsigned char *)salt64, (int)strlen(salt64));
    int hl = EVP_DecodeBlock(hash, (const unsigned char *)hash64, (int)strlen(hash64));
    if(sl < 12 || hl < 64 || iter < 1)
        return false;
    sl = 12; /* EVP_DecodeBlock counts the padding */
    return PKCS5_PBKDF2_HMAC(secret, (int)strlen(secret), salt, sl, (int)iter, EVP_sha512(),
                             (int)sizeof(want), want) == 1 &&
           memcmp(want, hash, sizeof(want)) == 0;
}

static size_t count_creds_cb_n;
static bool count_cred(void *ctx, const gds_kc_cred *c) {
    (void)ctx, (void)c;
    count_creds_cb_n++;
    return true;
}
static size_t count_creds(gds_store *st) {
    count_creds_cb_n = 0;
    CHECK(gds_store_kc_cred_scan(st, count_cred, NULL) == GDS_OK);
    return count_creds_cb_n;
}

/* ---- cases ---- */

/* RsaEncryptedSecret round trip for every policy; tampering is caught. */
static void test_enc_secret(void) {
    gds_buf cert = {reqCert.data, reqCert.length};
    gds_buf secret = {(uint8_t *)(uintptr_t)"a secret", 8};
    static const char *const pol[] = {GDS_POLICY_BASIC256SHA256, GDS_POLICY_AES128_RSAOAEP,
                                      GDS_POLICY_AES256_RSAPSS};
    for(size_t i = 0; i < 3; i++) {
        gds_buf blob = {0}, out = {0};
        CHECK(gds_enc_secret_check(pol[i], strlen(pol[i]), &cert) == GDS_OK);
        if(!CHECK(gds_enc_secret_rsa(pol[i], strlen(pol[i]), &cert, &secret, &blob) == GDS_OK))
            continue;
        CHECK(gds_enc_secret_rsa_decrypt(pol[i], strlen(pol[i]), &cert, reqKey, &blob, &out) ==
              GDS_OK);
        CHECK(out.len == secret.len && memcmp(out.data, secret.data, secret.len) == 0);
        gds_buf_free_secret(&out);
        /* another policy's name, a flipped byte of the payload or signature */
        const char *other = pol[(i + 1) % 3];
        CHECK(gds_enc_secret_rsa_decrypt(other, strlen(other), &cert, reqKey, &blob, &out) ==
              GDS_EINVAL);
        blob.data[blob.len - 40] ^= 1;
        CHECK(gds_enc_secret_rsa_decrypt(pol[i], strlen(pol[i]), &cert, reqKey, &blob, &out) ==
              GDS_EINVAL);
        blob.data[blob.len - 40] ^= 1;
        blob.data[blob.len - 1] ^= 1;
        CHECK(gds_enc_secret_rsa_decrypt(pol[i], strlen(pol[i]), &cert, reqKey, &blob, &out) ==
              GDS_EINVAL);
        gds_buf_free(&blob);
    }
    static const char ecc[] = "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256";
    CHECK(gds_enc_secret_check(ecc, strlen(ecc), &cert) == GDS_EUNSUPPORTED);
    gds_buf junk = {(uint8_t *)(uintptr_t)"junk", 4};
    CHECK(gds_enc_secret_check(pol[0], strlen(pol[0]), &junk) == GDS_EINVAL);
    char hex[GDS_SHA1_HEX];
    CHECK(gds_sha1_hex(&cert, hex) == GDS_OK && strlen(hex) == 40);
}

/* The object and its properties (§8.5.3, §8.5.4). */
static void test_nodes(gds_server *s) {
    UA_Variant v;
    UA_NodeId res = child(s, "ResourceUri"), prof = child(s, "ProfileUris"),
              pol = child(s, "SecurityPolicyUris"), rev = child(s, "Revoke");
    if(CHECK(UA_Server_readValue(gds_server_ua(s), res, &v) == UA_STATUSCODE_GOOD)) {
        UA_String want = UA_STRING(BROKER);
        CHECK(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_STRING]) &&
              UA_String_equal(v.data, &want));
        UA_Variant_clear(&v);
    }
    if(CHECK(UA_Server_readValue(gds_server_ua(s), prof, &v) == UA_STATUSCODE_GOOD)) {
        CHECK(v.arrayLength == 1);
        UA_Variant_clear(&v);
    }
    if(CHECK(UA_Server_readValue(gds_server_ua(s), pol, &v) == UA_STATUSCODE_GOOD)) {
        CHECK(v.arrayLength == 3);
        UA_Variant_clear(&v);
    }
    CHECK(!UA_NodeId_isNull(&rev));
    UA_NodeId_clear(&res);
    UA_NodeId_clear(&prof);
    UA_NodeId_clear(&pol);
    UA_NodeId_clear(&rev);
}

/* StartRequest refusals (§8.5.5). */
static void test_refused(gds_server *s) {
    UA_NodeId id = UA_NODEID_NULL;
    CHECK_EQ_INT(start(s, &plain, &id), UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT);
    CHECK_EQ_INT(start(s, &outsider, &id), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(start(s, &appOther, &id), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(start_full(s, &admin, TEST_URI ":nobody", NULL, NULL, &id),
                 UA_STATUSCODE_BADNOTFOUND);
    CHECK_EQ_INT(start_full(s, &admin, APP_URI, &reqCert, NULL, &id),
                 UA_STATUSCODE_BADINVALIDARGUMENT); /* a key without a policy */
    CHECK_EQ_INT(start_full(s, &admin, APP_URI, NULL, GDS_POLICY_BASIC256SHA256, &id),
                 UA_STATUSCODE_BADINVALIDARGUMENT);
    UA_ByteString junk = UA_BYTESTRING("junk");
    CHECK_EQ_INT(start_full(s, &admin, APP_URI, &junk, GDS_POLICY_BASIC256SHA256, &id),
                 UA_STATUSCODE_BADCERTIFICATEINVALID);
    CHECK_EQ_INT(start_full(s, &admin, APP_URI, &reqCert,
                            "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256", &id),
                 UA_STATUSCODE_BADSECURITYPOLICYREJECTED);
    UA_NodeId bogus = UA_NODEID_GUID(s->ns, UA_GUID("00000000-0000-0000-0000-000000000001"));
    CHECK_EQ_INT(finish(s, &bogus, NULL), UA_STATUSCODE_BADINVALIDARGUMENT);
    CHECK_EQ_INT(kc_revoke(s, &admin, "opengds-none"), UA_STATUSCODE_BADINVALIDARGUMENT);
}

static void check_delivered(gds_store *st, const delivered *d1);

/* Manual: pending, approved, only over the asking certificate, once. */
static void test_manual_deliver(gds_server *s, gds_store *st, delivered *d1) {
    UA_NodeId a = UA_NODEID_NULL;
    delivered d2;
    if(!CHECK_EQ_INT(start(s, &admin, &a), UA_STATUSCODE_GOOD))
        return;
    CHECK(dialog_exists(s, &a));
    CHECK_EQ_INT(finish(s, &a, d1), UA_STATUSCODE_BADREQUESTNOTCOMPLETE);
    CHECK_EQ_INT(respond2(s, &a, 0), UA_STATUSCODE_GOOD);
    CHECK(!dialog_exists(s, &a));
    CHECK_EQ_INT(finish_as(s, &app, &a, false, d1), UA_STATUSCODE_BADUSERACCESSDENIED);
    if(CHECK_EQ_INT(finish(s, &a, d1), UA_STATUSCODE_GOOD))
        check_delivered(st, d1);
    CHECK_EQ_INT(finish(s, &a, &d2), UA_STATUSCODE_BADINVALIDARGUMENT); /* once only */
    UA_NodeId_clear(&a);
}

/* The credential: format, thumbprint, and only a hash in the store. */
static void check_delivered(gds_store *st, const delivered *d1) {
    {
        CHECK(strncmp(d1->id, "opengds-", 8) == 0 && strlen(d1->id) == 40);
        CHECK(strlen(d1->secret) == 43); /* base64url of 32 bytes */
        CHECK(strcmp(d1->policy, GDS_POLICY_BASIC256SHA256) == 0);
        char hex[GDS_SHA1_HEX];
        gds_buf cert = {reqCert.data, reqCert.length};
        CHECK(gds_sha1_hex(&cert, hex) == GDS_OK && strcmp(hex, d1->thumb) == 0);
        gds_kc_cred kc;
        if(CHECK(gds_store_kc_cred_get(st, d1->id, &kc) == GDS_OK)) {
            CHECK(strstr(kc.verifier, d1->secret) == NULL);
            CHECK(verifier_matches(kc.verifier, d1->secret));
            CHECK(!verifier_matches(kc.verifier, "wrong"));
            CHECK(strcmp(kc.service, "mqtt") == 0);
        }
    }
}

/* Rejected; cancelled while pending (the dialog goes). */
static void test_reject_cancel(gds_server *s) {
    UA_NodeId b = UA_NODEID_NULL, c = UA_NODEID_NULL;
    delivered d;
    if(CHECK_EQ_INT(start(s, &admin, &b), UA_STATUSCODE_GOOD)) {
        CHECK_EQ_INT(respond2(s, &b, 1), UA_STATUSCODE_GOOD);
        CHECK_EQ_INT(finish(s, &b, &d), UA_STATUSCODE_BADREQUESTNOTALLOWED);
    }
    if(CHECK_EQ_INT(start(s, &admin, &c), UA_STATUSCODE_GOOD)) {
        CHECK_EQ_INT(finish_as(s, &admin, &c, true, NULL), UA_STATUSCODE_GOOD);
        CHECK(!dialog_exists(s, &c));
        CHECK_EQ_INT(finish(s, &c, &d), UA_STATUSCODE_BADINVALIDARGUMENT);
    }
    UA_NodeId_clear(&b);
    UA_NodeId_clear(&c);
}

/* Without encryption of its own (the channel protects it); replaces d1;
 * Revoke. */
static void test_replace_revoke(gds_server *s, gds_store *st, const delivered *d1) {
    UA_NodeId e = UA_NODEID_NULL;
    delivered d2;
    if(!CHECK_EQ_INT(start_full(s, &admin, APP_URI, NULL, NULL, &e), UA_STATUSCODE_GOOD) ||
       !CHECK_EQ_INT(respond2(s, &e, 0), UA_STATUSCODE_GOOD) ||
       !CHECK_EQ_INT(finish(s, &e, &d2), UA_STATUSCODE_GOOD)) {
        UA_NodeId_clear(&e);
        return;
    }
    CHECK(d2.thumb[0] == '\0' && d2.policy[0] == '\0' && strlen(d2.secret) == 43);
    CHECK(strcmp(d1->id, d2.id) != 0);
    gds_kc_cred kc;
    CHECK(gds_store_kc_cred_get(st, d1->id, &kc) == GDS_ENOTFOUND);
    CHECK_EQ_INT(count_creds(st), 1);
    CHECK_EQ_INT(kc_revoke(s, &outsider, d2.id), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(kc_revoke(s, &plain, d2.id), UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT);
    CHECK_EQ_INT(kc_revoke(s, &admin, d2.id), UA_STATUSCODE_GOOD);
    CHECK(gds_store_kc_cred_get(st, d2.id, &kc) == GDS_ENOTFOUND);
    CHECK_EQ_INT(kc_revoke(s, &admin, d2.id), UA_STATUSCODE_BADINVALIDARGUMENT);
    UA_NodeId_clear(&e);
}

static void test_manual(gds_server *s, gds_store *st, UA_NodeId *leftPending) {
    delivered d1;
    memset(&d1, 0, sizeof(d1));
    test_manual_deliver(s, st, &d1);
    test_reject_cancel(s);
    if(d1.id[0])
        test_replace_revoke(s, st, &d1);
    CHECK_EQ_INT(start(s, &admin, leftPending), UA_STATUSCODE_GOOD);
}

/* After a restart the pending request has its dialog again. */
static void test_rebuilt(gds_server *s, const UA_NodeId *pending) {
    delivered d;
    CHECK(dialog_exists(s, pending));
    CHECK_EQ_INT(respond2(s, pending, 0), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(finish(s, pending, &d), UA_STATUSCODE_GOOD);
}

/* Renewals: the application's own repeat request is approved on arrival,
 * an administrator's and a first request wait. */
static void test_renewals(gds_server *s) {
    UA_NodeId a = UA_NODEID_NULL, b = UA_NODEID_NULL, c = UA_NODEID_NULL;
    delivered d;
    /* the app already holds a credential (test_rebuilt) */
    if(CHECK_EQ_INT(start(s, &app, &a), UA_STATUSCODE_GOOD)) {
        CHECK(!dialog_exists(s, &a));
        CHECK_EQ_INT(finish_as(s, &app, &a, false, &d), UA_STATUSCODE_GOOD);
    }
    if(CHECK_EQ_INT(start(s, &admin, &b), UA_STATUSCODE_GOOD))
        CHECK(dialog_exists(s, &b));
    if(register_app(s, TEST_URI ":new") &&
       CHECK_EQ_INT(start_full(s, &admin, TEST_URI ":new", NULL, NULL, &c), UA_STATUSCODE_GOOD))
        CHECK(dialog_exists(s, &c));
    UA_NodeId_clear(&a);
    UA_NodeId_clear(&b);
    UA_NodeId_clear(&c);
}

/* Auto: approved on arrival. */
static void test_auto(gds_server *s) {
    UA_NodeId a = UA_NODEID_NULL;
    delivered d;
    if(CHECK_EQ_INT(start(s, &admin, &a), UA_STATUSCODE_GOOD)) {
        CHECK(!dialog_exists(s, &a));
        CHECK_EQ_INT(finish(s, &a, &d), UA_STATUSCODE_GOOD);
    }
    UA_NodeId_clear(&a);
}

/* Configuration the server refuses. */
static void test_config(gds_server_config cfg) {
    gds_server *s = NULL;
    static const char *const prof[] = {MQTT_PROFILE};
    gds_keycred_service bad[2] = {{"mqtt", BROKER, prof, 1}, {"mqtt", BROKER, prof, 1}};
    cfg.keyCredServices = bad;
    cfg.keyCredServicesSize = 2; /* same name twice */
    CHECK(gds_server_new(&cfg, &s) == GDS_EINVAL && !s);
    bad[1].name = "has space";
    CHECK(gds_server_new(&cfg, &s) == GDS_EINVAL && !s);
    cfg.keyCredServicesSize = 1;
    bad[0].profileUrisSize = 0;
    CHECK(gds_server_new(&cfg, &s) == GDS_EINVAL && !s);
}

static void session_init(gds_session *x, const char *user, uint32_t roles) {
    memset(x, 0, sizeof(*x));
    x->roles = roles;
    x->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    if(user)
        memcpy(x->user, user, strlen(user) + 1);
    else
        x->anonymous = true;
}

static void sessions_init(void) {
    session_init(&admin, "registrar", GDS_ROLE_DISCOVERY_ADMIN | GDS_ROLE_KEY_CREDENTIAL_ADMIN);
    admin.clientCert = reqCert; /* borrowed: the channel certificate */
    session_init(&approver, "approver", GDS_ROLE_REGISTRATION_AUTHORITY_ADMIN);
    session_init(&outsider, NULL, 0);
    session_init(&plain, "registrar", GDS_ROLE_DISCOVERY_ADMIN | GDS_ROLE_KEY_CREDENTIAL_ADMIN);
    plain.securityMode = UA_MESSAGESECURITYMODE_SIGN;
    session_init(&app, NULL, 0); /* the application itself (ApplicationSelfAdmin) */
    app.clientAppUri = UA_STRING(APP_URI);
    app.clientCert = UA_BYTESTRING("another certificate");
    session_init(&appOther, NULL, 0);
    appOther.clientAppUri = UA_STRING(TEST_URI ":other");
    appOther.clientCert = UA_BYTESTRING("other");
}

/* One server on cfg: phase 0 the first start, 1 a restart, 2 renewals, 3 auto. */
static void run_phase(const gds_server_config *cfg, gds_store *st, int phase, UA_NodeId *pending) {
    gds_server *s = NULL;
    if(!CHECK(gds_server_new(cfg, &s) == GDS_OK) || !s)
        return;
    UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
    if(phase == 0 && register_app(s, APP_URI)) {
        test_nodes(s);
        test_refused(s);
        test_manual(s, st, pending);
    } else if(phase == 1) {
        test_rebuilt(s, pending);
    } else if(phase == 2) {
        test_renewals(s);
    } else if(phase == 3) {
        test_auto(s);
    }
    UA_Server_setAdminSessionContext(gds_server_ua(s), NULL);
    gds_server_delete(s);
}

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);

    static uint8_t pw[] = "keycred-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    gds_store *st = NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS test")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    UA_String rsubject[] = {UA_STRING_STATIC("CN=KeyCredential requester")};
    UA_String rsan[] = {UA_STRING_STATIC("URI:" APP_URI)};
    if(!CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) || !CHECK(gds_store_open(db, &st) == GDS_OK) ||
       !CHECK(UA_CreateCertificate(UA_Log_Stdout, subject, 1, san, 2, UA_CERTIFICATEFORMAT_DER,
                                   NULL, &key, &cert) == UA_STATUSCODE_GOOD) ||
       !CHECK(UA_CreateCertificate(UA_Log_Stdout, rsubject, 1, rsan, 1, UA_CERTIFICATEFORMAT_DER,
                                   NULL, &reqKeyDer, &reqCert) == UA_STATUSCODE_GOOD))
        return CHECK_DONE();
    const unsigned char *kp = reqKeyDer.data;
    reqKey = d2i_AutoPrivateKey(NULL, &kp, (long)reqKeyDer.length);
    if(!CHECK(reqKey != NULL))
        return CHECK_DONE();
    CHECK(gds_store_kc_supported(st));

    test_enc_secret();

    sessions_init();

    static gds_users users;
    static const char *const prof[] = {MQTT_PROFILE};
    static const gds_keycred_service svc[] = {{"mqtt", BROKER, prof, 1}};
    gds_server_config cfg = {0};
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS keycred test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_MANUAL;
    test_config(cfg);
    cfg.keyCredServices = svc;
    cfg.keyCredServicesSize = 1;

    UA_NodeId pending = UA_NODEID_NULL;
    run_phase(&cfg, st, 0, &pending);
    run_phase(&cfg, st, 1, &pending); /* restart */
    app.clientCert = reqCert;         /* the app asks over its own channel now */
    cfg.approval = GDS_APPROVE_RENEWALS;
    run_phase(&cfg, st, 2, &pending);
    cfg.approval = GDS_APPROVE_ALL;
    run_phase(&cfg, st, 3, &pending);

    UA_NodeId_clear(&pending);
    EVP_PKEY_free(reqKey);
    gds_store_close(st);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    UA_ByteString_clear(&reqCert);
    UA_ByteString_clear(&reqKeyDer);
    gds_ca_close(ca);
    return CHECK_DONE();
}
