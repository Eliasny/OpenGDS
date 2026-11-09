/* OpenGDS unit test: the AuthorizationService (OPC 10000-12 §9.6) and its
 * JWT AccessTokens (OPC 10000-6 §6.5.2). Real clients over SignAndEncrypt
 * call StartRequestToken, FinishRequestToken and RefreshToken for each
 * UserTokenPolicy; the tokens are decoded and their signature checked with
 * the ServiceCertificate.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/nodeids.h>
#include <open62541/nodeids_gds.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "common/ids.h"
#include "gds_internal.h"
#include "gds_jwt.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI    "urn:opengds:test:authz"
#define CLIENT_URI  "urn:opengds:test:authz:client"
#define CLIENT2_URI "urn:opengds:test:authz:client2"
#define RESOURCE    "urn:opengds:test:authz:target"
#define CLIENTONLY  "urn:opengds:test:authz:only-a-client"
#define PASSWORD    "authz-test-pw"
#define B256        "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"

#define ID_START   95
#define ID_FINISH  98
#define ID_REFRESH 64

typedef struct {
    UA_ByteString cert, key;
} pair;

typedef struct {
    gds_store *store;
    gds_ca *ca;
    pair own, svc, app, app2, stranger, admin;
    char url[64];
    UA_UInt16 ns;
} fixture;

/* ---- the JWT encoding itself ---- */

static void test_b64url(void) {
    static const struct {
        const char *in, *out;
    } v[] = {{"", ""}, {"f", "Zg"}, {"fo", "Zm8"}, {"foo", "Zm9v"}, {"foob", "Zm9vYg"},
             {"fooba", "Zm9vYmE"}, {"foobar", "Zm9vYmFy"}, {"\xfb\xff", "-_8"}};
    for(size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        gds_buf e = {0}, d = {0};
        size_t n = strlen(v[i].in);
        if(CHECK(gds_b64url((const uint8_t *)v[i].in, n, &e) == GDS_OK))
            CHECK(strcmp((const char *)e.data, v[i].out) == 0);
        if(CHECK(gds_b64url_decode(v[i].out, strlen(v[i].out), &d) == GDS_OK))
            CHECK(d.len == n && (n == 0 || memcmp(d.data, v[i].in, n) == 0));
        gds_buf_free(&e);
        gds_buf_free(&d);
    }
    gds_buf d = {0};
    CHECK(gds_b64url_decode("Zm9v=", 5, &d) == GDS_EINVAL); /* no padding */
    CHECK(gds_b64url_decode("Zh", 2, &d) == GDS_EINVAL);    /* stray bits */
    CHECK(gds_b64url_decode("Z", 1, &d) == GDS_EINVAL);
}

/* "<b64url>.<b64url>.<b64url>": the decoded parts. */
static bool jwt_split(const char *tok, size_t len, gds_buf parts[3], size_t *signedLen) {
    const char *dot1 = memchr(tok, '.', len);
    const char *dot2 = dot1 ? memchr(dot1 + 1, '.', len - (size_t)(dot1 + 1 - tok)) : NULL;
    if(!dot2 || memchr(dot2 + 1, '.', len - (size_t)(dot2 + 1 - tok)))
        return false;
    *signedLen = (size_t)(dot2 - tok);
    return gds_b64url_decode(tok, (size_t)(dot1 - tok), &parts[0]) == GDS_OK &&
           gds_b64url_decode(dot1 + 1, (size_t)(dot2 - dot1 - 1), &parts[1]) == GDS_OK &&
           gds_b64url_decode(dot2 + 1, len - (size_t)(dot2 + 1 - tok), &parts[2]) == GDS_OK;
}

static bool has(const gds_buf *json, const char *needle) {
    size_t n = strlen(needle);
    for(size_t i = 0; json->len >= n && i <= json->len - n; i++)
        if(memcmp(json->data + i, needle, n) == 0)
            return true;
    return false;
}

static bool verify_rs256(const UA_ByteString *certDer, const char *tok, size_t signedLen,
                         const gds_buf *sig) {
    const unsigned char *p = certDer->data;
    X509 *x = d2i_X509(NULL, &p, (long)certDer->length);
    EVP_PKEY *pk = x ? X509_get0_pubkey(x) : NULL;
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    bool ok = pk && mc && EVP_DigestVerifyInit(mc, NULL, EVP_sha256(), NULL, pk) == 1 &&
              EVP_DigestVerify(mc, sig->data, sig->len, (const unsigned char *)tok, signedLen) == 1;
    EVP_MD_CTX_free(mc);
    X509_free(x);
    return ok;
}

static void check_es256_parts(const gds_buf parts[3]) {
    CHECK(has(&parts[0], "\"alg\":\"ES256\""));
    CHECK(has(&parts[1], "\"roles\":[\"Operator\",\"a\\\"b\\\\c\\u000a\"]"));
    CHECK(has(&parts[1], "\"exp\":70"));
    CHECK(!has(&parts[1], "\"cnf\""));
}

/* A JWS ES256 signature (R || S) over msg, checked as DER */
static bool es256_verifies(EVP_PKEY *pk, const gds_buf *rs, const uint8_t *msg, size_t len) {
    if(rs->len != 64)
        return false;
    ECDSA_SIG *es = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(rs->data, 32, NULL), *s = BN_bin2bn(rs->data + 32, 32, NULL);
    unsigned char *sd = NULL;
    int sdl = -1;
    if(es && r && s && ECDSA_SIG_set0(es, r, s) == 1)
        sdl = i2d_ECDSA_SIG(es, &sd);
    else {
        BN_free(r);
        BN_free(s);
    }
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    bool ok = sdl > 0 && mc && EVP_DigestVerifyInit(mc, NULL, EVP_sha256(), NULL, pk) == 1 &&
              EVP_DigestVerify(mc, sd, (size_t)sdl, msg, len) == 1;
    EVP_MD_CTX_free(mc);
    OPENSSL_free(sd);
    ECDSA_SIG_free(es);
    return ok;
}

static void test_jwt_es256(void) {
    EVP_PKEY *pk = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    unsigned char *der = NULL;
    int dl = pk ? i2d_PrivateKey(pk, &der) : -1;
    gds_buf kd = {der, dl > 0 ? (size_t)dl : 0};
    gds_jwt_key *k = NULL;
    const char *alg = NULL;
    if(CHECK(dl > 0) && CHECK(gds_jwt_key_new(&kd, &k, &alg) == GDS_OK) &&
       CHECK(strcmp(alg, "ES256") == 0)) {
        uint8_t x5t[GDS_JWT_THUMBPRINT] = {1};
        const char *roles[] = {"Operator", "a\"b\\c\n"};
        gds_jwt_claims c = {"urn:iss", "user", "urn:aud", "jti-1", 10, 10, 70, roles, 2, NULL};
        gds_buf t = {0}, parts[3] = {{0}, {0}, {0}};
        size_t sl = 0;
        if(CHECK(gds_jwt_make(alg, x5t, &c, gds_jwt_key_sign, k, &t) == GDS_OK) &&
           CHECK(jwt_split((const char *)t.data, t.len, parts, &sl))) {
            check_es256_parts(parts);
            /* R || S, 64 bytes, verifies once turned back into DER */
            CHECK(es256_verifies(pk, &parts[2], t.data, sl));
        }
        /* exp must follow nbf; no empty subject */
        c.exp = c.nbf;
        gds_buf t2 = {0};
        CHECK(gds_jwt_make(alg, x5t, &c, gds_jwt_key_sign, k, &t2) == GDS_EINVAL);
        c.exp = 70;
        c.sub = "";
        CHECK(gds_jwt_make(alg, x5t, &c, gds_jwt_key_sign, k, &t2) == GDS_EINVAL);
        for(size_t i = 0; i < 3; i++)
            gds_buf_free(&parts[i]);
        gds_buf_free(&t);
    }
    gds_jwt_key_free(k);
    OPENSSL_clear_free(der, kd.len);
    EVP_PKEY_free(pk);
}

/* ---- certificates ---- */

static bool make_cert(const char *cn, const char *uri, pair *p) {
    UA_String subject[] = {UA_STRING((char *)(uintptr_t)cn), UA_STRING_STATIC("O=OpenGDS")};
    UA_String san[] = {UA_STRING((char *)(uintptr_t)uri), UA_STRING_STATIC("DNS:localhost")};
    return UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER,
                                NULL, &p->key, &p->cert) == UA_STATUSCODE_GOOD;
}

static void pair_clear(pair *p) {
    UA_ByteString_clear(&p->cert);
    UA_ByteString_clear(&p->key);
}

static bool insert_app(gds_store *st, const char *uri, UA_ApplicationType type, UA_Guid *id) {
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_LocalizedText name = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)uri);
    UA_String durl = UA_STRING("opc.tcp://localhost:4840");
    rec.applicationUri = UA_STRING((char *)(uintptr_t)uri);
    rec.applicationType = type;
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    rec.productUri = UA_STRING("urn:opengds:test");
    if(type != UA_APPLICATIONTYPE_CLIENT) {
        rec.discoveryUrls = &durl;
        rec.discoveryUrlsSize = 1;
    }
    return gds_guid_random(id) == GDS_OK && gds_store_app_insert(st, id, &rec) == GDS_OK;
}

/* A client application certificate issued by the GDS CA. */
static bool issue_client(fixture *f, const char *uri, pair *out) {
    UA_Guid app;
    if(!insert_app(f->store, uri, UA_APPLICATIONTYPE_CLIENT, &app))
        return false;
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    X509_REQ *req = X509_REQ_new();
    unsigned char *k = NULL, *c = NULL;
    int kl = -1, cl = -1;
    if(key && req && X509_REQ_set_pubkey(req, key) == 1 &&
       X509_REQ_sign(req, key, EVP_sha256()) > 0) {
        kl = i2d_PrivateKey(key, &k);
        cl = i2d_X509_REQ(req, &c);
    }
    bool ok = false;
    gds_request q;
    memset(&q, 0, sizeof(q));
    q.appId = app;
    q.groupId = UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP;
    q.certType = UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE;
    q.state = GDS_REQ_RECEIVED;
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    gds_ca_issued is;
    memset(&is, 0, sizeof(is));
    if(kl > 0 && cl > 0 && gds_guid_random(&q.id) == GDS_OK &&
       gds_buf_dup(c, (size_t)cl, &q.csr) == GDS_OK &&
       gds_store_req_insert(f->store, &q) == GDS_OK &&
       gds_store_app_get(f->store, &app, &rec) == GDS_OK) {
        gds_ca_subject subj = {&q.id, &rec, q.groupId, q.certType};
        ok = gds_ca_sign_csr(f->ca, &subj, &q.csr, &is) == GDS_OK &&
             UA_ByteString_allocBuffer(&out->cert, is.der.len) == UA_STATUSCODE_GOOD &&
             UA_ByteString_allocBuffer(&out->key, (size_t)kl) == UA_STATUSCODE_GOOD;
        if(ok) {
            memcpy(out->cert.data, is.der.data, is.der.len);
            memcpy(out->key.data, k, (size_t)kl);
        }
    }
    gds_ca_issued_clear(&is);
    UA_ApplicationRecordDataType_clear(&rec);
    gds_request_clear(&q);
    if(k)
        OPENSSL_clear_free(k, (size_t)kl);
    OPENSSL_free(c);
    X509_REQ_free(req);
    EVP_PKEY_free(key);
    return ok;
}

static bool thumb(const UA_ByteString *der, uint8_t out[32]) {
    unsigned len = 0;
    return EVP_Digest(der->data, der->length, out, &len, EVP_sha256(), NULL) == 1 && len == 32;
}

/* ---- clients ---- */

static UA_Client *connect_as(fixture *f, const pair *app, const char *appUri, bool user) {
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(UA_LOGLEVEL_ERROR);
    if(UA_ClientConfig_setDefault(&cfg) != UA_STATUSCODE_GOOD ||
       UA_ClientConfig_setDefaultEncryption(&cfg, app->cert, app->key, &f->own.cert, 1, NULL, 0) !=
           UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    cfg.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    UA_String_clear(&cfg.securityPolicyUri);
    cfg.securityPolicyUri = UA_STRING_ALLOC(B256);
    UA_String_clear(&cfg.clientDescription.applicationUri);
    cfg.clientDescription.applicationUri = UA_STRING_ALLOC(appUri);
    UA_Client *c = UA_Client_newWithConfig(&cfg);
    if(!c) {
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    UA_StatusCode r = user ? UA_Client_connectUsername(c, f->url, "pw", PASSWORD)
                           : UA_Client_connect(c, f->url);
    if(r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "connect: %s\n", UA_StatusCode_name(r));
        UA_Client_delete(c);
        return NULL;
    }
    return c;
}

static void drop(UA_Client *c) {
    if(c) {
        (void)UA_Client_disconnect(c);
        UA_Client_delete(c);
    }
}

static UA_NodeId service(const fixture *f) {
    return UA_NODEID_STRING(f->ns, "AuthorizationServices.OpenGDS");
}

static UA_StatusCode call(fixture *f, UA_Client *c, UA_UInt32 m, size_t nIn, UA_Variant *in,
                          size_t *nOut, UA_Variant **out) {
    *nOut = 0;
    *out = NULL;
    return UA_Client_call(c, service(f), UA_NODEID_NUMERIC(f->ns, m), nIn, in, nOut, out);
}

static UA_StatusCode start(fixture *f, UA_Client *c, const char *res, const char *policy,
                           const UA_ByteString *rdata, UA_Guid *id, UA_ByteString *sd) {
    UA_String r = UA_STRING((char *)(uintptr_t)res), p = UA_STRING((char *)(uintptr_t)policy);
    UA_ByteString none = UA_BYTESTRING_NULL;
    UA_Variant in[3];
    UA_Variant_setScalar(&in[0], &r, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &p, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[2], (void *)(uintptr_t)(rdata ? rdata : &none),
                         &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t n = 0;
    UA_Variant *out = NULL;
    UA_StatusCode st = call(f, c, ID_START, 3, in, &n, &out);
    if(st == UA_STATUSCODE_GOOD && n == 2) {
        *id = *(UA_Guid *)out[1].data;
        if(sd)
            st = UA_ByteString_copy(out[0].data, sd);
    }
    UA_Array_delete(out, n, &UA_TYPES[UA_TYPES_VARIANT]);
    return st;
}

typedef struct {
    UA_String access, refresh;
    UA_DateTime accessExp, refreshExp;
} tokens;

static void tokens_clear(tokens *t) {
    UA_String_clear(&t->access);
    UA_String_clear(&t->refresh);
}

static UA_StatusCode take_tokens(UA_StatusCode st, UA_Variant *out, size_t n, tokens *t) {
    memset(t, 0, sizeof(*t));
    if(st == UA_STATUSCODE_GOOD && n == 4) {
        st = UA_String_copy(out[0].data, &t->access);
        t->accessExp = *(UA_DateTime *)out[1].data;
        if(st == UA_STATUSCODE_GOOD)
            st = UA_String_copy(out[2].data, &t->refresh);
        t->refreshExp = *(UA_DateTime *)out[3].data;
    }
    UA_Array_delete(out, n, &UA_TYPES[UA_TYPES_VARIANT]);
    return st;
}

static UA_StatusCode finish(fixture *f, UA_Client *c, const UA_Guid *id, const UA_String *roles,
                            size_t nRoles, void *token, const UA_DataType *type,
                            const UA_SignatureData *sig, tokens *t) {
    UA_ExtensionObject eo;
    UA_AnonymousIdentityToken anon;
    UA_AnonymousIdentityToken_init(&anon);
    anon.policyId = UA_STRING("opengds-session");
    if(!token) {
        token = &anon;
        type = &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN];
    }
    UA_ExtensionObject_setValue(&eo, token, type);
    UA_SignatureData none;
    UA_SignatureData_init(&none);
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)id, &UA_TYPES[UA_TYPES_GUID]);
    UA_Variant_setArray(&in[1], nRoles ? (void *)(uintptr_t)roles : UA_EMPTY_ARRAY_SENTINEL,
                        nRoles, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[2], &eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
    UA_Variant_setScalar(&in[3], (void *)(uintptr_t)(sig ? sig : &none),
                         &UA_TYPES[UA_TYPES_SIGNATUREDATA]);
    size_t n = 0;
    UA_Variant *out = NULL;
    UA_StatusCode st = call(f, c, ID_FINISH, 4, in, &n, &out);
    return take_tokens(st, out, n, t);
}

static UA_StatusCode refresh(fixture *f, UA_Client *c, const char *res, const UA_String *cur,
                             tokens *t) {
    UA_String r = UA_STRING((char *)(uintptr_t)res);
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &r, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], (void *)(uintptr_t)cur, &UA_TYPES[UA_TYPES_STRING]);
    size_t n = 0;
    UA_Variant *out = NULL;
    UA_StatusCode st = call(f, c, ID_REFRESH, 2, in, &n, &out);
    return take_tokens(st, out, n, t);
}

/* The token verifies with the ServiceCertificate and carries these claims. */
/* The RS256 token's header and claims */
static bool claims_ok(const gds_buf parts[3], const char *sub, const char *roles,
                      const pair *client) {
    char want[512];
    uint8_t ct[32];
    gds_buf cnf = {0};
    bool ok = CHECK(has(&parts[0], "\"alg\":\"RS256\"")) &&
              CHECK(has(&parts[1], "\"iss\":\"" TEST_URI "/AuthorizationService\"")) &&
              CHECK(has(&parts[1], "\"aud\":\"" RESOURCE "\""));
    (void)snprintf(want, sizeof(want), "\"sub\":\"%s\"", sub);
    ok = ok && CHECK(has(&parts[1], want));
    (void)snprintf(want, sizeof(want), "\"roles\":[%s]", roles);
    ok = ok && CHECK(has(&parts[1], want));
    ok = ok && CHECK(thumb(&client->cert, ct)) && CHECK(gds_b64url(ct, 32, &cnf) == GDS_OK);
    (void)snprintf(want, sizeof(want), "\"cnf\":{\"x5t#S256\":\"%s\"}",
                   cnf.data ? (const char *)cnf.data : "");
    ok = ok && CHECK(has(&parts[1], want));
    gds_buf_free(&cnf);
    return ok;
}

static bool token_ok(fixture *f, const UA_String *tok, const char *sub, const char *roles,
                     const pair *client) {
    if(tok->length == 0 || !tok->data) {
        CHECK(tok->length > 0 && tok->data); /* reports the empty token */
        return false;
    }
    gds_buf parts[3] = {{0}, {0}, {0}};
    size_t sl = 0;
    char *s = malloc(tok->length + 1);
    if(!s)
        return false;
    memcpy(s, tok->data, tok->length);
    s[tok->length] = 0;
    bool ok = CHECK(jwt_split(s, tok->length, parts, &sl)) &&
              CHECK(verify_rs256(&f->svc.cert, s, sl, &parts[2])) &&
              claims_ok(parts, sub, roles, client);
    for(size_t i = 0; i < 3; i++)
        gds_buf_free(&parts[i]);
    free(s);
    return ok;
}

/* ---- the server ---- */

static UA_Boolean running = true;

static void *loop_main(void *arg) {
    CHECK(gds_server_run(arg, &running) == GDS_OK);
    return NULL;
}

static void stop_cb(UA_Server *ua, void *data) {
    (void)ua;
    *(UA_Boolean *)data = false;
}

static bool wait_listening(UA_UInt16 port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for(int i = 0; i < 200; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        bool up = fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0;
        if(fd >= 0)
            (void)close(fd);
        if(up)
            return true;
        (void)usleep(50000);
    }
    return false;
}

static size_t audit_rows(gds_store *st);

static void test_description(fixture *f, UA_Client *c) {
    size_t n = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(c, service(f),
                                     UA_NODEID_NUMERIC(f->ns, UA_GDSID_AUTHORIZATIONSERVICETYPE_GETSERVICEDESCRIPTION),
                                     0, NULL, &n, &out);
    if(CHECK_EQ_INT(r, UA_STATUSCODE_GOOD) && CHECK_EQ_INT(n, 3)) {
        UA_String uri = UA_STRING(TEST_URI "/AuthorizationService");
        CHECK(UA_String_equal(out[0].data, &uri));
        CHECK(UA_ByteString_equal(out[1].data, &f->svc.cert));
        CHECK_EQ_INT(out[2].arrayLength, 3); /* session, username, x509 */
    }
    UA_Array_delete(out, n, &UA_TYPES[UA_TYPES_VARIANT]);
}

static void test_refusals(fixture *f, UA_Client *user, UA_Client *stranger) {
    UA_Guid id;
    CHECK_EQ_INT(start(f, user, "urn:opengds:test:authz:nowhere", "opengds-session", NULL, &id, NULL),
                 UA_STATUSCODE_BADNOTFOUND);
    /* a Client application is no Resource */
    CHECK_EQ_INT(start(f, user, CLIENTONLY, "opengds-session", NULL, &id, NULL),
                 UA_STATUSCODE_BADNOTFOUND);
    CHECK_EQ_INT(start(f, user, RESOURCE, "no-such-policy", NULL, &id, NULL),
                 UA_STATUSCODE_BADIDENTITYTOKENINVALID);
    /* Table 149: RequestorData only with the Certificate policy */
    UA_ByteString junk = UA_BYTESTRING("not used");
    CHECK_EQ_INT(start(f, user, RESOURCE, "opengds-session", &junk, &id, NULL),
                 UA_STATUSCODE_BADNONCEINVALID);
    CHECK_EQ_INT(start(f, user, RESOURCE, "opengds-x509", &junk, &id, NULL),
                 UA_STATUSCODE_BADNONCEINVALID);
    /* AccessTokenRequestor: a certificate the GDS CA did not issue */
    CHECK_EQ_INT(start(f, stranger, RESOURCE, "opengds-session", NULL, &id, NULL),
                 UA_STATUSCODE_BADUSERACCESSDENIED);
    tokens t;
    UA_Guid unknown = UA_Guid_random();
    CHECK_EQ_INT(finish(f, user, &unknown, NULL, 0, NULL, NULL, NULL, &t),
                 UA_STATUSCODE_BADNOTFOUND);
    UA_String bogus = UA_STRING("not-a-refresh-token");
    CHECK_EQ_INT(refresh(f, user, RESOURCE, &bogus, &t), UA_STATUSCODE_BADIDENTITYTOKENREJECTED);
    CHECK_EQ_INT(refresh(f, user, "urn:opengds:test:authz:nowhere", &bogus, &t),
                 UA_STATUSCODE_BADNOTFOUND);
}

/* Implicit (§9.3): the Session's user and Roles. */
static void test_session_policy(fixture *f, UA_Client *user, UA_Client *other) {
    size_t before = audit_rows(f->store);
    UA_Guid id;
    tokens t;
    if(CHECK_EQ_INT(start(f, user, RESOURCE, "opengds-session", NULL, &id, NULL), UA_STATUSCODE_GOOD)) {
        /* another Session cannot finish it (§9.6.6) */
        CHECK_EQ_INT(finish(f, other, &id, NULL, 0, NULL, NULL, NULL, &t), UA_STATUSCODE_BADNOTFOUND);
        if(CHECK_EQ_INT(finish(f, user, &id, NULL, 0, NULL, NULL, NULL, &t), UA_STATUSCODE_GOOD)) {
            token_ok(f, &t.access, "pw", "\"Operator\",\"Engineer\"", &f->app);
            UA_DateTime now = UA_DateTime_now();
            CHECK(t.accessExp > now + 3500 * UA_DATETIME_SEC && t.accessExp < now + 3700 * UA_DATETIME_SEC);
            CHECK(t.refresh.length > 0 && t.refreshExp > t.accessExp);
            /* RefreshToken (§9.6.8): a new pair, the old RefreshToken is spent */
            tokens t2, t3;
            if(CHECK_EQ_INT(refresh(f, user, RESOURCE, &t.refresh, &t2), UA_STATUSCODE_GOOD)) {
                token_ok(f, &t2.access, "pw", "\"Operator\",\"Engineer\"", &f->app);
                CHECK(!UA_String_equal(&t2.refresh, &t.refresh));
                CHECK_EQ_INT(refresh(f, user, RESOURCE, &t.refresh, &t3),
                             UA_STATUSCODE_BADIDENTITYTOKENREJECTED);
                /* only for the client certificate that received it */
                CHECK_EQ_INT(refresh(f, other, RESOURCE, &t2.refresh, &t3),
                             UA_STATUSCODE_BADIDENTITYTOKENREJECTED);
            }
            tokens_clear(&t2);
            tokens_clear(&t3);
        }
        tokens_clear(&t);
        /* the request is single use */
        CHECK_EQ_INT(finish(f, user, &id, NULL, 0, NULL, NULL, NULL, &t), UA_STATUSCODE_BADNOTFOUND);
    }
    /* RequestedRoles narrow the token; Roles not held are refused */
    UA_String op = UA_STRING("Operator"), sa = UA_STRING("SecurityAdmin"), no = UA_STRING("NoSuchRole");
    if(CHECK_EQ_INT(start(f, user, RESOURCE, "opengds-session", NULL, &id, NULL), UA_STATUSCODE_GOOD) &&
       CHECK_EQ_INT(finish(f, user, &id, &op, 1, NULL, NULL, NULL, &t), UA_STATUSCODE_GOOD))
        token_ok(f, &t.access, "pw", "\"Operator\"", &f->app);
    tokens_clear(&t);
    if(CHECK_EQ_INT(start(f, user, RESOURCE, "opengds-session", NULL, &id, NULL), UA_STATUSCODE_GOOD))
        CHECK_EQ_INT(finish(f, user, &id, &sa, 1, NULL, NULL, NULL, &t), UA_STATUSCODE_BADUSERACCESSDENIED);
    if(CHECK_EQ_INT(start(f, user, RESOURCE, "opengds-session", NULL, &id, NULL), UA_STATUSCODE_GOOD))
        CHECK_EQ_INT(finish(f, user, &id, &no, 1, NULL, NULL, NULL, &t), UA_STATUSCODE_BADINVALIDARGUMENT);
    /* a Session without a user: the client application is the subject */
    if(CHECK_EQ_INT(start(f, other, RESOURCE, "opengds-session", NULL, &id, NULL), UA_STATUSCODE_GOOD) &&
       CHECK_EQ_INT(finish(f, other, &id, NULL, 0, NULL, NULL, NULL, &t), UA_STATUSCODE_GOOD))
        token_ok(f, &t.access, CLIENT2_URI, "", &f->app2);
    tokens_clear(&t);
    /* AccessTokenRequested for each Finish that named a live request (5),
     * AccessTokenIssued for each token (4) */
    CHECK_EQ_INT(audit_rows(f->store), before + 9);
}

/* Explicit (§9.4) with a UserName token; then the lockout. */
static void test_username_policy(fixture *f, UA_Client *c) {
    UA_Guid id;
    tokens t;
    UA_UserNameIdentityToken u;
    UA_UserNameIdentityToken_init(&u);
    u.policyId = UA_STRING("opengds-username");
    u.userName = UA_STRING("pw");
    u.password = UA_BYTESTRING(PASSWORD);
    if(CHECK_EQ_INT(start(f, c, RESOURCE, "opengds-username", NULL, &id, NULL), UA_STATUSCODE_GOOD) &&
       CHECK_EQ_INT(finish(f, c, &id, NULL, 0, &u, &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN], NULL, &t),
                    UA_STATUSCODE_GOOD))
        token_ok(f, &t.access, "pw", "\"Operator\",\"Engineer\"", &f->app2);
    tokens_clear(&t);
    /* a token of another policy */
    if(CHECK_EQ_INT(start(f, c, RESOURCE, "opengds-username", NULL, &id, NULL), UA_STATUSCODE_GOOD))
        CHECK_EQ_INT(finish(f, c, &id, NULL, 0, NULL, NULL, NULL, &t), UA_STATUSCODE_BADIDENTITYTOKENINVALID);
    /* four more failures make five: locked out, the right password too */
    u.password = UA_BYTESTRING("wrong");
    for(int i = 0; i < 4; i++)
        if(CHECK_EQ_INT(start(f, c, RESOURCE, "opengds-username", NULL, &id, NULL), UA_STATUSCODE_GOOD))
            CHECK_EQ_INT(finish(f, c, &id, NULL, 0, &u, &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN], NULL, &t),
                         UA_STATUSCODE_BADIDENTITYTOKENREJECTED);
    u.password = UA_BYTESTRING(PASSWORD);
    if(CHECK_EQ_INT(start(f, c, RESOURCE, "opengds-username", NULL, &id, NULL), UA_STATUSCODE_GOOD))
        CHECK_EQ_INT(finish(f, c, &id, NULL, 0, &u, &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN], NULL, &t),
                     UA_STATUSCODE_BADUSERACCESSDENIED);
}

/* Certificate policy: RSA-SHA256 over the GDS certificate || ServiceData. */
static bool sign_x509(fixture *f, const UA_ByteString *key, const UA_ByteString *sd,
                      UA_SignatureData *sig) {
    const unsigned char *p = key->data;
    EVP_PKEY *pk = d2i_AutoPrivateKey(NULL, &p, (long)key->length);
    size_t n = f->own.cert.length + sd->length, sl = 0;
    unsigned char *data = malloc(n);
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    bool ok = false;
    if(pk && data && mc) {
        memcpy(data, f->own.cert.data, f->own.cert.length);
        memcpy(data + f->own.cert.length, sd->data, sd->length);
        ok = EVP_DigestSignInit(mc, NULL, EVP_sha256(), NULL, pk) == 1 &&
             EVP_DigestSign(mc, NULL, &sl, data, n) == 1 &&
             UA_ByteString_allocBuffer(&sig->signature, sl) == UA_STATUSCODE_GOOD &&
             EVP_DigestSign(mc, sig->signature.data, &sl, data, n) == 1;
        sig->signature.length = sl;
        sig->algorithm = UA_STRING_ALLOC("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    }
    EVP_MD_CTX_free(mc);
    free(data);
    EVP_PKEY_free(pk);
    return ok;
}

static void test_x509_policy(fixture *f, UA_Client *c) {
    uint8_t nonce[32];
    memset(nonce, 7, sizeof(nonce));
    UA_ByteString rd = {sizeof(nonce), nonce}, sd = UA_BYTESTRING_NULL;
    UA_Guid id;
    tokens t;
    UA_X509IdentityToken x;
    UA_X509IdentityToken_init(&x);
    x.policyId = UA_STRING("opengds-x509");
    x.certificateData = f->admin.cert;
    UA_SignatureData sig;
    UA_SignatureData_init(&sig);
    if(CHECK_EQ_INT(start(f, c, RESOURCE, "opengds-x509", &rd, &id, &sd), UA_STATUSCODE_GOOD) &&
       CHECK_EQ_INT(sd.length, 32) && CHECK(sign_x509(f, &f->admin.key, &sd, &sig)) &&
       CHECK_EQ_INT(finish(f, c, &id, NULL, 0, &x, &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN], &sig, &t),
                    UA_STATUSCODE_GOOD))
        token_ok(f, &t.access, "admin", "\"SecurityAdmin\"", &f->app);
    tokens_clear(&t);
    UA_SignatureData_clear(&sig);
    UA_ByteString_clear(&sd);
    /* signed with another key */
    if(CHECK_EQ_INT(start(f, c, RESOURCE, "opengds-x509", &rd, &id, &sd), UA_STATUSCODE_GOOD) &&
       CHECK(sign_x509(f, &f->stranger.key, &sd, &sig)))
        CHECK_EQ_INT(finish(f, c, &id, NULL, 0, &x, &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN], &sig, &t),
                     UA_STATUSCODE_BADIDENTITYTOKENREJECTED);
    UA_SignatureData_clear(&sig);
    UA_ByteString_clear(&sd);
}

static bool count_row(void *ctx, const gds_audit_row *row) {
    (void)row;
    (*(size_t *)ctx)++;
    return true;
}

static size_t audit_rows(gds_store *st) {
    size_t n = 0;
    CHECK(gds_store_audit_scan(st, 0, count_row, &n) == GDS_OK);
    return n;
}

static void serve(fixture *f, gds_server *s, UA_UInt16 port) {
    running = true;
    pthread_t loop;
    if(!CHECK(pthread_create(&loop, NULL, loop_main, s) == 0))
        return;
    (void)snprintf(f->url, sizeof(f->url), "opc.tcp://127.0.0.1:%u", (unsigned)port);
    CHECK(wait_listening(port));
    UA_Client *user = connect_as(f, &f->app, CLIENT_URI, true);
    UA_Client *other = connect_as(f, &f->app2, CLIENT2_URI, false);
    UA_Client *stranger = connect_as(f, &f->stranger, "urn:opengds:test:authz:stranger", true);
    if(CHECK(user && other && stranger) &&
       CHECK(UA_Client_getNamespaceIndex(user, UA_STRING("http://opcfoundation.org/UA/GDS/"), &f->ns) ==
             UA_STATUSCODE_GOOD)) {
        test_description(f, user);
        test_refusals(f, user, stranger);
        test_session_policy(f, user, other);
        test_x509_policy(f, user);
        test_username_policy(f, other);
    }
    drop(user);
    drop(other);
    drop(stranger);
    (void)UA_Server_addTimedCallback(gds_server_ua(s), stop_cb, &running,
                                     UA_DateTime_nowMonotonic(), NULL);
    (void)pthread_join(loop, NULL);
}

static bool write_file(const char *path, const char *text) {
    return CHECK(gds_file_write_atomic(path, text, strlen(text), 0600) == GDS_OK);
}

static void test_served(fixture *f, const char *dir) {
    static gds_users users;
    char path[1024], pki[1024], certs[1024], text[1024], hash[256], tp[65];
    uint8_t md[32];
    UA_Guid rid;
    if(!CHECK(gds_password_hash((const uint8_t *)PASSWORD, strlen(PASSWORD), 10000, hash,
                                sizeof(hash)) == GDS_OK) ||
       !CHECK(thumb(&f->admin.cert, md)) || !CHECK(gds_hex(md, 32, tp, sizeof(tp)) == GDS_OK))
        return;
    (void)snprintf(text, sizeof(text), "pw Operator,Engineer %s\nadmin SecurityAdmin x509-sha256:%s\n",
                   hash, tp);
    if(!CHECK(gds_path(path, sizeof(path), "%s/users", dir) == GDS_OK) || !write_file(path, text) ||
       !CHECK(gds_users_load(path, &users) == GDS_OK) ||
       !CHECK(gds_path(pki, sizeof(pki), "%s/pki", dir) == GDS_OK) ||
       !CHECK(gds_path(certs, sizeof(certs), "%s/UserTokenCerts/trusted/certs", pki) == GDS_OK) ||
       !CHECK(gds_mkdirs(certs, 0700) == GDS_OK) ||
       !CHECK(gds_path(path, sizeof(path), "%s/admin.der", certs) == GDS_OK) ||
       !CHECK(gds_file_write_atomic(path, f->admin.cert.data, f->admin.cert.length, 0600) == GDS_OK) ||
       !CHECK(insert_app(f->store, RESOURCE, UA_APPLICATIONTYPE_SERVER, &rid)) ||
       !CHECK(insert_app(f->store, CLIENTONLY, UA_APPLICATIONTYPE_CLIENT, &rid)))
        return;

    const char *alg = NULL;
    gds_jwt_key *k = NULL;
    gds_buf kd = {f->svc.key.data, f->svc.key.length};
    if(!CHECK(gds_jwt_key_new(&kd, &k, &alg) == GDS_OK))
        return;
    gds_authz_config az;
    memset(&az, 0, sizeof(az));
    az.serviceCertificate = (gds_buf){f->svc.cert.data, f->svc.cert.length};
    az.sign = gds_jwt_key_sign;
    az.signCtx = k;
    az.alg = alg;
    az.accessLifetime = 3600;
    az.refreshLifetime = 86400;
    UA_UInt16 port = (UA_UInt16)(52000 + getpid() % 1000);
    gds_server_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.port = port;
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS AuthorizationService test";
    cfg.ownCert = (gds_buf){f->own.cert.data, f->own.cert.length};
    cfg.ownKey = (gds_buf){f->own.key.data, f->own.key.length};
    cfg.userPkiDir = pki;
    cfg.store = f->store;
    cfg.ca = f->ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;
    cfg.authz = &az;
    gds_server *s = NULL;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK))
        serve(f, s, port);
    gds_server_delete(s);
    gds_jwt_key_free(k);
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    CHECK(setenv("TZ", "UTC", 1) == 0);
    tzset();
    test_b64url();
    test_jwt_es256();
    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);
    static uint8_t pw[] = "authz-ca-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    fixture f;
    memset(&f, 0, sizeof(f));
    if(CHECK(gds_ca_openssl_open(&cc, &f.ca) == GDS_OK) &&
       CHECK(gds_store_open(db, &f.store) == GDS_OK) &&
       CHECK(make_cert("CN=OpenGDS authz test", "URI:" TEST_URI, &f.own)) &&
       CHECK(make_cert("CN=OpenGDS tokens", "URI:" TEST_URI "/AuthorizationService", &f.svc)) &&
       CHECK(make_cert("CN=Stranger", "URI:urn:opengds:test:authz:stranger", &f.stranger)) &&
       CHECK(make_cert("CN=Admin", "URI:urn:opengds:test:user:admin", &f.admin)) &&
       CHECK(issue_client(&f, CLIENT_URI, &f.app)) && CHECK(issue_client(&f, CLIENT2_URI, &f.app2)))
        test_served(&f, argv[1]);
    pair *all[] = {&f.own, &f.svc, &f.app, &f.app2, &f.stranger, &f.admin};
    for(size_t i = 0; i < 6; i++)
        pair_clear(all[i]);
    gds_store_close(f.store);
    gds_ca_close(f.ca);
    return CHECK_DONE();
}
