/* OpenGDS unit test: opengds-signer core, protocol and the ca_ipc client.
 * The signer must sign only what the store holds: the record and CSR that
 * opengdsd passes are ignored (decision G1).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ca.h"
#include "ca_ipc.h"
#include "check.h"
#include "common/buf.h"
#include "common/ids.h"
#include "common/limits.h"
#include "proto.h"
#include "signer.h"
#include "store.h"
#include "common/banned.h"

#define STORED_URI "urn:opengds:test:stored"

/* Entries on a CRL (an empty CRL has no list at all). */
static int crl_count(X509_CRL *crl) {
    STACK_OF(X509_REVOKED) *l = X509_CRL_get_REVOKED(crl);
    return l ? sk_X509_REVOKED_num(l) : 0;
}

static gds_status make_csr(gds_buf *out) {
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    X509_REQ *req = X509_REQ_new();
    gds_status r = GDS_ECRYPTO;
    if(key && req && X509_REQ_set_pubkey(req, key) == 1 &&
       X509_REQ_sign(req, key, EVP_sha256()) > 0) {
        int len = i2d_X509_REQ(req, NULL);
        out->data = len > 0 ? malloc((size_t)len) : NULL;
        unsigned char *p = out->data;
        out->len = len > 0 ? (size_t)len : 0;
        r = (out->data && i2d_X509_REQ(req, &p) == len) ? GDS_OK : GDS_ECRYPTO;
    }
    X509_REQ_free(req);
    EVP_PKEY_free(key);
    return r;
}

static bool cert_has_uri(const gds_buf *der, const char *uri) {
    const unsigned char *p = der->data;
    X509 *x = d2i_X509(NULL, &p, (long)der->len);
    GENERAL_NAMES *gens = x ? X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL) : NULL;
    bool found = false;
    for(int i = 0; gens && i < sk_GENERAL_NAME_num(gens); i++) {
        const GENERAL_NAME *g = sk_GENERAL_NAME_value(gens, i);
        found |= g->type == GEN_URI && (size_t)g->d.ia5->length == strlen(uri) &&
                 memcmp(g->d.ia5->data, uri, strlen(uri)) == 0;
    }
    GENERAL_NAMES_free(gens);
    X509_free(x);
    return found;
}

/* One application and one Received request in a fresh store. */
static void seed_store(gds_store *w, UA_Guid *appId, UA_Guid *reqId) {
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "Stored Client");
    rec.applicationUri = UA_STRING(STORED_URI);
    rec.applicationType = UA_APPLICATIONTYPE_CLIENT;
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    CHECK(gds_guid_random(appId) == GDS_OK && gds_guid_random(reqId) == GDS_OK);
    CHECK(gds_store_app_insert(w, appId, &rec) == GDS_OK);
    gds_request q;
    memset(&q, 0, sizeof(q));
    q.id = *reqId;
    q.appId = *appId;
    q.groupId = 615;
    q.certType = UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE;
    q.state = GDS_REQ_RECEIVED;
    CHECK(make_csr(&q.csr) == GDS_OK);
    CHECK(gds_store_req_insert(w, &q) == GDS_OK);
    gds_buf_free(&q.csr);
}

typedef struct {
    gds_signer *s;
    int fd;
    gds_status result;
} serve_arg;

/* A Received request of the stored application; withCsr false makes it a
 * StartNewKeyPairRequest. */
static void add_request(gds_store *w, const UA_Guid *appId, bool withCsr, UA_Guid *reqId) {
    gds_request q;
    memset(&q, 0, sizeof(q));
    CHECK(gds_guid_random(reqId) == GDS_OK);
    q.id = *reqId;
    q.appId = *appId;
    q.groupId = 615;
    q.certType = UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE;
    q.state = GDS_REQ_RECEIVED;
    if(withCsr)
        CHECK(make_csr(&q.csr) == GDS_OK);
    CHECK(gds_store_req_insert(w, &q) == GDS_OK);
    gds_buf_free(&q.csr);
}

static X509 *der_cert(const gds_buf *der) {
    const unsigned char *p = der->data;
    return d2i_X509(NULL, &p, (long)der->len);
}

static void *serve_thread(void *p) {
    serve_arg *a = p;
    a->result = gds_signer_serve(a->s, a->fd);
    return NULL;
}

/* opengdsd's view: it passes a different record and junk instead of a CSR;
 * the signer must use the stored ones. */
static void test_ipc_sign(gds_ca *ipc, gds_store *w, const UA_Guid *reqId,
                          gds_ca_issued *kept) {
    UA_ApplicationRecordDataType lie;
    UA_ApplicationRecordDataType_init(&lie);
    lie.applicationUri = UA_STRING("urn:evil:daemon");
    uint8_t junk[] = {1, 2, 3};
    gds_buf junkCsr = {junk, sizeof(junk)};
    gds_ca_subject subj = {reqId, &lie, 1, 1};
    gds_ca_issued out;
    CHECK(gds_ca_sign_csr(ipc, &subj, &junkCsr, &out) == GDS_OK);
    CHECK(out.der.len > 0 && out.serial.len == 20 && out.notAfter > out.notBefore);
    CHECK(cert_has_uri(&out.der, STORED_URI));
    CHECK(!cert_has_uri(&out.der, "urn:evil:daemon"));
    /* once issued, never signed again */
    CHECK(gds_store_req_set_state(w, reqId, GDS_REQ_ISSUED, &out.der, UA_STATUSCODE_GOOD) ==
          GDS_OK);
    *kept = out; /* for test_ipc_revoke */
    memset(&out, 0, sizeof(out));
    CHECK(gds_ca_sign_csr(ipc, &subj, &junkCsr, &out) == GDS_ESTATE);
    UA_Guid unknown;
    CHECK(gds_guid_random(&unknown) == GDS_OK);
    subj.requestId = &unknown;
    CHECK(gds_ca_sign_csr(ipc, &subj, &junkCsr, &out) == GDS_ENOTFOUND);
}

#define KP_PASSWORD "kp-unit-password"

/* The PFX opens with the password only, holds the key of the certificate
 * and the CA certificate (§7.9.5: certificate and private key). */
static void check_pfx(const gds_buf *pfx, const gds_buf *certDer) {
    const unsigned char *p = pfx->data;
    PKCS12 *p12 = d2i_PKCS12(NULL, &p, (long)pfx->len);
    EVP_PKEY *k = NULL;
    X509 *c = NULL, *issued = der_cert(certDer);
    STACK_OF(X509) *chain = NULL;
    CHECK(p12 && PKCS12_verify_mac(p12, "wrong", -1) == 0);
    CHECK(p12 && PKCS12_parse(p12, KP_PASSWORD, &k, &c, &chain) == 1);
    CHECK(k && c && issued && X509_cmp(c, issued) == 0 && X509_check_private_key(issued, k) == 1);
    CHECK(chain && sk_X509_num(chain) == 1);
    OSSL_STACK_OF_X509_free(chain);
    X509_free(c);
    X509_free(issued);
    EVP_PKEY_free(k);
    PKCS12_free(p12);
}

/* PKCS #8 PEM, encrypted exactly when a password is given. */
static void check_pem(const gds_buf *pem, const gds_buf *certDer, const char *pw) {
    const char *tag = pw ? "-----BEGIN ENCRYPTED PRIVATE KEY-----"
                         : "-----BEGIN PRIVATE KEY-----";
    CHECK(pem->len > strlen(tag) && memcmp(pem->data, tag, strlen(tag)) == 0);
    BIO *b = BIO_new_mem_buf(pem->data, (int)pem->len);
    char pwc[] = KP_PASSWORD;
    EVP_PKEY *k = b ? PEM_read_bio_PrivateKey(b, NULL, NULL, pw ? pwc : NULL) : NULL;
    X509 *issued = der_cert(certDer);
    CHECK(k && issued && X509_check_private_key(issued, k) == 1);
    X509_free(issued);
    EVP_PKEY_free(k);
    BIO_free(b);
    if(pw) { /* and not with another password */
        char wrong[] = "wrong-password";
        b = BIO_new_mem_buf(pem->data, (int)pem->len);
        k = b ? PEM_read_bio_PrivateKey(b, NULL, NULL, wrong) : NULL;
        CHECK(k == NULL);
        EVP_PKEY_free(k);
        BIO_free(b);
    }
}

/* StartNewKeyPairRequest through the signer: the key is generated there,
 * for the stored record, and only for a request without a CSR. */
static void test_ipc_key_pair(gds_ca *ipc, gds_store *w, const UA_Guid *appId) {
    UA_ApplicationRecordDataType lie;
    UA_ApplicationRecordDataType_init(&lie);
    lie.applicationUri = UA_STRING("urn:evil:daemon");
    uint8_t pwb[] = KP_PASSWORD;
    gds_buf pw = {pwb, sizeof(pwb) - 1}, none = {0};
    const struct {
        gds_ca_key_format f;
        const gds_buf *pw;
    } cases[] = {{GDS_CA_KEY_PFX, &pw}, {GDS_CA_KEY_PEM, &pw}, {GDS_CA_KEY_PEM, &none}};
    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        UA_Guid id;
        add_request(w, appId, false, &id);
        gds_ca_subject subj = {&id, &lie, 1, 1};
        gds_ca_keyreq kr = {cases[i].f, cases[i].pw};
        gds_ca_issued out;
        gds_buf key = {0};
        CHECK(gds_ca_new_key_pair(ipc, &subj, &kr, &out, &key) == GDS_OK);
        CHECK(cert_has_uri(&out.der, STORED_URI) && !cert_has_uri(&out.der, "urn:evil:daemon"));
        if(cases[i].f == GDS_CA_KEY_PFX)
            check_pfx(&key, &out.der);
        else
            check_pem(&key, &out.der, cases[i].pw->len ? KP_PASSWORD : NULL);
        CHECK(gds_store_req_set_state(w, &id, GDS_REQ_ISSUED, &out.der, UA_STATUSCODE_GOOD) ==
              GDS_OK);
        gds_ca_issued_clear(&out);
        gds_buf_free_secret(&key);
        CHECK(gds_ca_new_key_pair(ipc, &subj, &kr, &out, &key) == GDS_ESTATE && !key.data);
    }
    /* a signing request never gets a generated key; a key pair request is never signed */
    UA_Guid csrReq, kpReq;
    add_request(w, appId, true, &csrReq);
    add_request(w, appId, false, &kpReq);
    gds_ca_subject subj = {&csrReq, &lie, 1, 1};
    gds_ca_keyreq kr = {GDS_CA_KEY_PFX, &pw};
    gds_ca_issued out;
    gds_buf key = {0};
    CHECK(gds_ca_new_key_pair(ipc, &subj, &kr, &out, &key) == GDS_EDENIED && !key.data);
    subj.requestId = &kpReq;
    CHECK(gds_ca_sign_csr(ipc, &subj, &none, &out) != GDS_OK);
    gds_ca_keyreq bad = {(gds_ca_key_format)7, &pw}; // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange)
    CHECK(gds_ca_new_key_pair(ipc, &subj, &bad, &out, &key) == GDS_EINVAL);
}

/* NEW_KEY_PAIR messages: round trip, and every truncation refused. */
static void test_key_pair_proto(void) {
    UA_Guid id;
    CHECK(gds_guid_random(&id) == GDS_OK);
    uint8_t pwb[] = KP_PASSWORD;
    gds_buf pw = {pwb, sizeof(pwb) - 1}, msg = {0};
    uint8_t longPw[GDS_MAX_KEY_PASSWORD + 1];
    memset(longPw, 'x', sizeof(longPw));
    gds_buf tooLong = {longPw, sizeof(longPw)};
    CHECK(gds_sigp_encode_new_key_pair(&id, GDS_CA_KEY_PFX, &tooLong, &msg) == GDS_EINVAL &&
          !msg.data);
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    CHECK(gds_sigp_encode_new_key_pair(&id, (gds_ca_key_format)0, &pw, &msg) == GDS_EINVAL);
    CHECK(gds_sigp_encode_new_key_pair(&id, GDS_CA_KEY_PEM, &pw, &msg) == GDS_OK);
    gds_sigp_request m;
    CHECK(gds_sigp_decode(msg.data, msg.len, &m) == GDS_OK);
    CHECK(m.op == GDS_SIGP_NEW_KEY_PAIR && m.format == GDS_CA_KEY_PEM &&
          UA_Guid_equal(&m.requestId, &id) && m.password.len == pw.len &&
          memcmp(m.password.data, pwb, pw.len) == 0);
    gds_sigp_request_clear(&m);
    for(size_t n = 0; n < msg.len; n++) {
        gds_status d = gds_sigp_decode(msg.data, n, &m);
        CHECK(d != GDS_OK);
        if(d == GDS_OK)
            gds_sigp_request_clear(&m);
    }
    gds_buf_free_secret(&msg);
    /* the reply carries the key; an OK reply without one is refused */
    uint8_t der[] = {0x30, 0x00}, ser[] = {1}, k[] = {9, 9, 9};
    gds_ca_issued is;
    memset(&is, 0, sizeof(is));
    is.serial = (gds_buf){ser, 1};
    is.der = (gds_buf){der, 2};
    is.notBefore = 1;
    is.notAfter = 2;
    gds_buf key = {k, 3}, got = {0}, reply = {0};
    CHECK(gds_sigp_encode_key_reply(GDS_OK, &is, &key, &reply) == GDS_OK);
    gds_status st = GDS_EIO;
    gds_ca_issued gi;
    CHECK(gds_sigp_decode_key_reply(reply.data, reply.len, &st, &gi, &got) == GDS_OK);
    CHECK(st == GDS_OK && got.len == 3 && memcmp(got.data, k, 3) == 0 && gi.der.len == 2);
    gds_ca_issued_clear(&gi);
    gds_buf_free_secret(&got);
    CHECK(gds_sigp_decode_key_reply(reply.data, reply.len - 1, &st, &gi, &got) != GDS_OK &&
          !got.data);
    gds_buf_free(&reply);
    gds_buf empty = {0};
    CHECK(gds_sigp_encode_key_reply(GDS_OK, &is, &empty, &reply) == GDS_EINVAL);
}

/* What test_ipc_sign left in the journal: the issuance, then the two
 * refusals, in order and with a verified chain. */
typedef struct {
    gds_journal_entry e[3];
    int n;
} journal_seen;

static bool keep_entry(void *ctx, const gds_journal_entry *e) {
    journal_seen *js = ctx;
    js->e[js->n++] = *e;
    return js->n < 3;
}

static void test_journal(const char *path, const UA_Guid *reqId) {
    journal_seen js;
    memset(&js, 0, sizeof(js));
    int64_t bad = -1;
    CHECK(gds_journal_read(path, keep_entry, &js, &bad) == GDS_OK);
    CHECK_EQ_INT(bad, 0);
    if(!CHECK_EQ_INT(js.n, 3))
        return;
    CHECK(js.e[0].seq == 1 && js.e[0].issued && js.e[0].serialLen == 20 && js.e[0].status == 0);
    CHECK(UA_Guid_equal(&js.e[0].requestId, reqId));
    CHECK(!js.e[1].issued && js.e[1].status == (int)GDS_ESTATE);
    CHECK(UA_Guid_equal(&js.e[1].requestId, reqId));
    CHECK(!js.e[2].issued && js.e[2].status == (int)GDS_ENOTFOUND);
}

static int crl_entries(gds_ca *ca) {
    gds_buf der = {0};
    CHECK(gds_ca_get_crl(ca, &der) == GDS_OK);
    const unsigned char *p = der.data;
    X509_CRL *crl = der.data ? d2i_X509_CRL(NULL, &p, (long)der.len) : NULL;
    int n = crl ? crl_count(crl) : -1;
    X509_CRL_free(crl);
    gds_buf_free(&der);
    return n;
}

/* REVOKE: the signer puts a serial on the CRL only once the store marks
 * that certificate revoked, so opengdsd cannot revoke at will. */
static void test_ipc_revoke(gds_ca *ipc, gds_store *w, const UA_Guid *appId,
                            const gds_ca_issued *issued) {
    CHECK(gds_store_cert_add(w, appId, 615, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE,
                             &issued->serial, &issued->der, issued->notBefore,
                             issued->notAfter) == GDS_OK);
    int before = crl_entries(ipc); /* the CA directory outlives a run */
    CHECK(gds_ca_revoke(ipc, &issued->serial) == GDS_EDENIED); /* not marked */
    CHECK_EQ_INT(crl_entries(ipc), before);
    uint8_t unknown[] = {0x42, 0x42};
    gds_buf unk = {unknown, sizeof(unknown)};
    CHECK(gds_ca_revoke(ipc, &unk) == GDS_EDENIED); /* not in the store */
    gds_buf serial = {0};
    CHECK(gds_store_cert_revoke(w, appId, &issued->der, &serial) == GDS_OK);
    gds_buf_free(&serial);
    CHECK(gds_ca_revoke(ipc, &issued->serial) == GDS_OK);
    CHECK_EQ_INT(crl_entries(ipc), before + 1);
    CHECK(gds_ca_revoke(ipc, &issued->serial) == GDS_OK); /* the retry after a failure */
    CHECK_EQ_INT(crl_entries(ipc), before + 1);
}

/* REVOKE framing: exact body, bounded serial. */
static void test_revoke_proto(void) {
    uint8_t ser[GDS_SIGP_MAX_SERIAL + 1];
    memset(ser, 0x11, sizeof(ser));
    gds_buf big = {ser, sizeof(ser)}, ok = {ser, 20}, msg = {0}, got = {0};
    CHECK(gds_sigp_encode_revoke(&big, &msg) == GDS_EINVAL && !msg.data);
    CHECK(gds_sigp_encode_request(GDS_SIGP_REVOKE, NULL, &msg) == GDS_EINVAL && !msg.data);
    CHECK(gds_sigp_encode_revoke(&ok, &msg) == GDS_OK);
    gds_sigp_op op = GDS_SIGP_SIGN_CSR;
    UA_Guid id;
    CHECK(gds_sigp_decode_request_ex(msg.data, msg.len, &op, &id, &got) == GDS_OK);
    CHECK(op == GDS_SIGP_REVOKE && got.len == 20 && memcmp(got.data, ser, 20) == 0);
    gds_buf_free(&got);
    CHECK(gds_sigp_decode_request(msg.data, msg.len, &op, &id) == GDS_OK);
    /* a serial length that does not match the body */
    if(CHECK(msg.len > GDS_SIGP_HEADER + 2)) {
        msg.data[GDS_SIGP_HEADER + 1]++;
        CHECK(gds_sigp_decode_request_ex(msg.data, msg.len, &op, &id, &got) == GDS_EINVAL &&
              !got.data);
        msg.data[GDS_SIGP_HEADER + 1] = 0;
        CHECK(gds_sigp_decode_request_ex(msg.data, msg.len, &op, &id, &got) == GDS_EINVAL);
    }
    gds_buf_free(&msg);
}

static void test_ipc_get(gds_ca *ipc, gds_ca *direct) {
    gds_buf a = {0}, b = {0};
    CHECK(gds_ca_get_ca_cert(ipc, &a) == GDS_OK && gds_ca_get_ca_cert(direct, &b) == GDS_OK);
    CHECK(a.data && b.data && a.len == b.len && memcmp(a.data, b.data, a.len) == 0);
    gds_buf_free(&a);
    gds_buf_free(&b);
    CHECK(gds_ca_get_crl(ipc, &a) == GDS_OK && a.len > 0);
    gds_buf_free(&a);
    /* each ECC issuer over IPC is the signer's own, and differs from RSA */
    for(unsigned i = GDS_CA_ISSUER_P256; i < GDS_CA_ISSUERS; i++) {
        gds_buf rsa = {0};
        CHECK(gds_ca_get_issuer_cert(ipc, (gds_ca_issuer)i, &a) == GDS_OK);
        CHECK(gds_ca_get_issuer_cert(direct, (gds_ca_issuer)i, &b) == GDS_OK);
        CHECK(gds_ca_get_ca_cert(direct, &rsa) == GDS_OK);
        CHECK(a.data && b.data && a.len == b.len && memcmp(a.data, b.data, a.len) == 0);
        CHECK(a.data && rsa.data && (a.len != rsa.len || memcmp(a.data, rsa.data, a.len) != 0));
        gds_buf_free(&a);
        gds_buf_free(&b);
        gds_buf_free(&rsa);
        CHECK(gds_ca_get_issuer_crl(ipc, (gds_ca_issuer)i, &a) == GDS_OK && a.len > 0);
        gds_buf_free(&a);
    }
}

/* Issuer bytes: RSA is never explicit, unknown issuers are refused. */
static void test_issuer_proto(void) {
    gds_buf msg = {0};
    gds_sigp_request m;
    CHECK(gds_sigp_encode_issuer_request(GDS_SIGP_ISSUE_CRL, GDS_CA_ISSUER_P384, &msg) == GDS_OK);
    CHECK(gds_sigp_decode(msg.data, msg.len, &m) == GDS_OK && m.issuer == GDS_CA_ISSUER_P384);
    gds_sigp_request_clear(&m);
    msg.data[msg.len - 1] = 0; /* explicit RSA */
    CHECK(gds_sigp_decode(msg.data, msg.len, &m) == GDS_EINVAL);
    msg.data[msg.len - 1] = (uint8_t)GDS_CA_ISSUERS;
    CHECK(gds_sigp_decode(msg.data, msg.len, &m) == GDS_EINVAL);
    gds_buf_free(&msg);
    CHECK(gds_sigp_encode_issuer_request(GDS_SIGP_SIGN_CSR, GDS_CA_ISSUER_P256, &msg) == GDS_EINVAL);
    uint8_t one = 1;
    gds_buf serial = {&one, 1};
    CHECK(gds_sigp_encode_revoke_issuer(GDS_CA_ISSUER_P256, &serial, &msg) == GDS_OK);
    CHECK(gds_sigp_decode(msg.data, msg.len, &m) == GDS_OK && m.issuer == GDS_CA_ISSUER_P256 &&
          m.serial.len == 1);
    gds_sigp_request_clear(&m);
    gds_buf_free(&msg);
}

/* Malformed and mutated datagrams: always a well-formed refusal, no crash. */
static void test_malformed(gds_signer *s, const UA_Guid *reqId) {
    gds_buf good = {0}, reply = {0};
    CHECK(gds_sigp_encode_request(GDS_SIGP_SIGN_CSR, reqId, &good) == GDS_OK);
    uint8_t m[256];
    for(int i = 0; i < 3000; i++) {
        size_t len = good.len;
        memcpy(m, good.data, good.len);
        unsigned char rnd[4];
        CHECK(RAND_bytes(rnd, sizeof(rnd)) == 1);
        if(i % 3 == 0) {
            len = rnd[0] % sizeof(m);
            CHECK(RAND_bytes(m, (int)(len ? len : 1)) == 1);
        } else {
            m[rnd[1] % good.len] ^= (uint8_t)(rnd[2] | 1u);
            if(i % 3 == 2)
                len = rnd[3] % (good.len + 1);
        }
        CHECK(gds_signer_handle(s, m, len, &reply) == GDS_OK);
        gds_status st = GDS_OK;
        gds_ca_issued iss;
        gds_status d = gds_sigp_decode_reply(GDS_SIGP_SIGN_CSR, reply.data, reply.len, &st, &iss,
                                             NULL);
        /* a mutated request may still name a valid op; then the op differs */
        if(d == GDS_OK)
            gds_ca_issued_clear(&iss);
        gds_buf_free(&reply);
    }
    gds_buf_free(&good);
    /* header-only garbage gets EINVAL */
    uint8_t zero[12] = {0};
    CHECK(gds_signer_handle(s, zero, sizeof(zero), &reply) == GDS_OK);
    gds_status st = GDS_OK;
    gds_ca_issued iss;
    CHECK(gds_sigp_decode_reply(GDS_SIGP_SIGN_CSR, reply.data, reply.len, &st, &iss, NULL) ==
              GDS_OK &&
          st == GDS_EINVAL);
    gds_buf_free(&reply);
}

static gds_ca *open_direct_ca(const char *dir) {
    static uint8_t pw[] = "signer-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cfg;
    gds_ca_config_init(&cfg);
    cfg.dir = dir;
    cfg.caKeyBits = 2048;
    cfg.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    CHECK(gds_ca_openssl_open(&cfg, &ca) == GDS_OK);
    return ca;
}

/* ---- the AccessToken key (TOKEN_CHAIN, TOKEN_SIGN) ---- */

#define TOKEN_URI "urn:opengds:test:AuthorizationService"
/* base64url of {"alg":"RS256","typ":"JWT"} '.' base64url of {} */
#define JWS_OK "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30"

static void test_jws_input(void) {
    static const struct {
        const char *in;
        bool ok;
    } cases[] = {
        {JWS_OK, true},
        {"eyJhbGciOiJSUzI1NiJ9.e30", true},          /* {"alg":"RS256"} */
        {"eyJhbGciOiJFUzI1NiJ9.e30", false},         /* {"alg":"ES256"} */
        {"eyJhbGciOiJSUzI1NiJ9", false},             /* no payload */
        {"eyJhbGciOiJSUzI1NiJ9.", false},
        {".e30", false},
        {"eyJhbGciOiJSUzI1NiJ9.e30.c2ln", false},    /* a whole JWS */
        {"eyJhbGciOiJSUzI1NiJ9.e3+", false},         /* base64, not base64url */
        {"eyJhbGciOiJSUzI1Ni.e30", false},           /* header cut short */
        {"MIIB.e30", false},
    };
    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        CHECK(gds_ca_jws_input_ok((const uint8_t *)cases[i].in, strlen(cases[i].in)) ==
              cases[i].ok);
}

static X509 *first_of(const gds_buf *chain, size_t *len) {
    const unsigned char *p = chain->data;
    X509 *x = chain->data ? d2i_X509(NULL, &p, (long)chain->len) : NULL;
    *len = x ? (size_t)(p - chain->data) : 0;
    return x;
}

static bool san_uri_is(X509 *x, const char *uri) {
    GENERAL_NAMES *g = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
    bool ok = false;
    for(int i = 0; g && i < sk_GENERAL_NAME_num(g); i++) {
        const GENERAL_NAME *n = sk_GENERAL_NAME_value(g, i);
        if(n->type == GEN_URI)
            ok = (size_t)n->d.uniformResourceIdentifier->length == strlen(uri) &&
                 memcmp(n->d.uniformResourceIdentifier->data, uri, strlen(uri)) == 0;
    }
    GENERAL_NAMES_free(g);
    return ok;
}

static bool verifies(X509 *x, const char *in, const gds_buf *sig) {
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    bool ok = mc && EVP_DigestVerifyInit(mc, NULL, EVP_sha256(), NULL, X509_get0_pubkey(x)) == 1 &&
              EVP_DigestVerify(mc, sig->data, sig->len, (const uint8_t *)in, strlen(in)) == 1;
    EVP_MD_CTX_free(mc);
    return ok;
}

static void test_ipc_token(gds_ca *ipc, gds_ca *direct, gds_signer *s, const char *caDir) {
    gds_buf in = {(uint8_t *)(uintptr_t)JWS_OK, strlen(JWS_OK)}, sig = {0}, chain = {0};
    /* no certificate yet: nothing is signed */
    CHECK(gds_ca_token_sign(ipc, &in, &sig) == GDS_ESTATE && !sig.data);
    CHECK(gds_ca_token_chain(ipc, "", &chain) == GDS_EINVAL);
    CHECK(gds_ca_token_chain(ipc, TOKEN_URI, &chain) == GDS_OK);
    size_t len = 0;
    X509 *leaf = first_of(&chain, &len);
    gds_buf caDer = {0};
    CHECK(gds_ca_get_ca_cert(direct, &caDer) == GDS_OK);
    /* chain = token certificate || RSA CA certificate */
    CHECK(leaf && chain.len == len + caDer.len &&
          memcmp(chain.data + len, caDer.data, caDer.len) == 0);
    const unsigned char *p = caDer.data;
    X509 *caCert = d2i_X509(NULL, &p, (long)caDer.len);
    CHECK(leaf && caCert && X509_check_issued(caCert, leaf) == X509_V_OK &&
          X509_verify(leaf, X509_get0_pubkey(caCert)) == 1);
    CHECK(leaf && san_uri_is(leaf, TOKEN_URI));
    CHECK(leaf && (X509_get_key_usage(leaf) & ~(uint32_t)KU_DIGITAL_SIGNATURE) == 0 &&
          (X509_get_key_usage(leaf) & KU_DIGITAL_SIGNATURE));
    CHECK(leaf && X509_check_ca(leaf) == 0);
    CHECK(gds_ca_token_sign(ipc, &in, &sig) == GDS_OK && leaf && verifies(leaf, JWS_OK, &sig));
    gds_buf_free(&sig);
    /* the same URI: the same certificate; another: a new one, same key */
    gds_buf again = {0};
    CHECK(gds_ca_token_chain(ipc, TOKEN_URI, &again) == GDS_OK && again.len == chain.len &&
          memcmp(again.data, chain.data, chain.len) == 0);
    gds_buf_free(&again);
    CHECK(gds_ca_token_chain(ipc, TOKEN_URI ":2", &again) == GDS_OK);
    X509 *leaf2 = first_of(&again, &len);
    CHECK(leaf2 && leaf && san_uri_is(leaf2, TOKEN_URI ":2") &&
          EVP_PKEY_eq(X509_get0_pubkey(leaf2), X509_get0_pubkey(leaf)) == 1 &&
          X509_cmp(leaf2, leaf) != 0);
    gds_buf_free(&again);
    /* the signer refuses anything but a JWS signing input, even when
     * opengdsd's own check is bypassed */
    static const char csrLike[] = "\x30\x82\x01\x0a not a token";
    gds_buf bad = {(uint8_t *)(uintptr_t)csrLike, sizeof(csrLike) - 1}, msg = {0}, reply = {0};
    CHECK(gds_sigp_encode_token(GDS_SIGP_TOKEN_SIGN, &bad, &msg) == GDS_OK);
    CHECK(gds_signer_handle(s, msg.data, msg.len, &reply) == GDS_OK);
    gds_status st = GDS_OK;
    CHECK(gds_sigp_decode_reply(GDS_SIGP_TOKEN_SIGN, reply.data, reply.len, &st, NULL, &sig) ==
              GDS_OK &&
          st == GDS_EINVAL && !sig.data);
    gds_buf_free(&msg);
    gds_buf_free(&reply);
    CHECK(gds_ca_token_sign(ipc, &bad, &sig) == GDS_EINVAL);
    /* a restarted signer signs with the key and certificate from disk */
    gds_ca *reopened = open_direct_ca(caDir);
    CHECK(reopened && gds_ca_token_sign(reopened, &in, &sig) == GDS_OK && leaf2 &&
          verifies(leaf2, JWS_OK, &sig));
    gds_buf_free(&sig);
    gds_ca_close(reopened);
    X509_free(leaf2);
    X509_free(leaf);
    X509_free(caCert);
    gds_buf_free(&caDer);
    gds_buf_free(&chain);
}

static void test_token_proto(void) {
    gds_buf msg = {0}, uri = {(uint8_t *)(uintptr_t)TOKEN_URI, strlen(TOKEN_URI)};
    gds_sigp_request m;
    CHECK(gds_sigp_encode_token(GDS_SIGP_TOKEN_CHAIN, &uri, &msg) == GDS_OK);
    CHECK(gds_sigp_decode(msg.data, msg.len, &m) == GDS_OK && m.op == GDS_SIGP_TOKEN_CHAIN &&
          m.data.len == strlen(TOKEN_URI) && strcmp((const char *)m.data.data, TOKEN_URI) == 0);
    gds_sigp_request_clear(&m);
    msg.data[GDS_SIGP_HEADER + 2 + 3] = 0; /* a NUL inside the URI */
    CHECK(gds_sigp_decode(msg.data, msg.len, &m) == GDS_EINVAL);
    for(size_t n = 0; n < msg.len; n++)
        CHECK(gds_sigp_decode(msg.data, n, &m) != GDS_OK);
    gds_buf_free(&msg);
    gds_buf empty = {(uint8_t *)(uintptr_t)"", 0};
    CHECK(gds_sigp_encode_token(GDS_SIGP_TOKEN_SIGN, &empty, &msg) == GDS_EINVAL && !msg.data);
    CHECK(gds_sigp_encode_token(GDS_SIGP_GET_CHAIN, &uri, &msg) == GDS_EINVAL && !msg.data);
    CHECK(gds_sigp_encode_request(GDS_SIGP_TOKEN_SIGN, NULL, &msg) == GDS_EINVAL && !msg.data);
    static uint8_t big[GDS_CA_MAX_JWS_INPUT + 1];
    gds_buf tooBig = {big, sizeof(big)};
    CHECK(gds_sigp_encode_token(GDS_SIGP_TOKEN_SIGN, &tooBig, &msg) == GDS_EINVAL && !msg.data);
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);
    char tokenFile[1100];
    CHECK(gds_path(tokenFile, sizeof(tokenFile), "%s/token/token.der", caDir) == GDS_OK);
    (void)unlink(tokenFile); /* a fresh token certificate each run */

    gds_store *w = NULL;
    if(!CHECK(gds_store_open(db, &w) == GDS_OK) || !w)
        return CHECK_DONE();
    UA_Guid appId, reqId;
    seed_store(w, &appId, &reqId);

    char jpath[1100];
    CHECK(gds_path(jpath, sizeof(jpath), "%s/" GDS_JOURNAL_FILE, caDir) == GDS_OK);
    (void)unlink(jpath);
    gds_signer s = {NULL, open_direct_ca(caDir), NULL, false};
    CHECK(gds_store_open_readonly(db, &s.store) == GDS_OK);
    CHECK(gds_journal_open(jpath, &s.journal) == GDS_OK);
    gds_journal *second = NULL;
    CHECK(gds_journal_open(jpath, &second) == GDS_EEXISTS); /* one signer per journal */
    int sv[2];
    if(!CHECK(s.store && s.ca && socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) == 0))
        return CHECK_DONE();
    serve_arg arg = {&s, sv[1], GDS_EIO};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, serve_thread, &arg) == 0);
    gds_ca *ipc = NULL;
    CHECK(gds_ca_ipc_open(sv[0], 10000, &ipc) == GDS_OK);
    if(ipc) {
        gds_ca_issued issued;
        memset(&issued, 0, sizeof(issued));
        test_ipc_sign(ipc, w, &reqId, &issued);
        test_ipc_get(ipc, s.ca);
        if(issued.der.data)
            test_ipc_revoke(ipc, w, &appId, &issued);
        gds_ca_issued_clear(&issued);
        test_ipc_key_pair(ipc, w, &appId);
        test_ipc_token(ipc, s.ca, &s, caDir);
    }
    gds_ca_close(ipc); /* closes sv[0]: the signer sees EOF */
    CHECK(pthread_join(th, NULL) == 0);
    CHECK(arg.result == GDS_OK);
    close(sv[1]);

    test_journal(jpath, &reqId);
    test_malformed(&s, &reqId);
    test_revoke_proto();
    test_key_pair_proto();
    test_issuer_proto();
    test_jws_input();
    test_token_proto();
    gds_journal_close(s.journal);
    gds_ca_close(s.ca);
    gds_store_close(s.store);
    gds_store_close(w);
    return CHECK_DONE();
}
