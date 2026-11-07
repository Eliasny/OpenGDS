/* OpenGDS unit test: opengds-signer core, protocol and the ca_ipc client.
 * The signer must sign only what the store holds: the record and CSR that
 * opengdsd passes are ignored (decision G1).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <openssl/evp.h>
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
    }
    gds_ca_close(ipc); /* closes sv[0]: the signer sees EOF */
    CHECK(pthread_join(th, NULL) == 0);
    CHECK(arg.result == GDS_OK);
    close(sv[1]);

    test_journal(jpath, &reqId);
    test_malformed(&s, &reqId);
    test_revoke_proto();
    gds_journal_close(s.journal);
    gds_ca_close(s.ca);
    gds_store_close(s.store);
    gds_store_close(w);
    return CHECK_DONE();
}
