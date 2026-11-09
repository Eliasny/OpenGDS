/* OpenGDS unit test: gds_signer_main with an embedder's store (UASM ask
 * A21). A child process runs the signer program with hooks and no --store;
 * it can sign only if the hook's store was used.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ca.h"
#include "ca_ipc.h"
#include "check.h"
#include "common/buf.h"
#include "common/ids.h"
#include "journal.h"
#include "signer_main.h"
#include "store.h"
#include "common/banned.h"

#define STORED_URI "urn:opengds:test:hooked"
#define PASSPHRASE "signer-hooks-test-passphrase"

static char db[1024], caDir[1024], passFile[1024];

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

static void seed_store(gds_store *w, UA_Guid *reqId, const char *uri) {
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "Hooked Client");
    rec.applicationUri = UA_STRING((char *)(uintptr_t)uri);
    rec.applicationType = UA_APPLICATIONTYPE_CLIENT;
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    UA_Guid appId;
    CHECK(gds_guid_random(&appId) == GDS_OK && gds_guid_random(reqId) == GDS_OK);
    CHECK(gds_store_app_insert(w, &appId, &rec) == GDS_OK);
    gds_request q;
    memset(&q, 0, sizeof(q));
    q.id = *reqId;
    q.appId = appId;
    q.groupId = 615;
    q.certType = UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE;
    q.state = GDS_REQ_RECEIVED;
    CHECK(make_csr(&q.csr) == GDS_OK);
    CHECK(gds_store_req_insert(w, &q) == GDS_OK);
    gds_buf_free(&q.csr);
}

/* The embedder's store: a backend in front of the SQLite file, as UASM's
 * is in front of its store service. While the file `dead` exists it
 * answers GDS_EIO, as a backend whose service connection broke. */
static char deadFile[1100];

static gds_store *inner(void *ctx) {
    return ctx;
}
static bool dead(void) {
    return access(deadFile, F_OK) == 0;
}
static void be_close(void *ctx) {
    gds_store_close(inner(ctx));
}
static int be_version(void *ctx) {
    (void)ctx;
    return 1;
}
static gds_status be_app_insert(void *ctx, const UA_Guid *id,
                                const UA_ApplicationRecordDataType *rec) {
    (void)ctx, (void)id, (void)rec;
    return GDS_EDENIED; /* the signer only reads */
}
static gds_status be_app_get(void *ctx, const UA_Guid *id, UA_ApplicationRecordDataType *out) {
    return dead() ? GDS_EIO : gds_store_app_get(inner(ctx), id, out);
}
static gds_status be_app_find_uri(void *ctx, const UA_String *uri, size_t max,
                                  UA_ApplicationRecordDataType **out, size_t *n) {
    return dead() ? GDS_EIO : gds_store_app_find_uri(inner(ctx), uri, max, out, n);
}
static gds_status be_app_update(void *ctx, const UA_Guid *id,
                                const UA_ApplicationRecordDataType *rec) {
    (void)ctx, (void)id, (void)rec;
    return GDS_EDENIED;
}
static gds_status be_app_delete(void *ctx, const UA_Guid *id) {
    (void)ctx, (void)id;
    return GDS_EDENIED;
}
static gds_status be_app_scan(void *ctx, int64_t from, gds_store_scan_cb cb, void *cbCtx) {
    return dead() ? GDS_EIO : gds_store_app_scan(inner(ctx), from, cb, cbCtx);
}
static gds_status be_req_insert(void *ctx, const gds_request *q) {
    (void)ctx, (void)q;
    return GDS_EDENIED;
}
static gds_status be_req_get(void *ctx, const UA_Guid *id, gds_request *out) {
    return dead() ? GDS_EIO : gds_store_req_get(inner(ctx), id, out);
}
static gds_status be_req_next(void *ctx, gds_request *out) {
    return dead() ? GDS_EIO : gds_store_req_next_received(inner(ctx), out);
}
static gds_status be_req_set_state(void *ctx, const UA_Guid *id, gds_req_state st,
                                   const gds_buf *cert, UA_StatusCode err) {
    (void)ctx, (void)id, (void)st, (void)cert, (void)err;
    return GDS_EDENIED;
}
static gds_status be_cert_add(void *ctx, const UA_Guid *appId, uint32_t g, uint32_t ty,
                              const gds_buf *serial, const gds_buf *der, int64_t nb, int64_t na) {
    (void)ctx, (void)appId, (void)g, (void)ty, (void)serial, (void)der, (void)nb, (void)na;
    return GDS_EDENIED;
}
static gds_status be_cert_latest(void *ctx, const UA_Guid *appId, uint32_t g, uint32_t ty,
                                 gds_buf *der, int64_t *na) {
    return dead() ? GDS_EIO : gds_store_cert_latest(inner(ctx), appId, g, ty, der, na);
}
static gds_status be_cert_is_revoked(void *ctx, const gds_buf *serial, bool *revoked) {
    return dead() ? GDS_EIO : gds_store_cert_is_revoked(inner(ctx), serial, revoked);
}

static const gds_store_backend BACKEND = {
    GDS_STORE_ABI_MAJOR, 3, offsetof(gds_store_backend, cert_scan),
    be_close, be_version, be_app_insert, be_app_get, be_app_find_uri, be_app_update,
    be_app_delete, be_app_scan, be_req_insert, be_req_get, be_req_next, be_req_set_state,
    be_cert_add, be_cert_latest,
    NULL, NULL, /* no audit log */
    NULL,       /* no req_scan */
    NULL, NULL, be_cert_is_revoked,
    NULL,
    NULL, NULL, /* no trust lists */
    NULL, NULL, NULL, /* no push targets */
    NULL,             /* no cert_issue */
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* no KeyCredentials */
};

static gds_status hook_open(void *ctx, gds_store **out) {
    gds_store *sq = NULL;
    gds_status r = gds_store_open_readonly(ctx, &sq);
    return r == GDS_OK ? gds_store_open_backend(&BACKEND, sq, out) : r;
}

static gds_status hook_fail(void *ctx, gds_store **out) {
    (void)ctx, (void)out;
    return GDS_EIO;
}

static const char *const EXTRA[] = {"/nonexistent-is-fine-under-asan"};

static gds_signer_hooks hooks_of(gds_status (*fn)(void *, gds_store **)) {
    gds_signer_hooks h;
    memset(&h, 0, sizeof(h));
    h.abi_major = GDS_SIGNER_HOOKS_ABI_MAJOR;
    h.abi_minor = GDS_SIGNER_HOOKS_ABI_MINOR;
    h.struct_size = sizeof(h);
    h.open_store = fn;
    h.ctx = db;
    return h;
}

/* Runs gds_signer_main in a child; its exit status, or -1. */
static int run_child(char **argv, const gds_signer_hooks *h, int closeFd) {
    pid_t pid = fork();
    if(pid == 0) {
        if(closeFd >= 0)
            (void)close(closeFd);
        int argc = 0;
        while(argv[argc])
            argc++;
        _exit(gds_signer_main(argc, argv, h));
    }
    return pid;
}

static int wait_child(pid_t pid) {
    int st = 0;
    if(pid <= 0 || waitpid(pid, &st, 0) != pid || !WIFEXITED(st))
        return -1;
    return WEXITSTATUS(st);
}

static void test_refusals(void) {
    char *withStore[] = {"signer", "--fd", "0", "--store", db, "--ca-dir", caDir, NULL};
    gds_signer_hooks h = hooks_of(hook_open);
    CHECK_EQ_INT(wait_child(run_child(withStore, &h, -1)), 2); /* --store with hooks */
    char *noStore[] = {"signer", "--fd", "0", "--ca-dir", caDir, NULL};
    CHECK_EQ_INT(wait_child(run_child(noStore, NULL, -1)), 2); /* no hooks, no --store */
    gds_signer_hooks bad = h;
    bad.abi_major = 99;
    CHECK_EQ_INT(wait_child(run_child(noStore, &bad, -1)), 2);
    bad = h;
    bad.open_store = NULL;
    CHECK_EQ_INT(wait_child(run_child(noStore, &bad, -1)), 2);
    bad = h;
    bad.nPaths = GDS_SIGNER_MAX_HOOK_PATHS + 1;
    bad.paths = EXTRA;
    CHECK_EQ_INT(wait_child(run_child(noStore, &bad, -1)), 2);
}

/* A store the hook cannot open: the signer exits 1 before serving. */
static void test_hook_fails(void) {
    int sv[2];
    if(!CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) == 0))
        return;
    char fd[16];
    CHECK(snprintf(fd, sizeof(fd), "%d", sv[1]) > 0);
    char *args[] = {"signer", "--fd", fd, "--ca-dir", caDir, "--passphrase-file", passFile, NULL};
    gds_signer_hooks h = hooks_of(hook_fail);
    pid_t pid = run_child(args, &h, sv[0]);
    CHECK_EQ_INT(wait_child(pid), 1);
    (void)close(sv[0]);
    (void)close(sv[1]);
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

static void test_signs(const UA_Guid *reqId, const UA_Guid *reqId2) {
    int sv[2];
    if(!CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0))
        return;
    char fd[16];
    CHECK(snprintf(fd, sizeof(fd), "%d", sv[1]) > 0);
    char *args[] = {"signer", "--fd", fd, "--ca-dir", caDir, "--passphrase-file", passFile, NULL};
    gds_signer_hooks h = hooks_of(hook_open);
    h.paths = EXTRA;
    h.nPaths = 1;
    pid_t pid = run_child(args, &h, sv[0]);
    (void)close(sv[1]);
    gds_ca *ipc = NULL;
    CHECK(gds_ca_ipc_open(sv[0], 20000, &ipc) == GDS_OK);
    if(ipc) {
        UA_ApplicationRecordDataType lie;
        UA_ApplicationRecordDataType_init(&lie);
        lie.applicationUri = UA_STRING("urn:not:the:stored:one");
        uint8_t junk[] = {1, 2, 3};
        gds_buf junkCsr = {junk, sizeof(junk)};
        gds_ca_subject subj = {reqId, &lie, 1, 1};
        gds_ca_issued out;
        memset(&out, 0, sizeof(out));
        CHECK(gds_ca_sign_csr(ipc, &subj, &junkCsr, &out) == GDS_OK);
        CHECK(out.der.len > 0 && cert_has_uri(&out.der, STORED_URI));
        gds_ca_issued_clear(&out);
        /* the store's service goes away: refused, then the signer exits */
        CHECK(gds_file_write_atomic(deadFile, "x", 1, 0600) == GDS_OK);
        subj.requestId = reqId2;
        CHECK(gds_ca_sign_csr(ipc, &subj, &junkCsr, &out) == GDS_EIO);
        gds_ca_issued_clear(&out);
        CHECK_EQ_INT(wait_child(pid), 1);
        pid = -1;
        gds_ca_close(ipc);
    } else {
        (void)close(sv[0]);
    }
    if(pid > 0)
        CHECK_EQ_INT(wait_child(pid), 0);
    (void)unlink(deadFile);
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    CHECK(gds_path(passFile, sizeof(passFile), "%s/pass", argv[1]) == GDS_OK);
    (void)unlink(db);
    CHECK(gds_path(deadFile, sizeof(deadFile), "%s/dead", argv[1]) == GDS_OK);
    (void)unlink(deadFile);
    char jpath[1100];
    CHECK(gds_path(jpath, sizeof(jpath), "%s/" GDS_JOURNAL_FILE, caDir) == GDS_OK);
    (void)unlink(jpath);
    CHECK(gds_file_write_atomic(passFile, PASSPHRASE, strlen(PASSPHRASE), 0600) == GDS_OK);

    /* the CA, created once by opengdsd's side */
    gds_buf pass = {(uint8_t *)(uintptr_t)PASSPHRASE, strlen(PASSPHRASE)};
    gds_ca_config cfg;
    gds_ca_config_init(&cfg);
    cfg.dir = caDir;
    cfg.caKeyBits = 2048;
    cfg.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    CHECK(gds_ca_openssl_open(&cfg, &ca) == GDS_OK);
    gds_ca_close(ca);

    gds_store *w = NULL;
    if(!CHECK(gds_store_open(db, &w) == GDS_OK) || !w)
        return CHECK_DONE();
    UA_Guid reqId, reqId2;
    seed_store(w, &reqId, STORED_URI);
    seed_store(w, &reqId2, STORED_URI "2");

    test_refusals();
    test_hook_fails();
    test_signs(&reqId, &reqId2);
    gds_store_close(w);
    return CHECK_DONE();
}
