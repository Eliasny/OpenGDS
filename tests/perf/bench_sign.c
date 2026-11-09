/* OpenGDS performance test: certificate issuance on the CSR path against
 * the bare OpenSSL signature (OpenGDS plan, "Performance design and
 * targets": RSA-2048 issuance "bound by OpenSSL signing; within 10% of
 * openssl speed on the same box").
 *
 * For each issuer (RSA, 3072-bit CA key by default; NIST P-256) issuing
 * for an RSA-2048 / P-256 CSR it measures, single-threaded like
 * `openssl speed`:
 *   raw: EVP_PKEY_sign of a SHA-256 digest with a key of the CA key type
 *        and size, the
 *        operation `openssl speed rsa3072` / `ecdsap256` times;
 *   ca:  gds_ca_sign_csr through the CA slot with the built-in OpenSSL
 *        backend: CSR parse and proof-of-possession check, certificate
 *        built from the record, signed, serial and validity returned.
 * The CA backend is the one opengds-signer runs; the IPC hop and the
 * signer's journal are measured end to end by load_pull.
 *
 * Usage: bench_sign --dir WORK [--seconds 5]
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "ca.h"
#include "common/buf.h"
#include "common/banned.h"

/* The thread's own CPU time: on a shared or virtual host the wall clock
 * also counts time the thread was not running (other tenants, steal),
 * which differs between two measures taken one after the other. */
static uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

#define ROUND_NS 250000000u /* one measure: a quarter second of CPU time */

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static double median(double *v, size_t n) {
    qsort(v, n, sizeof(*v), cmp_double);
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
}

static void result(const char *name, double v, const char *unit) {
    printf("RESULT %s %.3f %s\n", name, v, unit);
    fflush(stdout);
}

/* Signatures per second of a SHA-256 digest with key, for `seconds` */
static double raw_rate(EVP_PKEY *key, bool rsa, uint64_t ns) {
    unsigned char dgst[32], sig[512];
    memset(dgst, 0x5a, sizeof(dgst));
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if(!ctx || EVP_PKEY_sign_init(ctx) != 1 ||
       (rsa && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) ||
       EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    uint64_t start = now_ns(), end = start + ns, t = start;
    unsigned long n = 0;
    while(t < end) {
        size_t len = sizeof(sig);
        if(EVP_PKEY_sign(ctx, sig, &len, dgst, sizeof(dgst)) != 1)
            break;
        n++;
        t = now_ns();
    }
    EVP_PKEY_CTX_free(ctx);
    return (double)n / ((double)(t - start) / 1e9);
}

static bool csr_for(EVP_PKEY *key, gds_buf *out) {
    X509_REQ *req = X509_REQ_new();
    X509_NAME *n = X509_NAME_new();
    bool ok = req && n &&
              X509_NAME_add_entry_by_NID(n, NID_commonName, MBSTRING_UTF8,
                                         (const unsigned char *)"perf", -1, -1, 0) == 1 &&
              X509_REQ_set_subject_name(req, n) == 1 && X509_REQ_set_pubkey(req, key) == 1 &&
              X509_REQ_sign(req, key, EVP_sha256()) > 0;
    int len = ok ? i2d_X509_REQ(req, NULL) : -1;
    out->data = len > 0 ? malloc((size_t)len) : NULL;
    unsigned char *p = out->data;
    ok = out->data && i2d_X509_REQ(req, &p) == len;
    out->len = ok ? (size_t)len : 0;
    X509_NAME_free(n);
    X509_REQ_free(req);
    return ok;
}

/* gds_ca_sign_csr per second for `seconds` */
static double ca_rate(gds_ca *ca, UA_UInt32 certType, EVP_PKEY *leafKey, uint64_t ns) {
    gds_buf csr = {0};
    if(!csr_for(leafKey, &csr))
        return 0;
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "OpenGDS perf server");
    UA_String url = UA_STRING("opc.tcp://perf.example:4840");
    rec.applicationUri = UA_STRING("urn:opengds:perf:server");
    rec.applicationType = UA_APPLICATIONTYPE_SERVER;
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    rec.discoveryUrls = &url;
    rec.discoveryUrlsSize = 1;
    UA_Guid reqId = {0x0bedc0de, 1, 2, {1, 2, 3, 4, 5, 6, 7, 8}};
    gds_ca_subject subj = {&reqId, &rec, 615 /* DefaultApplicationGroup */, certType};
    uint64_t start = now_ns(), end = start + ns, t = start;
    unsigned long n = 0;
    while(t < end) {
        gds_ca_issued out;
        memset(&out, 0, sizeof(out));
        gds_status s = gds_ca_sign_csr(ca, &subj, &csr, &out);
        gds_ca_issued_clear(&out);
        if(s != GDS_OK) {
            fprintf(stderr, "bench_sign: gds_ca_sign_csr: %s\n", gds_status_name(s));
            n = 0;
            break;
        }
        n++;
        t = now_ns();
    }
    gds_buf_free(&csr);
    return (double)n / ((double)(t - start) / 1e9);
}

typedef struct {
    const char *name; /* in the RESULT names */
    bool rsa;
    UA_UInt32 certType;
    EVP_PKEY *caKey; /* the raw baseline's key: the CA key's type and size */
    EVP_PKEY *leaf;
} issuer_bench;

/* Raw and CA measures alternate in short rounds, so that a change in the
 * host's speed hits both alike; the ratio is the median of the rounds'
 * ratios. False when a measure failed. */
static bool measure(gds_ca *ca, const issuer_bench *b, unsigned rounds) {
    double *ratio = calloc(rounds, sizeof(double));
    double raw = 0, issued = 0;
    bool ok = ratio != NULL;
    for(unsigned i = 0; ok && i < rounds; i++) {
        double r = raw_rate(b->caKey, b->rsa, ROUND_NS);
        double c = ca_rate(ca, b->certType, b->leaf, ROUND_NS);
        ok = r > 0 && c > 0;
        raw += r / rounds;
        issued += c / rounds;
        ratio[i] = ok ? c / r : 0;
    }
    char n[64];
    (void)snprintf(n, sizeof(n), "sign_raw_%s_cakey", b->name);
    result(n, raw, "sign/s");
    (void)snprintf(n, sizeof(n), "sign_ca_%s", b->name);
    result(n, issued, "cert/s");
    (void)snprintf(n, sizeof(n), "sign_ca_%s_vs_raw", b->name);
    result(n, ok ? 100.0 * median(ratio, rounds) : 0, "%");
    free(ratio);
    return ok;
}

int main(int argc, char **argv) {
    const char *dir = NULL;
    unsigned seconds = 5;
    for(int i = 1; i + 1 < argc; i += 2) {
        if(strcmp(argv[i], "--dir") == 0) {
            dir = argv[i + 1];
        } else if(strcmp(argv[i], "--seconds") == 0) {
            char *e = NULL;
            errno = 0;
            unsigned long v = strtoul(argv[i + 1], &e, 10);
            if(errno || !e || *e || v == 0 || v > 3600)
                return 2;
            seconds = (unsigned)v;
        } else {
            fprintf(stderr, "bench_sign: unknown option %s\n", argv[i]);
            return 2;
        }
    }
    if(!dir || argc % 2 == 0) {
        fprintf(stderr, "usage: bench_sign --dir WORK [--seconds N]\n");
        return 2;
    }
    if(mkdir(dir, 0700) != 0 && errno != EEXIST)
        return 1;
    gds_buf pass = {(uint8_t *)(uintptr_t)"bench-sign-passphrase", 21};
    gds_ca_config cfg;
    gds_ca_config_init(&cfg);
    cfg.dir = dir;
    cfg.caSubjectCN = "OpenGDS perf CA";
    cfg.organization = "OpenGDS perf";
    cfg.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    gds_status s = gds_ca_openssl_open(&cfg, &ca);
    if(s != GDS_OK) {
        fprintf(stderr, "bench_sign: open CA in %s: %s\n", dir, gds_status_name(s));
        return 1;
    }
    /* The raw baseline signs with a key of the issuer's type and size: the
     * cost of an RSA private-key operation depends only on the modulus
     * size (cfg.caKeyBits), and of ECDSA only on the curve. */
    printf("# CA key RSA-%u, leaf CSR RSA-2048; single thread, %u s of CPU time per "
           "measure in 0.25 s rounds\n",
           cfg.caKeyBits, seconds);
    EVP_PKEY *rsaCa = EVP_RSA_gen(cfg.caKeyBits);
    EVP_PKEY *ecCa = EVP_EC_gen("P-256");
    EVP_PKEY *rsaLeaf = EVP_RSA_gen(2048);
    EVP_PKEY *ecLeaf = EVP_EC_gen("P-256");
    int rc = 1;
    if(rsaCa && ecCa && rsaLeaf && ecLeaf) {
        const issuer_bench rsa = {"rsa", true, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE, rsaCa,
                                  rsaLeaf};
        const issuer_bench ec = {"p256", false, UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE, ecCa,
                                 ecLeaf};
        rc = measure(ca, &rsa, seconds * 4) && measure(ca, &ec, seconds * 4) ? 0 : 1;
    }
    EVP_PKEY_free(rsaCa);
    EVP_PKEY_free(ecCa);
    EVP_PKEY_free(rsaLeaf);
    EVP_PKEY_free(ecLeaf);
    gds_ca_close(ca);
    return rc;
}
