/* OpenGDS performance tests - shared helpers (perf_common.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "perf_common.h"

#include <open62541/client_highlevel.h>
#include <open62541/nodeids.h>
#include <open62541/nodeids_gds.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/limits.h"
#include "common/ua_args.h"
#include "client/gdsc_gds.h"
#include "common/banned.h"

uint64_t perf_now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

void perf_result(const char *name, double value, const char *unit) {
    printf("RESULT %s %.3f %s\n", name, value, unit);
    fflush(stdout);
}

unsigned long perf_arg_ul(const char *opt, const char *v) {
    char *end = NULL;
    errno = 0;
    unsigned long n = v ? strtoul(v, &end, 10) : 0;
    if(!v || !*v || errno != 0 || !end || *end != '\0') {
        fprintf(stderr, "%s: not a number: %s\n", opt, v ? v : "(missing)");
        exit(2);
    }
    return n;
}

/* ---- samples ---- */

void perf_samples_init(perf_samples *s) {
    memset(s, 0, sizeof(*s));
    pthread_mutex_init(&s->lock, NULL);
}

void perf_samples_add(perf_samples *s, uint64_t ns) {
    pthread_mutex_lock(&s->lock);
    if(s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 1024;
        uint64_t *v = realloc(s->v, cap * sizeof(*v));
        if(!v) {
            pthread_mutex_unlock(&s->lock);
            return;
        }
        s->v = v;
        s->cap = cap;
    }
    s->v[s->n++] = ns;
    pthread_mutex_unlock(&s->lock);
}

void perf_samples_free(perf_samples *s) {
    free(s->v);
    pthread_mutex_destroy(&s->lock);
    memset(s, 0, sizeof(*s));
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static double pct(const perf_samples *s, double p) {
    size_t i = (size_t)(p * (double)(s->n - 1) + 0.5);
    return (double)s->v[i] / 1e6;
}

void perf_samples_report(perf_samples *s, const char *name) {
    char n[128];
    if(s->n == 0)
        return;
    qsort(s->v, s->n, sizeof(*s->v), cmp_u64);
    static const struct {
        const char *suffix;
        double p;
    } ps[] = {{"p50", 0.50}, {"p95", 0.95}, {"p99", 0.99}, {"max", 1.0}};
    for(size_t i = 0; i < sizeof(ps) / sizeof(ps[0]); i++) {
        if(gds_path(n, sizeof(n), "%s_%s_ms", name, ps[i].suffix) == GDS_OK)
            perf_result(n, pct(s, ps[i].p), "ms");
    }
}

/* ---- errors ---- */

void perf_errors_init(perf_errors *e) {
    memset(e, 0, sizeof(*e));
    pthread_mutex_init(&e->lock, NULL);
}

void perf_errors_add(perf_errors *e, UA_StatusCode c) {
    pthread_mutex_lock(&e->lock);
    size_t i = 0;
    for(; i < PERF_MAX_CODES && e->count[i] && e->code[i] != c; i++)
        ;
    if(i == PERF_MAX_CODES) {
        e->other++;
    } else {
        e->code[i] = c;
        e->count[i]++;
    }
    pthread_mutex_unlock(&e->lock);
}

unsigned long perf_errors_total(perf_errors *e) {
    pthread_mutex_lock(&e->lock);
    unsigned long t = e->other;
    for(size_t i = 0; i < PERF_MAX_CODES; i++)
        t += e->count[i];
    pthread_mutex_unlock(&e->lock);
    return t;
}

void perf_errors_report(perf_errors *e, const char *what) {
    pthread_mutex_lock(&e->lock);
    for(size_t i = 0; i < PERF_MAX_CODES && e->count[i]; i++)
        printf("ERRORS %s %s %lu\n", what, UA_StatusCode_name(e->code[i]), e->count[i]);
    if(e->other)
        printf("ERRORS %s other %lu\n", what, e->other);
    pthread_mutex_unlock(&e->lock);
    fflush(stdout);
}

/* ---- GDS sessions ---- */

bool perf_gds_opt(perf_gds *g, const char *opt, const char *v) {
    static const struct {
        const char *name;
        size_t off;
    } opts[] = {
        {"--gds", offsetof(perf_gds, url)},          {"--cert", offsetof(perf_gds, certFile)},
        {"--key", offsetof(perf_gds, keyFile)},      {"--trust", offsetof(perf_gds, trustFile)},
        {"--crl", offsetof(perf_gds, crlFile)},      {"--user", offsetof(perf_gds, user)},
        {"--password-file", offsetof(perf_gds, passwordFile)},
    };
    for(size_t i = 0; i < sizeof(opts) / sizeof(opts[0]); i++) {
        if(strcmp(opt, opts[i].name) == 0) {
            memcpy((char *)g + opts[i].off, &v, sizeof(v));
            return true;
        }
    }
    return false;
}

static void must_read(const char *what, const char *path, size_t max, gds_buf *out) {
    if(!path) {
        fprintf(stderr, "missing %s\n", what);
        exit(2);
    }
    if(gds_file_read(path, max, out) != GDS_OK) {
        fprintf(stderr, "cannot read %s %s\n", what, path);
        exit(2);
    }
}

void perf_gds_load(perf_gds *g) {
    if(!g->url || !g->user) {
        fprintf(stderr, "missing --gds or --user\n");
        exit(2);
    }
    must_read("--cert", g->certFile, GDS_MAX_CERT_SIZE, &g->cert);
    must_read("--key", g->keyFile, GDS_MAX_KEY_SIZE, &g->key);
    must_read("--trust", g->trustFile, GDS_MAX_CERT_SIZE, &g->trust);
    if(g->crlFile)
        must_read("--crl", g->crlFile, GDS_MAX_CRL_SIZE, &g->crl);
    must_read("--password-file", g->passwordFile, GDS_MAX_STRING, &g->password);
    while(g->password.len &&
          (g->password.data[g->password.len - 1] == '\n' || g->password.data[g->password.len - 1] == '\r'))
        g->password.len--;
}

void perf_gds_clear(perf_gds *g) {
    gds_buf_free(&g->cert);
    gds_buf_free_secret(&g->key);
    gds_buf_free(&g->trust);
    gds_buf_free(&g->crl);
    gds_buf_free_secret(&g->password);
}

/* gdsc_gds_bind writes the process-wide GDS DataType table */
static pthread_mutex_t bindLock = PTHREAD_MUTEX_INITIALIZER;

UA_StatusCode perf_gds_open(const perf_gds *g, gdsc_session **out, UA_UInt16 *ns) {
    gdsc_session_cfg c;
    memset(&c, 0, sizeof(c));
    c.endpointUrl = g->url;
    c.cert = &g->cert;
    c.key = &g->key;
    c.trust = &g->trust;
    c.trustN = 1;
    c.crls = g->crl.data ? &g->crl : NULL;
    c.crlN = g->crl.data ? 1 : 0;
    c.identity = GDSC_IDENTITY_USERNAME;
    c.userName = g->user;
    c.password = &g->password;
    c.timeoutMs = 60000;
    UA_StatusCode r = gdsc_session_open(&c, out);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    pthread_mutex_lock(&bindLock);
    r = gdsc_gds_bind(gdsc_session_client(*out), ns);
    pthread_mutex_unlock(&bindLock);
    if(r != UA_STATUSCODE_GOOD) {
        gdsc_session_close(*out);
        *out = NULL;
    }
    return r;
}

/* ---- records, CSRs, signing ---- */

void perf_record(UA_ApplicationRecordDataType *rec, UA_LocalizedText *name, UA_String *uri,
                 UA_String *product, const char *uriText, UA_ApplicationType type,
                 UA_String *discoveryUrl) {
    UA_ApplicationRecordDataType_init(rec);
    *uri = UA_STRING((char *)(uintptr_t)uriText);
    *product = UA_STRING("urn:opengds:perf:product");
    *name = UA_LOCALIZEDTEXT("en", "OpenGDS perf application");
    rec->applicationUri = *uri;
    rec->productUri = *product;
    rec->applicationType = type;
    rec->applicationNames = name;
    rec->applicationNamesSize = 1;
    if(discoveryUrl) {
        rec->discoveryUrls = discoveryUrl;
        rec->discoveryUrlsSize = 1;
    }
}

bool perf_make_csr(const char *appUri, gds_buf *csrOut) {
    memset(csrOut, 0, sizeof(*csrOut));
    EVP_PKEY *key = EVP_RSA_gen(2048);
    X509_REQ *req = X509_REQ_new();
    X509_NAME *n = X509_NAME_new();
    bool ok = false;
    if(key && req && n &&
       X509_NAME_add_entry_by_NID(n, NID_commonName, MBSTRING_UTF8,
                                  (const unsigned char *)"OpenGDS perf", -1, -1, 0) == 1 &&
       X509_REQ_set_subject_name(req, n) == 1 && X509_REQ_set_pubkey(req, key) == 1) {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        char san[GDS_MAX_APPLICATION_URI + 8];
        STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
        X509_EXTENSION *e = NULL;
        if(exts && gds_path(san, sizeof(san), "URI:%s", appUri) == GDS_OK)
            e = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
        if(e && sk_X509_EXTENSION_push(exts, e) > 0) {
            e = NULL;
            ok = X509_REQ_add_extensions(req, exts) == 1 && X509_REQ_sign(req, key, EVP_sha256()) > 0;
        }
        X509_EXTENSION_free(e);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
    if(ok) {
        int len = i2d_X509_REQ(req, NULL);
        csrOut->data = len > 0 ? malloc((size_t)len) : NULL;
        unsigned char *p = csrOut->data;
        ok = csrOut->data && i2d_X509_REQ(req, &p) == len;
        csrOut->len = ok ? (size_t)len : 0;
    }
    X509_NAME_free(n);
    X509_REQ_free(req);
    EVP_PKEY_free(key);
    return ok;
}

static UA_StatusCode call(UA_Client *c, UA_UInt16 ns, UA_UInt32 method, size_t inN,
                          const UA_Variant *in, size_t *outN, UA_Variant **out) {
    *out = NULL;
    *outN = 0;
    return UA_Client_call(c, UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY),
                          UA_NODEID_NUMERIC(ns, method), inN, in, outN, out);
}

UA_StatusCode perf_sign(UA_Client *c, UA_UInt16 ns, const UA_NodeId *appId, const gds_buf *csr,
                        unsigned pollMs, unsigned timeoutMs, gds_buf *certOut) {
    memset(certOut, 0, sizeof(*certOut));
    UA_NodeId group = gdsc_gds_default_group(ns);
    UA_NodeId type = UA_NODEID_NUMERIC(0, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
    UA_ByteString csrBs = {csr->len, csr->data};
    UA_Variant in[4], *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[3], &csrBs, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_StatusCode r = call(c, ns, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, 4, in, &outN, &out);
    UA_NodeId reqId;
    UA_NodeId_init(&reqId);
    if(r == UA_STATUSCODE_GOOD) {
        if(outN < 1 || !UA_Variant_hasScalarType(&out[0], &UA_TYPES[UA_TYPES_NODEID]))
            r = UA_STATUSCODE_BADUNEXPECTEDERROR;
        else
            r = UA_NodeId_copy(out[0].data, &reqId);
    }
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Variant_setScalar(&in[1], &reqId, &UA_TYPES[UA_TYPES_NODEID]);
    uint64_t deadline = perf_now_ns() + (uint64_t)timeoutMs * 1000000u;
    const struct timespec step = {(time_t)(pollMs / 1000), (long)(pollMs % 1000) * 1000000L};
    for(;;) {
        r = call(c, ns, UA_GDSID_DIRECTORY_FINISHREQUEST, 2, in, &outN, &out);
        if(r != UA_STATUSCODE_BADNOTHINGTODO || perf_now_ns() > deadline)
            break;
        UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
        nanosleep(&step, NULL);
    }
    if(r == UA_STATUSCODE_GOOD) {
        if(outN < 1 || !UA_Variant_hasScalarType(&out[0], &UA_TYPES[UA_TYPES_BYTESTRING]))
            r = UA_STATUSCODE_BADUNEXPECTEDERROR;
        else {
            const UA_ByteString *b = out[0].data;
            if(gds_buf_dup(b->data, b->length, certOut) != GDS_OK)
                r = UA_STATUSCODE_BADOUTOFMEMORY;
        }
    }
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    UA_NodeId_clear(&reqId);
    return r;
}

unsigned long perf_rss_kib(long pid) {
    char path[64], line[256];
    if(gds_path(path, sizeof(path), "/proc/%ld/status", pid) != GDS_OK)
        return 0;
    FILE *f = fopen(path, "r");
    unsigned long kib = 0;
    while(f && fgets(line, sizeof(line), f)) {
        if(strncmp(line, "VmRSS:", 6) == 0) {
            kib = strtoul(line + 6, NULL, 10);
            break;
        }
    }
    if(f)
        fclose(f);
    return kib;
}
