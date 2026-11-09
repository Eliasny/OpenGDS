/* OpenGDS push engine - the scheduler (push_engine.h).
 *
 * Threads: one engine thread ticks (lists the targets, notes the trust
 * list, asks the scheduler slot which due jobs start) and `concurrency`
 * workers run the jobs. `lock` guards the targets, the queue and the
 * counters; no gds_server or network call is made under it, except the
 * scheduler's next_jobs, which must not block.
 * SPDX-License-Identifier: MPL-2.0 */
#include "push_engine.h"

#include <open62541/types_gds_generated.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#include "client/gdsc_push.h"
#include "client/gdsc_session.h"
#include "common/limits.h"
#include "gds_plugin.h"
#include "push_rejected.h"
#include "push_sched.h"
#include "push_workflows.h"
#include "common/banned.h"

#define DEFAULT_TICK_MS 60000u
#define DEFAULT_CONCURRENCY 4u
#define DEFAULT_BACKOFF_MIN_S 60u
#define DEFAULT_BACKOFF_MAX_S (6u * 3600u)
#define DEFAULT_TIMEOUT_MS 10000u
#define DEFAULT_SIGN_TIMEOUT_MS 60000u
#define DEFAULT_PRESENT_TIMEOUT_MS 30000u
#define MAX_ANCHORS ((size_t)64)

typedef struct {
    UA_NodeId appId;
    char uri[GDS_MAX_APPLICATION_URI + 1];
    char endpoint[GDS_MAX_PUSH_ENDPOINT];
    bool enabled;
    bool seen;     /* in the latest target list */
    bool running;  /* queued or running */
    bool removed;  /* left the list while running: freed after the job */
    uint32_t reasons; /* of the queued job */
    push_state st;
    UA_StatusCode lastResult;
    uint64_t jobs, tlPushes, certPushes, harvests;
} target;

struct push_engine {
    push_engine_cfg cfg;
    push_timing timing;
    push_rejected *rejected;
    gds_push_scheduler sched;
    UA_ByteString issuers[GDS_CA_ISSUERS]; /* views of cfg.issuers */
    size_t issuersN;
    pthread_mutex_t lock;
    pthread_cond_t tickCond, workCond;
    target **targets;
    size_t n, cap;
    target *queue[PUSH_MAX_CONCURRENCY];
    size_t queued, running;
    bool stop, kick, wasStandby;
    pthread_t tickThread;
    pthread_t workers[PUSH_MAX_CONCURRENCY];
    size_t nWorkers;
    bool tickStarted;
};

static uint64_t rnd64(void) {
    uint64_t r = 0;
    if(getrandom(&r, sizeof(r), 0) != (ssize_t)sizeof(r))
        r = (uint64_t)UA_DateTime_now(); /* never: getrandom does not fail for 8 bytes */
    return r;
}

static UA_DateTime secs(uint32_t s) {
    return (UA_DateTime)s * UA_DATETIME_SEC;
}

/* ---- certificates ---- */

static X509 *parse_cert(const UA_ByteString *der) {
    if(!der || der->length == 0 || der->length > GDS_MAX_CERT_SIZE)
        return NULL;
    const unsigned char *p = der->data;
    X509 *x = d2i_X509(NULL, &p, (long)der->length);
    if(x && p != der->data + der->length) {
        X509_free(x);
        x = NULL;
    }
    return x;
}

static bool to_datetime(const ASN1_TIME *t, UA_DateTime *out) {
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    if(!t || ASN1_TIME_to_tm(t, &tm) != 1)
        return false;
    time_t s = timegm(&tm);
    if(s == (time_t)-1)
        return false;
    *out = (UA_DateTime)s * UA_DATETIME_SEC + UA_DATETIME_UNIX_EPOCH;
    return true;
}

/* Issued (and signed) by one of the CA certificates in cas */
static bool issued_by(X509 *x, const UA_ByteString *cas, size_t n) {
    for(size_t i = 0; i < n; i++) {
        X509 *ca = parse_cert(&cas[i]);
        bool hit = false;
        if(ca && X509_check_ca(ca) && X509_check_issued(ca, x) == X509_V_OK) {
            EVP_PKEY *k = X509_get0_pubkey(ca);
            hit = k && X509_verify(x, k) == 1;
        }
        X509_free(ca);
        if(hit)
            return true;
    }
    return false;
}

/* ---- the trust list ---- */

static bool tl_hash(const UA_TrustListDataType *tl, uint8_t out[PUSH_HASH_LEN]) {
    UA_TrustListDataType t = *tl; /* shallow: only the mask differs */
    t.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    UA_ByteString enc = UA_BYTESTRING_NULL;
    if(UA_encodeBinary(&t, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &enc, NULL) !=
       UA_STATUSCODE_GOOD)
        return false;
    unsigned int n = 0;
    bool ok = EVP_Digest(enc.data, enc.length, out, &n, EVP_sha256(), NULL) == 1 &&
              n == PUSH_HASH_LEN;
    UA_ByteString_clear(&enc);
    return ok;
}

static bool same_set(const UA_ByteString *a, size_t na, const UA_ByteString *b, size_t nb) {
    if(na != nb)
        return false;
    for(size_t i = 0; i < na; i++) {
        bool found = false;
        for(size_t k = 0; !found && k < nb; k++)
            found = UA_ByteString_equal(&a[i], &b[k]);
        if(!found)
            return false;
    }
    return true;
}

/* The Server holds the same four lists (in any order) */
static bool same_lists(const UA_TrustListDataType *a, const UA_TrustListDataType *b) {
    return same_set(a->trustedCertificates, a->trustedCertificatesSize, b->trustedCertificates,
                    b->trustedCertificatesSize) &&
           same_set(a->trustedCrls, a->trustedCrlsSize, b->trustedCrls, b->trustedCrlsSize) &&
           same_set(a->issuerCertificates, a->issuerCertificatesSize, b->issuerCertificates,
                    b->issuerCertificatesSize) &&
           same_set(a->issuerCrls, a->issuerCrlsSize, b->issuerCrls, b->issuerCrlsSize);
}

/* ---- one job ---- */

typedef struct {
    UA_NodeId appId;
    char uri[GDS_MAX_APPLICATION_URI + 1];
    char endpoint[GDS_MAX_PUSH_ENDPOINT];
    uint32_t reasons;
    push_state st; /* the state when the job started */
} job_in;

typedef struct {
    UA_StatusCode result;
    bool connected;
    bool certOurs;
    UA_DateTime notBefore, notAfter;
    bool tlValid;
    uint8_t tlSent[PUSH_HASH_LEN];
    bool harvested, tlPushed, certPushed;
} job_out;

typedef struct {
    push_engine *e;
    const job_in *in;
} sign_ctx;

/* The Server's CSR, signed by the GDS CA for the target's record (decision
 * G5: every field from the record). The engine is the approver: the
 * administrator approved the target when adding it. */
static gds_status sign_cb(void *ctx, const gds_buf *csrDer, gds_buf *certOut,
                          gds_buf *issuersOut, size_t *issuersN) {
    sign_ctx *sc = ctx;
    UA_ByteString csr = {csrDer->len, csrDer->data};
    UA_ByteString cert = UA_BYTESTRING_NULL;
    UA_ByteString *iss = NULL;
    size_t nIss = 0;
    gds_status st = gds_server_sign_request(sc->e->cfg.server, PUSH_ACTOR, &sc->in->appId, NULL,
                                            NULL, &csr, sc->e->cfg.signTimeoutMs, &cert, &iss,
                                            &nIss);
    *issuersN = 0;
    if(st == GDS_OK)
        st = gds_buf_dup(cert.data, cert.length, certOut);
    for(size_t i = 0; st == GDS_OK && i < nIss && i < GDS_MAX_CHAIN_LEN; i++) {
        st = gds_buf_dup(iss[i].data, iss[i].length, &issuersOut[i]);
        if(st == GDS_OK)
            *issuersN = i + 1;
    }
    UA_ByteString_clear(&cert);
    if(iss)
        UA_Array_delete(iss, nIss, &UA_TYPES[UA_TYPES_BYTESTRING]);
    return st;
}

/* The CA certificates of the trust list vouch for the Server; every CRL
 * applies. Pointers into tl. */
static void anchors(const UA_TrustListDataType *tl, gds_buf *trust, size_t *trustN,
                    gds_buf *crls, size_t *crlN) {
    *trustN = *crlN = 0;
    const UA_ByteString *lists[2] = {tl->trustedCertificates, tl->issuerCertificates};
    size_t sizes[2] = {tl->trustedCertificatesSize, tl->issuerCertificatesSize};
    for(size_t l = 0; l < 2; l++)
        for(size_t i = 0; i < sizes[l] && *trustN < MAX_ANCHORS; i++) {
            X509 *x = parse_cert(&lists[l][i]);
            if(x && X509_check_ca(x))
                trust[(*trustN)++] = (gds_buf){lists[l][i].data, lists[l][i].length};
            X509_free(x);
        }
    const UA_ByteString *cl[2] = {tl->trustedCrls, tl->issuerCrls};
    size_t cs[2] = {tl->trustedCrlsSize, tl->issuerCrlsSize};
    for(size_t l = 0; l < 2; l++)
        for(size_t i = 0; i < cs[l] && *crlN < MAX_ANCHORS; i++)
            crls[(*crlN)++] = (gds_buf){cl[l][i].data, cl[l][i].length};
}

/* What the Server presents now */
static void look_at_cert(const push_engine *e, gdsc_session *dev, const UA_TrustListDataType *tl,
                         job_out *out) {
    gds_buf der = {0};
    if(gdsc_session_server_cert(dev, &der) != GDS_OK)
        return;
    UA_ByteString bs = {der.len, der.data};
    X509 *x = parse_cert(&bs);
    if(x && to_datetime(X509_get0_notBefore(x), &out->notBefore) &&
       to_datetime(X509_get0_notAfter(x), &out->notAfter))
        out->certOurs = e->issuersN
                            ? issued_by(x, e->issuers, e->issuersN)
                            : issued_by(x, tl->trustedCertificates, tl->trustedCertificatesSize) ||
                                  issued_by(x, tl->issuerCertificates, tl->issuerCertificatesSize);
    X509_free(x);
    gds_buf_free(&der);
}

static void harvest(push_engine *e, UA_Client *c, const job_in *in,
                    const UA_TrustListDataType *tl, job_out *out) {
    UA_ByteString *certs = NULL;
    size_t n = 0;
    UA_StatusCode r = gdsc_get_rejected_list(c, &certs, &n);
    out->harvested = true; /* also on an error: try again next period */
    if(r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "opengds: push: %s: GetRejectedList: %s\n", in->uri,
                UA_StatusCode_name(r));
        return;
    }
    size_t opened = push_rejected_offer(e->rejected, in->uri, certs, n, tl);
    if(opened)
        fprintf(stderr, "opengds: push: %s refused %zu unknown client(s): dialogs opened\n",
                in->uri, opened);
    UA_Array_delete(certs, n, &UA_TYPES[UA_TYPES_BYTESTRING]);
}

static void run_push(push_engine *e, UA_Client *c, const job_in *in, UA_TrustListDataType *tl,
                     const uint8_t cur[PUSH_HASH_LEN], bool needTl, bool needCert,
                     job_out *out) {
    sign_ctx sc = {e, in};
    push_job job;
    memset(&job, 0, sizeof(job));
    job.certificateGroup = GDSC_DEFAULT_APP_GROUP;
    job.trustListNode = GDSC_DEFAULT_APP_TRUSTLIST;
    job.certificateType = GDSC_RSA_SHA256_APP_CERT;
    job.trustList = needTl ? tl : NULL;
    job.sign = needCert ? sign_cb : NULL;
    job.signCtx = &sc;
    push_report rep;
    gds_status st = push_run(c, &job, &rep);
    if(rep.trustListUpdated && st == GDS_OK) {
        out->tlPushed = true;
        out->tlValid = true;
        memcpy(out->tlSent, cur, PUSH_HASH_LEN);
    }
    if(st != GDS_OK) {
        out->result = rep.failedCode != UA_STATUSCODE_GOOD ? rep.failedCode
                                                            : UA_STATUSCODE_BADINTERNALERROR;
        fprintf(stderr, "opengds: push: %s: %s failed: %s%s\n", in->uri,
                push_step_name(rep.failedStep), UA_StatusCode_name(out->result),
                rep.cancelled ? " (CancelChanges called)" : "");
    } else if(rep.certificateUpdated) {
        /* §7.7.2: ApplyChanges may close the endpoints; the new certificate
         * counts once the Server presents it */
        UA_StatusCode r = gdsc_wait_presents(in->endpoint, &job.certificateType, &rep.issued,
                                             e->cfg.presentTimeoutMs);
        if(r != UA_STATUSCODE_GOOD) {
            out->result = r;
            fprintf(stderr, "opengds: push: %s does not present the new certificate: %s\n",
                    in->uri, UA_StatusCode_name(r));
        } else {
            UA_ByteString bs = {rep.issued.len, rep.issued.data};
            X509 *x = parse_cert(&bs);
            if(x && to_datetime(X509_get0_notBefore(x), &out->notBefore) &&
               to_datetime(X509_get0_notAfter(x), &out->notAfter))
                out->certOurs = true;
            X509_free(x);
            out->certPushed = true;
        }
    }
    push_report_clear(&rep);
}

static void run_job(push_engine *e, const job_in *in, job_out *out) {
    memset(out, 0, sizeof(*out));
    out->result = UA_STATUSCODE_GOOD;
    out->tlValid = in->st.tlValid;
    memcpy(out->tlSent, in->st.tlSent, PUSH_HASH_LEN);
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    uint8_t cur[PUSH_HASH_LEN];
    if(gds_server_get_trust_list(e->cfg.server, NULL, &tl) != GDS_OK || !tl_hash(&tl, cur)) {
        out->result = UA_STATUSCODE_BADINTERNALERROR;
        UA_TrustListDataType_clear(&tl);
        return;
    }
    gds_buf trust[MAX_ANCHORS], crls[MAX_ANCHORS];
    size_t trustN = 0, crlN = 0;
    anchors(&tl, trust, &trustN, crls, &crlN);
    gdsc_session_cfg c;
    memset(&c, 0, sizeof(c));
    c.endpointUrl = in->endpoint;
    c.serverUri = in->uri;
    c.cert = &e->cfg.cert;
    c.key = &e->cfg.key;
    c.trust = trust;
    c.trustN = trustN;
    c.crls = crls;
    c.crlN = crlN;
    c.identity = GDSC_IDENTITY_APP_CERT; /* Annex G.3 */
    c.timeoutMs = e->cfg.timeoutMs;
    gdsc_session *dev = NULL;
    UA_StatusCode r = gdsc_session_open(&c, &dev);
    if(r != UA_STATUSCODE_GOOD) {
        out->result = r;
        fprintf(stderr, "opengds: push: %s: connect to %s: %s\n", in->uri, in->endpoint,
                UA_StatusCode_name(r));
        UA_TrustListDataType_clear(&tl);
        return;
    }
    out->connected = true;
    UA_Client *cl = gdsc_session_client(dev);
    look_at_cert(e, dev, &tl, out);
    UA_DateTime now = UA_DateTime_now();
    bool needCert = !out->certOurs || now >= push_renew_at(out->notBefore, out->notAfter);
    bool needTl = !out->tlValid || memcmp(out->tlSent, cur, PUSH_HASH_LEN) != 0;
    if(needTl && !in->st.tlValid) {
        /* nothing known: the Server may hold the list already */
        UA_TrustListDataType dev_tl;
        UA_NodeId tlNode = GDSC_DEFAULT_APP_TRUSTLIST;
        if(gdsc_trustlist_read(cl, &tlNode, &dev_tl) == UA_STATUSCODE_GOOD) {
            if(same_lists(&tl, &dev_tl)) {
                needTl = false;
                out->tlValid = true;
                memcpy(out->tlSent, cur, PUSH_HASH_LEN);
            }
            UA_TrustListDataType_clear(&dev_tl);
        }
    }
    if(e->rejected && (in->reasons & (GDS_PUSH_REJECTED | GDS_PUSH_CHECK)))
        harvest(e, cl, in, &tl, out);
    if(needTl || needCert)
        run_push(e, cl, in, &tl, cur, needTl, needCert, out);
    gdsc_session_close(dev);
    UA_TrustListDataType_clear(&tl);
}

/* ---- targets (lock held) ---- */

static target *find_target(push_engine *e, const UA_NodeId *id) {
    for(size_t i = 0; i < e->n; i++)
        if(UA_NodeId_equal(&e->targets[i]->appId, id))
            return e->targets[i];
    return NULL;
}

static void target_free(target *t) {
    if(!t)
        return;
    UA_NodeId_clear(&t->appId);
    free(t);
}

static void drop_at(push_engine *e, size_t i) {
    target *t = e->targets[i];
    e->targets[i] = e->targets[--e->n];
    if(t->running)
        t->removed = true; /* the worker frees it */
    else
        target_free(t);
}

typedef struct {
    UA_NodeId id;
    char uri[GDS_MAX_APPLICATION_URI + 1];
    char endpoint[GDS_MAX_PUSH_ENDPOINT];
    bool enabled;
} listed;

typedef struct {
    listed *v;
    size_t n, cap;
    bool err;
} listing;

static bool list_cb(void *ctx, const UA_NodeId *id, const char *uri, const char *endpoint,
                    bool enabled) {
    listing *l = ctx;
    if(l->n == l->cap) {
        size_t cap = l->cap ? 2 * l->cap : 32;
        listed *v = cap <= GDS_MAX_PUSH_TARGETS ? realloc(l->v, cap * sizeof(*v)) : NULL;
        if(!v) {
            l->err = true;
            return false;
        }
        l->v = v;
        l->cap = cap;
    }
    listed *x = &l->v[l->n];
    if(strlen(uri) >= sizeof(x->uri) || strlen(endpoint) >= sizeof(x->endpoint) ||
       UA_NodeId_copy(id, &x->id) != UA_STATUSCODE_GOOD)
        return true;
    memcpy(x->uri, uri, strlen(uri) + 1);
    memcpy(x->endpoint, endpoint, strlen(endpoint) + 1);
    x->enabled = enabled;
    l->n++;
    return true;
}

/* A new target, NULL when out of memory */
static target *add_target(push_engine *e, const UA_NodeId *id, UA_DateTime now) {
    if(e->n == e->cap) {
        size_t cap = e->cap ? 2 * e->cap : 32;
        target **v = (target **)realloc((void *)e->targets, cap * sizeof(target *));
        if(!v)
            return NULL;
        e->targets = v;
        e->cap = cap;
    }
    target *t = calloc(1, sizeof(*t));
    if(!t || UA_NodeId_copy(id, &t->appId) != UA_STATUSCODE_GOOD) {
        free(t);
        return NULL;
    }
    /* the first look at each Server spreads over the jitter */
    t->st.notBefore = now + push_jitter(&e->timing, rnd64());
    e->targets[e->n++] = t;
    return t;
}

static void merge(push_engine *e, listing *l, UA_DateTime now) {
    for(size_t i = 0; i < e->n; i++)
        e->targets[i]->seen = false;
    for(size_t i = 0; i < l->n; i++) {
        listed *x = &l->v[i];
        target *t = find_target(e, &x->id);
        if(!t)
            t = add_target(e, &x->id, now);
        if(!t)
            continue;
        if(!t->running) {
            if(strcmp(t->endpoint, x->endpoint) != 0)
                t->st.known = false; /* another endpoint: look again */
            memcpy(t->uri, x->uri, sizeof(t->uri));
            memcpy(t->endpoint, x->endpoint, sizeof(t->endpoint));
        }
        t->enabled = x->enabled;
        t->seen = true;
    }
    for(size_t i = e->n; i-- > 0;)
        if(!e->targets[i]->seen)
            drop_at(e, i);
}

static void listing_clear(listing *l) {
    for(size_t i = 0; i < l->n; i++)
        UA_NodeId_clear(&l->v[i].id);
    free(l->v);
}

/* ---- the tick ---- */

typedef struct {
    gds_push_job job;
    target *t;
} due_job;

static int by_due(const void *a, const void *b) {
    const due_job *x = a, *y = b;
    return x->job.due < y->job.due ? -1 : x->job.due > y->job.due;
}

/* The targets that are due now, into due (e->n entries) */
static size_t collect_due(push_engine *e, const uint8_t cur[PUSH_HASH_LEN], UA_DateTime now,
                          due_job *due) {
    size_t nDue = 0;
    for(size_t i = 0; i < e->n; i++) {
        target *t = e->targets[i];
        if(!t->enabled || t->running)
            continue;
        push_note_trust_list(&t->st, cur, now);
        UA_DateTime when = 0;
        uint32_t reasons = push_due(&t->st, &e->timing, cur, now, &when);
        if(!e->rejected)
            reasons &= ~GDS_PUSH_REJECTED;
        if(!reasons || reasons == GDS_PUSH_RETRY)
            continue;
        gds_push_job *j = &due[nDue].job;
        j->applicationId = t->appId;
        j->applicationUri = t->uri;
        j->endpointUrl = t->endpoint;
        j->reasons = reasons;
        j->due = when;
        j->certNotAfter = t->st.known ? t->st.certNotAfter : 0;
        j->failures = t->st.failures;
        due[nDue++].t = t;
    }
    return nDue;
}

static void pick(push_engine *e, const uint8_t cur[PUSH_HASH_LEN], UA_DateTime now) {
    size_t budget = e->cfg.concurrency - e->running - e->queued;
    if(budget == 0 || e->n == 0)
        return;
    due_job *due = calloc(e->n, sizeof(*due));
    size_t *picked = calloc(budget, sizeof(*picked));
    size_t nDue = due && picked ? collect_due(e, cur, now, due) : 0;
    if(nDue > 0) {
        qsort(due, nDue, sizeof(*due), by_due);
        gds_push_job *jobs = calloc(nDue, sizeof(*jobs));
        for(size_t i = 0; jobs && i < nDue; i++)
            jobs[i] = due[i].job;
        size_t k = jobs ? e->sched.next_jobs(e->sched.ctx, now, budget, jobs, nDue, picked) : 0;
        free(jobs);
        for(size_t i = 0; i < k && i < budget; i++) {
            size_t p = picked[i];
            if(p >= nDue || due[p].t->running)
                continue; /* out of range or picked twice */
            target *t = due[p].t;
            t->running = true;
            t->reasons = due[p].job.reasons;
            e->queue[e->queued++] = t;
        }
        if(e->queued)
            pthread_cond_broadcast(&e->workCond);
    }
    free(due);
    free(picked);
}

static void tick(push_engine *e) {
    gds_server *s = e->cfg.server;
    if(gds_server_role(s) == GDS_NODE_STANDBY) {
        pthread_mutex_lock(&e->lock);
        e->wasStandby = true;
        pthread_mutex_unlock(&e->lock);
        return;
    }
    listing l;
    memset(&l, 0, sizeof(l));
    gds_status st = gds_server_push_targets(s, list_cb, &l);
    if(st != GDS_OK || l.err) {
        if(st != GDS_EUNSUPPORTED)
            fprintf(stderr, "opengds: push: target list: %s\n",
                    gds_status_name(st != GDS_OK ? st : GDS_ENOMEM));
        listing_clear(&l);
        return;
    }
    UA_TrustListDataType tl;
    uint8_t cur[PUSH_HASH_LEN];
    bool haveTl = gds_server_get_trust_list(s, NULL, &tl) == GDS_OK;
    haveTl = haveTl && tl_hash(&tl, cur);
    if(haveTl || tl.trustedCertificatesSize)
        UA_TrustListDataType_clear(&tl);
    UA_DateTime now = UA_DateTime_now();
    pthread_mutex_lock(&e->lock);
    if(e->wasStandby) {
        /* now primary: what the old primary pushed is not known here */
        for(size_t i = 0; i < e->n; i++)
            memset(&e->targets[i]->st, 0, sizeof(push_state));
        e->wasStandby = false;
    }
    merge(e, &l, now);
    if(haveTl)
        pick(e, cur, now);
    pthread_mutex_unlock(&e->lock);
    listing_clear(&l);
    push_rejected_tick(e->rejected);
}

static void *tick_main(void *p) {
    push_engine *e = p;
    for(;;) {
        tick(e);
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_sec += (time_t)(e->cfg.tickMs / 1000);
        until.tv_nsec += (long)(e->cfg.tickMs % 1000) * 1000000L;
        if(until.tv_nsec >= 1000000000L) {
            until.tv_sec++;
            until.tv_nsec -= 1000000000L;
        }
        pthread_mutex_lock(&e->lock);
        while(!e->stop && !e->kick &&
              pthread_cond_timedwait(&e->tickCond, &e->lock, &until) == 0) {
        }
        bool stop = e->stop;
        e->kick = false;
        pthread_mutex_unlock(&e->lock);
        if(stop)
            return NULL;
    }
}

/* ---- workers ---- */

static void finish(push_engine *e, target *t, const job_in *in, const job_out *out) {
    UA_DateTime now = UA_DateTime_now();
    bool ok = out->result == UA_STATUSCODE_GOOD;
    t->jobs++;
    t->lastResult = out->result;
    t->tlPushes += out->tlPushed;
    t->certPushes += out->certPushed;
    t->harvests += out->harvested;
    if(out->connected) {
        t->st.known = true;
        t->st.certOurs = out->certOurs;
        t->st.certNotBefore = out->notBefore;
        t->st.certNotAfter = out->notAfter;
        t->st.tlValid = out->tlValid;
        memcpy(t->st.tlSent, out->tlSent, PUSH_HASH_LEN);
        if(out->tlValid)
            t->st.tlChangedAt = 0;
    }
    if(out->harvested)
        t->st.lastRejected = now;
    push_after_job(&t->st, &e->timing, ok, now, rnd64());
    (void)in;
}

static void *worker_main(void *p) {
    push_engine *e = p;
    pthread_mutex_lock(&e->lock);
    for(;;) {
        while(!e->stop && e->queued == 0)
            pthread_cond_wait(&e->workCond, &e->lock);
        if(e->stop)
            break;
        target *t = e->queue[0];
        memmove((void *)&e->queue[0], (const void *)&e->queue[1],
                (--e->queued) * sizeof(target *)); // NOLINT(bugprone-sizeof-expression): an array of pointers
        e->running++;
        job_in in;
        memset(&in, 0, sizeof(in));
        bool ok = UA_NodeId_copy(&t->appId, &in.appId) == UA_STATUSCODE_GOOD;
        memcpy(in.uri, t->uri, sizeof(in.uri));
        memcpy(in.endpoint, t->endpoint, sizeof(in.endpoint));
        in.reasons = t->reasons;
        in.st = t->st;
        gds_push_job done;
        memset(&done, 0, sizeof(done));
        pthread_mutex_unlock(&e->lock);
        job_out out;
        if(ok) {
            run_job(e, &in, &out);
        } else {
            memset(&out, 0, sizeof(out));
            out.result = UA_STATUSCODE_BADOUTOFMEMORY;
        }
        if(e->sched.job_done) {
            done.applicationId = in.appId;
            done.applicationUri = in.uri;
            done.endpointUrl = in.endpoint;
            done.reasons = in.reasons;
            done.due = UA_DateTime_now();
            done.certNotAfter = out.notAfter;
            done.failures = in.st.failures + (out.result != UA_STATUSCODE_GOOD);
            e->sched.job_done(e->sched.ctx, &done, out.result);
        }
        UA_NodeId_clear(&in.appId);
        pthread_mutex_lock(&e->lock);
        e->running--;
        t->running = false;
        if(t->removed)
            target_free(t);
        else
            finish(e, t, &in, &out);
    }
    pthread_mutex_unlock(&e->lock);
    return NULL;
}

/* ---- life cycle ---- */

static void defaults(push_engine_cfg *c) {
    if(!c->tickMs)
        c->tickMs = DEFAULT_TICK_MS;
    if(!c->concurrency)
        c->concurrency = DEFAULT_CONCURRENCY;
    if(c->concurrency > PUSH_MAX_CONCURRENCY)
        c->concurrency = PUSH_MAX_CONCURRENCY;
    if(!c->backoffMinS)
        c->backoffMinS = DEFAULT_BACKOFF_MIN_S;
    if(!c->backoffMaxS)
        c->backoffMaxS = DEFAULT_BACKOFF_MAX_S;
    if(c->backoffMaxS < c->backoffMinS)
        c->backoffMaxS = c->backoffMinS;
    if(!c->timeoutMs)
        c->timeoutMs = DEFAULT_TIMEOUT_MS;
    if(!c->signTimeoutMs)
        c->signTimeoutMs = DEFAULT_SIGN_TIMEOUT_MS;
    if(!c->presentTimeoutMs)
        c->presentTimeoutMs = DEFAULT_PRESENT_TIMEOUT_MS;
}

gds_status push_engine_start(const push_engine_cfg *cfg, push_engine **out) {
    *out = NULL;
    if(!cfg || !cfg->server || !cfg->cert.data || !cfg->key.data)
        return GDS_EINVAL;
    push_engine *e = calloc(1, sizeof(*e));
    if(!e)
        return GDS_ENOMEM;
    e->cfg = *cfg;
    defaults(&e->cfg);
    for(size_t i = 0; cfg->issuers && i < cfg->issuersN && i < GDS_CA_ISSUERS; i++)
        e->issuers[e->issuersN++] = (UA_ByteString){cfg->issuers[i].len, cfg->issuers[i].data};
    e->timing.jitterMax = secs(e->cfg.jitterS);
    e->timing.backoffMin = secs(e->cfg.backoffMinS);
    e->timing.backoffMax = secs(e->cfg.backoffMaxS);
    e->timing.rejectedInterval = secs(e->cfg.rejectedS);
    if(!gds_server_push_scheduler(cfg->server, &e->sched)) {
        memset(&e->sched, 0, sizeof(e->sched));
        e->sched.next_jobs = gds_push_next_jobs_default;
    }
    pthread_mutex_init(&e->lock, NULL);
    pthread_cond_init(&e->tickCond, NULL);
    pthread_cond_init(&e->workCond, NULL);
    gds_status st = GDS_OK;
    if(e->cfg.rejectedS) {
        push_rejected_cfg rc = {cfg->server, 0, 0};
        st = push_rejected_new(&rc, &e->rejected);
    }
    for(size_t i = 0; st == GDS_OK && i < e->cfg.concurrency; i++) {
        if(pthread_create(&e->workers[i], NULL, worker_main, e) != 0)
            st = GDS_ENOMEM;
        else
            e->nWorkers++;
    }
    if(st == GDS_OK) {
        if(pthread_create(&e->tickThread, NULL, tick_main, e) != 0)
            st = GDS_ENOMEM;
        else
            e->tickStarted = true;
    }
    if(st != GDS_OK) {
        push_engine_stop(e);
        return st;
    }
    *out = e;
    return GDS_OK;
}

void push_engine_kick(push_engine *e) {
    if(!e)
        return;
    pthread_mutex_lock(&e->lock);
    e->kick = true;
    pthread_cond_signal(&e->tickCond);
    pthread_mutex_unlock(&e->lock);
}

void push_engine_stop(push_engine *e) {
    if(!e)
        return;
    pthread_mutex_lock(&e->lock);
    e->stop = true;
    pthread_cond_broadcast(&e->tickCond);
    pthread_cond_broadcast(&e->workCond);
    pthread_mutex_unlock(&e->lock);
    if(e->tickStarted)
        pthread_join(e->tickThread, NULL);
    for(size_t i = 0; i < e->nWorkers; i++)
        pthread_join(e->workers[i], NULL);
    for(size_t i = 0; i < e->n; i++)
        target_free(e->targets[i]); /* nothing runs now */
    free((void *)e->targets);
    push_rejected_free(e->rejected);
    pthread_cond_destroy(&e->workCond);
    pthread_cond_destroy(&e->tickCond);
    pthread_mutex_destroy(&e->lock);
    free(e);
}

gds_status push_engine_status(push_engine *e, const char *uri, push_target_status *out) {
    memset(out, 0, sizeof(*out));
    if(!e || !uri)
        return GDS_EINVAL;
    gds_status st = GDS_ENOTFOUND;
    pthread_mutex_lock(&e->lock);
    for(size_t i = 0; i < e->n; i++) {
        const target *t = e->targets[i];
        if(strcmp(t->uri, uri) != 0)
            continue;
        out->known = t->st.known;
        out->certOurs = t->st.certOurs;
        out->certNotAfter = t->st.certNotAfter;
        out->trustListCurrent = t->st.tlValid && t->st.tlChangedAt == 0;
        out->failures = t->st.failures;
        out->lastResult = t->lastResult;
        out->jobs = t->jobs;
        out->trustListPushes = t->tlPushes;
        out->certificatePushes = t->certPushes;
        out->rejectedHarvests = t->harvests;
        st = GDS_OK;
        break;
    }
    pthread_mutex_unlock(&e->lock);
    return st;
}

size_t push_engine_open_dialogs(push_engine *e) {
    return e ? push_rejected_open(e->rejected) : 0;
}
