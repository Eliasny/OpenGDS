/* THROWAWAY SPIKE (week 1): async method calls on a worker pool, open62541 v1.5.10.
 * Not production code. Findings: docs/spikes/02-async-methods-worker-pool.md
 * SPDX-License-Identifier: MPL-2.0
 *
 * A method "SlowOp" stands in for the slow part of a Part 12 call (store write
 * with fsync, signer IPC, RSA key generation). The method callback copies its
 * input into a job, queues it on a worker pool and returns
 * GoodCompletesAsynchronously. Two completion patterns:
 *
 *   handoff (default): the worker only fills job-owned memory and pushes the
 *     job to a completion queue; a timed callback on the server thread writes
 *     the output and calls UA_Server_setAsyncCallMethodResult. The in-flight
 *     table is touched only on the server thread.
 *   direct (PATTERN=direct): the worker writes the output and calls
 *     UA_Server_setAsyncCallMethodResult itself while holding the job lock,
 *     as the upstream tutorial does from a timer. Shows the lock-order
 *     inversion with the cancel callback (run under -fsanitize=thread). */
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_highlevel_async.h>
#include <open62541/plugin/log_stdout.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#define PORT 48411
#define WORKERS 8
#define QUEUE_CAP 16
static int failures;
#define CHECK(cond, ...) do { int ok_ = !!(cond); if(!ok_) failures++; \
    printf("%s  ", ok_ ? "PASS" : "FAIL"); printf(__VA_ARGS__); printf("\n"); } while(0)

static double
nowMs(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

/* ------------------------------------------------------------- worker pool */

typedef enum { JOB_SLEEP = 0, JOB_RSA2048 = 1 } JobKind;

typedef struct Job {
    struct Job *next;
    /* Input, owned by the job (deep copy from the request). */
    UA_ByteString input;
    UA_UInt32 workMs;
    JobKind kind;
    /* Result, written by the worker, owned by the job. */
    UA_ByteString result;
    UA_StatusCode status;
    /* Server-thread-only fields (handoff pattern). */
    UA_Variant *output;      /* NULL once cancelled */
    UA_Boolean inFlight;
    /* direct pattern */
    pthread_mutex_t lock;
    UA_Boolean cancelled;
} Job;

static UA_Server *server;
static volatile UA_Boolean running = true;
static UA_Boolean directPattern;
static pthread_t serverTid;
static unsigned holdMs; /* PATTERN=deadlock */

static pthread_mutex_t qLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qCond = PTHREAD_COND_INITIALIZER;
static Job *qHead, *qTail;
static size_t qLen;
static UA_Boolean poolStop;

static pthread_mutex_t doneLock = PTHREAD_MUTEX_INITIALIZER;
static Job *doneHead;

/* Stats */
static volatile unsigned jobsStarted, jobsCompleted, jobsCancelled, lateResultsDropped,
    rejectedQueueFull;

/* In-flight table: touched only on the server thread (method callback, cancel
 * callback, completion callback). That is the whole synchronisation story. */
#define MAX_INFLIGHT 1024
static Job *inflight[MAX_INFLIGHT];

static void
assertServerThread(const char *where) {
    if(!pthread_equal(pthread_self(), serverTid) && running) {
        printf("FAIL  %s ran off the server thread\n", where);
        failures++;
    }
}

static void
doWork(Job *j) {
    if(j->kind == JOB_RSA2048) {
        EVP_PKEY *k = EVP_RSA_gen(2048);
        unsigned char *der = NULL;
        int len = k ? i2d_PrivateKey(k, &der) : -1;
        if(len > 0) {
            UA_ByteString_allocBuffer(&j->result, (size_t)len);
            memcpy(j->result.data, der, (size_t)len);
            OPENSSL_free(der);
            j->status = UA_STATUSCODE_GOOD;
        } else {
            j->status = UA_STATUSCODE_BADINTERNALERROR;
        }
        EVP_PKEY_free(k);
        return;
    }
    usleep(j->workMs * 1000);
    UA_ByteString_copy(&j->input, &j->result);   /* "signed" = echo */
    j->status = UA_STATUSCODE_GOOD;
}

static void drainCompletions(UA_Server *s, void *data);

static void *
workerMain(void *arg) {
    (void)arg;
    for(;;) {
        pthread_mutex_lock(&qLock);
        while(!qHead && !poolStop)
            pthread_cond_wait(&qCond, &qLock);
        if(!qHead && poolStop) { pthread_mutex_unlock(&qLock); return NULL; }
        Job *j = qHead; qHead = j->next; if(!qHead) qTail = NULL; qLen--;
        pthread_mutex_unlock(&qLock);

        __atomic_add_fetch(&jobsStarted, 1, __ATOMIC_RELAXED);
        doWork(j);

        if(directPattern) {
            /* Tutorial pattern moved to a worker thread: job lock held across
             * a call that takes the server lock. */
            pthread_mutex_lock(&j->lock);
            if(holdMs) usleep(holdMs * 1000); /* e.g. encoding the result under the lock */
            if(!j->cancelled) {
                UA_Variant_setScalarCopy(j->output, &j->result, &UA_TYPES[UA_TYPES_BYTESTRING]);
                UA_Server_setAsyncCallMethodResult(server, j->output, j->status);
                __atomic_add_fetch(&jobsCompleted, 1, __ATOMIC_RELAXED);
            } else {
                __atomic_add_fetch(&lateResultsDropped, 1, __ATOMIC_RELAXED);
            }
            pthread_mutex_unlock(&j->lock);
            /* Ownership in this pattern is murky; leak rather than race (spike). */
            continue;
        }

        /* Handoff pattern: hand the job back, wake the server thread. No lock
         * of ours is held while calling into open62541. */
        pthread_mutex_lock(&doneLock);
        j->next = doneHead; doneHead = j;
        pthread_mutex_unlock(&doneLock);
        UA_Server_addTimedCallback(server, drainCompletions, NULL, UA_DateTime_nowMonotonic(), NULL);
    }
}

static void
freeJob(Job *j) {
    UA_ByteString_clear(&j->input);
    UA_ByteString_clear(&j->result);
    pthread_mutex_destroy(&j->lock);
    free(j);
}

/* Server thread. */
static void
drainCompletions(UA_Server *s, void *data) {
    (void)data;
    assertServerThread("completion");
    pthread_mutex_lock(&doneLock);
    Job *list = doneHead; doneHead = NULL;
    pthread_mutex_unlock(&doneLock);
    while(list) {
        Job *j = list; list = j->next;
        if(j->output) {
            UA_Variant_setScalarCopy(j->output, &j->result, &UA_TYPES[UA_TYPES_BYTESTRING]);
            UA_StatusCode rv = UA_Server_setAsyncCallMethodResult(s, j->output, j->status);
            if(rv != UA_STATUSCODE_GOOD)
                printf("INFO  setAsyncCallMethodResult -> %s\n", UA_StatusCode_name(rv));
            __atomic_add_fetch(&jobsCompleted, 1, __ATOMIC_RELAXED);
        } else {
            __atomic_add_fetch(&lateResultsDropped, 1, __ATOMIC_RELAXED);
        }
        for(size_t i = 0; i < MAX_INFLIGHT; i++)
            if(inflight[i] == j) { inflight[i] = NULL; break; }
        freeJob(j);
    }
}

/* Called by open62541 with the server lock held: on timeout (server thread),
 * on the Cancel service (server thread) and from UA_Server_delete. */
static void
cancelCallback(UA_Server *s, const void *out) {
    (void)s;
    __atomic_add_fetch(&jobsCancelled, 1, __ATOMIC_RELAXED);
    for(size_t i = 0; i < MAX_INFLIGHT; i++) {
        Job *j = inflight[i];
        if(!j || (const void*)j->output != out)
            continue;
        if(directPattern) {
            pthread_mutex_lock(&j->lock);     /* server lock -> job lock */
            j->cancelled = true;
            pthread_mutex_unlock(&j->lock);
        }
        j->output = NULL;   /* the server frees that memory now */
        if(directPattern) inflight[i] = NULL;
        return;
    }
}

static UA_StatusCode
slowOpCallback(UA_Server *s, const UA_NodeId *sessionId, void *sessionContext,
               const UA_NodeId *methodId, void *methodContext,
               const UA_NodeId *objectId, void *objectContext,
               size_t inputSize, const UA_Variant *input,
               size_t outputSize, UA_Variant *output) {
    (void)s; (void)sessionId; (void)sessionContext; (void)methodId; (void)methodContext;
    (void)objectId; (void)objectContext; (void)outputSize;
    if(inputSize != 3)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    assertServerThread("method callback");

    pthread_mutex_lock(&qLock);
    UA_Boolean full = qLen >= QUEUE_CAP;
    pthread_mutex_unlock(&qLock);
    if(full) {
        __atomic_add_fetch(&rejectedQueueFull, 1, __ATOMIC_RELAXED);
        return UA_STATUSCODE_BADTOOMANYOPERATIONS;  /* answer now, do not queue */
    }
    size_t slot = MAX_INFLIGHT;
    for(size_t i = 0; i < MAX_INFLIGHT; i++)
        if(!inflight[i]) { slot = i; break; }
    if(slot == MAX_INFLIGHT)
        return UA_STATUSCODE_BADTOOMANYOPERATIONS;

    Job *j = calloc(1, sizeof(Job));
    if(!j)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    pthread_mutex_init(&j->lock, NULL);
    /* Deep copy: nothing that points into the request crosses the thread. */
    UA_ByteString_copy((const UA_ByteString*)input[0].data, &j->input);
    j->workMs = *(const UA_UInt32*)input[1].data;
    j->kind = (JobKind)*(const UA_UInt32*)input[2].data;
    j->output = output;
    inflight[slot] = j;

    pthread_mutex_lock(&qLock);
    if(qTail) qTail->next = j; else qHead = j;
    qTail = j; qLen++;
    pthread_cond_signal(&qCond);
    pthread_mutex_unlock(&qLock);
    return UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY;
}

static void *
serverThread(void *arg) {
    (void)arg;
    serverTid = pthread_self();
    UA_Server_run(server, &running);
    return NULL;
}

static void
startServer(UA_Double asyncTimeoutMs) {
    server = UA_Server_new();
    UA_ServerConfig *cfg = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(cfg, PORT, NULL);
    cfg->asyncOperationCancelCallback = cancelCallback;
    cfg->asyncOperationTimeout = asyncTimeoutMs;
    cfg->maxAsyncOperationQueueSize = 256;

    UA_Argument in[3], out;
    for(int i = 0; i < 3; i++) UA_Argument_init(&in[i]);
    in[0].name = UA_STRING("Payload"); in[0].dataType = UA_TYPES[UA_TYPES_BYTESTRING].typeId;
    in[1].name = UA_STRING("WorkMs"); in[1].dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
    in[2].name = UA_STRING("Kind"); in[2].dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
    for(int i = 0; i < 3; i++) in[i].valueRank = UA_VALUERANK_SCALAR;
    UA_Argument_init(&out);
    out.name = UA_STRING("Result"); out.dataType = UA_TYPES[UA_TYPES_BYTESTRING].typeId;
    out.valueRank = UA_VALUERANK_SCALAR;
    UA_MethodAttributes ma = UA_MethodAttributes_default;
    ma.displayName = UA_LOCALIZEDTEXT("en", "SlowOp");
    ma.executable = ma.userExecutable = true;
    UA_Server_addMethodNode(server, UA_NODEID_STRING(1, "SlowOp"), UA_NS0ID(OBJECTSFOLDER),
                            UA_NS0ID(HASCOMPONENT), UA_QUALIFIEDNAME(1, "SlowOp"), ma,
                            slowOpCallback, 3, in, 1, &out, NULL, NULL);
}

/* ------------------------------------------------------------------ client */

typedef struct { int done; UA_StatusCode service; UA_StatusCode op; size_t outLen; double at; size_t nResults; } CallResult;

static void
onCall(UA_Client *c, void *ud, UA_UInt32 reqId, UA_CallResponse *cr) {
    (void)c; (void)reqId;
    CallResult *r = (CallResult*)ud;
    r->done = 1;
    r->at = nowMs();
    r->service = cr->responseHeader.serviceResult;
    r->nResults = cr->resultsSize;
    r->op = UA_STATUSCODE_BADUNKNOWNRESPONSE;
    if(cr->resultsSize == 1) {
        r->op = cr->results[0].statusCode;
        if(cr->results[0].outputArgumentsSize == 1 &&
           UA_Variant_hasScalarType(&cr->results[0].outputArguments[0], &UA_TYPES[UA_TYPES_BYTESTRING]))
            r->outLen = ((UA_ByteString*)cr->results[0].outputArguments[0].data)->length;
    }
}

static UA_Client *
connectClient(void) {
    UA_Client *c = UA_Client_new();
    UA_ClientConfig *cc = UA_Client_getConfig(c);
    UA_ClientConfig_setDefault(cc);
    cc->timeout = 20000;
    char url[64]; snprintf(url, sizeof(url), "opc.tcp://localhost:%d", PORT);
    for(int i = 0; i < 100 && UA_Client_connect(c, url) != UA_STATUSCODE_GOOD; i++)
        usleep(50000);
    return c;
}

static UA_StatusCode
startCall(UA_Client *c, UA_UInt32 workMs, UA_UInt32 kind, CallResult *r, UA_UInt32 *reqId) {
    UA_Variant in[3];
    UA_ByteString payload = UA_BYTESTRING("fake CSR bytes");
    UA_Variant_setScalar(&in[0], &payload, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[1], &workMs, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[2], &kind, &UA_TYPES[UA_TYPES_UINT32]);
    memset(r, 0, sizeof(*r));
    return UA_Client_call_async(c, UA_NS0ID(OBJECTSFOLDER), UA_NODEID_STRING(1, "SlowOp"),
                                3, in, onCall, r, reqId);
}

static int
waitAll(UA_Client *c, CallResult *r, size_t n, double maxMs) {
    double t0 = nowMs();
    for(;;) {
        size_t done = 0;
        for(size_t i = 0; i < n; i++) done += (size_t)r[i].done;
        if(done == n) return 1;
        if(nowMs() - t0 > maxMs) return 0;
        UA_Client_run_iterate(c, 10);
    }
}

static double
readLatencyMs(UA_Client *c) {
    UA_Variant v; UA_Variant_init(&v);
    double t0 = nowMs();
    UA_Client_readValueAttribute(c, UA_NS0ID(SERVER_SERVERSTATUS_CURRENTTIME), &v);
    UA_Variant_clear(&v);
    return nowMs() - t0;
}

/* Measures Read latency on a second connection while the first one waits. */
typedef struct { UA_Client *c; volatile int stop; double maxMs; int reads; } Prober;
static void *
probeMain(void *arg) {
    Prober *p = (Prober*)arg;
    while(!p->stop) {
        double l = readLatencyMs(p->c);
        if(l > p->maxMs) p->maxMs = l;
        p->reads++;
        usleep(20000);
    }
    return NULL;
}

static void
onAlarm(int sig) {
    (void)sig;
    static const char msg[] = "FAIL  DEADLOCK: no progress after 10 s (worker holds job lock and waits "
        "for the server lock; the server thread holds the server lock in checkTimeouts and waits "
        "for the job lock in the cancel callback)\n";
    ssize_t w = write(1, msg, sizeof(msg) - 1); (void)w;
    _exit(2);
}

int
main(void) {
    const char *pat = getenv("PATTERN");
    directPattern = pat && (!strcmp(pat, "direct") || !strcmp(pat, "deadlock"));
    if(pat && !strcmp(pat, "deadlock")) {
        /* Deterministic: the job finishes inside the timeout, but the worker
         * keeps the job lock across the 1 s timeout tick. */
        holdMs = 2500;
        printf("INFO  completion pattern: direct, job lock held %u ms before setAsync\n", holdMs);
        startServer(1500.0);
        pthread_t th, w;
        pthread_create(&th, NULL, serverThread, NULL);
        pthread_create(&w, NULL, workerMain, NULL);
        UA_Client *c = connectClient();
        signal(SIGALRM, onAlarm);
        alarm(10);
        static CallResult r; /* static: callbacks may fire on client delete */
        startCall(c, 200, JOB_SLEEP, &r, NULL);
        waitAll(c, &r, 1, 8000);
        usleep(3000000);
        printf("PASS  no deadlock this time (result %s)\n", UA_StatusCode_name(r.op));
        return 0;
    }
    printf("INFO  completion pattern: %s\n", directPattern ? "direct (worker calls setAsync)" : "handoff");
    startServer(1500.0);
    pthread_t th, workers[WORKERS];
    pthread_create(&th, NULL, serverThread, NULL);
    for(int i = 0; i < WORKERS; i++) pthread_create(&workers[i], NULL, workerMain, NULL);

    UA_Client *c = connectClient();
    UA_Client *probe = connectClient();
    printf("INFO  idle Read latency: %.2f ms\n", readLatencyMs(probe));

    /* 1. Throughput: 16 x 200 ms on 8 workers, network loop stays responsive. */
    {
        static CallResult r[16]; /* static: callbacks may fire on client delete */
        Prober p = {probe, 0, 0, 0};
        pthread_t pt; pthread_create(&pt, NULL, probeMain, &p);
        double t0 = nowMs();
        for(int i = 0; i < 16; i++) startCall(c, 200, JOB_SLEEP, &r[i], NULL);
        int ok = waitAll(c, r, 16, 10000);
        double total = nowMs() - t0;
        p.stop = 1; pthread_join(pt, NULL);
        int good = 0;
        for(int i = 0; i < 16; i++) good += (r[i].service == UA_STATUSCODE_GOOD && r[i].op == UA_STATUSCODE_GOOD && r[i].outLen > 0);
        CHECK(ok && good == 16, "16 async calls x 200 ms on %d workers: all Good with output (%d/16)", WORKERS, good);
        CHECK(total < 1200, "  wall time %.0f ms (serial would be 3200 ms)", total);
        CHECK(p.maxMs < 50, "  Read on a second session meanwhile: max %.1f ms over %d reads", p.maxMs, p.reads);
    }

    /* 2. Bounded queue: 40 at once -> some refused right away. */
    {
        static CallResult r[40]; /* static: callbacks may fire on client delete */
        unsigned before = rejectedQueueFull;
        for(int i = 0; i < 40; i++) startCall(c, 300, JOB_SLEEP, &r[i], NULL);
        waitAll(c, r, 40, 15000);
        int refused = 0, good = 0;
        for(int i = 0; i < 40; i++) {
            refused += (r[i].op == UA_STATUSCODE_BADTOOMANYOPERATIONS);
            good += (r[i].op == UA_STATUSCODE_GOOD);
        }
        CHECK(refused > 0 && refused + good == 40,
              "40 concurrent calls, queue cap %d + %d workers: %d Good, %d BadTooManyOperations (server counted %u)",
              QUEUE_CAP, WORKERS, good, refused, rejectedQueueFull - before);
    }

    /* 3. Timeout: 1.5 s server async timeout, 4 s job. */
    {
        static CallResult r; /* static: callbacks may fire on client delete */
        unsigned dropped = lateResultsDropped;
        startCall(c, 4000, JOB_SLEEP, &r, NULL);
        waitAll(c, &r, 1, 10000);
        CHECK(r.op == UA_STATUSCODE_BADTIMEOUT, "4 s job vs 1.5 s asyncOperationTimeout -> %s (timeout checked once a second)",
              UA_StatusCode_name(r.op));
        usleep(3500000);
        UA_Client_run_iterate(c, 10);
        CHECK(lateResultsDropped == dropped + 1, "  the worker's late result was dropped, not written into freed memory");
    }

    /* 4. Cancel service. */
    {
        static CallResult r; /* static: callbacks may fire on client delete */ UA_UInt32 reqId = 0;
        unsigned dropped = lateResultsDropped;
        startCall(c, 800, JOB_SLEEP, &r, &reqId);
        for(int i = 0; i < 10; i++) UA_Client_run_iterate(c, 10);
        UA_UInt32 cancelCount = 0;
        UA_StatusCode crv = UA_Client_cancelByRequestId(c, reqId, &cancelCount);
        waitAll(c, &r, 1, 5000);
        CHECK(crv == UA_STATUSCODE_GOOD && cancelCount == 1,
              "Cancel service on a pending call: cancelCount=%u (%s)", cancelCount, UA_StatusCode_name(crv));
        printf("INFO    call result: service %s, %zu result(s), operation %s\n", UA_StatusCode_name(r.service),
               r.nResults, r.nResults ? UA_StatusCode_name(r.op) : "-");
        usleep(1000000);
        UA_Client_run_iterate(c, 10);
        CHECK(lateResultsDropped == dropped + 1, "  late result after Cancel dropped");
    }

    /* 5. Client disconnects with a call in flight. */
    {
        UA_Client *c2 = connectClient();
        static CallResult r; /* static: callbacks may fire on client delete */
        startCall(c2, 500, JOB_SLEEP, &r, NULL);
        for(int i = 0; i < 5; i++) UA_Client_run_iterate(c2, 10);
        unsigned completed = jobsCompleted, cancelled = jobsCancelled;
        UA_Client_disconnect(c2);
        UA_Client_delete(c2);
        usleep(1000000);
        CHECK(jobsCompleted == completed + 1 && jobsCancelled == cancelled,
              "session closed mid-call: open62541 does not cancel the op; the job completes and the response is dropped");
    }

    /* 6. Real crypto on the pool: 8 x RSA-2048 key generation. */
    {
        static CallResult r[8]; /* static: callbacks may fire on client delete */
        Prober p = {probe, 0, 0, 0};
        pthread_t pt; pthread_create(&pt, NULL, probeMain, &p);
        double t0 = nowMs();
        for(int i = 0; i < 8; i++) startCall(c, 0, JOB_RSA2048, &r[i], NULL);
        int ok = waitAll(c, r, 8, 60000);
        double total = nowMs() - t0;
        p.stop = 1; pthread_join(pt, NULL);
        int good = 0;
        for(int i = 0; i < 8; i++) good += (r[i].op == UA_STATUSCODE_GOOD && r[i].outLen > 1000);
        CHECK(ok && good == 8, "8 x RSA-2048 keygen on the pool: %d/8 Good in %.0f ms; max Read latency meanwhile %.1f ms",
              good, total, p.maxMs);
    }

    /* 7. Shutdown with calls in flight. */
    {
        static CallResult r[4]; /* static: callbacks may fire on client delete */
        for(int i = 0; i < 4; i++) startCall(c, 1500, JOB_SLEEP, &r[i], NULL);
        for(int i = 0; i < 10; i++) UA_Client_run_iterate(c, 10);
        unsigned cancelled = jobsCancelled;
        running = false;               /* 1. stop the network loop */
        pthread_join(th, NULL);
        pthread_mutex_lock(&qLock);    /* 2. stop and join the workers */
        poolStop = true;
        pthread_cond_broadcast(&qCond);
        pthread_mutex_unlock(&qLock);
        for(int i = 0; i < WORKERS; i++) pthread_join(workers[i], NULL);
        serverTid = pthread_self();    /* 3. remaining callbacks run here */
        drainCompletions(server, NULL); /* finished jobs whose results never got back */
        UA_Server_delete(server);      /* 4. cancels the rest with BadShutdown */
        CHECK(1, "shutdown with 4 calls in flight: loop stopped, workers joined, %u op(s) cancelled by UA_Server_delete",
              jobsCancelled - cancelled);
    }
    UA_Client_delete(c);
    UA_Client_delete(probe);
    for(size_t i = 0; i < MAX_INFLIGHT; i++) if(inflight[i]) freeJob(inflight[i]);
    printf("INFO  jobs started %u, completed %u, cancelled %u, late results dropped %u\n",
           jobsStarted, jobsCompleted, jobsCancelled, lateResultsDropped);
    printf("\n%s: %d failure(s)\n", failures ? "FAILED" : "ALL PASS", failures);
    return failures ? 1 : 0;
}
