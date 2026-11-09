/* OpenGDS performance test: push coverage (OpenGDS plan, "Performance
 * design and targets": 10,000 servers per 24 h with 64 parallel sessions).
 *
 * P workers each hold one GDS session (a CertificateAuthorityAdmin) and take
 * push jobs in turn; job j goes to device j mod D. A job is the "push now"
 * of gdsadm (OPC 10000-12 §7.7.2, Annex G.3), all over standard OPC UA:
 *   FindApplications (the device's record) -> GetTrustList ->
 *   connect to the device with our certificate (SecurityAdmin there) ->
 *   TrustList Open/Write/CloseAndUpdate -> CreateSigningRequest ->
 *   StartSigningRequest/FinishRequest on the GDS -> UpdateCertificate ->
 *   ApplyChanges.
 * One job per device at a time. The result is pushes per second and the
 * servers that rate covers in 24 h.
 *
 * Devices file: one line per device, "<ApplicationUri> <opc.tcp URL>
 * <device certificate DER>"; the certificate is pinned next to the GDS CA so
 * that the device is trusted before and after its first push.
 *
 * Usage: load_push <common options> --devices FILE [--parallel 64] [--jobs N]
 * SPDX-License-Identifier: MPL-2.0 */
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client/gdsc_gds.h"
#include "client/gdsc_push.h"
#include "perf_common.h"
#include "push/push_workflows.h"
#include "common/banned.h"

#define MAX_DEVICES 1024

typedef struct {
    char uri[GDS_MAX_APPLICATION_URI];
    char url[GDS_MAX_PATH];
    gds_buf cert;
    pthread_mutex_t lock;
} device;

typedef struct {
    const perf_gds *g;
    device *dev;
    size_t devN;
    unsigned long jobs;
    atomic_ulong next, ok;
    perf_samples total, sign;
    perf_errors err;
} shared;

typedef struct {
    UA_Client *gds;
    UA_UInt16 ns;
    UA_NodeId appId;
    shared *sh;
} sign_ctx;

static gds_status sign_via_gds(void *ctx, const gds_buf *csr, gds_buf *certOut,
                               gds_buf *issuersOut, size_t *issuersN) {
    (void)issuersOut;
    sign_ctx *sc = ctx;
    *issuersN = 0;
    uint64_t t0 = perf_now_ns();
    UA_StatusCode r = perf_sign(sc->gds, sc->ns, &sc->appId, csr, 20, 120000, certOut);
    perf_samples_add(&sc->sh->sign, perf_now_ns() - t0);
    return r == UA_STATUSCODE_GOOD ? GDS_OK : GDS_EREMOTE;
}

static UA_StatusCode push_one(shared *sh, UA_Client *gds, UA_UInt16 ns, device *d) {
    UA_ApplicationRecordDataType *recs = NULL;
    size_t n = 0;
    UA_StatusCode r = gdsc_find_applications(gds, ns, d->uri, &recs, &n);
    if(r == UA_STATUSCODE_GOOD && n != 1)
        r = UA_STATUSCODE_BADNOTFOUND;
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    sign_ctx sc = {gds, ns, UA_NODEID_NULL, sh};
    if(r == UA_STATUSCODE_GOOD) {
        sc.appId = recs[0].applicationId;
        UA_NodeId group = gdsc_gds_default_group(ns);
        r = gdsc_get_trust_list(gds, ns, &sc.appId, &group, &tl);
    }
    gdsc_session *dev = NULL;
    if(r == UA_STATUSCODE_GOOD) {
        gds_buf trust[2] = {sh->g->trust, d->cert};
        gdsc_session_cfg c;
        memset(&c, 0, sizeof(c));
        c.endpointUrl = d->url;
        c.serverUri = d->uri;
        c.cert = &sh->g->cert;
        c.key = &sh->g->key;
        c.trust = trust;
        c.trustN = 2;
        c.crls = sh->g->crl.data ? &sh->g->crl : NULL;
        c.crlN = sh->g->crl.data ? 1 : 0;
        c.identity = GDSC_IDENTITY_APP_CERT; /* Annex G.3 */
        c.timeoutMs = 60000;
        r = gdsc_session_open(&c, &dev);
    }
    if(r == UA_STATUSCODE_GOOD) {
        push_job job;
        memset(&job, 0, sizeof(job));
        job.certificateGroup = GDSC_DEFAULT_APP_GROUP;
        job.trustListNode = GDSC_DEFAULT_APP_TRUSTLIST;
        job.certificateType = GDSC_RSA_SHA256_APP_CERT;
        job.trustList = &tl;
        job.sign = sign_via_gds;
        job.signCtx = &sc;
        job.issuers = &sh->g->trust;
        job.issuersN = 1;
        push_report rep;
        memset(&rep, 0, sizeof(rep));
        gds_status s = push_run(gdsc_session_client(dev), &job, &rep);
        if(s != GDS_OK)
            r = rep.failedCode != UA_STATUSCODE_GOOD ? rep.failedCode : UA_STATUSCODE_BADINTERNALERROR;
        else if(!rep.certificateUpdated || !rep.trustListUpdated)
            r = UA_STATUSCODE_BADUNEXPECTEDERROR;
        if(s != GDS_OK)
            fprintf(stderr, "load_push: %s: failed at %s: %s\n", d->uri,
                    push_step_name(rep.failedStep), UA_StatusCode_name(rep.failedCode));
        push_report_clear(&rep);
        gdsc_session_close(dev);
    }
    UA_TrustListDataType_clear(&tl);
    if(recs)
        UA_Array_delete(recs, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    return r;
}

static void *worker(void *arg) {
    shared *sh = arg;
    gdsc_session *s = NULL;
    UA_UInt16 ns = 0;
    UA_StatusCode r = perf_gds_open(sh->g, &s, &ns);
    if(r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "load_push: GDS session: %s\n", UA_StatusCode_name(r));
        perf_errors_add(&sh->err, r);
        return NULL;
    }
    for(;;) {
        unsigned long j = atomic_fetch_add(&sh->next, 1);
        if(j >= sh->jobs)
            break;
        device *d = &sh->dev[j % sh->devN];
        pthread_mutex_lock(&d->lock);
        uint64_t t0 = perf_now_ns();
        r = push_one(sh, gdsc_session_client(s), ns, d);
        uint64_t dt = perf_now_ns() - t0;
        pthread_mutex_unlock(&d->lock);
        if(r == UA_STATUSCODE_GOOD) {
            perf_samples_add(&sh->total, dt);
            atomic_fetch_add(&sh->ok, 1);
        } else {
            perf_errors_add(&sh->err, r);
        }
    }
    gdsc_session_close(s);
    return NULL;
}

static size_t load_devices(const char *path, device *dev) {
    FILE *f = fopen(path, "r");
    if(!f)
        return 0;
    size_t n = 0;
    char line[2 * GDS_MAX_PATH + GDS_MAX_APPLICATION_URI], certFile[GDS_MAX_PATH];
    while(n < MAX_DEVICES && fgets(line, sizeof(line), f)) {
        device *d = &dev[n];
        char fmt[64];
        if(gds_path(fmt, sizeof(fmt), "%%%zus %%%zus %%%zus", sizeof(d->uri) - 1,
                    sizeof(d->url) - 1, sizeof(certFile) - 1) != GDS_OK)
            break;
        /* fmt is built from sizes above, not from input */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
        int got = sscanf(line, fmt, d->uri, d->url, certFile);
#pragma GCC diagnostic pop
        if(got != 3)
            continue;
        if(gds_file_read(certFile, GDS_MAX_CERT_SIZE, &d->cert) != GDS_OK) {
            fprintf(stderr, "load_push: cannot read %s\n", certFile);
            break;
        }
        pthread_mutex_init(&d->lock, NULL);
        n++;
    }
    fclose(f);
    return n;
}

int main(int argc, char **argv) {
    perf_gds g;
    memset(&g, 0, sizeof(g));
    unsigned long parallel = 64, jobs = 0;
    const char *devFile = NULL;
    for(int i = 1; i + 1 < argc; i += 2) {
        if(perf_gds_opt(&g, argv[i], argv[i + 1]))
            continue;
        if(strcmp(argv[i], "--devices") == 0)
            devFile = argv[i + 1];
        else if(strcmp(argv[i], "--parallel") == 0)
            parallel = perf_arg_ul(argv[i], argv[i + 1]);
        else if(strcmp(argv[i], "--jobs") == 0)
            jobs = perf_arg_ul(argv[i], argv[i + 1]);
        else {
            fprintf(stderr, "load_push: unknown option %s\n", argv[i]);
            return 2;
        }
    }
    if(argc % 2 == 0 || !devFile || parallel == 0 || parallel > 1024) {
        fprintf(stderr, "usage: load_push --gds URL --cert DER --key DER --trust DER [--crl DER] "
                        "--user NAME --password-file FILE --devices FILE [--parallel P] "
                        "[--jobs N]\n");
        return 2;
    }
    perf_gds_load(&g);
    shared *sh = calloc(1, sizeof(*sh));
    device *dev = calloc(MAX_DEVICES, sizeof(*dev));
    pthread_t *tid = calloc(parallel, sizeof(*tid));
    if(!sh || !dev || !tid) {
        free(sh);
        free(dev);
        free(tid);
        return 1;
    }
    sh->g = &g;
    sh->dev = dev;
    sh->devN = load_devices(devFile, dev);
    if(sh->devN == 0) {
        fprintf(stderr, "load_push: no devices in %s\n", devFile);
        free(sh);
        free(dev);
        free(tid);
        return 2;
    }
    sh->jobs = jobs ? jobs : sh->devN;
    perf_samples_init(&sh->total);
    perf_samples_init(&sh->sign);
    perf_errors_init(&sh->err);
    uint64_t t0 = perf_now_ns();
    for(unsigned long i = 0; i < parallel; i++)
        if(pthread_create(&tid[i], NULL, worker, sh) != 0)
            exit(1); /* workers already run on sh */
    for(unsigned long i = 0; i < parallel; i++)
        pthread_join(tid[i], NULL);
    double secs = (double)(perf_now_ns() - t0) / 1e9;
    unsigned long ok = atomic_load(&sh->ok), want = sh->jobs;
    double rate = (double)ok / secs;
    printf("# %lu of %lu pushes to %zu devices with %lu parallel sessions in %.1f s\n", ok,
           sh->jobs, sh->devN, parallel, secs);
    perf_result("push_ok", (double)ok, "pushes");
    perf_result("push_rate", rate, "push/s");
    perf_result("push_servers_per_24h", rate * 86400.0, "servers");
    perf_samples_report(&sh->total, "push_job");
    perf_samples_report(&sh->sign, "push_sign");
    perf_errors_report(&sh->err, "push");
    for(size_t i = 0; i < sh->devN; i++) {
        gds_buf_free(&dev[i].cert);
        pthread_mutex_destroy(&dev[i].lock);
    }
    perf_samples_free(&sh->total);
    perf_samples_free(&sh->sign);
    free(dev);
    free(tid);
    free(sh);
    perf_gds_clear(&g);
    return ok == want ? 0 : 1;
}
