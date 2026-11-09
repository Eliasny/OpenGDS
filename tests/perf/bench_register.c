/* OpenGDS performance test: RegisterApplication throughput over OPC UA
 * (OpenGDS plan, "Performance design and targets": 1,000 per second;
 * 50,000 registered applications). OPC 10000-12 §6.5.5.
 *
 * T threads each open one SignAndEncrypt UserName session (a
 * DiscoveryAdmin) and register their share of `count` Client records with
 * distinct ApplicationUris urn:opengds:perf:<prefix>:<i>. The session set-up
 * is not timed; the rate is registrations over the wall time from the first
 * call to the last answer. Afterwards FindApplications for a few URIs
 * times the lookup at the store's final size.
 *
 * Usage: bench_register <common options> --count N [--threads T] [--prefix P]
 * SPDX-License-Identifier: MPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client/gdsc_gds.h"
#include "perf_common.h"
#include "common/banned.h"

typedef struct {
    const perf_gds *g;
    const char *prefix;
    unsigned long first, n;
    pthread_barrier_t *ready;
    perf_samples *lat;
    perf_errors *err;
    unsigned long ok;
} worker;

static void *run(void *arg) {
    worker *w = arg;
    gdsc_session *s = NULL;
    UA_UInt16 ns = 0;
    UA_StatusCode r = perf_gds_open(w->g, &s, &ns);
    if(r != UA_STATUSCODE_GOOD) {
        perf_errors_add(w->err, r);
        fprintf(stderr, "bench_register: session: %s\n", UA_StatusCode_name(r));
    }
    pthread_barrier_wait(w->ready);
    for(unsigned long i = w->first; s && i < w->first + w->n; i++) {
        char uri[GDS_MAX_APPLICATION_URI];
        if(gds_path(uri, sizeof(uri), "urn:opengds:perf:%s:%lu", w->prefix, i) != GDS_OK)
            break;
        UA_ApplicationRecordDataType rec;
        UA_LocalizedText name;
        UA_String u, product;
        perf_record(&rec, &name, &u, &product, uri, UA_APPLICATIONTYPE_CLIENT, NULL);
        UA_NodeId id;
        UA_NodeId_init(&id);
        uint64_t t0 = perf_now_ns();
        r = gdsc_register_application(gdsc_session_client(s), ns, &rec, &id);
        perf_samples_add(w->lat, perf_now_ns() - t0);
        UA_NodeId_clear(&id);
        if(r == UA_STATUSCODE_GOOD)
            w->ok++;
        else
            perf_errors_add(w->err, r);
    }
    gdsc_session_close(s);
    return NULL;
}

static void lookups(const perf_gds *g, const char *prefix, unsigned long count) {
    gdsc_session *s = NULL;
    UA_UInt16 ns = 0;
    if(count == 0 || perf_gds_open(g, &s, &ns) != UA_STATUSCODE_GOOD)
        return;
    perf_samples lat;
    perf_samples_init(&lat);
    for(unsigned long k = 0; k < 200; k++) {
        char uri[GDS_MAX_APPLICATION_URI];
        if(gds_path(uri, sizeof(uri), "urn:opengds:perf:%s:%lu", prefix,
                    (k * 7919u) % count) != GDS_OK)
            break;
        UA_ApplicationRecordDataType *recs = NULL;
        size_t n = 0;
        uint64_t t0 = perf_now_ns();
        UA_StatusCode r = gdsc_find_applications(gdsc_session_client(s), ns, uri, &recs, &n);
        perf_samples_add(&lat, perf_now_ns() - t0);
        if(r == UA_STATUSCODE_GOOD)
            UA_Array_delete(recs, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    }
    perf_samples_report(&lat, "find_applications");
    perf_samples_free(&lat);
    gdsc_session_close(s);
}

int main(int argc, char **argv) {
    perf_gds g;
    memset(&g, 0, sizeof(g));
    unsigned long count = 0, threads = 16;
    const char *prefix = "app";
    for(int i = 1; i + 1 < argc; i += 2) {
        if(perf_gds_opt(&g, argv[i], argv[i + 1]))
            continue;
        if(strcmp(argv[i], "--count") == 0)
            count = perf_arg_ul(argv[i], argv[i + 1]);
        else if(strcmp(argv[i], "--threads") == 0)
            threads = perf_arg_ul(argv[i], argv[i + 1]);
        else if(strcmp(argv[i], "--prefix") == 0)
            prefix = argv[i + 1];
        else {
            fprintf(stderr, "bench_register: unknown option %s\n", argv[i]);
            return 2;
        }
    }
    if(argc % 2 == 0 || count == 0 || threads == 0 || threads > 1024) {
        fprintf(stderr, "usage: bench_register --gds URL --cert DER --key DER --trust DER "
                        "[--crl DER] --user NAME --password-file FILE --count N "
                        "[--threads T] [--prefix P]\n");
        return 2;
    }
    perf_gds_load(&g);
    worker *w = calloc(threads, sizeof(*w));
    pthread_t *tid = calloc(threads, sizeof(*tid));
    if(!w || !tid) {
        free(w);
        free(tid);
        return 1;
    }
    perf_samples lat;
    perf_errors err;
    perf_samples_init(&lat);
    perf_errors_init(&err);
    pthread_barrier_t ready;
    pthread_barrier_init(&ready, NULL, (unsigned)threads + 1);
    unsigned long per = count / threads, extra = count % threads, next = 0;
    for(unsigned long t = 0; t < threads; t++) {
        w[t] = (worker){&g, prefix, next, per + (t < extra), &ready, &lat, &err, 0};
        next += w[t].n;
        if(pthread_create(&tid[t], NULL, run, &w[t]) != 0)
            return 1;
    }
    pthread_barrier_wait(&ready); /* every session is open */
    uint64_t t0 = perf_now_ns();
    unsigned long ok = 0;
    for(unsigned long t = 0; t < threads; t++) {
        pthread_join(tid[t], NULL);
        ok += w[t].ok;
    }
    double secs = (double)(perf_now_ns() - t0) / 1e9;
    printf("# %lu of %lu registered by %lu sessions in %.1f s\n", ok, count, threads, secs);
    perf_result("register_rate", (double)ok / secs, "reg/s");
    perf_result("register_ok", (double)ok, "apps");
    perf_samples_report(&lat, "register");
    perf_errors_report(&err, "register");
    lookups(&g, prefix, count);
    perf_samples_free(&lat);
    free(w);
    free(tid);
    perf_gds_clear(&g);
    return ok == count ? 0 : 1;
}
