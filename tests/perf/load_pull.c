/* OpenGDS performance test: N concurrent pull agents (OpenGDS plan,
 * "Performance design and targets": 500 concurrent sessions; certificate
 * issuance end to end through opengdsd and opengds-signer).
 *
 * Each agent is a thread with its own SignAndEncrypt UserName session, as a
 * pull client of OPC 10000-12 §7.6 with an administrator's credentials:
 *   1. connect: all N sessions are opened, then held open together; the
 *      number that are open at the same moment is the concurrent-session
 *      result;
 *   2. with every session still open, each agent runs the pull workflow:
 *      RegisterApplication (§6.5.5), StartSigningRequest and FinishRequest
 *      polled every 20 ms (§7.9.4, §7.9.6), GetTrustList and the TrustList
 *      read (§7.9.8, §7.8.2).
 * Latency of each step and the issuance rate (certificates over the wall
 * time of step 2) are reported. Approval must be `auto` in the GDS config.
 *
 * Usage: load_pull <common options> --agents N [--prefix P] [--hold-seconds S]
 * SPDX-License-Identifier: MPL-2.0 */
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "client/gdsc_gds.h"
#include "perf_common.h"
#include "common/banned.h"

typedef struct {
    perf_samples connect, reg, sign, trust, total;
    perf_errors connectErr, regErr, signErr, trustErr;
} stats;

typedef struct {
    const perf_gds *g;
    const gds_buf *csr;
    const char *prefix;
    unsigned long idx;
    pthread_barrier_t *opened, *go;
    stats *st;
    atomic_ulong *open, *issued;
} agent;

static void *run(void *arg) {
    agent *a = arg;
    gdsc_session *s = NULL;
    UA_UInt16 ns = 0;
    uint64_t t0 = perf_now_ns();
    UA_StatusCode r = perf_gds_open(a->g, &s, &ns);
    if(r == UA_STATUSCODE_GOOD) {
        perf_samples_add(&a->st->connect, perf_now_ns() - t0);
        atomic_fetch_add(a->open, 1);
    } else {
        perf_errors_add(&a->st->connectErr, r);
    }
    pthread_barrier_wait(a->opened);
    pthread_barrier_wait(a->go);
    if(!s)
        return NULL;
    UA_Client *c = gdsc_session_client(s);
    char uri[GDS_MAX_APPLICATION_URI];
    if(gds_path(uri, sizeof(uri), "urn:opengds:perf:%s:%lu", a->prefix, a->idx) != GDS_OK) {
        gdsc_session_close(s);
        return NULL;
    }
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    UA_String u, product;
    perf_record(&rec, &name, &u, &product, uri, UA_APPLICATIONTYPE_CLIENT, NULL);
    UA_NodeId id;
    UA_NodeId_init(&id);
    uint64_t start = perf_now_ns(), t = start;
    r = gdsc_register_application(c, ns, &rec, &id);
    perf_samples_add(&a->st->reg, perf_now_ns() - t);
    if(r != UA_STATUSCODE_GOOD) {
        perf_errors_add(&a->st->regErr, r);
        goto out;
    }
    gds_buf cert = {0};
    t = perf_now_ns();
    r = perf_sign(c, ns, &id, a->csr, 20, 120000, &cert);
    perf_samples_add(&a->st->sign, perf_now_ns() - t);
    gds_buf_free(&cert);
    if(r != UA_STATUSCODE_GOOD) {
        perf_errors_add(&a->st->signErr, r);
        goto out;
    }
    atomic_fetch_add(a->issued, 1);
    UA_NodeId group = gdsc_gds_default_group(ns);
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    t = perf_now_ns();
    r = gdsc_get_trust_list(c, ns, &id, &group, &tl);
    perf_samples_add(&a->st->trust, perf_now_ns() - t);
    UA_TrustListDataType_clear(&tl);
    if(r != UA_STATUSCODE_GOOD) {
        perf_errors_add(&a->st->trustErr, r);
        goto out;
    }
    perf_samples_add(&a->st->total, perf_now_ns() - start);
out:
    UA_NodeId_clear(&id);
    gdsc_session_close(s);
    return NULL;
}

int main(int argc, char **argv) {
    perf_gds g;
    memset(&g, 0, sizeof(g));
    unsigned long agents = 0, hold = 2;
    const char *prefix = "pull";
    for(int i = 1; i + 1 < argc; i += 2) {
        if(perf_gds_opt(&g, argv[i], argv[i + 1]))
            continue;
        if(strcmp(argv[i], "--agents") == 0)
            agents = perf_arg_ul(argv[i], argv[i + 1]);
        else if(strcmp(argv[i], "--prefix") == 0)
            prefix = argv[i + 1];
        else if(strcmp(argv[i], "--hold-seconds") == 0)
            hold = perf_arg_ul(argv[i], argv[i + 1]);
        else {
            fprintf(stderr, "load_pull: unknown option %s\n", argv[i]);
            return 2;
        }
    }
    if(argc % 2 == 0 || agents == 0 || agents > 4096) {
        fprintf(stderr, "usage: load_pull --gds URL --cert DER --key DER --trust DER [--crl DER] "
                        "--user NAME --password-file FILE --agents N [--prefix P] "
                        "[--hold-seconds S]\n");
        return 2;
    }
    perf_gds_load(&g);
    gds_buf csr = {0};
    if(!perf_make_csr("urn:opengds:perf:pull", &csr)) {
        fprintf(stderr, "load_pull: cannot make a CSR\n");
        return 1;
    }
    stats st;
    perf_samples_init(&st.connect);
    perf_samples_init(&st.reg);
    perf_samples_init(&st.sign);
    perf_samples_init(&st.trust);
    perf_samples_init(&st.total);
    perf_errors_init(&st.connectErr);
    perf_errors_init(&st.regErr);
    perf_errors_init(&st.signErr);
    perf_errors_init(&st.trustErr);
    atomic_ulong open = 0, issued = 0;
    pthread_barrier_t opened, go;
    pthread_barrier_init(&opened, NULL, (unsigned)agents + 1);
    pthread_barrier_init(&go, NULL, (unsigned)agents + 1);
    agent *a = calloc(agents, sizeof(*a));
    pthread_t *tid = calloc(agents, sizeof(*tid));
    if(!a || !tid) {
        free(a);
        free(tid);
        return 1;
    }
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1u << 20);
    uint64_t c0 = perf_now_ns();
    for(unsigned long i = 0; i < agents; i++) {
        a[i] = (agent){&g, &csr, prefix, i, &opened, &go, &st, &open, &issued};
        if(pthread_create(&tid[i], &attr, run, &a[i]) != 0) {
            fprintf(stderr, "load_pull: thread %lu\n", i);
            return 1;
        }
    }
    pthread_barrier_wait(&opened);
    double connectSecs = (double)(perf_now_ns() - c0) / 1e9;
    unsigned long held = atomic_load(&open);
    printf("# %lu of %lu sessions open at once after %.1f s; holding %lu s\n", held, agents,
           connectSecs, hold);
    sleep((unsigned)hold);
    perf_result("pull_sessions_open", (double)held, "sessions");
    perf_result("pull_connect_wall", connectSecs, "s");
    uint64_t w0 = perf_now_ns();
    pthread_barrier_wait(&go);
    for(unsigned long i = 0; i < agents; i++)
        pthread_join(tid[i], NULL);
    double secs = (double)(perf_now_ns() - w0) / 1e9;
    unsigned long n = atomic_load(&issued);
    printf("# %lu certificates issued in %.1f s\n", n, secs);
    perf_result("pull_issued", (double)n, "certs");
    perf_result("pull_issue_rate", (double)n / secs, "cert/s");
    perf_samples_report(&st.connect, "pull_connect");
    perf_samples_report(&st.reg, "pull_register");
    perf_samples_report(&st.sign, "pull_sign");
    perf_samples_report(&st.trust, "pull_trustlist");
    perf_samples_report(&st.total, "pull_workflow");
    perf_errors_report(&st.connectErr, "connect");
    perf_errors_report(&st.regErr, "register");
    perf_errors_report(&st.signErr, "sign");
    perf_errors_report(&st.trustErr, "trustlist");
    gds_buf_free(&csr);
    free(a);
    free(tid);
    perf_gds_clear(&g);
    return n == agents ? 0 : 1;
}
