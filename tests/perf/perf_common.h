/* OpenGDS performance tests - shared helpers (OpenGDS plan, "Performance
 * design and targets"; docs/perf.md).
 *
 * Every tool prints its measurements as `RESULT <name> <value> <unit>`
 * lines, which run_perf.sh collects into one table. The tools measure; they
 * never change product behaviour.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_PERF_COMMON_H
#define OPENGDS_PERF_COMMON_H
#include <open62541/client.h>
#include <open62541/types_gds_generated.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/buf.h"
#include "client/gdsc_session.h"

/* Monotonic clock in nanoseconds */
uint64_t perf_now_ns(void);

/* Latency samples (ns), thread-safe append. */
typedef struct {
    pthread_mutex_t lock;
    uint64_t *v;
    size_t n, cap;
} perf_samples;
void perf_samples_init(perf_samples *s);
void perf_samples_add(perf_samples *s, uint64_t ns);
void perf_samples_free(perf_samples *s);
/* Print p50/p95/p99/max in ms as RESULT lines named <name>_p50_ms ... */
void perf_samples_report(perf_samples *s, const char *name);

/* Status codes seen, counted (thread-safe), printed as `ERRORS` lines. */
#define PERF_MAX_CODES 16
typedef struct {
    pthread_mutex_t lock;
    UA_StatusCode code[PERF_MAX_CODES];
    unsigned long count[PERF_MAX_CODES];
    unsigned long other;
} perf_errors;
void perf_errors_init(perf_errors *e);
void perf_errors_add(perf_errors *e, UA_StatusCode c);
unsigned long perf_errors_total(perf_errors *e);
void perf_errors_report(perf_errors *e, const char *what);

void perf_result(const char *name, double value, const char *unit);

/* Unsigned option value; exits with a message on a bad number. */
unsigned long perf_arg_ul(const char *opt, const char *v);

/* What a tool needs to open a GDS session as an administrator: the GDS URL,
 * a client certificate and key (DER; any certificate the GDS accepts for a
 * UserName session), the GDS CA and CRL, and a user name and password file.
 * The common options are
 *   --gds URL --cert DER --key DER --trust DER [--crl DER]
 *   --user NAME --password-file FILE */
typedef struct {
    const char *url, *certFile, *keyFile, *trustFile, *crlFile, *user, *passwordFile;
    gds_buf cert, key, trust, crl, password;
} perf_gds;
/* Take one common option (opt, v) into g; false: not a common option. */
bool perf_gds_opt(perf_gds *g, const char *opt, const char *v);
/* Read the files; exits on error. */
void perf_gds_load(perf_gds *g);
void perf_gds_clear(perf_gds *g);
/* Open a SignAndEncrypt UserName session and bind the GDS namespace. */
UA_StatusCode perf_gds_open(const perf_gds *g, gdsc_session **out, UA_UInt16 *ns);

/* An RSA-2048 key and a PKCS#10 CSR for it (the GDS takes only the public
 * key from a CSR, OPC 10000-12 §7.9.3, so one CSR serves every record). */
bool perf_make_csr(const char *appUri, gds_buf *csrOut);

/* A Client application record with this URI (strings borrowed; *name and
 * the record live in the caller). */
void perf_record(UA_ApplicationRecordDataType *rec, UA_LocalizedText *name, UA_String *uri,
                 UA_String *product, const char *uriText, UA_ApplicationType type,
                 UA_String *discoveryUrl);

/* StartSigningRequest then FinishRequest every pollMs until the certificate
 * arrives (Bad_NothingToDo while pending, §7.9.6) or timeoutMs passes.
 * Unlike gdsc_sign_csr (1 s steps) the poll is fine-grained so latency is
 * measured, not quantised. */
UA_StatusCode perf_sign(UA_Client *c, UA_UInt16 ns, const UA_NodeId *appId, const gds_buf *csr,
                        unsigned pollMs, unsigned timeoutMs, gds_buf *certOut);

/* VmRSS of a process in KiB, 0 if unknown */
unsigned long perf_rss_kib(long pid);
#endif
