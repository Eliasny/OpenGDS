/* OpenGDS push engine - when a managed Server needs a job (OpenGDS plan
 * push_engine.c: renew when a third of the lifetime is left, re-push on
 * trust-list or CRL change, back-off on failure, random jitter on every
 * job). Pure functions over one target's state, so the timing rules are
 * unit-tested without a network (tests/unit/test_push_sched.c).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_PUSH_SCHED_H
#define OPENGDS_PUSH_SCHED_H

#include <open62541/types.h>

#include <stdbool.h>
#include <stdint.h>

#define PUSH_HASH_LEN 32 /* SHA-256 of the encoded trust list */

typedef struct {
    UA_DateTime jitterMax;  /* every job's random delay is in [0, jitterMax] */
    UA_DateTime backoffMin; /* after the first failure */
    UA_DateTime backoffMax; /* the back-off doubles up to this */
    UA_DateTime rejectedInterval; /* GetRejectedList period; 0: never */
} push_timing;

/* What the engine knows about one Server. Zeroed: nothing (CHECK). */
typedef struct {
    bool known;               /* a job connected and looked at the Server */
    bool certOurs;            /* the Server presents a GDS-issued certificate */
    UA_DateTime certNotBefore, certNotAfter; /* of the presented certificate */
    bool tlValid;             /* tlSent is the list the Server holds */
    uint8_t tlSent[PUSH_HASH_LEN];
    UA_DateTime tlChangedAt;  /* when the engine first saw another list; 0 none */
    UA_DateTime lastRejected; /* last GetRejectedList; 0 never */
    UA_DateTime notBefore;    /* no job before this (back-off, jitter) */
    UA_DateTime jitter;       /* this target's delay for the next event */
    uint32_t failures;        /* consecutive */
} push_state;

/* notAfter - lifetime / 3: the renewal time of a certificate. */
UA_DateTime push_renew_at(UA_DateTime notBefore, UA_DateTime notAfter);
/* backoffMin * 2^(failures - 1), at most backoffMax; 0 for no failures. */
UA_DateTime push_backoff(const push_timing *t, uint32_t failures);
/* Notes that the current trust list hashes to cur (sets tlChangedAt the
 * first time it differs from what the Server holds). */
void push_note_trust_list(push_state *st, const uint8_t cur[PUSH_HASH_LEN], UA_DateTime now);
/* GDS_PUSH_* reasons due at now (0: nothing) and *due, the time the job
 * became due (jitter and back-off included). */
uint32_t push_due(const push_state *st, const push_timing *t, const uint8_t cur[PUSH_HASH_LEN],
                  UA_DateTime now, UA_DateTime *due);
/* After a job: Good resets the failures; a failure counts one and waits
 * for the back-off. Either way the jitter is drawn again from rnd (a
 * uniform 64-bit random number). */
void push_after_job(push_state *st, const push_timing *t, bool ok, UA_DateTime now,
                    uint64_t rnd);
/* A uniform delay in [0, jitterMax] from rnd. */
UA_DateTime push_jitter(const push_timing *t, uint64_t rnd);

#endif
