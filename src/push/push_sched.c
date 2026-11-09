/* OpenGDS push engine - when a managed Server needs a job (push_sched.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "push_sched.h"

#include <string.h>

#include "gds_plugin.h"
#include "common/banned.h"

UA_DateTime push_renew_at(UA_DateTime notBefore, UA_DateTime notAfter) {
    if(notAfter <= notBefore)
        return notBefore; /* a broken validity: renew at once */
    return notAfter - (notAfter - notBefore) / 3;
}

UA_DateTime push_backoff(const push_timing *t, uint32_t failures) {
    if(failures == 0 || t->backoffMin <= 0)
        return 0;
    UA_DateTime d = t->backoffMin;
    for(uint32_t i = 1; i < failures && d < t->backoffMax; i++)
        d = d > t->backoffMax / 2 ? t->backoffMax : 2 * d;
    return d < t->backoffMax ? d : t->backoffMax;
}

UA_DateTime push_jitter(const push_timing *t, uint64_t rnd) {
    if(t->jitterMax <= 0)
        return 0;
    return (UA_DateTime)(rnd % ((uint64_t)t->jitterMax + 1));
}

void push_note_trust_list(push_state *st, const uint8_t cur[PUSH_HASH_LEN], UA_DateTime now) {
    bool same = st->tlValid && memcmp(st->tlSent, cur, PUSH_HASH_LEN) == 0;
    if(same)
        st->tlChangedAt = 0;
    else if(st->tlChangedAt == 0)
        st->tlChangedAt = now;
}

static void earliest(UA_DateTime *e, bool *have, UA_DateTime t) {
    if(!*have || t < *e)
        *e = t;
    *have = true;
}

uint32_t push_due(const push_state *st, const push_timing *t, const uint8_t cur[PUSH_HASH_LEN],
                  UA_DateTime now, UA_DateTime *due) {
    *due = 0;
    uint32_t pending = 0;
    UA_DateTime event = 0; /* the earliest pending event, jitter included */
    bool have = false;
    if(!st->known) {
        pending |= GDS_PUSH_CHECK;
        earliest(&event, &have, 1); /* at once: notBefore holds the start-up jitter */
    } else {
        UA_DateTime renew = st->certOurs ? push_renew_at(st->certNotBefore, st->certNotAfter) : 0;
        if(!st->certOurs || now >= renew)
            pending |= GDS_PUSH_RENEW;
        if(pending & GDS_PUSH_RENEW)
            earliest(&event, &have, renew + st->jitter);
        if(!st->tlValid || memcmp(st->tlSent, cur, PUSH_HASH_LEN) != 0) {
            pending |= GDS_PUSH_TRUSTLIST;
            earliest(&event, &have, st->tlChangedAt + st->jitter); /* 0: at once */
        }
        if(t->rejectedInterval > 0 && now >= st->lastRejected + t->rejectedInterval) {
            pending |= GDS_PUSH_REJECTED;
            earliest(&event, &have, st->lastRejected + t->rejectedInterval + st->jitter);
        }
    }
    if(!pending)
        return 0;
    UA_DateTime when = event > st->notBefore ? event : st->notBefore;
    if(now < when)
        return 0;
    *due = when;
    return st->failures ? pending | GDS_PUSH_RETRY : pending;
}

void push_after_job(push_state *st, const push_timing *t, bool ok, UA_DateTime now,
                    uint64_t rnd) {
    st->jitter = push_jitter(t, rnd);
    if(ok) {
        st->failures = 0;
        st->notBefore = now;
        return;
    }
    if(st->failures < UINT32_MAX)
        st->failures++;
    st->notBefore = now + push_backoff(t, st->failures) + st->jitter;
}
