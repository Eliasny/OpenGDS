/* OpenGDS unit test: the push engine's timing rules (src/push/push_sched.c;
 * OpenGDS plan push_engine.c): renew when a third of the certificate's
 * lifetime is left, push the trust list again when it changes, read the
 * rejected list periodically, back off exponentially after failures, add
 * jitter to every job; and the built-in scheduler (earliest first).
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include "check.h"
#include "gds_plugin.h"
#include "push_sched.h"
#include "common/banned.h"

#define SEC UA_DATETIME_SEC
#define DAY (86400LL * SEC)
#define T0 ((UA_DateTime)1000 * DAY) /* some "now" */

static const push_timing timing = {
    .jitterMax = 300 * SEC,
    .backoffMin = 60 * SEC,
    .backoffMax = 3600 * SEC,
    .rejectedInterval = 3600 * SEC,
};

static uint8_t tlA[PUSH_HASH_LEN], tlB[PUSH_HASH_LEN];

static push_state known_state(void) {
    push_state st;
    memset(&st, 0, sizeof(st));
    st.known = true;
    st.certOurs = true;
    st.certNotBefore = T0 - 10 * DAY;
    st.certNotAfter = T0 + 290 * DAY; /* 300 days; renew at T0 + 190 days */
    st.tlValid = true;
    memcpy(st.tlSent, tlA, PUSH_HASH_LEN);
    st.lastRejected = T0;
    return st;
}

static void test_renew_at(void) {
    CHECK_EQ_INT(push_renew_at(0, 300 * DAY), 200 * DAY);
    CHECK_EQ_INT(push_renew_at(T0, T0 + 3 * DAY), T0 + 2 * DAY);
    CHECK_EQ_INT(push_renew_at(T0, T0), T0); /* broken validity: at once */
    CHECK_EQ_INT(push_renew_at(T0, T0 - 1), T0);
}

static void test_backoff(void) {
    CHECK_EQ_INT(push_backoff(&timing, 0), 0);
    CHECK_EQ_INT(push_backoff(&timing, 1), 60 * SEC);
    CHECK_EQ_INT(push_backoff(&timing, 2), 120 * SEC);
    CHECK_EQ_INT(push_backoff(&timing, 6), 1920 * SEC);
    CHECK_EQ_INT(push_backoff(&timing, 7), 3600 * SEC); /* capped */
    CHECK_EQ_INT(push_backoff(&timing, 4000000000u), 3600 * SEC);
}

static void test_jitter(void) {
    CHECK_EQ_INT(push_jitter(&timing, 0), 0);
    CHECK(push_jitter(&timing, UINT64_MAX) <= 300 * SEC);
    for(uint64_t r = 1; r < 1000000; r *= 7)
        CHECK(push_jitter(&timing, r * 0x9E3779B97F4A7C15ULL) <= timing.jitterMax);
    push_timing none = timing;
    none.jitterMax = 0;
    CHECK_EQ_INT(push_jitter(&none, 12345), 0);
}

static void test_first_look(void) {
    push_state st;
    memset(&st, 0, sizeof(st));
    st.notBefore = T0 + 100 * SEC; /* the start-up jitter */
    UA_DateTime due = 0;
    CHECK_EQ_INT(push_due(&st, &timing, tlA, T0, &due), 0);
    CHECK_EQ_INT(push_due(&st, &timing, tlA, T0 + 100 * SEC, &due), GDS_PUSH_CHECK);
    CHECK_EQ_INT(due, T0 + 100 * SEC);
}

static void test_renewal(void) {
    push_timing tm = timing;
    tm.rejectedInterval = 0; /* only the certificate here */
    push_state st = known_state();
    UA_DateTime due = 0;
    CHECK_EQ_INT(push_due(&st, &tm, tlA, T0, &due), 0);
    CHECK_EQ_INT(push_due(&st, &tm, tlA, T0 + 190 * DAY - SEC, &due), 0);
    CHECK_EQ_INT(push_due(&st, &tm, tlA, T0 + 190 * DAY, &due), GDS_PUSH_RENEW);
    CHECK_EQ_INT(due, T0 + 190 * DAY);
    /* with jitter: later by exactly the target's jitter */
    st.jitter = 42 * SEC;
    CHECK_EQ_INT(push_due(&st, &tm, tlA, T0 + 190 * DAY, &due), 0);
    CHECK_EQ_INT(push_due(&st, &tm, tlA, T0 + 190 * DAY + 42 * SEC, &due), GDS_PUSH_RENEW);
    CHECK_EQ_INT(due, T0 + 190 * DAY + 42 * SEC);
    /* not the GDS's certificate: at once */
    st = known_state();
    st.certOurs = false;
    CHECK_EQ_INT(push_due(&st, &tm, tlA, T0, &due), GDS_PUSH_RENEW);
}

static void test_trust_list_change(void) {
    push_state st = known_state();
    st.jitter = 10 * SEC;
    UA_DateTime due = 0;
    push_note_trust_list(&st, tlA, T0);
    CHECK_EQ_INT(st.tlChangedAt, 0);
    push_note_trust_list(&st, tlB, T0 + SEC); /* a CRL or an entry changed */
    CHECK_EQ_INT(st.tlChangedAt, T0 + SEC);
    push_note_trust_list(&st, tlB, T0 + 5 * SEC); /* noted once */
    CHECK_EQ_INT(st.tlChangedAt, T0 + SEC);
    CHECK_EQ_INT(push_due(&st, &timing, tlB, T0 + 5 * SEC, &due), 0);
    CHECK_EQ_INT(push_due(&st, &timing, tlB, T0 + 11 * SEC, &due), GDS_PUSH_TRUSTLIST);
    CHECK_EQ_INT(due, T0 + 11 * SEC);
    /* back to what the Server holds: nothing to do */
    push_note_trust_list(&st, tlA, T0 + 12 * SEC);
    CHECK_EQ_INT(st.tlChangedAt, 0);
    CHECK_EQ_INT(push_due(&st, &timing, tlA, T0 + 12 * SEC, &due), 0);
    /* the Server's list was never confirmed: due */
    st.tlValid = false;
    CHECK(push_due(&st, &timing, tlA, T0 + 20 * SEC, &due) & GDS_PUSH_TRUSTLIST);
}

static void test_rejected_period(void) {
    push_state st = known_state();
    UA_DateTime due = 0;
    CHECK_EQ_INT(push_due(&st, &timing, tlA, T0 + 3599 * SEC, &due), 0);
    CHECK_EQ_INT(push_due(&st, &timing, tlA, T0 + 3600 * SEC, &due), GDS_PUSH_REJECTED);
    push_timing never = timing;
    never.rejectedInterval = 0;
    CHECK_EQ_INT(push_due(&st, &never, tlA, T0 + 100 * DAY, &due), 0);
}

static void test_failures(void) {
    push_state st = known_state();
    st.certOurs = false; /* due at once */
    UA_DateTime due = 0;
    CHECK_EQ_INT(push_due(&st, &timing, tlA, T0, &due), GDS_PUSH_RENEW);
    push_after_job(&st, &timing, false, T0, 0); /* jitter 0 */
    CHECK_EQ_INT(st.failures, 1);
    CHECK_EQ_INT(st.notBefore, T0 + 60 * SEC);
    CHECK_EQ_INT(push_due(&st, &timing, tlA, T0 + 59 * SEC, &due), 0);
    CHECK_EQ_INT(push_due(&st, &timing, tlA, T0 + 60 * SEC, &due),
                 GDS_PUSH_RENEW | GDS_PUSH_RETRY);
    push_after_job(&st, &timing, false, T0 + 60 * SEC, 0);
    CHECK_EQ_INT(st.failures, 2);
    CHECK_EQ_INT(st.notBefore, T0 + 180 * SEC); /* 120 s later */
    /* the jitter comes on top of the back-off */
    push_after_job(&st, &timing, false, T0 + 180 * SEC, 7 * SEC);
    CHECK_EQ_INT(st.jitter, 7 * SEC);
    CHECK_EQ_INT(st.notBefore, T0 + 180 * SEC + 240 * SEC + 7 * SEC);
    /* success: failures reset, the next event waits for its jitter */
    push_after_job(&st, &timing, true, T0 + DAY, 5 * SEC);
    CHECK_EQ_INT(st.failures, 0);
    CHECK_EQ_INT(st.jitter, 5 * SEC);
    CHECK_EQ_INT(st.notBefore, T0 + DAY);
}

static void test_default_scheduler(void) {
    gds_push_job due[5];
    memset(due, 0, sizeof(due));
    size_t picked[3] = {9, 9, 9};
    CHECK_EQ_INT(gds_push_next_jobs_default(NULL, T0, 3, due, 5, picked), 3);
    CHECK(picked[0] == 0 && picked[1] == 1 && picked[2] == 2);
    CHECK_EQ_INT(gds_push_next_jobs_default(NULL, T0, 3, due, 2, picked), 2);
    CHECK_EQ_INT(gds_push_next_jobs_default(NULL, T0, 3, due, 0, picked), 0);
}

int main(void) {
    memset(tlA, 0xA, sizeof(tlA));
    memset(tlB, 0xB, sizeof(tlB));
    test_renew_at();
    test_backoff();
    test_jitter();
    test_first_look();
    test_renewal();
    test_trust_list_change();
    test_rejected_period();
    test_failures();
    test_default_scheduler();
    return CHECK_DONE();
}
