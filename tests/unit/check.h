/* OpenGDS unit tests - minimal checks (abort-free, counted). The checks are
 * functions, not branching macros, so test bodies stay flat for clang-tidy.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_TEST_CHECK_H
#define OPENGDS_TEST_CHECK_H

#include <stdbool.h>
#include <stdio.h>

static int check_failures = 0;

static inline bool check_impl(bool ok, const char *file, int line, const char *expr) {
    if(!ok) {
        fprintf(stderr, "%s:%d: CHECK failed: %s\n", file, line, expr);
        check_failures++;
    }
    return ok;
}

static inline bool check_eq_impl(long long a, long long b, const char *file, int line,
                                 const char *ea, const char *eb) {
    if(a != b) {
        fprintf(stderr, "%s:%d: CHECK failed: %s == %s (%lld != %lld)\n", file, line, ea, eb,
                a, b);
        check_failures++;
    }
    return a == b;
}

static inline int check_done(void) {
    if(check_failures) {
        fprintf(stderr, "%d check(s) failed\n", check_failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}

#define CHECK(cond) check_impl((cond) ? true : false, __FILE__, __LINE__, #cond)
#define CHECK_EQ_INT(a, b)                                                               \
    check_eq_impl((long long)(a), (long long)(b), __FILE__, __LINE__, #a, #b)
#define CHECK_DONE() check_done()

#endif
