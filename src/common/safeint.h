/* OpenGDS - checked size arithmetic (rule: every size computation is checked).
 * Same semantics as C23 ckd_add/ckd_mul: returns true on overflow.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_COMMON_SAFEINT_H
#define OPENGDS_COMMON_SAFEINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "compiler.h"

static inline GDS_MUST_CHECK bool
gds_add_size(size_t a, size_t b, size_t *out) {
    return __builtin_add_overflow(a, b, out);
}

static inline GDS_MUST_CHECK bool
gds_mul_size(size_t a, size_t b, size_t *out) {
    return __builtin_mul_overflow(a, b, out);
}

/* Parse a decimal number in [min, max]. Returns false on any error
 * (replaces atoi/atol, which are banned). */
GDS_MUST_CHECK bool gds_parse_long(const char *s, long min, long max, long *out);

#endif
