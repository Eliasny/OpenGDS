/* OpenGDS - compiler attributes used by the C rules (docs/architecture.md).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_COMMON_COMPILER_H
#define OPENGDS_COMMON_COMPILER_H

#include <stdio.h>
#include <stdlib.h>

#if defined(__GNUC__) || defined(__clang__)
#define GDS_MUST_CHECK __attribute__((warn_unused_result))
#ifdef __MINGW32__ /* __USE_MINGW_ANSI_STDIO: C99 formats such as %zu */
#define GDS_FORMAT(fmtIdx, argIdx) __attribute__((format(gnu_printf, fmtIdx, argIdx)))
#else
#define GDS_FORMAT(fmtIdx, argIdx) __attribute__((format(printf, fmtIdx, argIdx)))
#endif
#define GDS_NORETURN __attribute__((noreturn))
#define GDS_UNUSED __attribute__((unused))
#else
#define GDS_MUST_CHECK
#define GDS_FORMAT(fmtIdx, argIdx)
#define GDS_NORETURN
#define GDS_UNUSED
#endif

/* Broken invariant: memory may already be corrupt, so stop. Kept in release
 * builds. Never used for input errors. */
#define GDS_ASSERT(cond)                                                       \
    do {                                                                       \
        if(!(cond)) {                                                          \
            fprintf(stderr, "%s:%d: invariant failed: %s\n", __FILE__,         \
                    __LINE__, #cond);                                          \
            abort();                                                           \
        }                                                                      \
    } while(0)

#define GDS_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#endif
