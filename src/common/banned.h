/* OpenGDS - banned functions (docs/architecture.md, "Language and dialect").
 * Include this LAST in every .c file, after all system and library headers.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_COMMON_BANNED_H
#define OPENGDS_COMMON_BANNED_H

#if defined(__GNUC__) || defined(__clang__)
/* FORTIFY_SOURCE (clang) defines some of these as macros: drop them first,
 * nothing after this header may use them anyway */
#undef strcpy
#undef strcat
#undef sprintf
#undef vsprintf
#pragma GCC poison strcpy strcat sprintf vsprintf gets strtok
#pragma GCC poison atoi atol atoll atof
#pragma GCC poison rand srand
#pragma GCC poison system popen tmpnam mktemp
#endif

#endif
