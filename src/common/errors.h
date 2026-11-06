/* OpenGDS - internal error model (docs/architecture.md, "Error handling").
 * One enum, one map to UA_StatusCode (in errors_ua.h, for code that links
 * open62541).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_COMMON_ERRORS_H
#define OPENGDS_COMMON_ERRORS_H

typedef enum {
    GDS_OK = 0,
    GDS_ENOMEM,      /* allocation failed */
    GDS_EOVERFLOW,   /* size arithmetic overflowed */
    GDS_ETOOBIG,     /* input above a limit in limits.h */
    GDS_EINVAL,      /* malformed or wrong-typed input */
    GDS_ENOTFOUND,   /* file, record or node missing */
    GDS_EIO,         /* file system error */
    GDS_ECRYPTO,     /* OpenSSL refused (details in the log, never on the wire) */
    GDS_EDENIED,     /* access refused */
    GDS_ESTATE,      /* operation not valid in the current state */
    GDS_EREMOTE      /* the peer returned an error or a malformed result */
} gds_status;

const char *gds_status_name(gds_status s);

#endif
