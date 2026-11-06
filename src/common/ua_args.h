/* OpenGDS - checks for method arguments and method results (open62541).
 * Rule: never touch Variant.data before its type, shape and length are
 * checked (docs/architecture.md, "Input validation and limits").
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_COMMON_UA_ARGS_H
#define OPENGDS_COMMON_UA_ARGS_H

#include <open62541/types.h>

#include "compiler.h"
#include "errors.h"

/* Scalar of exactly this type. *out borrows from v. */
GDS_MUST_CHECK UA_StatusCode gds_arg_scalar(const UA_Variant *v, const UA_DataType *type,
                                            const void **out);

/* Array of this type (an empty array of any type counts as empty) with at
 * most maxLen elements. *out borrows from v and is NULL when *len is 0. */
GDS_MUST_CHECK UA_StatusCode gds_arg_array(const UA_Variant *v, const UA_DataType *type,
                                           size_t maxLen, const void **out, size_t *len);

/* ByteString scalar no longer than maxLen. A null ByteString is allowed and
 * returned with length 0. */
GDS_MUST_CHECK UA_StatusCode gds_arg_bytes(const UA_Variant *v, size_t maxLen,
                                           const UA_ByteString **out);

/* String scalar no longer than maxLen, without embedded NUL bytes. */
GDS_MUST_CHECK UA_StatusCode gds_arg_string(const UA_Variant *v, size_t maxLen,
                                            const UA_String **out);

/* The one map from the internal error model to OPC UA status codes. */
UA_StatusCode gds_status_to_ua(gds_status s);

#endif
