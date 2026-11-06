/* OpenGDS - checks for method arguments and method results (open62541).
 * SPDX-License-Identifier: MPL-2.0 */
#include "ua_args.h"

#include <string.h>

#include "banned.h"

UA_StatusCode gds_arg_scalar(const UA_Variant *v, const UA_DataType *type,
                             const void **out) {
    *out = NULL;
    if(!v || v->type != type || !UA_Variant_isScalar(v) || !v->data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    *out = v->data;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode gds_arg_array(const UA_Variant *v, const UA_DataType *type,
                            size_t maxLen, const void **out, size_t *len) {
    *out = NULL;
    *len = 0;
    if(!v)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(UA_Variant_isEmpty(v))
        return UA_STATUSCODE_GOOD;
    /* An empty array of structures arrives as ExtensionObject[0]: the wire
     * carries no element to name the type, so any empty array is empty. */
    if(!UA_Variant_isScalar(v) && v->arrayLength == 0)
        return UA_STATUSCODE_GOOD;
    if(v->type != type || UA_Variant_isScalar(v))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(v->arrayLength > maxLen)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    if(v->arrayLength == 0 || v->data == UA_EMPTY_ARRAY_SENTINEL)
        return UA_STATUSCODE_GOOD;
    if(!v->data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    *out = v->data;
    *len = v->arrayLength;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode gds_arg_bytes(const UA_Variant *v, size_t maxLen, const UA_ByteString **out) {
    const void *p = NULL;
    UA_StatusCode r = gds_arg_scalar(v, &UA_TYPES[UA_TYPES_BYTESTRING], &p);
    *out = NULL;
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_ByteString *b = p;
    if(b->length > maxLen)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    *out = b;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode gds_arg_string(const UA_Variant *v, size_t maxLen, const UA_String **out) {
    const void *p = NULL;
    UA_StatusCode r = gds_arg_scalar(v, &UA_TYPES[UA_TYPES_STRING], &p);
    *out = NULL;
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_String *s = p;
    if(s->length > maxLen)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    if(s->length > 0 && memchr(s->data, '\0', s->length))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    *out = s;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode gds_status_to_ua(gds_status s) {
    switch(s) {
    case GDS_OK: return UA_STATUSCODE_GOOD;
    case GDS_ENOMEM: return UA_STATUSCODE_BADOUTOFMEMORY;
    case GDS_EOVERFLOW:
    case GDS_ETOOBIG: return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    case GDS_EINVAL: return UA_STATUSCODE_BADINVALIDARGUMENT;
    case GDS_ENOTFOUND: return UA_STATUSCODE_BADNOTFOUND;
    case GDS_EIO: return UA_STATUSCODE_BADINTERNALERROR;
    case GDS_ECRYPTO: return UA_STATUSCODE_BADCERTIFICATEINVALID;
    case GDS_EDENIED: return UA_STATUSCODE_BADUSERACCESSDENIED;
    case GDS_ESTATE: return UA_STATUSCODE_BADINVALIDSTATE;
    case GDS_EREMOTE: return UA_STATUSCODE_BADUNEXPECTEDERROR;
    case GDS_EEXISTS: return UA_STATUSCODE_BADALREADYEXISTS;
    case GDS_ENOTLEADER: return UA_STATUSCODE_BADINVALIDSTATE; /* clients retry on the primary */
    case GDS_EUNSUPPORTED: return UA_STATUSCODE_BADNOTSUPPORTED;
    }
    return UA_STATUSCODE_BADINTERNALERROR;
}
