/* OpenGDS - the DefaultApplicationGroup TrustList (OPC 10000-12 §7.8.2
 * TrustListType, OPC 10000-20 FileType): Open, OpenWithMasks, Read, Close,
 * GetPosition, SetPosition. The file is the binary TrustListDataType with
 * the CA certificate and its CRL as trusted entries, built at Open.
 * Handles are random, per session, at most GDS_MAX_TL_HANDLES; another
 * session's handle is unknown here.
 * Writing the GDS's own trust list (SecurityAdmin) is not offered in T1.
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include "common/ids.h"
#include "common/limits.h"
#include "gds_internal.h"
#include "common/banned.h"

#define FILE_MODE_READ 0x01u
#define MAX_READ_CHUNK ((size_t)1024 * 1024)

static gds_tl_handle *find_handle(void *sessionContext, UA_UInt32 h) {
    gds_session *s = sessionContext;
    for(size_t i = 0; s && h && i < GDS_SESSION_TL_HANDLES; i++)
        if(s->tl[i].handle == h)
            return &s->tl[i];
    return NULL;
}

UA_StatusCode gds_trustlist_data(gds_server *s, UA_UInt32 masks, UA_TrustListDataType *out) {
    UA_TrustListDataType_init(out);
    gds_buf crl = {0};
    gds_status st = gds_ca_get_crl(s->ca, &crl);
    if(st != GDS_OK)
        return gds_status_to_ua(st);
    UA_ByteString c = {s->caCert.len, s->caCert.data}, l = {crl.len, crl.data};
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    tl.specifiedLists = masks & (UA_UInt32)UA_TRUSTLISTMASKS_ALL;
    if(masks & UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES) {
        tl.trustedCertificates = &c;
        tl.trustedCertificatesSize = 1;
    }
    if(masks & UA_TRUSTLISTMASKS_TRUSTEDCRLS) {
        tl.trustedCrls = &l;
        tl.trustedCrlsSize = 1;
    }
    UA_StatusCode r = UA_TrustListDataType_copy(&tl, out);
    gds_buf_free(&crl);
    return r;
}

static UA_StatusCode build_file(gds_server *s, UA_UInt32 masks, UA_ByteString *out) {
    UA_TrustListDataType tl;
    UA_StatusCode r = gds_trustlist_data(s, masks, &tl);
    *out = UA_BYTESTRING_NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_encodeBinary(&tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], out, NULL);
    UA_TrustListDataType_clear(&tl);
    return r;
}

static UA_StatusCode open_file(gds_server *s, void *sessionContext, UA_UInt32 masks,
                               UA_Variant *output) {
    gds_session *sess = sessionContext;
    gds_tl_handle *slot = NULL;
    for(size_t i = 0; sess && i < GDS_SESSION_TL_HANDLES && !slot; i++)
        if(sess->tl[i].handle == 0)
            slot = &sess->tl[i];
    if(!slot)
        return UA_STATUSCODE_BADTOOMANYOPERATIONS; /* per-session handle limit */
    UA_UInt32 h = 0;
    do {
        if(gds_handle_random(&h) != GDS_OK)
            return UA_STATUSCODE_BADINTERNALERROR;
    } while(find_handle(sessionContext, h));
    UA_ByteString file;
    UA_StatusCode r = build_file(s, masks, &file);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[0], &h, &UA_TYPES[UA_TYPES_UINT32]);
    if(r != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&file);
        return r;
    }
    slot->handle = h;
    slot->file = file;
    slot->pos = 0;
    return UA_STATUSCODE_GOOD;
}

static GDS_METHOD(tl_open) {
    GDS_METHOD_UNUSED;
    if(inputSize < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const void *p = NULL;
    if(gds_arg_scalar(&input[0], &UA_TYPES[UA_TYPES_BYTE], &p) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Byte mode = *(const UA_Byte *)p;
    if(mode != FILE_MODE_READ) {
        /* any write, erase or append mode */
        return gds_session_has(sessionContext, GDS_ROLE_SECURITY_ADMIN)
                   ? UA_STATUSCODE_BADNOTWRITABLE
                   : UA_STATUSCODE_BADUSERACCESSDENIED;
    }
    return open_file(gds_ctx(methodContext), sessionContext, UA_TRUSTLISTMASKS_ALL, output);
}

static GDS_METHOD(tl_open_with_masks) {
    GDS_METHOD_UNUSED;
    if(inputSize < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const void *p = NULL;
    if(gds_arg_scalar(&input[0], &UA_TYPES[UA_TYPES_UINT32], &p) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_UInt32 masks = *(const UA_UInt32 *)p;
    if(masks & ~(UA_UInt32)UA_TRUSTLISTMASKS_ALL)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return open_file(gds_ctx(methodContext), sessionContext, masks, output);
}

static UA_StatusCode handle_arg(void *sessionContext, size_t inputSize, const UA_Variant *input,
                                gds_tl_handle **out) {
    if(inputSize < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const void *p = NULL;
    if(gds_arg_scalar(&input[0], &UA_TYPES[UA_TYPES_UINT32], &p) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    *out = find_handle(sessionContext, *(const UA_UInt32 *)p);
    return *out ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINVALIDARGUMENT;
}

static GDS_METHOD(tl_read) {
    GDS_METHOD_UNUSED;
    (void)methodContext;
    gds_tl_handle *h = NULL;
    UA_StatusCode r = handle_arg(sessionContext, inputSize, input, &h);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const void *p = NULL;
    if(inputSize < 2)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if(gds_arg_scalar(&input[1], &UA_TYPES[UA_TYPES_INT32], &p) != UA_STATUSCODE_GOOD ||
       *(const UA_Int32 *)p < 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    size_t want = (size_t)*(const UA_Int32 *)p;
    GDS_ASSERT(h->pos <= h->file.length);
    size_t n = h->file.length - h->pos;
    if(n > want)
        n = want;
    if(n > MAX_READ_CHUNK)
        n = MAX_READ_CHUNK; /* a shorter Read is allowed; empty means end of file */
    UA_ByteString chunk = {n, n ? h->file.data + h->pos : NULL};
    r = UA_Variant_setScalarCopy(&output[0], &chunk, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        h->pos += n;
    return r;
}

static GDS_METHOD(tl_close) {
    GDS_METHOD_UNUSED;
    (void)methodContext, (void)output;
    gds_tl_handle *h = NULL;
    UA_StatusCode r = handle_arg(sessionContext, inputSize, input, &h);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_ByteString_clear(&h->file);
    memset(h, 0, sizeof(*h));
    return UA_STATUSCODE_GOOD;
}

static GDS_METHOD(tl_get_position) {
    GDS_METHOD_UNUSED;
    (void)methodContext;
    gds_tl_handle *h = NULL;
    UA_StatusCode r = handle_arg(sessionContext, inputSize, input, &h);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_UInt64 pos = h->pos;
    return UA_Variant_setScalarCopy(&output[0], &pos, &UA_TYPES[UA_TYPES_UINT64]);
}

static GDS_METHOD(tl_set_position) {
    GDS_METHOD_UNUSED;
    (void)methodContext, (void)output;
    gds_tl_handle *h = NULL;
    UA_StatusCode r = handle_arg(sessionContext, inputSize, input, &h);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const void *p = NULL;
    if(inputSize < 2)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if(gds_arg_scalar(&input[1], &UA_TYPES[UA_TYPES_UINT64], &p) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_UInt64 pos = *(const UA_UInt64 *)p;
    h->pos = pos > h->file.length ? h->file.length : (size_t)pos; /* past the end: at the end */
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode gds_trustlist_install(gds_server *s) {
    static const gds_method_entry m[] = {
        {UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPEN, tl_open},
        {UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPENWITHMASKS,
         tl_open_with_masks},
        {UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_READ, tl_read},
        {UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSE, tl_close},
        {UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_GETPOSITION,
         tl_get_position},
        {UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_SETPOSITION,
         tl_set_position},
    };
    return gds_install_methods(s, m, GDS_ARRAY_SIZE(m));
}
