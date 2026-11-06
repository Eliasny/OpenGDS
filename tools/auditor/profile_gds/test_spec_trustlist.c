/* OpenGDS T0 spec tests: trust list distribution (OPC 10000-12 §7.9.8,
 * TrustListType §7.8.2, FileType OPC 10000-5 Annex C).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>
#include <open62541/nodeids_gds.h>

#include "common/limits.h"
#include "gds_target.h"
#include "spec_tests.h"
#include "common/banned.h"

#define URI_LEN (GDS_MAX_APPLICATION_URI + 1)
#define FILE_WRITE_ERASE 0x06

static UA_NodeId default_tl(const gds_target *t) {
    return gt_node(t, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST);
}

static void t_get_trustlist(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    UA_NodeId id;
    UA_StatusCode r = gt_session(t);
    if(r == UA_STATUSCODE_GOOD)
        r = gt_register(t, UA_APPLICATIONTYPE_CLIENT, uri, sizeof(uri), &id);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: RegisterApplication -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_NodeId group = gt_default_group(t);
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &id, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    r = gt_call(t, UA_GDSID_DIRECTORY_GETTRUSTLIST, 2, in, 1, &outN, &out);
    const UA_NodeId *tl = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_NODEID]);
    UA_TrustListDataType data;
    UA_TrustListDataType_init(&data);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "GetTrustList -> %s", UA_StatusCode_name(r));
    } else if(!tl || UA_NodeId_isNull(tl)) {
        ga_fail(ctx, "GetTrustList returned no TrustList NodeId");
    } else if((r = uac_read_trustlist(t->client, *tl, &data)) != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "reading the returned TrustList failed: %s", UA_StatusCode_name(r));
    } else if(data.trustedCertificatesSize + data.issuerCertificatesSize == 0) {
        ga_fail(ctx, "trust list has no CA certificate for the application to trust");
    } else {
        if(data.trustedCrlsSize + data.issuerCrlsSize == 0)
            ga_note(ctx, "no CRL in the trust list (clients cannot check revocation)");
        ga_pass(ctx, "%zu trusted, %zu issuer certificate(s), %zu CRL(s)",
                data.trustedCertificatesSize, data.issuerCertificatesSize,
                data.trustedCrlsSize + data.issuerCrlsSize);
    }
    UA_TrustListDataType_clear(&data);
    gt_free_out(out, outN);
    UA_NodeId_clear(&id);
}

static void t_read_bad_handle(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "session -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_NodeId tl = default_tl(t);
    UA_NodeId mRead = gt_node(t, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_READ);
    UA_UInt32 handle = 0x7fff1234u; /* never handed out */
    UA_Int32 len = 1024;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[1], &len, &UA_TYPES[UA_TYPES_INT32]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    r = UA_Client_call(t->client, tl, mRead, 2, in, &outN, &out);
    gt_free_out(out, outN);
    if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "Read with a file handle that was never opened succeeded");
    else if(r == UA_STATUSCODE_BADINVALIDARGUMENT || r == UA_STATUSCODE_BADINVALIDSTATE)
        ga_pass(ctx, "refused with %s", UA_StatusCode_name(r));
    else
        ga_warn(ctx, "refused with %s; FileType names BadInvalidArgument", UA_StatusCode_name(r));
}

/* Writing the GDS trust lists is an administrator action (§7.8.2) */
static void t_write_anonymous(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_Client *c = gt_new_client(t);
    if(!c) {
        ga_not_tested(ctx, "could not create a client");
        return;
    }
    UA_StatusCode r = UA_Client_connect(c, t->url);
    if(r != UA_STATUSCODE_GOOD) {
        ga_pass(ctx, "anonymous session refused (%s)", UA_StatusCode_name(r));
        UA_Client_delete(c);
        return;
    }
    UA_UInt16 ns = 0;
    r = UA_Client_getNamespaceIndex(c, UA_STRING("http://opcfoundation.org/UA/GDS/"), &ns);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "no GDS namespace: %s", UA_StatusCode_name(r));
        UA_Client_disconnect(c);
        UA_Client_delete(c);
        return;
    }
    UA_NodeId tl = UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST);
    UA_NodeId mOpen = UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPEN);
    UA_Byte mode = FILE_WRITE_ERASE;
    UA_Variant in;
    UA_Variant_setScalar(&in, &mode, &UA_TYPES[UA_TYPES_BYTE]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    r = UA_Client_call(c, tl, mOpen, 1, &in, &outN, &out);
    if(r == UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "an anonymous session opened the GDS trust list for writing");
        const UA_UInt32 *h = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_UINT32]);
        if(h) { /* close without writing */
            UA_NodeId mClose = UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSE);
            UA_Variant cin;
            UA_Variant_setScalar(&cin, (void *)(uintptr_t)h, &UA_TYPES[UA_TYPES_UINT32]);
            size_t cN = 0;
            UA_Variant *cV = NULL;
            if(UA_Client_call(c, tl, mClose, 1, &cin, &cN, &cV) != UA_STATUSCODE_GOOD)
                ga_note(ctx, "Close of the write handle failed");
            gt_free_out(cV, cN);
        }
    } else if(r == UA_STATUSCODE_BADUSERACCESSDENIED || r == UA_STATUSCODE_BADNOTWRITABLE) {
        ga_pass(ctx, "refused with %s", UA_StatusCode_name(r));
    } else {
        ga_warn(ctx, "refused with %s; expected BadUserAccessDenied", UA_StatusCode_name(r));
    }
    gt_free_out(out, outN);
    UA_Client_disconnect(c);
    UA_Client_delete(c);
}

const ga_test spec_trustlist_tests[] = {
    {"gds.tl.get_trustlist", "12 §7.9.9", "GetTrustList returns a readable trust list with the CA",
     true, false, t_get_trustlist},
    {"gds.tl.read_bad_handle", "5 Annex C.2.4", "TrustList Read refuses a handle that was never opened",
     false, false, t_read_bad_handle},
    {"gds.tl.write_anonymous", "12 §7.8.2", "An anonymous session cannot open the GDS trust list for writing",
     false, false, t_write_anonymous},
};
const size_t spec_trustlist_count = GDS_ARRAY_SIZE(spec_trustlist_tests);
