/* OpenGDS Auditor server profile: rejected list (srv_rejected.c).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "Rejected list".
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include <open62541/client_highlevel.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "x509util.h"
#include "common/banned.h"

#define PEER_UNKNOWN_URI "urn:opengds:auditor:peer-unknown"
#define PEER_BADSIG_URI "urn:opengds:auditor:peer-badsig"
#define DAG UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP

/* GetRejectedList on obj (ServerConfiguration or a CertificateGroup) as
 * admin: the Certificates output, deep-copied. */
static UA_StatusCode rejected_list(srv_target *t, UA_UInt32 obj, UA_UInt32 method,
                                   UA_ByteString **out, size_t *n) {
    *out = NULL;
    *n = 0;
    UA_StatusCode r = st_admin(t);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    size_t outN = 0;
    UA_Variant *outV = NULL;
    r = UA_Client_call(t->client, UA_NODEID_NUMERIC(0, obj), UA_NODEID_NUMERIC(0, method), 0, NULL,
                       &outN, &outV);
    if(r == UA_STATUSCODE_GOOD) {
        if(outN < 1 || UA_Variant_isScalar(&outV[0]) ||
           (outV[0].type != &UA_TYPES[UA_TYPES_BYTESTRING] && outV[0].arrayLength > 0))
            r = UA_STATUSCODE_BADTYPEMISMATCH;
        else if(outV[0].arrayLength > 0)
            r = UA_Array_copy(outV[0].data, outV[0].arrayLength, (void **)out,
                              &UA_TYPES[UA_TYPES_BYTESTRING]);
        if(r == UA_STATUSCODE_GOOD)
            *n = outV[0].arrayLength;
    }
    UA_Array_delete(outV, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

static bool absent(UA_StatusCode r) {
    return r == UA_STATUSCODE_BADMETHODINVALID || r == UA_STATUSCODE_BADNODEIDUNKNOWN ||
           r == UA_STATUSCODE_BADNOTIMPLEMENTED || r == UA_STATUSCODE_BADNOTSUPPORTED;
}

/* Does an entry hold cert (its first certificate, so a chain also counts)? */
static bool listed(const UA_ByteString *l, size_t n, const gds_buf *cert) {
    X509 *want = x509_parse_cert(cert);
    bool found = false;
    for(size_t i = 0; want && i < n && !found; i++) {
        gds_buf b = {l[i].data, l[i].length};
        X509 *x = x509_parse_cert(&b);
        found = x && X509_cmp(x, want) == 0;
        X509_free(x);
    }
    X509_free(want);
    ERR_clear_error();
    return found;
}

/* A self-signed client identity (cert, key DER); broken: one bit of the
 * signature flipped. */
static gds_status make_peer(const char *cn, const char *uri, bool broken, gds_buf *cert,
                            gds_buf *key) {
    EVP_PKEY *k = EVP_RSA_gen(2048);
    gds_status gs = k ? st_make_leaf(NULL, k, cn, uri, -3600, 7 * 86400L, false, 0, cert)
                      : GDS_ECRYPTO;
    if(gs == GDS_OK)
        gs = x509_key_to_der(k, key);
    EVP_PKEY_free(k);
    ERR_clear_error();
    if(gs == GDS_OK && broken)
        cert->data[cert->len - 1] ^= 0x01; /* the signature's last byte */
    if(gs != GDS_OK) {
        gds_buf_free(cert);
        gds_buf_free_secret(key);
    }
    return gs;
}

/* Connect as a fresh self-signed peer, which the target must refuse; then
 * read the rejected list. *refused: the connection was refused. */
static UA_StatusCode refused_then_list(srv_target *t, const char *cn, const char *uri,
                                       bool broken, bool *refused, gds_buf *cert,
                                       UA_ByteString **l, size_t *n, ga_ctx *ctx) {
    gds_buf key = {0};
    *refused = false;
    gds_status gs = make_peer(cn, uri, broken, cert, &key);
    if(gs != GDS_OK)
        return gds_status_to_ua(gs);
    UA_Client *c = NULL;
    UA_StatusCode r = st_peer_connect(t, cert, &key, &c);
    st_client_free(c);
    gds_buf_free_secret(&key);
    ga_note(ctx, "session as %s -> %s", cn, UA_StatusCode_name(r));
    *refused = r != UA_STATUSCODE_GOOD && st_cert_refusal(r);
    if(!*refused)
        return UA_STATUSCODE_GOOD;
    r = rejected_list(t, UA_NS0ID_SERVERCONFIGURATION, UA_NS0ID_SERVERCONFIGURATION_GETREJECTEDLIST,
                      l, n);
    ga_note(ctx, "GetRejectedList -> %s, %zu entries", UA_StatusCode_name(r), *n);
    return r;
}

/* SRV-REJ-01 (12 §7.10.12): a valid but untrusted client certificate is
 * recommended to be added. */
static void t_rej_untrusted(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    gds_buf cert = {0};
    UA_ByteString *l = NULL;
    size_t n = 0;
    bool refused = false;
    UA_StatusCode r = refused_then_list(t, "peer-unknown", PEER_UNKNOWN_URI, false, &refused,
                                        &cert, &l, &n, ctx);
    if(r != UA_STATUSCODE_GOOD && absent(r))
        ga_not_supported(ctx, "GetRejectedList -> %s", UA_StatusCode_name(r));
    else if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: peer-unknown and GetRejectedList -> %s", UA_StatusCode_name(r));
    else if(!refused)
        ga_not_tested(ctx, "peer-unknown was not refused (SRV-WIRE-06 checks it)");
    else if(listed(l, n, &cert))
        ga_pass(ctx, "peer-unknown is in the rejected list (%zu entries)", n);
    else
        ga_warn(ctx, "peer-unknown was refused but is not in the rejected list (%zu entries)", n);
    UA_Array_delete(l, n, &UA_TYPES[UA_TYPES_BYTESTRING]);
    gds_buf_free(&cert);
}

/* SRV-REJ-02 (12 §7.8.3.2): only certificates with no unsuppressed
 * validation error are added; a broken signature is one (4 §6.1.3). */
static void t_rej_invalid(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    gds_buf cert = {0};
    UA_ByteString *l = NULL;
    size_t n = 0;
    bool refused = false;
    UA_StatusCode r = refused_then_list(t, "peer-badsig", PEER_BADSIG_URI, true, &refused, &cert,
                                        &l, &n, ctx);
    if(r != UA_STATUSCODE_GOOD && absent(r))
        ga_not_supported(ctx, "GetRejectedList -> %s", UA_StatusCode_name(r));
    else if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: peer-badsig and GetRejectedList -> %s", UA_StatusCode_name(r));
    else if(!refused)
        ga_not_tested(ctx, "peer-badsig (signature broken) was not refused");
    else if(listed(l, n, &cert))
        ga_fail(ctx, "peer-badsig, whose signature is broken, is in the rejected list");
    else
        ga_pass(ctx, "peer-badsig refused and not in the rejected list (%zu entries)", n);
    UA_Array_delete(l, n, &UA_TYPES[UA_TYPES_BYTESTRING]);
    gds_buf_free(&cert);
}

/* The index of the first entry that is not a DER certificate, or n. */
static size_t first_undecodable(const UA_ByteString *l, size_t n) {
    for(size_t i = 0; i < n; i++) {
        gds_buf b = {l[i].data, l[i].length};
        X509 *x = x509_parse_cert(&b);
        X509_free(x);
        ERR_clear_error();
        if(!x)
            return i;
    }
    return n;
}

/* SRV-REJ-03 (12 §7.10.12): Certificates is the DER form of each. */
static void t_rej_decode(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_ByteString *l = NULL;
    size_t n = 0;
    UA_StatusCode r = rejected_list(t, UA_NS0ID_SERVERCONFIGURATION,
                                    UA_NS0ID_SERVERCONFIGURATION_GETREJECTEDLIST, &l, &n);
    size_t bad = r == UA_STATUSCODE_GOOD ? first_undecodable(l, n) : n;
    if(r != UA_STATUSCODE_GOOD && absent(r))
        ga_not_supported(ctx, "GetRejectedList -> %s", UA_StatusCode_name(r));
    else if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "GetRejectedList as SecurityAdmin -> %s", UA_StatusCode_name(r));
    else if(bad < n)
        ga_fail(ctx, "entry %zu of %zu (%zu bytes) is not a DER certificate", bad + 1, n,
                l[bad].length);
    else
        ga_pass(ctx, "all %zu entries are DER certificates", n);
    UA_Array_delete(l, n, &UA_TYPES[UA_TYPES_BYTESTRING]);
}

/* SRV-REJ-04 (12 §7.8.3.1, §7.8.3.2): GetRejectedList of the
 * DefaultApplicationGroup, if it has one. */
static void t_rej_group(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_ByteString *l = NULL;
    size_t n = 0;
    UA_StatusCode r = rejected_list(
        t, DAG, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_GETREJECTEDLIST,
        &l, &n);
    size_t bad = r == UA_STATUSCODE_GOOD ? first_undecodable(l, n) : n;
    if(r != UA_STATUSCODE_GOOD && absent(r))
        ga_not_supported(ctx, "DefaultApplicationGroup GetRejectedList -> %s",
                         UA_StatusCode_name(r));
    else if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "DefaultApplicationGroup GetRejectedList as SecurityAdmin -> %s",
                UA_StatusCode_name(r));
    else if(bad < n)
        ga_fail(ctx, "entry %zu of %zu (%zu bytes) is not a DER certificate", bad + 1, n,
                l[bad].length);
    else
        ga_pass(ctx, "DefaultApplicationGroup GetRejectedList: %zu DER certificates", n);
    UA_Array_delete(l, n, &UA_TYPES[UA_TYPES_BYTESTRING]);
}

const ga_test srv_rejected_tests[] = {
    {"SRV-REJ-01", "12 §7.10.12", "A refused untrusted client certificate is in the rejected list",
     false, false, t_rej_untrusted},
    {"SRV-REJ-02", "12 §7.8.3.2, §7.10.12",
     "A client certificate with a broken signature is not in the rejected list", false, false,
     t_rej_invalid},
    {"SRV-REJ-03", "12 §7.10.12", "Every rejected list entry is a DER certificate", false, false,
     t_rej_decode},
    {"SRV-REJ-04", "12 §7.8.3.1, §7.8.3.2", "The group-level GetRejectedList works", false, false,
     t_rej_group},
};
const size_t srv_rejected_count = GDS_ARRAY_SIZE(srv_rejected_tests);
