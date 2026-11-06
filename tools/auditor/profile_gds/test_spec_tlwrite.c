/* OpenGDS spec tests: the GDS's CertificateGroup TrustList as a TrustListType
 * (OPC 10000-12 §7.8.2.1-§7.8.2.9) and FileType (OPC 10000-20 §4.2).
 * Tests that change the trust list restore it before they end; they are
 * needsWrite, so they run only with --allow-changes.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>
#include <open62541/nodeids_gds.h>

#include <string.h>

#include "common/limits.h"
#include "gds_tl.h"
#include "spec_tests.h"
#include "common/banned.h"

#define URI_LEN (GDS_MAX_APPLICATION_URI + 1)

static bool admin(ga_ctx *ctx, gds_target *t) {
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
        return false;
    }
    return true;
}

static UA_StatusCode read_list(UA_Client *c, UA_NodeId tl, UA_TrustListDataType *d) {
    return uac_read_trustlist(c, tl, d);
}

/* A self-signed application certificate the trust list does not hold yet */
static gds_status fresh_cert(gds_target *t, gds_buf *cert) {
    EVP_PKEY *k = EVP_RSA_gen(2048);
    if(!k)
        return GDS_ECRYPTO;
    char uri[URI_LEN];
    gt_unique_uri(t, uri, sizeof(uri));
    gds_status s = gtl_make_cert(NULL, NULL, k, "OpenGDS Auditor TL entry", uri, false, 7, cert);
    EVP_PKEY_free(k);
    return s;
}

static void t_open_bad_mode(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_NodeId tl = gtl_default(t);
    const UA_Byte modes[] = {0x02, 0x03, 0x04};
    size_t handles = 0, other = 0;
    for(size_t i = 0; i < GDS_ARRAY_SIZE(modes); i++) {
        UA_UInt32 h = 0;
        UA_StatusCode r = gtl_open(t->client, tl, modes[i], false, 0, &h);
        ga_note(ctx, "Open(0x%02x) -> %s", modes[i], UA_StatusCode_name(r));
        if(r == UA_STATUSCODE_GOOD) {
            handles++;
            gtl_close(t->client, tl, h);
        } else if(r != UA_STATUSCODE_BADNOTSUPPORTED) {
            other++;
        }
    }
    if(handles)
        ga_fail(ctx, "%zu of 3 modes other than Read and Write+EraseExisting returned a handle",
                handles);
    else if(other)
        ga_warn(ctx, "%zu of 3 unsupported modes refused with a code other than BadNotSupported",
                other);
    else
        ga_pass(ctx, "Open(0x02), Open(0x03) and Open(0x04) -> BadNotSupported");
}

static void t_open_with_masks(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_NodeId tl = gtl_default(t);
    UA_UInt32 h = 0;
    UA_StatusCode r = gtl_open(t->client, tl, 0, true, 0x1 /* TrustedCertificates */, &h);
    (void)gt_absent(ctx, r, false, "OpenWithMasks");
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "OpenWithMasks(TrustedCertificates) -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_ByteString file;
    r = gtl_read_all(t->client, tl, h, 16384, &file);
    gtl_close(t->client, tl, h);
    UA_TrustListDataType d;
    UA_TrustListDataType_init(&d);
    if(r == UA_STATUSCODE_GOOD)
        r = gtl_decode(&file, &d);
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "Read after OpenWithMasks -> %s", UA_StatusCode_name(r));
    else if((d.specifiedLists & ~0x1u) != 0)
        ga_fail(ctx, "SpecifiedLists 0x%x includes lists the masks did not ask for",
                (unsigned)d.specifiedLists);
    else if(d.trustedCrlsSize + d.issuerCertificatesSize + d.issuerCrlsSize != 0)
        ga_fail(ctx, "the file holds CRLs or issuer certificates although only "
                     "TrustedCertificates was asked for");
    else
        ga_pass(ctx, "only TrustedCertificates returned (SpecifiedLists 0x%x, %zu certificate(s))",
                (unsigned)d.specifiedLists, d.trustedCertificatesSize);
    UA_TrustListDataType_clear(&d);
    UA_ByteString_clear(&file);
}

/* A Server may return less than Length; reading in small chunks gives the
 * same file as one large Read. */
static void t_read_chunked(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_NodeId tl = gtl_default(t);
    UA_UInt32 h1 = 0, h2 = 0;
    UA_ByteString big, small;
    UA_ByteString_init(&big);
    UA_ByteString_init(&small);
    UA_StatusCode r = gtl_open(t->client, tl, GTL_READ, false, 0, &h1);
    if(r == UA_STATUSCODE_GOOD) {
        r = gtl_read_all(t->client, tl, h1, 1 << 20, &big);
        gtl_close(t->client, tl, h1);
    }
    if(r == UA_STATUSCODE_GOOD)
        r = gtl_open(t->client, tl, GTL_READ, false, 0, &h2);
    if(r == UA_STATUSCODE_GOOD) {
        r = gtl_read_all(t->client, tl, h2, 64, &small);
        gtl_close(t->client, tl, h2);
    }
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "Open/Read -> %s", UA_StatusCode_name(r));
    else if(big.length == 0)
        ga_fail(ctx, "the trust list file is empty");
    else if(!UA_ByteString_equal(&big, &small))
        ga_fail(ctx, "64-byte Reads give %zu bytes, one Read gives %zu, contents differ",
                small.length, big.length);
    else
        ga_pass(ctx, "%zu bytes read in 64-byte chunks equal one large Read", big.length);
    UA_ByteString_clear(&big);
    UA_ByteString_clear(&small);
}

/* A file handle is unique for the Session and cannot be used from another */
static void t_handle_other_session(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_Client *other = gt_new_client(t);
    UA_StatusCode r = other ? (t->user ? UA_Client_connectUsername(other, t->url, t->user,
                                                                   t->password)
                                       : UA_Client_connect(other, t->url))
                            : UA_STATUSCODE_BADOUTOFMEMORY;
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: second admin session -> %s", UA_StatusCode_name(r));
        if(other)
            UA_Client_delete(other);
        return;
    }
    UA_NodeId tl = gtl_default(t);
    UA_UInt32 h = 0;
    r = gtl_open(t->client, tl, GTL_READ, false, 0, &h);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: Open(Read) -> %s", UA_StatusCode_name(r));
        gt_drop(other);
        return;
    }
    UA_ByteString file;
    UA_StatusCode rr = gtl_read_all(other, tl, h, 16384, &file);
    UA_ByteString_clear(&file);
    gtl_close(t->client, tl, h);
    gt_drop(other);
    if(rr == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "another Session read the trust list with this Session's file handle");
    else
        ga_pass(ctx, "Read with another Session's handle refused: %s", UA_StatusCode_name(rr));
}

/* Write without CloseAndUpdate: Close discards the data */
static void t_close_discards(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_NodeId tl = gtl_default(t);
    UA_TrustListDataType before, after, changed;
    UA_TrustListDataType_init(&after);
    UA_TrustListDataType_init(&changed);
    UA_StatusCode r = read_list(t->client, tl, &before);
    gds_buf extra = {0};
    if(r != UA_STATUSCODE_GOOD || fresh_cert(t, &extra) != GDS_OK) {
        ga_not_tested(ctx, "setup: read the trust list -> %s", UA_StatusCode_name(r));
        goto done;
    }
    r = UA_TrustListDataType_copy(&before, &changed);
    UA_ByteString eb = {extra.len, extra.data};
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Array_appendCopy((void **)&changed.trustedCertificates,
                                &changed.trustedCertificatesSize, &eb,
                                &UA_TYPES[UA_TYPES_BYTESTRING]);
    changed.specifiedLists = 0xf;
    bool acr = false;
    if(r == UA_STATUSCODE_GOOD)
        r = gtl_write(t->client, tl, &changed, false, &acr);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "Open(Write|EraseExisting)/Write/Close -> %s", UA_StatusCode_name(r));
        goto done;
    }
    r = read_list(t->client, tl, &after);
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "reading back -> %s", UA_StatusCode_name(r));
    else if(gtl_has(after.trustedCertificates, after.trustedCertificatesSize, &extra))
        ga_fail(ctx, "written data was applied although Close, not CloseAndUpdate, was called");
    else
        ga_pass(ctx, "Close after Write left the trust list unchanged");
done:
    gds_buf_free(&extra);
    UA_TrustListDataType_clear(&before);
    UA_TrustListDataType_clear(&after);
    UA_TrustListDataType_clear(&changed);
}

/* Write + CloseAndUpdate applies the list and moves LastUpdateTime; then
 * the original list is written back. */
static void t_write_update(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_NodeId tl = gtl_default(t);
    UA_TrustListDataType before, after, changed;
    UA_TrustListDataType_init(&after);
    UA_TrustListDataType_init(&changed);
    UA_DateTime t0 = 0, t1 = 0;
    UA_StatusCode r = read_list(t->client, tl, &before);
    gds_buf extra = {0};
    if(r != UA_STATUSCODE_GOOD || fresh_cert(t, &extra) != GDS_OK) {
        ga_not_tested(ctx, "setup: read the trust list -> %s", UA_StatusCode_name(r));
        goto done;
    }
    gtl_last_update(t->client, tl, &t0);
    before.specifiedLists = 0xf;
    r = UA_TrustListDataType_copy(&before, &changed);
    UA_ByteString eb = {extra.len, extra.data};
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Array_appendCopy((void **)&changed.trustedCertificates,
                                &changed.trustedCertificatesSize, &eb,
                                &UA_TYPES[UA_TYPES_BYTESTRING]);
    bool acr = false;
    if(r == UA_STATUSCODE_GOOD)
        r = gtl_write(t->client, tl, &changed, true, &acr);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "Open(Write|EraseExisting)/Write/CloseAndUpdate -> %s",
                UA_StatusCode_name(r));
        goto done;
    }
    ga_note(ctx, "CloseAndUpdate ApplyChangesRequired=%s", acr ? "true" : "false");
    r = read_list(t->client, tl, &after);
    UA_StatusCode rt = gtl_last_update(t->client, tl, &t1);
    bool restoreAcr = false;
    UA_StatusCode rs = gtl_write(t->client, tl, &before, true, &restoreAcr);
    if(rs != UA_STATUSCODE_GOOD)
        ga_note(ctx, "restoring the original trust list -> %s", UA_StatusCode_name(rs));
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "reading back -> %s", UA_StatusCode_name(r));
    else if(!gtl_has(after.trustedCertificates, after.trustedCertificatesSize, &extra))
        ga_fail(ctx, "the written certificate is not in the trust list after CloseAndUpdate%s",
                acr ? " (ApplyChangesRequired=true: the Directory has no ApplyChanges)" : "");
    else if(rt != UA_STATUSCODE_GOOD || t1 <= t0)
        ga_fail(ctx, "LastUpdateTime did not advance (%s)", UA_StatusCode_name(rt));
    else if(rs != UA_STATUSCODE_GOOD)
        ga_warn(ctx, "applied, but writing the original list back failed: %s",
                UA_StatusCode_name(rs));
    else
        ga_pass(ctx, "CloseAndUpdate applied the list and LastUpdateTime advanced");
done:
    gds_buf_free(&extra);
    UA_TrustListDataType_clear(&before);
    UA_TrustListDataType_clear(&after);
    UA_TrustListDataType_clear(&changed);
}

static void t_add_remove(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_NodeId tl = gtl_default(t);
    gds_buf extra = {0};
    char tp[X509_THUMBPRINT_LEN];
    if(fresh_cert(t, &extra) != GDS_OK || x509_thumbprint(&extra, tp) != GDS_OK) {
        ga_not_tested(ctx, "setup: test certificate");
        gds_buf_free(&extra);
        return;
    }
    UA_DateTime t0 = 0, t1 = 0, t2 = 0;
    gtl_last_update(t->client, tl, &t0);
    UA_StatusCode ra = gtl_add(t->client, tl, &extra, true);
    UA_TrustListDataType mid, end;
    UA_TrustListDataType_init(&mid);
    UA_TrustListDataType_init(&end);
    UA_StatusCode r1 = ra == UA_STATUSCODE_GOOD ? read_list(t->client, tl, &mid) : ra;
    gtl_last_update(t->client, tl, &t1);
    UA_StatusCode rr = ra == UA_STATUSCODE_GOOD ? gtl_remove_thumb(t->client, tl, tp, true) : ra;
    UA_StatusCode r2 = rr == UA_STATUSCODE_GOOD ? read_list(t->client, tl, &end) : rr;
    gtl_last_update(t->client, tl, &t2);
    (void)gt_absent(ctx, ra, false, "AddCertificate");
    if(ra != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "AddCertificate(self-signed, trusted) -> %s", UA_StatusCode_name(ra));
    else if(r1 != UA_STATUSCODE_GOOD ||
            !gtl_has(mid.trustedCertificates, mid.trustedCertificatesSize, &extra))
        ga_fail(ctx, "the added certificate is not in the Trusted list");
    else if(rr != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "RemoveCertificate(thumbprint, trusted) -> %s", UA_StatusCode_name(rr));
    else if(r2 != UA_STATUSCODE_GOOD ||
            gtl_has(end.trustedCertificates, end.trustedCertificatesSize, &extra))
        ga_fail(ctx, "the removed certificate is still in the Trusted list");
    else if(!(t1 > t0 && t2 > t1))
        ga_fail(ctx, "LastUpdateTime did not advance on AddCertificate and RemoveCertificate");
    else
        ga_pass(ctx, "AddCertificate and RemoveCertificate change the list and LastUpdateTime");
    UA_TrustListDataType_clear(&mid);
    UA_TrustListDataType_clear(&end);
    gds_buf_free(&extra);
}

static void t_add_untrusted_flag(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_NodeId tl = gtl_default(t);
    gds_buf extra = {0};
    if(fresh_cert(t, &extra) != GDS_OK) {
        ga_not_tested(ctx, "setup: test certificate");
        return;
    }
    UA_StatusCode r = gtl_add(t->client, tl, &extra, false);
    if(r == UA_STATUSCODE_BADCERTIFICATEINVALID) {
        ga_pass(ctx, "IsTrustedCertificate FALSE -> BadCertificateInvalid");
    } else if(r == UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "AddCertificate with IsTrustedCertificate FALSE succeeded");
        char tp[X509_THUMBPRINT_LEN];
        if(x509_thumbprint(&extra, tp) == GDS_OK &&
           gtl_remove_thumb(t->client, tl, tp, false) != UA_STATUSCODE_GOOD)
            ga_note(ctx, "could not remove the certificate again");
    } else {
        ga_warn(ctx, "refused with %s; the spec names BadCertificateInvalid",
                UA_StatusCode_name(r));
    }
    gds_buf_free(&extra);
}

/* An application certificate whose CA is not in the trust list fails validation */
static void t_add_no_issuer(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_NodeId tl = gtl_default(t);
    EVP_PKEY *caKey = EVP_RSA_gen(2048), *leafKey = EVP_RSA_gen(2048);
    gds_buf caDer = {0}, leaf = {0};
    X509 *ca = NULL;
    char uri[URI_LEN];
    gt_unique_uri(t, uri, sizeof(uri));
    if(!caKey || !leafKey ||
       gtl_make_cert(NULL, NULL, caKey, "OpenGDS Auditor unknown CA", NULL, true, 7, &caDer) !=
           GDS_OK ||
       !(ca = x509_parse_cert(&caDer)) ||
       gtl_make_cert(ca, caKey, leafKey, "OpenGDS Auditor orphan", uri, false, 7, &leaf) !=
           GDS_OK) {
        ga_not_tested(ctx, "setup: test certificates");
        goto done;
    }
    UA_StatusCode r = gtl_add(t->client, tl, &leaf, true);
    if(r == UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "AddCertificate accepted a certificate whose issuer is not in the list");
        char tp[X509_THUMBPRINT_LEN];
        if(x509_thumbprint(&leaf, tp) == GDS_OK &&
           gtl_remove_thumb(t->client, tl, tp, true) != UA_STATUSCODE_GOOD)
            ga_note(ctx, "could not remove the certificate again");
    } else if((r & 0xFFFF0000u) >= UA_STATUSCODE_BADCERTIFICATEINVALID &&
              (r & 0xFFFF0000u) <= UA_STATUSCODE_BADCERTIFICATEREVOKED) {
        ga_pass(ctx, "refused with the validation error %s", UA_StatusCode_name(r));
    } else if(r == UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE ||
              r == UA_STATUSCODE_BADSECURITYCHECKSFAILED) {
        ga_pass(ctx, "refused with the validation error %s", UA_StatusCode_name(r));
    } else {
        ga_warn(ctx, "refused with %s, not a certificate validation error (OPC 10000-4)",
                UA_StatusCode_name(r));
    }
done:
    X509_free(ca);
    EVP_PKEY_free(caKey);
    EVP_PKEY_free(leafKey);
    gds_buf_free(&caDer);
    gds_buf_free(&leaf);
}

static void t_add_while_open(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_NodeId tl = gtl_default(t);
    gds_buf extra = {0};
    if(fresh_cert(t, &extra) != GDS_OK) {
        ga_not_tested(ctx, "setup: test certificate");
        return;
    }
    UA_UInt32 h = 0;
    UA_StatusCode r = gtl_open(t->client, tl, GTL_WRITE_ERASE, false, 0, &h);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: Open(Write|EraseExisting) -> %s", UA_StatusCode_name(r));
        gds_buf_free(&extra);
        return;
    }
    r = gtl_add(t->client, tl, &extra, true);
    gtl_close(t->client, tl, h);
    if(r == UA_STATUSCODE_BADINVALIDSTATE) {
        ga_pass(ctx, "BadInvalidState while the list is open for writing");
    } else if(r == UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "AddCertificate succeeded while the list was open for writing");
        char tp[X509_THUMBPRINT_LEN];
        if(x509_thumbprint(&extra, tp) == GDS_OK &&
           gtl_remove_thumb(t->client, tl, tp, true) != UA_STATUSCODE_GOOD)
            ga_note(ctx, "could not remove the certificate again");
    } else {
        ga_warn(ctx, "refused with %s; the spec names BadInvalidState", UA_StatusCode_name(r));
    }
    gds_buf_free(&extra);
}

static void t_remove_unknown(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_StatusCode r = gtl_remove_thumb(t->client, gtl_default(t),
                                       "0123456789ABCDEF0123456789ABCDEF01234567", true);
    if(r == UA_STATUSCODE_BADINVALIDARGUMENT)
        ga_pass(ctx, "BadInvalidArgument");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "RemoveCertificate succeeded for a thumbprint in no list");
    else
        ga_warn(ctx, "refused with %s; the spec names BadInvalidArgument", UA_StatusCode_name(r));
}

const ga_test spec_tlwrite_tests[] = {
    {"gds.tl.open_bad_mode", "12 §7.8.2.2", "TrustList Open refuses modes other than Read and Write+EraseExisting",
     false, false, t_open_bad_mode},
    {"gds.tl.open_with_masks", "12 §7.8.2.3, §7.8.2.9", "OpenWithMasks returns only the lists asked for",
     false, false, t_open_with_masks},
    {"gds.tl.read_chunked", "12 §7.8.2.4; 20 §4.2.4", "Reading the trust list in small chunks gives the same file",
     false, false, t_read_chunked},
    {"gds.tl.handle_other_session", "20 §4.2.2", "A TrustList file handle is not valid in another Session",
     false, false, t_handle_other_session},
    {"gds.tl.close_discards", "12 §7.8.2.1", "Close after Write discards the written trust list",
     true, false, t_close_discards},
    {"gds.tl.write_update", "12 §7.8.2.1, §7.8.2.5", "Write and CloseAndUpdate apply the list and move LastUpdateTime",
     true, false, t_write_update},
    {"gds.tl.add_remove", "12 §7.8.2.1, §7.8.2.6, §7.8.2.7", "AddCertificate and RemoveCertificate change the Trusted list",
     true, false, t_add_remove},
    {"gds.tl.add_untrusted_flag", "12 §7.8.2.6", "AddCertificate with IsTrustedCertificate FALSE returns BadCertificateInvalid",
     true, false, t_add_untrusted_flag},
    {"gds.tl.add_no_issuer", "12 §7.8.2.6", "AddCertificate refuses a certificate whose CA is not in the list",
     true, false, t_add_no_issuer},
    {"gds.tl.add_while_open", "12 §7.8.2.6", "AddCertificate is refused while the list is open for writing",
     true, false, t_add_while_open},
    {"gds.tl.remove_unknown", "12 §7.8.2.7", "RemoveCertificate of an unknown thumbprint returns BadInvalidArgument",
     true, false, t_remove_unknown},
};
const size_t spec_tlwrite_count = GDS_ARRAY_SIZE(spec_tlwrite_tests);
