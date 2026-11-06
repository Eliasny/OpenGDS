/* OpenGDS Auditor server profile: trust list write (srv_trustlist.c).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "Trust list write".
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <stdint.h>
#include <string.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "common/banned.h"

#define TLOBJ UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST
#define TLM(x) UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_##x
#define DAY 86400L

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

static bool admin_ready(ga_ctx *ctx, srv_target *t, bool needPushed) {
    UA_StatusCode r = st_snapshot(t, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = st_admin(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin session and snapshot -> %s", UA_StatusCode_name(r));
        return false;
    }
    if(needPushed && !t->tlPushed) {
        ga_not_tested(ctx, "setup: needs the trust list of SRV-TL-02 (ca and its CRL)");
        return false;
    }
    return true;
}

static UA_StatusCode last_update(UA_Client *c, UA_DateTime *out) {
    *out = 0;
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode r = UA_Client_readValueAttribute(c, ns0(TLM(LASTUPDATETIME)), &v);
    if(r == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_DATETIME]))
        *out = *(UA_DateTime *)v.data;
    else if(r == UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    UA_Variant_clear(&v);
    return r;
}

/* The applied list as the persistent admin session reads it. */
static UA_StatusCode applied(srv_target *t, UA_TrustListDataType *out) {
    UA_StatusCode r = st_admin(t);
    return r == UA_STATUSCODE_GOOD ? st_read_trustlist(t->client, ST_MASK_ALL, out) : r;
}

/* Write `tl` with CloseAndUpdate and apply it if required. */
static UA_StatusCode write_apply(UA_Client *c, const UA_TrustListDataType *tl, ga_ctx *ctx) {
    if(!c) /* the admin session was lost (st_admin failed) */
        return UA_STATUSCODE_BADSESSIONCLOSED;
    bool acr = false;
    UA_StatusCode r = st_write_trustlist(c, tl, 512, &acr, ctx);
    if(r == UA_STATUSCODE_GOOD && acr)
        r = st_apply(c);
    return r;
}

/* SRV-TL-01 (12 §7.8.2.2): Open with 0x02, 0x03 and 0x04 */
static void t_tl_open_modes(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, false))
        return;
    UA_Client *c = NULL;
    UA_StatusCode r = st_admin_fresh(t, true, &c);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: second admin session -> %s", UA_StatusCode_name(r));
        return;
    }
    const UA_Byte modes[] = {0x02, 0x03, 0x04};
    size_t handles = 0, other = 0;
    for(size_t i = 0; i < GDS_ARRAY_SIZE(modes); i++) {
        UA_Byte m = modes[i];
        UA_Variant in;
        UA_Variant_setScalar(&in, &m, &UA_TYPES[UA_TYPES_BYTE]);
        size_t outN = 0;
        UA_Variant *out = NULL;
        r = UA_Client_call(c, ns0(TLOBJ), ns0(TLM(OPEN)), 1, &in, &outN, &out);
        const UA_UInt32 *h = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_UINT32]);
        ga_note(ctx, "Open(0x%02x) -> %s%s", m, UA_StatusCode_name(r),
                r == UA_STATUSCODE_GOOD && h ? " with a handle" : "");
        if(r == UA_STATUSCODE_GOOD && h) {
            handles++;
            UA_UInt32 hv = *h;
            UA_Variant cin;
            UA_Variant_setScalar(&cin, &hv, &UA_TYPES[UA_TYPES_UINT32]);
            size_t coN = 0;
            UA_Variant *co = NULL;
            (void)UA_Client_call(c, ns0(TLOBJ), ns0(TLM(CLOSE)), 1, &cin, &coN, &co);
            if(co)
                UA_Array_delete(co, coN, &UA_TYPES[UA_TYPES_VARIANT]);
        } else if(r != UA_STATUSCODE_BADNOTSUPPORTED) {
            other++;
        }
        if(out)
            UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    }
    st_discard(c);
    if(handles)
        ga_fail(ctx, "%zu of 3 unsupported Open modes returned a file handle", handles);
    else if(other)
        ga_warn(ctx, "%zu of 3 unsupported Open modes refused with a code other than "
                     "Bad_NotSupported",
                other);
    else
        ga_pass(ctx, "Open(0x02), Open(0x03) and Open(0x04) -> Bad_NotSupported");
}

/* SRV-TL-02 (12 §7.8.2.1, §7.8.2.5, §7.10.9): Open(0x06), Write the new list
 * in 512-byte chunks, CloseAndUpdate, ApplyChanges if ApplyChangesRequired,
 * then OpenWithMasks(All) and Read back. The new list is the snapshot plus
 * the run's test CA and its CRL, so the Auditor keeps its own access. */
static void t_tl_write_readback(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_StatusCode r = st_snapshot(t, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: snapshot of the trust list -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_TrustListDataType_clear(&t->pushed);
    if((r = st_list_copy_add(&t->snap, &t->caDer, &t->caCrl, &t->pushed)) != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: building the new list -> %s", UA_StatusCode_name(r));
        return;
    }
    bool acr = false;
    r = st_write_trustlist(t->client, &t->pushed, 512, &acr, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "a valid trust list was not accepted: %s", UA_StatusCode_name(r));
        return;
    }
    if(acr) {
        r = st_apply(t->client);
        ga_note(ctx, "ApplyChangesRequired TRUE; ApplyChanges -> %s", UA_StatusCode_name(r));
        if(r != UA_STATUSCODE_GOOD) {
            ga_fail(ctx, "ApplyChanges after CloseAndUpdate -> %s", UA_StatusCode_name(r));
            return;
        }
    }
    UA_TrustListDataType back;
    r = st_admin(t);
    if(r == UA_STATUSCODE_GOOD)
        r = st_read_trustlist(t->client, ST_MASK_ALL, &back);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "OpenWithMasks(All) read-back -> %s", UA_StatusCode_name(r));
        return;
    }
    char why[160];
    if(st_lists_equal(&t->pushed, &back, why, sizeof(why))) {
        t->tlPushed = true;
        ga_pass(ctx, "list read back equals the list written (%zu trusted, %zu CRL)",
                back.trustedCertificatesSize, back.trustedCrlsSize);
    } else {
        ga_fail(ctx, "list read back differs from the list written: %s", why);
    }
    UA_TrustListDataType_clear(&back);
}


/* SRV-TL-03 (12 §7.8.2.1, §7.8.2.8): the file is one UA Binary TrustListDataType */
static void t_tl_encoding(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_StatusCode r = st_admin(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
        return;
    }
    gds_buf raw = {NULL, 0};
    r = st_read_trustlist_raw(t->client, ST_MASK_ALL, &raw);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "OpenWithMasks(All) and Read -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_ByteString bs = {raw.len, raw.data};
    UA_TrustListDataType l;
    UA_TrustListDataType_init(&l);
    UA_DecodeBinaryOptions opt;
    memset(&opt, 0, sizeof(opt));
    r = UA_decodeBinary(&bs, &l, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &opt);
    size_t used = opt.decodedLength;
    UA_UInt32 masks = l.specifiedLists;
    UA_TrustListDataType_clear(&l);
    size_t len = raw.len;
    gds_buf_free(&raw);
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "%zu bytes do not decode as a TrustListDataType: %s", len,
                UA_StatusCode_name(r));
    else if(used != len)
        ga_fail(ctx, "a TrustListDataType decodes from %zu of the %zu bytes", used, len);
    else if(masks > ST_MASK_ALL)
        ga_fail(ctx, "SpecifiedLists 0x%08x has bits outside TrustListMasks: not a bare "
                     "TrustListDataType",
                (unsigned)masks);
    else
        ga_pass(ctx, "%zu bytes are exactly one TrustListDataType (SpecifiedLists %u)", len,
                (unsigned)masks);
}

/* SRV-TL-04 (12 §7.8.2.5, §7.8.2.9): SpecifiedLists = TrustedCertificates only */
static void t_tl_mask(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, true))
        return;
    UA_TrustListDataType cur, want, in, back;
    UA_TrustListDataType_init(&want);
    UA_TrustListDataType_init(&in);
    UA_TrustListDataType_init(&back);
    UA_StatusCode r = applied(t, &cur);
    if(r == UA_STATUSCODE_GOOD)
        r = st_list_copy_add(&cur, &t->peerCert, NULL, &want);
    if(r != UA_STATUSCODE_GOOD) {
        UA_TrustListDataType_clear(&cur);
        ga_not_tested(ctx, "setup: reading the trust list -> %s", UA_StatusCode_name(r));
        return;
    }
    /* only TrustedCertificates is specified; the other lists are sent empty */
    in.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES;
    in.trustedCertificates = want.trustedCertificates;
    in.trustedCertificatesSize = want.trustedCertificatesSize;
    ga_note(ctx, "applied: %zu trusted, %zu CRL, %zu issuer, %zu issuer CRL; sending %zu trusted "
                 "with SpecifiedLists 1",
            cur.trustedCertificatesSize, cur.trustedCrlsSize, cur.issuerCertificatesSize,
            cur.issuerCrlsSize, in.trustedCertificatesSize);
    r = write_apply(t->client, &in, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = applied(t, &back);
    char why[160] = "";
    bool same = r == UA_STATUSCODE_GOOD && st_lists_equal(&want, &back, why, sizeof(why));
    UA_TrustListDataType_clear(&back);
    UA_TrustListDataType_clear(&want);
    /* back to the list of SRV-TL-02 */
    UA_StatusCode rr = write_apply(t->client, &cur, ctx);
    UA_TrustListDataType_clear(&cur);
    if(rr != UA_STATUSCODE_GOOD)
        ga_note(ctx, "putting the previous list back -> %s", UA_StatusCode_name(rr));
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "a masked write was not accepted and applied: %s", UA_StatusCode_name(r));
    else if(!same)
        ga_fail(ctx, "after a TrustedCertificates-only write the lists are not as expected: %s",
                why);
    else
        ga_pass(ctx, "TrustedCertificates replaced; the three unmasked lists unchanged");
}

/* SRV-TL-05 (12 §7.8.2.3, §7.8.2.9): OpenWithMasks(TrustedCertificates) */
static void t_tl_masks_read(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, true))
        return;
    UA_TrustListDataType l;
    UA_StatusCode r = st_read_trustlist(t->client, UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES, &l);
    if(r != UA_STATUSCODE_GOOD) {
        ga_warn(ctx, "OpenWithMasks(TrustedCertificates) -> %s", UA_StatusCode_name(r));
        return;
    }
    size_t others = l.trustedCrlsSize + l.issuerCertificatesSize + l.issuerCrlsSize;
    UA_UInt32 m = l.specifiedLists;
    size_t n = l.trustedCertificatesSize;
    UA_TrustListDataType_clear(&l);
    if(others || m != UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES)
        ga_warn(ctx, "SpecifiedLists %u and %zu entries of other lists returned", (unsigned)m,
                others);
    else
        ga_pass(ctx, "only TrustedCertificates returned (%zu), SpecifiedLists 1", n);
}

/* Write `tl` in a fresh admin session with CloseAndUpdate (or Close), call
 * ApplyChanges there, then close it; *wr is the write's status. */
static UA_StatusCode probe_write(const srv_target *t, const UA_TrustListDataType *tl, bool update,
                                 UA_StatusCode *wr, ga_ctx *ctx) {
    UA_Client *c = NULL;
    UA_StatusCode r = st_admin_fresh(t, true, &c);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    bool acr = false;
    *wr = st_write_trustlist_ex(c, tl, 512, update, &acr, ctx);
    if(*wr != UA_STATUSCODE_GOOD || !update) {
        /* nothing may be queued now: ApplyChanges must find nothing to do */
        UA_StatusCode a = st_apply(c);
        ga_note(ctx, "ApplyChanges in the same session -> %s", UA_StatusCode_name(a));
    }
    st_discard(c);
    return UA_STATUSCODE_GOOD;
}

/* SRV-TL-06 (12 §7.8.2.1): Close instead of CloseAndUpdate discards */
static void t_tl_close(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, false))
        return;
    UA_TrustListDataType l0, l1, other;
    UA_TrustListDataType_init(&l1);
    UA_TrustListDataType_init(&other);
    UA_DateTime t0 = 0, t1 = 0;
    UA_StatusCode r = applied(t, &l0);
    if(r == UA_STATUSCODE_GOOD)
        r = last_update(t->client, &t0);
    if(r == UA_STATUSCODE_GOOD)
        r = st_list_copy_add(&l0, &t->peerCert, NULL, &other);
    UA_StatusCode w = UA_STATUSCODE_GOOD;
    if(r == UA_STATUSCODE_GOOD)
        r = probe_write(t, &other, false, &w, ctx);
    UA_TrustListDataType_clear(&other);
    if(r != UA_STATUSCODE_GOOD) {
        UA_TrustListDataType_clear(&l0);
        ga_not_tested(ctx, "setup -> %s", UA_StatusCode_name(r));
        return;
    }
    r = applied(t, &l1);
    if(r == UA_STATUSCODE_GOOD)
        r = last_update(t->client, &t1);
    char why[160] = "";
    bool same = r == UA_STATUSCODE_GOOD && st_lists_equal(&l0, &l1, why, sizeof(why));
    UA_TrustListDataType_clear(&l0);
    UA_TrustListDataType_clear(&l1);
    if(w != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "Open, Write and Close -> %s", UA_StatusCode_name(w));
    else if(!same)
        ga_fail(ctx, "the trust list changed after Write and Close: %s",
                why[0] ? why : UA_StatusCode_name(r));
    else if(t1 != t0)
        ga_fail(ctx, "the list is unchanged but LastUpdateTime moved after Close");
    else
        ga_pass(ctx, "Close discarded the written list; LastUpdateTime unchanged");
}

/* SRV-TL-07 and -08: a list with one bad entry is refused and discarded */
static void refuse_entry(ga_ctx *ctx, srv_target *t, const gds_buf *bad, const char *what,
                         UA_StatusCode want) {
    UA_TrustListDataType l0, l1, in;
    UA_TrustListDataType_init(&l1);
    UA_TrustListDataType_init(&in);
    UA_StatusCode r = applied(t, &l0);
    if(r == UA_STATUSCODE_GOOD)
        r = st_list_copy_add(&l0, bad, NULL, &in);
    UA_StatusCode w = UA_STATUSCODE_GOOD;
    if(r == UA_STATUSCODE_GOOD)
        r = probe_write(t, &in, true, &w, ctx);
    UA_TrustListDataType_clear(&in);
    if(r == UA_STATUSCODE_GOOD)
        r = applied(t, &l1);
    char why[160] = "";
    bool same = r == UA_STATUSCODE_GOOD && st_lists_equal(&l0, &l1, why, sizeof(why));
    UA_TrustListDataType_clear(&l0);
    UA_TrustListDataType_clear(&l1);
    if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup -> %s", UA_StatusCode_name(r));
    else if(w == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "CloseAndUpdate accepted a list with %s", what);
    else if(!same)
        ga_fail(ctx, "refused with %s, but part of the list was applied: %s",
                UA_StatusCode_name(w), why);
    else if(w == want || want == UA_STATUSCODE_GOOD)
        ga_pass(ctx, "a list with %s refused with %s; nothing applied", what,
                UA_StatusCode_name(w));
    else
        ga_warn(ctx, "a list with %s refused with %s, not %s; nothing applied", what,
                UA_StatusCode_name(w), UA_StatusCode_name(want));
}

static void t_tl_badsig(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, true))
        return;
    gds_buf bad = {NULL, 0};
    if(gds_buf_dup(t->peerCert.data, t->peerCert.len, &bad) != GDS_OK || bad.len < 2) {
        gds_buf_free(&bad);
        ga_not_tested(ctx, "setup: no peer-good certificate");
        return;
    }
    bad.data[bad.len - 1] ^= 0x01; /* t-badsig: the signature's last byte */
    refuse_entry(ctx, t, &bad, "t-badsig (signature broken)",
                 UA_STATUSCODE_BADCERTIFICATEINVALID);
    gds_buf_free(&bad);
}

static void t_tl_expired(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, false))
        return;
    EVP_PKEY *key = EVP_RSA_gen(2048);
    gds_buf ca = {NULL, 0};
    gds_status s = key ? st_make_cert(NULL, key, TESTCA_ORG " expired CA", -10 * DAY, -DAY, true,
                                      0, &ca)
                       : GDS_ECRYPTO;
    EVP_PKEY_free(key);
    if(s != GDS_OK) {
        ga_not_tested(ctx, "setup: expired CA certificate -> %s", gds_status_name(s));
        return;
    }
    /* decision D2: any refusal passes, an accepted expired certificate fails */
    refuse_entry(ctx, t, &ca, "an expired CA certificate", UA_STATUSCODE_GOOD);
    gds_buf_free(&ca);
}

/* ---------------- AddCertificate, RemoveCertificate (§7.8.2.6, §7.8.2.7) ---------------- */

static UA_StatusCode add_cert(UA_Client *c, const gds_buf *cert, bool trusted) {
    if(!c)
        return UA_STATUSCODE_BADSESSIONCLOSED;
    UA_ByteString b = {cert->len, cert->data};
    UA_Boolean tr = trusted;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &b, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[1], &tr, &UA_TYPES[UA_TYPES_BOOLEAN]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(c, ns0(TLOBJ), ns0(TLM(ADDCERTIFICATE)), 2, in, &outN, &out);
    if(out)
        UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

static UA_StatusCode remove_cert(UA_Client *c, const gds_buf *cert, bool trusted) {
    if(!c)
        return UA_STATUSCODE_BADSESSIONCLOSED;
    char tp[X509_THUMBPRINT_LEN];
    if(x509_thumbprint(cert, tp) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_String thumb = UA_STRING(tp);
    UA_Boolean tr = trusted;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &thumb, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &tr, &UA_TYPES[UA_TYPES_BOOLEAN]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r =
        UA_Client_call(c, ns0(TLOBJ), ns0(TLM(REMOVECERTIFICATE)), 2, in, &outN, &out);
    if(out)
        UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

static bool has(const UA_ByteString *l, size_t n, const gds_buf *x) {
    UA_ByteString b = {x->len, x->data};
    for(size_t i = 0; i < n; i++)
        if(UA_ByteString_equal(&l[i], &b))
            return true;
    return false;
}

/* After a direct change: ApplyChanges (nothing should be queued), then the
 * list in use. */
static UA_StatusCode settle_read(srv_target *t, UA_TrustListDataType *back, ga_ctx *ctx) {
    UA_TrustListDataType_init(back);
    UA_StatusCode a = st_apply(t->client);
    ga_note(ctx, "ApplyChanges -> %s", UA_StatusCode_name(a));
    return applied(t, back);
}

/* SRV-TL-09 */
static void t_tl_add(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, true))
        return;
    UA_StatusCode r = add_cert(t->client, &t->peerCert, true);
    ga_note(ctx, "AddCertificate(peer-good, TRUE) -> %s", UA_StatusCode_name(r));
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "AddCertificate refused a valid certificate whose CA is trusted: %s",
                UA_StatusCode_name(r));
        return;
    }
    UA_TrustListDataType back;
    r = settle_read(t, &back, ctx);
    bool in = r == UA_STATUSCODE_GOOD &&
              has(back.trustedCertificates, back.trustedCertificatesSize, &t->peerCert);
    UA_TrustListDataType_clear(&back);
    if(in)
        ga_pass(ctx, "peer-good is in TrustedCertificates after AddCertificate");
    else
        ga_fail(ctx, "AddCertificate returned Good but peer-good is not in the list (%s)",
                UA_StatusCode_name(r));
}

/* An Add that should be refused; a Good is undone. */
static void add_refused(ga_ctx *ctx, srv_target *t, const gds_buf *cert, bool trusted,
                        const char *what, UA_StatusCode want, UA_StatusCode alsoOk) {
    UA_StatusCode r = add_cert(t->client, cert, trusted);
    if(r == UA_STATUSCODE_GOOD) {
        UA_StatusCode u = remove_cert(t->client, cert, trusted);
        ga_note(ctx, "undo: RemoveCertificate -> %s", UA_StatusCode_name(u));
        ga_fail(ctx, "AddCertificate accepted %s", what);
    } else if(r == want || (alsoOk != UA_STATUSCODE_GOOD && r == alsoOk)) {
        ga_pass(ctx, "AddCertificate of %s -> %s", what, UA_StatusCode_name(r));
    } else {
        ga_warn(ctx, "AddCertificate of %s refused with %s, not %s", what, UA_StatusCode_name(r),
                UA_StatusCode_name(want));
    }
}

/* SRV-TL-10 */
static void t_tl_add_issuer(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, false))
        return;
    add_refused(ctx, t, &t->peerCert, false, "peer-good with IsTrustedCertificate FALSE",
                UA_STATUSCODE_BADCERTIFICATEINVALID, UA_STATUSCODE_GOOD);
}

/* SRV-TL-11 */
static void t_tl_add_nochain(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, false))
        return;
    gds_status s = st_intermediate(t);
    if(s != GDS_OK) {
        ga_not_tested(ctx, "setup: ca-int and peer-int -> %s", gds_status_name(s));
        return;
    }
    add_refused(ctx, t, &t->peerInt, true, "peer-int while ca-int is not in the list",
                UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE, UA_STATUSCODE_BADCERTIFICATEINVALID);
}

/* SRV-TL-12 */
static void t_tl_add_open(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, true))
        return;
    EVP_PKEY *k = EVP_RSA_gen(2048);
    gds_buf extra = {NULL, 0};
    gds_status s = k ? st_make_cert(&t->ca, k, TESTCA_ORG " peer-extra", -3600, DAY, false, 0,
                                    &extra)
                     : GDS_ECRYPTO;
    EVP_PKEY_free(k);
    if(s != GDS_OK) {
        ga_not_tested(ctx, "setup: a second peer certificate -> %s", gds_status_name(s));
        return;
    }
    UA_Byte mode = ST_OPEN_WRITE_ERASE;
    UA_Variant in;
    UA_Variant_setScalar(&in, &mode, &UA_TYPES[UA_TYPES_BYTE]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(t->client, ns0(TLOBJ), ns0(TLM(OPEN)), 1, &in, &outN, &out);
    const UA_UInt32 *hp = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_UINT32]);
    UA_UInt32 h = hp ? *hp : 0;
    if(out)
        UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    if(r != UA_STATUSCODE_GOOD || !hp) {
        gds_buf_free(&extra);
        ga_not_tested(ctx, "setup: Open(0x06) -> %s", UA_StatusCode_name(r));
        return;
    }
    r = add_cert(t->client, &extra, true);
    UA_Variant_setScalar(&in, &h, &UA_TYPES[UA_TYPES_UINT32]);
    UA_StatusCode cr = UA_Client_call(t->client, ns0(TLOBJ), ns0(TLM(CLOSE)), 1, &in, &outN, &out);
    if(out)
        UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    ga_note(ctx, "Close -> %s", UA_StatusCode_name(cr));
    if(r == UA_STATUSCODE_GOOD) {
        UA_StatusCode u = remove_cert(t->client, &extra, true);
        ga_note(ctx, "undo: RemoveCertificate -> %s", UA_StatusCode_name(u));
        ga_fail(ctx, "AddCertificate succeeded while the TrustList was open for writing");
    } else if(r == UA_STATUSCODE_BADINVALIDSTATE) {
        ga_pass(ctx, "AddCertificate while open for writing -> Bad_InvalidState");
    } else {
        ga_warn(ctx, "AddCertificate while open for writing -> %s, not Bad_InvalidState",
                UA_StatusCode_name(r));
    }
    gds_buf_free(&extra);
}

/* SRV-TL-13 */
static void t_tl_remove_unknown(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, false))
        return;
    gds_status s = st_intermediate(t);
    if(s != GDS_OK) {
        ga_not_tested(ctx, "setup: peer-int -> %s", gds_status_name(s));
        return;
    }
    UA_StatusCode r = remove_cert(t->client, &t->peerInt, true);
    if(r == UA_STATUSCODE_BADINVALIDARGUMENT)
        ga_pass(ctx, "RemoveCertificate of a thumbprint not in the list -> Bad_InvalidArgument");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "RemoveCertificate of a thumbprint not in the list returned Good");
    else
        ga_warn(ctx, "RemoveCertificate of an unknown thumbprint -> %s, not Bad_InvalidArgument",
                UA_StatusCode_name(r));
}

/* SRV-TL-14 */
static void t_tl_remove(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, true))
        return;
    UA_TrustListDataType back;
    UA_StatusCode r = applied(t, &back);
    bool there = r == UA_STATUSCODE_GOOD &&
                 has(back.trustedCertificates, back.trustedCertificatesSize, &t->peerCert);
    UA_TrustListDataType_clear(&back);
    if(!there) {
        ga_not_tested(ctx, "setup: peer-good is not in TrustedCertificates (SRV-TL-09)");
        return;
    }
    r = remove_cert(t->client, &t->peerCert, true);
    ga_note(ctx, "RemoveCertificate(peer-good, TRUE) -> %s", UA_StatusCode_name(r));
    UA_StatusCode b = settle_read(t, &back, ctx);
    there = b != UA_STATUSCODE_GOOD ||
            has(back.trustedCertificates, back.trustedCertificatesSize, &t->peerCert);
    UA_TrustListDataType_clear(&back);
    if(there)
        ga_fail(ctx, "peer-good is still in TrustedCertificates (RemoveCertificate -> %s)",
                UA_StatusCode_name(r));
    else
        ga_pass(ctx, "peer-good is gone after RemoveCertificate");
}

/* cur plus ca-int as an issuer, with peer-int trusted or ca-int's CRL. */
static UA_StatusCode with_ca_int(const srv_target *t, const UA_TrustListDataType *cur,
                                 bool withPeer, UA_TrustListDataType *out) {
    UA_StatusCode r = UA_TrustListDataType_copy(cur, out);
    out->specifiedLists = ST_MASK_ALL;
    UA_ByteString ci = {t->caIntDer.len, t->caIntDer.data};
    UA_ByteString x = withPeer ? (UA_ByteString){t->peerInt.len, t->peerInt.data}
                               : (UA_ByteString){t->caIntCrl.len, t->caIntCrl.data};
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Array_appendCopy((void **)&out->issuerCertificates, &out->issuerCertificatesSize,
                                &ci, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD && withPeer)
        r = UA_Array_appendCopy((void **)&out->trustedCertificates,
                                &out->trustedCertificatesSize, &x,
                                &UA_TYPES[UA_TYPES_BYTESTRING]);
    else if(r == UA_STATUSCODE_GOOD)
        r = UA_Array_appendCopy((void **)&out->issuerCrls, &out->issuerCrlsSize, &x,
                                &UA_TYPES[UA_TYPES_BYTESTRING]);
    return r;
}

/* SRV-TL-15 and -16: put ca-int in, call RemoveCertificate(ca-int, FALSE),
 * read back, then put the previous list back. */
static UA_StatusCode remove_ca_int(srv_target *t, bool withPeer, UA_StatusCode *rr,
                                   UA_TrustListDataType *back, ga_ctx *ctx) {
    UA_TrustListDataType cur, in;
    UA_TrustListDataType_init(&in);
    UA_TrustListDataType_init(back);
    gds_status s = st_intermediate(t);
    UA_StatusCode r = s == GDS_OK ? applied(t, &cur) : UA_STATUSCODE_BADINTERNALERROR;
    if(r != UA_STATUSCODE_GOOD)
        return r;
    r = with_ca_int(t, &cur, withPeer, &in);
    if(r == UA_STATUSCODE_GOOD)
        r = write_apply(t->client, &in, ctx);
    UA_TrustListDataType_clear(&in);
    if(r == UA_STATUSCODE_GOOD) {
        *rr = remove_cert(t->client, &t->caIntDer, false);
        ga_note(ctx, "RemoveCertificate(ca-int, FALSE) -> %s", UA_StatusCode_name(*rr));
        r = settle_read(t, back, ctx);
    }
    UA_StatusCode b = write_apply(t->client, &cur, ctx);
    if(b != UA_STATUSCODE_GOOD)
        ga_note(ctx, "putting the previous list back -> %s", UA_StatusCode_name(b));
    UA_TrustListDataType_clear(&cur);
    return r;
}

static void t_tl_remove_in_use(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, true))
        return;
    UA_StatusCode rr = UA_STATUSCODE_GOOD;
    UA_TrustListDataType back;
    UA_StatusCode r = remove_ca_int(t, true, &rr, &back, ctx);
    bool kept = has(back.issuerCertificates, back.issuerCertificatesSize, &t->caIntDer);
    UA_TrustListDataType_clear(&back);
    if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: ca-int and peer-int in the list -> %s", UA_StatusCode_name(r));
    else if(rr == UA_STATUSCODE_GOOD || !kept)
        ga_fail(ctx, "ca-int was removed although peer-int needs it (-> %s)",
                UA_StatusCode_name(rr));
    else if(rr == UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE)
        ga_pass(ctx, "RemoveCertificate of a CA in use -> Bad_CertificateChainIncomplete; kept");
    else
        ga_warn(ctx, "RemoveCertificate of a CA in use -> %s, not "
                     "Bad_CertificateChainIncomplete; kept",
                UA_StatusCode_name(rr));
}

static void t_tl_remove_crl(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, true))
        return;
    UA_StatusCode rr = UA_STATUSCODE_GOOD;
    UA_TrustListDataType back;
    UA_StatusCode r = remove_ca_int(t, false, &rr, &back, ctx);
    bool caLeft = has(back.issuerCertificates, back.issuerCertificatesSize, &t->caIntDer);
    bool crlLeft = has(back.issuerCrls, back.issuerCrlsSize, &t->caIntCrl) ||
                   has(back.trustedCrls, back.trustedCrlsSize, &t->caIntCrl);
    UA_TrustListDataType_clear(&back);
    if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: ca-int and its CRL in the list -> %s", UA_StatusCode_name(r));
    else if(caLeft)
        ga_fail(ctx, "ca-int is still in the list (RemoveCertificate -> %s)",
                UA_StatusCode_name(rr));
    else if(crlLeft)
        ga_fail(ctx, "ca-int was removed but its CRL remains");
    else
        ga_pass(ctx, "ca-int and its CRL are gone");
}

/* SRV-TL-18 (12 §7.8.2.1): an idle write handle is closed after ActivityTimeout */
static double activity_timeout(UA_Client *c) {
    UA_NodeId n;
    double ms = 60000.0; /* the default of §7.8.2.1 */
    if(uac_find_child(c, ns0(TLOBJ), "ActivityTimeout", &n) == UA_STATUSCODE_GOOD) {
        UA_Variant v;
        UA_Variant_init(&v);
        if(UA_Client_readValueAttribute(c, n, &v) == UA_STATUSCODE_GOOD &&
           UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_DOUBLE])) {
            double d = *(UA_Double *)v.data;
            if(d > 0 && d < 3600000.0)
                ms = d;
        }
        UA_Variant_clear(&v);
    }
    UA_NodeId_clear(&n);
    return ms;
}

static UA_StatusCode call_h(UA_Client *c, UA_UInt32 method, UA_UInt32 h, const UA_ByteString *data) {
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &h, &UA_TYPES[UA_TYPES_UINT32]);
    if(data)
        UA_Variant_setScalar(&in[1], (void *)(uintptr_t)data, &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(c, ns0(TLOBJ), ns0(method), data ? 2 : 1, in, &outN, &out);
    if(out)
        UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

static void t_tl_idle(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->slow) {
        ga_not_tested(ctx, "slow test (ActivityTimeout + 10 s): run with --slow");
        return;
    }
    if(!admin_ready(ctx, t, true))
        return;
    double ms = activity_timeout(t->client);
    UA_TrustListDataType l0, l1, other;
    UA_TrustListDataType_init(&l1);
    UA_TrustListDataType_init(&other);
    UA_StatusCode r = applied(t, &l0);
    if(r == UA_STATUSCODE_GOOD)
        r = st_list_copy_add(&l0, &t->peerCert, NULL, &other);
    UA_ByteString file = UA_BYTESTRING_NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_encodeBinary(&other, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &file, NULL);
    UA_TrustListDataType_clear(&other);
    UA_Client *c = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = st_admin_fresh(t, true, &c);
    UA_Byte mode = ST_OPEN_WRITE_ERASE;
    UA_Variant in;
    UA_Variant_setScalar(&in, &mode, &UA_TYPES[UA_TYPES_BYTE]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_call(c, ns0(TLOBJ), ns0(TLM(OPEN)), 1, &in, &outN, &out);
    const UA_UInt32 *hp = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_UINT32]);
    UA_UInt32 h = hp ? *hp : 0;
    if(out)
        UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    if(r == UA_STATUSCODE_GOOD && !hp)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(r == UA_STATUSCODE_GOOD)
        r = call_h(c, TLM(WRITE), h, &file);
    UA_ByteString_clear(&file);
    if(r != UA_STATUSCODE_GOOD) {
        if(c)
            st_discard(c);
        UA_TrustListDataType_clear(&l0);
        ga_not_tested(ctx, "setup: Open and Write -> %s", UA_StatusCode_name(r));
        return;
    }
    ga_note(ctx, "ActivityTimeout %.0f ms; idle for %.0f ms", ms, ms + 10000.0);
    UA_DateTime end = UA_DateTime_nowMonotonic() + (UA_DateTime)((ms + 10000.0) * UA_DATETIME_MSEC);
    while(UA_DateTime_nowMonotonic() < end) {
        (void)UA_Client_run_iterate(c, 200);
        (void)UA_Client_run_iterate(t->client, 0);
    }
    UA_StatusCode cu = call_h(c, TLM(CLOSEANDUPDATE), h, NULL);
    ga_note(ctx, "CloseAndUpdate after the idle time -> %s", UA_StatusCode_name(cu));
    st_discard(c);
    r = applied(t, &l1);
    char why[160] = "";
    bool same = r == UA_STATUSCODE_GOOD && st_lists_equal(&l0, &l1, why, sizeof(why));
    UA_TrustListDataType_clear(&l0);
    UA_TrustListDataType_clear(&l1);
    if(cu == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "CloseAndUpdate succeeded on a handle idle longer than ActivityTimeout");
    else if(!same)
        ga_fail(ctx, "CloseAndUpdate failed but the list changed: %s", why);
    else
        ga_pass(ctx, "the idle handle was closed (%s); list unchanged", UA_StatusCode_name(cu));
}

/* CloseAndUpdate then CancelChanges; *has false if the target lacks it. */
static UA_StatusCode cancelled_txn(UA_Client *c, const UA_TrustListDataType *tl, bool *has,
                                   ga_ctx *ctx) {
    UA_NodeId cancel = UA_NODEID_NULL;
    bool present = false, txn = false; /* CancelChanges belongs to transactions (12 §7.10.3) */
    st_supports_transactions(c, &present, &txn);
    *has = txn && uac_find_child(c, ns0(UA_NS0ID_SERVERCONFIGURATION), "CancelChanges",
                                 &cancel) == UA_STATUSCODE_GOOD;
    if(!*has) {
        UA_NodeId_clear(&cancel);
        ga_note(ctx, "no CancelChanges or SupportsTransactions not TRUE: the cancelled "
                     "transaction is skipped");
        return UA_STATUSCODE_GOOD;
    }
    bool acr = false;
    UA_StatusCode r = st_write_trustlist(c, tl, 512, &acr, ctx);
    size_t outN = 0;
    UA_Variant *out = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_call(c, ns0(UA_NS0ID_SERVERCONFIGURATION), cancel, 0, NULL, &outN, &out);
    if(out)
        UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    UA_NodeId_clear(&cancel);
    ga_note(ctx, "CloseAndUpdate then CancelChanges -> %s", UA_StatusCode_name(r));
    return r;
}

/* The steps of SRV-TL-17; ts[0] is read before, ts[i] after step i. */
static UA_StatusCode lastupdate_steps(srv_target *t, const UA_TrustListDataType *l0,
                                      const UA_TrustListDataType *more, UA_DateTime ts[5],
                                      bool *hasCancel, ga_ctx *ctx) {
    UA_Client *c = t->client;
    bool acr = false;
    UA_StatusCode r = last_update(c, &ts[0]);
    if(r == UA_STATUSCODE_GOOD)
        r = write_apply(c, more, ctx); /* 1: an applied change */
    if(r == UA_STATUSCODE_GOOD)
        r = last_update(c, &ts[1]);
    if(r == UA_STATUSCODE_GOOD) /* 2: Open, Write, Close */
        r = st_write_trustlist_ex(c, l0, 512, false, &acr, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = last_update(c, &ts[2]);
    if(r == UA_STATUSCODE_GOOD) /* 3: a cancelled transaction */
        r = cancelled_txn(c, l0, hasCancel, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = last_update(c, &ts[3]);
    UA_StatusCode rr = write_apply(c, l0, ctx); /* 4: back to the list, always */
    if(rr == UA_STATUSCODE_GOOD)
        rr = last_update(c, &ts[4]);
    return r != UA_STATUSCODE_GOOD ? r : rr;
}

/* SRV-TL-17 (12 §7.8.2.1): LastUpdateTime moves with each applied change only */
static void t_tl_lastupdate(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_ready(ctx, t, true))
        return;
    UA_TrustListDataType l0, more;
    UA_TrustListDataType_init(&more);
    UA_DateTime ts[5] = {0};
    bool hasCancel = false;
    UA_StatusCode r = applied(t, &l0);
    if(r == UA_STATUSCODE_GOOD)
        r = st_list_copy_add(&l0, &t->peerCert, NULL, &more);
    if(r == UA_STATUSCODE_GOOD)
        r = lastupdate_steps(t, &l0, &more, ts, &hasCancel, ctx);
    UA_TrustListDataType_clear(&l0);
    UA_TrustListDataType_clear(&more);
    const char *bad = ts[1] <= ts[0]    ? "it did not move after an applied change"
                      : ts[2] != ts[1] ? "it moved after Close"
                      : ts[3] != ts[2] ? "it moved after CancelChanges"
                      : ts[4] <= ts[3] ? "it did not move after the second applied change"
                                       : NULL;
    if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "a step of the sequence failed: %s", UA_StatusCode_name(r));
    else if(bad)
        ga_fail(ctx, "LastUpdateTime: %s", bad);
    else
        ga_pass(ctx, "LastUpdateTime moved after both applied changes and stayed after Close%s",
                hasCancel ? " and CancelChanges" : "");
}

/* SRV-TL-19 (12 §7.8.2.1; OPC 10000-20 §4.2.1): Size has no meaning */
static void t_tl_size(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_StatusCode r = st_admin(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_NodeId size;
    if(uac_find_child(t->client, ns0(TLOBJ), "Size", &size) != UA_STATUSCODE_GOOD) {
        ga_pass(ctx, "the TrustList exposes no Size");
        return;
    }
    UA_Variant v;
    UA_Variant_init(&v);
    r = UA_Client_readValueAttribute(t->client, size, &v);
    UA_NodeId_clear(&size);
    bool num = UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_UINT64]);
    unsigned long long n = num ? (unsigned long long)*(UA_UInt64 *)v.data : 0;
    UA_Variant_clear(&v);
    if(r != UA_STATUSCODE_GOOD)
        ga_pass(ctx, "Read Size -> %s", UA_StatusCode_name(r));
    else if(num)
        ga_warn(ctx, "Size returns a value (%llu); it has no meaning for a TrustList", n);
    else
        ga_warn(ctx, "Size returns a value; it has no meaning for a TrustList");
}

/* SRV-TL-20 (12 §7.8.2.1): UpdateFrequency, if present, writable for admin */
static void t_tl_updatefreq(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_StatusCode r = st_admin(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_NodeId uf;
    if(uac_find_child(t->client, ns0(TLOBJ), "UpdateFrequency", &uf) != UA_STATUSCODE_GOOD) {
        ga_not_supported(ctx, "no UpdateFrequency (§7.8.2.1: not present inside "
                              "ServerConfiguration)");
        return;
    }
    UA_Byte ual = 0;
    r = UA_Client_readUserAccessLevelAttribute(t->client, uf, &ual);
    UA_NodeId_clear(&uf);
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "UserAccessLevel of UpdateFrequency -> %s", UA_StatusCode_name(r));
    else if(!(ual & UA_ACCESSLEVELMASK_WRITE))
        ga_fail(ctx, "UpdateFrequency is not writable for admin (UserAccessLevel 0x%02x)",
                (unsigned)ual);
    else
        ga_pass(ctx, "UpdateFrequency writable for admin (UserAccessLevel 0x%02x)", (unsigned)ual);
}

const ga_test srv_trustlist_tests[] = {
    {"SRV-TL-01", "12 §7.8.2.2", "Open refuses the modes the TrustList does not support", true,
     false, t_tl_open_modes},
    {"SRV-TL-02", "12 §7.8.2.1, §7.8.2.5, §7.10.9",
     "A trust list written in chunks and applied is read back unchanged", true, false,
     t_tl_write_readback},
    {"SRV-TL-03", "12 §7.8.2.1, §7.8.2.8", "The TrustList file is one bare TrustListDataType",
     false, false, t_tl_encoding},
    {"SRV-TL-04", "12 §7.8.2.5, §7.8.2.9", "CloseAndUpdate replaces only the specified lists",
     true, false, t_tl_mask},
    {"SRV-TL-05", "12 §7.8.2.3, §7.8.2.9", "OpenWithMasks returns only the requested lists",
     false, false, t_tl_masks_read},
    {"SRV-TL-06", "12 §7.8.2.1", "Close without CloseAndUpdate discards the written list", true,
     false, t_tl_close},
    {"SRV-TL-07", "12 §7.8.2.5", "A list with a broken signature is refused whole", true, false,
     t_tl_badsig},
    {"SRV-TL-08", "12 §7.8.2.5; 4 §6.1.3", "A list with an expired CA certificate is refused",
     true, false, t_tl_expired},
    {"SRV-TL-09", "12 §7.8.2.6", "AddCertificate adds a trusted certificate", true, false,
     t_tl_add},
    {"SRV-TL-10", "12 §7.8.2.6", "AddCertificate refuses IsTrustedCertificate FALSE", true, false,
     t_tl_add_issuer},
    {"SRV-TL-11", "12 §7.8.2.6", "AddCertificate needs the issuer in the TrustList", true, false,
     t_tl_add_nochain},
    {"SRV-TL-12", "12 §7.8.2.6", "AddCertificate refuses while the TrustList is open", true, false,
     t_tl_add_open},
    {"SRV-TL-13", "12 §7.8.2.7", "RemoveCertificate of an unknown thumbprint is refused", true,
     false, t_tl_remove_unknown},
    {"SRV-TL-14", "12 §7.8.2.7", "RemoveCertificate removes a trusted certificate", true, false,
     t_tl_remove},
    {"SRV-TL-15", "12 §7.8.2.7", "RemoveCertificate keeps a CA another certificate needs", true,
     false, t_tl_remove_in_use},
    {"SRV-TL-16", "12 §7.8.2.7", "RemoveCertificate of a CA removes its CRLs", true, false,
     t_tl_remove_crl},
    {"SRV-TL-17", "12 §7.8.2.1", "LastUpdateTime moves with applied changes only", true, false,
     t_tl_lastupdate},
    {"SRV-TL-18", "12 §7.8.2.1", "An idle write handle is closed after ActivityTimeout", true,
     false, t_tl_idle},
    {"SRV-TL-19", "12 §7.8.2.1", "The TrustList Size Property returns no value", false, false,
     t_tl_size},
    {"SRV-TL-20", "12 §7.8.2.1", "UpdateFrequency, if present, is writable for admin", false,
     false, t_tl_updatefreq},
};
const size_t srv_trustlist_count = GDS_ARRAY_SIZE(srv_trustlist_tests);
