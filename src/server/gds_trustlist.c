/* OpenGDS - the DefaultApplicationGroup TrustList (OPC 10000-12 §7.8.2
 * TrustListType, OPC 10000-20 §4.2 FileType).
 *
 * Reading: Open(Read), OpenWithMasks, Read, Close, GetPosition,
 * SetPosition. The file is the binary TrustListDataType, built at Open:
 * the CA certificate and its CRL first, then the entries an administrator
 * wrote.
 *
 * Writing (pull management, so CertificateAuthorityAdmin, §7.8.2.5-7):
 * Open(Write+EraseExisting) / Write / CloseAndUpdate, AddCertificate and
 * RemoveCertificate. The written entries are kept in the store (schema 4)
 * and every change is checked with gds_tl_validate first; a list that
 * fails is discarded. The GDS CA certificate and its CRL always stay in
 * the list: copies of them in a written list are dropped, and removing the
 * CA certificate is refused. The Directory has no transactions, so
 * CloseAndUpdate applies at once (ApplyChangesRequired FALSE). Every change
 * moves LastUpdateTime and raises a TrustListUpdatedAuditEventType.
 *
 * File handles: random, per session, at most GDS_MAX_TL_HANDLES; another
 * session's handle is unknown here. One writer and no reader, or readers
 * only (20 §4.2.2: Open for writing fails with Bad_NotWritable when the
 * file is open, Open for reading with Bad_NotReadable when it is open for
 * writing). A handle not used for ActivityTimeout is closed (§7.8.2.1).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>

#include "common/ids.h"
#include "common/limits.h"
#include "gds_internal.h"
#include "gds_tlcheck.h"
#include "common/banned.h"

#define FILE_MODE_READ 0x01u
#define FILE_MODE_WRITE_ERASE 0x06u
#define MAX_READ_CHUNK ((size_t)1024 * 1024)
#define ACTIVITY_TIMEOUT_MS 60000.0
#define GROUP_ID UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP
#define TL_NODE(m) UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_##m
#define SHA1_LEN ((size_t)20)
#define SEVERITY_CHANGE 500

/* ---- open handles ---- */

static gds_tl_handle *openList; /* every session's open handles; server thread */

static void handle_clear(gds_tl_handle *h) {
    UA_ByteString_clear(&h->file);
    memset(h, 0, sizeof(*h));
}

static void close_handle(gds_tl_handle *h) {
    for(gds_tl_handle **pp = &openList; *pp; pp = &(*pp)->next) {
        if(*pp == h) {
            *pp = h->next;
            break;
        }
    }
    handle_clear(h);
}

static void on_session_free(gds_session *sess) {
    for(size_t i = 0; i < GDS_SESSION_TL_HANDLES; i++)
        if(sess->tl[i].handle)
            close_handle(&sess->tl[i]);
}

/* Close the handles idle for longer than ActivityTimeout. */
static void expire(UA_DateTime now) {
    gds_tl_handle **pp = &openList;
    while(*pp) {
        gds_tl_handle *h = *pp;
        if(now - h->active > (UA_DateTime)(ACTIVITY_TIMEOUT_MS * UA_DATETIME_MSEC)) {
            *pp = h->next;
            handle_clear(h);
        } else {
            pp = &h->next;
        }
    }
}

/* After expiring the idle handles: is any handle (any writer) open? */
static bool is_open(bool writersOnly) {
    expire(UA_DateTime_nowMonotonic());
    for(const gds_tl_handle *h = openList; h; h = h->next)
        if(!writersOnly || h->write)
            return true;
    return false;
}

static gds_tl_handle *find_handle(void *sessionContext, UA_UInt32 h) {
    gds_session *s = sessionContext;
    for(size_t i = 0; s && h && i < GDS_SESSION_TL_HANDLES; i++)
        if(s->tl[i].handle == h)
            return &s->tl[i];
    return NULL;
}

/* ---- the stored entries ---- */

static UA_ByteString *list_of(UA_TrustListDataType *t, size_t i, size_t **n) {
    switch(i) {
    case 0: *n = &t->trustedCertificatesSize; return t->trustedCertificates;
    case 1: *n = &t->trustedCrlsSize; return t->trustedCrls;
    case 2: *n = &t->issuerCertificatesSize; return t->issuerCertificates;
    default: *n = &t->issuerCrlsSize; return t->issuerCrls;
    }
}
static UA_ByteString **list_ptr(UA_TrustListDataType *t, size_t i) {
    switch(i) {
    case 0: return &t->trustedCertificates;
    case 1: return &t->trustedCrls;
    case 2: return &t->issuerCertificates;
    default: return &t->issuerCrls;
    }
}
static const UA_UInt32 listMask[4] = {
    UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES, UA_TRUSTLISTMASKS_TRUSTEDCRLS,
    UA_TRUSTLISTMASKS_ISSUERCERTIFICATES, UA_TRUSTLISTMASKS_ISSUERCRLS};

static void remove_at(UA_TrustListDataType *t, size_t list, size_t i) {
    size_t *n = NULL;
    UA_ByteString *a = list_of(t, list, &n);
    UA_ByteString_clear(&a[i]);
    memmove(&a[i], &a[i + 1], (*n - i - 1) * sizeof(*a));
    if(--*n == 0) {
        UA_free(a);
        *list_ptr(t, list) = NULL;
    }
}

/* The administrator's entries; empty when none were written (or the
 * backend cannot keep them). */
static UA_StatusCode load_entries(gds_server *s, UA_TrustListDataType *out) {
    UA_TrustListDataType_init(out);
    gds_buf b = {0};
    int64_t lastUpdate = 0;
    gds_lock(s);
    gds_status st = gds_store_tl_get(s->store, GROUP_ID, &b, &lastUpdate);
    gds_unlock(s);
    if(st == GDS_ENOTFOUND || st == GDS_EUNSUPPORTED)
        return UA_STATUSCODE_GOOD;
    if(st != GDS_OK)
        return gds_status_to_ua(st);
    UA_ByteString bs = {b.len, b.data};
    UA_StatusCode r = UA_decodeBinary(&bs, out, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
    gds_buf_free(&b);
    if(r != UA_STATUSCODE_GOOD) {
        UA_TrustListDataType_clear(out);
        return UA_STATUSCODE_BADINTERNALERROR; /* the store holds what we wrote */
    }
    out->specifiedLists = UA_TRUSTLISTMASKS_ALL;
    return UA_STATUSCODE_GOOD;
}

static void set_last_update_node(gds_server *s) {
    UA_Variant v;
    UA_Variant_setScalar(&v, &s->tlLastUpdate, &UA_TYPES[UA_TYPES_DATETIME]);
    if(UA_Server_writeValue(s->ua, UA_NODEID_NUMERIC(s->ns, TL_NODE(LASTUPDATETIME)), v) !=
       UA_STATUSCODE_GOOD)
        fprintf(stderr, "opengds: cannot set the trust list LastUpdateTime\n");
}

static UA_StatusCode save_entries(gds_server *s, UA_TrustListDataType *t) {
    t->specifiedLists = UA_TRUSTLISTMASKS_ALL;
    UA_ByteString enc = UA_BYTESTRING_NULL;
    UA_StatusCode r = UA_encodeBinary(t, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &enc, NULL);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(enc.length > GDS_MAX_TRUSTLIST_SIZE / 2) { /* room for the CA's CRL */
        UA_ByteString_clear(&enc);
        return UA_STATUSCODE_BADREQUESTTOOLARGE;
    }
    /* LastUpdateTime only moves forward, also within one clock tick */
    UA_DateTime now = UA_DateTime_now();
    UA_DateTime t1 = now > s->tlLastUpdate ? now : s->tlLastUpdate + 1;
    gds_buf b = {enc.data, enc.length};
    gds_lock(s);
    gds_status st = gds_store_tl_put(s->store, GROUP_ID, &b, t1);
    gds_unlock(s);
    UA_ByteString_clear(&enc);
    if(st != GDS_OK)
        return gds_status_to_ua(st);
    s->tlLastUpdate = t1;
    set_last_update_node(s);
    return UA_STATUSCODE_GOOD;
}

/* ---- the file ---- */

/* Prepend a copy of first to the list (the GDS's own entries come first). */
static UA_StatusCode prepend(UA_ByteString **a, size_t *n, const UA_ByteString *first) {
    UA_ByteString *b = (UA_ByteString *)UA_Array_new(*n + 1, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(!b)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode r = UA_ByteString_copy(first, &b[0]);
    if(r != UA_STATUSCODE_GOOD) {
        UA_free(b);
        return r;
    }
    if(*n)
        memcpy(&b[1], *a, *n * sizeof(**a)); /* moved, not copied */
    UA_free(*a);
    *a = b;
    (*n)++;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode gds_trustlist_data(gds_server *s, UA_UInt32 masks, UA_TrustListDataType *out) {
    UA_StatusCode r = load_entries(s, out);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    gds_buf crl = {0};
    gds_status st = gds_ca_get_crl(s->ca, &crl);
    if(st != GDS_OK) {
        UA_TrustListDataType_clear(out);
        return gds_status_to_ua(st);
    }
    UA_ByteString c = {s->caCert.len, s->caCert.data}, l = {crl.len, crl.data};
    r = prepend(&out->trustedCertificates, &out->trustedCertificatesSize, &c);
    if(r == UA_STATUSCODE_GOOD)
        r = prepend(&out->trustedCrls, &out->trustedCrlsSize, &l);
    gds_buf_free(&crl);
    out->specifiedLists = masks & (UA_UInt32)UA_TRUSTLISTMASKS_ALL;
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && i < 4; i++) {
        if(out->specifiedLists & listMask[i])
            continue;
        size_t *n = NULL;
        void *list = list_of(out, i, &n); /* sets n: not in the same call (order) */
        UA_Array_delete(list, *n, &UA_TYPES[UA_TYPES_BYTESTRING]);
        *list_ptr(out, i) = NULL;
        *n = 0;
    }
    if(r != UA_STATUSCODE_GOOD)
        UA_TrustListDataType_clear(out);
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

static UA_StatusCode open_file(gds_server *s, void *sessionContext, UA_UInt32 masks, bool write,
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
    UA_ByteString file = UA_BYTESTRING_NULL; /* Write+EraseExisting: empty */
    UA_StatusCode r = write ? UA_STATUSCODE_GOOD : build_file(s, masks, &file);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[0], &h, &UA_TYPES[UA_TYPES_UINT32]);
    if(r != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&file);
        return r;
    }
    slot->handle = h;
    slot->write = write;
    slot->file = file;
    slot->pos = 0;
    slot->active = UA_DateTime_nowMonotonic();
    slot->next = openList;
    openList = slot;
    return UA_STATUSCODE_GOOD;
}

/* ---- access ---- */

/* Changing the list: pull management, so CertificateAuthorityAdmin
 * (§7.8.2.5-7), over an authenticated channel (§7.8.2.2), on the primary. */
static UA_StatusCode may_change(gds_server *s, const void *sessionContext) {
    const gds_session *sess = gds_session_get(sessionContext);
    if(!sess || sess->securityMode < UA_MESSAGESECURITYMODE_SIGN)
        return UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;
    if(!gds_session_has(sessionContext, GDS_ROLE_CERTIFICATE_AUTHORITY_ADMIN))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    return gds_refuse_on_standby(s);
}

static void audit(gds_server *s, const void *sessionContext, UA_UInt32 method,
                  const UA_Variant *input, size_t inputSize, bool ok) {
    const gds_session *sess = gds_session_get(sessionContext);
    UA_NodeId methodId = UA_NODEID_NUMERIC(s->ns, method);
    gds_event_field f[2];
    f[0].nsIndex = 0;
    f[0].name = "MethodId";
    UA_Variant_setScalar(&f[0].value, &methodId, &UA_TYPES[UA_TYPES_NODEID]);
    f[1].nsIndex = 0;
    f[1].name = "InputArguments";
    UA_Variant_setArray(&f[1].value, (void *)(uintptr_t)input, inputSize,
                        &UA_TYPES[UA_TYPES_VARIANT]);
    UA_NodeId visible[2] = {
        UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN),
        UA_NODEID_NUMERIC(s->ns, UA_GDSID_WELLKNOWNROLE_CERTIFICATEAUTHORITYADMIN)};
    gds_audit_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.abi_major = GDS_PLUGIN_ABI_MAJOR;
    ev.abi_minor = GDS_PLUGIN_ABI_MINOR;
    ev.struct_size = sizeof(ev);
    ev.eventType = UA_NODEID_NUMERIC(0, UA_NS0ID_TRUSTLISTUPDATEDAUDITEVENTTYPE);
    ev.sourceNode = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST);
    ev.severity = SEVERITY_CHANGE;
    ev.message = ok ? "trust list updated" : "trust list update refused";
    ev.status = ok;
    ev.fields = f;
    ev.fieldsSize = 2;
    ev.visibleTo = visible;
    ev.visibleToSize = 2;
    const char *user = sess && !gds_session_anonymous(sess) ? sess->user : NULL;
    gds_status a = gds_audit_raise(s, user, &ev, NULL);
    if(a != GDS_OK && a != GDS_EUNSUPPORTED)
        fprintf(stderr, "opengds: audit of a trust list update: %s\n", gds_status_name(a));
}

/* ---- changing the list ---- */

static bool is_gds_crl(const UA_ByteString *der, X509 *gdsCa) {
    X509_CRL *c = gds_tl_parse_crl(der);
    bool r = c && X509_NAME_cmp(X509_CRL_get_issuer(c), X509_get_subject_name(gdsCa)) == 0;
    X509_CRL_free(c);
    return r;
}

/* Drop the GDS CA certificate and the CRLs it issued: the server adds the
 * current ones itself. */
static void strip_gds_entries(gds_server *s, UA_TrustListDataType *t, X509 *gdsCa) {
    UA_ByteString ca = {s->caCert.len, s->caCert.data};
    for(size_t list = 0; list < 4; list++) {
        bool crl = list == 1 || list == 3;
        size_t *n = NULL;
        list_of(t, list, &n);
        for(size_t i = *n; i-- > 0;) {
            const UA_ByteString *e = &list_of(t, list, &n)[i];
            if(crl ? is_gds_crl(e, gdsCa) : UA_ByteString_equal(e, &ca))
                remove_at(t, list, i);
        }
    }
}

static UA_StatusCode check_and_save(gds_server *s, UA_TrustListDataType *t, X509 *gdsCa) {
    strip_gds_entries(s, t, gdsCa);
    if(t->trustedCertificatesSize + t->trustedCrlsSize + t->issuerCertificatesSize +
           t->issuerCrlsSize >
       GDS_MAX_TRUSTLIST_ENTRIES)
        return UA_STATUSCODE_BADREQUESTTOOLARGE;
    UA_StatusCode r = gds_tl_validate(t, gdsCa);
    if(r == UA_STATUSCODE_GOOD)
        r = save_entries(s, t);
    return r;
}

/* The stored entries with the lists in `in`'s SpecifiedLists replaced
 * (§7.8.2.5: a partial update keeps the other lists). */
static UA_StatusCode update_from(gds_server *s, const UA_TrustListDataType *in) {
    X509 *gdsCa = gds_tl_parse_cert(&(UA_ByteString){s->caCert.len, s->caCert.data});
    UA_TrustListDataType cur;
    UA_StatusCode r = gdsCa ? load_entries(s, &cur) : UA_STATUSCODE_BADINTERNALERROR;
    if(!gdsCa)
        UA_TrustListDataType_init(&cur);
    UA_TrustListDataType src = *in; /* shallow, for list_of */
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && i < 4; i++) {
        if(!(in->specifiedLists & listMask[i]))
            continue;
        size_t *nc = NULL, *ns = NULL;
        UA_ByteString *old = list_of(&cur, i, &nc);
        const UA_ByteString *neu = list_of(&src, i, &ns);
        UA_Array_delete(old, *nc, &UA_TYPES[UA_TYPES_BYTESTRING]);
        *list_ptr(&cur, i) = NULL;
        *nc = 0;
        r = UA_Array_copy(neu, *ns, (void **)list_ptr(&cur, i), &UA_TYPES[UA_TYPES_BYTESTRING]);
        if(r == UA_STATUSCODE_GOOD)
            *nc = *ns;
    }
    if(r == UA_STATUSCODE_GOOD)
        r = check_and_save(s, &cur, gdsCa);
    UA_TrustListDataType_clear(&cur);
    X509_free(gdsCa);
    return r;
}

static UA_StatusCode sha1_of(const UA_ByteString *der, uint8_t out[SHA1_LEN]) {
    unsigned int n = 0;
    return EVP_Digest(der->data, der->length, out, &n, EVP_sha1(), NULL) == 1 && n == SHA1_LEN
               ? UA_STATUSCODE_GOOD
               : UA_STATUSCODE_BADINTERNALERROR;
}

static int hexval(UA_Byte c) {
    if(c >= '0' && c <= '9')
        return c - '0';
    if(c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if(c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* The SHA1 thumbprint as hexadecimal text (§7.8.2.7), either case. */
static bool parse_thumbprint(const UA_String *t, uint8_t out[SHA1_LEN]) {
    if(t->length != 2 * SHA1_LEN)
        return false;
    for(size_t i = 0; i < SHA1_LEN; i++) {
        int hi = hexval(t->data[2 * i]), lo = hexval(t->data[2 * i + 1]);
        if(hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return true;
}

/* Index of the entry of `list` with this thumbprint, or *n. */
static size_t find_thumb(UA_TrustListDataType *t, size_t list, const uint8_t tp[SHA1_LEN]) {
    size_t *n = NULL;
    const UA_ByteString *a = list_of(t, list, &n);
    for(size_t i = 0; i < *n; i++) {
        uint8_t d[SHA1_LEN];
        if(sha1_of(&a[i], d) == UA_STATUSCODE_GOOD && memcmp(d, tp, SHA1_LEN) == 0)
            return i;
    }
    return *n;
}

/* A removed CA takes its CRLs with it (§7.8.2.7). */
static void remove_crls_of(UA_TrustListDataType *t, X509 *ca) {
    EVP_PKEY *k = X509_get0_pubkey(ca);
    for(size_t list = 1; k && list < 4; list += 2) {
        size_t *n = NULL;
        list_of(t, list, &n);
        for(size_t i = *n; i-- > 0;) {
            X509_CRL *c = gds_tl_parse_crl(&list_of(t, list, &n)[i]);
            bool its = c && X509_NAME_cmp(X509_CRL_get_issuer(c), X509_get_subject_name(ca)) == 0 &&
                       X509_CRL_verify(c, k) == 1;
            X509_CRL_free(c);
            if(its)
                remove_at(t, list, i);
        }
    }
}

static UA_StatusCode add_certificate(gds_server *s, const UA_ByteString *cert) {
    X509 *x = gds_tl_parse_cert(cert);
    bool ca = x && gds_tl_is_ca(x);
    X509_free(x);
    if(!x || ca) /* CA certificates go in with Write (§7.8.2.6) */
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    X509 *gdsCa = gds_tl_parse_cert(&(UA_ByteString){s->caCert.len, s->caCert.data});
    if(!gdsCa)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_TrustListDataType cur;
    UA_StatusCode r = load_entries(s, &cur);
    bool present = false;
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && i < cur.trustedCertificatesSize; i++)
        present = present || UA_ByteString_equal(&cur.trustedCertificates[i], cert);
    if(r == UA_STATUSCODE_GOOD && !present)
        r = UA_Array_appendCopy((void **)&cur.trustedCertificates, &cur.trustedCertificatesSize,
                                cert, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = check_and_save(s, &cur, gdsCa);
    UA_TrustListDataType_clear(&cur);
    X509_free(gdsCa);
    return r;
}

static UA_StatusCode remove_certificate(gds_server *s, const uint8_t tp[SHA1_LEN], bool trusted) {
    uint8_t caTp[SHA1_LEN];
    UA_ByteString caDer = {s->caCert.len, s->caCert.data};
    X509 *gdsCa = gds_tl_parse_cert(&caDer);
    if(!gdsCa || sha1_of(&caDer, caTp) != UA_STATUSCODE_GOOD) {
        X509_free(gdsCa);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_TrustListDataType cur;
    UA_StatusCode r = load_entries(s, &cur);
    size_t list = trusted ? 0 : 2, *n = NULL;
    list_of(&cur, list, &n);
    size_t at = r == UA_STATUSCODE_GOOD ? find_thumb(&cur, list, tp) : 0;
    if(r != UA_STATUSCODE_GOOD) {
        /* nothing */
    } else if(memcmp(tp, caTp, SHA1_LEN) == 0) {
        /* the GDS CA issues every certificate of the group: it stays */
        r = UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE;
    } else if(at == *n) {
        r = UA_STATUSCODE_BADINVALIDARGUMENT; /* in neither list */
    } else {
        X509 *x = gds_tl_parse_cert(&list_of(&cur, list, &n)[at]);
        remove_at(&cur, list, at);
        if(x && gds_tl_is_ca(x))
            remove_crls_of(&cur, x);
        X509_free(x);
        /* a CA another entry still needs: Bad_CertificateChainIncomplete */
        r = check_and_save(s, &cur, gdsCa);
    }
    UA_TrustListDataType_clear(&cur);
    X509_free(gdsCa);
    return r;
}

/* ---- methods ---- */

static UA_StatusCode open_checked(gds_server *s, void *sessionContext, UA_UInt32 masks,
                                  UA_Variant *output) {
    if(is_open(true))
        return UA_STATUSCODE_BADNOTREADABLE; /* 20 §4.2.2: open for writing */
    return open_file(s, sessionContext, masks, false, output);
}

static GDS_METHOD(tl_open) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    if(inputSize < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const void *p = NULL;
    if(gds_arg_scalar(&input[0], &UA_TYPES[UA_TYPES_BYTE], &p) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Byte mode = *(const UA_Byte *)p;
    if(mode == FILE_MODE_READ)
        return open_checked(s, sessionContext, UA_TRUSTLISTMASKS_ALL, output);
    if(mode != FILE_MODE_WRITE_ERASE)
        return UA_STATUSCODE_BADNOTSUPPORTED; /* §7.8.2.2 */
    UA_StatusCode r = may_change(s, sessionContext);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(is_open(false))
        return UA_STATUSCODE_BADNOTWRITABLE; /* 20 §4.2.2: already open */
    return open_file(s, sessionContext, UA_TRUSTLISTMASKS_ALL, true, output);
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
    return open_checked(gds_ctx(methodContext), sessionContext, masks, output);
}

static UA_StatusCode handle_arg(void *sessionContext, size_t inputSize, const UA_Variant *input,
                                gds_tl_handle **out) {
    if(inputSize < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const void *p = NULL;
    if(gds_arg_scalar(&input[0], &UA_TYPES[UA_TYPES_UINT32], &p) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_DateTime now = UA_DateTime_nowMonotonic();
    expire(now);
    *out = find_handle(sessionContext, *(const UA_UInt32 *)p);
    if(!*out)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    (*out)->active = now;
    return UA_STATUSCODE_GOOD;
}

static GDS_METHOD(tl_read) {
    GDS_METHOD_UNUSED;
    (void)methodContext;
    gds_tl_handle *h = NULL;
    UA_StatusCode r = handle_arg(sessionContext, inputSize, input, &h);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(h->write)
        return UA_STATUSCODE_BADINVALIDSTATE; /* not opened for reading */
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

static GDS_METHOD(tl_write) {
    GDS_METHOD_UNUSED;
    (void)methodContext, (void)output;
    gds_tl_handle *h = NULL;
    UA_StatusCode r = handle_arg(sessionContext, inputSize, input, &h);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(!h->write)
        return UA_STATUSCODE_BADINVALIDSTATE; /* not opened for writing */
    const UA_ByteString *data = NULL;
    if(inputSize < 2)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if(gds_arg_bytes(&input[1], GDS_MAX_TRUSTLIST_SIZE, &data) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    GDS_ASSERT(h->pos <= h->file.length);
    if(data->length > GDS_MAX_TRUSTLIST_SIZE - h->pos)
        return UA_STATUSCODE_BADREQUESTTOOLARGE; /* MaxTrustListSize */
    size_t end = h->pos + data->length;
    if(end > h->file.length) {
        UA_Byte *b = (UA_Byte *)UA_realloc(h->file.data, end);
        if(!b)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        h->file.data = b;
        h->file.length = end;
    }
    if(data->length)
        memcpy(h->file.data + h->pos, data->data, data->length);
    h->pos = end;
    return UA_STATUSCODE_GOOD;
}

static GDS_METHOD(tl_close) {
    GDS_METHOD_UNUSED;
    (void)methodContext, (void)output;
    gds_tl_handle *h = NULL;
    UA_StatusCode r = handle_arg(sessionContext, inputSize, input, &h);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    close_handle(h); /* a written list is discarded (§7.8.2.1) */
    return UA_STATUSCODE_GOOD;
}

static GDS_METHOD(tl_close_and_update) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    gds_tl_handle *h = NULL;
    UA_StatusCode r = handle_arg(sessionContext, inputSize, input, &h);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(!h->write)
        return UA_STATUSCODE_BADINVALIDSTATE; /* §7.8.2.5: only after Open for writing */
    r = may_change(s, sessionContext);
    if(r != UA_STATUSCODE_GOOD)
        return r; /* the handle stays open: a Close discards it */
    UA_ByteString file = h->file;
    h->file = UA_BYTESTRING_NULL;
    close_handle(h);
    UA_TrustListDataType in;
    UA_TrustListDataType_init(&in);
    r = UA_decodeBinary(&file, &in, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
    UA_ByteString_clear(&file);
    if(r != UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADINVALIDARGUMENT; /* not a TrustListDataType */
    else
        r = update_from(s, &in);
    UA_TrustListDataType_clear(&in);
    audit(s, sessionContext, TL_NODE(CLOSEANDUPDATE), input, 1, r == UA_STATUSCODE_GOOD);
    UA_Boolean applyChangesRequired = false; /* no transactions: applied now */
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[0], &applyChangesRequired,
                                     &UA_TYPES[UA_TYPES_BOOLEAN]);
    return r;
}

static GDS_METHOD(tl_add_certificate) {
    GDS_METHOD_UNUSED;
    (void)output;
    gds_server *s = gds_ctx(methodContext);
    UA_StatusCode r = may_change(s, sessionContext);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(inputSize < 2)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const UA_ByteString *cert = NULL;
    const void *trusted = NULL;
    if(gds_arg_bytes(&input[0], GDS_MAX_CERT_SIZE, &cert) != UA_STATUSCODE_GOOD ||
       gds_arg_scalar(&input[1], &UA_TYPES[UA_TYPES_BOOLEAN], &trusted) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(!*(const UA_Boolean *)trusted)
        r = UA_STATUSCODE_BADCERTIFICATEINVALID; /* §7.8.2.6: Trusted list only */
    else if(is_open(true))
        r = UA_STATUSCODE_BADINVALIDSTATE; /* open for writing */
    else
        r = add_certificate(s, cert);
    audit(s, sessionContext, TL_NODE(ADDCERTIFICATE), input, 2, r == UA_STATUSCODE_GOOD);
    return r;
}

static GDS_METHOD(tl_remove_certificate) {
    GDS_METHOD_UNUSED;
    (void)output;
    gds_server *s = gds_ctx(methodContext);
    UA_StatusCode r = may_change(s, sessionContext);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(inputSize < 2)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const UA_String *thumb = NULL;
    const void *trusted = NULL;
    if(gds_arg_string(&input[0], 2 * SHA1_LEN + 1, &thumb) != UA_STATUSCODE_GOOD ||
       gds_arg_scalar(&input[1], &UA_TYPES[UA_TYPES_BOOLEAN], &trusted) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    uint8_t tp[SHA1_LEN];
    if(!parse_thumbprint(thumb, tp))
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    else if(is_open(true))
        r = UA_STATUSCODE_BADINVALIDSTATE;
    else
        r = remove_certificate(s, tp, *(const UA_Boolean *)trusted);
    audit(s, sessionContext, TL_NODE(REMOVECERTIFICATE), input, 2, r == UA_STATUSCODE_GOOD);
    return r;
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

/* LastUpdateTime from the store (DateTime.MinValue when the list was never
 * written, §7.8.2.1), Writable, and ActivityTimeout. */
static void init_variables(gds_server *s) {
    gds_buf b = {0};
    int64_t lastUpdate = 0;
    gds_lock(s);
    gds_status st = gds_store_tl_get(s->store, GROUP_ID, &b, &lastUpdate);
    gds_unlock(s);
    gds_buf_free(&b);
    s->tlLastUpdate = st == GDS_OK ? lastUpdate : 0;
    set_last_update_node(s);
    UA_Duration timeout = ACTIVITY_TIMEOUT_MS;
    UA_Variant v;
    UA_Variant_setScalar(&v, &timeout, &UA_TYPES[UA_TYPES_DURATION]);
    (void)UA_Server_writeValue(s->ua, UA_NODEID_NUMERIC(s->ns, TL_NODE(ACTIVITYTIMEOUT)), v);
    UA_Boolean writable = st != GDS_EUNSUPPORTED;
    UA_Variant_setScalar(&v, &writable, &UA_TYPES[UA_TYPES_BOOLEAN]);
    (void)UA_Server_writeValue(s->ua, UA_NODEID_NUMERIC(s->ns, TL_NODE(WRITABLE)), v);
}

UA_StatusCode gds_trustlist_install(gds_server *s) {
    static const gds_method_entry m[] = {
        {TL_NODE(OPEN), tl_open},
        {TL_NODE(OPENWITHMASKS), tl_open_with_masks},
        {TL_NODE(READ), tl_read},
        {TL_NODE(WRITE), tl_write},
        {TL_NODE(CLOSE), tl_close},
        {TL_NODE(CLOSEANDUPDATE), tl_close_and_update},
        {TL_NODE(ADDCERTIFICATE), tl_add_certificate},
        {TL_NODE(REMOVECERTIFICATE), tl_remove_certificate},
        {TL_NODE(GETPOSITION), tl_get_position},
        {TL_NODE(SETPOSITION), tl_set_position},
    };
    openList = NULL;
    gds_access_on_session_free(on_session_free);
    init_variables(s);
    return gds_install_methods(s, m, GDS_ARRAY_SIZE(m));
}
