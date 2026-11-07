/* OpenGDS - plugin CertificateGroups with a writable TrustList (UASM ask
 * A18), for example the SKS's list of push targets that admins manage
 * over OPC UA only.
 *
 * gds_server_add_trust_list creates a CertificateGroupType object (OPC
 * 10000-12 §7.8.3.1) under the plugin's object; its TrustList
 * (TrustListType, §7.8.2.1) is kept in an open62541 memory store and
 * saved after every change, as one encoded TrustListDataType, to
 * pkiDir/trustlist.bin (written atomically, mode 0600), so it survives
 * restarts. (open62541 v1.5.10's file store appends the group NodeId to
 * its directory without terminating the string, so its directory name
 * changes from run to run and the lists were lost.) The TrustList methods
 * are OpenGDS's:
 * - Open (FileType; mode Read 0x01 or Write|EraseExisting 0x06, §7.8.2.1)
 *   and OpenWithMasks (§7.8.2.2) take a snapshot to read; one writer at a
 *   time, and no writer while anyone reads (Bad_NotWritable /
 *   Bad_NotReadable);
 * - Read, Write, GetPosition, SetPosition, Close (OPC 10000-20 §4.2);
 * - CloseAndUpdate (§7.8.2.3) decodes the written TrustListDataType,
 *   checks every certificate and CRL and replaces the lists it specifies;
 *   applyChangesRequired is FALSE (the change is live at once);
 * - AddCertificate (§7.8.2.4) adds a trusted certificate, or with
 *   isTrustedCertificate FALSE an issuer (CA) certificate; refused while
 *   the TrustList is open (Bad_InvalidState);
 * - RemoveCertificate (§7.8.2.5) removes a certificate by its SHA-1
 *   thumbprint (hex), with the CRLs of a CA (Bad_InvalidArgument if none).
 * - On a STANDBY node the writing calls answer Bad_InvalidState; the
 *   embedder keeps the lists in line with gds_server_set_trust_list (A20),
 *   which also makes a writer opened before it fail at CloseAndUpdate.
 * Handles belong to the session that opened them; a handle of a session
 * that has closed is dropped when it is in the way. Only sessions with
 * one of the group's Roles over SignAndEncrypt may call the methods
 * (gds_access.c); UserWritable reads TRUE for them (A17).
 * These method nodes are namespace 0's FileType and TrustListType methods,
 * which instances share: a call on another object goes to the callback
 * that was bound before.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <open62541/plugin/certificategroup_default.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/buf.h"
#include "common/limits.h"
#include "gds_internal.h"
#include "common/banned.h"

#define PTL_HANDLES 8
#define PTL_MAX_FILE GDS_MAX_TRUSTLIST_SIZE
#define MODE_READ 0x01u
#define MODE_WRITE 0x02u
#define MODE_ERASE 0x04u

typedef struct {
    UA_UInt32 handle; /* 0 = free */
    UA_NodeId session;
    bool write;
    UA_UInt64 gen; /* p->gen when a writer opened */
    UA_ByteString file;
    size_t pos;
} ptl_handle;

struct gds_ptl {
    UA_NodeId group, tl;
    UA_NodeId sizeNode, openCountNode, lastUpdateNode;
    UA_CertificateGroup cg; /* under ptlLock */
    UA_UInt64 gen;          /* replacements by the embedder (A20), ptlLock */
    unsigned roleBits;
    bool anon, auth;
    ptl_handle h[PTL_HANDLES]; /* server thread only */
    UA_NodeId mids[10];        /* the methods of this TrustList, as METHODS[] */
    char file[GDS_MAX_PATH];   /* pkiDir/trustlist.bin */
};

typedef struct {
    UA_UInt32 id;
    UA_MethodCallback cb;
} ptl_method;

static const UA_UInt32 METHODS[] = {
    UA_NS0ID_FILETYPE_OPEN,          UA_NS0ID_FILETYPE_CLOSE,
    UA_NS0ID_FILETYPE_READ,          UA_NS0ID_FILETYPE_WRITE,
    UA_NS0ID_FILETYPE_GETPOSITION,   UA_NS0ID_FILETYPE_SETPOSITION,
    UA_NS0ID_TRUSTLISTTYPE_OPENWITHMASKS, UA_NS0ID_TRUSTLISTTYPE_CLOSEANDUPDATE,
    UA_NS0ID_TRUSTLISTTYPE_ADDCERTIFICATE, UA_NS0ID_TRUSTLISTTYPE_REMOVECERTIFICATE};
#define N_METHODS (sizeof(METHODS) / sizeof(METHODS[0]))

static const char *const METHOD_NAMES[] = {
    "Open",          "Close",          "Read",           "Write",           "GetPosition",
    "SetPosition",   "OpenWithMasks",  "CloseAndUpdate", "AddCertificate",  "RemoveCertificate"};

/* The METHODS[] entry for a method of this list: the type's method node,
 * or the copy open62541 made when it instantiated the mandatory ones. */
static UA_UInt32 method_of(const gds_ptl *p, const UA_NodeId *methodId) {
    for(size_t i = 0; methodId && i < N_METHODS; i++)
        if((methodId->namespaceIndex == 0 && methodId->identifierType == UA_NODEIDTYPE_NUMERIC &&
            methodId->identifier.numeric == METHODS[i]) ||
           UA_NodeId_equal(&p->mids[i], methodId))
            return METHODS[i];
    return 0;
}

/* ---- lookup ---- */

static gds_ptl *find_tl(gds_server *s, const UA_NodeId *obj) {
    for(size_t i = 0; obj && i < s->nPtls; i++)
        if(UA_NodeId_equal(&s->ptls[i]->tl, obj))
            return s->ptls[i];
    return NULL;
}

static gds_ptl *find_group(gds_server *s, const UA_NodeId *group) {
    for(size_t i = 0; group && i < s->nPtls; i++)
        if(UA_NodeId_equal(&s->ptls[i]->group, group))
            return s->ptls[i];
    return NULL;
}

bool gds_ptl_is_list(gds_server *s, const UA_NodeId *objectId, const UA_NodeId *methodId) {
    pthread_mutex_lock(&s->ptlLock);
    const gds_ptl *p = find_tl(s, objectId);
    bool r = p && (!methodId || method_of(p, methodId) != 0);
    pthread_mutex_unlock(&s->ptlLock);
    return r;
}

bool gds_ptl_may_call(gds_server *s, const void *sessionContext, const UA_NodeId *objectId) {
    const gds_session *ss = gds_session_get(sessionContext);
    if(!ss || ss->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return false;
    bool anon = gds_session_anonymous(ss);
    unsigned roles = gds_session_roles(ss);
    pthread_mutex_lock(&s->ptlLock);
    gds_ptl *p = find_tl(s, objectId);
    bool ok = p && (p->anon || (p->auth && !anon) || (p->roleBits & roles) != 0);
    pthread_mutex_unlock(&s->ptlLock);
    return ok;
}

/* ---- certificate checks ---- */

static bool cert_ok(const UA_ByteString *der, bool mustBeCa) {
    const unsigned char *p = der->data;
    X509 *x = der->length ? d2i_X509(NULL, &p, (long)der->length) : NULL;
    bool ok = x && p == der->data + der->length && (!mustBeCa || X509_check_ca(x) > 0);
    X509_free(x);
    return ok;
}

static bool crl_ok(const UA_ByteString *der) {
    const unsigned char *p = der->data;
    X509_CRL *c = der->length ? d2i_X509_CRL(NULL, &p, (long)der->length) : NULL;
    bool ok = c && p == der->data + der->length;
    X509_CRL_free(c);
    return ok;
}

static bool list_ok(const UA_TrustListDataType *tl) {
    for(size_t i = 0; i < tl->trustedCertificatesSize; i++)
        if(!cert_ok(&tl->trustedCertificates[i], false))
            return false;
    for(size_t i = 0; i < tl->issuerCertificatesSize; i++)
        if(!cert_ok(&tl->issuerCertificates[i], true))
            return false;
    for(size_t i = 0; i < tl->trustedCrlsSize; i++)
        if(!crl_ok(&tl->trustedCrls[i]))
            return false;
    for(size_t i = 0; i < tl->issuerCrlsSize; i++)
        if(!crl_ok(&tl->issuerCrls[i]))
            return false;
    return true;
}

/* ---- persistence ---- */

/* Saves the whole list after a change; ptlLock held. The change stays in
 * memory when the file cannot be written: Bad_InternalError tells the
 * caller it is not durable. */
static UA_StatusCode persist(gds_ptl *p, UA_StatusCode changed) {
    if(changed != UA_STATUSCODE_GOOD)
        return changed;
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    UA_ByteString enc = UA_BYTESTRING_NULL;
    UA_StatusCode r = p->cg.getTrustList(&p->cg, &tl);
    tl.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_encodeBinary(&tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &enc, NULL);
    if(r == UA_STATUSCODE_GOOD &&
       gds_file_write_atomic(p->file, enc.data, enc.length, 0600) != GDS_OK)
        r = UA_STATUSCODE_BADINTERNALERROR;
    UA_ByteString_clear(&enc);
    UA_TrustListDataType_clear(&tl);
    return r;
}

/* The saved list, if any (*tl empty when there is none yet). */
static gds_status load(const char *file, UA_TrustListDataType *tl) {
    UA_TrustListDataType_init(tl);
    gds_buf b = {0};
    gds_status st = gds_file_read(file, PTL_MAX_FILE, &b);
    if(st == GDS_ENOTFOUND)
        return GDS_OK;
    if(st != GDS_OK)
        return st;
    UA_ByteString enc = {b.len, b.data};
    if(UA_decodeBinary(&enc, tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL) !=
           UA_STATUSCODE_GOOD ||
       !list_ok(tl)) {
        UA_TrustListDataType_clear(tl);
        st = GDS_EINVAL;
    }
    gds_buf_free(&b);
    tl->specifiedLists = UA_TRUSTLISTMASKS_ALL;
    return st;
}

/* SHA-1 thumbprint as hex (OPC 10000-12 §7.8.2.5), either case. */
static bool thumb_matches(const UA_ByteString *der, const UA_String *hex) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    if(hex->length != 40 || EVP_Digest(der->data, der->length, md, &n, EVP_sha1(), NULL) != 1 ||
       n != 20)
        return false;
    static const char digits[] = "0123456789abcdef";
    char want[40];
    for(size_t i = 0; i < 20; i++) {
        want[2 * i] = digits[md[i] >> 4];
        want[(2 * i) + 1] = digits[md[i] & 0xf];
    }
    for(size_t i = 0; i < 40; i++)
        if(tolower(hex->data[i]) != want[i])
            return false;
    return true;
}

/* ---- properties ---- */

static void write_prop(UA_Server *ua, const UA_NodeId *n, const void *v, const UA_DataType *t) {
    UA_Variant var;
    UA_Variant_setScalar(&var, (void *)(uintptr_t)v, t);
    if(!UA_NodeId_isNull(n))
        (void)UA_Server_writeValue(ua, *n, var);
}

static void update_open_count(gds_server *s, gds_ptl *p) {
    UA_UInt16 n = 0;
    for(size_t i = 0; i < PTL_HANDLES; i++)
        n = (UA_UInt16)(n + (p->h[i].handle != 0));
    write_prop(s->ua, &p->openCountNode, &n, &UA_TYPES[UA_TYPES_UINT16]);
}

/* Size of the whole list's file and LastUpdateTime. */
static void update_size(gds_server *s, gds_ptl *p, bool changed) {
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    pthread_mutex_lock(&s->ptlLock);
    UA_StatusCode r = p->cg.getTrustList(&p->cg, &tl);
    pthread_mutex_unlock(&s->ptlLock);
    if(r == UA_STATUSCODE_GOOD) {
        tl.specifiedLists = UA_TRUSTLISTMASKS_ALL;
        UA_UInt64 size = UA_calcSizeBinary(&tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
        write_prop(s->ua, &p->sizeNode, &size, &UA_TYPES[UA_TYPES_UINT64]);
    }
    UA_TrustListDataType_clear(&tl);
    if(changed) {
        UA_DateTime now = UA_DateTime_now();
        write_prop(s->ua, &p->lastUpdateNode, &now, &UA_TYPES[UA_TYPES_DATETIME]);
    }
}

/* ---- handles ---- */

static ptl_handle *handle_of(gds_ptl *p, const UA_NodeId *session, UA_UInt32 h) {
    for(size_t i = 0; h && i < PTL_HANDLES; i++)
        if(p->h[i].handle == h && UA_NodeId_equal(&p->h[i].session, session))
            return &p->h[i];
    return NULL;
}

static void handle_free(ptl_handle *h) {
    UA_NodeId_clear(&h->session);
    UA_ByteString_clear(&h->file);
    memset(h, 0, sizeof(*h));
}

/* Drops the handles of sessions that have closed. */
static void drop_stale(gds_ptl *p) {
    for(size_t i = 0; i < PTL_HANDLES; i++)
        if(p->h[i].handle && !gds_access_session_live(&p->h[i].session))
            handle_free(&p->h[i]);
}

static bool any_open(gds_ptl *p, bool writers) {
    for(size_t i = 0; i < PTL_HANDLES; i++)
        if(p->h[i].handle && (!writers || p->h[i].write))
            return true;
    return false;
}

static ptl_handle *free_slot(gds_ptl *p) {
    for(size_t i = 0; i < PTL_HANDLES; i++)
        if(!p->h[i].handle)
            return &p->h[i];
    return NULL;
}

/* The file a reader gets: the lists the masks select (Part 12 §7.8.2.2). */
static UA_StatusCode encode_selected(gds_server *s, gds_ptl *p, UA_UInt32 masks,
                                     UA_ByteString *file) {
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    pthread_mutex_lock(&s->ptlLock);
    UA_StatusCode r = p->cg.getTrustList(&p->cg, &tl);
    pthread_mutex_unlock(&s->ptlLock);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_TrustListDataType sel;
    UA_TrustListDataType_init(&sel);
    sel.specifiedLists = masks & (UA_UInt32)UA_TRUSTLISTMASKS_ALL;
    if(masks & UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES) {
        sel.trustedCertificates = tl.trustedCertificates;
        sel.trustedCertificatesSize = tl.trustedCertificatesSize;
    }
    if(masks & UA_TRUSTLISTMASKS_TRUSTEDCRLS) {
        sel.trustedCrls = tl.trustedCrls;
        sel.trustedCrlsSize = tl.trustedCrlsSize;
    }
    if(masks & UA_TRUSTLISTMASKS_ISSUERCERTIFICATES) {
        sel.issuerCertificates = tl.issuerCertificates;
        sel.issuerCertificatesSize = tl.issuerCertificatesSize;
    }
    if(masks & UA_TRUSTLISTMASKS_ISSUERCRLS) {
        sel.issuerCrls = tl.issuerCrls;
        sel.issuerCrlsSize = tl.issuerCrlsSize;
    }
    r = UA_encodeBinary(&sel, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], file, NULL);
    UA_TrustListDataType_clear(&tl);
    return r;
}

static UA_StatusCode open_handle(gds_server *s, gds_ptl *p, const UA_NodeId *session, bool write,
                                 UA_UInt32 masks, UA_UInt32 *out) {
    if(any_open(p, true) || (write && any_open(p, false)))
        drop_stale(p);
    if(any_open(p, true))
        return write ? UA_STATUSCODE_BADNOTWRITABLE : UA_STATUSCODE_BADNOTREADABLE;
    if(write && any_open(p, false))
        return UA_STATUSCODE_BADNOTWRITABLE;
    ptl_handle *h = free_slot(p);
    if(!h) {
        drop_stale(p);
        h = free_slot(p);
    }
    if(!h)
        return UA_STATUSCODE_BADTOOMANYOPERATIONS;
    UA_StatusCode r = write ? UA_STATUSCODE_GOOD : encode_selected(s, p, masks, &h->file);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_NodeId_copy(session, &h->session);
    if(r != UA_STATUSCODE_GOOD) {
        handle_free(h);
        return r;
    }
    do {
        h->handle = UA_UInt32_random();
    } while(h->handle == 0 || handle_of(p, session, h->handle) != h);
    h->write = write;
    pthread_mutex_lock(&s->ptlLock);
    h->gen = p->gen;
    pthread_mutex_unlock(&s->ptlLock);
    *out = h->handle;
    update_open_count(s, p);
    return UA_STATUSCODE_GOOD;
}

/* ---- methods ---- */

static UA_MethodCallback prior[N_METHODS];

static UA_MethodCallback prior_of(const UA_NodeId *methodId) {
    for(size_t i = 0; i < N_METHODS; i++)
        if(METHODS[i] == methodId->identifier.numeric)
            return prior[i];
    return NULL;
}

static UA_StatusCode in_u32(size_t n, const UA_Variant *in, size_t i, UA_UInt32 *out) {
    if(i >= n || !UA_Variant_hasScalarType(&in[i], &UA_TYPES[UA_TYPES_UINT32]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    *out = *(UA_UInt32 *)in[i].data;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode set_out(UA_Variant *out, size_t nOut, const void *v, const UA_DataType *t) {
    if(nOut < 1)
        return UA_STATUSCODE_BADINTERNALERROR;
    return UA_Variant_setScalarCopy(&out[0], v, t);
}

static UA_StatusCode m_open(gds_server *s, gds_ptl *p, const UA_NodeId *sid, size_t n,
                            const UA_Variant *in, size_t nOut, UA_Variant *out, bool masks) {
    UA_UInt32 handle = 0, m = UA_TRUSTLISTMASKS_ALL;
    bool write = false;
    if(masks) {
        if(n != 1 || in_u32(n, in, 0, &m) != UA_STATUSCODE_GOOD)
            return UA_STATUSCODE_BADINVALIDARGUMENT;
    } else {
        if(n != 1 || !UA_Variant_hasScalarType(&in[0], &UA_TYPES[UA_TYPES_BYTE]))
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        UA_Byte mode = *(UA_Byte *)in[0].data;
        if(mode != MODE_READ && mode != (MODE_WRITE | MODE_ERASE))
            return UA_STATUSCODE_BADINVALIDARGUMENT; /* §7.8.2.1 */
        write = mode != MODE_READ;
    }
    if(write && gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    UA_StatusCode r = open_handle(s, p, sid, write, m, &handle);
    if(r == UA_STATUSCODE_GOOD)
        r = set_out(out, nOut, &handle, &UA_TYPES[UA_TYPES_UINT32]);
    return r;
}

static UA_StatusCode m_read(ptl_handle *h, size_t n, const UA_Variant *in, size_t nOut,
                            UA_Variant *out) {
    if(n != 2 || !UA_Variant_hasScalarType(&in[1], &UA_TYPES[UA_TYPES_INT32]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Int32 len = *(UA_Int32 *)in[1].data;
    if(h->write || len < 0)
        return h->write ? UA_STATUSCODE_BADINVALIDSTATE : UA_STATUSCODE_BADINVALIDARGUMENT;
    size_t left = h->file.length - h->pos, take = (size_t)len < left ? (size_t)len : left;
    UA_ByteString chunk = {take, take ? h->file.data + h->pos : NULL};
    UA_StatusCode r = set_out(out, nOut, &chunk, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        h->pos += take;
    return r;
}

static UA_StatusCode m_write(ptl_handle *h, size_t n, const UA_Variant *in) {
    if(n != 2 || !UA_Variant_hasScalarType(&in[1], &UA_TYPES[UA_TYPES_BYTESTRING]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(!h->write)
        return UA_STATUSCODE_BADINVALIDSTATE;
    const UA_ByteString *d = in[1].data;
    if(h->file.length + d->length > PTL_MAX_FILE)
        return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
    if(d->length == 0)
        return UA_STATUSCODE_GOOD;
    UA_Byte *g = realloc(h->file.data, h->file.length + d->length);
    if(!g)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    memcpy(g + h->file.length, d->data, d->length);
    h->file.data = g;
    h->file.length += d->length;
    h->pos = h->file.length;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode m_position(ptl_handle *h, bool set, size_t n, const UA_Variant *in,
                                size_t nOut, UA_Variant *out) {
    if(!set) {
        UA_UInt64 pos = h->pos;
        return set_out(out, nOut, &pos, &UA_TYPES[UA_TYPES_UINT64]);
    }
    if(n != 2 || !UA_Variant_hasScalarType(&in[1], &UA_TYPES[UA_TYPES_UINT64]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_UInt64 pos = *(UA_UInt64 *)in[1].data;
    h->pos = pos > h->file.length ? h->file.length : (size_t)pos;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode m_close_and_update(gds_server *s, gds_ptl *p, ptl_handle *h, size_t nOut,
                                        UA_Variant *out) {
    if(!h->write)
        return UA_STATUSCODE_BADINVALIDSTATE;
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    UA_StatusCode r = UA_decodeBinary(&h->file, &tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
    if(r != UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    else if((tl.specifiedLists & ~(UA_UInt32)UA_TRUSTLISTMASKS_ALL) != 0)
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    else if(!list_ok(&tl))
        r = UA_STATUSCODE_BADCERTIFICATEINVALID;
    else if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADINVALIDSTATE;
    if(r == UA_STATUSCODE_GOOD) {
        pthread_mutex_lock(&s->ptlLock);
        /* replaced by the embedder since this writer opened (A20) */
        r = h->gen == p->gen ? persist(p, p->cg.setTrustList(&p->cg, &tl))
                             : UA_STATUSCODE_BADINVALIDSTATE;
        pthread_mutex_unlock(&s->ptlLock);
    }
    UA_TrustListDataType_clear(&tl);
    handle_free(h); /* closed either way (OPC 10000-20 §4.2.2.5) */
    update_open_count(s, p);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    update_size(s, p, true);
    UA_Boolean apply = false;
    return set_out(out, nOut, &apply, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_StatusCode m_add(gds_server *s, gds_ptl *p, size_t n, const UA_Variant *in) {
    if(n != 2 || !UA_Variant_hasScalarType(&in[0], &UA_TYPES[UA_TYPES_BYTESTRING]) ||
       !UA_Variant_hasScalarType(&in[1], &UA_TYPES[UA_TYPES_BOOLEAN]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    drop_stale(p);
    if(any_open(p, false))
        return UA_STATUSCODE_BADINVALIDSTATE;
    UA_ByteString *cert = in[0].data;
    bool trusted = *(UA_Boolean *)in[1].data;
    if(!cert_ok(cert, !trusted))
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    if(trusted) {
        tl.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES;
        tl.trustedCertificates = cert;
        tl.trustedCertificatesSize = 1;
    } else {
        tl.specifiedLists = UA_TRUSTLISTMASKS_ISSUERCERTIFICATES;
        tl.issuerCertificates = cert;
        tl.issuerCertificatesSize = 1;
    }
    pthread_mutex_lock(&s->ptlLock);
    UA_StatusCode r = persist(p, p->cg.addToTrustList(&p->cg, &tl));
    pthread_mutex_unlock(&s->ptlLock);
    if(r == UA_STATUSCODE_GOOD)
        update_size(s, p, true);
    return r;
}

/* The entry with this thumbprint and, for a CA, its CRLs. */
static UA_StatusCode removal(const UA_TrustListDataType *all, const UA_String *thumb, bool trusted,
                             UA_TrustListDataType *out) {
    const UA_ByteString *certs = trusted ? all->trustedCertificates : all->issuerCertificates;
    size_t n = trusted ? all->trustedCertificatesSize : all->issuerCertificatesSize;
    const UA_ByteString *hit = NULL;
    for(size_t i = 0; i < n && !hit; i++)
        if(thumb_matches(&certs[i], thumb))
            hit = &certs[i];
    if(!hit)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_TrustListDataType_init(out);
    UA_StatusCode r = UA_Array_copy(hit, 1, (void **)(trusted ? &out->trustedCertificates
                                                              : &out->issuerCertificates),
                                    &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(trusted) {
        out->trustedCertificatesSize = 1;
        out->specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES;
    } else {
        out->issuerCertificatesSize = 1;
        out->specifiedLists = UA_TRUSTLISTMASKS_ISSUERCERTIFICATES;
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode m_remove(gds_server *s, gds_ptl *p, size_t n, const UA_Variant *in) {
    if(n != 2 || !UA_Variant_hasScalarType(&in[0], &UA_TYPES[UA_TYPES_STRING]) ||
       !UA_Variant_hasScalarType(&in[1], &UA_TYPES[UA_TYPES_BOOLEAN]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    drop_stale(p);
    if(any_open(p, false))
        return UA_STATUSCODE_BADINVALIDSTATE;
    bool trusted = *(UA_Boolean *)in[1].data;
    UA_TrustListDataType all, rm;
    UA_TrustListDataType_init(&all);
    UA_TrustListDataType_init(&rm);
    pthread_mutex_lock(&s->ptlLock);
    UA_StatusCode r = p->cg.getTrustList(&p->cg, &all);
    if(r == UA_STATUSCODE_GOOD)
        r = removal(&all, in[0].data, trusted, &rm);
    if(r == UA_STATUSCODE_GOOD) {
        /* a CA's CRLs go with it (§7.8.2.5) */
        UA_ByteString *crls = NULL;
        size_t nCrls = 0;
        const UA_ByteString *c = trusted ? rm.trustedCertificates : rm.issuerCertificates;
        if(p->cg.getCertificateCrls &&
           p->cg.getCertificateCrls(&p->cg, c, trusted, &crls, &nCrls) == UA_STATUSCODE_GOOD &&
           nCrls > 0) {
            if(trusted) {
                rm.trustedCrls = crls;
                rm.trustedCrlsSize = nCrls;
                rm.specifiedLists |= UA_TRUSTLISTMASKS_TRUSTEDCRLS;
            } else {
                rm.issuerCrls = crls;
                rm.issuerCrlsSize = nCrls;
                rm.specifiedLists |= UA_TRUSTLISTMASKS_ISSUERCRLS;
            }
        } else {
            UA_Array_delete(crls, nCrls, &UA_TYPES[UA_TYPES_BYTESTRING]);
        }
        r = persist(p, p->cg.removeFromTrustList(&p->cg, &rm));
    }
    pthread_mutex_unlock(&s->ptlLock);
    UA_TrustListDataType_clear(&all);
    UA_TrustListDataType_clear(&rm);
    if(r == UA_STATUSCODE_GOOD)
        update_size(s, p, true);
    return r;
}

/* Calls that name a file handle (input 0). */
static UA_StatusCode with_handle(gds_server *s, gds_ptl *p, UA_UInt32 id, const UA_NodeId *sid,
                                 size_t n, const UA_Variant *in, size_t nOut, UA_Variant *out) {
    UA_UInt32 hv = 0;
    if(in_u32(n, in, 0, &hv) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    ptl_handle *h = handle_of(p, sid, hv);
    if(!h)
        return UA_STATUSCODE_BADINVALIDARGUMENT; /* unknown, or another session's */
    switch(id) {
    case UA_NS0ID_FILETYPE_CLOSE:
        if(n != 1)
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        handle_free(h);
        update_open_count(s, p);
        return UA_STATUSCODE_GOOD;
    case UA_NS0ID_FILETYPE_READ:
        return m_read(h, n, in, nOut, out);
    case UA_NS0ID_FILETYPE_WRITE:
        return m_write(h, n, in);
    case UA_NS0ID_FILETYPE_GETPOSITION:
        return n == 1 ? m_position(h, false, n, in, nOut, out) : UA_STATUSCODE_BADINVALIDARGUMENT;
    case UA_NS0ID_FILETYPE_SETPOSITION:
        return m_position(h, true, n, in, nOut, out);
    case UA_NS0ID_TRUSTLISTTYPE_CLOSEANDUPDATE:
        return n == 1 ? m_close_and_update(s, p, h, nOut, out) : UA_STATUSCODE_BADINVALIDARGUMENT;
    default:
        return UA_STATUSCODE_BADMETHODINVALID;
    }
}

static GDS_METHOD(ptl_call) {
    gds_server *s = UA_Server_getConfig(server)->context;
    pthread_mutex_lock(&s->ptlLock);
    gds_ptl *p = find_tl(s, objectId);
    pthread_mutex_unlock(&s->ptlLock); /* lists live as long as the server */
    if(!p) {
        UA_MethodCallback cb = prior_of(methodId);
        return cb ? cb(server, sessionId, sessionContext, methodId, methodContext, objectId,
                       objectContext, inputSize, input, outputSize, output)
                  : UA_STATUSCODE_BADMETHODINVALID;
    }
    if(!gds_ptl_may_call(s, sessionContext, objectId))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    UA_UInt32 id = method_of(p, methodId);
    switch(id) {
    case UA_NS0ID_FILETYPE_OPEN:
        return m_open(s, p, sessionId, inputSize, input, outputSize, output, false);
    case UA_NS0ID_TRUSTLISTTYPE_OPENWITHMASKS:
        return m_open(s, p, sessionId, inputSize, input, outputSize, output, true);
    case UA_NS0ID_TRUSTLISTTYPE_ADDCERTIFICATE:
        return m_add(s, p, inputSize, input);
    case UA_NS0ID_TRUSTLISTTYPE_REMOVECERTIFICATE:
        return m_remove(s, p, inputSize, input);
    default:
        return with_handle(s, p, id, sessionId, inputSize, input, outputSize, output);
    }
}

/* ---- creation ---- */

static UA_NodeId child_of(UA_Server *ua, const UA_NodeId *parent, UA_UInt16 ns, const char *name) {
    UA_QualifiedName qn = UA_QUALIFIEDNAME(ns, (char *)(uintptr_t)name);
    UA_BrowsePathResult bp = UA_Server_browseSimplifiedBrowsePath(ua, *parent, 1, &qn);
    UA_NodeId id = UA_NODEID_NULL;
    if(bp.statusCode == UA_STATUSCODE_GOOD && bp.targetsSize == 1)
        (void)UA_NodeId_copy(&bp.targets[0].targetId.nodeId, &id);
    UA_BrowsePathResult_clear(&bp);
    return id;
}

static bool def_ok(const gds_trust_list_def *d) {
    return d && d->abi_major == GDS_PLUGIN_ABI_MAJOR &&
           d->struct_size >= offsetof(gds_trust_list_def, rolesSize) + sizeof(size_t) &&
           d->name && d->name[0] && strnlen(d->name, GDS_MAX_STRING + 1) <= GDS_MAX_STRING &&
           d->pkiDir && d->pkiDir[0] && strnlen(d->pkiDir, GDS_MAX_STRING + 1) <= GDS_MAX_STRING &&
           d->rolesSize > 0 && d->rolesSize <= GDS_MAX_CALLER_ROLES && d->roles &&
           !UA_NodeId_isNull(&d->groupId) && !UA_NodeId_isNull(&d->parentId);
}

static void ptl_free(gds_ptl *p) {
    if(!p)
        return;
    for(size_t i = 0; i < PTL_HANDLES; i++)
        handle_free(&p->h[i]);
    if(p->cg.clear)
        p->cg.clear(&p->cg);
    UA_NodeId_clear(&p->group);
    UA_NodeId_clear(&p->tl);
    UA_NodeId_clear(&p->sizeNode);
    UA_NodeId_clear(&p->openCountNode);
    UA_NodeId_clear(&p->lastUpdateNode);
    for(size_t i = 0; i < N_METHODS; i++)
        UA_NodeId_clear(&p->mids[i]);
    free(p);
}

static UA_StatusCode bind_methods(gds_server *s) {
    if(s->ptlBound)
        return UA_STATUSCODE_GOOD;
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < N_METHODS && r == UA_STATUSCODE_GOOD; i++) {
        UA_NodeId m = UA_NODEID_NUMERIC(0, METHODS[i]);
        prior[i] = NULL;
        (void)UA_Server_getMethodNodeCallback(s->ua, m, &prior[i]);
        r = UA_Server_setMethodNodeCallback(s->ua, m, ptl_call);
    }
    if(r == UA_STATUSCODE_GOOD)
        s->ptlBound = true;
    return r;
}

static gds_status create_nodes(gds_server *s, const gds_trust_list_def *def, gds_ptl *p) {
    UA_ObjectAttributes oa = UA_ObjectAttributes_default;
    oa.displayName = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)def->name);
    UA_StatusCode r = UA_Server_addObjectNode(
        s->ua, def->groupId, def->parentId, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(def->groupId.namespaceIndex, (char *)(uintptr_t)def->name),
        UA_NODEID_NUMERIC(0, UA_NS0ID_CERTIFICATEGROUPTYPE), oa, NULL, &p->group);
    if(r != UA_STATUSCODE_GOOD)
        return r == UA_STATUSCODE_BADNODEIDEXISTS ? GDS_EEXISTS
               : r == UA_STATUSCODE_BADPARENTNODEIDINVALID ? GDS_ENOTFOUND
                                                           : GDS_EINVAL;
    p->tl = child_of(s->ua, &p->group, 0, "TrustList");
    if(UA_NodeId_isNull(&p->tl))
        return GDS_EINVAL;
    p->sizeNode = child_of(s->ua, &p->tl, 0, "Size");
    p->openCountNode = child_of(s->ua, &p->tl, 0, "OpenCount");
    p->lastUpdateNode = child_of(s->ua, &p->tl, 0, "LastUpdateTime");
    /* open62541 copies the mandatory methods (without a callback, as the
     * type's had none when it copied them) and leaves out the optional
     * ones: bind the copies, reference the type's for the rest. */
    for(size_t i = 0; i < N_METHODS && r == UA_STATUSCODE_GOOD; i++) {
        p->mids[i] = child_of(s->ua, &p->tl, 0, METHOD_NAMES[i]);
        if(UA_NodeId_isNull(&p->mids[i]))
            r = UA_Server_addReference(s->ua, p->tl, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                       UA_EXPANDEDNODEID_NUMERIC(0, METHODS[i]), true);
        else
            r = UA_Server_setMethodNodeCallback(s->ua, p->mids[i], ptl_call);
    }
    if(r != UA_STATUSCODE_GOOD)
        return GDS_EINVAL;
    UA_NodeId writable = child_of(s->ua, &p->tl, 0, "Writable");
    UA_NodeId userWritable = child_of(s->ua, &p->tl, 0, "UserWritable");
    UA_Boolean t = true;
    write_prop(s->ua, &writable, &t, &UA_TYPES[UA_TYPES_BOOLEAN]);
    gds_status st = UA_NodeId_isNull(&userWritable)
                        ? GDS_OK
                        : gds_server_set_role_boolean(s, &userWritable, def->roles, def->rolesSize);
    UA_NodeId_clear(&writable);
    UA_NodeId_clear(&userWritable);
    return st;
}

/* A memory store holding the saved lists. */
static UA_StatusCode open_store(gds_server *s, gds_ptl *p, const UA_NodeId *groupId,
                                const UA_TrustListDataType *saved) {
    UA_NodeId gid = *groupId;
    UA_UInt32 maxSize = (UA_UInt32)PTL_MAX_FILE;
    UA_KeyValuePair kv;
    kv.key = UA_QUALIFIEDNAME(0, "max-trust-listsize");
    UA_Variant_setScalar(&kv.value, &maxSize, &UA_TYPES[UA_TYPES_UINT32]);
    UA_KeyValueMap params = {1, &kv};
    UA_StatusCode r = UA_CertificateGroup_Memorystore(&p->cg, &gid, NULL,
                                                      UA_Server_getConfig(s->ua)->logging, &params);
    bool any = saved->trustedCertificatesSize || saved->issuerCertificatesSize ||
               saved->trustedCrlsSize || saved->issuerCrlsSize;
    if(r == UA_STATUSCODE_GOOD && any)
        r = p->cg.setTrustList(&p->cg, saved);
    return r;
}

gds_status gds_server_add_trust_list(gds_server *s, const gds_trust_list_def *def) {
    if(!s || !def_ok(def))
        return GDS_EINVAL;
    if(def->groupId.namespaceIndex == 0 || def->groupId.namespaceIndex == s->ns ||
       def->parentId.namespaceIndex == s->ns)
        return GDS_EDENIED;
    pthread_mutex_lock(&s->ptlLock);
    bool full = s->nPtls == GDS_MAX_PLUGIN_TRUST_LISTS;
    pthread_mutex_unlock(&s->ptlLock);
    if(full)
        return GDS_ETOOBIG;
    gds_ptl *p = calloc(1, sizeof(*p));
    if(!p)
        return GDS_ENOMEM;
    gds_status st = gds_role_bits(s, def->roles, def->rolesSize, &p->roleBits, &p->anon, &p->auth);
    if(st == GDS_OK && gds_mkdirs(def->pkiDir, 0700) != GDS_OK)
        st = GDS_EIO;
    if(st == GDS_OK)
        st = gds_path(p->file, sizeof(p->file), "%s/trustlist.bin", def->pkiDir);
    UA_TrustListDataType saved;
    UA_TrustListDataType_init(&saved);
    if(st == GDS_OK)
        st = load(p->file, &saved);
    if(st == GDS_OK && open_store(s, p, &def->groupId, &saved) != UA_STATUSCODE_GOOD)
        st = GDS_EIO;
    UA_TrustListDataType_clear(&saved);
    if(st == GDS_OK)
        st = create_nodes(s, def, p);
    if(st == GDS_OK && bind_methods(s) != UA_STATUSCODE_GOOD)
        st = GDS_EINVAL;
    if(st != GDS_OK) {
        if(!UA_NodeId_isNull(&p->group))
            (void)UA_Server_deleteNode(s->ua, p->group, true);
        ptl_free(p);
        return st;
    }
    pthread_mutex_lock(&s->ptlLock);
    if(s->nPtls < GDS_MAX_PLUGIN_TRUST_LISTS)
        s->ptls[s->nPtls++] = p;
    else
        st = GDS_ETOOBIG;
    pthread_mutex_unlock(&s->ptlLock);
    if(st != GDS_OK) {
        (void)UA_Server_deleteNode(s->ua, p->group, true);
        ptl_free(p);
        return st;
    }
    update_open_count(s, p);
    update_size(s, p, false);
    return GDS_OK;
}

gds_status gds_ptl_get(gds_server *s, const UA_NodeId *groupId, UA_TrustListDataType *out,
                       bool *found) {
    pthread_mutex_lock(&s->ptlLock);
    gds_ptl *p = find_group(s, groupId);
    *found = p != NULL;
    UA_StatusCode r = p ? p->cg.getTrustList(&p->cg, out) : UA_STATUSCODE_GOOD;
    pthread_mutex_unlock(&s->ptlLock);
    if(r == UA_STATUSCODE_GOOD && p)
        out->specifiedLists = UA_TRUSTLISTMASKS_ALL;
    return r == UA_STATUSCODE_GOOD ? GDS_OK : gds_ua_status(r);
}

gds_status gds_server_set_trust_list(gds_server *s, const UA_NodeId *groupId,
                                     const UA_TrustListDataType *tl) {
    if(!s || !groupId || !tl)
        return GDS_EINVAL;
    if((tl->specifiedLists & ~(UA_UInt32)UA_TRUSTLISTMASKS_ALL) != 0 || !list_ok(tl))
        return GDS_EINVAL;
    pthread_mutex_lock(&s->ptlLock);
    gds_ptl *p = find_group(s, groupId);
    UA_StatusCode r = UA_STATUSCODE_BADNOTFOUND;
    if(p) {
        r = persist(p, p->cg.setTrustList(&p->cg, tl));
        p->gen++; /* a writer open now gets Bad_InvalidState at CloseAndUpdate */
    }
    pthread_mutex_unlock(&s->ptlLock);
    if(!p)
        return GDS_ENOTFOUND;
    if(r != UA_STATUSCODE_GOOD)
        return gds_ua_status(r);
    update_size(s, p, true);
    return GDS_OK;
}

void gds_ptl_free(gds_server *s) {
    for(size_t i = 0; i < s->nPtls; i++)
        ptl_free(s->ptls[i]);
    s->nPtls = 0;
}
