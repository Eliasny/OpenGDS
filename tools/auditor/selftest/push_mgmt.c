/* OpenGDS Auditor self-test target: PushManagement methods of push_test_server.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Single-threaded: the server runs on the main thread and the method
 * callbacks below are called with the server's service lock held, so the
 * state needs no lock of its own. Every input is checked for type and size
 * before use; the caller may be hostile (docs/architecture.md). */
#include "push_mgmt.h"

#include <open62541/plugin/certificategroup.h>
#include <open62541/plugin/log_stdout.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/compiler.h"
#include "common/limits.h"
#include "x509util.h"
#include "common/banned.h"

#define PM_MAX_FILES 8
#define PM_MODE_READ 0x01
#define PM_MODE_WRITE_ERASE 0x06
#define PM_MASK_ALL 15u
#define PM_MAX_TL_SIZE 65535u /* the MaxTrustListSize default of 12 §7.10.3 */

/* ---------------- Mutants ---------------- */

/* Each mutant is caught by the catalogue test named beside it
 * (docs/auditor/server-profile.md, Mutant column). */
static const struct {
    const char *name;
    const char *test;
    const char *what;
} mutants[] = {
    {"drop-last-chunk", "SRV-TL-02", "TrustList Write drops the last chunk before CloseAndUpdate"},
    {"update-refuse-valid", "SRV-UPD-01", "UpdateCertificate refuses every certificate"},
    {"apply-ignored", "SRV-TXN-03",
     "ApplyChanges returns Good but drops a transaction that holds a certificate"},
    {"anon-admin", "SRV-SEC-01", "an anonymous session has SecurityAdmin"},
    {"no-secadmin", "SRV-SEC-02", "every authenticated user has SecurityAdmin"},
    {"allow-none", "SRV-SEC-03", "sessions over a None channel are allowed and have SecurityAdmin"},
    {"sign-is-enough", "SRV-SEC-04", "Sign-only sessions allowed; no method checks the channel"},
    {"sign-for-apply", "SRV-SEC-05",
     "Sign-only sessions allowed; only the encrypt-only methods refuse them"},
    {"diag-public", "SRV-SEC-06", "TransactionDiagnostics readable without SecurityAdmin"},
    {"trustlist-read-any", "SRV-SEC-07", "OpenWithMasks/Read/Close need no SecurityAdmin"},
    {"deprecated-policy", "SRV-SEC-08", "Basic128Rsa15 and Basic256 endpoints offered"},
    {"wire-old-cert", "SRV-WIRE-01",
     "after ApplyChanges the Basic256Sha256 policy keeps the old certificate"},
    {"no-rejected-list-method", "SRV-CAP-01", "ServerConfiguration has no GetRejectedList"},
    {"no-default-group", "SRV-CAP-02", "CertificateGroups does not reference DefaultApplicationGroup"},
    {"mixed-cert-types", "SRV-CAP-03",
     "DefaultApplicationGroup advertises an application and an HTTPS CertificateType"},
    {"bad-capability-id", "SRV-CAP-04", "ServerCapabilities holds an identifier not in Annex D"},
    {"bad-key-format-name", "SRV-CAP-05", "SupportedPrivateKeyFormats is [\"DER\"]"},
    {"accept-key-unadvertised", "SRV-CAP-06",
     "UpdateCertificate accepts (and ignores) a private key although none is advertised"},
    {"ignore-max-size", "SRV-CAP-07", "TrustList Write ignores MaxTrustListSize"},
    {"transactions-no-cancel", "SRV-CAP-08", "SupportsTransactions TRUE without CancelChanges"},
    {"advertise-unsupported-type", "SRV-CAP-09",
     "RsaMinApplicationCertificateType advertised but CreateSigningRequest refuses it"},
    {"open-any-mode", "SRV-TL-01", "TrustList Open accepts any mode with Write or EraseExisting"},
    {"trustlist-wrapped", "SRV-TL-03", "the TrustList file is wrapped in an ExtensionObject"},
    {"mask-ignored", "SRV-TL-04", "CloseAndUpdate replaces all four lists whatever SpecifiedLists"},
    {"openwithmasks-ignores", "SRV-TL-05", "OpenWithMasks returns all four lists"},
    {"close-applies", "SRV-TL-06", "Close on a write handle queues the list like CloseAndUpdate"},
    {"accept-invalid-cert", "SRV-TL-07", "CloseAndUpdate does not check certificate signatures"},
    {"accept-expired-ca", "SRV-TL-08", "CloseAndUpdate does not check certificate validity times"},
    {"lastupdate-frozen", "SRV-TL-17", "ApplyChanges does not move LastUpdateTime"},
    {"size-readable", "SRV-TL-19", "the TrustList Size Property returns a value"},
    {"updatefreq-readonly", "SRV-TL-20", "the TrustList has a read-only UpdateFrequency"},
};

bool pm_mutant_known(const char *name) {
    for(size_t i = 0; i < GDS_ARRAY_SIZE(mutants); i++)
        if(strcmp(mutants[i].name, name) == 0)
            return true;
    return false;
}

void pm_mutant_list(void) {
    for(size_t i = 0; i < GDS_ARRAY_SIZE(mutants); i++)
        printf("%-24s %-12s %s\n", mutants[i].name, mutants[i].test, mutants[i].what);
}

/* ---------------- State ---------------- */

typedef struct {
    bool used;
    UA_UInt32 handle;
    UA_NodeId session;
    UA_Byte mode;
    UA_ByteString data;
    size_t pos;
    size_t lastWrite; /* bytes of the last Write (drop-last-chunk) */
} pm_file;

static struct {
    UA_Server *server;
    const char *brk;
    size_t maxSize;
    pm_file files[PM_MAX_FILES];
    UA_UInt32 nextHandle;
    /* the transaction (12 §7.10.2): one at a time, owned by one Session */
    bool txn;
    UA_NodeId owner;
    bool hasList;
    UA_TrustListDataType list;
    bool hasCert;
    UA_ByteString cert;
    UA_NodeId certType;
    UA_ByteString ownKey; /* only for wire-old-cert */
    pm_mode_fn modeOf;
    UA_MethodCallback libCsr, libRejected, libAdd, libRemove;
} P;

bool pm_breaking(const char *name) {
    return P.brk && strcmp(P.brk, name) == 0;
}

static bool breaking(const char *name) {
    return pm_breaking(name);
}

/* The channel a method needs (12 §7.4 and each method's clause):
 * UpdateCertificate and CreateSigningRequest need an encrypted channel
 * (§7.10.5, §7.10.10), the others an authenticated one (§7.10.9, §7.10.11,
 * §7.10.12, §7.8.2.2 - §7.8.2.7). */
static UA_StatusCode need_channel(const UA_NodeId *sessionId, bool encrypt) {
    if(breaking("allow-none") || breaking("sign-is-enough") || !P.modeOf)
        return UA_STATUSCODE_GOOD;
    UA_MessageSecurityMode m = P.modeOf(sessionId);
    UA_MessageSecurityMode least =
        encrypt ? UA_MESSAGESECURITYMODE_SIGNANDENCRYPT : UA_MESSAGESECURITYMODE_SIGN;
    return m >= least ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;
}

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

static void txn_clear(void) {
    P.txn = false;
    UA_NodeId_clear(&P.owner);
    UA_TrustListDataType_clear(&P.list);
    P.hasList = false;
    UA_ByteString_clear(&P.cert);
    UA_NodeId_clear(&P.certType);
    P.hasCert = false;
}

/* Join or start the caller's transaction; Bad_TransactionPending if another
 * Session holds one (§7.8.2.2, §7.10.5). */
static UA_StatusCode txn_join(const UA_NodeId *session) {
    if(P.txn)
        return UA_NodeId_equal(&P.owner, session) ? UA_STATUSCODE_GOOD
                                                  : UA_STATUSCODE_BADTRANSACTIONPENDING;
    UA_StatusCode r = UA_NodeId_copy(session, &P.owner);
    if(r == UA_STATUSCODE_GOOD)
        P.txn = true;
    return r;
}

static void file_free(pm_file *f) {
    UA_ByteString_clear(&f->data);
    UA_NodeId_clear(&f->session);
    memset(f, 0, sizeof(*f));
}

static pm_file *file_get(const UA_NodeId *session, UA_UInt32 handle) {
    for(size_t i = 0; i < PM_MAX_FILES; i++)
        if(P.files[i].used && P.files[i].handle == handle &&
           UA_NodeId_equal(&P.files[i].session, session))
            return &P.files[i];
    return NULL;
}

static bool write_open(void) {
    for(size_t i = 0; i < PM_MAX_FILES; i++)
        if(P.files[i].used && P.files[i].mode == PM_MODE_WRITE_ERASE)
            return true;
    return false;
}

void pm_session_closed(const UA_NodeId *sessionId) {
    for(size_t i = 0; i < PM_MAX_FILES; i++)
        if(P.files[i].used && UA_NodeId_equal(&P.files[i].session, sessionId))
            file_free(&P.files[i]);
    if(P.txn && UA_NodeId_equal(&P.owner, sessionId)) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Session with a transaction ended: transaction discarded");
        txn_clear();
    }
}

void pm_clear(void) {
    if(P.ownKey.length)
        OPENSSL_cleanse(P.ownKey.data, P.ownKey.length);
    UA_ByteString_clear(&P.ownKey);
    for(size_t i = 0; i < PM_MAX_FILES; i++)
        if(P.files[i].used)
            file_free(&P.files[i]);
    txn_clear();
}

/* ---------------- Trust list helpers ---------------- */

static UA_CertificateGroup *pki(void) {
    return &UA_Server_getConfig(P.server)->secureChannelPKI;
}

static UA_StatusCode current_list(UA_TrustListDataType *out) {
    UA_TrustListDataType_init(out);
    out->specifiedLists = PM_MASK_ALL;
    UA_CertificateGroup *g = pki();
    return g->getTrustList(g, out);
}

static void drop(UA_ByteString **l, size_t *n) {
    UA_Array_delete(*l, *n, &UA_TYPES[UA_TYPES_BYTESTRING]);
    *l = NULL;
    *n = 0;
}

static void keep_masked(UA_TrustListDataType *l, UA_UInt32 masks) {
    if(!(masks & UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES))
        drop(&l->trustedCertificates, &l->trustedCertificatesSize);
    if(!(masks & UA_TRUSTLISTMASKS_TRUSTEDCRLS))
        drop(&l->trustedCrls, &l->trustedCrlsSize);
    if(!(masks & UA_TRUSTLISTMASKS_ISSUERCERTIFICATES))
        drop(&l->issuerCertificates, &l->issuerCertificatesSize);
    if(!(masks & UA_TRUSTLISTMASKS_ISSUERCRLS))
        drop(&l->issuerCrls, &l->issuerCrlsSize);
    l->specifiedLists = masks & PM_MASK_ALL;
}

/* The certificates of a new list (§7.8.2.5): each parses, is within its
 * validity period, and, where its issuer is in the list, carries a valid
 * signature of that issuer. Bad_CertificateInvalid or
 * Bad_CertificateTimeInvalid; the whole list is then discarded. */
#define PM_MAX_CHECK (2 * GDS_MAX_TRUSTLIST_ENTRIES)
static UA_StatusCode one_cert(X509 *x, X509 *const *all, size_t n) {
    if(!breaking("accept-expired-ca") && (X509_cmp_current_time(X509_get0_notBefore(x)) > 0 ||
                                          X509_cmp_current_time(X509_get0_notAfter(x)) < 0))
        return UA_STATUSCODE_BADCERTIFICATETIMEINVALID;
    if(breaking("accept-invalid-cert"))
        return UA_STATUSCODE_GOOD;
    for(size_t k = 0; k < n; k++) {
        if(X509_check_issued(all[k], x) != X509_V_OK)
            continue;
        EVP_PKEY *pk = X509_get0_pubkey(all[k]);
        if(pk && X509_verify(x, pk) == 1)
            return UA_STATUSCODE_GOOD;
    }
    /* no issuer in the list verifies it: fine only if none is there */
    for(size_t k = 0; k < n; k++)
        if(X509_check_issued(all[k], x) == X509_V_OK)
            return UA_STATUSCODE_BADCERTIFICATEINVALID;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode certs_check(const UA_TrustListDataType *in) {
    static X509 *all[PM_MAX_CHECK];
    size_t n = 0;
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    const UA_ByteString *lists[2] = {in->trustedCertificates, in->issuerCertificates};
    const size_t sizes[2] = {in->trustedCertificatesSize, in->issuerCertificatesSize};
    for(size_t l = 0; l < 2 && r == UA_STATUSCODE_GOOD; l++)
        for(size_t i = 0; i < sizes[l] && r == UA_STATUSCODE_GOOD; i++) {
            gds_buf b = {lists[l][i].data, lists[l][i].length};
            X509 *x = n < PM_MAX_CHECK ? x509_parse_cert(&b) : NULL;
            if(!x)
                r = UA_STATUSCODE_BADCERTIFICATEINVALID;
            else
                all[n++] = x;
        }
    for(size_t i = 0; i < n && r == UA_STATUSCODE_GOOD; i++)
        r = one_cert(all[i], all, n);
    for(size_t i = 0; i < n; i++)
        X509_free(all[i]);
    ERR_clear_error();
    return r;
}

static UA_StatusCode replace(UA_ByteString **dst, size_t *dstN, const UA_ByteString *src,
                             size_t srcN) {
    drop(dst, dstN);
    if(srcN == 0)
        return UA_STATUSCODE_GOOD;
    UA_StatusCode r = UA_Array_copy(src, srcN, (void **)dst, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        *dstN = srcN;
    return r;
}

/* The queued list = (queued or current) with the masked lists replaced
 * (§7.8.2.5, §7.8.2.9). */
static UA_StatusCode queue_list(const UA_TrustListDataType *in) {
    UA_TrustListDataType base;
    UA_StatusCode r = P.hasList ? UA_TrustListDataType_copy(&P.list, &base) : current_list(&base);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_UInt32 m = breaking("mask-ignored") ? PM_MASK_ALL : in->specifiedLists;
    if(m & UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES)
        r |= replace(&base.trustedCertificates, &base.trustedCertificatesSize,
                     in->trustedCertificates, in->trustedCertificatesSize);
    if(m & UA_TRUSTLISTMASKS_TRUSTEDCRLS)
        r |= replace(&base.trustedCrls, &base.trustedCrlsSize, in->trustedCrls,
                     in->trustedCrlsSize);
    if(m & UA_TRUSTLISTMASKS_ISSUERCERTIFICATES)
        r |= replace(&base.issuerCertificates, &base.issuerCertificatesSize,
                     in->issuerCertificates, in->issuerCertificatesSize);
    if(m & UA_TRUSTLISTMASKS_ISSUERCRLS)
        r |= replace(&base.issuerCrls, &base.issuerCrlsSize, in->issuerCrls, in->issuerCrlsSize);
    if(r != UA_STATUSCODE_GOOD) {
        UA_TrustListDataType_clear(&base);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    base.specifiedLists = PM_MASK_ALL;
    UA_TrustListDataType_clear(&P.list);
    P.list = base;
    P.hasList = true;
    return UA_STATUSCODE_GOOD;
}

/* ---------------- TrustList methods (12 §7.8.2, OPC 10000-5 Annex C) ---------------- */

#define METHOD_ARGS                                                                        \
    UA_Server *server, const UA_NodeId *sessionId, void *sessionContext,                   \
        const UA_NodeId *methodId, void *methodContext, const UA_NodeId *objectId,         \
        void *objectContext, size_t inputSize, const UA_Variant *input, size_t outputSize, \
        UA_Variant *output
#define UNUSED_ARGS                                                                          \
    (void)server, (void)sessionContext, (void)methodId, (void)methodContext, (void)objectId, \
        (void)objectContext

static bool scalar(const UA_Variant *in, size_t inN, size_t i, const UA_DataType *t) {
    return i < inN && UA_Variant_hasScalarType(&in[i], t);
}

static UA_StatusCode new_file(const UA_NodeId *session, UA_Byte mode, UA_ByteString *data,
                              UA_Variant *output) {
    pm_file *f = NULL;
    for(size_t i = 0; i < PM_MAX_FILES && !f; i++)
        if(!P.files[i].used)
            f = &P.files[i];
    if(!f) {
        UA_ByteString_clear(data);
        return UA_STATUSCODE_BADTOOMANYOPERATIONS;
    }
    if(UA_NodeId_copy(session, &f->session) != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(data);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    f->used = true;
    f->handle = ++P.nextHandle ? P.nextHandle : ++P.nextHandle;
    f->mode = mode;
    f->data = *data;
    f->pos = 0;
    return UA_Variant_setScalarCopy(&output[0], &f->handle, &UA_TYPES[UA_TYPES_UINT32]);
}

static UA_StatusCode open_read(const UA_NodeId *session, UA_UInt32 masks, UA_Variant *output) {
    UA_TrustListDataType l;
    UA_StatusCode r = current_list(&l);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    keep_masked(&l, breaking("openwithmasks-ignores") ? PM_MASK_ALL : masks);
    UA_ByteString enc = UA_BYTESTRING_NULL;
    if(breaking("trustlist-wrapped")) { /* §7.8.2.1 forbids the ExtensionObject */
        UA_ExtensionObject eo;
        UA_ExtensionObject_setValue(&eo, &l, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE]);
        r = UA_encodeBinary(&eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT], &enc, NULL);
    } else {
        r = UA_encodeBinary(&l, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &enc, NULL);
    }
    UA_TrustListDataType_clear(&l);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    return new_file(session, PM_MODE_READ, &enc, output);
}

static UA_StatusCode tlOpen(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    if(!scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_BYTE]) || outputSize < 1)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Byte mode = *(const UA_Byte *)input[0].data;
    if(mode == PM_MODE_READ)
        return open_read(sessionId, PM_MASK_ALL, output);
    if(breaking("open-any-mode") && (mode & PM_MODE_WRITE_ERASE))
        mode = PM_MODE_WRITE_ERASE;
    if(mode != PM_MODE_WRITE_ERASE)
        return UA_STATUSCODE_BADNOTSUPPORTED; /* §7.8.2.2 */
    if(P.txn && !UA_NodeId_equal(&P.owner, sessionId))
        return UA_STATUSCODE_BADTRANSACTIONPENDING;
    if(write_open())
        return UA_STATUSCODE_BADNOTWRITABLE;
    UA_ByteString empty = UA_BYTESTRING_NULL;
    return new_file(sessionId, mode, &empty, output);
}

static UA_StatusCode tlOpenWithMasks(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    if(!scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_UINT32]) || outputSize < 1)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return open_read(sessionId, *(const UA_UInt32 *)input[0].data, output);
}

static UA_StatusCode tlRead(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    if(!scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_UINT32]) ||
       !scalar(input, inputSize, 1, &UA_TYPES[UA_TYPES_INT32]) || outputSize < 1)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    pm_file *f = file_get(sessionId, *(const UA_UInt32 *)input[0].data);
    UA_Int32 len = *(const UA_Int32 *)input[1].data;
    if(!f || len < 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(f->mode != PM_MODE_READ)
        return UA_STATUSCODE_BADINVALIDSTATE;
    size_t n = f->data.length - f->pos;
    if(n > (size_t)len)
        n = (size_t)len;
    UA_ByteString chunk = {n, n ? f->data.data + f->pos : NULL};
    f->pos += n;
    return UA_Variant_setScalarCopy(&output[0], &chunk, &UA_TYPES[UA_TYPES_BYTESTRING]);
}

static UA_StatusCode tlWrite(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    (void)output;
    (void)outputSize;
    if(!scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_UINT32]) ||
       !scalar(input, inputSize, 1, &UA_TYPES[UA_TYPES_BYTESTRING]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    pm_file *f = file_get(sessionId, *(const UA_UInt32 *)input[0].data);
    const UA_ByteString *d = input[1].data;
    if(!f)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(f->mode != PM_MODE_WRITE_ERASE)
        return UA_STATUSCODE_BADINVALIDSTATE;
    /* §7.10.3 MaxTrustListSize; ignore-max-size keeps only the hard cap */
    size_t cap = breaking("ignore-max-size") ? GDS_MAX_TRUSTLIST_SIZE : P.maxSize;
    if(d->length > cap || f->pos > cap - d->length)
        return UA_STATUSCODE_BADREQUESTTOOLARGE;
    size_t end = f->pos + d->length;
    if(end > f->data.length) {
        UA_Byte *nd = realloc(f->data.data, end ? end : 1);
        if(!nd)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        f->data.data = nd;
        f->data.length = end;
    }
    if(d->length)
        memcpy(f->data.data + f->pos, d->data, d->length);
    f->pos = end;
    f->lastWrite = d->length;
    return UA_STATUSCODE_GOOD;
}

/* CloseAndUpdate on write handle f (freed here): decode, check, queue. */
static UA_StatusCode close_and_update(const UA_NodeId *sessionId, pm_file *f) {
    UA_ByteString data = f->data;
    if(breaking("drop-last-chunk") && data.length >= f->lastWrite)
        data.length -= f->lastWrite;
    UA_TrustListDataType in;
    UA_TrustListDataType_init(&in);
    UA_StatusCode r = UA_decodeBinary(&data, &in, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
    file_free(f);
    if(r != UA_STATUSCODE_GOOD) {
        UA_TrustListDataType_clear(&in);
        return UA_STATUSCODE_BADDECODINGERROR;
    }
    if(in.trustedCertificatesSize > GDS_MAX_TRUSTLIST_ENTRIES ||
       in.trustedCrlsSize > GDS_MAX_TRUSTLIST_ENTRIES ||
       in.issuerCertificatesSize > GDS_MAX_TRUSTLIST_ENTRIES ||
       in.issuerCrlsSize > GDS_MAX_TRUSTLIST_ENTRIES)
        r = UA_STATUSCODE_BADREQUESTTOOLARGE;
    else
        r = certs_check(&in); /* §7.8.2.5: on error the whole list is discarded */
    if(r == UA_STATUSCODE_GOOD)
        r = txn_join(sessionId);
    if(r == UA_STATUSCODE_GOOD)
        r = queue_list(&in);
    UA_TrustListDataType_clear(&in);
    return r;
}

static UA_StatusCode tlClose(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    (void)output;
    (void)outputSize;
    if(!scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_UINT32]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    pm_file *f = file_get(sessionId, *(const UA_UInt32 *)input[0].data);
    if(!f)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(breaking("close-applies") && f->mode == PM_MODE_WRITE_ERASE)
        return close_and_update(sessionId, f);
    file_free(f); /* a write handle closed without CloseAndUpdate changes nothing (§7.8.2.1) */
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode tlCloseAndUpdate(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    if(!scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_UINT32]) || outputSize < 1)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    pm_file *f = file_get(sessionId, *(const UA_UInt32 *)input[0].data);
    if(!f)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(f->mode != PM_MODE_WRITE_ERASE)
        return UA_STATUSCODE_BADINVALIDSTATE;
    UA_StatusCode r = close_and_update(sessionId, f);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Boolean applyRequired = true;
    return UA_Variant_setScalarCopy(&output[0], &applyRequired, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_StatusCode tlGetPosition(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    if(!scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_UINT32]) || outputSize < 1)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    pm_file *f = file_get(sessionId, *(const UA_UInt32 *)input[0].data);
    if(!f)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_UInt64 pos = f->pos;
    return UA_Variant_setScalarCopy(&output[0], &pos, &UA_TYPES[UA_TYPES_UINT64]);
}

static UA_StatusCode tlSetPosition(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    (void)output;
    (void)outputSize;
    if(!scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_UINT32]) ||
       !scalar(input, inputSize, 1, &UA_TYPES[UA_TYPES_UINT64]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    pm_file *f = file_get(sessionId, *(const UA_UInt32 *)input[0].data);
    if(!f)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_UInt64 pos = *(const UA_UInt64 *)input[1].data;
    f->pos = pos > f->data.length ? f->data.length : (size_t)pos;
    return UA_STATUSCODE_GOOD;
}

/* ---------------- ServerConfiguration methods (12 §7.10) ---------------- */

static UA_StatusCode scUpdateCertificate(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode sec = need_channel(sessionId, true);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    if(inputSize != 6 || outputSize < 1 || !scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_NODEID]) ||
       !scalar(input, inputSize, 1, &UA_TYPES[UA_TYPES_NODEID]) ||
       !scalar(input, inputSize, 2, &UA_TYPES[UA_TYPES_BYTESTRING]) ||
       !UA_Variant_hasArrayType(&input[3], &UA_TYPES[UA_TYPES_BYTESTRING]) ||
       !scalar(input, inputSize, 4, &UA_TYPES[UA_TYPES_STRING]) ||
       !scalar(input, inputSize, 5, &UA_TYPES[UA_TYPES_BYTESTRING]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(breaking("update-refuse-valid"))
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    const UA_NodeId *group = input[0].data, *type = input[1].data;
    const UA_ByteString *cert = input[2].data, *key = input[5].data;
    const UA_NodeId dag = ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    const UA_NodeId rsa = ns0(UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
    if(!UA_NodeId_equal(group, &dag) || !UA_NodeId_equal(type, &rsa))
        return UA_STATUSCODE_BADINVALIDARGUMENT; /* §7.10.5: not in the group's CertificateTypes */
    if(key->length > 0 && !breaking("accept-key-unadvertised"))
        return UA_STATUSCODE_BADNOTSUPPORTED; /* SupportedPrivateKeyFormats is empty */
    if(cert->length == 0 || cert->length > GDS_MAX_CERT_SIZE)
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    gds_buf b = {cert->data, cert->length};
    X509 *x = x509_parse_cert(&b);
    if(!x)
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    X509_free(x);
    UA_StatusCode r = txn_join(sessionId);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_ByteString_clear(&P.cert);
    UA_NodeId_clear(&P.certType);
    r = UA_ByteString_copy(cert, &P.cert);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_NodeId_copy(type, &P.certType);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    P.hasCert = true;
    UA_Boolean applyRequired = true;
    return UA_Variant_setScalarCopy(&output[0], &applyRequired, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_StatusCode txn_owner_check(const UA_NodeId *sessionId) {
    if(!P.txn)
        return UA_STATUSCODE_BADNOTHINGTODO;
    if(!UA_NodeId_equal(&P.owner, sessionId))
        return UA_STATUSCODE_BADSESSIONIDINVALID; /* §7.10.9, decision D5 */
    return UA_STATUSCODE_GOOD;
}

/* wire-old-cert: the Basic256Sha256 SecurityPolicy, which the Auditor's
 * sessions do not use, is put back on its old certificate (same key). */
static UA_SecurityPolicy *stale_policy(void) {
    UA_ServerConfig *cfg = UA_Server_getConfig(P.server);
    const UA_String b256 = UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    for(size_t i = 0; i < cfg->securityPoliciesSize; i++)
        if(UA_String_equal(&cfg->securityPolicies[i].policyUri, &b256))
            return &cfg->securityPolicies[i];
    return NULL;
}

static UA_StatusCode apply(void) {
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(P.hasList) {
        UA_CertificateGroup *g = pki();
        r = g->setTrustList(g, &P.list);
        if(r != UA_STATUSCODE_GOOD)
            return r;
        UA_DateTime now = breaking("lastupdate-frozen") ? 0 : UA_DateTime_now();
        UA_Variant v;
        UA_Variant_setScalar(&v, &now, &UA_TYPES[UA_TYPES_DATETIME]);
        if(now)
            r = UA_Server_writeValue(
                P.server,
                ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_LASTUPDATETIME),
                v);
        if(r != UA_STATUSCODE_GOOD)
            return r;
    }
    if(P.hasCert) {
        UA_SecurityPolicy *sp = breaking("wire-old-cert") ? stale_policy() : NULL;
        UA_ByteString old = UA_BYTESTRING_NULL;
        if(sp && UA_ByteString_copy(&sp->localCertificate, &old) != UA_STATUSCODE_GOOD)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        r = UA_Server_updateCertificate(
            P.server, ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP),
            P.certType, P.cert, NULL);
        if(sp && r == UA_STATUSCODE_GOOD && P.ownKey.length)
            r = sp->updateCertificate(sp, old, P.ownKey);
        UA_ByteString_clear(&old);
    }
    return r;
}

static UA_StatusCode scApplyChanges(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    (void)input;
    (void)inputSize;
    (void)output;
    (void)outputSize;
    UA_StatusCode r = txn_owner_check(sessionId);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    for(size_t i = 0; i < PM_MAX_FILES; i++)
        if(P.files[i].used && P.files[i].mode == PM_MODE_WRITE_ERASE &&
           UA_NodeId_equal(&P.files[i].session, sessionId))
            return UA_STATUSCODE_BADINVALIDSTATE; /* §7.10.9: a TrustList is still open */
    if(!(breaking("apply-ignored") && P.hasCert))
        r = apply();
    txn_clear();
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "ApplyChanges -> %s",
                UA_StatusCode_name(r));
    return r;
}

static UA_StatusCode scCancelChanges(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    (void)input;
    (void)inputSize;
    (void)output;
    (void)outputSize;
    UA_StatusCode r = txn_owner_check(sessionId);
    if(r == UA_STATUSCODE_GOOD)
        txn_clear();
    return r;
}

/* The library's own methods, behind the same channel check */
static UA_StatusCode scCreateSigningRequest(METHOD_ARGS) {
    UA_StatusCode sec = need_channel(sessionId, true);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    /* §7.10.10 Bad_InvalidArgument: only the one slot this target has */
    const UA_NodeId dag = ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    const UA_NodeId rsa = ns0(UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
    if(inputSize < 2 || !scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_NODEID]) ||
       !scalar(input, inputSize, 1, &UA_TYPES[UA_TYPES_NODEID]) ||
       !UA_NodeId_equal(input[0].data, &dag) || !UA_NodeId_equal(input[1].data, &rsa))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return P.libCsr(server, sessionId, sessionContext, methodId, methodContext, objectId,
                    objectContext, inputSize, input, outputSize, output);
}

static UA_StatusCode scGetRejectedList(METHOD_ARGS) {
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    return P.libRejected(server, sessionId, sessionContext, methodId, methodContext, objectId,
                         objectContext, inputSize, input, outputSize, output);
}

static UA_StatusCode tlAddCertificate(METHOD_ARGS) {
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    return P.libAdd(server, sessionId, sessionContext, methodId, methodContext, objectId,
                    objectContext, inputSize, input, outputSize, output);
}

static UA_StatusCode tlRemoveCertificate(METHOD_ARGS) {
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    return P.libRemove(server, sessionId, sessionContext, methodId, methodContext, objectId,
                       objectContext, inputSize, input, outputSize, output);
}

static UA_StatusCode wrap_lib(UA_UInt32 id, UA_MethodCallback *orig, UA_MethodCallback cb) {
    UA_StatusCode r = UA_Server_getMethodNodeCallback(P.server, ns0(id), orig);
    if(r == UA_STATUSCODE_GOOD && !*orig)
        r = UA_STATUSCODE_BADINTERNALERROR;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setMethodNodeCallback(P.server, ns0(id), cb);
    return r;
}

/* ---------------- Install ---------------- */

static UA_StatusCode set_cb(UA_UInt32 id, UA_MethodCallback cb) {
    return UA_Server_setMethodNodeCallback(P.server, ns0(id), cb);
}

/* Advertise what this target supports (§7.10.3): one RSA slot, no private
 * keys pushed, the size limit tlWrite enforces, and transactions (§7.10.2). */
static UA_StatusCode advertise(UA_Server *server) {
    UA_NodeId types[3] = {ns0(UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE), UA_NODEID_NULL,
                          UA_NODEID_NULL};
    size_t nTypes = 1;
    if(breaking("mixed-cert-types"))
        types[nTypes++] = ns0(UA_NS0ID_HTTPSCERTIFICATETYPE);
    if(breaking("advertise-unsupported-type"))
        types[nTypes++] = ns0(UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE);
    UA_Variant v;
    UA_Variant_setArray(&v, types, nTypes, &UA_TYPES[UA_TYPES_NODEID]);
    UA_StatusCode r = UA_Server_writeValue(
        server, ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_CERTIFICATETYPES),
        v);
    UA_String der = UA_STRING_STATIC("DER");
    if(breaking("bad-key-format-name"))
        UA_Variant_setArray(&v, &der, 1, &UA_TYPES[UA_TYPES_STRING]);
    else
        UA_Variant_setArray(&v, UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_STRING]);
    r |= UA_Server_writeValue(server, ns0(UA_NS0ID_SERVERCONFIGURATION_SUPPORTEDPRIVATEKEYFORMATS), v);
    /* Annex D "NA": no capability information (this target registers nowhere) */
    UA_String cap = UA_STRING_STATIC("NA");
    if(breaking("bad-capability-id"))
        cap = UA_STRING((char *)(uintptr_t)"NOT-A-CAPABILITY");
    UA_Variant_setArray(&v, &cap, 1, &UA_TYPES[UA_TYPES_STRING]);
    r |= UA_Server_writeValue(server, ns0(UA_NS0ID_SERVERCONFIGURATION_SERVERCAPABILITIES), v);
    UA_UInt32 max = (UA_UInt32)P.maxSize;
    UA_Variant_setScalar(&v, &max, &UA_TYPES[UA_TYPES_UINT32]);
    r |= UA_Server_writeValue(server, ns0(UA_NS0ID_SERVERCONFIGURATION_MAXTRUSTLISTSIZE), v);
    /* SupportsTransactions (Optional) is not in the library's ns0 instance */
    UA_Boolean yes = true;
    UA_VariableAttributes va = UA_VariableAttributes_default;
    UA_Variant_setScalar(&va.value, &yes, &UA_TYPES[UA_TYPES_BOOLEAN]);
    va.dataType = UA_TYPES[UA_TYPES_BOOLEAN].typeId;
    va.displayName = UA_LOCALIZEDTEXT("", "SupportsTransactions");
    UA_StatusCode a = UA_Server_addVariableNode(
        server, ns0(UA_NS0ID_SERVERCONFIGURATION_SUPPORTSTRANSACTIONS),
        ns0(UA_NS0ID_SERVERCONFIGURATION), ns0(UA_NS0ID_HASPROPERTY),
        UA_QUALIFIEDNAME(0, "SupportsTransactions"), ns0(UA_NS0ID_PROPERTYTYPE), va, NULL, NULL);
    if(a == UA_STATUSCODE_BADNODEIDEXISTS)
        a = UA_Server_writeValue(server, ns0(UA_NS0ID_SERVERCONFIGURATION_SUPPORTSTRANSACTIONS),
                                 va.value);
    return r | a;
}

/* Size has no meaning for a TrustList (12 §7.8.2.1): OPC 10000-20 §4.2.1
 * says it is returned with Bad_NotSupported. */
static UA_StatusCode size_read(UA_Server *server, const UA_NodeId *sessionId,
                               void *sessionContext, const UA_NodeId *nodeId, void *nodeContext,
                               UA_Boolean includeSourceTimeStamp, const UA_NumericRange *range,
                               UA_DataValue *value) {
    (void)server, (void)sessionId, (void)sessionContext, (void)nodeId, (void)nodeContext;
    (void)includeSourceTimeStamp, (void)range;
    value->hasStatus = true;
    value->status = UA_STATUSCODE_BADNOTSUPPORTED;
    return UA_STATUSCODE_GOOD;
}

#define TLP(x) UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_##x

/* TrustList Properties: Size refused; UpdateFrequency absent, as 7.8.2.1
 * requires for a TrustList inside ServerConfiguration. */
static UA_StatusCode trustlist_props(UA_Server *server) {
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(!breaking("size-readable")) {
        UA_CallbackValueSource src = {size_read, NULL};
        r = UA_Server_setVariableNode_callbackValueSource(server, ns0(TLP(SIZE)), src);
    }
    (void)UA_Server_deleteNode(server, ns0(TLP(UPDATEFREQUENCY)), true);
    if(r == UA_STATUSCODE_GOOD && breaking("updatefreq-readonly")) {
        UA_Double ms = 3600000.0;
        UA_VariableAttributes va = UA_VariableAttributes_default;
        UA_Variant_setScalar(&va.value, &ms, &UA_TYPES[UA_TYPES_DOUBLE]);
        va.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        va.accessLevel = UA_ACCESSLEVELMASK_READ;
        va.displayName = UA_LOCALIZEDTEXT("", "UpdateFrequency");
        r = UA_Server_addVariableNode(server, ns0(TLP(UPDATEFREQUENCY)),
                                      ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST),
                                      ns0(UA_NS0ID_HASPROPERTY),
                                      UA_QUALIFIEDNAME(0, "UpdateFrequency"),
                                      ns0(UA_NS0ID_PROPERTYTYPE), va, NULL, NULL);
    }
    return r;
}
#undef TLP

/* The mutants that remove a node or a reference (SRV-CAP-01, -02, -08). */
static UA_StatusCode structure_mutants(UA_Server *server) {
    if(breaking("no-rejected-list-method"))
        return UA_Server_deleteNode(server, ns0(UA_NS0ID_SERVERCONFIGURATION_GETREJECTEDLIST), true);
    if(breaking("transactions-no-cancel"))
        return UA_Server_deleteNode(server, ns0(UA_NS0ID_SERVERCONFIGURATION_CANCELCHANGES), true);
    if(breaking("no-default-group")) {
        UA_ExpandedNodeId dag =
            UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
        const UA_UInt32 refs[] = {UA_NS0ID_ORGANIZES, UA_NS0ID_HASCOMPONENT};
        bool gone = false;
        for(size_t i = 0; i < GDS_ARRAY_SIZE(refs); i++)
            gone |= UA_Server_deleteReference(server,
                                              ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS),
                                              ns0(refs[i]), true, dag, true) == UA_STATUSCODE_GOOD;
        return gone ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADNOTFOUND;
    }
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode pm_install(UA_Server *server, const char *mutant, const UA_ByteString *ownKey,
                         pm_mode_fn modeOf) {
    memset(&P, 0, sizeof(P));
    P.server = server;
    P.brk = mutant;
    P.modeOf = modeOf;
    if(breaking("wire-old-cert") && UA_ByteString_copy(ownKey, &P.ownKey) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    P.maxSize = PM_MAX_TL_SIZE;
#define TL(x) UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_##x
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    r |= set_cb(TL(OPEN), tlOpen);
    r |= set_cb(TL(OPENWITHMASKS), tlOpenWithMasks);
    r |= set_cb(TL(READ), tlRead);
    r |= set_cb(TL(WRITE), tlWrite);
    r |= set_cb(TL(CLOSE), tlClose);
    r |= set_cb(TL(CLOSEANDUPDATE), tlCloseAndUpdate);
    r |= set_cb(TL(GETPOSITION), tlGetPosition);
    r |= set_cb(TL(SETPOSITION), tlSetPosition);
#undef TL
    r |= wrap_lib(UA_NS0ID_SERVERCONFIGURATION_CREATESIGNINGREQUEST, &P.libCsr,
                  scCreateSigningRequest);
    r |= wrap_lib(UA_NS0ID_SERVERCONFIGURATION_GETREJECTEDLIST, &P.libRejected, scGetRejectedList);
    r |= wrap_lib(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_ADDCERTIFICATE,
                  &P.libAdd, tlAddCertificate);
    r |= wrap_lib(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_REMOVECERTIFICATE,
                  &P.libRemove, tlRemoveCertificate);
    r |= set_cb(UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE, scUpdateCertificate);
    r |= set_cb(UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES, scApplyChanges);
    if(r != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINTERNALERROR;
    /* CancelChanges is Optional (§7.10.11): offered when the node exists */
    if(set_cb(UA_NS0ID_SERVERCONFIGURATION_CANCELCHANGES, scCancelChanges) != UA_STATUSCODE_GOOD)
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "no CancelChanges node");
    if(advertise(server) != UA_STATUSCODE_GOOD || structure_mutants(server) != UA_STATUSCODE_GOOD ||
       trustlist_props(server) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINTERNALERROR;
    return UA_STATUSCODE_GOOD;
}


