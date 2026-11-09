/* OpenGDS Auditor self-test target: PushManagement methods of push_test_server.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Single-threaded: the server runs on the main thread and the method
 * callbacks below are called with the server's service lock held, so the
 * state needs no lock of its own. Every input is checked for type and size
 * before use; the caller may be hostile (docs/architecture.md). */
#include "push_mgmt.h"

#include <open62541/plugin/certificategroup.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/log_stdout.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/buf.h"
#include "common/compiler.h"
#include "common/limits.h"
#include "push_csr.h"
#include "x509util.h"
#include "common/banned.h"

#define PM_MAX_FILES 8
#define PM_MODE_READ 0x01
#define PM_MODE_WRITE_ERASE 0x06
#define PM_MASK_ALL 15u
#define PM_MAX_TL_SIZE 65535u /* the MaxTrustListSize default of 12 §7.10.3 */
/* ActivityTimeout (12 §7.8.2.1), short so that SRV-TL-18 stays quick in CI */
#define PM_ACTIVITY_TIMEOUT_MS 2000.0

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
    {"wire-keep-channels", "SRV-WIRE-02",
     "after ApplyChanges with a certificate the SecureChannels stay open"},
    {"wire-no-shutdown-notice", "SRV-WIRE-03",
     "ApplyChanges closes the channels without SecondsTillShutdown or ShutdownReason"},
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
    {"wire-trustlist-not-loaded", "SRV-WIRE-04",
     "client certificates are checked against the trust list of the start, not the applied one"},
    {"wire-ignore-crl", "SRV-WIRE-05", "a revoked client certificate is accepted"},
    {"wire-trust-all", "SRV-WIRE-06", "every client certificate is accepted"},
    {"wire-keep-removed-sessions", "SRV-WIRE-07",
     "sessions of a client whose certificate was removed stay open"},
    {"wire-crl-no-reeval", "SRV-WIRE-08", "sessions of a client that a new CRL revokes stay open"},
    {"diag-stale", "SRV-TXN-12", "ApplyChanges leaves TransactionDiagnostics as it was"},
    {"diag-cancel-good", "SRV-TXN-13", "after CancelChanges the diagnostics Result is Good"},
    {"size-readable", "SRV-TL-19", "the TrustList Size Property returns a value"},
    {"updatefreq-readonly", "SRV-TL-20", "the TrustList has a read-only UpdateFrequency"},
    {"addcert-noop", "SRV-TL-09", "AddCertificate returns Good and adds nothing"},
    {"addcert-issuer-allowed", "SRV-TL-10", "AddCertificate(IsTrustedCertificate FALSE) adds an issuer"},
    {"addcert-no-chain-check", "SRV-TL-11", "AddCertificate does not need the issuer in the TrustList"},
    {"addcert-while-open", "SRV-TL-12", "AddCertificate works while the TrustList is open for writing"},
    {"remove-unknown-good", "SRV-TL-13", "RemoveCertificate of an unknown thumbprint returns Good"},
    {"remove-noop", "SRV-TL-14", "RemoveCertificate returns Good and removes nothing"},
    {"remove-ca-in-use", "SRV-TL-15", "RemoveCertificate removes a CA another certificate needs"},
    {"remove-keeps-crl", "SRV-TL-16", "RemoveCertificate of a CA keeps its CRLs"},
    {"no-activity-timeout", "SRV-TL-18", "an idle write handle is never closed"},
    {"csr-new-key-always", "SRV-CSR-01", "CreateSigningRequest always makes a new key pair"},
    {"csr-empty-subject", "SRV-CSR-02", "the CSR has an empty subject"},
    {"csr-no-san", "SRV-CSR-03", "the CSR has no subjectAltName"},
    {"csr-regen-ignored", "SRV-CSR-04", "RegeneratePrivateKey TRUE reuses the active key"},
    {"csr-short-nonce", "SRV-CSR-05", "RegeneratePrivateKey TRUE accepts a Nonce under 32 bytes"},
    {"csr-key-per-session", "SRV-CSR-06", "the new key pair is usable only from its own Session"},
    {"csr-keep-old-new-key", "SRV-CSR-07", "a later CreateSigningRequest keeps the older new key pair"},
    {"csr-any-type", "SRV-CSR-08", "CreateSigningRequest accepts any CertificateTypeId"},
    {"update-no-key-check", "SRV-UPD-02",
     "UpdateCertificate accepts a certificate for a key the target does not hold"},
    {"update-no-uri-check", "SRV-UPD-03",
     "UpdateCertificate accepts a SAN URI other than the ApplicationUri"},
    {"update-trust-issuer-arg", "SRV-UPD-04",
     "UpdateCertificate trusts an issuer passed in IssuerCertificates"},
    {"update-no-sig-check", "SRV-UPD-05", "UpdateCertificate does not verify the signature"},
    {"update-any-type", "SRV-UPD-06", "UpdateCertificate accepts any CertificateTypeId"},
    {"update-type-mismatch", "SRV-UPD-07",
     "UpdateCertificate takes an ECC certificate into the RSA slot unchecked"},
    {"update-accept-expired", "SRV-UPD-08", "UpdateCertificate accepts an expired certificate"},
    {"getcerts-mismatched", "SRV-UPD-11",
     "GetCertificates returns two CertificateTypeIds for one Certificate"},
    {"selfsigned-overwrite", "SRV-UPD-12",
     "CreateSelfSignedCertificate returns Good on the occupied slot"},
    {"delete-in-use", "SRV-UPD-13", "DeleteCertificate returns Good on the certificate in use"},
    {"forget-on-restart", "SRV-PER-01",
     "after a restart the initial self-signed certificate is in use again"},
    {"lastupdate-reset-now", "SRV-PER-02", "after a restart LastUpdateTime is the start time"},
    {"csr-key-in-ram", "SRV-PER-03", "the new key pair of CreateSigningRequest is lost on restart"},
    {"txn-persist-uncommitted", "SRV-PER-04",
     "a queued certificate is written to the store before ApplyChanges"},
    {"rejected-not-recorded", "SRV-REJ-01", "refused client certificates are not recorded"},
    {"rejected-records-invalid", "SRV-REJ-02",
     "every refused client certificate is recorded, also one with a broken signature"},
    {"rejected-garbage", "SRV-REJ-03", "GetRejectedList returns an entry that is not a certificate"},
    {"group-rejected-broken", "SRV-REJ-04",
     "DefaultApplicationGroup GetRejectedList returns Bad_InternalError"},
    {"apply-required-false", "SRV-TXN-01", "CloseAndUpdate returns ApplyChangesRequired FALSE"},
    {"apply-early", "SRV-TXN-02", "CloseAndUpdate puts the trust list in use before ApplyChanges"},
    {"cancel-keeps-trustlist", "SRV-TXN-04", "CancelChanges puts the queued trust list in use"},
    {"txn-survives-session", "SRV-TXN-05",
     "a transaction outlives its Session and the next Session may apply it"},
    {"txn-interleave", "SRV-TXN-06", "another Session may join a transaction in progress"},
    {"apply-any-session", "SRV-TXN-07", "any Session may apply or cancel a transaction"},
    {"apply-while-open", "SRV-TXN-08", "ApplyChanges ignores a TrustList open for writing"},
    {"apply-nothing-good", "SRV-TXN-09", "ApplyChanges with no transaction returns Good"},
    {"fail-aborts-txn", "SRV-TXN-10", "a failed UpdateCertificate discards the transaction"},
    {"apply-partial", "SRV-TXN-11",
     "ApplyChanges puts the trust list in use and then fails on the certificate"},
    {"update-ignore-key", "SRV-UPD-09",
     "with --accept-keys: UpdateCertificate accepts a private key and keeps the old one"},
    {"update-accept-bad-key", "SRV-UPD-10",
     "with --accept-keys: UpdateCertificate accepts a private key of another certificate"},
    /* push_setup.c (push_test_server --setup) */
    {"audit-no-trustlist-event", "SRV-AUD-01",
     "no TrustListUpdatedAuditEventType when a trust list is put in use"},
    {"audit-no-cert-event", "SRV-AUD-02",
     "no CertificateUpdatedAuditEventType when a certificate is put in use"},
    {"setup-state-running", "SRV-SET-01", "in application setup ServerStatus.State is Running"},
    {"setup-no-cert", "SRV-SET-02", "in application setup the endpoints present no certificate"},
    {"setup-exit-no-role", "SRV-SET-03",
     "ApplyChanges ends application setup without a SecurityAdmin identity"},
    {"setup-sticky", "SRV-SET-04", "AddIdentity to SecurityAdmin does not end application setup"},
    {"setup-open-after", "SRV-SET-05",
     "after application setup every client certificate is still accepted"},
    {"reset-no-shutdown", "SRV-SET-06", "ResetToServerDefaults returns Good and does nothing"},
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
    UA_DateTime lastUse; /* monotonic time of the last call on the handle */
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
    UA_ByteString certKey; /* key of the queued certificate (empty: the active key) */
    UA_ByteString ownKey;  /* the active private key */
    /* the new key pair of the last CreateSigningRequest with
     * RegeneratePrivateKey (12 §7.10.10); prevKey only for csr-keep-old-new-key */
    UA_ByteString newKey, prevKey;
    UA_NodeId newKeySession; /* only for csr-key-per-session */
    pm_mode_fn modeOf;
    bool acceptKeys; /* --accept-keys: SupportedPrivateKeyFormats ["PEM"] */
} P;

static bool acceptKeys; /* set before pm_install */
static void (*onListInstalled)(void);
static void (*onApplied)(void);

void pm_on_list_installed(void (*fn)(void)) {
    onListInstalled = fn;
}

void pm_on_applied(void (*fn)(void)) {
    onApplied = fn;
}
static UA_CertificateGroup startupPki; /* wire-trustlist-not-loaded */
static bool hasStartupPki;

void pm_accept_keys(bool on) {
    acceptKeys = on;
}

bool pm_breaking(const char *name) {
    return P.brk && strcmp(P.brk, name) == 0;
}

/* ---------------- Restart state (SRV-PER-01 to -04) ----------------
 * What a restart must keep beyond the library's file store (trust list,
 * own certificate and key): LastUpdateTime (§7.8.2.1) and the new key pair
 * of CreateSigningRequest (§7.10.10), under <pki>/push/. */
static char storeDir[GDS_MAX_PATH];

void pm_store(const char *pki) {
    if(gds_path(storeDir, sizeof(storeDir), "%s/push", pki) != GDS_OK ||
       gds_mkdirs(storeDir, 0700) != GDS_OK)
        storeDir[0] = '\0';
}

static gds_status store_path(char *out, size_t len, const char *name) {
    return storeDir[0] ? gds_path(out, len, "%s/%s", storeDir, name) : GDS_ENOTFOUND;
}

static void store_put(const char *name, const void *data, size_t len, mode_t mode) {
    char p[GDS_MAX_PATH];
    if(store_path(p, sizeof(p), name) != GDS_OK || gds_file_write_atomic(p, data, len, mode) != GDS_OK)
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "cannot store %s", name);
}

static void store_drop(const char *name) {
    char p[GDS_MAX_PATH];
    if(store_path(p, sizeof(p), name) == GDS_OK && unlink(p) != 0 && errno != ENOENT)
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "cannot remove %s", name);
}

static bool store_get(const char *name, size_t max, gds_buf *out) {
    char p[GDS_MAX_PATH];
    return store_path(p, sizeof(p), name) == GDS_OK && gds_file_read(p, max, out) == GDS_OK;
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

static void secret_clear(UA_ByteString *b) {
    if(b->length)
        OPENSSL_cleanse(b->data, b->length);
    UA_ByteString_clear(b);
}

static void reject_clear(void);

static void txn_clear(void) {
    P.txn = false;
    UA_NodeId_clear(&P.owner);
    UA_TrustListDataType_clear(&P.list);
    P.hasList = false;
    UA_ByteString_clear(&P.cert);
    UA_NodeId_clear(&P.certType);
    secret_clear(&P.certKey);
    P.hasCert = false;
}

/* ---------------- TransactionDiagnostics (12 §7.10.17) ----------------
 * The last transaction: all Variables Bad_OutOfService until one starts,
 * reset when the next one starts. */
#define DIAG(x) UA_NS0ID_SERVERCONFIGURATION_TRANSACTIONDIAGNOSTICS_##x

static struct {
    bool started, done;
    UA_DateTime start, end; /* end 0: DateTime.MinValue, not completed */
    UA_StatusCode result;
    bool trustList, group; /* DefaultApplicationGroup's TrustList / the group */
} D;

static void diag_begin(void) {
    memset(&D, 0, sizeof(D));
    D.started = true;
    D.start = UA_DateTime_now();
}

static void diag_end(UA_StatusCode result) {
    D.done = true;
    D.end = UA_DateTime_now();
    D.result = result;
}

/* Join or start the caller's transaction; Bad_TransactionPending if another
 * Session holds one (§7.8.2.2, §7.10.5). */
static UA_StatusCode txn_join(const UA_NodeId *session) {
    if(P.txn && UA_NodeId_isNull(&P.owner)) /* txn-survives-session: adopted */
        return UA_NodeId_copy(session, &P.owner);
    if(P.txn)
        return UA_NodeId_equal(&P.owner, session) || breaking("txn-interleave")
                   ? UA_STATUSCODE_GOOD
                   : UA_STATUSCODE_BADTRANSACTIONPENDING;
    UA_StatusCode r = UA_NodeId_copy(session, &P.owner);
    if(r == UA_STATUSCODE_GOOD) {
        P.txn = true;
        diag_begin();
    }
    return r;
}

static void file_free(pm_file *f) {
    UA_ByteString_clear(&f->data);
    UA_NodeId_clear(&f->session);
    memset(f, 0, sizeof(*f));
}

/* §7.8.2.1: a handle idle for ActivityTimeout is closed, changes discarded */
static void expire_files(void) {
    if(breaking("no-activity-timeout"))
        return;
    UA_DateTime now = UA_DateTime_nowMonotonic();
    for(size_t i = 0; i < PM_MAX_FILES; i++)
        if(P.files[i].used &&
           now - P.files[i].lastUse > (UA_DateTime)(PM_ACTIVITY_TIMEOUT_MS * UA_DATETIME_MSEC))
            file_free(&P.files[i]);
}

static pm_file *file_get(const UA_NodeId *session, UA_UInt32 handle) {
    expire_files();
    for(size_t i = 0; i < PM_MAX_FILES; i++)
        if(P.files[i].used && P.files[i].handle == handle &&
           UA_NodeId_equal(&P.files[i].session, session)) {
            P.files[i].lastUse = UA_DateTime_nowMonotonic();
            return &P.files[i];
        }
    return NULL;
}

static bool write_open(void) {
    expire_files();
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
        if(breaking("txn-survives-session")) { /* kept for whoever comes next */
            UA_NodeId_clear(&P.owner);
            return;
        }
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Session with a transaction ended: transaction discarded");
        txn_clear();
    }
}

static void notice_free(void);

void pm_clear(void) {
    if(hasStartupPki) {
        startupPki.clear(&startupPki);
        hasStartupPki = false;
    }
    secret_clear(&P.ownKey);
    secret_clear(&P.newKey);
    secret_clear(&P.prevKey);
    UA_NodeId_clear(&P.newKeySession);
    for(size_t i = 0; i < PM_MAX_FILES; i++)
        if(P.files[i].used)
            file_free(&P.files[i]);
    txn_clear();
    reject_clear();
    notice_free();
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
static UA_StatusCode install_list(const UA_TrustListDataType *l);

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
    D.trustList = true;
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
    f->lastUse = UA_DateTime_nowMonotonic();
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
    if(P.txn && !UA_NodeId_isNull(&P.owner) && !UA_NodeId_equal(&P.owner, sessionId) &&
       !breaking("txn-interleave"))
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
    if(r == UA_STATUSCODE_GOOD && breaking("apply-early"))
        r = install_list(&P.list); /* in use before ApplyChanges */
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
    UA_Boolean applyRequired = !breaking("apply-required-false");
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

/* ---------------- CreateSigningRequest (12 §7.10.10) ----------------
 * This target's own implementation: open62541 v1.5.10 throws the
 * regenerated key away. The new key pair is kept (one at a time, any later
 * call discards it) and usable from any Session until a certificate for it
 * is applied. */

/* The certificate in use for RsaSha256 (from the SecurityPolicies). */
static const UA_ByteString *current_cert(void) {
    UA_ServerConfig *cfg = UA_Server_getConfig(P.server);
    const UA_NodeId rsa = ns0(UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
    for(size_t i = 0; i < cfg->securityPoliciesSize; i++)
        if(UA_NodeId_equal(&cfg->securityPolicies[i].certificateTypeId, &rsa) &&
           cfg->securityPolicies[i].localCertificate.length > 0)
            return &cfg->securityPolicies[i].localCertificate;
    return NULL;
}

static UA_StatusCode new_key(UA_ByteString *out) {
    gds_buf k = {0};
    if(x509_new_rsa_key(2048, &k) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_ByteString b = {k.len, k.data};
    UA_StatusCode r = UA_ByteString_copy(&b, out);
    gds_buf_free_secret(&k);
    return r;
}

/* Discard the unused new key pair (any CreateSigningRequest does, §7.10.10)
 * and keep `fresh` (may be empty) as the new one. */
static void replace_new_key(UA_ByteString *fresh, const UA_NodeId *session) {
    if(breaking("csr-keep-old-new-key")) {
        if(P.newKey.length) {
            secret_clear(&P.prevKey);
            P.prevKey = P.newKey;
            UA_ByteString_init(&P.newKey);
        }
    } else
        secret_clear(&P.prevKey);
    secret_clear(&P.newKey);
    P.newKey = *fresh;
    UA_ByteString_init(fresh);
    if(P.newKey.length && !breaking("csr-key-in-ram"))
        store_put("csr-new.key", P.newKey.data, P.newKey.length, 0600);
    else
        store_drop("csr-new.key");
    UA_NodeId_clear(&P.newKeySession);
    if(UA_NodeId_copy(session, &P.newKeySession) != UA_STATUSCODE_GOOD)
        UA_NodeId_init(&P.newKeySession);
}

static UA_StatusCode csr_args(size_t inputSize, const UA_Variant *input) {
    if(inputSize != 5 || !scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_NODEID]) ||
       !scalar(input, inputSize, 1, &UA_TYPES[UA_TYPES_NODEID]) ||
       !scalar(input, inputSize, 2, &UA_TYPES[UA_TYPES_STRING]) ||
       !scalar(input, inputSize, 3, &UA_TYPES[UA_TYPES_BOOLEAN]) ||
       !scalar(input, inputSize, 4, &UA_TYPES[UA_TYPES_BYTESTRING]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    /* only the one slot this target has; a null group is the default */
    const UA_NodeId *group = input[0].data, *type = input[1].data;
    const UA_NodeId dag = ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    const UA_NodeId rsa = ns0(UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
    if(!UA_NodeId_isNull(group) && !UA_NodeId_equal(group, &dag))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(!UA_NodeId_equal(type, &rsa) && !breaking("csr-any-type"))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    /* "at least 32 bytes" when the key is regenerated */
    bool regen = *(const UA_Boolean *)input[3].data;
    if(regen && ((const UA_ByteString *)input[4].data)->length < 32 && !breaking("csr-short-nonce"))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode scCreateSigningRequest(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode r = need_channel(sessionId, true);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(outputSize < 1)
        return UA_STATUSCODE_BADINTERNALERROR;
    if((r = csr_args(inputSize, input)) != UA_STATUSCODE_GOOD)
        return r;
    bool regen = *(const UA_Boolean *)input[3].data;
    if(breaking("csr-new-key-always"))
        regen = true;
    if(breaking("csr-regen-ignored"))
        regen = false;
    const UA_ByteString *cur = current_cert();
    if(!cur)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_ByteString fresh = UA_BYTESTRING_NULL;
    if(regen && (r = new_key(&fresh)) != UA_STATUSCODE_GOOD)
        return r;
    gds_buf kb = regen ? (gds_buf){fresh.data, fresh.length} : (gds_buf){P.ownKey.data, P.ownKey.length};
    EVP_PKEY *k = x509_parse_key(&kb);
    UA_ByteString csr = UA_BYTESTRING_NULL;
    r = k ? pc_build(cur, k, input[2].data, breaking("csr-empty-subject"), breaking("csr-no-san"), &csr)
          : UA_STATUSCODE_BADINTERNALERROR;
    EVP_PKEY_free(k);
    if(r == UA_STATUSCODE_GOOD) {
        replace_new_key(&fresh, sessionId);
        r = UA_Variant_setScalarCopy(&output[0], &csr, &UA_TYPES[UA_TYPES_BYTESTRING]);
        UA_ByteString_clear(&csr);
    }
    secret_clear(&fresh);
    return r;
}

/* The key of `cert` for UpdateCertificate without a PrivateKey: the active
 * key (*key empty) or the new key pair of CreateSigningRequest (§7.10.5).
 * Bad_CertificateInvalid for any other key. */
static UA_StatusCode key_for(const UA_ByteString *cert, const UA_NodeId *session,
                             UA_ByteString *key) {
    UA_ByteString_init(key);
    gds_buf c = {cert->data, cert->length};
    gds_buf own = {P.ownKey.data, P.ownKey.length};
    if(x509_key_matches(&c, &own))
        return UA_STATUSCODE_GOOD;
    const UA_ByteString *cand[2] = {&P.newKey, &P.prevKey};
    for(size_t i = 0; i < 2; i++) {
        gds_buf k = {cand[i]->data, cand[i]->length};
        if(k.len == 0 || !x509_key_matches(&c, &k))
            continue;
        if(i == 0 && breaking("csr-key-per-session") && !UA_NodeId_equal(session, &P.newKeySession))
            break; /* the mutant binds the new key to its Session */
        return UA_ByteString_copy(cand[i], key);
    }
    return UA_STATUSCODE_BADCERTIFICATEINVALID;
}

/* ---------------- ServerConfiguration methods (12 §7.10) ---------------- */

static UA_StatusCode update_checks(X509 *x, const UA_Variant *issuers, const UA_NodeId *session,
                                   UA_ByteString *key, bool keyGiven);
static UA_StatusCode pushed_key(X509 *x, const UA_String *format, const UA_ByteString *in,
                                UA_ByteString *out);

/* txn-persist-uncommitted: the queued pair goes to the own store at once,
 * where the next start finds it (push_test_server loads the newest). */
static void persist_queued_cert(void) {
    const UA_ByteString *key = P.certKey.length ? &P.certKey : &P.ownKey;
    char dir[GDS_MAX_PATH], p[GDS_MAX_PATH];
    if(store_path(dir, sizeof(dir), "..") != GDS_OK)
        return;
    if(gds_path(p, sizeof(p), "%s/ApplCerts/own/certs/queued.der", dir) != GDS_OK ||
       gds_file_write_atomic(p, P.cert.data, P.cert.length, 0644) != GDS_OK ||
       gds_path(p, sizeof(p), "%s/ApplCerts/own/private/queued.key", dir) != GDS_OK ||
       gds_file_write_atomic(p, key->data, key->length, 0600) != GDS_OK)
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "cannot store the queued pair");
}

/* UpdateCertificate's checks of the certificate and of the pushed key, if
 * any; ck receives the key to install */
static UA_StatusCode update_key_checks(X509 *x, const UA_Variant *input, const UA_NodeId *sessionId,
                                       UA_ByteString *ck) {
    const UA_ByteString *key = input[5].data;
    if(key->length == 0)
        return update_checks(x, &input[3], sessionId, ck, false);
    if(!P.acceptKeys)
        return UA_STATUSCODE_GOOD; /* accept-key-unadvertised: the key is ignored */
    /* §7.10.5: a key in an advertised format, for this certificate */
    UA_StatusCode r = pushed_key(x, input[4].data, key, ck);
    if(r == UA_STATUSCODE_GOOD)
        r = update_checks(x, &input[3], sessionId, ck, true);
    if(r == UA_STATUSCODE_GOOD && breaking("update-ignore-key"))
        secret_clear(ck);
    return r;
}

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
    if(!UA_NodeId_equal(group, &dag) || (!UA_NodeId_equal(type, &rsa) && !breaking("update-any-type")))
        return UA_STATUSCODE_BADINVALIDARGUMENT; /* §7.10.5: not in the group's CertificateTypes */
    if(key->length > 0 && !P.acceptKeys && !breaking("accept-key-unadvertised"))
        return UA_STATUSCODE_BADNOTSUPPORTED; /* SupportedPrivateKeyFormats is empty */
    if(cert->length == 0 || cert->length > GDS_MAX_CERT_SIZE)
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    gds_buf b = {cert->data, cert->length};
    X509 *x = x509_parse_cert(&b);
    if(!x)
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    UA_ByteString ck = UA_BYTESTRING_NULL;
    UA_StatusCode r = update_key_checks(x, input, sessionId, &ck);
    X509_free(x);
    if(r != UA_STATUSCODE_GOOD && breaking("fail-aborts-txn") && P.txn && P.hasList &&
       UA_NodeId_equal(&P.owner, sessionId))
        txn_clear(); /* §7.10.2: a failed call must leave the transaction as it was */
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if((r = txn_join(sessionId)) != UA_STATUSCODE_GOOD) {
        secret_clear(&ck);
        return r;
    }
    UA_ByteString_clear(&P.cert);
    UA_NodeId_clear(&P.certType);
    secret_clear(&P.certKey);
    P.certKey = ck;
    r = UA_ByteString_copy(cert, &P.cert);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_NodeId_copy(type, &P.certType);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    P.hasCert = true;
    if(breaking("txn-persist-uncommitted"))
        persist_queued_cert();
    D.group = true;
    UA_Boolean applyRequired = true;
    return UA_Variant_setScalarCopy(&output[0], &applyRequired, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_StatusCode txn_owner_check(const UA_NodeId *sessionId) {
    if(!P.txn)
        return breaking("apply-nothing-good") ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADNOTHINGTODO;
    if(UA_NodeId_isNull(&P.owner)) /* txn-survives-session */
        return UA_NodeId_copy(sessionId, &P.owner);
    if(!UA_NodeId_equal(&P.owner, sessionId) && !breaking("apply-any-session"))
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

/* Put a list in use and move LastUpdateTime (§7.8.2.1). */
/* ---------------- Audit events (12 §7.8.2.13, §7.10.27) ----------------
 * Server.Auditing is TRUE; each change put in use raises one event. */
#define DAG_NODE UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP
#define DAG_TL_NODE UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST

static void audit_event(UA_UInt32 type, UA_UInt32 source, const char *what, UA_KeyValuePair *f,
                        size_t n) {
    UA_KeyValueMap m = {n, f};
    UA_StatusCode r = UA_Server_createEvent(P.server, ns0(source), ns0(type), 100,
                                            UA_LOCALIZEDTEXT("en", (char *)(uintptr_t)what), &m,
                                            NULL, NULL);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "audit event: %s -> %s", what,
                UA_StatusCode_name(r));
}

static UA_StatusCode auditing_read(UA_Server *server, const UA_NodeId *sessionId,
                                   void *sessionContext, const UA_NodeId *nodeId, void *nodeContext,
                                   UA_Boolean includeSourceTimeStamp, const UA_NumericRange *range,
                                   UA_DataValue *value) {
    (void)server, (void)sessionId, (void)sessionContext, (void)nodeId, (void)nodeContext;
    (void)includeSourceTimeStamp;
    if(range)
        return UA_STATUSCODE_BADINDEXRANGEINVALID;
    UA_Boolean on = true;
    value->hasValue = true;
    return UA_Variant_setScalarCopy(&value->value, &on, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static void audit_trustlist(void) {
    if(breaking("audit-no-trustlist-event"))
        return;
    UA_Boolean ok = true;
    UA_NodeId tl = ns0(DAG_TL_NODE);
    UA_KeyValuePair f[2];
    f[0].key = UA_QUALIFIEDNAME(0, "/Status");
    UA_Variant_setScalar(&f[0].value, &ok, &UA_TYPES[UA_TYPES_BOOLEAN]);
    f[1].key = UA_QUALIFIEDNAME(0, "/TrustListId");
    UA_Variant_setScalar(&f[1].value, &tl, &UA_TYPES[UA_TYPES_NODEID]);
    audit_event(UA_NS0ID_TRUSTLISTUPDATEDAUDITEVENTTYPE, DAG_TL_NODE, "TrustList updated", f, 2);
}

static void audit_certificate(void) {
    if(breaking("audit-no-cert-event"))
        return;
    UA_Boolean ok = true;
    UA_NodeId group = ns0(DAG_NODE);
    UA_KeyValuePair f[3];
    f[0].key = UA_QUALIFIEDNAME(0, "/Status");
    UA_Variant_setScalar(&f[0].value, &ok, &UA_TYPES[UA_TYPES_BOOLEAN]);
    f[1].key = UA_QUALIFIEDNAME(0, "/CertificateGroup");
    UA_Variant_setScalar(&f[1].value, &group, &UA_TYPES[UA_TYPES_NODEID]);
    f[2].key = UA_QUALIFIEDNAME(0, "/CertificateType");
    UA_Variant_setScalar(&f[2].value, &P.certType, &UA_TYPES[UA_TYPES_NODEID]);
    audit_event(UA_NS0ID_CERTIFICATEUPDATEDAUDITEVENTTYPE, UA_NS0ID_SERVERCONFIGURATION,
                "Certificate updated", f, 3);
}

static UA_StatusCode install_list(const UA_TrustListDataType *l) {
    UA_CertificateGroup *g = pki();
    UA_StatusCode r = g->setTrustList(g, l);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_DateTime now = breaking("lastupdate-frozen") ? 0 : UA_DateTime_now();
    UA_Variant v;
    UA_Variant_setScalar(&v, &now, &UA_TYPES[UA_TYPES_DATETIME]);
    if(now)
        store_put("lastupdate", &now, sizeof(now), 0600);
    if(now)
        r = UA_Server_writeValue(
            P.server,
            ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_LASTUPDATETIME),
            v);
    if(onListInstalled)
        onListInstalled(); /* sessions are checked against the new list (§7.8.2.5) */
    audit_trustlist();
    return r;
}

static bool issuer_among(X509 *x, const UA_ByteString *l, size_t n, bool *sigOk);

/* apply-partial: does the queued certificate chain to the queued list? */
static bool chains_to_queued(void) {
    gds_buf b = {P.cert.data, P.cert.length};
    X509 *x = x509_parse_cert(&b);
    bool sig = false;
    bool found = x && (X509_check_issued(x, x) == X509_V_OK ||
                       issuer_among(x, P.list.trustedCertificates, P.list.trustedCertificatesSize, &sig) ||
                       issuer_among(x, P.list.issuerCertificates, P.list.issuerCertificatesSize, &sig));
    X509_free(x);
    ERR_clear_error();
    return found;
}

/* The queued certificate into every SecurityPolicy of its type and their
 * endpoints, as UA_Server_updateCertificate does, without closing the
 * SecureChannels: the caller decides when they close. */
static UA_StatusCode install_cert_quiet(void) {
    UA_ServerConfig *cfg = UA_Server_getConfig(P.server);
    UA_ByteString key = P.certKey.length ? P.certKey : UA_BYTESTRING_NULL;
    for(size_t i = 0; i < cfg->endpointsSize; i++) {
        UA_EndpointDescription *ed = &cfg->endpoints[i];
        UA_SecurityPolicy *sp = NULL;
        for(size_t j = 0; j < cfg->securityPoliciesSize && !sp; j++)
            if(UA_String_equal(&cfg->securityPolicies[j].policyUri, &ed->securityPolicyUri))
                sp = &cfg->securityPolicies[j];
        if(!sp)
            return UA_STATUSCODE_BADINTERNALERROR;
        if(!UA_NodeId_equal(&sp->certificateTypeId, &P.certType))
            continue;
        UA_StatusCode r = sp->updateCertificate(sp, P.cert, key);
        if(r != UA_STATUSCODE_GOOD)
            return r;
        UA_ByteString_clear(&ed->serverCertificate);
        if(UA_ByteString_copy(&P.cert, &ed->serverCertificate) != UA_STATUSCODE_GOOD)
            return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    return UA_STATUSCODE_GOOD;
}

/* closeNow: UA_Server_updateCertificate, which closes the SecureChannels of
 * the CertificateType right away; else install_cert_quiet. */
static UA_StatusCode apply(bool closeNow) {
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(P.hasList) {
        r = install_list(&P.list);
        if(r != UA_STATUSCODE_GOOD)
            return r;
    }
    if(P.hasCert && P.hasList && breaking("apply-partial") && !chains_to_queued())
        return UA_STATUSCODE_BADCERTIFICATEINVALID; /* the list is already in use */
    if(P.hasCert) {
        UA_SecurityPolicy *sp = breaking("wire-old-cert") ? stale_policy() : NULL;
        UA_ByteString old = UA_BYTESTRING_NULL;
        if(sp && UA_ByteString_copy(&sp->localCertificate, &old) != UA_STATUSCODE_GOOD)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        r = closeNow ? UA_Server_updateCertificate(
                           P.server,
                           ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP),
                           P.certType, P.cert, P.certKey.length ? &P.certKey : NULL)
                     : install_cert_quiet();
        if(sp && r == UA_STATUSCODE_GOOD && P.ownKey.length)
            r = sp->updateCertificate(sp, old, P.ownKey);
        UA_ByteString_clear(&old);
        if(r == UA_STATUSCODE_GOOD)
            audit_certificate();
        if(r == UA_STATUSCODE_GOOD && P.certKey.length) { /* the new key pair is in use */
            secret_clear(&P.ownKey);
            P.ownKey = P.certKey;
            UA_ByteString_init(&P.certKey);
            secret_clear(&P.newKey);
            secret_clear(&P.prevKey);
            store_drop("csr-new.key");
        }
    }
    return r;
}

static UA_StatusCode apply_done(UA_StatusCode r) {
    bool applied = r == UA_STATUSCODE_GOOD && P.txn;
    txn_clear();
    if(applied && onApplied)
        onApplied();
    if(!breaking("diag-stale"))
        diag_end(r);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "ApplyChanges -> %s",
                UA_StatusCode_name(r));
    return r;
}

/* ---------------- Shutdown notice (12 §7.10.9) ----------------
 * A new certificate closes the SecureChannels of its CertificateType. The
 * server first advertises that in ServerStatus SecondsTillShutdown and
 * ShutdownReason: ApplyChanges completes asynchronously after
 * PM_NOTICE_MS, its response goes out, and then the channels close. */
#define PM_NOTICE_MS 1500

static struct {
    UA_Variant *output; /* the waiting ApplyChanges (its async operation) */
    bool cancelled;     /* the server gave up on it (session closed, shutdown) */
    UA_DateTime until;  /* the announced interruption, 0: none */
    UA_StatusCode result; /* applied, response not yet sent (respond_due) */
    UA_ByteString cert;
    UA_NodeId type;
} N;

static void reason_write(const char *text) {
    UA_LocalizedText t = UA_LOCALIZEDTEXT(text[0] ? "en" : "", (char *)(uintptr_t)text);
    UA_Variant v;
    UA_Variant_setScalar(&v, &t, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    if(UA_Server_writeValue(P.server, ns0(UA_NS0ID_SERVER_SERVERSTATUS_SHUTDOWNREASON), v) !=
       UA_STATUSCODE_GOOD)
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "ShutdownReason not written");
}

/* An ApplyChanges still waiting for respond_due at shutdown */
static void notice_free(void) {
    UA_ByteString_clear(&N.cert);
    UA_NodeId_clear(&N.type);
}

static void notice_clear(void) {
    memset(&N, 0, sizeof(N));
    reason_write("");
}

/* The change is applied when the notice is due; the response, and then the
 * channels' close, follow PM_PUBLISH_MS later, so that what the change
 * raised (its audit event, 12 §7.10.27) is published first. */
#define PM_PUBLISH_MS 250

static void respond_due(UA_Server *server, void *data) {
    (void)data;
    UA_Variant *out = N.output;
    bool cancelled = N.cancelled;
    UA_StatusCode r = N.result;
    UA_ByteString cert = N.cert;
    UA_NodeId type = N.type;
    notice_clear();
    if(!cancelled) {
        UA_StatusCode s = UA_Server_setAsyncCallMethodResult(server, out, r);
        if(s != UA_STATUSCODE_GOOD)
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "ApplyChanges result -> %s",
                           UA_StatusCode_name(s));
    }
    /* the response first (the delayed callbacks run in order, open62541
     * EventLoop); the same certificate again, now closing the channels */
    if(r == UA_STATUSCODE_GOOD) {
        UA_StatusCode c = UA_Server_updateCertificate(
            server, ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP), type,
            cert, NULL);
        if(c != UA_STATUSCODE_GOOD)
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "closing the channels -> %s",
                           UA_StatusCode_name(c));
    }
    UA_ByteString_clear(&cert);
    UA_NodeId_clear(&type);
}

static void notice_due(UA_Server *server, void *data) {
    (void)data;
    if(N.cancelled) {
        notice_clear();
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "ApplyChanges cancelled");
        return;
    }
    UA_StatusCode r = UA_STATUSCODE_BADINVALIDSTATE; /* the transaction went with its session */
    if(P.txn && P.hasCert) {
        r = UA_ByteString_copy(&P.cert, &N.cert) | UA_NodeId_copy(&P.certType, &N.type);
        if(r == UA_STATUSCODE_GOOD)
            r = apply(false);
    }
    N.result = apply_done(r);
    UA_EventLoop *el = UA_Server_getConfig(server)->eventLoop;
    UA_DateTime due = el->dateTime_nowMonotonic(el) + PM_PUBLISH_MS * UA_DATETIME_MSEC;
    if(UA_Server_addTimedCallback(server, respond_due, NULL, due, NULL) != UA_STATUSCODE_GOOD)
        respond_due(server, NULL); /* at once, then */
}

static UA_StatusCode notice_start(UA_Variant *output) {
    UA_EventLoop *el = UA_Server_getConfig(P.server)->eventLoop;
    UA_DateTime due = el->dateTime_nowMonotonic(el) + PM_NOTICE_MS * UA_DATETIME_MSEC;
    UA_StatusCode r = UA_Server_addTimedCallback(P.server, notice_due, NULL, due, NULL);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    N.output = output;
    N.cancelled = false;
    N.until = UA_DateTime_now() + PM_NOTICE_MS * UA_DATETIME_MSEC;
    reason_write("The application certificate changes: SecureChannels will be closed");
    return UA_STATUSCODE_GOOD;
}

static void notice_cancelled(UA_Server *server, const void *out) {
    (void)server;
    if(N.output && out == N.output)
        N.cancelled = true;
}

/* SecondsTillShutdown, rounded up while a notice stands */
static UA_StatusCode notice_read(UA_Server *server, const UA_NodeId *sessionId,
                                 void *sessionContext, const UA_NodeId *nodeId, void *nodeContext,
                                 UA_Boolean includeSourceTimeStamp, const UA_NumericRange *range,
                                 UA_DataValue *value) {
    (void)server, (void)sessionId, (void)sessionContext, (void)nodeId, (void)nodeContext;
    (void)includeSourceTimeStamp;
    if(range)
        return UA_STATUSCODE_BADINDEXRANGEINVALID;
    UA_DateTime left = N.until ? N.until - UA_DateTime_now() : 0;
    UA_UInt32 sec = left > 0 ? (UA_UInt32)((left + UA_DATETIME_SEC - 1) / UA_DATETIME_SEC) : 0;
    value->hasValue = true;
    return UA_Variant_setScalarCopy(&value->value, &sec, &UA_TYPES[UA_TYPES_UINT32]);
}

static UA_StatusCode shutdown_notice(UA_Server *server) {
    UA_Server_getConfig(server)->asyncOperationCancelCallback = notice_cancelled;
    UA_CallbackValueSource src = {notice_read, NULL};
    return UA_Server_setVariableNode_callbackValueSource(
        server, ns0(UA_NS0ID_SERVER_SERVERSTATUS_SECONDSTILLSHUTDOWN), src);
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
    for(size_t i = 0; i < PM_MAX_FILES && !breaking("apply-while-open"); i++)
        if(P.files[i].used && P.files[i].mode == PM_MODE_WRITE_ERASE &&
           UA_NodeId_equal(&P.files[i].session, sessionId))
            return UA_STATUSCODE_BADINVALIDSTATE; /* §7.10.9: a TrustList is still open */
    if(P.hasCert && !breaking("apply-ignored") && !breaking("wire-no-shutdown-notice") &&
       !breaking("wire-keep-channels") && !breaking("wire-old-cert")) {
        if(N.output)
            return UA_STATUSCODE_BADINVALIDSTATE; /* this ApplyChanges is in progress */
        if(notice_start(output) == UA_STATUSCODE_GOOD)
            return UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY; /* notice_due completes it */
    }
    if(!(breaking("apply-ignored") && P.hasCert))
        r = apply(!breaking("wire-keep-channels"));
    return apply_done(r);
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
    if(r == UA_STATUSCODE_GOOD && breaking("cancel-keeps-trustlist") && P.hasList)
        r = install_list(&P.list);
    if(r == UA_STATUSCODE_GOOD) {
        txn_clear();
        diag_end(breaking("diag-cancel-good") ? UA_STATUSCODE_GOOD
                                              : UA_STATUSCODE_BADREQUESTCANCELLEDBYCLIENT);
    }
    return r;
}

/* ---------------- GetCertificates, CreateSelfSignedCertificate, DeleteCertificate ----------------
 * Optional ServerConfiguration Methods (12 §7.10.6 - §7.10.8), which
 * open62541's ns0 does not instantiate. This target has one slot
 * (DefaultApplicationGroup, RsaSha256) and it is always occupied and in use. */

static bool slot_args(size_t inputSize, const UA_Variant *input, size_t need) {
    if(inputSize != need || !scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_NODEID]))
        return false;
    const UA_NodeId dag = ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    return UA_NodeId_equal(input[0].data, &dag);
}

static bool rsa_type(size_t inputSize, const UA_Variant *input) {
    const UA_NodeId rsa = ns0(UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
    return scalar(input, inputSize, 1, &UA_TYPES[UA_TYPES_NODEID]) &&
           UA_NodeId_equal(input[1].data, &rsa);
}

static UA_StatusCode scGetCertificates(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode r = need_channel(sessionId, false);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(outputSize < 2)
        return UA_STATUSCODE_BADINTERNALERROR;
    if(!slot_args(inputSize, input, 1))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    const UA_ByteString *cur = current_cert();
    if(!cur)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_NodeId types[2] = {ns0(UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE),
                          ns0(UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE)};
    size_t nTypes = breaking("getcerts-mismatched") ? 2 : 1;
    r = UA_Variant_setArrayCopy(&output[0], types, nTypes, &UA_TYPES[UA_TYPES_NODEID]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setArrayCopy(&output[1], cur, 1, &UA_TYPES[UA_TYPES_BYTESTRING]);
    return r;
}

static UA_StatusCode scCreateSelfSigned(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode r = need_channel(sessionId, true);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(outputSize < 1)
        return UA_STATUSCODE_BADINTERNALERROR;
    if(!slot_args(inputSize, input, 6) || !rsa_type(inputSize, input))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(!breaking("selfsigned-overwrite"))
        return UA_STATUSCODE_BADINVALIDSTATE; /* §7.10.6: the slot holds a certificate */
    const UA_ByteString *cur = current_cert(); /* the mutant answers Good and changes nothing */
    return cur ? UA_Variant_setScalarCopy(&output[0], cur, &UA_TYPES[UA_TYPES_BYTESTRING])
               : UA_STATUSCODE_BADINTERNALERROR;
}

static UA_StatusCode scDeleteCertificate(METHOD_ARGS) {
    UNUSED_ARGS;
    (void)output;
    (void)outputSize;
    UA_StatusCode r = need_channel(sessionId, true);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(!slot_args(inputSize, input, 2) || !rsa_type(inputSize, input))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    /* §7.10.7: the endpoints use this certificate (the mutant: Good, no change) */
    return breaking("delete-in-use") ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINVALIDSTATE;
}

static void arg(UA_Argument *a, const char *name, UA_UInt32 type, bool array) {
    UA_Argument_init(a);
    a->name = UA_STRING((char *)(uintptr_t)name);
    a->dataType = ns0(type);
    a->valueRank = array ? UA_VALUERANK_ONE_DIMENSION : UA_VALUERANK_SCALAR;
}

static UA_StatusCode add_method(UA_Server *server, UA_UInt32 id, const char *name,
                                UA_MethodCallback cb, size_t inN, const UA_Argument *in,
                                size_t outN, const UA_Argument *out) {
    UA_MethodAttributes ma = UA_MethodAttributes_default;
    ma.displayName = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)name);
    ma.executable = true;
    ma.userExecutable = true;
    return UA_Server_addMethodNode(server, ns0(id), ns0(UA_NS0ID_SERVERCONFIGURATION),
                                   ns0(UA_NS0ID_HASCOMPONENT),
                                   UA_QUALIFIEDNAME(0, (char *)(uintptr_t)name), ma, cb, inN, in,
                                   outN, out, NULL, NULL);
}

static UA_StatusCode optional_methods(UA_Server *server) {
    UA_Argument in[6], out[2];
    arg(&in[0], "CertificateGroupId", UA_NS0ID_NODEID, false);
    arg(&out[0], "CertificateTypeIds", UA_NS0ID_NODEID, true);
    arg(&out[1], "Certificates", UA_NS0ID_BYTESTRING, true);
    UA_StatusCode r = add_method(server, UA_NS0ID_SERVERCONFIGURATION_GETCERTIFICATES,
                                 "GetCertificates", scGetCertificates, 1, in, 2, out);
    arg(&in[1], "CertificateTypeId", UA_NS0ID_NODEID, false);
    arg(&in[2], "SubjectName", UA_NS0ID_STRING, false);
    arg(&in[3], "DnsNames", UA_NS0ID_STRING, true);
    arg(&in[4], "LifetimeInDays", UA_NS0ID_UINT16, false);
    arg(&in[5], "KeySizeInBits", UA_NS0ID_UINT16, false);
    arg(&out[0], "Certificate", UA_NS0ID_BYTESTRING, false);
    r |= add_method(server, UA_NS0ID_SERVERCONFIGURATION_CREATESELFSIGNEDCERTIFICATE,
                    "CreateSelfSignedCertificate", scCreateSelfSigned, 6, in, 1, out);
    r |= add_method(server, UA_NS0ID_SERVERCONFIGURATION_DELETECERTIFICATE, "DeleteCertificate",
                    scDeleteCertificate, 2, in, 0, NULL);
    return r;
}

/* ---------------- Rejected list (12 §7.8.3.2, §7.10.12) ----------------
 * The client certificates the server refused, newest last. Only those with
 * no unsuppressed validation error that are not trusted are added
 * (§7.8.3.2); the library's own list keeps every refused certificate. */
#define PM_MAX_REJECTED 32

static struct {
    UA_ByteString c[PM_MAX_REJECTED];
    size_t n;
} R;

/* No signature error that the server can see: a self-signed certificate
 * verifies with its own key; one whose issuer is in the trust list
 * verifies with that issuer's key. */
static bool signature_sound(const UA_ByteString *der) {
    gds_buf b = {der->data, der->length};
    X509 *x = x509_parse_cert(&b);
    if(!x)
        return false;
    bool ok;
    if(X509_check_issued(x, x) == X509_V_OK) {
        EVP_PKEY *k = X509_get0_pubkey(x);
        ok = k && X509_verify(x, k) == 1;
    } else {
        UA_TrustListDataType l;
        if(current_list(&l) != UA_STATUSCODE_GOOD) {
            X509_free(x);
            return false;
        }
        bool sig = false;
        bool known = issuer_among(x, l.trustedCertificates, l.trustedCertificatesSize, &sig) ||
                     issuer_among(x, l.issuerCertificates, l.issuerCertificatesSize, &sig);
        ok = !known || sig;
        UA_TrustListDataType_clear(&l);
    }
    X509_free(x);
    ERR_clear_error();
    return ok;
}

static void reject_note(const UA_ByteString *cert, UA_StatusCode r) {
    if(r == UA_STATUSCODE_GOOD || breaking("rejected-not-recorded"))
        return;
    if(!breaking("rejected-records-invalid") &&
       (r != UA_STATUSCODE_BADCERTIFICATEUNTRUSTED || !signature_sound(cert)))
        return;
    for(size_t i = 0; i < R.n; i++)
        if(UA_ByteString_equal(&R.c[i], cert))
            return;
    if(R.n == PM_MAX_REJECTED) { /* the oldest goes */
        UA_ByteString_clear(&R.c[0]);
        memmove(&R.c[0], &R.c[1], (PM_MAX_REJECTED - 1) * sizeof(R.c[0]));
        R.n--;
    }
    if(UA_ByteString_copy(cert, &R.c[R.n]) == UA_STATUSCODE_GOOD)
        R.n++;
}

static void reject_clear(void) {
    for(size_t i = 0; i < R.n; i++)
        UA_ByteString_clear(&R.c[i]);
    R.n = 0;
}

static UA_StatusCode rejected_out(size_t outputSize, UA_Variant *output) {
    if(outputSize < 1)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_ByteString all[PM_MAX_REJECTED + 1];
    size_t n = R.n;
    memcpy(all, R.c, R.n * sizeof(R.c[0]));
    if(breaking("rejected-garbage"))
        all[n++] = UA_BYTESTRING("not a certificate");
    return UA_Variant_setArrayCopy(&output[0], n ? all : UA_EMPTY_ARRAY_SENTINEL, n,
                                   &UA_TYPES[UA_TYPES_BYTESTRING]);
}

static UA_StatusCode scGetRejectedList(METHOD_ARGS) {
    UNUSED_ARGS;
    (void)inputSize, (void)input;
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    return rejected_out(outputSize, output);
}

/* GetRejectedList on the DefaultApplicationGroup (§7.8.3.2): the same list */
static UA_StatusCode groupGetRejectedList(METHOD_ARGS) {
    UNUSED_ARGS;
    (void)inputSize, (void)input;
    UA_StatusCode sec = need_channel(sessionId, false);
    if(sec != UA_STATUSCODE_GOOD)
        return sec;
    if(breaking("group-rejected-broken"))
        return UA_STATUSCODE_BADINTERNALERROR;
    return rejected_out(outputSize, output);
}

/* The library's ns0 may lack the group's Method: add it. */
static UA_StatusCode group_rejected_method(UA_Server *server) {
    UA_NodeId id = ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_GETREJECTEDLIST);
    if(UA_Server_setMethodNodeCallback(server, id, groupGetRejectedList) == UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_GOOD;
    UA_Argument out;
    UA_Argument_init(&out);
    out.name = UA_STRING("Certificates");
    out.dataType = ns0(UA_NS0ID_BYTESTRING);
    out.valueRank = UA_VALUERANK_ONE_DIMENSION;
    UA_MethodAttributes ma = UA_MethodAttributes_default;
    ma.executable = true;
    ma.displayName = UA_LOCALIZEDTEXT("", "GetRejectedList");
    return UA_Server_addMethodNode(
        server, id, ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP),
        ns0(UA_NS0ID_HASCOMPONENT), UA_QUALIFIEDNAME(0, "GetRejectedList"), ma,
        groupGetRejectedList, 0, NULL, 1, &out, NULL, NULL);
}

/* ---------------- AddCertificate, RemoveCertificate (12 §7.8.2.6, §7.8.2.7) ----------------
 * Both act on the list in use at once; they refuse while a write handle is
 * open (Bad_InvalidState) or a transaction is in progress
 * (Bad_TransactionPending). */

static UA_StatusCode list_change_allowed(void) {
    if(write_open())
        return UA_STATUSCODE_BADINVALIDSTATE;
    return P.txn && !breaking("txn-interleave") ? UA_STATUSCODE_BADTRANSACTIONPENDING
                                                : UA_STATUSCODE_GOOD;
}

/* The CA in `l` (trusted or issuer) whose signature verifies x. */
static bool issuer_in(X509 *x, const UA_TrustListDataType *l) {
    const UA_ByteString *lists[2] = {l->trustedCertificates, l->issuerCertificates};
    const size_t sizes[2] = {l->trustedCertificatesSize, l->issuerCertificatesSize};
    bool found = false;
    for(size_t k = 0; k < 2 && !found; k++)
        for(size_t i = 0; i < sizes[k] && !found; i++) {
            gds_buf b = {lists[k][i].data, lists[k][i].length};
            X509 *ca = x509_parse_cert(&b);
            if(ca && X509_cmp(ca, x) != 0 && X509_check_issued(ca, x) == X509_V_OK) {
                EVP_PKEY *pk = X509_get0_pubkey(ca);
                found = pk && X509_verify(x, pk) == 1;
            }
            X509_free(ca);
        }
    ERR_clear_error();
    return found;
}

/* ---------------- UpdateCertificate checks (12 §7.10.5, 4 §6.1.3) ---------------- */

/* The issuer of x among the certificates of `l` (n entries); *sigOk if it
 * verifies x's signature. */
static bool issuer_among(X509 *x, const UA_ByteString *l, size_t n, bool *sigOk) {
    bool found = false;
    for(size_t i = 0; i < n && !*sigOk; i++) {
        gds_buf b = {l[i].data, l[i].length};
        X509 *ca = x509_parse_cert(&b);
        if(ca && X509_cmp(ca, x) != 0 && X509_check_issued(ca, x) == X509_V_OK) {
            found = true;
            EVP_PKEY *pk = X509_get0_pubkey(ca);
            *sigOk = pk && X509_verify(x, pk) == 1;
        }
        X509_free(ca);
    }
    ERR_clear_error();
    return found;
}

/* Self-signed: its own signature. CA-issued: the issuer must be in the
 * TrustList; IssuerCertificates does not make it trusted (§7.10.5). */
static UA_StatusCode chain_check(X509 *x, const UA_Variant *issuers) {
    bool sigOk = false, found = false;
    if(X509_check_issued(x, x) == X509_V_OK) {
        EVP_PKEY *pk = X509_get0_pubkey(x);
        found = true;
        sigOk = pk && X509_verify(x, pk) == 1;
        ERR_clear_error();
    } else {
        /* the trust list it will be validated with: a queued one if any
         * (§7.10.2 applies both together; SRV-TXN-11) */
        UA_TrustListDataType cur;
        UA_StatusCode r = P.hasList && !breaking("apply-partial")
                              ? UA_TrustListDataType_copy(&P.list, &cur)
                              : current_list(&cur);
        if(r != UA_STATUSCODE_GOOD)
            return r;
        found = issuer_among(x, cur.trustedCertificates, cur.trustedCertificatesSize, &sigOk);
        found |= issuer_among(x, cur.issuerCertificates, cur.issuerCertificatesSize, &sigOk);
        UA_TrustListDataType_clear(&cur);
        if(breaking("update-trust-issuer-arg") && UA_Variant_hasArrayType(issuers, &UA_TYPES[UA_TYPES_BYTESTRING]))
            found |= issuer_among(x, issuers->data, issuers->arrayLength, &sigOk);
    }
    if(!found)
        return UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE;
    return sigOk || breaking("update-no-sig-check") ? UA_STATUSCODE_GOOD
                                                    : UA_STATUSCODE_BADCERTIFICATEINVALID;
}

/* The SAN URI is the ApplicationUri (Part 6 §6.2.2, decision D3) */
static UA_StatusCode uri_check(X509 *x) {
    if(breaking("update-no-uri-check"))
        return UA_STATUSCODE_GOOD;
    unsigned char *der = NULL;
    int len = i2d_X509(x, &der);
    char uri[GDS_MAX_APPLICATION_URI + 1];
    gds_buf b = {der, len > 0 ? (size_t)len : 0};
    bool ok = len > 0 && x509_san_uri(&b, uri, sizeof(uri)) == GDS_OK;
    OPENSSL_free(der);
    const UA_String *app = &UA_Server_getConfig(P.server)->applicationDescription.applicationUri;
    ok = ok && strlen(uri) == app->length && memcmp(uri, app->data, app->length) == 0;
    return ok ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADCERTIFICATEURIINVALID;
}

/* PrivateKey in PEM (the one advertised format): it must belong to the
 * certificate, else Bad_NotSupported (§7.10.5). Kept as DER. */
static UA_StatusCode pushed_key(X509 *x, const UA_String *format, const UA_ByteString *in,
                                UA_ByteString *out) {
    UA_ByteString_init(out);
    const UA_String pem = UA_STRING_STATIC("PEM");
    if(!UA_String_equal(format, &pem) || in->length > GDS_MAX_CERT_SIZE)
        return UA_STATUSCODE_BADNOTSUPPORTED;
    gds_buf kb = {in->data, in->length};
    EVP_PKEY *k = x509_parse_key(&kb);
    EVP_PKEY *pub = X509_get0_pubkey(x);
    bool match = k && pub && EVP_PKEY_eq(k, pub) == 1;
    gds_buf der = {0};
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(!k || (!match && !breaking("update-accept-bad-key")))
        r = UA_STATUSCODE_BADNOTSUPPORTED;
    else if(x509_key_to_der(k, &der) != GDS_OK)
        r = UA_STATUSCODE_BADINTERNALERROR;
    else {
        UA_ByteString b = {der.len, der.data};
        r = UA_ByteString_copy(&b, out);
    }
    gds_buf_free_secret(&der);
    EVP_PKEY_free(k);
    ERR_clear_error();
    return r;
}

static UA_StatusCode update_checks(X509 *x, const UA_Variant *issuers, const UA_NodeId *session,
                                   UA_ByteString *key, bool keyGiven) {
    if(!keyGiven)
        UA_ByteString_init(key);
    EVP_PKEY *pk = X509_get0_pubkey(x);
    if(!pk || EVP_PKEY_get_base_id(pk) != EVP_PKEY_RSA) { /* the slot is RsaSha256 */
        ERR_clear_error();
        return breaking("update-type-mismatch") ? UA_STATUSCODE_GOOD
                                                : UA_STATUSCODE_BADCERTIFICATEINVALID;
    }
    unsigned char *der = NULL;
    int len = i2d_X509(x, &der);
    UA_ByteString c = {len > 0 ? (size_t)len : 0, der};
    UA_StatusCode r = len > 0 ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADCERTIFICATEINVALID;
    if(r == UA_STATUSCODE_GOOD && !keyGiven && !breaking("update-no-key-check"))
        r = key_for(&c, session, key);
    OPENSSL_free(der);
    if(r == UA_STATUSCODE_GOOD)
        r = chain_check(x, issuers);
    if(r == UA_STATUSCODE_GOOD && !breaking("update-accept-expired") &&
       (X509_cmp_current_time(X509_get0_notBefore(x)) > 0 ||
        X509_cmp_current_time(X509_get0_notAfter(x)) < 0))
        r = UA_STATUSCODE_BADCERTIFICATETIMEINVALID;
    if(r == UA_STATUSCODE_GOOD)
        r = uri_check(x);
    if(r != UA_STATUSCODE_GOOD)
        secret_clear(key);
    ERR_clear_error();
    return r;
}

/* OPC 10000-4 validation, as far as this target goes: validity times, and a
 * CA-issued certificate needs its issuer in the TrustList (§7.8.2.6). */
static UA_StatusCode validate_new(const UA_ByteString *cert, const UA_TrustListDataType *cur) {
    gds_buf b = {cert->data, cert->length};
    X509 *x = x509_parse_cert(&b);
    if(!x)
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(X509_cmp_current_time(X509_get0_notBefore(x)) > 0 ||
       X509_cmp_current_time(X509_get0_notAfter(x)) < 0)
        r = UA_STATUSCODE_BADCERTIFICATETIMEINVALID;
    else if(X509_check_issued(x, x) != X509_V_OK && !breaking("addcert-no-chain-check") &&
            !issuer_in(x, cur))
        r = UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE;
    X509_free(x);
    ERR_clear_error();
    return r;
}

static bool in_list(const UA_ByteString *l, size_t n, const UA_ByteString *x) {
    for(size_t i = 0; i < n; i++)
        if(UA_ByteString_equal(&l[i], x))
            return true;
    return false;
}

static UA_StatusCode tlAddCertificate(METHOD_ARGS) {
    UNUSED_ARGS;
    (void)output;
    (void)outputSize;
    UA_StatusCode r = need_channel(sessionId, false);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(!scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_BYTESTRING]) ||
       !scalar(input, inputSize, 1, &UA_TYPES[UA_TYPES_BOOLEAN]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    const UA_ByteString *cert = input[0].data;
    bool trusted = *(const UA_Boolean *)input[1].data;
    if(!breaking("addcert-while-open") && (r = list_change_allowed()) != UA_STATUSCODE_GOOD)
        return r;
    if(!trusted && !breaking("addcert-issuer-allowed"))
        return UA_STATUSCODE_BADCERTIFICATEINVALID; /* issuers come with CRLs: Write only */
    UA_TrustListDataType cur;
    r = current_list(&cur);
    if(r == UA_STATUSCODE_GOOD)
        r = validate_new(cert, &cur);
    UA_ByteString **dst = trusted ? &cur.trustedCertificates : &cur.issuerCertificates;
    size_t *dstN = trusted ? &cur.trustedCertificatesSize : &cur.issuerCertificatesSize;
    bool add = r == UA_STATUSCODE_GOOD && !breaking("addcert-noop") && !in_list(*dst, *dstN, cert);
    if(add)
        r = UA_Array_appendCopy((void **)dst, dstN, cert, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(add && r == UA_STATUSCODE_GOOD &&
       UA_calcSizeBinary(&cur, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL) > P.maxSize)
        r = UA_STATUSCODE_BADREQUESTTOOLARGE;
    if(add && r == UA_STATUSCODE_GOOD)
        r = install_list(&cur);
    UA_TrustListDataType_clear(&cur);
    return r;
}

/* Index of the certificate with this SHA-1 thumbprint (hex, any case). */
static bool find_thumb(const UA_ByteString *l, size_t n, const UA_String *thumb, size_t *at) {
    for(size_t i = 0; i < n; i++) {
        unsigned char md[20];
        unsigned int mdLen = 0;
        char hex[41];
        if(EVP_Digest(l[i].data, l[i].length, md, &mdLen, EVP_sha1(), NULL) != 1 ||
           mdLen != sizeof(md))
            continue;
        for(size_t k = 0; k < sizeof(md); k++)
            (void)snprintf(hex + 2 * k, 3, "%02X", md[k]);
        if(thumb->length != 40)
            continue;
        bool eq = true;
        for(size_t k = 0; k < 40 && eq; k++) {
            char c = (char)thumb->data[k];
            if(c >= 'a' && c <= 'f')
                c = (char)(c - 'a' + 'A');
            eq = c == hex[k];
        }
        if(eq) {
            *at = i;
            return true;
        }
    }
    ERR_clear_error();
    return false;
}

/* Does CA `ca` issue another certificate of the list? */
static bool ca_in_use(X509 *ca, const UA_TrustListDataType *l) {
    const UA_ByteString *lists[2] = {l->trustedCertificates, l->issuerCertificates};
    const size_t sizes[2] = {l->trustedCertificatesSize, l->issuerCertificatesSize};
    bool used = false;
    for(size_t k = 0; k < 2 && !used; k++)
        for(size_t i = 0; i < sizes[k] && !used; i++) {
            gds_buf b = {lists[k][i].data, lists[k][i].length};
            X509 *x = x509_parse_cert(&b);
            used = x && X509_cmp(ca, x) != 0 && X509_check_issued(ca, x) == X509_V_OK;
            X509_free(x);
        }
    ERR_clear_error();
    return used;
}

/* Drop the CRLs issued by ca from a list of CRLs. */
static void drop_crls_of(X509 *ca, UA_ByteString **l, size_t *n) {
    if(*n == 0)
        return; /* *l may be UA_EMPTY_ARRAY_SENTINEL */
    size_t w = 0;
    for(size_t i = 0; i < *n; i++) {
        const unsigned char *q = (*l)[i].data;
        X509_CRL *crl = d2i_X509_CRL(NULL, &q, (long)(*l)[i].length);
        bool of = crl && X509_NAME_cmp(X509_CRL_get_issuer(crl), X509_get_subject_name(ca)) == 0;
        X509_CRL_free(crl);
        if(of)
            UA_ByteString_clear(&(*l)[i]);
        else
            (*l)[w++] = (*l)[i];
    }
    *n = w;
    if(w == 0) {
        UA_free(*l);
        *l = NULL;
    }
    ERR_clear_error();
}

static UA_StatusCode remove_at(UA_TrustListDataType *cur, bool trusted, size_t at) {
    UA_ByteString *l = trusted ? cur->trustedCertificates : cur->issuerCertificates;
    size_t *n = trusted ? &cur->trustedCertificatesSize : &cur->issuerCertificatesSize;
    gds_buf b = {l[at].data, l[at].length};
    X509 *x = x509_parse_cert(&b);
    bool isCa = x && X509_check_ca(x) > 0;
    if(isCa && !breaking("remove-ca-in-use") && ca_in_use(x, cur)) {
        X509_free(x);
        return UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE;
    }
    UA_ByteString_clear(&l[at]);
    l[at] = l[*n - 1];
    (*n)--;
    if(isCa && !breaking("remove-keeps-crl")) { /* §7.8.2.7: its CRLs go too */
        drop_crls_of(x, &cur->trustedCrls, &cur->trustedCrlsSize);
        drop_crls_of(x, &cur->issuerCrls, &cur->issuerCrlsSize);
    }
    X509_free(x);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode tlRemoveCertificate(METHOD_ARGS) {
    UNUSED_ARGS;
    (void)output;
    (void)outputSize;
    UA_StatusCode r = need_channel(sessionId, false);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(!scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_STRING]) ||
       !scalar(input, inputSize, 1, &UA_TYPES[UA_TYPES_BOOLEAN]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    const UA_String *thumb = input[0].data;
    bool trusted = *(const UA_Boolean *)input[1].data;
    if((r = list_change_allowed()) != UA_STATUSCODE_GOOD)
        return r;
    UA_TrustListDataType cur;
    if((r = current_list(&cur)) != UA_STATUSCODE_GOOD)
        return r;
    size_t at = 0;
    bool found = trusted ? find_thumb(cur.trustedCertificates, cur.trustedCertificatesSize, thumb, &at)
                         : find_thumb(cur.issuerCertificates, cur.issuerCertificatesSize, thumb, &at);
    if(!found)
        r = breaking("remove-unknown-good") ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINVALIDARGUMENT;
    else if(!breaking("remove-noop") && (r = remove_at(&cur, trusted, at)) == UA_STATUSCODE_GOOD)
        r = install_list(&cur);
    UA_TrustListDataType_clear(&cur);
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
    UA_String der = UA_STRING_STATIC("DER"), pem = UA_STRING_STATIC("PEM");
    if(breaking("bad-key-format-name"))
        UA_Variant_setArray(&v, &der, 1, &UA_TYPES[UA_TYPES_STRING]);
    else if(P.acceptKeys)
        UA_Variant_setArray(&v, &pem, 1, &UA_TYPES[UA_TYPES_STRING]);
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
    return UA_STATUSCODE_BADNOTSUPPORTED;
}

#define TLP(x) UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_##x

/* TrustList Properties: Size refused; UpdateFrequency absent, as 7.8.2.1
 * requires for a TrustList inside ServerConfiguration. */
static UA_StatusCode trustlist_props(UA_Server *server) {
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(!breaking("size-readable")) {
        UA_CallbackValueSource src = {size_read, NULL};
        r = UA_Server_setVariableNode_callbackValueSource(server, ns0(TLP(SIZE)), src);
    } else {
        UA_UInt64 size = 4096;
        UA_Variant v;
        UA_Variant_setScalar(&v, &size, &UA_TYPES[UA_TYPES_UINT64]);
        r = UA_Server_writeValue(server, ns0(TLP(SIZE)), v);
    }
    (void)UA_Server_deleteNode(server, ns0(TLP(UPDATEFREQUENCY)), true);
    /* ActivityTimeout (Optional) is not in the library's ns0 instance */
    UA_Double timeout = PM_ACTIVITY_TIMEOUT_MS;
    UA_VariableAttributes at = UA_VariableAttributes_default;
    UA_Variant_setScalar(&at.value, &timeout, &UA_TYPES[UA_TYPES_DOUBLE]);
    at.dataType = UA_TYPES[UA_TYPES_DURATION].typeId;
    at.displayName = UA_LOCALIZEDTEXT("", "ActivityTimeout");
    UA_StatusCode a = UA_Server_addVariableNode(
        server, ns0(TLP(ACTIVITYTIMEOUT)),
        ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST),
        ns0(UA_NS0ID_HASPROPERTY), UA_QUALIFIEDNAME(0, "ActivityTimeout"),
        ns0(UA_NS0ID_PROPERTYTYPE), at, NULL, NULL);
    if(a == UA_STATUSCODE_BADNODEIDEXISTS)
        a = UA_Server_writeValue(server, ns0(TLP(ACTIVITYTIMEOUT)), at.value);
    r |= a;
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

#define DAG_ID UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP
#define DAG_TL_ID UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST

static UA_StatusCode diag_value(UA_UInt32 id, UA_DataValue *value) {
    if(!D.started) {
        value->hasStatus = true;
        value->status = UA_STATUSCODE_BADOUTOFSERVICE;
        return value->status; /* the library keeps only a returned Bad code */
    }
    value->hasValue = true;
    UA_Variant *v = &value->value;
    switch(id) {
    case DIAG(STARTTIME):
        return UA_Variant_setScalarCopy(v, &D.start, &UA_TYPES[UA_TYPES_UTCTIME]);
    case DIAG(ENDTIME):
        return UA_Variant_setScalarCopy(v, &D.end, &UA_TYPES[UA_TYPES_UTCTIME]);
    case DIAG(RESULT):
        if(!D.done) {
            value->hasValue = false;
            value->hasStatus = true;
            value->status = UA_STATUSCODE_BADINVALIDSTATE;
            return value->status;
        }
        return UA_Variant_setScalarCopy(v, &D.result, &UA_TYPES[UA_TYPES_STATUSCODE]);
    case DIAG(AFFECTEDTRUSTLISTS): {
        UA_NodeId n = ns0(DAG_TL_ID);
        return UA_Variant_setArrayCopy(v, &n, D.trustList ? 1 : 0, &UA_TYPES[UA_TYPES_NODEID]);
    }
    case DIAG(AFFECTEDCERTIFICATEGROUPS): {
        UA_NodeId n = ns0(DAG_ID);
        return UA_Variant_setArrayCopy(v, &n, D.group ? 1 : 0, &UA_TYPES[UA_TYPES_NODEID]);
    }
    case DIAG(ERRORS): {
        /* one entry for a failed ApplyChanges, on the group or else the TrustList */
        UA_TransactionErrorType e;
        UA_TransactionErrorType_init(&e);
        e.targetId = ns0(D.group ? DAG_ID : DAG_TL_ID);
        e.error = D.result;
        e.message = UA_LOCALIZEDTEXT("", "ApplyChanges failed");
        bool err = D.done && D.result != UA_STATUSCODE_GOOD &&
                   D.result != UA_STATUSCODE_BADREQUESTCANCELLEDBYCLIENT;
        return UA_Variant_setArrayCopy(v, &e, err ? 1 : 0,
                                       &UA_TYPES[UA_TYPES_TRANSACTIONERRORTYPE]);
    }
    default:
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    }
}

static UA_StatusCode diag_read(UA_Server *server, const UA_NodeId *sessionId,
                               void *sessionContext, const UA_NodeId *nodeId, void *nodeContext,
                               UA_Boolean includeSourceTimeStamp, const UA_NumericRange *range,
                               UA_DataValue *value) {
    (void)server, (void)sessionId, (void)sessionContext, (void)nodeContext;
    (void)includeSourceTimeStamp, (void)range;
    if(nodeId->namespaceIndex != 0 || nodeId->identifierType != UA_NODEIDTYPE_NUMERIC)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    return diag_value(nodeId->identifier.numeric, value);
}

/* ServerConfiguration/TransactionDiagnostics (Optional, 12 §7.10.3), which
 * the library's ns0 does not instantiate. Read access is limited to
 * SecurityAdmin by push_test_server's access control. */
static UA_StatusCode diagnostics(UA_Server *server) {
    static const struct {
        UA_UInt32 id;
        const char *name;
        UA_UInt32 type;
        bool array;
    } vars[] = {
        {DIAG(STARTTIME), "StartTime", UA_NS0ID_UTCTIME, false},
        {DIAG(ENDTIME), "EndTime", UA_NS0ID_UTCTIME, false},
        {DIAG(RESULT), "Result", UA_NS0ID_STATUSCODE, false},
        {DIAG(AFFECTEDTRUSTLISTS), "AffectedTrustLists", UA_NS0ID_NODEID, true},
        {DIAG(AFFECTEDCERTIFICATEGROUPS), "AffectedCertificateGroups", UA_NS0ID_NODEID, true},
        {DIAG(ERRORS), "Errors", UA_NS0ID_TRANSACTIONERRORTYPE, true},
    };
    UA_ObjectAttributes oa = UA_ObjectAttributes_default;
    oa.displayName = UA_LOCALIZEDTEXT("", "TransactionDiagnostics");
    UA_StatusCode r = UA_Server_addNode_begin(
        server, UA_NODECLASS_OBJECT, ns0(UA_NS0ID_SERVERCONFIGURATION_TRANSACTIONDIAGNOSTICS),
        ns0(UA_NS0ID_SERVERCONFIGURATION), ns0(UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(0, "TransactionDiagnostics"), ns0(UA_NS0ID_TRANSACTIONDIAGNOSTICSTYPE),
        &oa, &UA_TYPES[UA_TYPES_OBJECTATTRIBUTES], NULL, NULL);
    if(r == UA_STATUSCODE_BADNODEIDEXISTS)
        r = UA_STATUSCODE_GOOD; /* a library with the full ns0 */
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && i < GDS_ARRAY_SIZE(vars); i++) {
        UA_VariableAttributes va = UA_VariableAttributes_default;
        va.dataType = ns0(vars[i].type);
        va.valueRank = vars[i].array ? UA_VALUERANK_ONE_DIMENSION : UA_VALUERANK_SCALAR;
        va.accessLevel = UA_ACCESSLEVELMASK_READ;
        va.displayName = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)vars[i].name);
        UA_UInt32 dims[1] = {0};
        if(vars[i].array) { /* an empty array, else the type check refuses the node */
            UA_Variant_setArray(&va.value, UA_EMPTY_ARRAY_SENTINEL, 0,
                                UA_findDataType(&va.dataType));
            va.arrayDimensions = dims;
            va.arrayDimensionsSize = 1;
        }
        UA_StatusCode a = UA_Server_addVariableNode(
            server, ns0(vars[i].id), ns0(UA_NS0ID_SERVERCONFIGURATION_TRANSACTIONDIAGNOSTICS),
            ns0(UA_NS0ID_HASPROPERTY), UA_QUALIFIEDNAME(0, (char *)(uintptr_t)vars[i].name),
            ns0(UA_NS0ID_PROPERTYTYPE), va, NULL, NULL);
        if(a != UA_STATUSCODE_GOOD && a != UA_STATUSCODE_BADNODEIDEXISTS)
            r = a;
        UA_CallbackValueSource src = {diag_read, NULL};
        if(r == UA_STATUSCODE_GOOD)
            r = UA_Server_setVariableNode_callbackValueSource(server, ns0(vars[i].id), src);
    }
    UA_StatusCode f = UA_Server_addNode_finish(server, ns0(UA_NS0ID_SERVERCONFIGURATION_TRANSACTIONDIAGNOSTICS));
    return r != UA_STATUSCODE_GOOD ? r : f;
}
#undef DAG_ID
#undef DAG_TL_ID
#undef DIAG

/* ---------------- Client certificate checks (SRV-WIRE-04 to -06) ----------------
 * The library verifies a client's certificate with the secureChannelPKI
 * group; the wire mutants wrap that call. */
static UA_StatusCode (*libVerify)(UA_CertificateGroup *, const UA_ByteString *);

static UA_StatusCode verify_client(UA_CertificateGroup *g, const UA_ByteString *cert) {
    if(breaking("wire-trust-all"))
        return UA_STATUSCODE_GOOD;
    if(breaking("wire-trustlist-not-loaded") && hasStartupPki)
        return startupPki.verifyCertificate(&startupPki, cert);
    UA_StatusCode r = libVerify(g, cert);
    if(breaking("wire-ignore-crl") && r == UA_STATUSCODE_BADCERTIFICATEREVOKED)
        return UA_STATUSCODE_GOOD;
    reject_note(cert, r);
    return r;
}

/* Every client certificate check goes through verify_client */
static UA_StatusCode verify_mutants(void) {
    UA_CertificateGroup *g = pki();
    if(breaking("wire-trustlist-not-loaded")) {
        UA_TrustListDataType l;
        UA_NodeId id = g->certificateGroupId;
        UA_StatusCode r = current_list(&l);
        if(r == UA_STATUSCODE_GOOD)
            r = UA_CertificateGroup_Memorystore(&startupPki, &id, &l, UA_Log_Stdout, NULL);
        UA_TrustListDataType_clear(&l);
        if(r != UA_STATUSCODE_GOOD)
            return r;
        hasStartupPki = true;
    }
    libVerify = g->verifyCertificate;
    g->verifyCertificate = verify_client;
    return UA_STATUSCODE_GOOD;
}

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

/* What the last run left: LastUpdateTime and a pending new key pair. */
static UA_StatusCode restart_state(UA_Server *server) {
    gds_buf b = {0};
    UA_DateTime when = 0;
    if(store_get("lastupdate", sizeof(when), &b) && b.len == sizeof(when))
        memcpy(&when, b.data, sizeof(when));
    gds_buf_free(&b);
    if(breaking("lastupdate-reset-now"))
        when = UA_DateTime_now();
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(when) {
        UA_Variant v;
        UA_Variant_setScalar(&v, &when, &UA_TYPES[UA_TYPES_DATETIME]);
        r = UA_Server_writeValue(
            server,
            ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_LASTUPDATETIME),
            v);
    }
    if(r == UA_STATUSCODE_GOOD && store_get("csr-new.key", GDS_MAX_KEY_SIZE, &b)) {
        UA_ByteString k = {b.len, b.data};
        r = UA_ByteString_copy(&k, &P.newKey);
        gds_buf_free_secret(&b);
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "the new key pair of the last CreateSigningRequest is kept");
    }
    return r;
}

UA_StatusCode pm_install(UA_Server *server, const char *mutant, const UA_ByteString *ownKey,
                         pm_mode_fn modeOf) {
    memset(&P, 0, sizeof(P));
    memset(&D, 0, sizeof(D));
    memset(&N, 0, sizeof(N));
    P.server = server;
    P.brk = mutant;
    P.acceptKeys = acceptKeys;
    P.modeOf = modeOf;
    if(UA_ByteString_copy(ownKey, &P.ownKey) != UA_STATUSCODE_GOOD)
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
    r |= set_cb(UA_NS0ID_SERVERCONFIGURATION_CREATESIGNINGREQUEST, scCreateSigningRequest);
    r |= set_cb(UA_NS0ID_SERVERCONFIGURATION_GETREJECTEDLIST, scGetRejectedList);
    r |= set_cb(TL(ADDCERTIFICATE), tlAddCertificate);
    r |= set_cb(TL(REMOVECERTIFICATE), tlRemoveCertificate);
#undef TL
    r |= set_cb(UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE, scUpdateCertificate);
    r |= set_cb(UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES, scApplyChanges);
    if(r != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINTERNALERROR;
    /* CancelChanges is Optional (§7.10.11): offered when the node exists */
    if(set_cb(UA_NS0ID_SERVERCONFIGURATION_CANCELCHANGES, scCancelChanges) != UA_STATUSCODE_GOOD)
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "no CancelChanges node");
    /* Server.Auditing TRUE (the library's value source reads FALSE) */
    UA_CallbackValueSource aud = {auditing_read, NULL};
    if(UA_Server_setVariableNode_callbackValueSource(server, ns0(UA_NS0ID_SERVER_AUDITING), aud) !=
       UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINTERNALERROR;
    if(advertise(server) != UA_STATUSCODE_GOOD || optional_methods(server) != UA_STATUSCODE_GOOD ||
       structure_mutants(server) != UA_STATUSCODE_GOOD ||
       trustlist_props(server) != UA_STATUSCODE_GOOD || diagnostics(server) != UA_STATUSCODE_GOOD ||
       shutdown_notice(server) != UA_STATUSCODE_GOOD ||
       group_rejected_method(server) != UA_STATUSCODE_GOOD || restart_state(server) != UA_STATUSCODE_GOOD ||
       verify_mutants() != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINTERNALERROR;
    return UA_STATUSCODE_GOOD;
}


