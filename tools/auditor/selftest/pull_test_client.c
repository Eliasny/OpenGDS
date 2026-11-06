/* OpenGDS Auditor self-test target: PULL test client
 * SPDX-License-Identifier: MPL-2.0
 *
 * A known-good OPC UA application that manages its own certificate and trust
 * list with Part 12 PullManagement against any GDS (OPC 10000-12 §6.4, §7.6,
 * Annex G.1). TEST TARGET, NOT A PRODUCT.
 *
 *   FindApplications -> RegisterApplication (first run only)
 *   GetCertificateGroups -> GetCertificateStatus
 *   StartSigningRequest (CSR from our own key) -> FinishRequest (polls while
 *   the GDS returns Bad_NothingToDo, i.e. awaiting approval)
 *   GetTrustList -> TrustList Open/Read/Close
 *
 * The result is written to a Part 12 Annex F.1 style PKI directory. The GDS
 * is trusted explicitly with --trust, never on first use (rogue GDS threat).
 *
 * Usage:
 *   pull_test_client --gds opc.tcp://localhost:4850 --pki ./pki-pull \
 *       --trust gds-ca.der [--crl gds-ca.crl] --user registrar \
 *       (--password-file FILE | --password P) [--app-uri urn:...] [--poll-seconds 60]
 *       [--discovery-url opc.tcp://host:port]   (register as ClientAndServer)
 *   pull_test_client --from-env [--break MUTANT]  (as the trigger of `gdsaudit client`)
 *
 * --from-env takes the GDS, its CA and CRL, the user, the password file and
 * the PKI directory from the GDSAUDIT_* variables gdsaudit client sets.
 * --break makes the client wrong in one named way, so that each CLI-* test
 * of the Auditor is seen to fail on cue (docs/auditor/client-profile.md).
 * A mutant only talks to a GDS on this host.
 */
#include <open62541/client_highlevel.h>
#include <open62541/nodeids_gds.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/securitypolicy_default.h>
#include <open62541/types_gds_generated.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>

#include "common/limits.h"
#include "common/safeint.h"
#include "uaclient.h"
#include "common/banned.h"

#define GDS_NS_URI "http://opcfoundation.org/UA/GDS/"
#define MAX_TRUST 8
#define MAX_PASSWORD 256
#define PTC_MAX_URL 256

#define POLICY_BASIC256 "http://opcfoundation.org/UA/SecurityPolicy#Basic256"

static const char *appUri = "urn:opengds:test:pullclient";
static const char *appName = "OpenGDS Pull Test Client";
static const char *mutant = NULL; /* --break */

static const char *const mutants[] = {
    "csr-bad-signature",  "csr-wrong-uri",       "csr-weak-key",       "csr-unlisted-type",
    "csr-no-dns",         "csr-reuse-key",       "leak-private-key",   "csr-retry-storm",
    "use-newkeypair",     "register-wrong-uri",  "register-wrong-type", "register-every-run",
    "pending-give-up",    "poll-no-backoff",     "pending-new-csr",    "poll-after-reject",
    "keep-session-open",  "ignore-update-required", "renew-always",    "renew-with-password",
    "read-one-chunk",     "no-close",            "always-download",    "trustlist-not-installed",
    "trustlist-merge",    "issuers-trusted",     "install-ignored",    "renew-keep-old",
    "install-unverified", "install-wrong-key",   "install-wrong-uri",  "install-expired",
    "send-password-untrusted", "trust-any-gds",  "ignore-gds-crl",     "accept-expired-gds",
    "no-gds-uri-check",   "use-sign-only",       "prefer-deprecated",  "ignore-crls",
    "parse-garbage",      "no-length-check",     "reconnect-storm",    "install-partial-trustlist",
    "pending-stuck-invalid", "no-call-timeout", "install-no-chain", "install-in-ram",
    "pending-forget"};

static bool is_mutant(const char *name) {
    return mutant && strcmp(mutant, name) == 0;
}

static bool known_mutant(const char *name) {
    for(size_t i = 0; i < GDS_ARRAY_SIZE(mutants); i++)
        if(strcmp(mutants[i], name) == 0)
            return true;
    return false;
}

/* "opc.tcp://host:port/path" -> host */
static void url_host(const char *url, char *out, size_t outLen) {
    const char *h = strstr(url, "://");
    h = h ? h + 3 : url;
    size_t n = strcspn(h, ":/");
    if(n >= outLen)
        n = outLen - 1;
    memcpy(out, h, n);
    out[n] = '\0';
}

static bool is_loopback(const char *url) {
    char h[PTC_MAX_URL];
    url_host(url, h, sizeof(h));
    return !strcmp(h, "localhost") || !strcmp(h, "127.0.0.1") || !strncmp(h, "[::1]", 5);
}

/* The CSR for one signing request. The good client makes a new RSA-2048 key
 * for every request (12 §7.6); *newKey receives it (empty: reuse `key`). */
static gds_status make_request(const gds_buf *key, const char *dnsName, gds_buf *newKey,
                               gds_buf *csr) {
    gds_status r = GDS_OK;
    if(!is_mutant("csr-reuse-key"))
        r = x509_new_rsa_key(is_mutant("csr-weak-key") ? 1024U : 2048U, newKey);
    if(r != GDS_OK)
        return r;
    const gds_buf *k = newKey->len ? newKey : key;
    r = x509_make_csr(k, appName, is_mutant("csr-wrong-uri") ? "urn:opengds:test:not-this-client" : appUri,
                      is_mutant("csr-no-dns") ? NULL : dnsName, csr);
    if(r != GDS_OK)
        return r;
    if(is_mutant("csr-bad-signature"))
        csr->data[csr->len - 1] ^= 0x01; /* inside the signature BIT STRING */
    if(is_mutant("leak-private-key")) {
        /* the key DER rides along behind the CSR */
        if((r = gds_buf_append(csr, k->data, k->len, GDS_MAX_CSR_SIZE + GDS_MAX_KEY_SIZE)) != GDS_OK)
            return r;
    }
    return GDS_OK;
}


/* Register the GDS-namespace data types (ApplicationRecordDataType) */
static UA_DataTypeArray gdsTypes = {NULL, UA_TYPES_GDS_COUNT, UA_TYPES_GDS, false};

static int fail(const char *what, UA_StatusCode r) {
    fprintf(stderr, "\nFAILED: %s: %s\n", what, UA_StatusCode_name(r));
    return 1;
}

static int failg(const char *what, gds_status s) {
    fprintf(stderr, "\nFAILED: %s: %s\n", what, gds_status_name(s));
    return 1;
}

static gds_status ensureOwnIdentity(const char *pki, gds_buf *cert, gds_buf *key) {
    char cp[GDS_MAX_PATH], kp[GDS_MAX_PATH], d[GDS_MAX_PATH], sanUri[GDS_MAX_APPLICATION_URI + 8];
    gds_status r;
    if((r = gds_path(cp, sizeof(cp), "%s/own/cert.der", pki)) != GDS_OK ||
       (r = gds_path(kp, sizeof(kp), "%s/own/private/key.der", pki)) != GDS_OK ||
       (r = gds_path(d, sizeof(d), "%s/own/private", pki)) != GDS_OK ||
       (r = gds_path(sanUri, sizeof(sanUri), "URI:%s", appUri)) != GDS_OK)
        return r;
    if(gds_file_read(cp, GDS_MAX_CERT_SIZE, cert) == GDS_OK &&
       gds_file_read(kp, GDS_MAX_KEY_SIZE, key) == GDS_OK && x509_key_matches(cert, key)) {
        uac_info("Loaded own certificate from %s", cp);
        return GDS_OK;
    }
    gds_buf_free(cert);
    gds_buf_free_secret(key);
    /* First start: self-signed certificate, replaced by the GDS below */
    UA_String subject[2] = {UA_STRING_STATIC("O=OpenGDS Test"),
                            UA_STRING_STATIC("CN=OpenGDS Pull Test Client")};
    UA_String san[2] = {UA_STRING(sanUri), UA_STRING_STATIC("DNS:localhost")};
    UA_ByteString c = UA_BYTESTRING_NULL, k = UA_BYTESTRING_NULL;
    if(UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER, NULL,
                            &k, &c) != UA_STATUSCODE_GOOD)
        return GDS_ECRYPTO;
    cert->data = c.data;
    cert->len = c.length;
    key->data = k.data;
    key->len = k.length;
    if((r = gds_mkdirs(d, 0700)) != GDS_OK ||
       (r = gds_file_write_atomic(kp, key->data, key->len, 0600)) != GDS_OK ||
       (r = gds_file_write_atomic(cp, cert->data, cert->len, 0644)) != GDS_OK) {
        gds_buf_free(cert);
        gds_buf_free_secret(key);
        return r;
    }
    uac_info("Created self-signed certificate (first start)");
    return GDS_OK;
}

static gds_status saveList(const char *pki, const char *sub, const char *ext,
                           const UA_ByteString *items, size_t n) {
    char dir[GDS_MAX_PATH];
    gds_status r;
    if((r = gds_path(dir, sizeof(dir), "%s/%s", pki, sub)) != GDS_OK ||
       (r = gds_mkdirs(dir, 0700)) != GDS_OK)
        return r;
    for(size_t i = 0; i < n; i++) {
        gds_buf b = {items[i].data, items[i].length};
        char tp[X509_THUMBPRINT_LEN], path[GDS_MAX_PATH];
        if(b.len == 0 || b.len > GDS_MAX_CRL_SIZE)
            return GDS_ETOOBIG;
        /* name by SHA-1 of the bytes; CRLs too (thumbprint() checks only size) */
        if(b.len > GDS_MAX_CERT_SIZE) {
            if((r = gds_path(path, sizeof(path), "%s/crl-%zu.%s", dir, i, ext)) != GDS_OK)
                return r;
        } else if((r = x509_thumbprint(&b, tp)) != GDS_OK ||
                  (r = gds_path(path, sizeof(path), "%s/%s.%s", dir, tp, ext)) != GDS_OK) {
            return r;
        }
        if((r = gds_file_write_atomic(path, b.data, b.len, 0644)) != GDS_OK)
            return r;
    }
    return GDS_OK;
}

static gds_status readPasswordFile(const char *path, char *out, size_t outLen) {
    gds_buf b = {0};
    gds_status r = gds_file_read(path, outLen - 1, &b);
    if(r != GDS_OK)
        return r;
    size_t n = b.len;
    while(n > 0 && (b.data[n - 1] == '\n' || b.data[n - 1] == '\r'))
        n--;
    if(memchr(b.data, '\0', n)) {
        gds_buf_free_secret(&b);
        return GDS_EINVAL;
    }
    memcpy(out, b.data, n);
    out[n] = '\0';
    gds_buf_free_secret(&b);
    return GDS_OK;
}

static void freeOut(UA_Variant **out, size_t *outN) {
    if(*out)
        UA_Array_delete(*out, *outN, &UA_TYPES[UA_TYPES_VARIANT]);
    *out = NULL;
    *outN = 0;
}

/* ---- state kept between cycles (12 §7.6) ----------------------------- */

#define MAX_POLLS 3 /* FinishRequest calls per cycle; 12 §7.6 says about 2 */

typedef struct {
    UA_Client *client;
    UA_UInt16 ns;
    UA_NodeId dir;
    const char *pki;
    const gds_buf *boot; /* the --trust certificates */
    size_t bootN;
} ptc;

/* ---- the PKI directory (Annex F.1 layout) ---------------------------- */

#define MAX_DIR_FILES 32

/* Read up to max regular files of PKI/sub; returns how many. */
static size_t load_dir(const char *pki, const char *sub, gds_buf *out, size_t max, size_t maxSize) {
    char d[GDS_MAX_PATH], f[GDS_MAX_PATH];
    if(gds_path(d, sizeof(d), "%s/%s", pki, sub) != GDS_OK)
        return 0;
    DIR *dp = opendir(d);
    if(!dp)
        return 0;
    size_t n = 0;
    const struct dirent *e;
    while(n < max && (e = readdir(dp)) != NULL) {
        if(e->d_name[0] == '.' || gds_path(f, sizeof(f), "%s/%s", d, e->d_name) != GDS_OK)
            continue;
        if(gds_file_read(f, maxSize, &out[n]) == GDS_OK)
            n++;
    }
    closedir(dp);
    return n;
}

static void free_list(gds_buf *l, size_t n) {
    for(size_t i = 0; i < n; i++)
        gds_buf_free(&l[i]);
}

/* 12 §7.8.2.8: a downloaded list replaces what was there */
static void wipe_dir(const char *pki, const char *sub) {
    char d[GDS_MAX_PATH], f[GDS_MAX_PATH];
    if(gds_path(d, sizeof(d), "%s/%s", pki, sub) != GDS_OK)
        return;
    DIR *dp = opendir(d);
    if(!dp)
        return;
    const struct dirent *e;
    while((e = readdir(dp)) != NULL)
        if(e->d_name[0] != '.' && gds_path(f, sizeof(f), "%s/%s", d, e->d_name) == GDS_OK)
            (void)unlink(f);
    closedir(dp);
}

/* open62541 keeps only the first certificate of localCertificate; put the
 * whole chain back so it is sent in OpenSecureChannel and CreateSession
 * (OPC 10000-6 §6.7.2.3 allows a chain there). */
static void send_chain(UA_Client *c, const gds_buf *sent) {
    UA_ClientConfig *cc = UA_Client_getConfig(c);
    for(size_t i = 0; c && i < cc->securityPoliciesSize; i++) {
        UA_ByteString *lc = &cc->securityPolicies[i].localCertificate;
        if(!lc->length || lc->length >= sent->len || memcmp(lc->data, sent->data, lc->length) != 0)
            continue;
        UA_ByteString full = {sent->len, sent->data}, copy;
        if(UA_ByteString_copy(&full, &copy) == UA_STATUSCODE_GOOD) {
            UA_ByteString_clear(lc);
            *lc = copy;
        }
    }
}

/* Connect to the Auditor's probe server with what is installed: our
 * certificate, and as trust the downloaded TrustedCertificates and CRLs. */
static int probe_connect(const char *pki, const char *url, const gds_buf *cert, const gds_buf *key,
                         const gds_buf *boot, size_t bootN) {
    static gds_buf trust[2 * MAX_DIR_FILES], crls[2 * MAX_DIR_FILES];
    size_t tn = 0, cn = 0;
    if(is_mutant("trustlist-not-installed")) {
        for(size_t i = 0; i < bootN && tn < MAX_DIR_FILES; i++)
            if(gds_buf_dup(boot[i].data, boot[i].len, &trust[tn]) == GDS_OK)
                tn++;
    } else {
        tn = load_dir(pki, "trusted/certs", trust, MAX_DIR_FILES, GDS_MAX_CERT_SIZE);
    }
    cn = is_mutant("ignore-crls") ? 0 : load_dir(pki, "trusted/crl", crls, MAX_DIR_FILES, GDS_MAX_CRL_SIZE);
    if(is_mutant("issuers-trusted")) {
        tn += load_dir(pki, "issuer/certs", trust + tn, MAX_DIR_FILES, GDS_MAX_CERT_SIZE);
        cn += load_dir(pki, "issuer/crl", crls + cn, MAX_DIR_FILES, GDS_MAX_CRL_SIZE);
    }
    uac_step("Connect to the probe server %s (%zu trusted, %zu CRLs)", url, tn, cn);
    int rc = 1;
    UA_Client *c = tn ? uac_new_secure(cert, key, trust, tn, crls, cn, appUri) : NULL;
    if(c) {
        send_chain(c, cert);
        UA_StatusCode r = UA_Client_connect(c, url);
        uac_info("probe connection -> %s", UA_StatusCode_name(r));
        if(r == UA_STATUSCODE_GOOD) {
            UA_Client_disconnect(c);
            rc = 0;
        }
        UA_Client_delete(c);
    }
    free_list(trust, tn);
    free_list(crls, cn);
    return rc;
}

/* Is the issued certificate one we may install? 12 §7.9.5, 4 §6.1.3 */
/* Signed by one of the trusted CAs or the bootstrap trust */
static bool signed_by_any(const ptc *x, const gds_buf *c, const gds_buf *cas, size_t n) {
    for(size_t i = 0; i < n; i++)
        if(x509_signed_by(c, &cas[i]))
            return true;
    for(size_t i = 0; i < x->bootN; i++)
        if(x509_signed_by(c, &x->boot[i]))
            return true;
    return false;
}

static bool acceptable(const ptc *x, const gds_buf *nc, const gds_buf *reqKey,
                       const UA_ByteString *issuers, size_t nIssuers) {
    if(!is_mutant("install-wrong-key") && !x509_key_matches(nc, reqKey)) {
        fprintf(stderr, "issued certificate does not match the request's key - refusing it\n");
        return false;
    }
    char uri[GDS_MAX_APPLICATION_URI];
    if(!is_mutant("install-wrong-uri") &&
       (x509_san_uri(nc, uri, sizeof(uri)) != GDS_OK || strcmp(uri, appUri) != 0)) {
        fprintf(stderr, "issued certificate names another ApplicationUri - refusing it\n");
        return false;
    }
    X509 *xc = x509_parse_cert(nc);
    bool valid = xc && X509_cmp_current_time(X509_get0_notBefore(xc)) < 0 &&
                 X509_cmp_current_time(X509_get0_notAfter(xc)) > 0;
    X509_free(xc);
    if(!is_mutant("install-expired") && !valid) {
        fprintf(stderr, "issued certificate is not valid now - refusing it\n");
        return false;
    }
    if(is_mutant("install-unverified") || is_mutant("trust-any-gds"))
        return true;
    static gds_buf cas[MAX_DIR_FILES];
    size_t n = load_dir(x->pki, "trusted/certs", cas, MAX_DIR_FILES, GDS_MAX_CERT_SIZE);
    bool chained = signed_by_any(x, nc, cas, n);
    /* Through one intermediate from IssuerCertificates (12 §7.9.5) */
    for(size_t i = 0; i < nIssuers && !chained; i++) {
        gds_buf in = {issuers[i].data, issuers[i].length};
        chained = x509_signed_by(nc, &in) && !x509_is_self_signed(&in) &&
                  signed_by_any(x, &in, cas, n);
    }
    free_list(cas, n);
    if(!chained)
        fprintf(stderr, "issued certificate is not from a trusted CA - refusing it\n");
    return chained;
}

static gds_status pki_file(const char *pki, const char *name, char *out, size_t outLen) {
    return gds_path(out, outLen, "%s/%s", pki, name);
}

/* A pending request: its RequestId and the key of its CSR. */
static bool load_pending(const char *pki, UA_NodeId *rid, gds_buf *key) {
    char ip[GDS_MAX_PATH], kp[GDS_MAX_PATH];
    gds_buf id = {0};
    if(pki_file(pki, "pending/request-id", ip, sizeof(ip)) != GDS_OK ||
       pki_file(pki, "pending/key.der", kp, sizeof(kp)) != GDS_OK ||
       gds_file_read(ip, 256, &id) != GDS_OK)
        return false;
    UA_String s = {id.len, id.data};
    bool ok = UA_NodeId_parse(rid, s) == UA_STATUSCODE_GOOD &&
              gds_file_read(kp, GDS_MAX_KEY_SIZE, key) == GDS_OK;
    gds_buf_free(&id);
    if(!ok)
        UA_NodeId_clear(rid);
    return ok;
}

static gds_status save_pending(const char *pki, const UA_NodeId *rid, const gds_buf *key) {
    char d[GDS_MAX_PATH], ip[GDS_MAX_PATH], kp[GDS_MAX_PATH];
    UA_String s = UA_STRING_NULL;
    gds_status r;
    if((r = pki_file(pki, "pending", d, sizeof(d))) != GDS_OK ||
       (r = pki_file(pki, "pending/request-id", ip, sizeof(ip))) != GDS_OK ||
       (r = pki_file(pki, "pending/key.der", kp, sizeof(kp))) != GDS_OK ||
       (r = gds_mkdirs(d, 0700)) != GDS_OK)
        return r;
    if(UA_NodeId_print(rid, &s) != UA_STATUSCODE_GOOD)
        return GDS_ENOMEM;
    /* key first: an id without its key is useless, a key without an id harmless */
    r = gds_file_write_atomic(kp, key->data, key->len, 0600);
    if(r == GDS_OK)
        r = gds_file_write_atomic(ip, s.data, s.length, 0600);
    UA_String_clear(&s);
    return r;
}

static void clear_pending(const char *pki) {
    char ip[GDS_MAX_PATH], kp[GDS_MAX_PATH];
    if(pki_file(pki, "pending/request-id", ip, sizeof(ip)) == GDS_OK)
        (void)unlink(ip);
    if(pki_file(pki, "pending/key.der", kp, sizeof(kp)) == GDS_OK)
        (void)unlink(kp);
}

/* install-in-ram: the certificate before the install, as if the new one
 * lived only in memory until a restart */
static gds_status ram_save(const char *pki) {
    char d[GDS_MAX_PATH], src[GDS_MAX_PATH], dst[GDS_MAX_PATH];
    static const char *const files[][2] = {{"own/cert.der", "ram/cert.der"},
                                           {"own/private/key.der", "ram/key.der"}};
    gds_status r = pki_file(pki, "ram", d, sizeof(d));
    if(r == GDS_OK)
        r = gds_mkdirs(d, 0700);
    for(size_t i = 0; i < 2 && r == GDS_OK; i++) {
        gds_buf b = {0};
        if((r = pki_file(pki, files[i][0], src, sizeof(src))) == GDS_OK &&
           (r = pki_file(pki, files[i][1], dst, sizeof(dst))) == GDS_OK &&
           (r = gds_file_read(src, GDS_MAX_CERT_SIZE + GDS_MAX_KEY_SIZE, &b)) == GDS_OK)
            r = gds_file_write_atomic(dst, b.data, b.len, 0600);
        gds_buf_free_secret(&b);
    }
    return r;
}

/* GDSAUDIT_ACTION=restart: this client keeps nothing in memory between
 * runs, so a restart is a no-op; the mutants lose state on it */
static int restart(const char *pki) {
    if(is_mutant("pending-forget")) {
        uac_info("MUTANT: the pending request is lost on restart");
        clear_pending(pki);
    }
    if(is_mutant("install-in-ram")) {
        static const char *const files[][2] = {{"ram/cert.der", "own/cert.der"},
                                               {"ram/key.der", "own/private/key.der"}};
        char src[GDS_MAX_PATH], dst[GDS_MAX_PATH], cp[GDS_MAX_PATH];
        for(size_t i = 0; i < 2; i++) {
            gds_buf b = {0};
            if(pki_file(pki, files[i][0], src, sizeof(src)) == GDS_OK &&
               pki_file(pki, files[i][1], dst, sizeof(dst)) == GDS_OK &&
               gds_file_read(src, GDS_MAX_CERT_SIZE + GDS_MAX_KEY_SIZE, &b) == GDS_OK &&
               gds_file_write_atomic(dst, b.data, b.len, 0600) == GDS_OK)
                uac_info("MUTANT: %s reverted on restart", files[i][1]);
            gds_buf_free_secret(&b);
        }
        if(pki_file(pki, "own/chain.der", cp, sizeof(cp)) == GDS_OK)
            (void)unlink(cp);
    }
    printf("restarted\n");
    return 0;
}

/* The intermediates of IssuerCertificates, sent after our certificate so a
 * peer that trusts only the root can build the chain (4 §6.1.3) */
static gds_status save_chain(const char *pki, const UA_ByteString *issuers, size_t n) {
    char p[GDS_MAX_PATH];
    gds_status r = pki_file(pki, "own/chain.der", p, sizeof(p));
    if(r != GDS_OK)
        return r;
    gds_buf chain = {0};
    for(size_t i = 0; i < n && r == GDS_OK && !is_mutant("install-no-chain"); i++) {
        gds_buf c = {issuers[i].data, issuers[i].length};
        if(!x509_is_self_signed(&c) && issuers[i].length <= GDS_MAX_CERT_SIZE)
            r = gds_buf_append(&chain, c.data, c.len, GDS_MAX_CHAIN_LEN * GDS_MAX_CERT_SIZE);
    }
    if(r == GDS_OK && chain.len)
        r = gds_file_write_atomic(p, chain.data, chain.len, 0644);
    else if(r == GDS_OK)
        (void)unlink(p);
    gds_buf_free(&chain);
    return r;
}

/* Our certificate as sent: the certificate, then the saved intermediates */
static gds_status presented_chain(const char *pki, const gds_buf *cert, gds_buf *out) {
    char p[GDS_MAX_PATH];
    gds_buf chain = {0};
    gds_status r = gds_buf_dup(cert->data, cert->len, out);
    if(r == GDS_OK && pki_file(pki, "own/chain.der", p, sizeof(p)) == GDS_OK &&
       gds_file_read(p, GDS_MAX_CHAIN_LEN * GDS_MAX_CERT_SIZE, &chain) == GDS_OK)
        r = gds_buf_append(out, chain.data, chain.len, (GDS_MAX_CHAIN_LEN + 1) * GDS_MAX_CERT_SIZE);
    gds_buf_free(&chain);
    return r;
}

typedef enum { FIN_ISSUED, FIN_PENDING, FIN_REJECTED, FIN_ERROR } fin_outcome;

/* Check and install what FinishRequest returned: key first, then the
 * certificate (a crash in between leaves a mismatch that the next start
 * detects in ensureOwnIdentity). */
static fin_outcome install(const ptc *x, const UA_Variant *out, size_t outN, const gds_buf *reqKey) {
    const UA_ByteString *newCert = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
    const UA_ByteString *gdsKey = uac_out_scalar(out, outN, 1, &UA_TYPES[UA_TYPES_BYTESTRING]);
    const void *issuers = NULL;
    size_t nIssuers = 0;
    if(!newCert || newCert->length == 0 || newCert->length > GDS_MAX_CERT_SIZE || outN < 3 ||
       gds_arg_array(&out[2], &UA_TYPES[UA_TYPES_BYTESTRING],
                     is_mutant("no-length-check") ? 100000 : GDS_MAX_CHAIN_LEN, &issuers,
                     &nIssuers) != UA_STATUSCODE_GOOD) {
        fail("FinishRequest result", UA_STATUSCODE_BADUNEXPECTEDERROR);
        return FIN_ERROR;
    }
    if(gdsKey && gdsKey->length > 0) {
        fprintf(stderr, "GDS returned a private key for a CSR request - refusing it\n");
        return FIN_ERROR;
    }
    gds_buf nc = {newCert->data, newCert->length};
    if(!acceptable(x, &nc, reqKey, (const UA_ByteString *)issuers, nIssuers))
        return FIN_ERROR;
    if(is_mutant("install-ignored")) {
        uac_info("MUTANT: the issued certificate is not installed");
        return FIN_ISSUED;
    }
    if(is_mutant("renew-keep-old")) {
        char cp0[GDS_MAX_PATH];
        gds_buf cur = {0};
        bool held = pki_file(x->pki, "own/cert.der", cp0, sizeof(cp0)) == GDS_OK &&
                    gds_file_read(cp0, GDS_MAX_CERT_SIZE, &cur) == GDS_OK && !x509_is_self_signed(&cur);
        gds_buf_free(&cur);
        if(held) {
            uac_info("MUTANT: the renewed certificate is not installed");
            return FIN_ISSUED;
        }
    }
    char d[512], tp[X509_THUMBPRINT_LEN], cp[GDS_MAX_PATH], kp[GDS_MAX_PATH];
    x509_describe(&nc, d, sizeof(d));
    gds_status gs;
    if(is_mutant("install-in-ram") && (gs = ram_save(x->pki)) != GDS_OK) {
        failg("keep the previous certificate", gs);
        return FIN_ERROR;
    }
    if((gs = x509_thumbprint(&nc, tp)) != GDS_OK ||
       (gs = pki_file(x->pki, "own/private/key.der", kp, sizeof(kp))) != GDS_OK ||
       (gs = pki_file(x->pki, "own/cert.der", cp, sizeof(cp))) != GDS_OK ||
       (gs = gds_file_write_atomic(kp, reqKey->data, reqKey->len, 0600)) != GDS_OK ||
       (gs = gds_file_write_atomic(cp, nc.data, nc.len, 0644)) != GDS_OK ||
       (gs = saveList(x->pki, "issuer/certs", "der", issuers, nIssuers)) != GDS_OK ||
       (gs = save_chain(x->pki, (const UA_ByteString *)issuers, nIssuers)) != GDS_OK) {
        failg("save certificate", gs);
        return FIN_ERROR;
    }
    uac_info("issued: %s", d);
    uac_info("thumbprint %s", tp);
    uac_info("installed key, certificate + %zu issuer certificate(s)", nIssuers);
    return FIN_ISSUED;
}

/* Poll FinishRequest a few times, 1 s apart (12 §7.6); a request that is
 * still pending is resumed in the next cycle. */
static fin_outcome finish(const ptc *x, const UA_NodeId *appId, const UA_NodeId *rid,
                          const gds_buf *reqKey) {
    uac_step("FinishRequest (at most %d calls in this cycle, 1 s apart)", MAX_POLLS);
    bool storm = is_mutant("poll-no-backoff");
    int polls = storm ? 10 : MAX_POLLS;
    UA_Variant fin[2], *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&fin[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&fin[1], (void *)(uintptr_t)rid, &UA_TYPES[UA_TYPES_NODEID]);
    UA_StatusCode r = UA_STATUSCODE_BADNOTHINGTODO;
    for(int i = 0; i < polls && r == UA_STATUSCODE_BADNOTHINGTODO; i++) {
        if(i > 0 && !storm)
            sleep(1);
        freeOut(&out, &outN);
        r = UA_Client_call(x->client, x->dir,
                           UA_NODEID_NUMERIC(x->ns, UA_GDSID_DIRECTORY_FINISHREQUEST), 2, fin,
                           &outN, &out);
        uac_info("FinishRequest              -> %s", UA_StatusCode_name(r));
    }
    fin_outcome o;
    if(r == UA_STATUSCODE_BADNOTHINGTODO) {
        uac_info("still pending approval: resumed in the next cycle");
        o = FIN_PENDING;
        if(is_mutant("pending-give-up")) {
            clear_pending(x->pki);
            o = FIN_REJECTED;
        }
    } else if(r != UA_STATUSCODE_GOOD) {
        uac_info("the request was not granted: %s; it is not polled again", UA_StatusCode_name(r));
        if(is_mutant("pending-stuck-invalid") && r != UA_STATUSCODE_BADREQUESTNOTALLOWED)
            uac_info("MUTANT: the pending request is kept");
        else if(!is_mutant("poll-after-reject"))
            clear_pending(x->pki);
        o = FIN_REJECTED;
    } else {
        /* the request is finished on the GDS side, installed or refused */
        o = install(x, out, outN, reqKey);
        clear_pending(x->pki);
    }
    freeOut(&out, &outN);
    return o;
}

/* The mutants read-one-chunk and no-close: a broken TrustList reader */
static UA_StatusCode mutant_read_trustlist(UA_Client *c, UA_NodeId tl, UA_TrustListDataType *out) {
    UA_NodeId mOpen, mRead, mClose;
    UA_StatusCode r = uac_find_child(c, tl, "Open", &mOpen);
    if(r == UA_STATUSCODE_GOOD)
        r = uac_find_child(c, tl, "Read", &mRead);
    if(r == UA_STATUSCODE_GOOD)
        r = uac_find_child(c, tl, "Close", &mClose);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Byte mode = 0x01;
    UA_Variant in[2], *o = NULL;
    size_t oN = 0;
    UA_Variant_setScalar(&in[0], &mode, &UA_TYPES[UA_TYPES_BYTE]);
    if((r = uac_call(c, "TrustList.Open(Read)", tl, mOpen, 1, in, 1, &oN, &o)) != UA_STATUSCODE_GOOD)
        return r;
    const UA_UInt32 *hp = uac_out_scalar(o, oN, 0, &UA_TYPES[UA_TYPES_UINT32]);
    UA_UInt32 h = hp ? *hp : 0;
    freeOut(&o, &oN);
    gds_buf acc = {0};
    UA_Int32 len = 16384;
    UA_Variant_setScalar(&in[0], &h, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[1], &len, &UA_TYPES[UA_TYPES_INT32]);
    for(int i = 0; i < 4096 && r == UA_STATUSCODE_GOOD; i++) {
        r = UA_Client_call(c, tl, mRead, 2, in, &oN, &o);
        const UA_ByteString *chunk = uac_out_scalar(o, oN, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
        size_t got = (r == UA_STATUSCODE_GOOD && chunk) ? chunk->length : 0;
        if(got && gds_buf_append(&acc, chunk->data, got, GDS_MAX_TRUSTLIST_SIZE) != GDS_OK)
            r = UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
        freeOut(&o, &oN);
        if(got == 0 || is_mutant("read-one-chunk"))
            break;
    }
    if(!is_mutant("no-close")) {
        UA_Variant_setScalar(&in[0], &h, &UA_TYPES[UA_TYPES_UINT32]);
        (void)UA_Client_call(c, tl, mClose, 1, in, &oN, &o);
        freeOut(&o, &oN);
    }
    UA_ByteString bs = {acc.len, acc.data};
    UA_TrustListDataType_init(out);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_decodeBinary(&bs, out, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
    gds_buf_free(&acc);
    return r;
}

/* TrustList.LastUpdateTime as decimal text in PKI/trustlist-updated */
static bool trustlist_unchanged(const char *pki, UA_DateTime now) {
    char p[GDS_MAX_PATH], want[32];
    gds_buf b = {0};
    if(pki_file(pki, "trustlist-updated", p, sizeof(p)) != GDS_OK ||
       gds_path(want, sizeof(want), "%lld", (long long)now) != GDS_OK ||
       gds_file_read(p, sizeof(want), &b) != GDS_OK)
        return false;
    bool same = b.len == strlen(want) && memcmp(b.data, want, b.len) == 0;
    gds_buf_free(&b);
    return same;
}

static gds_status save_trustlist_time(const char *pki, UA_DateTime t) {
    char p[GDS_MAX_PATH], v[32];
    gds_status r;
    if((r = pki_file(pki, "trustlist-updated", p, sizeof(p))) != GDS_OK ||
       (r = gds_path(v, sizeof(v), "%lld", (long long)t)) != GDS_OK)
        return r;
    return gds_file_write_atomic(p, v, strlen(v), 0644);
}

/* 4 §6.1.3: the GDS certificate must name the ApplicationUri the GDS
 * describes itself with; open62541 checks only the chain, so the server
 * certificate is recorded where the client verifies it. */
static UA_ByteString gdsCert;
static UA_StatusCode (*origVerify)(UA_CertificateGroup *, const UA_ByteString *);

static UA_StatusCode record_verify(UA_CertificateGroup *cg, const UA_ByteString *cert) {
    UA_ByteString_clear(&gdsCert);
    if(UA_ByteString_copy(cert, &gdsCert) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    return origVerify(cg, cert);
}

static bool gds_uri_matches(UA_Client *c) {
    UA_ApplicationDescription d;
    if(!gdsCert.length ||
       UA_Client_getConnectionAttribute_scalar(c, UA_QUALIFIEDNAME(0, "serverDescription"),
                                               &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION],
                                               &d) != UA_STATUSCODE_GOOD)
        return false;
    return UA_CertificateUtils_verifyApplicationUri(&gdsCert, &d.applicationUri) ==
           UA_STATUSCODE_GOOD;
}

/* prefer-deprecated: open62541 leaves Basic256 out of the client unless
 * built with UA_INCLUDE_INSECURE_POLICIES, so the mutant adds it itself. */
static UA_Client *deprecated_client(const gds_buf *cert, const gds_buf *key, const gds_buf *trust,
                                    size_t trustN, const gds_buf *crls, size_t crlN) {
    UA_Client *c = uac_new_secure_mode(cert, key, trust, trustN, crls, crlN, appUri, POLICY_BASIC256,
                                       UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);
    if(!c)
        return NULL;
    UA_ClientConfig *cc = UA_Client_getConfig(c);
    UA_SecurityPolicy *sp = (UA_SecurityPolicy *)realloc(
        cc->securityPolicies, (cc->securityPoliciesSize + 1) * sizeof(UA_SecurityPolicy));
    if(!sp) {
        UA_Client_delete(c);
        return NULL;
    }
    cc->securityPolicies = sp;
    UA_ByteString uc = {cert->len, cert->data}, uk = {key->len, key->data};
    if(UA_SecurityPolicy_Basic256(&sp[cc->securityPoliciesSize], uc, uk, cc->logging) !=
       UA_STATUSCODE_GOOD) {
        UA_Client_delete(c);
        return NULL;
    }
    cc->securityPoliciesSize++;
    return c;
}

/* The connection to the GDS; the trust mutants weaken it on purpose. */
static UA_Client *gds_client(const gds_buf *cert, const gds_buf *key, const gds_buf *trust,
                             size_t trustN, const gds_buf *crls, size_t crlN) {
    UA_Client *c;
    if(is_mutant("use-sign-only"))
        c = uac_new_secure_mode(cert, key, trust, trustN, crls, crlN, appUri, POLICY_RSAPSS,
                                UA_MESSAGESECURITYMODE_SIGN);
    else if(is_mutant("prefer-deprecated"))
        c = deprecated_client(cert, key, trust, trustN, crls, crlN);
    else
        c = uac_new_secure(cert, key, trust, trustN, crls,
                           is_mutant("ignore-gds-crl") ? 0 : crlN, appUri);
    if(c && (is_mutant("send-password-untrusted") || is_mutant("trust-any-gds") ||
             is_mutant("accept-expired-gds"))) {
        UA_ClientConfig *cc = UA_Client_getConfig(c);
        cc->certificateVerification.clear(&cc->certificateVerification);
        UA_CertificateGroup_AcceptAll(&cc->certificateVerification);
    }
    if(c)
        send_chain(c, cert);
    if(c && is_mutant("no-call-timeout"))
        UA_Client_getConfig(c)->timeout = 600000; /* MUTANT: wait 10 minutes for any answer */
    if(c) {
        UA_ClientConfig *cc = UA_Client_getConfig(c);
        origVerify = cc->certificateVerification.verifyCertificate;
        cc->certificateVerification.verifyCertificate = record_verify;
    }
    return c;
}

/* What main holds, freed at exit whichever return it took */
static struct {
    gds_buf *cert, *key, *newKey, *pendKey, *trust, *crls, *sent;
    UA_Client **client;
} held;

static void free_held(void) {
    if(!held.cert)
        return;
    if(held.client && *held.client) {
        UA_Client_delete(*held.client);
        *held.client = NULL;
    }
    gds_buf_free(held.cert);
    gds_buf_free(held.sent);
    gds_buf_free_secret(held.key);
    gds_buf_free_secret(held.newKey);
    gds_buf_free_secret(held.pendKey);
    for(size_t i = 0; i < MAX_TRUST; i++) {
        gds_buf_free(&held.trust[i]);
        gds_buf_free(&held.crls[i]);
    }
}

/* Self-test main: one linear script of steps, kept in one place on purpose. */
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
int main(int argc, char **argv) {
    const char *gds = "opc.tcp://localhost:4850";
    const char *pki = "./pki-pull";
    const char *user = NULL, *passwordArg = NULL, *passwordFile = NULL;
    const char *trustFiles[MAX_TRUST], *crlFiles[MAX_TRUST];
    size_t trustN = 0, crlN = 0;
    long pollSeconds = 60;
    char password[MAX_PASSWORD] = "";
    const char *discoveryUrl = NULL;
    bool fromEnv = false;

    for(int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if(!strcmp(a, "--from-env")) {
            const char *e;
            fromEnv = true;
            if((e = getenv("GDSAUDIT_GDS_URL"))) gds = e;
            if((e = getenv("GDSAUDIT_CLIENT_DIR"))) pki = e;
            if((e = getenv("GDSAUDIT_GDS_USER"))) user = e;
            if((e = getenv("GDSAUDIT_GDS_PASSWORD_FILE"))) passwordFile = e;
            if((e = getenv("GDSAUDIT_GDS_CA")) && trustN < MAX_TRUST) trustFiles[trustN++] = e;
            if((e = getenv("GDSAUDIT_GDS_CRL")) && crlN < MAX_TRUST) crlFiles[crlN++] = e;
            continue;
        }
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if(!v)
            goto usage;
        i++;
        if(!strcmp(a, "--gds")) gds = v;
        else if(!strcmp(a, "--pki")) pki = v;
        else if(!strcmp(a, "--user")) user = v;
        else if(!strcmp(a, "--password")) passwordArg = v;
        else if(!strcmp(a, "--password-file")) passwordFile = v;
        else if(!strcmp(a, "--app-uri") && strlen(v) < GDS_MAX_APPLICATION_URI) appUri = v;
        else if(!strcmp(a, "--trust") && trustN < MAX_TRUST) trustFiles[trustN++] = v;
        else if(!strcmp(a, "--crl") && crlN < MAX_TRUST) crlFiles[crlN++] = v;
        else if(!strcmp(a, "--poll-seconds") && gds_parse_long(v, 1, 3600, &pollSeconds)) {}
        else if(!strcmp(a, "--discovery-url") && strlen(v) < PTC_MAX_URL) discoveryUrl = v;
        else if(!strcmp(a, "--break") && known_mutant(v)) mutant = v;
        else goto usage;
    }
    (void)pollSeconds; /* kept for old scripts: polling is per cycle now (MAX_POLLS) */
    if(mutant && !is_loopback(gds)) {
        fprintf(stderr, "refusing --break %s against %s: mutants only talk to a GDS on this host\n",
                mutant, gds);
        return 2;
    }
    if(mutant)
        fprintf(stderr, "MUTANT %s: this client is wrong on purpose\n", mutant);
    if(trustN == 0) {
        fprintf(stderr, "refusing to run without --trust: the GDS must be trusted explicitly\n");
        return 1;
    }
    if(passwordFile) {
        gds_status s = readPasswordFile(passwordFile, password, sizeof(password));
        if(s != GDS_OK)
            return failg("read --password-file", s);
    } else if(passwordArg) {
        fprintf(stderr, "warning: --password is visible to other local users; prefer --password-file\n");
        if(gds_path(password, sizeof(password), "%s", passwordArg) != GDS_OK)
            return failg("--password", GDS_ETOOBIG);
    }
    if(user && !password[0]) {
        fprintf(stderr, "--user needs --password-file or --password\n");
        return 2;
    }

    {
        const char *act = fromEnv ? getenv("GDSAUDIT_ACTION") : NULL;
        if(act && !strcmp(act, "restart"))
            return restart(pki);
    }
    printf("OpenGDS pull test client (Auditor self-test target)  app=%s  gds=%s\n", appUri, gds);

    uac_step("Load identity and the explicitly trusted GDS issuer");
    /* static, so that the exit handler can free them on the early error
     * returns as well (LeakSanitizer turns a leak into a crash exit) */
    static gds_buf cert, key, newKey, pendKey, trust[MAX_TRUST], crls[MAX_TRUST], sent;
    held.cert = &cert;
    held.key = &key;
    held.newKey = &newKey;
    held.pendKey = &pendKey;
    held.trust = trust;
    held.crls = crls;
    held.sent = &sent;
    (void)atexit(free_held);
    gds_status gs = ensureOwnIdentity(pki, &cert, &key);
    if(gs != GDS_OK)
        return failg("own identity", gs);
    if((gs = presented_chain(pki, &cert, &sent)) != GDS_OK)
        return failg("own certificate chain", gs);
    for(size_t i = 0; i < trustN; i++)
        if((gs = gds_file_read(trustFiles[i], GDS_MAX_CERT_SIZE, &trust[i])) != GDS_OK)
            return failg(trustFiles[i], gs);
    for(size_t i = 0; i < crlN; i++)
        if((gs = gds_file_read(crlFiles[i], GDS_MAX_CRL_SIZE, &crls[i])) != GDS_OK)
            return failg(crlFiles[i], gs);
    {
        char d[512];
        x509_describe(&cert, d, sizeof(d));
        uac_info("own: %s", d);
    }
    const char *action = fromEnv ? getenv("GDSAUDIT_ACTION") : NULL;
    if(action && !strcmp(action, "probe")) {
        const char *url = getenv("GDSAUDIT_PROBE_URL");
        if(!url || (mutant && !is_loopback(url)))
            return 2;
        int rc = probe_connect(pki, url, &sent, &key, trust, trustN);
        free_list(trust, trustN);
        free_list(crls, crlN);
        gds_buf_free(&cert);
        gds_buf_free_secret(&key);
        return rc;
    }

    /* Annex G.1: with a certificate from the GDS the client is its own
     * ApplicationSelfAdmin (Anonymous); credentials only for the first one,
     * or when the GDS offers no Anonymous token. */
    bool selfAdmin = !x509_is_self_signed(&cert) && !is_mutant("renew-with-password");
    static UA_Client *client;
    held.client = &client;
    UA_StatusCode r = UA_STATUSCODE_BADINTERNALERROR;
    for(int attempt = 0; attempt < 2 && r != UA_STATUSCODE_GOOD; attempt++) {
        bool anonymous = attempt == 0 ? (selfAdmin || !user) : false;
        if(is_mutant("send-password-untrusted") && user)
            anonymous = false;
        if(attempt == 1 && (!user || !selfAdmin))
            break;
        uac_step("Connect to the GDS (SignAndEncrypt, %s)",
                 anonymous ? "application identity" : "user credentials");
        if(client)
            UA_Client_delete(client);
        client = gds_client(&sent, &key, trust, trustN, crls, crlN);
        if(!client)
            return 1;
        UA_Client_getConfig(client)->customDataTypes = &gdsTypes;
        r = anonymous ? UA_Client_connect(client, gds)
                      : UA_Client_connectUsername(client, gds, user, password);
    }
    OPENSSL_cleanse(password, sizeof(password));
    if(r != UA_STATUSCODE_GOOD)
        return fail("connect", r);
    if(!is_mutant("no-gds-uri-check") && !gds_uri_matches(client)) {
        fprintf(stderr, "the GDS certificate does not name the GDS ApplicationUri - not trusted\n");
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        client = NULL;
        return 1;
    }
    uac_info("connected");
    if(is_mutant("reconnect-storm")) {
        /* MUTANT: when the GDS closes the session, reconnect at once, again and again */
        for(int i = 0; i < 6; i++) {
            UA_Variant fa;
            UA_String u = UA_STRING((char *)(uintptr_t)appUri);
            size_t fN = 0;
            UA_Variant *fo = NULL;
            UA_Variant_setScalar(&fa, &u, &UA_TYPES[UA_TYPES_STRING]);
            UA_UInt16 nsi = 0;
            if(UA_Client_getNamespaceIndex(client, UA_STRING(GDS_NS_URI), &nsi) == UA_STATUSCODE_GOOD)
                r = uac_call(client, "FindApplications", UA_NODEID_NUMERIC(nsi, UA_GDSID_DIRECTORY),
                               UA_NODEID_NUMERIC(nsi, UA_GDSID_DIRECTORY_FINDAPPLICATIONS), 1, &fa, 1,
                               &fN, &fo);
            freeOut(&fo, &fN);
            uac_info("MUTANT: reconnect at once (%s)", UA_StatusCode_name(r));
            UA_Client_disconnect(client);
            r = UA_Client_connect(client, gds); /* as ApplicationSelfAdmin */
            if(r != UA_STATUSCODE_GOOD)
                return fail("reconnect", r);
        }
    }

    /* Bind the GDS namespace index at runtime */
    UA_UInt16 ns = 0;
    r = UA_Client_getNamespaceIndex(client, UA_STRING(GDS_NS_URI), &ns);
    if(r != UA_STATUSCODE_GOOD)
        return fail("GDS namespace not found on server", r);
    for(size_t i = 0; i < UA_TYPES_GDS_COUNT; i++) {
        UA_TYPES_GDS[i].typeId.namespaceIndex = ns;
        UA_TYPES_GDS[i].binaryEncodingId.namespaceIndex = ns;
    }
    uac_info("GDS namespace index = %u", ns);
    const UA_NodeId dir = UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY);
    const UA_DataType *recType = &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE];
    ptc x = {client, ns, dir, pki, trust, trustN};

    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_Variant in[4];

    UA_NodeId appId = UA_NODEID_NULL;
    UA_String uri = UA_STRING((char *)(uintptr_t)appUri);
    if(!is_mutant("register-every-run")) {
        uac_step("FindApplications(\"%s\")", appUri);
        UA_Variant_setScalar(&in[0], &uri, &UA_TYPES[UA_TYPES_STRING]);
        r = uac_call(client, "FindApplications", dir,
                     UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_FINDAPPLICATIONS), 1, in, 1, &outN, &out);
        if(r != UA_STATUSCODE_GOOD)
            return fail("FindApplications", r);
        const void *recs = NULL;
        size_t found = 0;
        r = gds_arg_array(&out[0], recType, GDS_MAX_QUERY_RECORDS, &recs, &found);
        if(r != UA_STATUSCODE_GOOD)
            return fail("FindApplications result", r);
        if(found > 1) {
            fprintf(stderr, "More than one record for this ApplicationUri - a DiscoveryAdmin must resolve this\n");
            return 1;
        }
        if(found == 1) {
            const UA_ApplicationRecordDataType *rec = recs;
            if(UA_NodeId_copy(&rec->applicationId, &appId) != UA_STATUSCODE_GOOD)
                return fail("copy", UA_STATUSCODE_BADOUTOFMEMORY);
            uac_info("already registered");
        }
        freeOut(&out, &outN);
    }

    if(UA_NodeId_isNull(&appId)) {
        uac_step("RegisterApplication");
        UA_ApplicationRecordDataType rec;
        UA_ApplicationRecordDataType_init(&rec);
        rec.applicationUri = is_mutant("register-wrong-uri") ? UA_STRING("urn:opengds:test:not-this-client") : uri;
        UA_String du = UA_STRING((char *)(uintptr_t)(discoveryUrl ? discoveryUrl : ""));
        rec.applicationType = discoveryUrl ? UA_APPLICATIONTYPE_CLIENTANDSERVER : UA_APPLICATIONTYPE_CLIENT;
        if(is_mutant("register-wrong-type"))
            rec.applicationType = UA_APPLICATIONTYPE_SERVER;
        if(discoveryUrl) {
            rec.discoveryUrls = &du;
            rec.discoveryUrlsSize = 1;
        }
        UA_LocalizedText name = UA_LOCALIZEDTEXT("en", (char *)(uintptr_t)appName);
        rec.applicationNames = &name;
        rec.applicationNamesSize = 1;
        rec.productUri = UA_STRING("urn:opengds:test");
        UA_Variant_setScalar(&in[0], &rec, recType);
        r = uac_call(client, "RegisterApplication", dir,
                     UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_REGISTERAPPLICATION), 1, in, 1,
                     &outN, &out);
        if(r != UA_STATUSCODE_GOOD)
            return fail("RegisterApplication", r);
        const UA_NodeId *id = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_NODEID]);
        if(!id || UA_NodeId_isNull(id) || UA_NodeId_copy(id, &appId) != UA_STATUSCODE_GOOD)
            return fail("RegisterApplication result", UA_STATUSCODE_BADUNEXPECTEDERROR);
        freeOut(&out, &outN);
    }
    {
        UA_String s = UA_STRING_NULL;
        if(UA_NodeId_print(&appId, &s) == UA_STATUSCODE_GOOD)
            uac_info("ApplicationId = %.*s", (int)s.length, s.data);
        UA_String_clear(&s);
    }

    uac_step("GetCertificateGroups");
    UA_Variant_setScalar(&in[0], &appId, &UA_TYPES[UA_TYPES_NODEID]);
    r = uac_call(client, "GetCertificateGroups", dir,
                 UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_GETCERTIFICATEGROUPS), 1, in, 1, &outN,
                 &out);
    if(r != UA_STATUSCODE_GOOD)
        return fail("GetCertificateGroups", r);
    UA_NodeId groupId;
    {
        const void *groups = NULL;
        size_t nGroups = 0;
        r = gds_arg_array(&out[0], &UA_TYPES[UA_TYPES_NODEID], GDS_MAX_ARRAY_FIELD, &groups,
                          &nGroups);
        if(r != UA_STATUSCODE_GOOD || nGroups == 0)
            return fail("GetCertificateGroups result", r ? r : UA_STATUSCODE_BADNOTFOUND);
        if(UA_NodeId_copy(&((const UA_NodeId *)groups)[0], &groupId) != UA_STATUSCODE_GOOD)
            return fail("copy", UA_STATUSCODE_BADOUTOFMEMORY);
        uac_info("%zu group(s); using the first (DefaultApplicationGroup)", nGroups);
    }
    freeOut(&out, &outN);

    /* 12 §7.6: a request still pending from an earlier cycle comes first */
    UA_NodeId requestId = UA_NODEID_NULL;
    if(!is_mutant("pending-new-csr") && load_pending(pki, &requestId, &pendKey)) {
        uac_info("resuming the pending request from an earlier cycle");
        if(finish(&x, &appId, &requestId, &pendKey) == FIN_ERROR)
            return 1;
    } else {
        uac_step("GetCertificateStatus");
        UA_NodeId certType = UA_NODEID_NUMERIC(0, is_mutant("csr-unlisted-type")
                                                      ? UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE
                                                      : UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
        UA_Variant_setScalar(&in[0], &appId, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[1], &groupId, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[2], &certType, &UA_TYPES[UA_TYPES_NODEID]);
        r = uac_call(client, "GetCertificateStatus", dir,
                     UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_GETCERTIFICATESTATUS), 3, in, 1, &outN,
                     &out);
        if(r != UA_STATUSCODE_GOOD)
            return fail("GetCertificateStatus", r);
        const UA_Boolean *upd = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BOOLEAN]);
        if(!upd)
            return fail("GetCertificateStatus result", UA_STATUSCODE_BADUNEXPECTEDERROR);
        UA_Boolean updateRequired = *upd;
        freeOut(&out, &outN);
        uac_info("updateRequired = %s", updateRequired ? "true" : "false");
        if(is_mutant("ignore-update-required"))
            updateRequired = false;
        if(is_mutant("renew-always"))
            updateRequired = true;

        if(updateRequired && is_mutant("use-newkeypair")) {
            uac_step("StartNewKeyPairRequest (MUTANT: the GDS would make our private key)");
            UA_Variant nk[7];
            UA_String subj = UA_STRING("CN=OpenGDS Pull Test Client"), fmt = UA_STRING("PFX");
            UA_String none = UA_STRING_NULL;
            for(size_t i = 0; i < 3; i++)
                nk[i] = in[i];
            UA_Variant_setScalar(&nk[3], &subj, &UA_TYPES[UA_TYPES_STRING]);
            UA_Variant_setArray(&nk[4], NULL, 0, &UA_TYPES[UA_TYPES_STRING]);
            UA_Variant_setScalar(&nk[5], &fmt, &UA_TYPES[UA_TYPES_STRING]);
            UA_Variant_setScalar(&nk[6], &none, &UA_TYPES[UA_TYPES_STRING]);
            r = uac_call(client, "StartNewKeyPairRequest", dir,
                         UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_STARTNEWKEYPAIRREQUEST), 7, nk, 1,
                         &outN, &out);
            return fail("StartNewKeyPairRequest", r ? r : UA_STATUSCODE_BADUNEXPECTEDERROR);
        }
        if(updateRequired) {
            uac_step("StartSigningRequest (CSR signed with a new key of ours; the key never leaves us)");
            char dnsName[PTC_MAX_URL] = "localhost";
            if(discoveryUrl)
                url_host(discoveryUrl, dnsName, sizeof(dnsName));
            gds_buf csr = {0};
            if((gs = make_request(&key, dnsName, &newKey, &csr)) != GDS_OK)
                return failg("CSR creation", gs);
            uac_info("CSR: %zu bytes%s", csr.len, newKey.len ? ", new key" : "");
            UA_ByteString csrBs = {csr.len, csr.data};
            UA_Variant_setScalar(&in[3], &csrBs, &UA_TYPES[UA_TYPES_BYTESTRING]);
            /* A good client gives up on Bad_CertificateUriInvalid; the storm mutant does not */
            int attempts = is_mutant("csr-retry-storm") ? 10 : 1;
            for(int a = 0; a < attempts; a++) {
                freeOut(&out, &outN);
                r = uac_call(client, "StartSigningRequest", dir,
                             UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST), 4, in, 1,
                             &outN, &out);
                if(r != UA_STATUSCODE_BADCERTIFICATEURIINVALID)
                    break;
            }
            gds_buf_free(&csr);
            if(r != UA_STATUSCODE_GOOD)
                return fail("StartSigningRequest", r);
            const UA_NodeId *rid = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_NODEID]);
            if(!rid || UA_NodeId_copy(rid, &requestId) != UA_STATUSCODE_GOOD)
                return fail("StartSigningRequest result", UA_STATUSCODE_BADUNEXPECTEDERROR);
            freeOut(&out, &outN);
            const gds_buf *reqKey = newKey.len ? &newKey : &key;
            if((gs = save_pending(pki, &requestId, reqKey)) != GDS_OK)
                return failg("save the pending request", gs);
            if(finish(&x, &appId, &requestId, reqKey) == FIN_ERROR)
                return 1;
        }
    }

    uac_step("GetTrustList -> read it through the standard FileType methods");
    UA_Variant_setScalar(&in[0], &appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &groupId, &UA_TYPES[UA_TYPES_NODEID]);
    r = uac_call(client, "GetTrustList", dir, UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_GETTRUSTLIST),
                 2, in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return fail("GetTrustList", r);
    UA_NodeId tlId;
    const UA_NodeId *tlp = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_NODEID]);
    if(!tlp || UA_NodeId_copy(tlp, &tlId) != UA_STATUSCODE_GOOD)
        return fail("GetTrustList result", UA_STATUSCODE_BADUNEXPECTEDERROR);
    freeOut(&out, &outN);
    /* 12 §7.6: download only when LastUpdateTime changed */
    UA_DateTime updated = 0;
    {
        UA_NodeId lut;
        UA_Variant v;
        UA_Variant_init(&v);
        if(uac_find_child(client, tlId, "LastUpdateTime", &lut) == UA_STATUSCODE_GOOD &&
           UA_Client_readValueAttribute(client, lut, &v) == UA_STATUSCODE_GOOD &&
           UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_DATETIME]))
            updated = *(const UA_DateTime *)v.data;
        UA_Variant_clear(&v);
        UA_NodeId_clear(&lut);
    }
    if(updated && trustlist_unchanged(pki, updated) && !is_mutant("always-download")) {
        uac_info("trust list unchanged since the last download: skipped");
    } else {
        UA_TrustListDataType tl;
        if(is_mutant("install-partial-trustlist")) {
            uac_info("MUTANT: the old trust list is dropped before the download");
            wipe_dir(pki, "trusted/certs");
            wipe_dir(pki, "trusted/crl");
        }
        r = (is_mutant("read-one-chunk") || is_mutant("no-close") || is_mutant("no-length-check"))
                ? mutant_read_trustlist(client, tlId, &tl)
                : uac_read_trustlist(client, tlId, &tl);
        if(r != UA_STATUSCODE_GOOD && is_mutant("parse-garbage")) {
            uac_info("MUTANT: the old trust list is dropped before the new one parsed");
            wipe_dir(pki, "trusted/certs");
            wipe_dir(pki, "trusted/crl");
        }
        if(r != UA_STATUSCODE_GOOD)
            return fail("TrustList read", r);
        uac_info("trusted certs=%zu trusted CRLs=%zu issuer certs=%zu issuer CRLs=%zu",
                 tl.trustedCertificatesSize, tl.trustedCrlsSize, tl.issuerCertificatesSize,
                 tl.issuerCrlsSize);
        if(!is_mutant("trustlist-merge")) {
            wipe_dir(pki, "trusted/certs");
            wipe_dir(pki, "trusted/crl");
            wipe_dir(pki, "issuer/certs");
            wipe_dir(pki, "issuer/crl");
        }
        if((gs = saveList(pki, "trusted/certs", "der", tl.trustedCertificates, tl.trustedCertificatesSize)) != GDS_OK ||
           (gs = saveList(pki, "trusted/crl", "crl", tl.trustedCrls, tl.trustedCrlsSize)) != GDS_OK ||
           (gs = saveList(pki, "issuer/certs", "der", tl.issuerCertificates, tl.issuerCertificatesSize)) != GDS_OK ||
           (gs = saveList(pki, "issuer/crl", "crl", tl.issuerCrls, tl.issuerCrlsSize)) != GDS_OK ||
           (updated && (gs = save_trustlist_time(pki, updated)) != GDS_OK))
            return failg("save trust list", gs);
        UA_TrustListDataType_clear(&tl);
    }

    if(is_mutant("keep-session-open")) {
        printf("\nMUTANT: leaving without CloseSession\n");
        fflush(stdout);
        _exit(0);
    }
    uac_step("Disconnect (Part 12 §6.3: stay connected to the GDS as briefly as possible)");
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    client = NULL;
    UA_NodeId_clear(&appId);
    UA_NodeId_clear(&groupId);
    UA_NodeId_clear(&tlId);
    UA_NodeId_clear(&requestId);
    for(size_t i = 0; i < trustN; i++)
        gds_buf_free(&trust[i]);
    for(size_t i = 0; i < crlN; i++)
        gds_buf_free(&crls[i]);
    gds_buf_free(&cert);
    gds_buf_free_secret(&key);
    gds_buf_free_secret(&newKey);
    gds_buf_free_secret(&pendKey);
    printf("\nPULL WORKFLOW COMPLETE - PKI written to %s\n", pki);
    return 0;

usage:
    fprintf(stderr,
            "usage: %s --gds URL --trust gds-ca.der [--crl x.crl] [--user U\n"
            "          (--password-file F | --password P)] [--pki DIR] [--app-uri URI]\n"
            "          [--discovery-url URL]\n"
            "       %s --from-env [--break MUTANT] [--discovery-url URL]\n",
            argv[0], argv[0]);
    return 2;
}
