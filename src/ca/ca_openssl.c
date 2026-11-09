/* OpenGDS - the built-in CA backend: one issuing CA per key algorithm (RSA
 * in the directory, ECC P-256 and P-384 in subdirectories; docs/ca.md),
 * OpenSSL 3.5 (decision G2). Runs inside opengds-signer (G1), or
 * in process for tests and embedding.
 *
 * Certificate contents (decision G5; docs/ca.md lists each field and its
 * clause): subject CN from the record's first ApplicationName, O from the
 * configuration, subjectAltName URI = ApplicationUri plus the DiscoveryUrl
 * hosts. From the CSR only the public key is used, after its signature
 * verifies.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "ca.h"
#include "ca_internal.h"
#include "ca_x509.h"
#include "common/limits.h"
#include "common/banned.h"

#define CLOCK_SKEW_SECONDS 300 /* notBefore in the past: verifiers' clocks drift */
#define DAY_SECONDS 86400

void gds_ca_config_init(gds_ca_config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->caSubjectCN = "OpenGDS CA";
    cfg->caKeyBits = 3072;
    cfg->caLifetimeDays = 3650;
    cfg->leafLifetimeDays = 365;
    cfg->crlLifetimeDays = 30;
    cfg->pluginFd = -1;
}

/* ---- key and certificate files ---- */

static int pass_cb(char *buf, int size, int rwflag, void *u) {
    (void)rwflag;
    const gds_buf *pass = u;
    /* No passphrase configured: fail instead of OpenSSL's terminal prompt */
    if(!pass || !pass->data || pass->len == 0 || pass->len > (size_t)size)
        return -1;
    memcpy(buf, pass->data, pass->len);
    return (int)pass->len;
}

static gds_status load_key(const char *path, const gds_buf *pass, EVP_PKEY **out) {
    gds_buf b = {0};
    gds_status r = gds_file_read(path, GDS_MAX_KEY_SIZE, &b);
    if(r != GDS_OK)
        return r;
    BIO *bio = BIO_new_mem_buf(b.data, (int)b.len);
    *out = bio ? PEM_read_bio_PrivateKey(bio, NULL, pass_cb, (void *)(uintptr_t)pass) : NULL;
    BIO_free(bio);
    gds_buf_free_secret(&b);
    return *out ? GDS_OK : GDS_ECRYPTO;
}

/* Encrypted PKCS#8 (decision G6): PBES2, PBKDF2-HMAC-SHA256 with
 * KEY_PBKDF2_ITER iterations, AES-256-CBC. */
#define KEY_PBKDF2_ITER 600000

static gds_status save_key(const char *path, EVP_PKEY *key, const gds_buf *pass) {
    PKCS8_PRIV_KEY_INFO *p8inf = EVP_PKEY2PKCS8(key);
    X509_SIG *p8 = p8inf ? PKCS8_encrypt_ex(-1, EVP_aes_256_cbc(), (const char *)pass->data,
                                            (int)pass->len, NULL, 0, KEY_PBKDF2_ITER, p8inf,
                                            NULL, NULL)
                         : NULL;
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    BIO *bio = p8 ? BIO_new(BIO_s_secmem()) : NULL;
    gds_status r = GDS_ECRYPTO;
    if(bio && PEM_write_bio_PKCS8(bio, p8) == 1) {
        char *data = NULL;
        long len = BIO_get_mem_data(bio, &data);
        if(len > 0)
            r = gds_file_write_atomic(path, data, (size_t)len, 0600);
    }
    BIO_free(bio); /* secure-heap BIO: cleared on free */
    X509_SIG_free(p8);
    return r;
}

static gds_status load_cert(const char *path, X509 **out) {
    gds_buf b = {0};
    gds_status r = gds_file_read(path, GDS_MAX_CERT_SIZE, &b);
    if(r != GDS_OK)
        return r;
    const unsigned char *p = b.data;
    *out = d2i_X509(NULL, &p, (long)b.len);
    if(*out && p != b.data + b.len) { /* trailing bytes */
        X509_free(*out);
        *out = NULL;
    }
    gds_buf_free(&b);
    return *out ? GDS_OK : GDS_ECRYPTO;
}

static gds_status save_cert(const char *path, X509 *x) {
    gds_buf der;
    gds_status r = cax_cert_der(x, &der);
    if(r == GDS_OK)
        r = gds_file_write_atomic(path, der.data, der.len, 0644);
    gds_buf_free(&der);
    return r;
}

/* Self-signed CA certificate for key (CA profile, RFC 5280 §4.2.1.9/§4.2.1.3:
 * basicConstraints cA critical, keyUsage keyCertSign and cRLSign). */
static gds_status make_ca_cert(const gds_ca_config *cfg, const ossl_ca *c, const char *cnText,
                               X509 **out) {
    *out = NULL;
    EVP_PKEY *key = c->key;
    X509 *x = X509_new();
    X509_NAME *name = NULL;
    UA_String cn = UA_STRING((char *)(uintptr_t)cnText);
    int64_t now = (int64_t)time(NULL);
    gds_status r = x ? GDS_OK : GDS_ENOMEM;
    if(r == GDS_OK && X509_set_version(x, X509_VERSION_3) != 1)
        r = GDS_ECRYPTO;
    if(r == GDS_OK)
        r = cax_set_random_serial(x, NULL);
    if(r == GDS_OK)
        r = cax_set_validity(x, now - CLOCK_SKEW_SECONDS,
                             now + (int64_t)cfg->caLifetimeDays * DAY_SECONDS);
    if(r == GDS_OK)
        r = cax_make_name(&cn, cfg->organization, &name);
    if(r == GDS_OK && (X509_set_subject_name(x, name) != 1 || X509_set_issuer_name(x, name) != 1 ||
                       X509_set_pubkey(x, key) != 1))
        r = GDS_ECRYPTO;
    if(r == GDS_OK)
        r = cax_add_basic_constraints(x, true);
    if(r == GDS_OK)
        r = cax_add_key_usage(x, CAX_KU_KEY_CERT_SIGN | CAX_KU_CRL_SIGN | CAX_KU_DIGITAL_SIGNATURE);
    if(r == GDS_OK)
        r = cax_add_key_ids(x, NULL);
    if(r == GDS_OK && X509_sign(x, key, c->md) <= 0)
        r = GDS_ECRYPTO;
    X509_NAME_free(name);
    if(r != GDS_OK) {
        X509_free(x);
        return r;
    }
    *out = x;
    return GDS_OK;
}

static bool file_exists(const char *path) {
    struct stat sb;
    return stat(path, &sb) == 0;
}

/* Load the CA, or create it. A key without a certificate (a crash between
 * the two writes) gets a new certificate; a certificate without its key is
 * refused rather than silently replaced. */
/* A new key for the issuer: RSA caKeyBits, or the issuer's curve. */
static gds_status new_ca_key(const gds_ca_config *cfg, gds_ca_issuer issuer, EVP_PKEY **out) {
    if(issuer == GDS_CA_ISSUER_RSA) {
        if(cfg->caKeyBits < 2048 || cfg->caKeyBits > 4096)
            return GDS_EINVAL; /* RsaSha256ApplicationCertificateType range (OPC 10000-12) */
        *out = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)cfg->caKeyBits);
    } else {
        *out = EVP_PKEY_Q_keygen(NULL, NULL, "EC", issuer == GDS_CA_ISSUER_P256 ? "P-256" : "P-384");
    }
    return *out ? GDS_OK : GDS_ECRYPTO;
}

/* Does the key fit the issuer (a CA key file swapped for another kind)? */
static bool key_fits(EVP_PKEY *k, gds_ca_issuer issuer) {
    if(issuer == GDS_CA_ISSUER_RSA)
        return EVP_PKEY_is_a(k, "RSA");
    char group[32] = {0};
    size_t len = 0;
    if(!EVP_PKEY_is_a(k, "EC") ||
       EVP_PKEY_get_group_name(k, group, sizeof(group), &len) != 1)
        return false;
    return strcmp(group, issuer == GDS_CA_ISSUER_P256 ? "prime256v1" : "secp384r1") == 0;
}

static gds_status load_or_create(ossl_ca *c, const gds_ca_config *cfg, const char *dir,
                                 const char *cn) {
    char keyPath[GDS_MAX_PATH], certPath[GDS_MAX_PATH];
    gds_status r = gds_path(keyPath, sizeof(keyPath), "%s/ca.key.pem", dir);
    if(r == GDS_OK)
        r = gds_path(certPath, sizeof(certPath), "%s/ca.der", dir);
    if(r == GDS_OK)
        r = gds_path(c->crlPath, sizeof(c->crlPath), "%s/ca.crl", dir);
    if(r != GDS_OK)
        return r;
    bool haveKey = file_exists(keyPath), haveCert = file_exists(certPath);
    if(!haveKey && haveCert)
        return GDS_ESTATE;
    if(haveKey) {
        r = load_key(keyPath, cfg->keyPassphrase, &c->key);
        if(r == GDS_OK && !key_fits(c->key, c->issuer))
            r = GDS_ESTATE;
    } else {
        r = new_ca_key(cfg, c->issuer, &c->key);
        if(r == GDS_OK)
            r = save_key(keyPath, c->key, cfg->keyPassphrase);
    }
    if(r != GDS_OK)
        return r;
    if(haveCert) {
        r = load_cert(certPath, &c->cert);
        if(r == GDS_OK && X509_check_private_key(c->cert, c->key) != 1)
            r = GDS_ESTATE; /* certificate and key do not belong together */
    } else {
        r = make_ca_cert(cfg, c, cn, &c->cert);
        if(r == GDS_OK)
            r = save_cert(certPath, c->cert);
    }
    return r;
}

/* ---- signing ---- */

/* Parse and check a CSR: exact DER, valid self-signature (proof of
 * possession), key matching the requested CertificateType. */
/* The CSR key fits the issuer: RSA 2048..4096 for the RSA types (12
 * §7.8.4.9), the curve for the ECC types (§7.8.4.11, §7.8.4.12). */
static bool csr_key_fits(EVP_PKEY *pk, gds_ca_issuer issuer) {
    if(issuer != GDS_CA_ISSUER_RSA)
        return key_fits(pk, issuer);
    int bits = EVP_PKEY_get_bits(pk);
    return EVP_PKEY_is_a(pk, "RSA") && bits >= 2048 && bits <= 4096;
}

static gds_status check_csr(const gds_buf *csrDer, gds_ca_issuer issuer, EVP_PKEY **pkOut) {
    *pkOut = NULL;
    if(csrDer->len == 0 || csrDer->len > GDS_MAX_CSR_SIZE)
        return csrDer->len ? GDS_ETOOBIG : GDS_EINVAL;
    const unsigned char *p = csrDer->data;
    X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)csrDer->len);
    if(!req)
        return GDS_EINVAL;
    gds_status r = GDS_EINVAL;
    EVP_PKEY *pk = NULL;
    if(p != csrDer->data + csrDer->len)
        goto done; /* trailing bytes */
    pk = X509_REQ_get_pubkey(req);
    if(!pk || X509_REQ_verify(req, pk) != 1)
        goto done;
    if(csr_key_fits(pk, issuer))
        r = GDS_OK;
done:
    if(r != GDS_OK)
        EVP_PKEY_free(pk);
    else
        *pkOut = pk;
    X509_REQ_free(req);
    return r;
}

static int64_t cert_not_after(X509 *x) {
    int days = 0, secs = 0;
    if(ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(x)) != 1)
        return 0;
    return (int64_t)time(NULL) + (int64_t)days * DAY_SECONDS + secs;
}

static gds_status leaf_extensions(ossl_ca *c, X509 *x, const UA_ApplicationRecordDataType *rec) {
    /* OPC 10000-6 §6.2.2 Application Instance Certificate: end entity; RSA
     * keys digitalSignature, nonRepudiation, keyEncipherment and
     * dataEncipherment, ECC keys digitalSignature ("other keyUsage bits are
     * allowed but not recommended"); server and/or client authentication */
    bool isClient = rec->applicationType == UA_APPLICATIONTYPE_CLIENT;
    unsigned ku = c->issuer == GDS_CA_ISSUER_RSA
                      ? CAX_KU_DIGITAL_SIGNATURE | CAX_KU_NON_REPUDIATION |
                            CAX_KU_KEY_ENCIPHERMENT | CAX_KU_DATA_ENCIPHERMENT
                      : CAX_KU_DIGITAL_SIGNATURE;
    gds_status r = cax_add_basic_constraints(x, false);
    if(r == GDS_OK)
        r = cax_add_key_usage(x, ku);
    if(r == GDS_OK)
        r = cax_add_ext_key_usage(x, !isClient, true);
    if(r == GDS_OK)
        r = cax_add_key_ids(x, c->cert);
    if(r == GDS_OK)
        r = cax_add_san(x, rec);
    return r;
}

static gds_status build_leaf(ossl_ca *c, const UA_ApplicationRecordDataType *rec, EVP_PKEY *pk,
                             X509 **out, gds_ca_issued *issued) {
    *out = NULL;
    if(rec->applicationNamesSize == 0)
        return GDS_EINVAL;
    X509 *x = X509_new();
    X509_NAME *name = NULL;
    int64_t now = (int64_t)time(NULL);
    int64_t notAfter = now + (int64_t)c->leafDays * DAY_SECONDS;
    int64_t caNotAfter = cert_not_after(c->cert);
    if(caNotAfter < notAfter)
        notAfter = caNotAfter; /* never outlive the issuer */
    gds_status r = x ? GDS_OK : GDS_ENOMEM;
    if(r == GDS_OK && X509_set_version(x, X509_VERSION_3) != 1)
        r = GDS_ECRYPTO;
    if(r == GDS_OK)
        r = cax_set_random_serial(x, &issued->serial);
    if(r == GDS_OK)
        r = cax_set_validity(x, now - CLOCK_SKEW_SECONDS, notAfter);
    if(r == GDS_OK)
        r = cax_make_name(&rec->applicationNames[0].text, c->org, &name);
    if(r == GDS_OK && (X509_set_subject_name(x, name) != 1 ||
                       X509_set_issuer_name(x, X509_get_subject_name(c->cert)) != 1 ||
                       X509_set_pubkey(x, pk) != 1))
        r = GDS_ECRYPTO;
    if(r == GDS_OK)
        r = leaf_extensions(c, x, rec);
    X509_NAME_free(name);
    if(r != GDS_OK) {
        X509_free(x);
        return r;
    }
    issued->notBefore = now - CLOCK_SKEW_SECONDS;
    issued->notAfter = notAfter;
    *out = x;
    return GDS_OK;
}

static gds_status issuer_sign_csr(ossl_ca *c, const gds_ca_subject *subj, const gds_buf *csrDer,
                                  gds_ca_issued *out) {
    EVP_PKEY *pk = NULL;
    gds_status r = check_csr(csrDer, c->issuer, &pk);
    if(r != GDS_OK)
        return r;
    X509 *x = NULL;
    r = build_leaf(c, subj->record, pk, &x, out);
    if(r == GDS_OK && X509_sign(x, c->key, c->md) <= 0)
        r = GDS_ECRYPTO;
    if(r == GDS_OK)
        r = cax_cert_der(x, &out->der);
    X509_free(x);
    EVP_PKEY_free(pk);
    return r;
}

static void issuer_free(ossl_ca *c) {
    if(!c)
        return;
    EVP_PKEY_free(c->key);
    X509_free(c->cert);
    X509_CRL_free(c->crl);
    free(c->org);
    free(c);
}

/* ---- the backend: every issuer ---- */

typedef struct {
    ossl_ca *ca[GDS_CA_ISSUERS];
} ossl_cas;

static ossl_ca *pick(void *ctx, gds_ca_issuer issuer) {
    ossl_cas *m = ctx;
    return (unsigned)issuer < GDS_CA_ISSUERS ? m->ca[issuer] : NULL;
}

static gds_status ossl_sign_csr(void *ctx, const gds_ca_subject *subj, const gds_buf *csrDer,
                                gds_ca_issued *out) {
    gds_ca_issuer issuer;
    /* RsaMin (deprecated with the Basic128Rsa15/Basic256 profiles) and the
     * ECC types other than NIST P-256/P-384 are not issued */
    if(!gds_ca_issuer_of(subj->certificateType, &issuer))
        return GDS_EUNSUPPORTED;
    ossl_ca *c = pick(ctx, issuer);
    return c ? issuer_sign_csr(c, subj, csrDer, out) : GDS_EUNSUPPORTED;
}

static gds_status ossl_get_issuer_cert(void *ctx, gds_ca_issuer issuer, gds_buf *out) {
    ossl_ca *c = pick(ctx, issuer);
    return c ? cax_cert_der(c->cert, out) : GDS_ENOTFOUND;
}

static gds_status ossl_get_issuer_crl(void *ctx, gds_ca_issuer issuer, gds_buf *out) {
    ossl_ca *c = pick(ctx, issuer);
    return c ? ca_ossl_get_crl(c, out) : GDS_ENOTFOUND;
}

static gds_status ossl_revoke_issuer(void *ctx, gds_ca_issuer issuer, const gds_buf *serial) {
    ossl_ca *c = pick(ctx, issuer);
    return c ? ca_ossl_revoke(c, serial) : GDS_ENOTFOUND;
}

static gds_status ossl_get_ca_cert(void *ctx, gds_buf *out) {
    return ossl_get_issuer_cert(ctx, GDS_CA_ISSUER_RSA, out);
}

static gds_status ossl_get_crl(void *ctx, gds_buf *out) {
    return ossl_get_issuer_crl(ctx, GDS_CA_ISSUER_RSA, out);
}

static gds_status ossl_revoke(void *ctx, const gds_buf *serial) {
    return ossl_revoke_issuer(ctx, GDS_CA_ISSUER_RSA, serial);
}

static void ossl_destroy(void *ctx) {
    ossl_cas *m = ctx;
    if(!m)
        return;
    for(size_t i = 0; i < GDS_CA_ISSUERS; i++)
        issuer_free(m->ca[i]);
    free(m);
}

static const gds_ca_backend ossl_backend = {
    .abiVersion = GDS_CA_ABI_VERSION,
    .pre_sign = NULL,
    .sign_csr = ossl_sign_csr,
    .get_ca_cert = ossl_get_ca_cert,
    .get_crl = ossl_get_crl,
    .destroy = ossl_destroy,
    .revoke = ossl_revoke,
    .new_key_pair = NULL,
    .get_issuer_cert = ossl_get_issuer_cert,
    .get_issuer_crl = ossl_get_issuer_crl,
    .revoke_issuer = ossl_revoke_issuer,
};

/* Each issuer: its directory, CN suffix and digest. The CA signs with the
 * hash that fits its curve (ECC-nistP384: SHA-384 above 256 bits). */
static const struct {
    const char *subdir; /* NULL: cfg->dir itself */
    const char *cnSuffix;
} issuerDirs[GDS_CA_ISSUERS] = {{NULL, ""}, {"nistP256", " P-256"}, {"nistP384", " P-384"}};

static gds_status open_issuer(const gds_ca_config *cfg, gds_ca_issuer issuer, ossl_ca **out) {
    *out = NULL;
    char dir[GDS_MAX_PATH], cn[GDS_MAX_PATH];
    gds_status r = issuerDirs[issuer].subdir
                       ? gds_path(dir, sizeof(dir), "%s/%s", cfg->dir, issuerDirs[issuer].subdir)
                       : gds_path(dir, sizeof(dir), "%s", cfg->dir);
    if(r == GDS_OK)
        r = gds_path(cn, sizeof(cn), "%s%s", cfg->caSubjectCN, issuerDirs[issuer].cnSuffix);
    if(r == GDS_OK)
        r = gds_mkdirs(dir, 0700);
    if(r != GDS_OK)
        return r;
    ossl_ca *c = calloc(1, sizeof(*c));
    if(!c)
        return GDS_ENOMEM;
    c->issuer = issuer;
    c->md = issuer == GDS_CA_ISSUER_P384 ? EVP_sha384() : EVP_sha256();
    c->leafDays = cfg->leafLifetimeDays;
    c->crlDays = cfg->crlLifetimeDays;
    if(cfg->organization && !(c->org = strdup(cfg->organization)))
        r = GDS_ENOMEM;
    if(r == GDS_OK)
        r = load_or_create(c, cfg, dir, cn);
    if(r == GDS_OK)
        r = ca_ossl_load_or_issue_crl(c);
    if(r != GDS_OK) {
        issuer_free(c);
        return r;
    }
    *out = c;
    return GDS_OK;
}

gds_status gds_ca_openssl_open(const gds_ca_config *cfg, gds_ca **out) {
    *out = NULL;
    if(!cfg || !cfg->dir || !cfg->caSubjectCN || cfg->leafLifetimeDays == 0 ||
       cfg->caLifetimeDays == 0 || cfg->crlLifetimeDays == 0 || !cfg->keyPassphrase ||
       !cfg->keyPassphrase->data || cfg->keyPassphrase->len == 0)
        return GDS_EINVAL;
    ossl_cas *m = calloc(1, sizeof(*m));
    if(!m)
        return GDS_ENOMEM;
    gds_status r = GDS_OK;
    for(unsigned i = 0; r == GDS_OK && i < GDS_CA_ISSUERS; i++)
        r = open_issuer(cfg, (gds_ca_issuer)i, &m->ca[i]);
    if(r != GDS_OK) {
        ossl_destroy(m);
        return r;
    }
    return gds_ca_wrap(&ossl_backend, m, out);
}
