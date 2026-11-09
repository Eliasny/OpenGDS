/* OpenGDS - the CA slot (OpenGDS plan "CA"; docs/architecture.md "Split by
 * privilege"). opengdsd fills it with ca_ipc (forwarding to opengds-signer);
 * the signer fills it with ca_openssl or a plugin (UASM ceremony CA, HSM).
 *
 * Rules every backend keeps (decision G5, OPC 10000-12 §7.9.3):
 * - every certificate field comes from the registered record; the CSR gives
 *   only its public key, after its signature (proof of possession) checks;
 * - the CA private key never leaves the backend.
 *
 * Ownership: inputs are borrowed for the duration of the call. Output
 * buffers are owned by the caller (gds_buf_free).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_CA_H
#define OPENGDS_CA_H

#include <open62541/types.h>
#include <open62541/types_gds_generated.h>

#include <stdint.h>

#include "common/buf.h"
#include "common/compiler.h"

#define GDS_CA_ABI_VERSION 3u /* 2: revoke; 3: new_key_pair */
/* Backends of an older version are accepted; the fields they lack are NULL. */
#define GDS_CA_ABI_MIN_VERSION 2u

typedef enum {
    GDS_CA_OP_SIGN_CSR = 1,
    GDS_CA_OP_NEW_KEY_PAIR = 2,
    GDS_CA_OP_REVOKE = 3,
    GDS_CA_OP_ISSUE_CRL = 4
} gds_ca_op;

/* What a certificate is issued for. requestId is the store's issuance
 * record id (the CertificateManager RequestId), so a backend can tie its own
 * records to the issuance (issue #13). */
typedef struct {
    const UA_Guid *requestId;
    const UA_ApplicationRecordDataType *record;
    UA_UInt32 certificateGroup; /* numeric NodeId in the GDS namespace */
    UA_UInt32 certificateType;  /* numeric NodeId in ns 0, e.g. RsaSha256ApplicationCertificateType */
} gds_ca_subject;

/* Issued certificate: DER, serial (big-endian, positive) and validity. */
typedef struct {
    gds_buf der;
    gds_buf serial;
    int64_t notBefore; /* Unix seconds */
    int64_t notAfter;
} gds_ca_issued;

void gds_ca_issued_clear(gds_ca_issued *c);

typedef struct gds_ca gds_ca;

/* StartNewKeyPairRequest (OPC 10000-12 §7.9.4): the private key encoding */
typedef enum {
    GDS_CA_KEY_PFX = 1, /* PKCS #12 with the certificate and the CA certificate */
    GDS_CA_KEY_PEM = 2  /* PKCS #8, Base64 DER (RFC 5958) */
} gds_ca_key_format;

typedef struct {
    gds_ca_key_format format;
    /* PrivateKeyPassword; empty: the key is not encrypted. Borrowed; the
     * caller wipes it. */
    const gds_buf *password;
} gds_ca_keyreq;

/* A CA backend. Every function pointer except pre_sign, revoke and
 * new_key_pair is required. */
typedef struct {
    uint32_t abiVersion; /* GDS_CA_ABI_VERSION */
    /* Optional (NULL = allow). Called immediately before every signature.
     * A refusal (any status but GDS_OK) leaves no certificate and no store
     * change; GDS_ESTATE maps to Bad_InvalidState (issue #13). */
    gds_status (*pre_sign)(void *ctx, gds_ca_op op, const gds_ca_subject *subj);
    gds_status (*sign_csr)(void *ctx, const gds_ca_subject *subj, const gds_buf *csrDer,
                           gds_ca_issued *out);
    /* The CA certificate (DER), for trust lists and chains. */
    gds_status (*get_ca_cert)(void *ctx, gds_buf *out);
    /* The current CRL (DER). */
    gds_status (*get_crl)(void *ctx, gds_buf *out);
    void (*destroy)(void *ctx);
    /* Optional (NULL = GDS_EUNSUPPORTED). Put serial (big-endian, positive)
     * on the CRL and issue a new CRL; revoking a serial again changes
     * nothing and succeeds. */
    gds_status (*revoke)(void *ctx, const gds_buf *serial);
    /* ABI 3, optional. Generate a key pair and issue its certificate; *key
     * is the private key in kr->format (gds_buf_free_secret). NULL: the
     * core generates the key next to the backend and issues it through
     * sign_csr (gds_ca_new_key_pair). ca_ipc sets it to forward the call
     * to the signer, so keys are never generated in opengdsd. */
    gds_status (*new_key_pair)(void *ctx, const gds_ca_subject *subj, const gds_ca_keyreq *kr,
                               gds_ca_issued *out, gds_buf *key);
} gds_ca_backend;

/* Settings for the built-in OpenSSL backend (ca_openssl.c). Defaults are set
 * by gds_ca_config_init; see docs/ca.md for where each comes from. */
typedef struct {
    const char *dir;          /* CA state: key, certificate, CRL, serials (0700) */
    const char *caSubjectCN;  /* CA certificate common name */
    const char *organization; /* O= of the CA and of issued certificates; may be NULL */
    unsigned caKeyBits;       /* RSA bits of a new CA key */
    unsigned caLifetimeDays;
    unsigned leafLifetimeDays;
    unsigned crlLifetimeDays;
    /* Required: passphrase of the CA key file, which is always encrypted
     * PKCS#8 (decision G6). From systemd credentials, never argv or env. */
    const gds_buf *keyPassphrase;
    /* Optional pre-connected socket for a CA plugin (issue #12), -1 = none.
     * The signer passes it through and never reads from it. */
    int pluginFd;
} gds_ca_config;

void gds_ca_config_init(gds_ca_config *cfg);

/* Open the CA in cfg->dir, creating its key, self-signed certificate and an
 * empty CRL on first use. */
GDS_MUST_CHECK gds_status gds_ca_openssl_open(const gds_ca_config *cfg, gds_ca **out);
/* Wrap any backend (plugins, ca_ipc). Takes ownership of ctx. */
GDS_MUST_CHECK gds_status gds_ca_wrap(const gds_ca_backend *backend, void *ctx, gds_ca **out);
void gds_ca_close(gds_ca *ca);

/* Calls pre_sign, then sign_csr. */
GDS_MUST_CHECK gds_status gds_ca_sign_csr(gds_ca *ca, const gds_ca_subject *subj,
                                          const gds_buf *csrDer, gds_ca_issued *out);
/* StartNewKeyPairRequest: a new key for the CertificateType (RSA 2048 for
 * the RSA types), its certificate issued from the record like any other
 * (pre_sign sees GDS_CA_OP_NEW_KEY_PAIR), and the private key encoded in
 * kr->format, encrypted with AES-256 under a non-empty password. *key is
 * owned by the caller (gds_buf_free_secret). */
GDS_MUST_CHECK gds_status gds_ca_new_key_pair(gds_ca *ca, const gds_ca_subject *subj,
                                              const gds_ca_keyreq *kr, gds_ca_issued *out,
                                              gds_buf *key);
GDS_MUST_CHECK gds_status gds_ca_get_ca_cert(gds_ca *ca, gds_buf *out);
GDS_MUST_CHECK gds_status gds_ca_get_crl(gds_ca *ca, gds_buf *out);
/* Revoke the certificate with this serial (OPC 10000-12 §7.9.6). The caller
 * has checked that this CA issued it. */
GDS_MUST_CHECK gds_status gds_ca_revoke(gds_ca *ca, const gds_buf *serial);

#endif
