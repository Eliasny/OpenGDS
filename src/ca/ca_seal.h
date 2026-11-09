/* OpenGDS - the CA keys sealed to backup recipients (UASM decision, Elias
 * 2026-11-09: backups contain the CA private keys, encrypted by the signer
 * itself to the backup key; docs/ca.md "Sealed key export").
 *
 * The signer reads the recipients from a file of its own (root-owned, not
 * writable by anyone else), never from opengdsd, so a compromised opengdsd
 * or embedder can ask for an export but cannot choose who can open it.
 *
 * Format "OGKX" version 1, big-endian:
 *   header      magic "OGKX" | version u16 = 1 | nRecipients u16 |
 *               created i64 (Unix seconds)
 *   recipients  nRecipients times: public key (X25519, 32) | enc (32) |
 *               wrapped content key (32 + 16)
 *   body        nonce (12) | ctLen u32 | ciphertext | tag (16)
 * Each recipient's copy of the random content key is sealed with HPKE
 * (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
 * AES-256-GCM, info "OpenGDS CA key export v1", aad = the header and that
 * recipient's public key. The body is AES-256-GCM under the content key,
 * aad = everything before the nonce. Its plaintext:
 *   count u8, then per issuer: issuer u8 (gds_ca_issuer) | certLen u32 |
 *   certificate DER | keyLen u32 | private key, unencrypted PKCS#8 DER |
 *   crlLen u32 | CRL DER (0: none)
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_CA_SEAL_H
#define OPENGDS_CA_SEAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ca.h"
#include "common/buf.h"
#include "common/compiler.h"

#define GDS_SEAL_KEY_LEN 32u
#define GDS_SEAL_MAX_RECIPIENTS 16u
#define GDS_SEAL_MAX_ITEM ((size_t)32 * 1024) /* each DER */
#define GDS_SEAL_MAX ((size_t)120 * 1024)     /* fits one signer reply */

typedef struct {
    gds_ca_issuer issuer;
    gds_buf cert; /* DER */
    gds_buf key;  /* unencrypted PKCS#8 DER: wipe with gds_buf_free_secret */
    gds_buf crl;  /* DER, may be empty */
} gds_seal_item;

typedef struct {
    int64_t created;
    gds_seal_item items[GDS_CA_ISSUERS];
    size_t n;
} gds_seal_contents;

/* Wipes the keys and frees everything. */
void gds_seal_contents_clear(gds_seal_contents *c);

/* Seals c (created, items) to the recipients' X25519 public keys. */
GDS_MUST_CHECK gds_status gds_seal_ca_keys(const gds_seal_contents *c,
                                           const uint8_t (*recipients)[32], size_t nRecipients,
                                           gds_buf *out);
/* Opens a sealed export with one recipient's X25519 private key.
 * GDS_EDENIED when the key is not a recipient or the export was altered;
 * GDS_EINVAL when it is not an export. */
GDS_MUST_CHECK gds_status gds_seal_open(const uint8_t *blob, size_t len, const uint8_t priv[32],
                                        gds_seal_contents *out);

/* The recipients file: one X25519 public key per line as 64 hex digits,
 * optionally after one word and a space (so a line like
 * "uasm-backup-recipient <hex>" works); blank lines and '#' comments are
 * skipped. GDS_EINVAL on a bad or repeated line, or no key; GDS_ETOOBIG on
 * more than cap. */
GDS_MUST_CHECK gds_status gds_seal_recipients_parse(const char *text, size_t len,
                                                    uint8_t (*out)[32], size_t cap, size_t *n);
/* Reads it from path: a regular file (not a link) owned by root, not
 * writable by group or others, at most 8 KiB. GDS_EDENIED when the file
 * fails those checks. */
GDS_MUST_CHECK gds_status gds_seal_recipients_read(const char *path, uint8_t (*out)[32], size_t cap,
                                                   size_t *n);

#endif
