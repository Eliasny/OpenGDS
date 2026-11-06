/* OpenGDS Auditor client profile - what a client's CSR says about it.
 * The CSR comes from the client under test: hostile input, size-checked and
 * parsed only through OpenSSL.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_CSR_CHECK_H
#define GDSAUDIT_CSR_CHECK_H

#include <stdbool.h>
#include <stddef.h>

#include "common/buf.h"

#define CSR_MAX_NAMES 8
#define CSR_MAX_NAME 256

typedef struct {
    bool parsed;          /* DER PKCS #10 */
    bool signatureOk;     /* signed with the key it carries */
    int keyType;          /* EVP_PKEY_RSA, EVP_PKEY_EC, ... */
    int bits;
    char curve[64];       /* EC group name, "" otherwise */
    size_t uriN, dnsN;
    char uris[CSR_MAX_NAMES][CSR_MAX_NAME];
    char dns[CSR_MAX_NAMES][CSR_MAX_NAME];
    gds_buf pubDer;       /* SubjectPublicKeyInfo, DER */
} csr_info;

/* Never fails on a bad CSR: parsed/signatureOk say what was found. */
void csr_inspect(const gds_buf *csr, csr_info *out);
void csr_info_clear(csr_info *info);

/* true if blob holds, at any offset, a DER or PEM private key whose public
 * key is pubDer. Bounded by the blob size (at most 64 KiB is scanned). */
bool csr_blob_has_private_key(const gds_buf *blob, const gds_buf *pubDer);

#endif
