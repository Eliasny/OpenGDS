/* OpenGDS - state of the built-in OpenSSL CA backend, shared by
 * ca_openssl.c and ca_crl.c only.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_CA_INTERNAL_H
#define OPENGDS_CA_INTERNAL_H

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "common/buf.h"
#include "common/limits.h"

typedef struct {
    EVP_PKEY *key;
    X509 *cert;
    X509_CRL *crl;
    char crlPath[GDS_MAX_PATH];
    char *org;
    unsigned leafDays;
    unsigned crlDays;
} ossl_ca;

/* Load the CRL from crlPath, or issue an empty one (CRL number 1). */
GDS_MUST_CHECK gds_status ca_ossl_load_or_issue_crl(ossl_ca *c);
/* The current CRL; reissued (number + 1) when within a day of nextUpdate. */
gds_status ca_ossl_get_crl(void *ctx, gds_buf *out);

#endif
