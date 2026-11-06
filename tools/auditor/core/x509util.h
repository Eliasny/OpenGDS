/* OpenGDS Auditor - X.509 helpers on OpenSSL 3 (seeded from the 2 Nov demo).
 * SPDX-License-Identifier: MPL-2.0
 *
 * All parsing goes through OpenSSL with the input size checked first
 * (limits.h). Inputs are borrowed; gds_buf outputs are owned by the caller. */
#ifndef GDSAUDIT_X509UTIL_H
#define GDSAUDIT_X509UTIL_H

#include <stdbool.h>
#include <stddef.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "common/buf.h"

#define X509_THUMBPRINT_LEN 41 /* SHA-1 as 40 hex chars + NUL (OPC UA thumbprint) */

GDS_MUST_CHECK gds_status x509_thumbprint(const gds_buf *certDer, char out[X509_THUMBPRINT_LEN]);
/* true only if the key parses and belongs to the certificate */
bool x509_key_matches(const gds_buf *certDer, const gds_buf *keyDer);
/* true if subject == issuer (the initial self-signed certificate) */
bool x509_is_self_signed(const gds_buf *certDer);
/* One line: subject | issuer | notAfter. Never fails; prints a marker if unparsable. */
void x509_describe(const gds_buf *certDer, char *out, size_t outLen);

/* PKCS#10 CSR signed with keyDer. SAN = URI:<applicationUri>[,DNS:<dnsName>]. */
GDS_MUST_CHECK gds_status x509_make_csr(const gds_buf *keyDer, const char *commonName,
                                        const char *applicationUri, const char *dnsName,
                                        gds_buf *csrOut);

/* Parsers with a size check. Returned objects are owned by the caller. */
X509 *x509_parse_cert(const gds_buf *der);
EVP_PKEY *x509_parse_key(const gds_buf *der); /* DER (PKCS#8 or traditional) or PEM */
GDS_MUST_CHECK gds_status x509_cert_to_der(X509 *x, gds_buf *out);
GDS_MUST_CHECK gds_status x509_key_to_der(EVP_PKEY *k, gds_buf *out);

/* Log and clear the OpenSSL error queue (rule: drain at the call site). */
void x509_drain_errors(const char *where);

#endif
