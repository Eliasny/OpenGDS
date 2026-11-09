/* OpenGDS - validation of a CertificateGroup trust list (gds_tlcheck.c).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDS_TLCHECK_H
#define OPENGDS_GDS_TLCHECK_H

#include <open62541/types.h>
#include <open62541/types_generated.h>
#include <openssl/x509.h>

#include <stdbool.h>

/* DER with nothing after it, or NULL. */
X509 *gds_tl_parse_cert(const UA_ByteString *b);
X509_CRL *gds_tl_parse_crl(const UA_ByteString *b);
/* basicConstraints cA TRUE */
bool gds_tl_is_ca(X509 *x);
/* Good, or the first OPC 10000-4 validation error of any entry of tl (all
 * four lists, whatever specifiedLists says). gdsCas, the GDS's issuing
 * CAs (at least one), count as trusted CAs of the list. */
UA_StatusCode gds_tl_validate(const UA_TrustListDataType *tl, X509 *const *gdsCas, size_t nGdsCas);

#endif
