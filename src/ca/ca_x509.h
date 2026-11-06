/* OpenGDS - X.509 building blocks for the CA (internal to src/ca and the
 * signer). Every extension is built from ASN.1 objects, never from OpenSSL
 * configuration strings, so no record value is ever parsed as config.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_CA_X509_H
#define OPENGDS_CA_X509_H

#include <open62541/types.h>
#include <open62541/types_gds_generated.h>
#include <openssl/x509.h>

#include <stdbool.h>
#include <stdint.h>

#include "common/buf.h"
#include "common/compiler.h"

/* keyUsage bits (RFC 5280 §4.2.1.3) */
#define CAX_KU_DIGITAL_SIGNATURE 0x01u
#define CAX_KU_NON_REPUDIATION   0x02u
#define CAX_KU_KEY_ENCIPHERMENT  0x04u
#define CAX_KU_DATA_ENCIPHERMENT 0x08u
#define CAX_KU_KEY_CERT_SIGN     0x20u
#define CAX_KU_CRL_SIGN          0x40u

/* RFC 5280 upper bound for a commonName */
#define CAX_MAX_CN 64

/* 20 random bytes, positive and non-zero (RFC 5280 §4.1.2.2). */
GDS_MUST_CHECK gds_status cax_set_random_serial(X509 *x, gds_buf *serialOut);
GDS_MUST_CHECK gds_status cax_set_validity(X509 *x, int64_t notBefore, int64_t notAfter);
/* CN (cut to CAX_MAX_CN bytes at a UTF-8 boundary) and optional O. */
GDS_MUST_CHECK gds_status cax_make_name(const UA_String *cn, const char *org, X509_NAME **out);
GDS_MUST_CHECK gds_status cax_add_basic_constraints(X509 *x, bool isCa);
GDS_MUST_CHECK gds_status cax_add_key_usage(X509 *x, unsigned bits);
GDS_MUST_CHECK gds_status cax_add_ext_key_usage(X509 *x, bool serverAuth, bool clientAuth);
/* subjectKeyIdentifier from x's key; authorityKeyIdentifier from issuer's
 * subjectKeyIdentifier (issuer NULL: self-signed, same as the subject's). */
GDS_MUST_CHECK gds_status cax_add_key_ids(X509 *x, X509 *issuer);
/* subjectAltName: URI = applicationUri, then one DNS or IP entry per
 * distinct DiscoveryUrl host. */
GDS_MUST_CHECK gds_status cax_add_san(X509 *x, const UA_ApplicationRecordDataType *rec);
/* Host of an opc.tcp / opc.https / https URL. IPv6 literals lose their
 * brackets. Refuses anything that is not a DNS name or an IP literal. */
GDS_MUST_CHECK gds_status cax_url_host(const UA_String *url, char *host, size_t hostLen,
                                       bool *isIp);
GDS_MUST_CHECK gds_status cax_cert_der(X509 *x, gds_buf *out);
GDS_MUST_CHECK gds_status cax_crl_der(X509_CRL *c, gds_buf *out);

#endif
