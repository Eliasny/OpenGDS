/* OpenGDS Auditor - test PKI (grows into core/test_ca.c of the Auditor plan).
 * SPDX-License-Identifier: MPL-2.0
 *
 * TEST ONLY. Every certificate carries "OpenGDS Auditor TEST" in its subject
 * and lives at most TESTCA_MAX_DAYS days, so it cannot pass for a real one. */
#ifndef GDSAUDIT_TEST_CA_H
#define GDSAUDIT_TEST_CA_H

#include "x509util.h"

#define TESTCA_ORG "OpenGDS Auditor TEST"
#define TESTCA_MAX_DAYS 30

typedef struct {
    EVP_PKEY *key;
    X509 *cert;
} testca_t;

/* Load <dir>/ca.der + <dir>/ca.key.der, or create a new CA there (0700/0600). */
GDS_MUST_CHECK gds_status testca_load_or_create(testca_t *ca, const char *dir, const char *cn);
void testca_free(testca_t *ca);
/* An intermediate CA issued by `parent`, in memory only */
GDS_MUST_CHECK gds_status testca_create_sub(testca_t *ca, const testca_t *parent, const char *cn);
GDS_MUST_CHECK gds_status testca_cert_der(const testca_t *ca, gds_buf *out);
/* Empty CRL signed by the CA (OPC UA trust lists expect one per CA). */
GDS_MUST_CHECK gds_status testca_crl_der(const testca_t *ca, gds_buf *out);
/* Sign a CSR after verifying its signature (proof of possession). If
 * applicationUri is non-NULL it replaces the CSR's SAN URI, as a real GDS
 * takes it from the record. The CSR subject is kept (fixture only: a real CA
 * builds the subject from the record). Validity starts 1 h in the past. */
GDS_MUST_CHECK gds_status testca_sign_csr(const testca_t *ca, const gds_buf *csrDer,
                                          const char *applicationUri, int days,
                                          gds_buf *certOut);
/* Fresh RSA-2048 key pair + certificate (fixture identities). */
GDS_MUST_CHECK gds_status testca_issue(const testca_t *ca, const char *commonName,
                                       const char *applicationUri, const char *dnsName,
                                       int days, gds_buf *certOut, gds_buf *keyOut);

/* Load <dir>/<name>.der + <name>.key.der, or issue and save them. */
GDS_MUST_CHECK gds_status testca_identity(const testca_t *ca, const char *dir, const char *name,
                                          const char *commonName, const char *applicationUri,
                                          gds_buf *certOut, gds_buf *keyOut);

#endif
