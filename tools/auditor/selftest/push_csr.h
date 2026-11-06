/* OpenGDS Auditor self-test target: the PKCS #10 request that
 * push_test_server's CreateSigningRequest returns (OPC 10000-12 §7.10.10).
 * TEST TARGET, NOT A PRODUCT.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_PUSH_CSR_H
#define GDSAUDIT_PUSH_CSR_H

#include <open62541/types.h>

#include <openssl/evp.h>

#include <stdbool.h>

/* A DER CSR for `key`, signed with it (SHA-256).
 * subject: the SubjectName argument (§7.6.4 form "CN=a,O=b"); empty means
 * the subject of `current`, the certificate in use. The subjectAltName of
 * `current` is copied into an extensionRequest. emptySubject and noSan are
 * the csr-empty-subject and csr-no-san mutants.
 * Bad_InvalidArgument if the subject does not parse. */
UA_StatusCode pc_build(const UA_ByteString *current, EVP_PKEY *key, const UA_String *subject,
                       bool emptySubject, bool noSan, UA_ByteString *csr);

#endif
