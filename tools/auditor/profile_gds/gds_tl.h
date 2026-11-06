/* OpenGDS Auditor GDS profile - trust list helpers for the GDS's
 * CertificateGroup TrustLists (TrustListType, OPC 10000-12 §7.8.2; FileType,
 * OPC 10000-20 §4.2) and test certificates the GDS spec tests need.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_GDS_TL_H
#define GDSAUDIT_GDS_TL_H

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "gds_target.h"

#define GTL_READ        0x01
#define GTL_WRITE_ERASE 0x06

/* The DefaultApplicationGroup TrustList of the Directory */
UA_NodeId gtl_default(const gds_target *t);

/* TrustList method by its (namespace 0) BrowseName, e.g. "Open". */
GDS_MUST_CHECK UA_StatusCode gtl_method(UA_Client *c, UA_NodeId tl, const char *name,
                                        UA_NodeId *out);

/* Open(mode) or OpenWithMasks(masks) (masks used when openWithMasks). */
GDS_MUST_CHECK UA_StatusCode gtl_open(UA_Client *c, UA_NodeId tl, UA_Byte mode, bool withMasks,
                                      UA_UInt32 masks, UA_UInt32 *handle);
void gtl_close(UA_Client *c, UA_NodeId tl, UA_UInt32 handle);
/* Read the whole file in `chunk`-byte Reads (bounded). */
GDS_MUST_CHECK UA_StatusCode gtl_read_all(UA_Client *c, UA_NodeId tl, UA_UInt32 handle,
                                          UA_Int32 chunk, UA_ByteString *out);
GDS_MUST_CHECK UA_StatusCode gtl_decode(const UA_ByteString *file, UA_TrustListDataType *out);
/* Open(Write|EraseExisting), Write in chunks, then CloseAndUpdate (update)
 * or Close (discard). */
GDS_MUST_CHECK UA_StatusCode gtl_write(UA_Client *c, UA_NodeId tl, const UA_TrustListDataType *d,
                                       bool update, bool *applyRequired);
GDS_MUST_CHECK UA_StatusCode gtl_add(UA_Client *c, UA_NodeId tl, const gds_buf *cert,
                                     bool trusted);
GDS_MUST_CHECK UA_StatusCode gtl_remove_thumb(UA_Client *c, UA_NodeId tl, const char *thumb,
                                              bool trusted);
/* *out stays 0 on failure. */
UA_StatusCode gtl_last_update(UA_Client *c, UA_NodeId tl, UA_DateTime *out);
bool gtl_has(const UA_ByteString *list, size_t n, const gds_buf *x);

/* Read the DefaultApplicationGroup TrustList over a session; the caller
 * clears *tl. */
GDS_MUST_CHECK UA_StatusCode gtl_read_group(gds_target *t, UA_TrustListDataType *tl);
/* Is the DER certificate listed in one of the CRLs of the trust list? */
bool gtl_crl_lists(const UA_TrustListDataType *tl, const gds_buf *certDer);

/* Test certificates: an RSA-2048 certificate for key with CN=cn, O=TESTCA_ORG,
 * an optional SAN URI, valid for days, signed by issuer/issuerKey (NULL:
 * self-signed). isCa adds basicConstraints CA:TRUE and keyCertSign. */
GDS_MUST_CHECK gds_status gtl_make_cert(X509 *issuer, EVP_PKEY *issuerKey, EVP_PKEY *key,
                                        const char *cn, const char *uri, bool isCa, int days,
                                        gds_buf *out);

#endif
