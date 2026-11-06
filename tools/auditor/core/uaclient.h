/* OpenGDS Auditor - OPC UA client helpers (open62541), seeded from the demo.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Every result that comes back from a target is checked (type, shape,
 * length) before use: the target may be hostile (docs/architecture.md). */
#ifndef GDSAUDIT_UACLIENT_H
#define GDSAUDIT_UACLIENT_H

#include <open62541/client.h>

#include "common/ua_args.h"
#include "x509util.h"

#define POLICY_RSAPSS "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"

/* Client with SignAndEncrypt, own certificate and an explicit trust list
 * (certificates and CRLs, DER). Inputs are borrowed (copied by open62541).
 * Returns NULL on error. */
UA_Client *uac_new_secure(const gds_buf *cert, const gds_buf *key,
                          const gds_buf *trust, size_t trustN,
                          const gds_buf *crls, size_t crlN,
                          const char *applicationUri);

/* GetEndpoints over the discovery-only None channel and return the server
 * certificate of the first SignAndEncrypt endpoint (trust on first use in
 * test setups only, Annex G.2). *out is owned by the caller. */
GDS_MUST_CHECK UA_StatusCode uac_fetch_server_cert(const char *url, UA_ByteString *out);

/* Resolve parent/0:<name> via TranslateBrowsePathsToNodeIds. */
GDS_MUST_CHECK UA_StatusCode uac_find_child(UA_Client *c, const UA_NodeId parent,
                                            const char *name, UA_NodeId *out);

/* Read a TrustListType object with Open(Read) -> Read... -> Close and decode
 * the TrustListDataType. The file is bounded by GDS_MAX_TRUSTLIST_SIZE. */
GDS_MUST_CHECK UA_StatusCode uac_read_trustlist(UA_Client *c, const UA_NodeId trustList,
                                                UA_TrustListDataType *out);

/* Call a method and print its status. On success *out has at least
 * minOutputs entries (else BadUnexpectedError and nothing is returned). */
GDS_MUST_CHECK UA_StatusCode uac_call(UA_Client *c, const char *label, UA_NodeId obj,
                                      UA_NodeId method, size_t inSize, const UA_Variant *in,
                                      size_t minOutputs, size_t *outSize, UA_Variant **out);

/* Checked access to output i of a method result. NULL if the output is
 * missing or not a scalar of `type`. Borrowed from out. */
const void *uac_out_scalar(const UA_Variant *out, size_t outSize, size_t i,
                           const UA_DataType *type);

/* Progress printing for the self-test tools. */
void uac_step(const char *fmt, ...) GDS_FORMAT(1, 2);
void uac_info(const char *fmt, ...) GDS_FORMAT(1, 2);

#endif
