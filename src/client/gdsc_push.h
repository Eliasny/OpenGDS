/* OpenGDS libgdsclient - push wrappers: the ServerConfiguration and TrustList
 * methods a CertificateManager calls on a managed Server (OPC 10000-12
 * v1.05.07 §7.7, §7.8.2, §7.10).
 * SPDX-License-Identifier: MPL-2.0
 *
 * Every function returns the OPC UA status of the call. Results from the
 * Server are checked (type, shape, length, limits.h) before use: the Server
 * may be hostile (docs/architecture.md, "Input validation and limits").
 * Inputs are borrowed. Outputs (`gds_buf *out`, `UA_TrustListDataType *out`)
 * are initialised by the callee and owned by the caller. */
#ifndef OPENGDS_CLIENT_GDSC_PUSH_H
#define OPENGDS_CLIENT_GDSC_PUSH_H

#include <open62541/client.h>
#include <open62541/types_gds_generated.h>

#include <stdbool.h>

#include "common/buf.h"
#include "common/compiler.h"

/* Well-known ServerConfiguration nodes (12 §7.10.3) */
#define GDSC_DEFAULT_APP_GROUP \
    UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP)
#define GDSC_DEFAULT_APP_TRUSTLIST                                                         \
    UA_NODEID_NUMERIC(                                                                     \
        0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST)
#define GDSC_RSA_SHA256_APP_CERT \
    UA_NODEID_NUMERIC(0, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE)

/* Largest block one TrustList Write sends. 12 §7.7.3 bounds a block by the
 * Server's MaxByteStringLength; open62541 and the .NET stack accept far more,
 * and the Server's limit is honoured when it is lower. */
#define GDSC_TL_BLOCK ((size_t)64 * 1024)

/* Resolve parent/0:<browseName> (TranslateBrowsePathsToNodeIds). */
GDS_MUST_CHECK UA_StatusCode gdsc_find_child(UA_Client *c, const UA_NodeId *parent,
                                             const char *browseName, UA_NodeId *out);

/* ServerConfiguration.MaxTrustListSize (12 §7.10.3); 0 means no limit. */
GDS_MUST_CHECK UA_StatusCode gdsc_read_max_trustlist_size(UA_Client *c, UA_UInt32 *out);

/* Update TrustList workflow (12 §7.7.3, §7.8.2.2, §7.8.2.5):
 * Open(Write+EraseExisting) -> Write... -> CloseAndUpdate. The encoded list
 * is refused locally with Bad_RequestTooLarge if it exceeds maxSize (> 0).
 * On any error after Open the handle is closed with Close, which discards
 * the written data (§7.8.2.5). */
GDS_MUST_CHECK UA_StatusCode gdsc_trustlist_write(UA_Client *c, const UA_NodeId *trustList,
                                                  const UA_TrustListDataType *tl,
                                                  UA_UInt32 maxSize,
                                                  bool *applyChangesRequired);

/* Read a TrustList: Open(Read) -> Read... -> Close (12 §7.8.2.2, §7.8.2.4),
 * bounded by GDS_MAX_TRUSTLIST_SIZE and GDS_MAX_TRUSTLIST_ENTRIES. */
GDS_MUST_CHECK UA_StatusCode gdsc_trustlist_read(UA_Client *c, const UA_NodeId *trustList,
                                                 UA_TrustListDataType *out);

/* CreateSigningRequest (12 §7.10.10) with SubjectName null (the Server keeps
 * its subject), RegeneratePrivateKey FALSE and no nonce. */
GDS_MUST_CHECK UA_StatusCode gdsc_create_signing_request(UA_Client *c, const UA_NodeId *group,
                                                         const UA_NodeId *certType,
                                                         gds_buf *csrOut);

/* UpdateCertificate (12 §7.10.5) without a private key: the Server made the
 * key pair in CreateSigningRequest. issuers: the CA chain, leaf's issuer
 * first, at most GDS_MAX_CHAIN_LEN. */
GDS_MUST_CHECK UA_StatusCode gdsc_update_certificate(UA_Client *c, const UA_NodeId *group,
                                                     const UA_NodeId *certType,
                                                     const gds_buf *cert, const gds_buf *issuers,
                                                     size_t issuersN,
                                                     bool *applyChangesRequired);

/* ApplyChanges (12 §7.10.9) and CancelChanges (§7.10.2) */
GDS_MUST_CHECK UA_StatusCode gdsc_apply_changes(UA_Client *c);
GDS_MUST_CHECK UA_StatusCode gdsc_cancel_changes(UA_Client *c);

#endif
