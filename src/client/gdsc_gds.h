/* OpenGDS libgdsclient - GDS Directory and CertificateManager wrappers, the
 * calls an Administration Component makes (OPC 10000-12 v1.05.07 §6.5,
 * §7.9; gdsadm push now, OpenGDS plan "Manual push now").
 * SPDX-License-Identifier: MPL-2.0
 *
 * Call gdsc_gds_bind once per session before any other call: it finds the
 * GDS namespace index and lets the client encode and decode the GDS
 * DataTypes. The GDS DataType table is process-wide (open62541 generated
 * types), so one process talks to one GDS at a time.
 * Every result is checked before use; outputs are owned by the caller. */
#ifndef OPENGDS_CLIENT_GDSC_GDS_H
#define OPENGDS_CLIENT_GDSC_GDS_H

#include <open62541/client.h>
#include <open62541/types_gds_generated.h>

#include <stdbool.h>

#include "common/buf.h"
#include "common/compiler.h"
#include "common/limits.h"

#define GDSC_GDS_NS_URI "http://opcfoundation.org/UA/GDS/"

GDS_MUST_CHECK UA_StatusCode gdsc_gds_bind(UA_Client *c, UA_UInt16 *ns);

/* DefaultApplicationGroup of the GDS (12 §7.9.4, in the GDS namespace) */
UA_NodeId gdsc_gds_default_group(UA_UInt16 ns);

/* FindApplications (12 §6.5.4). *recs: UA_Array_delete with the GDS
 * ApplicationRecordDataType; at most GDS_MAX_QUERY_RECORDS. */
GDS_MUST_CHECK UA_StatusCode gdsc_find_applications(UA_Client *c, UA_UInt16 ns,
                                                    const char *applicationUri,
                                                    UA_ApplicationRecordDataType **recs,
                                                    size_t *n);

/* RegisterApplication (12 §6.5.5) */
GDS_MUST_CHECK UA_StatusCode gdsc_register_application(UA_Client *c, UA_UInt16 ns,
                                                       const UA_ApplicationRecordDataType *rec,
                                                       UA_NodeId *applicationId);

/* UnregisterApplication (12 §6.5.8); the GDS revokes the application's
 * certificates. */
GDS_MUST_CHECK UA_StatusCode gdsc_unregister_application(UA_Client *c, UA_UInt16 ns,
                                                         const UA_NodeId *applicationId);

/* RevokeCertificate (12 §7.9.6): cert (DER) must have been issued by this GDS
 * to applicationId. */
GDS_MUST_CHECK UA_StatusCode gdsc_revoke_certificate(UA_Client *c, UA_UInt16 ns,
                                                     const UA_NodeId *applicationId,
                                                     const gds_buf *cert);

/* StartSigningRequest (12 §7.9.4) then FinishRequest (§7.9.6) until the
 * request completes or pollSeconds pass (Bad_NothingToDo while pending).
 * certOut: the issued certificate; issuersOut[GDS_MAX_CHAIN_LEN]: its issuer
 * chain. A private key in the answer is refused: a CSR was sent. */
GDS_MUST_CHECK UA_StatusCode gdsc_sign_csr(UA_Client *c, UA_UInt16 ns, const UA_NodeId *appId,
                                           const UA_NodeId *group, const UA_NodeId *certType,
                                           const gds_buf *csr, unsigned pollSeconds,
                                           gds_buf *certOut, gds_buf *issuersOut,
                                           size_t *issuersN);

/* GetCertificateGroups (12 v1.05.07 §7.9.7): the groups of an application.
 * *groups: UA_Array_delete with UA_TYPES_NODEID; at most GDS_MAX_GROUPS. */
#define GDSC_MAX_GROUPS 16
GDS_MUST_CHECK UA_StatusCode gdsc_get_certificate_groups(UA_Client *c, UA_UInt16 ns,
                                                         const UA_NodeId *appId,
                                                         UA_NodeId **groups, size_t *n);

/* GetCertificateStatus (12 v1.05.07 §7.9.10): does the certificate of this group and
 * type need an update? */
GDS_MUST_CHECK UA_StatusCode gdsc_get_certificate_status(UA_Client *c, UA_UInt16 ns,
                                                         const UA_NodeId *appId,
                                                         const UA_NodeId *group,
                                                         const UA_NodeId *certType,
                                                         bool *updateRequired);

/* StartSigningRequest (12 v1.05.07 §7.9.3): *requestId is copied out. */
GDS_MUST_CHECK UA_StatusCode gdsc_start_signing_request(UA_Client *c, UA_UInt16 ns,
                                                        const UA_NodeId *appId,
                                                        const UA_NodeId *group,
                                                        const UA_NodeId *certType,
                                                        const gds_buf *csr, UA_NodeId *requestId);

/* One FinishRequest call (12 v1.05.07 §7.9.5): Bad_NothingToDo while the request is
 * pending. On Good the certificate and its issuer chain are copied out as in
 * gdsc_sign_csr; a private key in the answer is refused (a CSR was sent). */
GDS_MUST_CHECK UA_StatusCode gdsc_finish_request(UA_Client *c, UA_UInt16 ns,
                                                 const UA_NodeId *appId,
                                                 const UA_NodeId *requestId, gds_buf *certOut,
                                                 gds_buf *issuersOut, size_t *issuersN);

/* GetTrustList (12 v1.05.07 §7.9.9): the NodeId of the application's TrustList. */
GDS_MUST_CHECK UA_StatusCode gdsc_get_trust_list_id(UA_Client *c, UA_UInt16 ns,
                                                    const UA_NodeId *appId,
                                                    const UA_NodeId *group, UA_NodeId *tl);

/* GetTrustList (12 §7.9.8) and read that TrustList (§7.8.2). */
GDS_MUST_CHECK UA_StatusCode gdsc_get_trust_list(UA_Client *c, UA_UInt16 ns,
                                                 const UA_NodeId *appId, const UA_NodeId *group,
                                                 UA_TrustListDataType *out);

#endif
