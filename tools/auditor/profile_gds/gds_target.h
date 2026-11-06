/* OpenGDS Auditor GDS profile - the GDS under test, seen only through
 * standard OPC UA (black box). Used by the T0 spec test programs.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_GDS_TARGET_H
#define GDSAUDIT_GDS_TARGET_H

#include <open62541/client.h>
#include <open62541/types_gds_generated.h>

#include "harness.h"
#include "uaclient.h"

#define GT_MAX_TRUST 8

typedef struct {
    /* configuration */
    const char *url;
    const char *user;          /* admin user able to register and request (NULL: none) */
    char password[256];
    gds_buf trust[GT_MAX_TRUST];
    size_t trustN;
    gds_buf crls[GT_MAX_TRUST];
    size_t crlN;
    gds_buf cert, key;         /* the Auditor's own application identity */
    const char *appUri;        /* ApplicationUri in cert */
    unsigned pollSeconds;      /* FinishRequest wait bound */
    char runTag[17];           /* random per run, keeps records of different runs apart */
    unsigned seq;
    /* session state */
    UA_Client *client;
    UA_UInt16 ns;              /* GDS namespace index on the target */
} gds_target;

/* Connect (or reuse the connection) as the configured admin user. */
GDS_MUST_CHECK UA_StatusCode gt_session(gds_target *t);
void gt_close(gds_target *t);
/* Encode the GDS DataTypes with namespace index ns (done by gt_session). */
void gt_bind_ns(UA_UInt16 ns);
void gt_clear(gds_target *t);

/* A fresh secure client with the Auditor identity, not connected. */
UA_Client *gt_new_client(gds_target *t);

/* Call Directory.<methodId> (GDS namespace numeric id). On Good, *out has
 * at least minOut entries; the caller frees it with gt_free_out. */
GDS_MUST_CHECK UA_StatusCode gt_call(gds_target *t, UA_UInt32 methodId, size_t inN,
                                     const UA_Variant *in, size_t minOut, size_t *outN,
                                     UA_Variant **out);
void gt_free_out(UA_Variant *out, size_t outN);

/* NodeId in the GDS namespace */
UA_NodeId gt_node(const gds_target *t, UA_UInt32 id);
const UA_DataType *gt_record_type(void);

/* "urn:opengds:auditor:<runTag>:<seq>" */
void gt_unique_uri(gds_target *t, char *out, size_t outLen);

/* Fill a valid record (borrowing uri/name strings) of the given type. */
void gt_record(UA_ApplicationRecordDataType *rec, const char *uri, UA_ApplicationType type,
               UA_LocalizedText *nameStorage, UA_String *discoveryUrlStorage);

/* RegisterApplication with a valid fresh record; *appId owned by caller. */
GDS_MUST_CHECK UA_StatusCode gt_register(gds_target *t, UA_ApplicationType type, char *uriOut,
                                         size_t uriLen, UA_NodeId *appId);

/* StartSigningRequest + FinishRequest polling. On Good, certOut/issuers are
 * owned by the caller; privKeyLen reports whether a private key came back. */
GDS_MUST_CHECK UA_StatusCode gt_sign(gds_target *t, const UA_NodeId *appId, const gds_buf *csr,
                                     ga_ctx *ctx, gds_buf *certOut, gds_buf *issuerOut,
                                     size_t *privKeyLen);

/* The DefaultApplicationGroup NodeId and RsaSha256ApplicationCertificateType */
UA_NodeId gt_default_group(const gds_target *t);
UA_NodeId gt_rsa_type(void);

#endif
