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

/* RegisterApplication with a caller-built record; *appId owned by caller. */
GDS_MUST_CHECK UA_StatusCode gt_register_record(gds_target *t, const UA_ApplicationRecordDataType *rec,
                                                UA_NodeId *appId);

/* Call obj.method with explicit NodeIds (objects other than the Directory).
 * Same result contract as gt_call. */
GDS_MUST_CHECK UA_StatusCode gt_call_obj(gds_target *t, UA_NodeId obj, UA_NodeId method,
                                         size_t inN, const UA_Variant *in, size_t minOut,
                                         size_t *outN, UA_Variant **out);

/* Resolve parent/<ns>:<name> with TranslateBrowsePathsToNodeIds. */
GDS_MUST_CHECK UA_StatusCode gt_find(UA_Client *c, UA_NodeId parent, UA_UInt16 ns,
                                     const char *name, UA_NodeId *out);

/* A connected session with the Auditor's application certificate and no
 * user (anonymous identity), or NULL with *r set. The caller deletes it
 * with gt_drop. */
UA_Client *gt_anon_session(gds_target *t, UA_StatusCode *r);
void gt_drop(UA_Client *c);

/* A session as the configured admin user over a Sign-only SecureChannel
 * (Basic256Sha256, then Aes128_Sha256_RsaOaep), or NULL with *r set when the
 * GDS offers no such endpoint. */
UA_Client *gt_sign_only_session(gds_target *t, UA_StatusCode *r);

/* Setup helper: register a fresh Client application and get it an RSA
 * certificate through the signing flow. On Good the caller owns *appId,
 * *cert and *issuer. */
GDS_MUST_CHECK UA_StatusCode gt_issue(gds_target *t, ga_ctx *ctx, char *uri, size_t uriLen,
                                      UA_NodeId *appId, gds_buf *cert, gds_buf *issuer);

/* gt_issue that also keeps the private key (*key, gds_buf_free_secret), so
 * the Auditor can open Sessions as that application. */
GDS_MUST_CHECK UA_StatusCode gt_issue_key(gds_target *t, ga_ctx *ctx, char *uri, size_t uriLen,
                                          UA_NodeId *appId, gds_buf *cert, gds_buf *issuer,
                                          gds_buf *key);
/* A fresh secure client with another application identity, not connected. */
UA_Client *gt_new_client_as(gds_target *t, const gds_buf *cert, const gds_buf *key,
                            const char *appUri);

/* StartSigningRequest + FinishRequest polling. On Good, certOut/issuers are
 * owned by the caller; privKeyLen reports whether a private key came back. */
GDS_MUST_CHECK UA_StatusCode gt_sign(gds_target *t, const UA_NodeId *appId, const gds_buf *csr,
                                     ga_ctx *ctx, gds_buf *certOut, gds_buf *issuerOut,
                                     size_t *privKeyLen);

/* The first Object organized or contained by folder that has a child
 * <GDS ns>:<method> (e.g. a KeyCredentialService under
 * KeyCredentialManagement). Bad_NotFound when there is none. */
GDS_MUST_CHECK UA_StatusCode gt_service(gds_target *t, UA_NodeId folder, const char *method,
                                        UA_NodeId *obj);

/* r says the method is not there (BadMethodInvalid, BadNotImplemented,
 * BadNodeIdUnknown). Then it records the verdict: Not supported for an
 * Optional method, Fail for a Mandatory one, and returns true. */
bool gt_absent(ga_ctx *ctx, UA_StatusCode r, bool optional, const char *method);

/* The DefaultApplicationGroup NodeId and RsaSha256ApplicationCertificateType */
UA_NodeId gt_default_group(const gds_target *t);
UA_NodeId gt_rsa_type(void);

#endif
