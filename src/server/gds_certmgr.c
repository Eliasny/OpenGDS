/* OpenGDS - CertificateManager methods (OPC 10000-12 §7.9): StartSigningRequest,
 * FinishRequest, GetCertificateGroups, GetTrustList, GetCertificateStatus,
 * GetCertificates, CheckRevocationStatus, StartNewKeyPairRequest, and the
 * signing worker.
 *
 * Decision G7: StartSigningRequest checks and stores the request and
 * returns at once; a background worker signs it through the CA slot
 * (opengds-signer); FinishRequest only reads the store. The approval
 * policy (gds_policy.c) approves a request on arrival or leaves it Pending
 * with a dialog for an administrator (gds_approvals.c); FinishRequest
 * answers Bad_NothingToDo until it is signed and Bad_RequestNotAllowed
 * once it is rejected (§7.9.6).
 * Access: CertificateAuthorityAdmin, or the application itself (its client
 * certificate carries the record's ApplicationUri, §7.2).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <openssl/bn.h>
#include <openssl/x509.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "common/ids.h"
#include "common/limits.h"
#include "gds_internal.h"
#include "common/banned.h"

#define WORKER_IDLE_SECONDS 2

/* ---- shared checks ---- */

/* A14: refused by our own checks; the embedder's may_manage hook decides,
 * and the method runs again if it allows. */
#define DEFER_IF_DENIED(fn, r, app)                                                          \
    do {                                                                                     \
        if((r) == UA_STATUSCODE_BADUSERACCESSDENIED)                                         \
            return gds_embed_defer_rights(s, fn, sessionId, sessionContext, methodId, objectId, \
                                          &(app), inputSize, input, outputSize, output);     \
    } while(0)

/* The application must exist, and the caller must be a CA admin or it. */
static UA_StatusCode check_app(gds_server *s, void *sessionContext, const UA_Guid *appId,
                               unsigned extraRoles) {
    UA_ApplicationRecordDataType rec;
    UA_StatusCode r = gds_load_app(s, appId, &rec);
    const gds_session *ss = sessionContext;
    if(r == UA_STATUSCODE_GOOD &&
       !gds_session_has(sessionContext, GDS_ROLE_CERTIFICATE_AUTHORITY_ADMIN | extraRoles) &&
       !gds_session_is_app(sessionContext, &rec.applicationUri) &&
       !(ss && ss->managedGranted && UA_Guid_equal(&ss->managedApp, appId)))
        r = UA_STATUSCODE_BADUSERACCESSDENIED; /* the embedder's hook may still allow it (A14) */
    UA_ApplicationRecordDataType_clear(&rec);
    return r;
}

/* Null or the DefaultApplicationGroup (the only group in T1). */
static UA_StatusCode group_arg(gds_server *s, size_t inputSize, const UA_Variant *input, size_t i,
                               UA_UInt32 *group) {
    const UA_NodeId *g = NULL;
    UA_StatusCode r = gds_in_nodeid(inputSize, input, i, &g);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_NodeId def =
        UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    if(!UA_NodeId_isNull(g) && !UA_NodeId_equal(g, &def))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    *group = UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP;
    return UA_STATUSCODE_GOOD;
}

/* DefaultApplicationGroup.CertificateTypes (12 §7.8.3.1): the types the CA
 * issues for the group, those whose issuer the CA slot has. RsaMin is
 * deprecated with its SecurityPolicies; Elias chose RSA, P-256 and P-384
 * for 1.0 (2026-11-09). The first entry is the default. */
static const UA_UInt32 groupCertTypes[] = {UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE,
                                           UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE,
                                           UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE};

const gds_buf *gds_issuer_cert(const gds_server *s, UA_UInt32 certType) {
    gds_ca_issuer i;
    if(!gds_ca_issuer_of(certType, &i) || s->issuerCert[i].len == 0)
        return NULL;
    return &s->issuerCert[i];
}

void gds_issuers_parse(const gds_server *s, X509 *out[GDS_CA_ISSUERS], size_t *n) {
    *n = 0;
    for(size_t i = 0; i < GDS_CA_ISSUERS; i++) {
        const unsigned char *p = s->issuerCert[i].data;
        X509 *x = s->issuerCert[i].len ? d2i_X509(NULL, &p, (long)s->issuerCert[i].len) : NULL;
        if(x)
            out[(*n)++] = x;
    }
}

static bool offered(const gds_server *s, UA_UInt32 type) {
    return gds_issuer_cert(s, type) != NULL;
}

const gds_buf *gds_issuer_for(const gds_server *s, UA_UInt32 certType) {
    const gds_buf *b = gds_issuer_cert(s, certType);
    return b ? b : &s->caCert; /* requests stored before ECC are all RSA */
}

bool gds_group_type(const gds_server *s, const UA_NodeId *t, UA_UInt32 *type) {
    if(!t || UA_NodeId_isNull(t)) {
        *type = groupCertTypes[0];
        return true;
    }
    if(t->namespaceIndex != 0 || t->identifierType != UA_NODEIDTYPE_NUMERIC)
        return false;
    for(size_t i = 0; i < GDS_ARRAY_SIZE(groupCertTypes); i++)
        if(t->identifier.numeric == groupCertTypes[i] && offered(s, groupCertTypes[i])) {
            *type = groupCertTypes[i];
            return true;
        }
    return false; /* §7.9.3, §7.9.4: not a type of the group, Bad_InvalidArgument */
}

/* Null means the group's default type. */
static UA_StatusCode type_arg(const gds_server *s, size_t inputSize, const UA_Variant *input,
                              size_t i, UA_UInt32 *type) {
    const UA_NodeId *t = NULL;
    UA_StatusCode r = gds_in_nodeid(inputSize, input, i, &t);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    return gds_group_type(s, t, type) ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINVALIDARGUMENT;
}

static UA_StatusCode set_group_types(gds_server *s) {
    UA_NodeId ids[GDS_ARRAY_SIZE(groupCertTypes)];
    size_t n = 0;
    for(size_t i = 0; i < GDS_ARRAY_SIZE(groupCertTypes); i++)
        if(offered(s, groupCertTypes[i]))
            ids[n++] = UA_NODEID_NUMERIC(0, groupCertTypes[i]);
    UA_Variant v;
    UA_Variant_setArray(&v, ids, n, &UA_TYPES[UA_TYPES_NODEID]);
    return UA_Server_writeValue(
        s->ua,
        UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_CERTIFICATETYPES),
        v);
}

/* DER CSR whose self-signature verifies (proof of possession). The signer
 * checks it again with the key rules of the certificate type. */
static bool csr_ok(const UA_ByteString *csr) {
    const unsigned char *p = csr->data;
    X509_REQ *req = csr->length ? d2i_X509_REQ(NULL, &p, (long)csr->length) : NULL;
    EVP_PKEY *pk = req && p == csr->data + csr->length ? X509_REQ_get_pubkey(req) : NULL;
    bool ok = pk && X509_REQ_verify(req, pk) == 1;
    EVP_PKEY_free(pk);
    X509_REQ_free(req);
    return ok;
}

/* ---- StartSigningRequest ---- */

/* StartSigningRequest's arguments and checks (§7.9.3). */
static UA_StatusCode signing_args(gds_server *s, void *sessionContext, size_t inputSize,
                                  const UA_Variant *input, UA_Guid *appId, UA_UInt32 *group,
                                  UA_UInt32 *type, const UA_ByteString **csr) {
    UA_StatusCode r = gds_in_guid(s, inputSize, input, 0, appId);
    if(r == UA_STATUSCODE_GOOD)
        r = check_app(s, sessionContext, appId, 0);
    if(r == UA_STATUSCODE_GOOD)
        r = group_arg(s, inputSize, input, 1, group);
    if(r == UA_STATUSCODE_GOOD)
        r = type_arg(s, inputSize, input, 2, type);
    if(r == UA_STATUSCODE_GOOD && inputSize < 4)
        r = UA_STATUSCODE_BADARGUMENTSMISSING;
    if(r == UA_STATUSCODE_GOOD && gds_arg_bytes(&input[3], GDS_MAX_CSR_SIZE, csr) != UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    if(r == UA_STATUSCODE_GOOD && !csr_ok(*csr))
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    if(r == UA_STATUSCODE_GOOD && gds_issuance_held(s, appId))
        r = UA_STATUSCODE_BADREQUESTNOTALLOWED; /* held by the embedder (A13) */
    return r;
}

/* The method call a request came in on, so that the approval hook (A22)
 * can run it again on a worker. */
typedef struct {
    UA_MethodCallback fn;
    const UA_NodeId *sessionId;
    void *sessionContext;
    const UA_NodeId *methodId;
    const UA_NodeId *objectId;
    size_t inputSize;
    const UA_Variant *input;
    size_t outputSize;
    UA_Variant *output;
} method_call;

#define METHOD_CALL(f)                                                                     \
    {(f), sessionId, sessionContext, methodId, objectId, inputSize, input, outputSize, output}

/* A22: a request the policy leaves Pending goes to the embedder's approval
 * hook once (on a worker; Good_CompletesAsynchronously, then the method
 * runs again); its yes makes the request Received. */
static UA_StatusCode approval_hook(gds_server *s, const method_call *mc, gds_request *q,
                                   bool *byHook) {
    const gds_session *ss = mc->sessionContext;
    if(q->state != GDS_REQ_PENDING || !s->approve || !ss)
        return UA_STATUSCODE_GOOD;
    if(ss->approvalAsked) {
        if(ss->approvalGranted && UA_Guid_equal(&ss->approvalApp, &q->appId)) {
            q->state = GDS_REQ_RECEIVED;
            *byHook = true;
        }
        return UA_STATUSCODE_GOOD;
    }
    UA_StatusCode r = gds_embed_defer_approval(s, mc->fn, mc->sessionId, mc->sessionContext,
                                               mc->methodId, mc->objectId, &q->appId,
                                               mc->inputSize, mc->input, mc->outputSize,
                                               mc->output);
    if(r == UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY || r == UA_STATUSCODE_BADSERVERTOOBUSY)
        return r;
    return UA_STATUSCODE_GOOD; /* no worker: it waits for an administrator */
}

/* The embedder approved it: recorded with the embedder as the approver.
 * A key pair request has no CSR, and its password is never audited. */
static void audit_hook_approval(gds_server *s, const gds_request *q) {
    bool keyPair = q->csr.len == 0;
    UA_NodeId app = UA_NODEID_GUID(s->ns, q->appId);
    UA_NodeId group = UA_NODEID_NUMERIC(s->ns, q->groupId), type = UA_NODEID_NUMERIC(0, q->certType);
    UA_ByteString csr = {q->csr.len, (UA_Byte *)(uintptr_t)q->csr.data};
    UA_Variant args[4];
    UA_Variant_setScalar(&args[0], &app, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&args[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&args[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&args[3], &csr, &UA_TYPES[UA_TYPES_BYTESTRING]);
    gds_status a = gds_cert_audit(
        s, "embedder", UA_GDSID_CERTIFICATEREQUESTEDAUDITEVENTTYPE,
        keyPair ? UA_GDSID_DIRECTORY_STARTNEWKEYPAIRREQUEST : UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST,
        q->certType, args, keyPair ? 3 : 4, true,
        "approved on arrival by the embedder's approval hook");
    if(a != GDS_OK)
        fprintf(stderr, "opengds: audit of an approval: %s\n", gds_status_name(a));
}

/* Store a request (approved or Pending) and raise its dialog or kick the
 * worker. Shared by StartSigningRequest and StartNewKeyPairRequest. */
static UA_StatusCode submit_request(gds_server *s, const method_call *mc, gds_request *q);

static GDS_METHOD(start_signing_request) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    UA_Guid appId;
    UA_UInt32 group = 0, type = 0;
    const UA_ByteString *csr = NULL;
    UA_StatusCode r = signing_args(s, sessionContext, inputSize, input, &appId, &group, &type, &csr);
    DEFER_IF_DENIED(start_signing_request, r, appId);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    gds_request q;
    memset(&q, 0, sizeof(q));
    if(gds_guid_random(&q.id) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    q.appId = appId;
    q.groupId = group;
    q.certType = type;
    q.csr.data = csr->data; /* borrowed for the insert */
    q.csr.len = csr->length;
    const method_call mc = METHOD_CALL(start_signing_request);
    r = submit_request(s, &mc, &q);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_NodeId rid = UA_NODEID_GUID(s->ns, q.id);
    return UA_Variant_setScalarCopy(&output[0], &rid, &UA_TYPES[UA_TYPES_NODEID]);
}

static UA_StatusCode submit_request(gds_server *s, const method_call *mc, gds_request *q) {
    gds_status st = gds_policy_initial_state(s, mc->sessionContext, q, &q->state);
    if(st != GDS_OK)
        return gds_status_to_ua(st);
    bool byHook = false;
    UA_StatusCode r = approval_hook(s, mc, q, &byHook);
    if(r != UA_STATUSCODE_GOOD)
        return r; /* asynchronous: asked on a worker, the method runs again */
    if(q->state == GDS_REQ_PENDING && s->pendingApprovals >= GDS_MAX_PENDING_APPROVALS)
        return UA_STATUSCODE_BADSERVERTOOBUSY; /* decision D1 */
    gds_lock(s);
    st = gds_store_req_insert(s->store, q);
    gds_unlock(s);
    if(st != GDS_OK)
        return gds_status_to_ua(st);
    if(q->state != GDS_REQ_PENDING) {
        if(byHook)
            audit_hook_approval(s, q);
        gds_worker_kick(s);
        return UA_STATUSCODE_GOOD;
    }
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    r = gds_load_app(s, &q->appId, &rec);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_approvals_raise(s, q, &rec.applicationUri);
    UA_ApplicationRecordDataType_clear(&rec);
    if(r != UA_STATUSCODE_GOOD) { /* no dialog: nobody could approve it */
        gds_lock(s);
        st = gds_store_req_set_state(s->store, &q->id, GDS_REQ_FAILED, NULL, r);
        gds_unlock(s);
        if(st != GDS_OK) /* stays Pending: its dialog is raised at the next start */
            fprintf(stderr, "opengds: failing a request without a dialog: %s\n",
                    gds_status_name(st));
    }
    return r;
}

/* ---- StartNewKeyPairRequest ---- */

/* §7.9.4: PFX and PEM shall be supported; nothing else is offered
 * (SupportedPrivateKeyFormats). */
static UA_StatusCode key_format_arg(const UA_Variant *v, gds_ca_key_format *f) {
    const UA_String *fmt = NULL;
    if(gds_arg_string(v, GDS_MAX_STRING, &fmt) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_String pfx = UA_STRING_STATIC("PFX"), pem = UA_STRING_STATIC("PEM");
    if(UA_String_equal(fmt, &pfx))
        *f = GDS_CA_KEY_PFX;
    else if(UA_String_equal(fmt, &pem))
        *f = GDS_CA_KEY_PEM;
    else
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return UA_STATUSCODE_GOOD;
}

/* SubjectName and DomainNames: checked for shape, then ignored; the record
 * decides both (§7.9.4 allows the GDS to ignore them; decision G5). */
static UA_StatusCode name_args(const UA_Variant *input) {
    const UA_String *subject = NULL;
    const void *names = NULL;
    size_t n = 0;
    if(gds_arg_string(&input[3], GDS_MAX_STRING, &subject) != UA_STATUSCODE_GOOD ||
       gds_arg_array(&input[4], &UA_TYPES[UA_TYPES_STRING], GDS_MAX_ARRAY_FIELD, &names, &n) !=
           UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode keypair_args(gds_server *s, void *sessionContext, size_t inputSize,
                                  const UA_Variant *input, gds_request *q, gds_ca_key_format *f,
                                  const UA_String **password) {
    const gds_session *ss = sessionContext;
    if(!ss || ss->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT; /* the password and key cross */
    UA_StatusCode r = gds_in_guid(s, inputSize, input, 0, &q->appId);
    if(r == UA_STATUSCODE_GOOD)
        r = check_app(s, sessionContext, &q->appId, 0);
    if(r == UA_STATUSCODE_GOOD)
        r = group_arg(s, inputSize, input, 1, &q->groupId);
    if(r == UA_STATUSCODE_GOOD)
        r = type_arg(s, inputSize, input, 2, &q->certType);
    if(r == UA_STATUSCODE_GOOD && inputSize < 7)
        r = UA_STATUSCODE_BADARGUMENTSMISSING;
    if(r == UA_STATUSCODE_GOOD)
        r = name_args(input);
    if(r == UA_STATUSCODE_GOOD)
        r = key_format_arg(&input[5], f);
    if(r == UA_STATUSCODE_GOOD &&
       gds_arg_string(&input[6], GDS_MAX_KEY_PASSWORD, password) != UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    if(r == UA_STATUSCODE_GOOD && gds_issuance_held(s, &q->appId))
        r = UA_STATUSCODE_BADREQUESTNOTALLOWED; /* held by the embedder (A13) */
    return r;
}

static GDS_METHOD(start_new_key_pair_request) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    gds_request q;
    memset(&q, 0, sizeof(q)); /* no CSR: a key pair request */
    gds_ca_key_format f = GDS_CA_KEY_PFX;
    const UA_String *password = NULL;
    UA_StatusCode r = keypair_args(s, sessionContext, inputSize, input, &q, &f, &password);
    DEFER_IF_DENIED(start_new_key_pair_request, r, q.appId);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(gds_guid_random(&q.id) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    gds_status st = gds_kp_add(s, &q.id, f, password);
    if(st == GDS_ETOOBIG)
        return UA_STATUSCODE_BADSERVERTOOBUSY;
    if(st != GDS_OK)
        return gds_status_to_ua(st);
    const method_call mc = METHOD_CALL(start_new_key_pair_request);
    r = submit_request(s, &mc, &q);
    if(r != UA_STATUSCODE_GOOD) { /* also when the hook runs it again */
        gds_kp_drop(s, &q.id);
        return r;
    }
    UA_NodeId rid = UA_NODEID_GUID(s->ns, q.id);
    return UA_Variant_setScalarCopy(&output[0], &rid, &UA_TYPES[UA_TYPES_NODEID]);
}

/* ---- FinishRequest ---- */

/* Issued -> Delivered. A key pair request hands its key over exactly once;
 * without it (a restart, a switchover) the request fails and the client
 * starts again (§7.9.5). Under storeLock. */
static gds_status deliver(gds_server *s, gds_request *q, gds_buf *key) {
    if(q->csr.len == 0 && gds_kp_take_key(s, &q->id, key) != GDS_OK) {
        q->state = GDS_REQ_FAILED;
        q->error = UA_STATUSCODE_BADREQUESTNOTALLOWED;
        return gds_store_req_set_state(s->store, &q->id, GDS_REQ_FAILED, NULL, q->error);
    }
    return gds_store_req_set_state(s->store, &q->id, GDS_REQ_DELIVERED, &q->cert,
                                   UA_STATUSCODE_GOOD);
}

/* key: the generated private key of a key pair request, else empty. */
static UA_StatusCode finish_outputs(gds_server *s, const gds_request *q, const gds_buf *key,
                                    UA_Variant *output) {
    UA_ByteString cert = {q->cert.len, q->cert.data}, pk = {key->len, key->data};
    const gds_buf *ib = gds_issuer_for(s, q->certType);
    UA_ByteString issuer = {ib->len, ib->data};
    UA_StatusCode r = UA_Variant_setScalarCopy(&output[0], &cert, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[1], &pk, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setArrayCopy(&output[2], &issuer, 1, &UA_TYPES[UA_TYPES_BYTESTRING]);
    return r;
}

static GDS_METHOD(finish_request) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    UA_Guid appId, reqId;
    UA_StatusCode r = gds_in_guid(s, inputSize, input, 0, &appId);
    if(r == UA_STATUSCODE_GOOD)
        r = check_app(s, sessionContext, &appId, 0);
    DEFER_IF_DENIED(finish_request, r, appId);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_in_guid(s, inputSize, input, 1, &reqId);
    if(r == UA_STATUSCODE_BADNOTFOUND)
        r = UA_STATUSCODE_BADINVALIDARGUMENT; /* §7.9.5: unknown requestId */
    if(r != UA_STATUSCODE_GOOD)
        return r;
    gds_request q;
    memset(&q, 0, sizeof(q));
    gds_buf key = {0};
    gds_lock(s);
    gds_status st = gds_store_req_get(s->store, &reqId, &q);
    if(st == GDS_OK && !UA_Guid_equal(&q.appId, &appId))
        st = GDS_ENOTFOUND; /* another application's request */
    if(st == GDS_OK && q.state == GDS_REQ_ISSUED)
        st = deliver(s, &q, &key);
    gds_unlock(s);
    if(st == GDS_ENOTFOUND)
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    else if(st != GDS_OK)
        r = gds_status_to_ua(st);
    else if(q.state == GDS_REQ_RECEIVED || q.state == GDS_REQ_PENDING)
        r = UA_STATUSCODE_BADNOTHINGTODO; /* not approved or not signed yet: poll again */
    else if(q.state == GDS_REQ_FAILED)
        r = q.error ? q.error : UA_STATUSCODE_BADREQUESTNOTALLOWED;
    else
        r = finish_outputs(s, &q, &key, output);
    gds_buf_free_secret(&key);
    gds_request_clear(&q);
    return r;
}

/* ---- GetCertificateGroups / GetTrustList / GetCertificateStatus ---- */

static GDS_METHOD(get_certificate_groups) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    UA_Guid appId;
    UA_StatusCode r = gds_in_guid(s, inputSize, input, 0, &appId);
    if(r == UA_STATUSCODE_GOOD)
        r = check_app(s, sessionContext, &appId, GDS_ROLE_DISCOVERY_ADMIN);
    DEFER_IF_DENIED(get_certificate_groups, r, appId);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_NodeId g =
        UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    return UA_Variant_setArrayCopy(&output[0], &g, 1, &UA_TYPES[UA_TYPES_NODEID]);
}

static GDS_METHOD(get_trust_list) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    UA_Guid appId;
    UA_UInt32 group = 0;
    UA_StatusCode r = gds_in_guid(s, inputSize, input, 0, &appId);
    if(r == UA_STATUSCODE_GOOD)
        r = check_app(s, sessionContext, &appId, 0);
    DEFER_IF_DENIED(get_trust_list, r, appId);
    if(r == UA_STATUSCODE_GOOD)
        r = group_arg(s, inputSize, input, 1, &group);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_NodeId tl =
        UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST);
    return UA_Variant_setScalarCopy(&output[0], &tl, &UA_TYPES[UA_TYPES_NODEID]);
}

/* updateRequired: no certificate of this group and type yet, or the newest
 * one has expired. */
static GDS_METHOD(get_certificate_status) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    UA_Guid appId;
    UA_UInt32 group = 0, type = 0;
    UA_StatusCode r = gds_in_guid(s, inputSize, input, 0, &appId);
    if(r == UA_STATUSCODE_GOOD)
        r = check_app(s, sessionContext, &appId, 0);
    DEFER_IF_DENIED(get_certificate_status, r, appId);
    if(r == UA_STATUSCODE_GOOD)
        r = group_arg(s, inputSize, input, 1, &group);
    if(r == UA_STATUSCODE_GOOD)
        r = type_arg(s, inputSize, input, 2, &type);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    gds_buf der = {0};
    int64_t notBefore = 0, notAfter = 0;
    gds_lock(s);
    gds_status st = gds_store_cert_latest(s->store, &appId, group, type, &der, &notAfter);
    gds_unlock(s);
    gds_buf_free(&der);
    if(st != GDS_OK && st != GDS_ENOTFOUND)
        return gds_status_to_ua(st);
    (void)notBefore;
    int64_t now = (int64_t)time(NULL);
    UA_Boolean update = st == GDS_ENOTFOUND || notAfter <= now;
    return UA_Variant_setScalarCopy(&output[0], &update, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

/* ---- GetCertificates (§7.9.8) ---- */

/* The application CertificateTypes of 12 §7.8.4 a certificate may have */
static const UA_UInt32 appCertTypes[] = {
    UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE,
    UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCBRAINPOOLP256R1APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCBRAINPOOLP384R1APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCCURVE25519APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCCURVE448APPLICATIONCERTIFICATETYPE,
};

/* The certificate assigned to each CertificateType: the newest unrevoked
 * one, if it has not expired ("only Certificates that are currently
 * valid"). A null CertificateGroupId means every group of the application;
 * DefaultApplicationGroup is the only one so far. */
static GDS_METHOD(get_certificates) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    UA_Guid appId;
    UA_UInt32 group = 0;
    UA_StatusCode r = gds_in_guid(s, inputSize, input, 0, &appId);
    if(r == UA_STATUSCODE_GOOD)
        r = check_app(s, sessionContext, &appId, 0);
    DEFER_IF_DENIED(get_certificates, r, appId);
    if(r == UA_STATUSCODE_GOOD)
        r = group_arg(s, inputSize, input, 1, &group);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_NodeId types[GDS_ARRAY_SIZE(appCertTypes)];
    UA_ByteString certs[GDS_ARRAY_SIZE(appCertTypes)];
    size_t n = 0;
    int64_t now = (int64_t)time(NULL);
    gds_status st = GDS_OK;
    gds_lock(s);
    for(size_t i = 0; st == GDS_OK && i < GDS_ARRAY_SIZE(appCertTypes); i++) {
        gds_buf der = {0};
        int64_t notAfter = 0;
        st = gds_store_cert_latest(s->store, &appId, group, appCertTypes[i], &der, &notAfter);
        if(st == GDS_ENOTFOUND) {
            st = GDS_OK;
            continue;
        }
        if(st == GDS_OK && notAfter > now) {
            types[n] = UA_NODEID_NUMERIC(0, appCertTypes[i]);
            certs[n].data = der.data; /* owned until the copy below */
            certs[n++].length = der.len;
        } else {
            gds_buf_free(&der);
        }
    }
    gds_unlock(s);
    if(st != GDS_OK)
        r = gds_status_to_ua(st);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setArrayCopy(&output[0], n ? (void *)types : UA_EMPTY_ARRAY_SENTINEL, n,
                                    &UA_TYPES[UA_TYPES_NODEID]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setArrayCopy(&output[1], n ? (void *)certs : UA_EMPTY_ARRAY_SENTINEL, n,
                                    &UA_TYPES[UA_TYPES_BYTESTRING]);
    for(size_t i = 0; i < n; i++) {
        gds_buf b = {certs[i].data, certs[i].length};
        gds_buf_free(&b);
    }
    return r;
}

/* ---- CheckRevocationStatus (§7.9.11) ---- */

/* The serial as the store keeps it: big-endian, without leading zeros */
static gds_status serial_of(const X509 *x, gds_buf *out) {
    BIGNUM *bn = ASN1_INTEGER_to_BN(X509_get0_serialNumber(x), NULL);
    int len = bn ? BN_num_bytes(bn) : -1;
    unsigned char b[GDS_MAX_SERIAL_SIZE];
    gds_status r = GDS_ECRYPTO;
    if(len > 0 && (size_t)len <= sizeof(b) && BN_bn2bin(bn, b) == len)
        r = gds_buf_dup(b, (size_t)len, out);
    BN_free(bn);
    return r;
}

static X509 *parse_der(const gds_buf *b) {
    const unsigned char *p = b->data;
    X509 *x = b->len ? d2i_X509(NULL, &p, (long)b->len) : NULL;
    if(x && p != b->data + b->len) {
        X509_free(x);
        x = NULL;
    }
    return x;
}

/* Revoked in the store or on the CA's current CRL; *validity is the CRL's
 * nextUpdate (when to ask again), 0 if unknown. */
static UA_StatusCode revocation(gds_server *s, gds_ca_issuer issuer, X509 *cert,
                                UA_DateTime *validity) {
    gds_buf serial = {0}, crlDer = {0};
    bool revoked = false;
    gds_status st = serial_of(cert, &serial);
    if(st == GDS_OK) {
        gds_lock(s);
        st = gds_store_cert_is_revoked(s->store, &serial, &revoked);
        gds_unlock(s);
    }
    gds_buf_free(&serial);
    if(st == GDS_OK)
        st = gds_ca_get_issuer_crl(s->ca, issuer, &crlDer); /* outside storeLock */
    if(st != GDS_OK) {
        gds_buf_free(&crlDer);
        return UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN;
    }
    const unsigned char *p = crlDer.data;
    X509_CRL *crl = d2i_X509_CRL(NULL, &p, (long)crlDer.len);
    X509_REVOKED *entry = NULL;
    if(crl && X509_CRL_get0_by_cert(crl, &entry, cert) == 1)
        revoked = true;
    const ASN1_TIME *next = crl ? X509_CRL_get0_nextUpdate(crl) : NULL;
    struct tm tm;
    if(next && ASN1_TIME_to_tm(next, &tm) == 1)
        *validity = UA_DateTime_fromUnixTime((UA_Int64)timegm(&tm));
    X509_CRL_free(crl);
    gds_buf_free(&crlDer);
    if(!crl)
        return UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN;
    return revoked ? UA_STATUSCODE_BADCERTIFICATEREVOKED : UA_STATUSCODE_GOOD;
}

/* The first error found: Bad_CertificateInvalid for a certificate that does
 * not parse or whose signature does not verify ("The CertificateManager
 * shall check the signature"), Bad_CertificateRevocationUnknown for one
 * this CA did not issue, Bad_CertificateRevoked, else Good. Any session on
 * an authenticated channel may call it; opengdsd has no other kind. */
static GDS_METHOD(check_revocation_status) {
    GDS_METHOD_UNUSED;
    (void)sessionContext;
    gds_server *s = gds_ctx(methodContext);
    if(inputSize < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const UA_ByteString *in = NULL;
    if(gds_arg_bytes(&input[0], GDS_MAX_CERT_SIZE, &in) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    gds_buf der = {in->data, in->length};
    X509 *cert = parse_der(&der), *ca = NULL;
    gds_ca_issuer issuer = GDS_CA_ISSUER_RSA;
    for(unsigned i = 0; cert && !ca && i < GDS_CA_ISSUERS; i++) { /* the issuer by name */
        ca = parse_der(&s->issuerCert[i]);
        issuer = (gds_ca_issuer)i; // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange): i < GDS_CA_ISSUERS
        if(ca && X509_NAME_cmp(X509_get_issuer_name(cert), X509_get_subject_name(ca)) != 0) {
            X509_free(ca);
            ca = NULL;
        }
    }
    EVP_PKEY *caKey = ca ? X509_get0_pubkey(ca) : NULL;
    UA_StatusCode status;
    UA_DateTime validity = 0; /* DateTime.MinValue: unknown */
    if(cert && !caKey)
        status = UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN; /* not issued by this CA */
    else if(!cert || X509_verify(cert, caKey) != 1)
        status = UA_STATUSCODE_BADCERTIFICATEINVALID;
    else
        status = revocation(s, issuer, cert, &validity);
    X509_free(cert);
    X509_free(ca);
    UA_StatusCode r = UA_Variant_setScalarCopy(&output[0], &status, &UA_TYPES[UA_TYPES_STATUSCODE]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[1], &validity, &UA_TYPES[UA_TYPES_DATETIME]);
    return r;
}

/* GetCertificates and CheckRevocationStatus are Optional (§7.9.8,
 * §7.9.11): the nodeset does not create them on the Directory object. */
static UA_StatusCode add_optional_nodes(gds_server *s) {
    static const gds_method_arg gcIn[] = {{"ApplicationId", UA_NS0ID_NODEID, false},
                                          {"CertificateGroupId", UA_NS0ID_NODEID, false}};
    static const gds_method_arg gcOut[] = {{"CertificateTypeIds", UA_NS0ID_NODEID, true},
                                           {"Certificates", UA_NS0ID_BYTESTRING, true}};
    static const gds_method_arg crIn[] = {{"Certificate", UA_NS0ID_BYTESTRING, false}};
    static const gds_method_arg crOut[] = {{"CertificateStatus", UA_NS0ID_STATUSCODE, false},
                                           {"ValidityTime", UA_NS0ID_UTCTIME, false}};
    UA_StatusCode r = gds_add_directory_method(s, UA_GDSID_DIRECTORY_GETCERTIFICATES,
                                               "GetCertificates", gcIn, 2, gcOut, 2);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_add_directory_method(s, UA_GDSID_DIRECTORY_CHECKREVOCATIONSTATUS,
                                     "CheckRevocationStatus", crIn, 1, crOut, 2);
    return r;
}

UA_StatusCode gds_certmgr_install(gds_server *s) {
    static const gds_method_entry m[] = {
        {UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, start_signing_request},
        {UA_GDSID_DIRECTORY_STARTNEWKEYPAIRREQUEST, start_new_key_pair_request},
        {UA_GDSID_DIRECTORY_FINISHREQUEST, finish_request},
        {UA_GDSID_DIRECTORY_GETCERTIFICATEGROUPS, get_certificate_groups},
        {UA_GDSID_DIRECTORY_GETTRUSTLIST, get_trust_list},
        {UA_GDSID_DIRECTORY_GETCERTIFICATESTATUS, get_certificate_status},
        {UA_GDSID_DIRECTORY_GETCERTIFICATES, get_certificates},
        {UA_GDSID_DIRECTORY_CHECKREVOCATIONSTATUS, check_revocation_status},
    };
    UA_StatusCode r = add_optional_nodes(s);
    if(r == UA_STATUSCODE_GOOD)
        r = set_group_types(s);
    return r == UA_STATUSCODE_GOOD ? gds_install_methods(s, m, GDS_ARRAY_SIZE(m)) : r;
}

/* ---- signing worker ---- */

static bool transient(gds_status r) {
    return r == GDS_EREMOTE || r == GDS_EIO || r == GDS_ENOMEM || r == GDS_ENOTLEADER;
}

/* The CA call: sign the CSR, or (no CSR) generate a key pair with the
 * format and password that StartNewKeyPairRequest left in memory. */
static gds_status issue(gds_server *s, const gds_request *q, const gds_ca_subject *subj,
                        gds_ca_issued *issued, gds_buf *key) {
    if(q->csr.len > 0)
        return gds_ca_sign_csr(s->ca, subj, &q->csr, issued);
    gds_ca_keyreq kr = {GDS_CA_KEY_PFX, NULL};
    gds_buf pw = {0};
    gds_status r = gds_kp_password(s, &q->id, &kr.format, &pw);
    kr.password = &pw;
    if(r == GDS_OK)
        r = gds_ca_new_key_pair(s->ca, subj, &kr, issued, key);
    gds_buf_free_secret(&pw);
    return r;
}

/* Store an issued certificate; a generated key goes to memory first, so
 * FinishRequest never sees Issued without it. Under storeLock. */
static gds_status store_issued(gds_server *s, const gds_request *q, const gds_ca_issued *issued,
                               gds_buf *key) {
    bool keyPair = q->csr.len == 0;
    gds_status w = keyPair ? gds_kp_set_key(s, &q->id, key) : GDS_OK;
    if(w == GDS_OK)
        w = gds_store_cert_add(s->store, &q->appId, q->groupId, q->certType, &issued->serial,
                               &issued->der, issued->notBefore, issued->notAfter);
    if(w == GDS_OK)
        w = gds_store_req_set_state(s->store, &q->id, GDS_REQ_ISSUED, &issued->der,
                                    UA_STATUSCODE_GOOD);
    if(w != GDS_OK) {
        fprintf(stderr, "opengds: storing an issued certificate failed: %s\n",
                gds_status_name(w));
        if(keyPair)
            gds_kp_drop(s, &q->id);
    }
    return w;
}

/* Record a refusal. A key pair request whose secrets are gone (a restart,
 * a switchover) fails with Bad_RequestNotAllowed and the client starts
 * again (§7.9.5). Under storeLock. */
static gds_status store_failed(gds_server *s, const gds_request *q, UA_StatusCode code) {
    if(q->csr.len == 0)
        gds_kp_drop(s, &q->id);
    return gds_store_req_set_state(s->store, &q->id, GDS_REQ_FAILED, NULL, code);
}

/* Sign the oldest Received request. Returns true if there may be more. */
static bool process_one(gds_server *s) {
    gds_request q;
    memset(&q, 0, sizeof(q));
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    gds_lock(s);
    gds_status r = gds_store_req_next_received(s->store, &q);
    if(r == GDS_OK)
        r = gds_store_app_get(s->store, &q.appId, &rec);
    gds_unlock(s);
    if(r != GDS_OK) {
        gds_request_clear(&q);
        return false;
    }
    gds_ca_subject subj = {&q.id, &rec, q.groupId, q.certType};
    gds_ca_issued issued;
    memset(&issued, 0, sizeof(issued));
    gds_buf key = {0};
    bool held = gds_issuance_held(s, &q.appId); /* A13: held after it was stored */
    r = held ? GDS_EDENIED : issue(s, &q, &subj, &issued, &key);
    UA_StatusCode code = gds_status_to_ua(r);
    if(held || (r == GDS_ENOTFOUND && q.csr.len == 0))
        code = UA_STATUSCODE_BADREQUESTNOTALLOWED;
    bool more = true;
    gds_lock(s);
    if(r == GDS_OK) {
        more = store_issued(s, &q, &issued, &key) == GDS_OK;
    } else if(!held && transient(r)) {
        fprintf(stderr, "opengds: CA unavailable (%s), retrying later\n", gds_status_name(r));
        more = false; /* keep the request Received */
    } else if(store_failed(s, &q, code) != GDS_OK) {
        more = false;
    }
    gds_unlock(s);
    gds_buf_free_secret(&key);
    gds_ca_issued_clear(&issued);
    UA_ApplicationRecordDataType_clear(&rec);
    gds_request_clear(&q);
    return more;
}

static void *worker_main(void *p) {
    gds_server *s = p;
    for(;;) {
        pthread_mutex_lock(&s->workLock);
        if(!s->workPending && !s->workStop) {
            struct timespec until;
            clock_gettime(CLOCK_REALTIME, &until);
            until.tv_sec += WORKER_IDLE_SECONDS; /* also picks up requests from before a restart */
            (void)pthread_cond_timedwait(&s->workCond, &s->workLock, &until);
        }
        bool stop = s->workStop;
        s->workPending = false;
        pthread_mutex_unlock(&s->workLock);
        if(stop)
            break;
        while(process_one(s)) {
            pthread_mutex_lock(&s->workLock);
            stop = s->workStop;
            pthread_mutex_unlock(&s->workLock);
            if(stop)
                return NULL;
        }
    }
    return NULL;
}

gds_status gds_worker_start(gds_server *s) {
    if(pthread_create(&s->worker, NULL, worker_main, s) != 0)
        return GDS_ENOMEM;
    s->workerStarted = true;
    return GDS_OK;
}

void gds_worker_kick(gds_server *s) {
    pthread_mutex_lock(&s->workLock);
    s->workPending = true;
    pthread_cond_signal(&s->workCond);
    pthread_mutex_unlock(&s->workLock);
}

void gds_worker_stop(gds_server *s) {
    if(!s->workerStarted)
        return;
    pthread_mutex_lock(&s->workLock);
    s->workStop = true;
    pthread_cond_signal(&s->workCond);
    pthread_mutex_unlock(&s->workLock);
    pthread_join(s->worker, NULL);
    s->workerStarted = false;
}
