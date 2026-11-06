/* OpenGDS - CertificateManager methods (OPC 10000-12 §7.9): StartSigningRequest,
 * FinishRequest, GetCertificateGroups, GetTrustList, GetCertificateStatus,
 * and the signing worker.
 *
 * Decision G7: StartSigningRequest checks and stores the request and
 * returns at once; a background worker signs it through the CA slot
 * (opengds-signer); FinishRequest only reads the store. Requests are
 * approved on arrival in T1 (autoApprove).
 * Access: CertificateAuthorityAdmin, or the application itself (its client
 * certificate carries the record's ApplicationUri, §7.2).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
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

/* The application must exist, and the caller must be a CA admin or it. */
static UA_StatusCode check_app(gds_server *s, void *sessionContext, const UA_Guid *appId,
                               unsigned extraRoles) {
    UA_ApplicationRecordDataType rec;
    UA_StatusCode r = gds_load_app(s, appId, &rec);
    if(r == UA_STATUSCODE_GOOD &&
       !gds_session_has(sessionContext, GDS_ROLE_CERTIFICATE_AUTHORITY_ADMIN | extraRoles) &&
       !gds_session_is_app(sessionContext, &rec.applicationUri))
        r = UA_STATUSCODE_BADUSERACCESSDENIED;
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

/* Null means the group's default type, RsaSha256ApplicationCertificateType. */
static UA_StatusCode type_arg(size_t inputSize, const UA_Variant *input, size_t i, UA_UInt32 *type) {
    const UA_NodeId *t = NULL;
    UA_StatusCode r = gds_in_nodeid(inputSize, input, i, &t);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(UA_NodeId_isNull(t)) {
        *type = UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE;
        return UA_STATUSCODE_GOOD;
    }
    if(t->namespaceIndex != 0 || t->identifierType != UA_NODEIDTYPE_NUMERIC)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    *type = t->identifier.numeric;
    return UA_STATUSCODE_GOOD;
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

static GDS_METHOD(start_signing_request) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    UA_Guid appId;
    UA_UInt32 group = 0, type = 0;
    const UA_ByteString *csr = NULL;
    UA_StatusCode r = gds_in_guid(s, inputSize, input, 0, &appId);
    if(r == UA_STATUSCODE_GOOD)
        r = check_app(s, sessionContext, &appId, 0);
    if(r == UA_STATUSCODE_GOOD)
        r = group_arg(s, inputSize, input, 1, &group);
    if(r == UA_STATUSCODE_GOOD)
        r = type_arg(inputSize, input, 2, &type);
    if(r == UA_STATUSCODE_GOOD && inputSize < 4)
        r = UA_STATUSCODE_BADARGUMENTSMISSING;
    if(r == UA_STATUSCODE_GOOD && gds_arg_bytes(&input[3], GDS_MAX_CSR_SIZE, &csr) != UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    if(r == UA_STATUSCODE_GOOD && !csr_ok(csr))
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    if(r != UA_STATUSCODE_GOOD)
        return r;
    gds_request q;
    memset(&q, 0, sizeof(q));
    if(gds_guid_random(&q.id) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    q.appId = appId;
    q.groupId = group;
    q.certType = type;
    q.state = GDS_REQ_RECEIVED;
    q.csr.data = csr->data; /* borrowed for the insert */
    q.csr.len = csr->length;
    gds_lock(s);
    gds_status st = gds_store_req_insert(s->store, &q);
    gds_unlock(s);
    if(st != GDS_OK)
        return gds_status_to_ua(st);
    gds_worker_kick(s);
    UA_NodeId rid = UA_NODEID_GUID(s->ns, q.id);
    return UA_Variant_setScalarCopy(&output[0], &rid, &UA_TYPES[UA_TYPES_NODEID]);
}

/* ---- FinishRequest ---- */

static UA_StatusCode finish_outputs(gds_server *s, const gds_request *q, UA_Variant *output) {
    UA_ByteString cert = {q->cert.len, q->cert.data}, none = UA_BYTESTRING_NULL;
    UA_ByteString issuer = {s->caCert.len, s->caCert.data};
    UA_StatusCode r = UA_Variant_setScalarCopy(&output[0], &cert, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD) /* a CSR request has no private key to return */
        r = UA_Variant_setScalarCopy(&output[1], &none, &UA_TYPES[UA_TYPES_BYTESTRING]);
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
    if(r == UA_STATUSCODE_GOOD)
        r = gds_in_guid(s, inputSize, input, 1, &reqId);
    if(r == UA_STATUSCODE_BADNOTFOUND)
        r = UA_STATUSCODE_BADINVALIDARGUMENT; /* §7.9.6: unknown requestId */
    if(r != UA_STATUSCODE_GOOD)
        return r;
    gds_request q;
    memset(&q, 0, sizeof(q));
    gds_lock(s);
    gds_status st = gds_store_req_get(s->store, &reqId, &q);
    if(st == GDS_OK && !UA_Guid_equal(&q.appId, &appId))
        st = GDS_ENOTFOUND; /* another application's request */
    if(st == GDS_OK && q.state == GDS_REQ_ISSUED)
        st = gds_store_req_set_state(s->store, &reqId, GDS_REQ_DELIVERED, &q.cert,
                                     UA_STATUSCODE_GOOD);
    gds_unlock(s);
    if(st == GDS_ENOTFOUND)
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    else if(st != GDS_OK)
        r = gds_status_to_ua(st);
    else if(q.state == GDS_REQ_RECEIVED)
        r = UA_STATUSCODE_BADNOTHINGTODO; /* not signed yet: poll again */
    else if(q.state == GDS_REQ_FAILED)
        r = q.error ? q.error : UA_STATUSCODE_BADREQUESTNOTALLOWED;
    else
        r = finish_outputs(s, &q, output);
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
    if(r == UA_STATUSCODE_GOOD)
        r = group_arg(s, inputSize, input, 1, &group);
    if(r == UA_STATUSCODE_GOOD)
        r = type_arg(inputSize, input, 2, &type);
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

UA_StatusCode gds_certmgr_install(gds_server *s) {
    static const gds_method_entry m[] = {
        {UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, start_signing_request},
        {UA_GDSID_DIRECTORY_FINISHREQUEST, finish_request},
        {UA_GDSID_DIRECTORY_GETCERTIFICATEGROUPS, get_certificate_groups},
        {UA_GDSID_DIRECTORY_GETTRUSTLIST, get_trust_list},
        {UA_GDSID_DIRECTORY_GETCERTIFICATESTATUS, get_certificate_status},
    };
    return gds_install_methods(s, m, GDS_ARRAY_SIZE(m));
}

/* ---- signing worker ---- */

static bool transient(gds_status r) {
    return r == GDS_EREMOTE || r == GDS_EIO || r == GDS_ENOMEM || r == GDS_ENOTLEADER;
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
    r = gds_ca_sign_csr(s->ca, &subj, &q.csr, &issued);
    bool more = true;
    gds_lock(s);
    if(r == GDS_OK) {
        gds_status w = gds_store_cert_add(s->store, &q.appId, q.groupId, q.certType,
                                          &issued.serial, &issued.der, issued.notBefore,
                                          issued.notAfter);
        if(w == GDS_OK)
            w = gds_store_req_set_state(s->store, &q.id, GDS_REQ_ISSUED, &issued.der,
                                        UA_STATUSCODE_GOOD);
        if(w != GDS_OK)
            fprintf(stderr, "opengds: storing an issued certificate failed: %s\n",
                    gds_status_name(w));
        more = w == GDS_OK;
    } else if(transient(r)) {
        fprintf(stderr, "opengds: CA unavailable (%s), retrying later\n", gds_status_name(r));
        more = false; /* keep the request Received */
    } else if(gds_store_req_set_state(s->store, &q.id, GDS_REQ_FAILED, NULL, gds_status_to_ua(r)) !=
              GDS_OK) {
        more = false;
    }
    gds_unlock(s);
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
        while(s->autoApprove && process_one(s)) {
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
