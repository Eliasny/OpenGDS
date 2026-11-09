/* OpenGDS - the Directory and the CertificateManager for embedders (UASM
 * ask A13, issue #81): register an application, hold back its issuance,
 * sign a CSR and read a trust list without the Part 12 methods, for a
 * Part 21 Registrar (OPC 10000-21 §7.2, §7.3, §9.2.8). gds_plugin.h has
 * the contract.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/ids.h"
#include "common/limits.h"
#include "gds_internal.h"
#include "common/banned.h"

#define POLL_MS 20u
#define MAX_ACTOR 256
#define SEVERITY_CHANGE 500
#define MAX_HOLDS 65536

/* ---- shared ---- */

static bool actor_ok(const char *actor) {
    size_t n = actor ? strnlen(actor, MAX_ACTOR + 1) : 0;
    return n > 0 && n <= MAX_ACTOR;
}

static gds_status standby(gds_server *s) {
    return gds_server_role(s) == GDS_NODE_STANDBY ? GDS_ENOTLEADER : GDS_OK;
}

/* An ApplicationId: a GUID NodeId in the GDS namespace. */
static bool app_guid(const gds_server *s, const UA_NodeId *id, UA_Guid *out) {
    if(!id || id->namespaceIndex != s->ns || id->identifierType != UA_NODEIDTYPE_GUID)
        return false;
    *out = id->identifier.guid;
    return true;
}

gds_status gds_method_audit(gds_server *s, const char *actor, UA_UInt32 type, UA_UInt32 method,
                            unsigned gdsRole, const gds_event_field *extra, size_t nExtra,
                            const UA_Variant *args, size_t nArgs, bool ok, const char *msg) {
    gds_event_field f[4];
    size_t n = 0;
    UA_NodeId methodId = UA_NODEID_NUMERIC(s->ns, method);
    f[n].nsIndex = 0;
    f[n].name = "MethodId";
    UA_Variant_setScalar(&f[n].value, &methodId, &UA_TYPES[UA_TYPES_NODEID]);
    n++;
    f[n].nsIndex = 0;
    f[n].name = "InputArguments";
    UA_Variant_setArray(&f[n].value, (void *)(uintptr_t)args, nArgs, &UA_TYPES[UA_TYPES_VARIANT]);
    n++;
    for(size_t i = 0; i < nExtra && n < GDS_ARRAY_SIZE(f); i++)
        f[n++] = extra[i];
    UA_NodeId visible[2] = {UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN),
                            UA_NODEID_NUMERIC(s->ns, gdsRole)};
    gds_audit_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.abi_major = GDS_PLUGIN_ABI_MAJOR;
    ev.abi_minor = GDS_PLUGIN_ABI_MINOR;
    ev.struct_size = sizeof(ev);
    ev.eventType = UA_NODEID_NUMERIC(s->ns, type);
    ev.severity = SEVERITY_CHANGE;
    ev.message = msg;
    ev.status = ok;
    ev.fields = f;
    ev.fieldsSize = n;
    ev.visibleTo = visible;
    ev.visibleToSize = 2;
    return gds_audit_raise(s, actor, &ev, NULL);
}

/* ---- RegisterApplication ---- */

gds_status gds_server_register_application(gds_server *s, const char *actor,
                                           const UA_ApplicationRecordDataType *rec,
                                           UA_NodeId *appId, bool *created) {
    if(!s || !rec || !appId || !created || !actor_ok(actor))
        return GDS_EINVAL;
    *created = false;
    UA_NodeId_init(appId);
    gds_status st = standby(s);
    if(st != GDS_OK)
        return st;
    if(gds_validate_record(rec) != UA_STATUSCODE_GOOD)
        return GDS_EINVAL;
    UA_ApplicationRecordDataType *found = NULL;
    size_t n = 0;
    UA_Guid id;
    gds_lock(s);
    st = gds_store_app_find_uri(s->store, &rec->applicationUri, 1, &found, &n);
    if(st == GDS_OK && n > 0) {
        id = found[0].applicationId.identifier.guid;
    } else if(st == GDS_OK) {
        st = gds_guid_random(&id);
        if(st == GDS_OK)
            st = gds_store_app_insert(s->store, &id, rec);
        *created = st == GDS_OK;
    }
    gds_unlock(s);
    if(found)
        UA_Array_delete(found, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    if(st != GDS_OK)
        return st;
    *appId = UA_NODEID_GUID(s->ns, id);
    if(!*created)
        return GDS_OK;
    UA_Variant arg;
    UA_Variant_setScalar(&arg, (void *)(uintptr_t)rec,
                         &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    gds_status a = gds_method_audit(s, actor, UA_GDSID_APPLICATIONREGISTRATIONCHANGEDAUDITEVENTTYPE,
                         UA_GDSID_DIRECTORY_REGISTERAPPLICATION, UA_GDSID_WELLKNOWNROLE_DISCOVERYADMIN,
                         NULL, 0, &arg, 1, true, "application registered");
    if(a != GDS_OK)
        fprintf(stderr, "opengds: audit of a registration: %s\n", gds_status_name(a));
    return GDS_OK;
}

/* ---- issuance holds ---- */

bool gds_issuance_held(gds_server *s, const UA_Guid *appId) {
    bool held = false;
    pthread_mutex_lock(&s->holdLock);
    for(size_t i = 0; i < s->nHolds && !held; i++)
        held = UA_Guid_equal(&s->holds[i], appId);
    pthread_mutex_unlock(&s->holdLock);
    return held;
}

void gds_holds_free(gds_server *s) {
    free(s->holds);
    s->holds = NULL;
    s->nHolds = s->capHolds = 0;
}

static gds_status hold_add(gds_server *s, const UA_Guid *id) {
    gds_status st = GDS_OK;
    pthread_mutex_lock(&s->holdLock);
    bool have = false;
    for(size_t i = 0; i < s->nHolds && !have; i++)
        have = UA_Guid_equal(&s->holds[i], id);
    if(!have && s->nHolds == s->capHolds) {
        size_t cap = s->capHolds ? s->capHolds * 2 : 16;
        UA_Guid *h = cap <= MAX_HOLDS ? realloc(s->holds, cap * sizeof(*h)) : NULL;
        if(h) {
            s->holds = h;
            s->capHolds = cap;
        } else {
            st = cap <= MAX_HOLDS ? GDS_ENOMEM : GDS_ETOOBIG;
        }
    }
    if(!have && st == GDS_OK)
        s->holds[s->nHolds++] = *id;
    pthread_mutex_unlock(&s->holdLock);
    return st;
}

static void hold_remove(gds_server *s, const UA_Guid *id) {
    pthread_mutex_lock(&s->holdLock);
    for(size_t i = 0; i < s->nHolds; i++) {
        if(UA_Guid_equal(&s->holds[i], id)) {
            s->holds[i] = s->holds[--s->nHolds];
            break;
        }
    }
    pthread_mutex_unlock(&s->holdLock);
}

gds_status gds_server_set_issuance_allowed(gds_server *s, const UA_NodeId *appId, bool allowed) {
    UA_Guid id;
    if(!s || !app_guid(s, appId, &id))
        return GDS_EINVAL;
    if(allowed) {
        hold_remove(s, &id);
        return GDS_OK;
    }
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    gds_lock(s);
    gds_status st = gds_store_app_get(s->store, &id, &rec);
    gds_unlock(s);
    UA_ApplicationRecordDataType_clear(&rec);
    return st == GDS_OK ? hold_add(s, &id) : st;
}

/* ---- signing ---- */

static bool csr_ok(const UA_ByteString *csr) {
    if(!csr || csr->length == 0 || csr->length > GDS_MAX_CSR_SIZE)
        return false;
    const unsigned char *p = csr->data;
    X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)csr->length);
    EVP_PKEY *pk = req && p == csr->data + csr->length ? X509_REQ_get_pubkey(req) : NULL;
    bool ok = pk && X509_REQ_verify(req, pk) == 1;
    EVP_PKEY_free(pk);
    X509_REQ_free(req);
    return ok;
}

static bool group_ok(const gds_server *s, const UA_NodeId *g) {
    UA_NodeId def =
        UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    return !g || UA_NodeId_isNull(g) || UA_NodeId_equal(g, &def);
}


static void sleep_ms(uint32_t ms) {
    struct timespec ts = {(time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L};
    (void)nanosleep(&ts, NULL);
}

/* Waits until the worker has left the request Received. */
static gds_status wait_signed(gds_server *s, const UA_Guid *id, uint32_t timeoutMs,
                              gds_request *q) {
    for(uint32_t waited = 0;; waited += POLL_MS) {
        gds_request_clear(q);
        memset(q, 0, sizeof(*q));
        gds_lock(s);
        gds_status st = gds_store_req_get(s->store, id, q);
        gds_unlock(s);
        if(st != GDS_OK)
            return st;
        if(q->state != GDS_REQ_RECEIVED)
            return GDS_OK;
        if(waited >= timeoutMs)
            return GDS_EREMOTE;
        gds_worker_kick(s);
        sleep_ms(POLL_MS);
    }
}

gds_status gds_cert_audit(gds_server *s, const char *actor, UA_UInt32 type, UA_UInt32 method,
                          UA_UInt32 certType, const UA_Variant *args, size_t nArgs, bool ok,
                          const char *msg) {
    UA_NodeId group =
        UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId ct = UA_NODEID_NUMERIC(0, certType);
    gds_event_field f[2];
    f[0].nsIndex = s->ns;
    f[0].name = "CertificateGroup";
    UA_Variant_setScalar(&f[0].value, &group, &UA_TYPES[UA_TYPES_NODEID]);
    f[1].nsIndex = s->ns;
    f[1].name = "CertificateType";
    UA_Variant_setScalar(&f[1].value, &ct, &UA_TYPES[UA_TYPES_NODEID]);
    return gds_method_audit(s, actor, type, method, UA_GDSID_WELLKNOWNROLE_CERTIFICATEAUTHORITYADMIN,
                            f, 2, args, nArgs, ok, msg);
}

typedef struct {
    UA_Guid app;
    UA_UInt32 type;
    const UA_ByteString *csr;
} sign_input;

static gds_status sign_checks(gds_server *s, const char *actor, const UA_NodeId *appId,
                              const UA_NodeId *groupId, const UA_NodeId *typeId,
                              const UA_ByteString *csr, sign_input *in) {
    if(!actor_ok(actor) || !app_guid(s, appId, &in->app) || !group_ok(s, groupId) ||
       !gds_group_type(s, typeId, &in->type) || !csr_ok(csr))
        return GDS_EINVAL;
    in->csr = csr;
    gds_status st = standby(s);
    if(st != GDS_OK)
        return st;
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    gds_lock(s);
    st = gds_store_app_get(s->store, &in->app, &rec);
    gds_unlock(s);
    UA_ApplicationRecordDataType_clear(&rec);
    if(st == GDS_OK && gds_issuance_held(s, &in->app))
        st = GDS_EDENIED;
    return st;
}

static gds_status deliver(gds_server *s, const gds_request *q, UA_ByteString *cert,
                          UA_ByteString **issuers, size_t *nIssuers) {
    gds_lock(s);
    gds_status st = gds_store_req_set_state(s->store, &q->id, GDS_REQ_DELIVERED, &q->cert,
                                            UA_STATUSCODE_GOOD);
    gds_unlock(s);
    if(st != GDS_OK)
        return st;
    UA_ByteString c = {q->cert.len, q->cert.data}, ca = {0, NULL};
    const gds_buf *ib = gds_issuer_for(s, q->certType);
    ca.length = ib->len;
    ca.data = ib->data;
    if(UA_ByteString_copy(&c, cert) != UA_STATUSCODE_GOOD ||
       UA_Array_copy(&ca, 1, (void **)issuers, &UA_TYPES[UA_TYPES_BYTESTRING]) !=
           UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(cert);
        return GDS_ENOMEM;
    }
    *nIssuers = 1;
    return GDS_OK;
}

gds_status gds_server_sign_request(gds_server *s, const char *actor, const UA_NodeId *appId,
                                   const UA_NodeId *groupId, const UA_NodeId *typeId,
                                   const UA_ByteString *csr, uint32_t timeoutMs,
                                   UA_ByteString *cert, UA_ByteString **issuers,
                                   size_t *nIssuers) {
    if(!s || !cert || !issuers || !nIssuers)
        return GDS_EINVAL;
    *cert = UA_BYTESTRING_NULL;
    *issuers = NULL;
    *nIssuers = 0;
    sign_input in;
    gds_status st = sign_checks(s, actor, appId, groupId, typeId, csr, &in);
    if(st != GDS_OK)
        return st;
    gds_request q;
    memset(&q, 0, sizeof(q));
    if(gds_guid_random(&q.id) != GDS_OK)
        return GDS_ECRYPTO;
    q.appId = in.app;
    q.groupId = UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP;
    q.certType = in.type;
    q.state = GDS_REQ_RECEIVED; /* approved: the embedder is the approver */
    q.csr.data = csr->data;     /* borrowed for the insert */
    q.csr.len = csr->length;
    gds_lock(s);
    st = gds_store_req_insert(s->store, &q);
    gds_unlock(s);
    UA_Variant args[4];
    UA_NodeId group = UA_NODEID_NUMERIC(s->ns, q.groupId), type = UA_NODEID_NUMERIC(0, q.certType);
    UA_Variant_setScalar(&args[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&args[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&args[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&args[3], (void *)(uintptr_t)csr, &UA_TYPES[UA_TYPES_BYTESTRING]);
    gds_status a = gds_cert_audit(s, actor, UA_GDSID_CERTIFICATEREQUESTEDAUDITEVENTTYPE,
                              UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, q.certType, args, 4,
                              st == GDS_OK, NULL);
    if(a != GDS_OK)
        fprintf(stderr, "opengds: audit of a signing request: %s\n", gds_status_name(a));
    if(st != GDS_OK)
        return st;
    gds_worker_kick(s);
    gds_request done;
    memset(&done, 0, sizeof(done));
    st = wait_signed(s, &q.id, timeoutMs, &done);
    if(st == GDS_OK && done.state == GDS_REQ_ISSUED)
        st = deliver(s, &done, cert, issuers, nIssuers);
    else if(st == GDS_OK)
        st = GDS_EDENIED; /* Failed: the signer or a hold refused it */
    UA_NodeId rid = UA_NODEID_GUID(s->ns, q.id);
    UA_Variant fin[2];
    UA_Variant_setScalar(&fin[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&fin[1], &rid, &UA_TYPES[UA_TYPES_NODEID]);
    if(st != GDS_EREMOTE) {
        a = gds_cert_audit(s, actor, UA_GDSID_CERTIFICATEDELIVEREDAUDITEVENTTYPE,
                       UA_GDSID_DIRECTORY_FINISHREQUEST, q.certType, fin, 2, st == GDS_OK, NULL);
        if(a != GDS_OK)
            fprintf(stderr, "opengds: audit of a delivery: %s\n", gds_status_name(a));
    }
    gds_request_clear(&done);
    return st;
}

/* ---- trust list ---- */

gds_status gds_server_get_trust_list(gds_server *s, const UA_NodeId *groupId,
                                     UA_TrustListDataType *out) {
    if(!s || !out)
        return GDS_EINVAL;
    UA_TrustListDataType_init(out);
    if(!group_ok(s, groupId)) {
        bool found = false; /* a plugin's group (A18) */
        gds_status st = gds_ptl_get(s, groupId, out, &found);
        return found ? st : GDS_ENOTFOUND;
    }
    UA_StatusCode r = gds_trustlist_data(s, (UA_UInt32)UA_TRUSTLISTMASKS_ALL, out);
    return r == UA_STATUSCODE_GOOD ? GDS_OK : gds_ua_status(r);
}
