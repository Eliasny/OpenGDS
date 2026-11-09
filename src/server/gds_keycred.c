/* OpenGDS - KeyCredential management, pull model (OPC 10000-12 §8.5).
 *
 * Every configured KeyCredentialService is an Object of
 * KeyCredentialServiceType under KeyCredentialManagement (§8.5.3, §8.5.4),
 * with its ResourceUri, ProfileUris and SecurityPolicyUris, the Mandatory
 * StartRequest and FinishRequest and the Optional Revoke.
 *
 * The GDS manages the credentials itself (§8.1): FinishRequest makes a
 * random CredentialId ("opengds-" + 32 hex digits) and secret (32 random
 * bytes, base64url, so a broker can take it as a password), returns the
 * secret once (encrypted as an RsaEncryptedSecret for the certificate given
 * to StartRequest, OPC 10000-4 §7.40.2.4) and stores only a salted hash of
 * it (mosquitto_passwd's PBKDF2-SHA512 "$7$" form). A new delivery for the
 * same application and service replaces the earlier credential.
 *
 * Requests follow the approval policy of certificates (gds_policy.c):
 * auto: approved on arrival; renewals: approved when the application itself
 * asks and already holds a credential for the service; manual: never. The
 * others wait for a RegistrationAuthorityAdmin on a dialog
 * (gds_approvals.c); FinishRequest answers Bad_RequestNotComplete until then.
 *
 * Access (§8.2, §8.5.5 - §8.5.7): every method needs an encrypted channel
 * and KeyCredentialAdmin, or the application itself (ApplicationSelfAdmin:
 * its GDS-issued certificate on the channel), or the embedder's may_manage
 * hook (ApplicationAdmin, UASM ask A14). FinishRequest also needs the
 * channel certificate that called StartRequest (§8.5.6).
 *
 * Audit (§8.5.8 - §8.5.11): KeyCredentialRequested (accepted or refused),
 * Delivered and Revoked, with the ResourceUri; never a secret.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/enc_secret.h"
#include "common/ids.h"
#include "common/limits.h"
#include "gds_internal.h"
#include "common/banned.h"

#define SECRET_BYTES 32
#define ID_BYTES 16
#define ID_PREFIX "opengds-"
#define PBKDF2_ITER 101 /* mosquitto_passwd's default for "$7$" */
#define PBKDF2_SALT 12
#define PBKDF2_HASH 64
#define MAX_REQUESTED_ROLES 32

static const char *const kcPolicies[] = {GDS_POLICY_BASIC256SHA256, GDS_POLICY_AES128_RSAOAEP,
                                         GDS_POLICY_AES256_RSAPSS};

/* ---- configuration ---- */

static bool name_ok(const char *n) {
    size_t len = n ? strnlen(n, GDS_MAX_KC_SERVICE + 1) : 0;
    if(len == 0 || len > GDS_MAX_KC_SERVICE)
        return false;
    for(size_t i = 0; i < len; i++) {
        char c = n[i];
        if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
             c == '.' || c == '_' || c == '-'))
            return false;
    }
    return true;
}

static bool uri_ok(const char *u) {
    size_t len = u ? strnlen(u, GDS_MAX_STRING + 1) : 0;
    return len > 0 && len <= GDS_MAX_STRING && strchr(u, ':') != NULL;
}

static char *dup_str(const char *v) {
    size_t n = strlen(v);
    char *d = malloc(n + 1);
    if(d)
        memcpy(d, v, n + 1);
    return d;
}

gds_status gds_keycred_copy(gds_server *s, const gds_keycred_service *svc, size_t n) {
    if(n == 0)
        return GDS_OK;
    if(!svc || n > GDS_MAX_KC_SERVICES)
        return GDS_EINVAL;
    if(!gds_store_kc_supported(s->store))
        return GDS_EUNSUPPORTED; /* a store backend before minor 6 */
    for(size_t i = 0; i < n; i++) {
        const gds_keycred_service *d = &svc[i];
        if(!name_ok(d->name) || !uri_ok(d->resourceUri) || d->profileUrisSize == 0 ||
           d->profileUrisSize > GDS_MAX_KC_PROFILES || !d->profileUris)
            return GDS_EINVAL;
        for(size_t j = 0; j < i; j++)
            if(strcmp(s->kc[j].name, d->name) == 0)
                return GDS_EINVAL;
        gds_kc_service *k = &s->kc[s->nKc++];
        memcpy(k->name, d->name, strlen(d->name) + 1);
        if(!(k->resourceUri = dup_str(d->resourceUri)))
            return GDS_ENOMEM;
        for(size_t j = 0; j < d->profileUrisSize; j++) {
            if(!uri_ok(d->profileUris[j]))
                return GDS_EINVAL;
            if(!(k->profileUris[j] = dup_str(d->profileUris[j])))
                return GDS_ENOMEM;
            k->nProfiles++;
        }
    }
    return GDS_OK;
}

void gds_keycred_free(gds_server *s) {
    for(size_t i = 0; i < s->nKc; i++) {
        free(s->kc[i].resourceUri);
        for(size_t j = 0; j < s->kc[i].nProfiles; j++)
            free(s->kc[i].profileUris[j]);
        UA_NodeId_clear(&s->kc[i].node);
    }
    memset(s->kc, 0, sizeof(s->kc));
    s->nKc = 0;
}

static const gds_kc_service *service_of(const gds_server *s, const UA_NodeId *objectId) {
    for(size_t i = 0; objectId && i < s->nKc; i++)
        if(UA_NodeId_equal(&s->kc[i].node, objectId))
            return &s->kc[i];
    return NULL;
}

/* ---- access ---- */

static bool encrypted(const void *sessionContext) {
    const gds_session *ss = sessionContext;
    return ss && ss->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
}

/* KeyCredentialAdmin, the application itself, or the embedder allowed it */
static bool may(const void *sessionContext, const UA_Guid *appId, const UA_String *appUri) {
    const gds_session *ss = sessionContext;
    return gds_session_has(sessionContext, GDS_ROLE_KEY_CREDENTIAL_ADMIN) ||
           (appUri && gds_session_is_app(sessionContext, appUri)) ||
           (ss && ss->managedGranted && UA_Guid_equal(&ss->managedApp, appId));
}

static bool caller_hash(const void *sessionContext, uint8_t out[GDS_KC_CALLER]) {
    const gds_session *ss = sessionContext;
    unsigned int n = 0;
    return ss && ss->clientCert.length > 0 &&
           EVP_Digest(ss->clientCert.data, ss->clientCert.length, out, &n, EVP_sha256(), NULL) ==
               1 &&
           n == GDS_KC_CALLER;
}

#define DEFER_IF_DENIED(fn, r, app)                                                          \
    do {                                                                                     \
        if((r) == UA_STATUSCODE_BADUSERACCESSDENIED)                                         \
            return gds_embed_defer_rights(s, fn, sessionId, sessionContext, methodId, objectId, \
                                          &(app), inputSize, input, outputSize, output);     \
    } while(0)

/* ---- audit ---- */

static void audit(gds_server *s, void *sessionContext, UA_UInt32 type, UA_UInt32 method,
                  const gds_kc_service *k, const UA_Variant *input, size_t nArgs, UA_StatusCode r,
                  const char *okMsg) {
    if(!k || !gds_audit_result(r))
        return;
    UA_String res = UA_STRING(k->resourceUri);
    gds_event_field f;
    f.nsIndex = 0;
    f.name = "ResourceUri";
    UA_Variant_setScalar(&f.value, &res, &UA_TYPES[UA_TYPES_STRING]);
    gds_status a = gds_method_audit(s, gds_session_actor(sessionContext), type, method,
                                    UA_GDSID_WELLKNOWNROLE_KEYCREDENTIALADMIN, &f, 1, input, nArgs,
                                    r == UA_STATUSCODE_GOOD,
                                    r == UA_STATUSCODE_GOOD ? okMsg : UA_StatusCode_name(r));
    if(a != GDS_OK && a != GDS_EUNSUPPORTED)
        fprintf(stderr, "opengds: audit of a KeyCredential method: %s\n", gds_status_name(a));
}

/* ---- the application ---- */

/* The one record with this ApplicationUri (§8.5.5): Bad_NotFound if none,
 * Bad_ConfigurationError if several. */
static UA_StatusCode app_by_uri(gds_server *s, const UA_String *uri, UA_Guid *id) {
    UA_ApplicationRecordDataType *recs = NULL;
    size_t n = 0;
    gds_lock(s);
    gds_status st = gds_store_app_find_uri(s->store, uri, 2, &recs, &n);
    gds_unlock(s);
    UA_StatusCode r = st != GDS_OK ? gds_status_to_ua(st)
                      : n == 0     ? UA_STATUSCODE_BADNOTFOUND
                      : n > 1      ? UA_STATUSCODE_BADCONFIGURATIONERROR
                                   : UA_STATUSCODE_GOOD;
    if(r == UA_STATUSCODE_GOOD) {
        const UA_NodeId *a = &recs[0].applicationId;
        if(a->identifierType == UA_NODEIDTYPE_GUID)
            *id = a->identifier.guid;
        else
            r = UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_Array_delete(recs, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    return r;
}

/* The application's ApplicationUri; empty if it is gone. */
static void app_uri(gds_server *s, const UA_Guid *id, UA_String *out) {
    UA_ApplicationRecordDataType rec;
    *out = UA_STRING_NULL;
    if(gds_load_app(s, id, &rec) == UA_STATUSCODE_GOOD) {
        *out = rec.applicationUri;
        rec.applicationUri = UA_STRING_NULL;
        UA_ApplicationRecordDataType_clear(&rec);
    }
}

/* ---- StartRequest (§8.5.5) ---- */

typedef struct {
    const UA_Guid *app;
    const char *service;
    bool found;
} cred_find;

static bool find_cred(void *ctx, const gds_kc_cred *c) {
    cred_find *f = ctx;
    if(UA_Guid_equal(&c->appId, f->app) && strcmp(c->service, f->service) == 0)
        f->found = true;
    return !f->found;
}

/* Approved on arrival, or Pending (see the file comment). */
static gds_status initial_state(gds_server *s, const void *sessionContext, const UA_Guid *app,
                                const UA_String *uri, const char *service, gds_kc_state *out) {
    *out = GDS_KC_PENDING;
    switch(s->approval) {
    case GDS_APPROVE_ALL:
        *out = GDS_KC_APPROVED;
        return GDS_OK;
    case GDS_APPROVE_RENEWALS: {
        if(!gds_session_is_app(sessionContext, uri))
            return GDS_OK; /* an administrator or the embedder asks: an admin decides */
        cred_find f = {app, service, false};
        gds_lock(s);
        gds_status st = gds_store_kc_cred_scan(s->store, find_cred, &f);
        gds_unlock(s);
        if(f.found)
            *out = GDS_KC_APPROVED;
        return st;
    }
    case GDS_APPROVE_MANUAL:
        return GDS_OK;
    default:
        return GDS_EINVAL;
    }
}

static UA_StatusCode start_args(size_t inputSize, const UA_Variant *input, const UA_String **uri,
                                const UA_ByteString **key, const UA_String **policy) {
    if(inputSize < 4)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if(inputSize > 4)
        return UA_STATUSCODE_BADTOOMANYARGUMENTS;
    const void *roles = NULL;
    size_t nRoles = 0;
    if(gds_arg_string(&input[0], GDS_MAX_APPLICATION_URI, uri) != UA_STATUSCODE_GOOD ||
       (*uri)->length == 0 || gds_arg_bytes(&input[1], GDS_MAX_CERT_SIZE, key) != UA_STATUSCODE_GOOD ||
       gds_arg_string(&input[2], GDS_MAX_KC_POLICY, policy) != UA_STATUSCODE_GOOD ||
       gds_arg_array(&input[3], &UA_TYPES[UA_TYPES_NODEID], MAX_REQUESTED_ROLES, &roles,
                     &nRoles) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    /* "If the SecurityPolicyUri is provided this field shall be provided",
     * and the other way round */
    if(((*key)->length > 0) != ((*policy)->length > 0))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode key_check(const UA_ByteString *key, const UA_String *policy) {
    if(key->length == 0)
        return UA_STATUSCODE_GOOD; /* no encryption: the encrypted channel protects it */
    gds_buf der = {key->data, key->length};
    gds_status st = gds_enc_secret_check((const char *)policy->data, policy->length, &der);
    return st == GDS_OK            ? UA_STATUSCODE_GOOD
           : st == GDS_EINVAL      ? UA_STATUSCODE_BADCERTIFICATEINVALID
                                   : UA_STATUSCODE_BADSECURITYPOLICYREJECTED;
}

static GDS_METHOD(start_request);

static GDS_METHOD(start_impl) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    const gds_kc_service *k = service_of(s, objectId);
    if(!k)
        return UA_STATUSCODE_BADMETHODINVALID;
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(!encrypted(sessionContext))
        return UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;
    const UA_String *uri = NULL, *policy = NULL;
    const UA_ByteString *key = NULL;
    UA_StatusCode r = start_args(inputSize, input, &uri, &key, &policy);
    UA_Guid app;
    memset(&app, 0, sizeof(app));
    /* rights before the lookup: who may not ask learns nothing of the records */
    bool admin = gds_session_has(sessionContext, GDS_ROLE_KEY_CREDENTIAL_ADMIN);
    if(r == UA_STATUSCODE_GOOD && !admin && !gds_session_is_app(sessionContext, uri) &&
       !s->mayManage && !gds_session_get(sessionContext)->managedGranted)
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    if(r == UA_STATUSCODE_GOOD)
        r = app_by_uri(s, uri, &app);
    if(r == UA_STATUSCODE_GOOD && !may(sessionContext, &app, uri))
        r = UA_STATUSCODE_BADUSERACCESSDENIED;
    DEFER_IF_DENIED(start_request, r, app);
    if(r == UA_STATUSCODE_GOOD)
        r = key_check(key, policy);
    if(r != UA_STATUSCODE_GOOD)
        return r;

    gds_kc_request q;
    memset(&q, 0, sizeof(q));
    if(gds_guid_random(&q.id) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    q.appId = app;
    memcpy(q.service, k->name, sizeof(q.service));
    q.publicKey.data = key->data; /* borrowed for the insert */
    q.publicKey.len = key->length;
    if(policy->length)
        memcpy(q.policy, policy->data, policy->length);
    q.hasCaller = caller_hash(sessionContext, q.caller);
    gds_status st = initial_state(s, sessionContext, &app, uri, k->name, &q.state);
    if(st == GDS_OK) {
        gds_lock(s);
        st = gds_store_kc_req_insert(s->store, &q);
        gds_unlock(s);
    }
    if(st != GDS_OK)
        return gds_status_to_ua(st);
    if(q.state == GDS_KC_PENDING) {
        r = gds_approvals_raise_kc(s, &q, uri);
        if(r != UA_STATUSCODE_GOOD) /* stored: the next start raises it again */
            fprintf(stderr, "opengds: approval dialog for a KeyCredential request: %s\n",
                    UA_StatusCode_name(r));
    }
    UA_NodeId rid = UA_NODEID_GUID(s->ns, q.id);
    return UA_Variant_setScalarCopy(&output[0], &rid, &UA_TYPES[UA_TYPES_NODEID]);
}

static GDS_METHOD(start_request) {
    UA_StatusCode r = start_impl(server, sessionId, sessionContext, methodId, methodContext,
                                 objectId, objectContext, inputSize, input, outputSize, output);
    gds_server *s = gds_ctx(methodContext);
    audit(s, sessionContext, UA_GDSID_KEYCREDENTIALREQUESTEDAUDITEVENTTYPE,
          UA_GDSID_KEYCREDENTIALSERVICETYPE_STARTREQUEST, service_of(s, objectId), input,
          inputSize < 4 ? inputSize : 4, r, "KeyCredential request accepted");
    return r;
}

/* ---- a KeyCredential source (gds_plugin.h) ---- */

static UA_StatusCode finish_outputs(const gds_kc_request *q, const char *credentialId,
                                    const gds_buf *plain, UA_Variant *output);

#define SOURCE_VERIFIER "!source" /* matches no secret: the source holds it */
#define ACTOR_MAX 160

typedef struct {
    gds_server *s;
    gds_kc_request q; /* owns publicKey */
    UA_Guid reqId;
    char service[GDS_MAX_KC_SERVICE + 1];
    char *resourceUri;
    UA_String appUri;
    UA_NodeId appId;
    char replaces[GDS_MAX_KC_ID + 1];
    char id[GDS_KEYCRED_ID_MAX + 1];
    UA_ByteString secret;
    char actor[ACTOR_MAX];
    UA_Variant args[2]; /* the call's inputs, for the audit */
    size_t nArgs;
} source_job;

static void source_job_free(void *p) {
    source_job *j = p;
    if(!j)
        return;
    gds_kc_request_clear(&j->q);
    free(j->resourceUri);
    UA_String_clear(&j->appUri);
    UA_NodeId_clear(&j->appId);
    if(j->secret.data)
        OPENSSL_cleanse(j->secret.data, j->secret.length);
    UA_ByteString_clear(&j->secret);
    for(size_t i = 0; i < j->nArgs; i++)
        UA_Variant_clear(&j->args[i]);
    free(j);
}

static const gds_kc_service *service_named(const gds_server *s, const char *name) {
    for(size_t i = 0; i < s->nKc; i++)
        if(strcmp(s->kc[i].name, name) == 0)
            return &s->kc[i];
    return NULL;
}

static source_job *source_job_new(gds_server *s, const gds_kc_service *k, void *sessionContext,
                                  const UA_Variant *input, size_t nArgs) {
    source_job *j = calloc(1, sizeof(*j));
    if(!j)
        return NULL;
    j->s = s;
    memcpy(j->service, k->name, strlen(k->name) + 1);
    j->resourceUri = dup_str(k->resourceUri);
    const char *actor = gds_session_actor(sessionContext);
    bool ok = j->resourceUri &&
              gds_path(j->actor, sizeof(j->actor), "%s", actor ? actor : "") == GDS_OK;
    for(size_t i = 0; ok && i < nArgs && i < 2; i++, j->nArgs++)
        ok = UA_Variant_copy(&input[i], &j->args[i]) == UA_STATUSCODE_GOOD;
    if(!ok) {
        source_job_free(j);
        return NULL;
    }
    return j;
}

static void source_audit(source_job *j, UA_UInt32 type, UA_UInt32 method, UA_StatusCode r,
                         const char *okMsg) {
    const gds_kc_service *k = service_named(j->s, j->service);
    if(!k || !gds_audit_result(r))
        return;
    UA_String res = UA_STRING(k->resourceUri);
    gds_event_field f;
    f.nsIndex = 0;
    f.name = "ResourceUri";
    UA_Variant_setScalar(&f.value, &res, &UA_TYPES[UA_TYPES_STRING]);
    gds_status a = gds_method_audit(j->s, j->actor, type, method,
                                    UA_GDSID_WELLKNOWNROLE_KEYCREDENTIALADMIN, &f, 1, j->args,
                                    j->nArgs, r == UA_STATUSCODE_GOOD,
                                    r == UA_STATUSCODE_GOOD ? okMsg : UA_StatusCode_name(r));
    if(a != GDS_OK && a != GDS_EUNSUPPORTED)
        fprintf(stderr, "opengds: audit of a KeyCredential method: %s\n", gds_status_name(a));
}

static bool printable_id(const char *id) {
    size_t n = strnlen(id, GDS_KEYCRED_ID_MAX + 1);
    if(n == 0 || n > GDS_KEYCRED_ID_MAX)
        return false;
    for(size_t i = 0; i < n; i++)
        if((unsigned char)id[i] < 0x21 || (unsigned char)id[i] > 0x7e)
            return false;
    return true;
}

/* Worker: the source makes the credential. */
static UA_StatusCode issue_run(void *p, const gds_caller *caller, size_t nIn, const UA_Variant *in) {
    (void)caller, (void)nIn, (void)in;
    source_job *j = p;
    const gds_keycred_source *src = &j->s->kcSource;
    gds_keycred_issue_request req;
    memset(&req, 0, sizeof(req));
    req.abi_major = GDS_PLUGIN_ABI_MAJOR;
    req.abi_minor = GDS_PLUGIN_ABI_MINOR;
    req.struct_size = sizeof(req);
    req.service = j->service;
    req.resourceUri = j->resourceUri;
    req.applicationUri = &j->appUri;
    req.applicationId = &j->appId;
    req.replaces = j->replaces[0] ? j->replaces : NULL;
    char id[GDS_KEYCRED_ID_MAX + 1];
    memset(id, 0, sizeof(id));
    UA_ByteString secret = UA_BYTESTRING_NULL;
    gds_status st = src->issue(src->ctx, &req, id, &secret);
    id[GDS_KEYCRED_ID_MAX] = '\0';
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(st != GDS_OK)
        r = st == GDS_EDENIED ? UA_STATUSCODE_BADREQUESTNOTALLOWED : UA_STATUSCODE_BADINTERNALERROR;
    else if(!printable_id(id) || secret.length == 0 || secret.length > GDS_KEYCRED_SECRET_MAX)
        r = UA_STATUSCODE_BADINTERNALERROR; /* the source broke its contract */
    if(r == UA_STATUSCODE_GOOD) {
        memcpy(j->id, id, sizeof(j->id));
        j->secret = secret;
        UA_ByteString_init(&secret);
    } else {
        fprintf(stderr, "opengds: KeyCredential source issue: %s\n", gds_status_name(st));
    }
    if(secret.data)
        OPENSSL_cleanse(secret.data, secret.length);
    UA_ByteString_clear(&secret);
    return r;
}

/* Server thread: store the CredentialId, answer with the secret. */
static UA_StatusCode issue_done(gds_server *s, void *p, UA_StatusCode status, UA_Variant *output) {
    source_job *j = p;
    UA_StatusCode r = status;
    if(r == UA_STATUSCODE_GOOD && !output) {
        /* the caller is gone: nobody received the secret */
        fprintf(stderr, "opengds: FinishRequest cancelled; source credential %s not delivered\n",
                j->id);
        r = UA_STATUSCODE_BADREQUESTCANCELLEDBYCLIENT;
    }
    if(r == UA_STATUSCODE_GOOD) {
        gds_kc_cred c;
        memset(&c, 0, sizeof(c));
        memcpy(c.id, j->id, strlen(j->id) + 1);
        c.appId = j->q.appId;
        memcpy(c.service, j->service, sizeof(c.service));
        memcpy(c.verifier, SOURCE_VERIFIER, sizeof(SOURCE_VERIFIER));
        char replaced[GDS_MAX_KC_ID + 1] = "";
        gds_lock(s);
        gds_status st = gds_store_kc_deliver(s->store, &j->reqId, &c, replaced);
        gds_unlock(s);
        if(st == GDS_ESTATE)
            r = UA_STATUSCODE_BADINVALIDARGUMENT; /* delivered or cancelled meanwhile */
        else if(st != GDS_OK)
            r = gds_status_to_ua(st);
        if(r != UA_STATUSCODE_GOOD)
            fprintf(stderr, "opengds: source credential %s not stored (%s): revoke it at the source\n",
                    j->id, gds_status_name(st));
        if(r == UA_STATUSCODE_GOOD) {
            gds_buf plain = {j->secret.data, j->secret.length};
            r = finish_outputs(&j->q, j->id, &plain, output);
        }
        if(r == UA_STATUSCODE_GOOD && replaced[0])
            fprintf(stderr, "opengds: KeyCredential %s replaces %s\n", j->id, replaced);
    }
    if(r == UA_STATUSCODE_GOOD)
        source_audit(j, UA_GDSID_KEYCREDENTIALDELIVEREDAUDITEVENTTYPE,
                     UA_GDSID_KEYCREDENTIALSERVICETYPE_FINISHREQUEST, r, "KeyCredential delivered");
    source_job_free(j);
    return r;
}

typedef struct {
    const UA_Guid *app;
    const char *service;
    char *id;
} cred_of;

static bool find_cred_id(void *ctx, const gds_kc_cred *c) {
    cred_of *f = ctx;
    if(UA_Guid_equal(&c->appId, f->app) && strcmp(c->service, f->service) == 0) {
        memcpy(f->id, c->id, strlen(c->id) + 1);
        return false;
    }
    return true;
}

/* FinishRequest of an approved request with a source: on a worker. Takes
 * *q on success (it is cleared). */
static UA_StatusCode defer_issue(gds_server *s, const gds_kc_service *k, gds_kc_request *q,
                                 const UA_Guid *reqId, const UA_NodeId *sessionId,
                                 void *sessionContext, const UA_NodeId *objectId,
                                 const UA_Variant *input, UA_Variant *output) {
    source_job *j = source_job_new(s, k, sessionContext, input, 2);
    if(!j)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    j->reqId = *reqId;
    app_uri(s, &q->appId, &j->appUri);
    j->appId = UA_NODEID_GUID(s->ns, q->appId);
    cred_of f = {&q->appId, k->name, j->replaces};
    gds_lock(s);
    gds_status st = gds_store_kc_cred_scan(s->store, find_cred_id, &f);
    gds_unlock(s);
    if(st != GDS_OK) {
        source_job_free(j);
        return gds_status_to_ua(st);
    }
    j->q = *q;
    UA_StatusCode r = gds_embed_defer(s, sessionId, sessionContext, objectId, 0, NULL, output,
                                      issue_run, issue_done, source_job_free, j);
    if(r == UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY) {
        memset(q, 0, sizeof(*q)); /* the job's now */
    } else {
        memset(&j->q, 0, sizeof(j->q)); /* still the caller's */
        source_job_free(j);
    }
    return r;
}

/* Worker: the source drops the credential. */
static UA_StatusCode revoke_run(void *p, const gds_caller *caller, size_t nIn,
                                const UA_Variant *in) {
    (void)caller, (void)nIn, (void)in;
    source_job *j = p;
    const gds_keycred_source *src = &j->s->kcSource;
    gds_status st = src->revoke(src->ctx, j->service, j->id);
    if(st != GDS_OK && st != GDS_ENOTFOUND) {
        fprintf(stderr, "opengds: KeyCredential source revoke: %s\n", gds_status_name(st));
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode revoke_done(gds_server *s, void *p, UA_StatusCode status, UA_Variant *output) {
    (void)output;
    source_job *j = p;
    UA_StatusCode r = status;
    if(r == UA_STATUSCODE_GOOD) {
        gds_lock(s);
        gds_status st = gds_store_kc_cred_delete(s->store, j->id);
        gds_unlock(s);
        r = st == GDS_ENOTFOUND ? UA_STATUSCODE_BADINVALIDARGUMENT : gds_status_to_ua(st);
    }
    source_audit(j, UA_GDSID_KEYCREDENTIALREVOKEDAUDITEVENTTYPE,
                 UA_GDSID_KEYCREDENTIALSERVICETYPE_REVOKE, r, "KeyCredential revoked");
    source_job_free(j);
    return r;
}

static UA_StatusCode defer_revoke(gds_server *s, const gds_kc_service *k, const char *cid,
                                  const UA_NodeId *sessionId, void *sessionContext,
                                  const UA_NodeId *objectId, const UA_Variant *input,
                                  UA_Variant *output) {
    source_job *j = source_job_new(s, k, sessionContext, input, 1);
    if(!j)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    memcpy(j->id, cid, strlen(cid) + 1);
    UA_StatusCode r = gds_embed_defer(s, sessionId, sessionContext, objectId, 0, NULL, output,
                                      revoke_run, revoke_done, source_job_free, j);
    if(r != UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY)
        source_job_free(j);
    return r;
}

gds_status gds_server_set_keycred_source(gds_server *s, const gds_keycred_source *source) {
    if(!s)
        return GDS_EINVAL;
    if(__atomic_load_n(&s->started, __ATOMIC_ACQUIRE))
        return GDS_ESTATE;
    if(!source) {
        s->hasKcSource = false;
        memset(&s->kcSource, 0, sizeof(s->kcSource));
        return GDS_OK;
    }
    if(source->abi_major != GDS_PLUGIN_ABI_MAJOR || source->struct_size < sizeof(*source) ||
       !source->issue || !source->revoke)
        return GDS_EINVAL;
    if(!gds_store_kc_supported(s->store))
        return GDS_EUNSUPPORTED;
    gds_status st = gds_embed_pool_start(s);
    if(st != GDS_OK)
        return st;
    memcpy(&s->kcSource, source, sizeof(*source));
    s->kcSource.struct_size = sizeof(s->kcSource);
    s->hasKcSource = true;
    return GDS_OK;
}

/* ---- FinishRequest (§8.5.6) ---- */

static gds_status random_hex(char *out, size_t outLen) {
    uint8_t b[ID_BYTES];
    if(RAND_bytes(b, sizeof(b)) != 1)
        return GDS_ECRYPTO;
    return gds_hex(b, sizeof(b), out, outLen);
}

static void b64(const uint8_t *in, size_t n, char *out, size_t outLen, bool url) {
    unsigned char tmp[256];
    int len = n <= 180 ? EVP_EncodeBlock(tmp, in, (int)n) : 0;
    size_t o = 0;
    for(int i = 0; i < len && o + 1 < outLen; i++) {
        char c = (char)tmp[i];
        if(url && c == '=')
            break;
        if(url && c == '+')
            c = '-';
        else if(url && c == '/')
            c = '_';
        out[o++] = c;
    }
    out[o] = '\0';
    OPENSSL_cleanse(tmp, sizeof(tmp));
}

/* A new CredentialId, secret and verifier. */
static gds_status make_credential(gds_kc_cred *c, char secret[64]) {
    uint8_t raw[SECRET_BYTES], salt[PBKDF2_SALT], hash[PBKDF2_HASH];
    char hex[2 * ID_BYTES + 1], s64[32], h64[96];
    gds_status st = random_hex(hex, sizeof(hex));
    if(st == GDS_OK && (RAND_bytes(raw, sizeof(raw)) != 1 || RAND_bytes(salt, sizeof(salt)) != 1))
        st = GDS_ECRYPTO;
    if(st == GDS_OK) {
        b64(raw, sizeof(raw), secret, 64, true);
        if(PKCS5_PBKDF2_HMAC(secret, (int)strlen(secret), salt, sizeof(salt), PBKDF2_ITER,
                             EVP_sha512(), sizeof(hash), hash) != 1)
            st = GDS_ECRYPTO;
    }
    if(st == GDS_OK) {
        b64(salt, sizeof(salt), s64, sizeof(s64), false);
        b64(hash, sizeof(hash), h64, sizeof(h64), false);
        st = gds_path(c->id, sizeof(c->id), ID_PREFIX "%s", hex);
        if(st == GDS_OK)
            st = gds_path(c->verifier, sizeof(c->verifier), "$7$%d$%s$%s", PBKDF2_ITER, s64, h64);
    }
    OPENSSL_cleanse(raw, sizeof(raw));
    OPENSSL_cleanse(hash, sizeof(hash));
    if(st != GDS_OK)
        OPENSSL_cleanse(secret, 64);
    return st;
}

/* CredentialId, CredentialSecret, CertificateThumbprint, SecurityPolicyUri,
 * GrantedRoles (empty: not relevant, §8.5.6). */
static UA_StatusCode finish_outputs(const gds_kc_request *q, const char *credentialId,
                                    const gds_buf *plain, UA_Variant *output) {
    gds_buf enc = {0};
    char thumb[GDS_SHA1_HEX] = "";
    gds_status st = GDS_OK;
    if(q->publicKey.len > 0) {
        st = gds_enc_secret_rsa(q->policy, strlen(q->policy), &q->publicKey, plain, &enc);
        if(st == GDS_OK)
            st = gds_sha1_hex(&q->publicKey, thumb);
    } else {
        st = gds_buf_dup(plain->data, plain->len, &enc);
    }
    if(st != GDS_OK) {
        gds_buf_free_secret(&enc);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_String id = UA_STRING((char *)(uintptr_t)credentialId);
    UA_ByteString sec = {enc.len, enc.data};
    UA_String tp = q->publicKey.len ? UA_STRING(thumb) : UA_STRING_NULL;
    UA_String pol = q->policy[0] ? UA_STRING((char *)(uintptr_t)q->policy) : UA_STRING_NULL;
    UA_StatusCode r = UA_Variant_setScalarCopy(&output[0], &id, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[1], &sec, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[2], &tp, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[3], &pol, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        UA_Variant_setArray(&output[4], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_NODEID]);
    gds_buf_free_secret(&enc);
    return r;
}

static GDS_METHOD(finish_request);

/* FinishRequest's inputs, the request and the caller's right to it (an
 * embedder's answer pending: Good_CompletesAsynchronously). */
static UA_StatusCode finish_load(gds_server *s, const gds_kc_service *k, size_t inputSize,
                                 const UA_Variant *input, UA_Guid *reqId, bool *cancel,
                                 gds_kc_request *q) {
    memset(q, 0, sizeof(*q));
    if(inputSize < 2)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if(inputSize > 2)
        return UA_STATUSCODE_BADTOOMANYARGUMENTS;
    const UA_Boolean *c = NULL;
    UA_StatusCode r = gds_in_guid(s, inputSize, input, 0, reqId);
    if(r == UA_STATUSCODE_BADNOTFOUND || r == UA_STATUSCODE_BADNODEIDUNKNOWN)
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    if(r == UA_STATUSCODE_GOOD &&
       gds_arg_scalar(&input[1], &UA_TYPES[UA_TYPES_BOOLEAN], (const void **)&c) !=
           UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    if(r != UA_STATUSCODE_GOOD)
        return r;
    *cancel = *c;
    gds_lock(s);
    gds_status st = gds_store_kc_req_get(s->store, reqId, q);
    gds_unlock(s);
    if(st == GDS_ENOTFOUND || (st == GDS_OK && strcmp(q->service, k->name) != 0))
        r = UA_STATUSCODE_BADINVALIDARGUMENT; /* §8.5.6: not a valid request */
    else if(st != GDS_OK)
        r = gds_status_to_ua(st);
    if(r != UA_STATUSCODE_GOOD)
        gds_kc_request_clear(q);
    return r;
}

/* KeyCredentialAdmin, the application or the embedder, over the
 * certificate that called StartRequest (§8.5.6). */
static bool finish_allowed(gds_server *s, const void *sessionContext, const gds_kc_request *q) {
    UA_String uri;
    app_uri(s, &q->appId, &uri);
    bool allowed = may(sessionContext, &q->appId, uri.length ? &uri : NULL);
    UA_String_clear(&uri);
    uint8_t caller[GDS_KC_CALLER];
    if(allowed && q->hasCaller &&
       (!caller_hash(sessionContext, caller) || memcmp(caller, q->caller, GDS_KC_CALLER) != 0))
        allowed = false;
    return allowed;
}

static UA_StatusCode finish_cancel(gds_server *s, const UA_Guid *reqId, const gds_kc_request *q,
                                   UA_Variant *output) {
    if(q->state != GDS_KC_PENDING && q->state != GDS_KC_APPROVED)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    gds_lock(s);
    gds_status st = gds_store_kc_req_set_state(s->store, reqId, GDS_KC_CANCELLED);
    gds_unlock(s);
    if(st == GDS_OK && q->state == GDS_KC_PENDING)
        gds_approvals_drop(s, reqId);
    if(st == GDS_OK) /* no credential: empty outputs */
        UA_Variant_setArray(&output[4], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_NODEID]);
    return gds_status_to_ua(st);
}

/* The core's own credential for an approved request. */
static UA_StatusCode finish_deliver(gds_server *s, const UA_Guid *reqId, const gds_kc_request *q,
                                    UA_Variant *output) {
    gds_kc_cred c;
    memset(&c, 0, sizeof(c));
    char secret[64];
    c.appId = q->appId;
    memcpy(c.service, q->service, sizeof(c.service));
    gds_status st = make_credential(&c, secret);
    char replaced[GDS_MAX_KC_ID + 1] = "";
    if(st == GDS_OK) {
        gds_lock(s);
        st = gds_store_kc_deliver(s->store, reqId, &c, replaced);
        gds_unlock(s);
    }
    UA_StatusCode r = st == GDS_ESTATE ? UA_STATUSCODE_BADINVALIDARGUMENT /* decided meanwhile */
                                       : gds_status_to_ua(st);
    if(r == UA_STATUSCODE_GOOD) {
        gds_buf plain = {(uint8_t *)secret, strlen(secret)};
        r = finish_outputs(q, c.id, &plain, output);
    }
    OPENSSL_cleanse(secret, sizeof(secret));
    if(r == UA_STATUSCODE_GOOD && replaced[0])
        fprintf(stderr, "opengds: KeyCredential %s replaces %s\n", c.id, replaced);
    return r;
}

static GDS_METHOD(finish_impl) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    const gds_kc_service *k = service_of(s, objectId);
    if(!k)
        return UA_STATUSCODE_BADMETHODINVALID;
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(!encrypted(sessionContext))
        return UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;
    UA_Guid reqId;
    bool cancel = false;
    gds_kc_request q;
    UA_StatusCode r = finish_load(s, k, inputSize, input, &reqId, &cancel, &q);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(!finish_allowed(s, sessionContext, &q)) {
        UA_Guid app = q.appId;
        gds_kc_request_clear(&q);
        r = UA_STATUSCODE_BADUSERACCESSDENIED;
        DEFER_IF_DENIED(finish_request, r, app);
        return r;
    }
    if(cancel)
        r = finish_cancel(s, &reqId, &q, output);
    else if(q.state == GDS_KC_PENDING)
        r = UA_STATUSCODE_BADREQUESTNOTCOMPLETE;
    else if(q.state == GDS_KC_REJECTED)
        r = UA_STATUSCODE_BADREQUESTNOTALLOWED;
    else if(q.state != GDS_KC_APPROVED)
        r = UA_STATUSCODE_BADINVALIDARGUMENT; /* delivered or cancelled */
    else if(s->hasKcSource)
        r = defer_issue(s, k, &q, &reqId, sessionId, sessionContext, objectId, input, output);
    else
        r = finish_deliver(s, &reqId, &q, output);
    gds_kc_request_clear(&q);
    return r;
}

static GDS_METHOD(finish_request) {
    UA_StatusCode r = finish_impl(server, sessionId, sessionContext, methodId, methodContext,
                                  objectId, objectContext, inputSize, input, outputSize, output);
    /* Delivered only when a credential went out (not on a cancel) */
    bool delivered = r == UA_STATUSCODE_GOOD && outputSize > 0 && !UA_Variant_isEmpty(&output[0]);
    if(delivered) {
        gds_server *s = gds_ctx(methodContext);
        audit(s, sessionContext, UA_GDSID_KEYCREDENTIALDELIVEREDAUDITEVENTTYPE,
              UA_GDSID_KEYCREDENTIALSERVICETYPE_FINISHREQUEST, service_of(s, objectId), input,
              inputSize < 2 ? inputSize : 2, r, "KeyCredential delivered");
    }
    return r;
}

/* ---- Revoke (§8.5.7) ---- */

static GDS_METHOD(revoke);

static GDS_METHOD(revoke_impl) {
    GDS_METHOD_UNUSED;
    (void)output;
    gds_server *s = gds_ctx(methodContext);
    const gds_kc_service *k = service_of(s, objectId);
    if(!k)
        return UA_STATUSCODE_BADMETHODINVALID;
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(!encrypted(sessionContext))
        return UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;
    if(inputSize < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if(inputSize > 1)
        return UA_STATUSCODE_BADTOOMANYARGUMENTS;
    const UA_String *id = NULL;
    if(gds_arg_string(&input[0], GDS_MAX_KC_ID, &id) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    char cid[GDS_MAX_KC_ID + 1];
    if(id->length)
        memcpy(cid, id->data, id->length);
    cid[id->length] = '\0';
    gds_kc_cred c;
    gds_lock(s);
    gds_status st = gds_store_kc_cred_get(s->store, cid, &c);
    gds_unlock(s);
    if(st == GDS_ENOTFOUND || (st == GDS_OK && strcmp(c.service, k->name) != 0))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(st != GDS_OK)
        return gds_status_to_ua(st);
    UA_String uri;
    app_uri(s, &c.appId, &uri);
    bool allowed = may(sessionContext, &c.appId, uri.length ? &uri : NULL);
    UA_String_clear(&uri);
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(!allowed) {
        r = UA_STATUSCODE_BADUSERACCESSDENIED;
        DEFER_IF_DENIED(revoke, r, c.appId);
    }
    if(s->hasKcSource)
        return defer_revoke(s, k, cid, sessionId, sessionContext, objectId, input, output);
    gds_lock(s);
    st = gds_store_kc_cred_delete(s->store, cid); /* "shall be deleted when revoked" */
    gds_unlock(s);
    return st == GDS_ENOTFOUND ? UA_STATUSCODE_BADINVALIDARGUMENT : gds_status_to_ua(st);
}

static GDS_METHOD(revoke) {
    UA_StatusCode r = revoke_impl(server, sessionId, sessionContext, methodId, methodContext,
                                  objectId, objectContext, inputSize, input, outputSize, output);
    gds_server *s = gds_ctx(methodContext);
    audit(s, sessionContext, UA_GDSID_KEYCREDENTIALREVOKEDAUDITEVENTTYPE,
          UA_GDSID_KEYCREDENTIALSERVICETYPE_REVOKE, service_of(s, objectId), input,
          inputSize < 1 ? inputSize : 1, r, "KeyCredential revoked");
    return r;
}

/* ---- install ---- */

static UA_StatusCode child(gds_server *s, const UA_NodeId *parent, const char *name,
                           UA_NodeId *out) {
    UA_QualifiedName qn = UA_QUALIFIEDNAME(s->ns, (char *)(uintptr_t)name);
    UA_BrowsePathResult bpr = UA_Server_browseSimplifiedBrowsePath(s->ua, *parent, 1, &qn);
    UA_StatusCode r = bpr.statusCode;
    if(r == UA_STATUSCODE_GOOD && bpr.targetsSize < 1)
        r = UA_STATUSCODE_BADNOTFOUND;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_NodeId_copy(&bpr.targets[0].targetId.nodeId, out);
    UA_BrowsePathResult_clear(&bpr);
    return r;
}

static UA_StatusCode bind(gds_server *s, const UA_NodeId *method, UA_MethodCallback cb) {
    UA_StatusCode r = UA_Server_setMethodNodeCallback(s->ua, *method, cb);
    return r == UA_STATUSCODE_GOOD ? UA_Server_setNodeContext(s->ua, *method, s) : r;
}

static UA_StatusCode write_prop(gds_server *s, const UA_NodeId *obj, const char *name,
                                const void *v, size_t n, bool array) {
    UA_NodeId p = UA_NODEID_NULL;
    UA_StatusCode r = child(s, obj, name, &p);
    UA_Variant val;
    if(array)
        UA_Variant_setArray(&val, (void *)(uintptr_t)v, n, &UA_TYPES[UA_TYPES_STRING]);
    else
        UA_Variant_setScalar(&val, (void *)(uintptr_t)v, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_writeValue(s->ua, p, val);
    UA_NodeId_clear(&p);
    return r;
}

/* SecurityPolicyUris is Optional and not instantiated: added here. */
static UA_StatusCode add_policies(gds_server *s, const UA_NodeId *obj) {
    UA_String pol[GDS_ARRAY_SIZE(kcPolicies)];
    for(size_t i = 0; i < GDS_ARRAY_SIZE(kcPolicies); i++)
        pol[i] = UA_STRING((char *)(uintptr_t)kcPolicies[i]);
    UA_VariableAttributes va = UA_VariableAttributes_default;
    va.displayName = UA_LOCALIZEDTEXT("", "SecurityPolicyUris");
    va.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
    va.valueRank = UA_VALUERANK_ONE_DIMENSION;
    UA_UInt32 dim = 0;
    va.arrayDimensions = &dim;
    va.arrayDimensionsSize = 1;
    UA_Variant_setArray(&va.value, pol, GDS_ARRAY_SIZE(pol), &UA_TYPES[UA_TYPES_STRING]);
    return UA_Server_addVariableNode(s->ua, UA_NODEID_NULL, *obj, UA_NS0ID(HASPROPERTY),
                                     UA_QUALIFIEDNAME(s->ns, "SecurityPolicyUris"),
                                     UA_NS0ID(PROPERTYTYPE), va, NULL, NULL);
}

static UA_StatusCode install_one(gds_server *s, gds_kc_service *k) {
    char sid[GDS_MAX_KC_SERVICE + 32];
    if(gds_path(sid, sizeof(sid), "KeyCredentialManagement/%s", k->name) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_ObjectAttributes oa = UA_ObjectAttributes_default;
    oa.displayName = UA_LOCALIZEDTEXT("", k->name);
    UA_StatusCode r = UA_Server_addObjectNode(
        s->ua, UA_NODEID_STRING(s->ns, sid), UA_NODEID_NUMERIC(s->ns, UA_GDSID_KEYCREDENTIALMANAGEMENT),
        UA_NS0ID(HASCOMPONENT), UA_QUALIFIEDNAME(s->ns, k->name),
        UA_NODEID_NUMERIC(s->ns, UA_GDSID_KEYCREDENTIALSERVICETYPE), oa, NULL, &k->node);
    UA_NodeId start = UA_NODEID_NULL, finish = UA_NODEID_NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = child(s, &k->node, "StartRequest", &start);
    if(r == UA_STATUSCODE_GOOD)
        r = child(s, &k->node, "FinishRequest", &finish);
    if(r == UA_STATUSCODE_GOOD)
        r = bind(s, &start, start_request);
    if(r == UA_STATUSCODE_GOOD)
        r = bind(s, &finish, finish_request);
    /* Revoke is Optional: the type's method, referenced (gds_approvals.c
     * does the same for Respond2) */
    UA_NodeId rev = UA_NODEID_NUMERIC(s->ns, UA_GDSID_KEYCREDENTIALSERVICETYPE_REVOKE);
    UA_NodeId probe = UA_NODEID_NULL;
    if(r == UA_STATUSCODE_GOOD && child(s, &k->node, "Revoke", &probe) != UA_STATUSCODE_GOOD)
        r = UA_Server_addReference(s->ua, k->node, UA_NS0ID(HASCOMPONENT),
                                   UA_EXPANDEDNODEID_NUMERIC(s->ns, rev.identifier.numeric), true);
    else if(r == UA_STATUSCODE_GOOD)
        rev = probe;
    if(r == UA_STATUSCODE_GOOD)
        r = bind(s, &rev, revoke);
    UA_String res = UA_STRING(k->resourceUri);
    UA_String prof[GDS_MAX_KC_PROFILES];
    for(size_t i = 0; i < k->nProfiles; i++)
        prof[i] = UA_STRING(k->profileUris[i]);
    if(r == UA_STATUSCODE_GOOD)
        r = write_prop(s, &k->node, "ResourceUri", &res, 1, false);
    if(r == UA_STATUSCODE_GOOD)
        r = write_prop(s, &k->node, "ProfileUris", prof, k->nProfiles, true);
    if(r == UA_STATUSCODE_GOOD)
        r = add_policies(s, &k->node);
    UA_NodeId_clear(&start);
    UA_NodeId_clear(&finish);
    UA_NodeId_clear(&probe);
    return r;
}

UA_StatusCode gds_keycred_install(gds_server *s) {
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && i < s->nKc; i++)
        r = install_one(s, &s->kc[i]);
    if(r != UA_STATUSCODE_GOOD)
        fprintf(stderr, "opengds: KeyCredentialService objects: %s\n", UA_StatusCode_name(r));
    return r;
}
