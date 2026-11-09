/* OpenGDS - the AuthorizationService (OPC 10000-12 §9.6): AccessTokens for
 * the Implicit and Explicit use cases of §9.3 and §9.4.
 *
 * Address space. One AuthorizationServiceType object, "OpenGDS", organized
 * by the AuthorizationServices folder (§9.6.2, §9.6.3). The GDS NodeSet of
 * open62541 v1.5.10 predates v1.05: its AuthorizationServiceType has no
 * StartRequestToken, FinishRequestToken, RefreshToken or SupportedRoles,
 * and AccessTokenRequestedAuditEventType is missing. They are added here
 * with the NodeIds of the v1.05.07 NodeSet (Opc.Ua.Gds.NodeIds.csv: 95, 98,
 * 64, 110, 111), unless the NodeSet already has them. RequestAccessToken
 * (§9.6.5) is deprecated, "because it can only be used with unencrypted
 * UserName IdentityTokens", and is not offered.
 *
 * UserTokenPolicies (§9.6.4, Table 149):
 *   opengds-session   Anonymous: the Session's own identity (Implicit,
 *                     §9.3): its user, or with no user the client
 *                     application (OPC 10000-4 §7.41: "the Client
 *                     ApplicationInstanceCertificate is used as the user
 *                     identification")
 *   opengds-username  UserName, SecurityPolicy None: the password of the
 *                     users file travels in clear inside the encrypted
 *                     SecureChannel these methods require (§9.6.6; OPC
 *                     10000-4 §7.40.2.1 allows a clear text password over
 *                     an encrypted SecureChannel)
 *   opengds-x509      Certificate, Basic256Sha256, only when X.509 users
 *                     are configured (users file x509-sha256 lines): the
 *                     UserTokenSignature is the legacy calculation of OPC
 *                     10000-4 §6.1.8 Table 102 (Basic256Sha256 has
 *                     SecureChannelEnhancements = FALSE) with ServiceData
 *                     in place of the ServerNonce (§9.6.7): RSA-PKCS1-v1_5
 *                     SHA-256 over GDS certificate || ServiceData.
 *
 * Every method needs an encrypted SecureChannel (Bad_SecurityModeInsufficient
 * first). The AccessTokenRequestor Privilege (§9.2) is held by a client whose
 * SecureChannel certificate the GDS CA issued (the application's identity,
 * gds_session.clientAppUri). ResourceIds are the ApplicationUris of Server
 * applications in the directory (OPC 10000-6 Table 55: "The default value
 * is the Server's ApplicationUri").
 *
 * Requests (StartRequestToken) live in memory for REQ_TTL and only for
 * their Session (§9.6.6). RefreshTokens are random 32-byte values; only
 * their SHA-256 is kept, in memory, bound to the client certificate that
 * received them (§9.6.8). A restart or a switchover forgets both, and the
 * client starts again with StartRequestToken. Each refresh replaces the
 * RefreshToken (NewRefreshToken) and reads the user's Roles again from the
 * users file, so a removed user or Role ends with the next refresh.
 *
 * Five failed identity checks from one client certificate lock it out for
 * LOCKOUT_TIME (OPC 10000-4 §7.40.2.1: "lock out Client applications after
 * five failures").
 *
 * Audit (§9.6.10, §9.6.11): AccessTokenRequestedAuditEventType for every
 * FinishRequestToken that names a live request, AccessTokenIssuedAuditEventType
 * for every token issued, by FinishRequestToken or RefreshToken. The v1.05
 * NodeSet marks both types IsAbstract, but §9.6.10 and §9.6.11 say the
 * events "are raised"; OpenGDS raises them with these types. Their
 * InputArguments never carry a password, a token or a nonce. Only
 * SecurityAdmin and AuthorizationServiceAdmin receive them.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gds_internal.h"
#include "common/banned.h"

/* v1.05.07 NodeIds (Opc.Ua.Gds.NodeIds.csv) */
#define ID_REFRESHTOKEN        64
#define ID_REFRESHTOKEN_IN     65
#define ID_REFRESHTOKEN_OUT    66
#define ID_STARTREQUESTTOKEN   95
#define ID_STARTREQUEST_IN     96
#define ID_STARTREQUEST_OUT    97
#define ID_FINISHREQUESTTOKEN  98
#define ID_FINISHREQUEST_IN    99
#define ID_FINISHREQUEST_OUT   100
#define ID_SUPPORTEDROLES      110
#define ID_AT_REQUESTED_EVENT  111

#define SERVICE_NAME "OpenGDS"
#define NODE_PREFIX  "AuthorizationServices.OpenGDS"
#define POLICY_SESSION  "opengds-session"
#define POLICY_USERNAME "opengds-username"
#define POLICY_X509     "opengds-x509"
#define URI_RSA_SHA256  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

#define MAX_REQUESTS   256
#define MAX_REFRESH    1024
#define MAX_LOCKOUTS   64
#define LOCKOUT_FAILS  5
#define REQ_TTL        ((UA_DateTime)300 * UA_DATETIME_SEC)
#define LOCKOUT_TIME   ((UA_DateTime)300 * UA_DATETIME_SEC)
#define NONCE_LEN      32
#define NONCE_MIN      32  /* OPC 10000-4 §7.40.2.3: 32 to 128 bytes */
#define NONCE_MAX      128
#define SUBJECT_MAX    (GDS_MAX_APPLICATION_URI + 1)
#define SEVERITY_SECURITY 500

typedef enum { POL_SESSION = 0, POL_USERNAME = 1, POL_X509 = 2, POL_COUNT = 3 } az_policy;

typedef struct {
    bool used;
    UA_Guid id;
    UA_NodeId session;
    char resource[GDS_MAX_APPLICATION_URI + 1];
    az_policy policy;
    uint8_t serviceData[NONCE_LEN];
    UA_DateTime created; /* monotonic */
} az_request;

typedef struct {
    bool used;
    uint8_t hash[32];   /* SHA-256 of the RefreshToken */
    uint8_t client[32]; /* SHA-256 of the client certificate */
    char resource[GDS_MAX_APPLICATION_URI + 1];
    bool user;          /* subject is a users-file user, else an ApplicationUri */
    char subject[SUBJECT_MAX];
    unsigned roles;     /* what the token may carry, re-read at refresh */
    UA_DateTime expires;
} az_refresh;

typedef struct {
    uint8_t client[32];
    unsigned fails;
    UA_DateTime until; /* monotonic */
} az_lockout;

struct gds_authz {
    pthread_mutex_t lock; /* leaf lock over the tables */
    char *serviceUri;
    gds_buf serviceCert; /* the chain */
    uint8_t x5t[GDS_JWT_THUMBPRINT];
    gds_buf ownCert; /* the GDS application certificate (X.509 signatures) */
    gds_jwt_sign_fn sign;
    void *signCtx;
    gds_status (*chain)(void *ctx, const char *serviceUri, gds_buf *out);
    int64_t certNotAfter; /* Unix seconds, of the first certificate */
    int64_t lastFetch;    /* the last chain() call */
    char alg[8];
    uint32_t accessLifetime, refreshLifetime;
    bool x509;
    UA_NodeId object;
    az_request req[MAX_REQUESTS];
    az_refresh refresh[MAX_REFRESH];
    az_lockout lockout[MAX_LOCKOUTS];
};

/* The identity a token is issued to. */
typedef struct {
    bool user;
    char subject[SUBJECT_MAX];
    unsigned roles;
} az_identity;

static const char *const policyIds[POL_COUNT] = {POLICY_SESSION, POLICY_USERNAME, POLICY_X509};

/* ---- small helpers ---- */

static gds_status sha256(const uint8_t *d, size_t n, uint8_t out[32]) {
    unsigned len = 0;
    return EVP_Digest(d, n, out, &len, EVP_sha256(), NULL) == 1 && len == 32 ? GDS_OK
                                                                            : GDS_ECRYPTO;
}

static bool copy_str(char *dst, size_t cap, const UA_String *s) {
    if(s->length == 0 || s->length >= cap || memchr(s->data, 0, s->length))
        return false;
    memcpy(dst, s->data, s->length);
    dst[s->length] = 0;
    return true;
}

static int64_t unix_now(void) {
    return (int64_t)UA_DateTime_toUnixTime(UA_DateTime_now());
}

static const gds_session *session_of(const void *sessionContext) {
    return gds_session_get(sessionContext);
}

/* Every method: an encrypted SecureChannel (§9.6.6 to §9.6.8). */
static UA_StatusCode channel_ok(const void *sessionContext) {
    const gds_session *ss = session_of(sessionContext);
    return ss && ss->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT
               ? UA_STATUSCODE_GOOD
               : UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;
}

/* The AccessTokenRequestor Privilege (§9.2): the SecureChannel certificate
 * names an application, which only a certificate of the GDS CA does. */
static bool requestor(const void *sessionContext) {
    const gds_session *ss = session_of(sessionContext);
    return ss && ss->clientAppUri.length > 0 && ss->clientCert.length > 0;
}

static gds_status client_thumb(const void *sessionContext, uint8_t out[32]) {
    const gds_session *ss = session_of(sessionContext);
    if(!ss || ss->clientCert.length == 0)
        return GDS_EDENIED;
    return sha256(ss->clientCert.data, ss->clientCert.length, out);
}

/* ResourceId (§9.6.6): a Server application of the directory. */
static bool resource_known(gds_server *s, const UA_String *uri) {
    if(uri->length == 0 || uri->length > GDS_MAX_APPLICATION_URI)
        return false;
    UA_ApplicationRecordDataType *found = NULL;
    size_t n = 0;
    gds_lock(s);
    gds_status st = gds_store_app_find_uri(s->store, uri, 4, &found, &n);
    gds_unlock(s);
    bool ok = false;
    for(size_t i = 0; st == GDS_OK && i < n && !ok; i++)
        ok = found[i].applicationType != UA_APPLICATIONTYPE_CLIENT;
    UA_Array_delete(found, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    return ok;
}

/* ---- lockout (OPC 10000-4 §7.40.2.1); lock held ---- */

static az_lockout *lockout_find(struct gds_authz *a, const uint8_t c[32], bool add) {
    az_lockout *oldest = &a->lockout[0];
    for(size_t i = 0; i < MAX_LOCKOUTS; i++) {
        if(CRYPTO_memcmp(a->lockout[i].client, c, 32) == 0 &&
           (a->lockout[i].fails || a->lockout[i].until))
            return &a->lockout[i];
        if(a->lockout[i].until < oldest->until)
            oldest = &a->lockout[i];
    }
    if(!add)
        return NULL;
    memset(oldest, 0, sizeof(*oldest));
    memcpy(oldest->client, c, 32);
    return oldest;
}

static bool locked_out(gds_server *s, const uint8_t c[32]) {
    struct gds_authz *a = s->authz;
    pthread_mutex_lock(&a->lock);
    az_lockout *l = lockout_find(a, c, false);
    bool locked = l && l->until > UA_DateTime_nowMonotonic();
    pthread_mutex_unlock(&a->lock);
    return locked;
}

static void note_failure(gds_server *s, const uint8_t c[32]) {
    struct gds_authz *a = s->authz;
    pthread_mutex_lock(&a->lock);
    az_lockout *l = lockout_find(a, c, true);
    UA_DateTime now = UA_DateTime_nowMonotonic();
    if(l->until && l->until <= now) { /* an expired lockout starts over */
        l->until = 0;
        l->fails = 0;
    }
    if(++l->fails >= LOCKOUT_FAILS) {
        l->until = now + LOCKOUT_TIME;
        l->fails = 0;
        fprintf(stderr, "opengds: AuthorizationService: a client is locked out after %d failed "
                        "identity checks\n", LOCKOUT_FAILS);
    }
    pthread_mutex_unlock(&a->lock);
}

static void note_success(gds_server *s, const uint8_t c[32]) {
    struct gds_authz *a = s->authz;
    pthread_mutex_lock(&a->lock);
    az_lockout *l = lockout_find(a, c, false);
    if(l && l->until <= UA_DateTime_nowMonotonic())
        memset(l, 0, sizeof(*l));
    pthread_mutex_unlock(&a->lock);
}

/* ---- requests; lock held ---- */

static void requests_expire(struct gds_authz *a) {
    UA_DateTime now = UA_DateTime_nowMonotonic();
    for(size_t i = 0; i < MAX_REQUESTS; i++) {
        az_request *q = &a->req[i];
        if(q->used && (now - q->created > REQ_TTL || !gds_access_session_live(&q->session))) {
            UA_NodeId_clear(&q->session);
            OPENSSL_cleanse(q, sizeof(*q));
        }
    }
}

/* Takes the request (single use): only from the Session that started it. */
static bool request_take(struct gds_authz *a, const UA_Guid *id, const UA_NodeId *session,
                         az_request *out) {
    requests_expire(a);
    for(size_t i = 0; i < MAX_REQUESTS; i++) {
        az_request *q = &a->req[i];
        if(q->used && UA_Guid_equal(&q->id, id) && UA_NodeId_equal(&q->session, session)) {
            *out = *q;
            out->session = UA_NODEID_NULL;
            UA_NodeId_clear(&q->session);
            OPENSSL_cleanse(q, sizeof(*q));
            return true;
        }
    }
    return false;
}

/* ---- refresh tokens; lock held ---- */

static void refresh_expire(struct gds_authz *a) {
    UA_DateTime now = UA_DateTime_now();
    for(size_t i = 0; i < MAX_REFRESH; i++)
        if(a->refresh[i].used && a->refresh[i].expires <= now)
            OPENSSL_cleanse(&a->refresh[i], sizeof(a->refresh[i]));
}

static az_refresh *refresh_find(struct gds_authz *a, const uint8_t hash[32]) {
    refresh_expire(a);
    for(size_t i = 0; i < MAX_REFRESH; i++)
        if(a->refresh[i].used && CRYPTO_memcmp(a->refresh[i].hash, hash, 32) == 0)
            return &a->refresh[i];
    return NULL;
}

static az_refresh *refresh_slot(struct gds_authz *a) {
    refresh_expire(a);
    az_refresh *soonest = NULL;
    for(size_t i = 0; i < MAX_REFRESH; i++) {
        if(!a->refresh[i].used)
            return &a->refresh[i];
        if(!soonest || a->refresh[i].expires < soonest->expires)
            soonest = &a->refresh[i];
    }
    /* full: the one closest to expiry goes; its holder starts over */
    OPENSSL_cleanse(soonest, sizeof(*soonest));
    return soonest;
}

/* ---- Roles ---- */

/* The names of the Roles in bits, at most max (borrowed, static). */
static size_t role_names(gds_server *s, unsigned bits, const char **out, size_t max) {
    size_t n = 0;
    for(size_t i = 0; i < gds_role_count() && n < max; i++) {
        UA_NodeId id;
        unsigned bit = 0;
        const char *name = NULL;
        gds_role_at(i, s->ns, &id, &bit, &name);
        if((bits & bit) && name)
            out[n++] = name;
    }
    return n;
}

/* RequestedRoles (§9.6.7): a subset of the available Roles; none: all. */
static UA_StatusCode requested_roles(gds_server *s, const UA_String *names, size_t n,
                                     unsigned available, unsigned *granted) {
    if(n == 0) {
        *granted = available;
        return UA_STATUSCODE_GOOD;
    }
    unsigned want = 0;
    for(size_t k = 0; k < n; k++) {
        unsigned found = 0;
        for(size_t i = 0; i < gds_role_count() && !found; i++) {
            UA_NodeId id;
            unsigned bit = 0;
            const char *name = NULL;
            gds_role_at(i, s->ns, &id, &bit, &name);
            if(name && names[k].length == strlen(name) &&
               memcmp(names[k].data, name, names[k].length) == 0)
                found = bit;
        }
        if(!found)
            return UA_STATUSCODE_BADINVALIDARGUMENT; /* not in SupportedRoles */
        want |= found;
    }
    if((want & ~available) != 0)
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    *granted = want;
    return UA_STATUSCODE_GOOD;
}

/* ---- issuing ---- */

static gds_status random_bytes(uint8_t *out, size_t n) {
    return RAND_bytes(out, (int)n) == 1 ? GDS_OK : GDS_ECRYPTO;
}

static gds_status make_jti(char out[37]) {
    uint8_t r[16];
    gds_status st = random_bytes(r, sizeof(r));
    if(st != GDS_OK)
        return st;
    r[6] = (uint8_t)((r[6] & 0x0F) | 0x40); /* RFC 9562 version 4 */
    r[8] = (uint8_t)((r[8] & 0x3F) | 0x80);
    static const char hx[] = "0123456789abcdef";
    size_t o = 0;
    for(size_t i = 0; i < 16; i++) {
        if(i == 4 || i == 6 || i == 8 || i == 10)
            out[o++] = '-';
        out[o++] = hx[r[i] >> 4];
        out[o++] = hx[r[i] & 15];
    }
    out[o] = 0;
    return GDS_OK;
}

typedef struct {
    gds_buf access;
    UA_DateTime accessExpiry;
    gds_buf refresh; /* NUL-terminated base64url, empty when none */
    UA_DateTime refreshExpiry;
} az_tokens;

static void tokens_clear(az_tokens *t) {
    gds_buf_free_secret(&t->access);
    gds_buf_free_secret(&t->refresh);
}

static void renew_chain(gds_server *s);

static gds_status issue(gds_server *s, const az_identity *who, const char *resource,
                        const uint8_t client[32], az_tokens *t) {
    struct gds_authz *a = s->authz;
    memset(t, 0, sizeof(*t));
    const char *roles[GDS_JWT_MAX_ROLES];
    size_t nRoles = role_names(s, who->roles, roles, GDS_JWT_MAX_ROLES);
    char jti[37];
    gds_status st = make_jti(jti);
    int64_t now = unix_now();
    gds_jwt_claims c;
    memset(&c, 0, sizeof(c));
    c.iss = a->serviceUri;
    c.sub = who->subject;
    c.aud = resource;
    c.jti = jti;
    c.iat = now;
    c.nbf = now;
    c.exp = now + (int64_t)a->accessLifetime;
    c.roles = roles;
    c.nRoles = nRoles;
    c.cnfThumbprint = client;
    renew_chain(s);
    uint8_t x5t[GDS_JWT_THUMBPRINT];
    pthread_mutex_lock(&a->lock);
    memcpy(x5t, a->x5t, sizeof(x5t));
    pthread_mutex_unlock(&a->lock);
    if(st == GDS_OK)
        st = gds_jwt_make(a->alg, x5t, &c, a->sign, a->signCtx, &t->access);
    if(st != GDS_OK)
        return st;
    t->accessExpiry = UA_DateTime_fromUnixTime(c.exp);
    if(a->refreshLifetime == 0)
        return GDS_OK; /* outputs a null RefreshToken */
    uint8_t raw[32], hash[32];
    st = random_bytes(raw, sizeof(raw));
    if(st == GDS_OK)
        st = gds_b64url(raw, sizeof(raw), &t->refresh);
    if(st == GDS_OK)
        st = sha256(t->refresh.data, t->refresh.len, hash);
    OPENSSL_cleanse(raw, sizeof(raw));
    if(st != GDS_OK) {
        tokens_clear(t);
        return st;
    }
    t->refreshExpiry = UA_DateTime_now() + (UA_DateTime)a->refreshLifetime * UA_DATETIME_SEC;
    pthread_mutex_lock(&a->lock);
    az_refresh *r = refresh_slot(a);
    r->used = true;
    memcpy(r->hash, hash, 32);
    memcpy(r->client, client, 32);
    (void)snprintf(r->resource, sizeof(r->resource), "%s", resource);
    r->user = who->user;
    (void)snprintf(r->subject, sizeof(r->subject), "%s", who->subject);
    r->roles = who->roles;
    r->expires = t->refreshExpiry;
    pthread_mutex_unlock(&a->lock);
    return GDS_OK;
}

static UA_StatusCode token_outputs(const az_tokens *t, UA_Variant *output) {
    UA_String at = {t->access.len, t->access.data};
    UA_String rt = {t->refresh.len, t->refresh.data};
    UA_StatusCode r = UA_Variant_setScalarCopy(&output[0], &at, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[1], &t->accessExpiry, &UA_TYPES[UA_TYPES_DATETIME]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[2], &rt, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[3], &t->refreshExpiry, &UA_TYPES[UA_TYPES_DATETIME]);
    return r;
}

/* ---- audit (§9.6.10, §9.6.11) ---- */

static const char *actor_of(const void *sessionContext, char *buf, size_t cap) {
    const gds_session *ss = session_of(sessionContext);
    if(ss && !gds_session_anonymous(ss) && ss->user[0])
        return ss->user;
    if(ss && ss->clientAppUri.length > 0 && ss->clientAppUri.length < cap) {
        memcpy(buf, ss->clientAppUri.data, ss->clientAppUri.length);
        buf[ss->clientAppUri.length] = 0;
        return buf;
    }
    return NULL;
}

static void audit(gds_server *s, const void *sessionContext, UA_UInt32 type, UA_UInt32 method,
                  const UA_Variant *args, size_t nArgs, bool ok, const char *msg) {
    char abuf[GDS_MAX_APPLICATION_URI + 1];
    const char *actor = actor_of(sessionContext, abuf, sizeof(abuf));
    gds_event_field f[2];
    UA_NodeId methodId = UA_NODEID_NUMERIC(s->ns, method);
    f[0].nsIndex = 0;
    f[0].name = "MethodId";
    UA_Variant_setScalar(&f[0].value, &methodId, &UA_TYPES[UA_TYPES_NODEID]);
    f[1].nsIndex = 0;
    f[1].name = "InputArguments";
    UA_Variant_setArray(&f[1].value, (void *)(uintptr_t)args, nArgs, &UA_TYPES[UA_TYPES_VARIANT]);
    UA_NodeId visible[2] = {UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN),
                            UA_NODEID_NUMERIC(s->ns, UA_GDSID_WELLKNOWNROLE_AUTHORIZATIONSERVICEADMIN)};
    gds_audit_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.abi_major = GDS_PLUGIN_ABI_MAJOR;
    ev.abi_minor = GDS_PLUGIN_ABI_MINOR;
    ev.struct_size = sizeof(ev);
    ev.eventType = UA_NODEID_NUMERIC(s->ns, type);
    ev.sourceNode = s->authz->object;
    ev.severity = SEVERITY_SECURITY;
    ev.message = msg;
    ev.status = ok;
    ev.fields = f;
    ev.fieldsSize = 2;
    ev.visibleTo = visible;
    ev.visibleToSize = 2;
    gds_status st = gds_audit_raise(s, actor, &ev, NULL);
    if(st != GDS_OK)
        fprintf(stderr, "opengds: AuthorizationService audit event: %s\n", gds_status_name(st));
}

static void audit_issued(gds_server *s, const void *sessionContext, UA_UInt32 method,
                         const UA_Variant *args, size_t nArgs, const az_identity *who,
                         const char *resource) {
    char msg[GDS_MAX_STRING];
    (void)snprintf(msg, sizeof(msg), "AccessToken issued to %s for %s", who->subject, resource);
    audit(s, sessionContext, UA_GDSID_ACCESSTOKENISSUEDAUDITEVENTTYPE, method, args, nArgs, true,
          msg);
}

/* ---- GetServiceDescription (§9.6.9) ---- */

static UA_StatusCode policies(const struct gds_authz *a, UA_UserTokenPolicy **out, size_t *n) {
    size_t count = a->x509 ? 3 : 2;
    UA_UserTokenPolicy p[3];
    memset(p, 0, sizeof(p));
    p[0].policyId = UA_STRING((char *)(uintptr_t)POLICY_SESSION);
    p[0].tokenType = UA_USERTOKENTYPE_ANONYMOUS;
    p[1].policyId = UA_STRING((char *)(uintptr_t)POLICY_USERNAME);
    p[1].tokenType = UA_USERTOKENTYPE_USERNAME;
    p[1].securityPolicyUri = UA_SECURITY_POLICY_NONE_URI;
    p[2].policyId = UA_STRING((char *)(uintptr_t)POLICY_X509);
    p[2].tokenType = UA_USERTOKENTYPE_CERTIFICATE;
    p[2].securityPolicyUri = UA_STRING((char *)(uintptr_t)"http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    UA_StatusCode r = UA_Array_copy(p, count, (void **)out, &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
    *n = r == UA_STATUSCODE_GOOD ? count : 0;
    return r;
}

static GDS_METHOD(get_service_description) {
    GDS_METHOD_UNUSED;
    (void)inputSize, (void)input;
    gds_server *s = gds_ctx(methodContext);
    if(!s->authz || !session_of(sessionContext))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    struct gds_authz *a = s->authz;
    UA_String uri = UA_STRING(a->serviceUri);
    UA_UserTokenPolicy *p = NULL;
    size_t n = 0;
    UA_StatusCode r = UA_Variant_setScalarCopy(&output[0], &uri, &UA_TYPES[UA_TYPES_STRING]);
    pthread_mutex_lock(&a->lock); /* renew_chain swaps the chain */
    UA_ByteString cert = {a->serviceCert.len, a->serviceCert.data};
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[1], &cert, &UA_TYPES[UA_TYPES_BYTESTRING]);
    pthread_mutex_unlock(&a->lock);
    if(r == UA_STATUSCODE_GOOD)
        r = policies(a, &p, &n);
    if(r == UA_STATUSCODE_GOOD)
        UA_Variant_setArray(&output[2], p, n, &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
    return r;
}

/* ---- StartRequestToken (§9.6.6) ---- */

static bool policy_by_id(const struct gds_authz *a, const UA_String *id, az_policy *out) {
    for(size_t i = 0; i < POL_COUNT; i++) {
        if(i == POL_X509 && !a->x509)
            continue;
        UA_String p = UA_STRING((char *)(uintptr_t)policyIds[i]);
        if(UA_String_equal(id, &p)) {
            *out = (az_policy)i;
            return true;
        }
    }
    return false;
}

static GDS_METHOD(start_request_token) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    struct gds_authz *a = s->authz;
    UA_StatusCode r = channel_ok(sessionContext);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_String *res = NULL, *pol = NULL;
    const UA_ByteString *rdata = NULL;
    if(inputSize < 3)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if(inputSize > 3)
        return UA_STATUSCODE_BADTOOMANYARGUMENTS;
    if(gds_arg_string(&input[0], GDS_MAX_APPLICATION_URI, &res) != UA_STATUSCODE_GOOD ||
       gds_arg_string(&input[1], GDS_MAX_STRING, &pol) != UA_STATUSCODE_GOOD ||
       gds_arg_bytes(&input[2], GDS_MAX_STRING, &rdata) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(!resource_known(s, res))
        return UA_STATUSCODE_BADNOTFOUND;
    az_policy p;
    if(!policy_by_id(a, pol, &p))
        return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
    /* Table 149: only the Certificate row uses RequestorData */
    bool needNonce = p == POL_X509;
    if(needNonce ? rdata->length < NONCE_MIN || rdata->length > NONCE_MAX : rdata->length != 0)
        return UA_STATUSCODE_BADNONCEINVALID;
    if(!requestor(sessionContext))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    r = gds_refuse_on_standby(s);
    if(r != UA_STATUSCODE_GOOD)
        return r;

    az_request q;
    memset(&q, 0, sizeof(q));
    q.used = true;
    q.id = UA_Guid_random();
    q.policy = p;
    q.created = UA_DateTime_nowMonotonic();
    if(!copy_str(q.resource, sizeof(q.resource), res) ||
       (needNonce && random_bytes(q.serviceData, sizeof(q.serviceData)) != GDS_OK) ||
       UA_NodeId_copy(sessionId, &q.session) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_ByteString sd = {needNonce ? sizeof(q.serviceData) : 0, needNonce ? q.serviceData : NULL};
    r = UA_Variant_setScalarCopy(&output[0], &sd, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[1], &q.id, &UA_TYPES[UA_TYPES_GUID]);
    if(r != UA_STATUSCODE_GOOD) {
        UA_NodeId_clear(&q.session);
        return r;
    }
    pthread_mutex_lock(&a->lock);
    requests_expire(a);
    az_request *slot = NULL;
    for(size_t i = 0; i < MAX_REQUESTS && !slot; i++)
        if(!a->req[i].used)
            slot = &a->req[i];
    if(slot)
        *slot = q;
    pthread_mutex_unlock(&a->lock);
    if(!slot) {
        UA_NodeId_clear(&q.session);
        return UA_STATUSCODE_BADTOOMANYOPERATIONS;
    }
    return UA_STATUSCODE_GOOD;
}

/* ---- FinishRequestToken (§9.6.7) ---- */

/* The identity token, decoded: open62541 unwraps a known ExtensionObject
 * into the Variant, a client may also send it wrapped. */
static const void *token_of(const UA_Variant *v, const UA_DataType **type) {
    *type = NULL;
    if(!UA_Variant_isScalar(v) || !v->data)
        return NULL;
    if(v->type == &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]) {
        const UA_ExtensionObject *eo = v->data;
        if(eo->encoding < UA_EXTENSIONOBJECT_DECODED)
            return NULL;
        *type = eo->content.decoded.type;
        return eo->content.decoded.data;
    }
    *type = v->type;
    return v->data;
}

static bool same_policy_id(const UA_String *got, az_policy p) {
    UA_String want = UA_STRING((char *)(uintptr_t)policyIds[p]);
    return UA_String_equal(got, &want);
}

/* The Session's own identity (Implicit, §9.3). */
static UA_StatusCode identity_session(const void *sessionContext, az_identity *who) {
    const gds_session *ss = session_of(sessionContext);
    if(ss && !gds_session_anonymous(ss) && ss->user[0]) {
        who->user = true;
        (void)snprintf(who->subject, sizeof(who->subject), "%s", ss->user);
        who->roles = gds_session_roles(ss);
        return UA_STATUSCODE_GOOD;
    }
    if(ss && copy_str(who->subject, sizeof(who->subject), &ss->clientAppUri)) {
        who->user = false;
        who->roles = 0;
        return UA_STATUSCODE_GOOD;
    }
    return UA_STATUSCODE_BADUSERACCESSDENIED;
}

static UA_StatusCode identity_username(const UA_UserNameIdentityToken *t, az_identity *who) {
    /* SecurityPolicy None (Table 149): the password is not encrypted */
    if(t->encryptionAlgorithm.length != 0)
        return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
    const gds_user *u = gds_users_check(gds_access_users(), &t->userName, &t->password);
    if(!u)
        return UA_STATUSCODE_BADIDENTITYTOKENREJECTED;
    who->user = true;
    (void)snprintf(who->subject, sizeof(who->subject), "%s", u->name);
    who->roles = gds_user_roles(u);
    return UA_STATUSCODE_GOOD;
}

/* RSA-PKCS1-v1_5 SHA-256 over the GDS certificate || ServiceData. */
static bool x509_signature_ok(const struct gds_authz *a, X509 *x, const az_request *q,
                              const UA_SignatureData *sig) {
    UA_String rsa = UA_STRING((char *)(uintptr_t)URI_RSA_SHA256);
    if(sig->algorithm.length && !UA_String_equal(&sig->algorithm, &rsa))
        return false;
    if(sig->signature.length == 0 || a->ownCert.len > SIZE_MAX - NONCE_LEN)
        return false;
    EVP_PKEY *pk = X509_get0_pubkey(x);
    if(!pk || !EVP_PKEY_is_a(pk, "RSA"))
        return false;
    size_t n = a->ownCert.len + NONCE_LEN;
    uint8_t *data = malloc(n);
    if(!data)
        return false;
    memcpy(data, a->ownCert.data, a->ownCert.len);
    memcpy(data + a->ownCert.len, q->serviceData, NONCE_LEN);
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    bool ok = mc && EVP_DigestVerifyInit(mc, NULL, EVP_sha256(), NULL, pk) == 1 &&
              EVP_DigestVerify(mc, sig->signature.data, sig->signature.length, data, n) == 1;
    EVP_MD_CTX_free(mc);
    free(data);
    return ok;
}

static UA_StatusCode identity_x509(gds_server *s, const UA_X509IdentityToken *t,
                                   const az_request *q, const UA_SignatureData *sig,
                                   az_identity *who) {
    struct gds_authz *a = s->authz;
    const UA_ByteString *c = &t->certificateData;
    if(c->length == 0 || c->length > GDS_MAX_CERT_SIZE)
        return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
    const unsigned char *p = c->data;
    X509 *x = d2i_X509(NULL, &p, (long)c->length);
    if(!x || p != c->data + c->length) {
        X509_free(x);
        return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
    }
    UA_StatusCode r = UA_STATUSCODE_BADIDENTITYTOKENREJECTED;
    const gds_user *u = gds_users_check_cert(gds_access_users(), c);
    /* the DefaultUserTokenGroup trust list, as for ActivateSession
     * (OPC 10000-4 §6.1.3: validity, trust, revocation) */
    UA_CertificateGroup *pki = &UA_Server_getConfig(s->ua)->sessionPKI;
    if(u && pki->verifyCertificate && pki->verifyCertificate(pki, c) == UA_STATUSCODE_GOOD &&
       X509_cmp_current_time(X509_get0_notAfter(x)) > 0 &&
       X509_cmp_current_time(X509_get0_notBefore(x)) < 0 && x509_signature_ok(a, x, q, sig)) {
        who->user = true;
        (void)snprintf(who->subject, sizeof(who->subject), "%s", u->name);
        who->roles = gds_user_roles(u);
        r = UA_STATUSCODE_GOOD;
    }
    X509_free(x);
    return r;
}

static UA_StatusCode identity_of(gds_server *s, const void *sessionContext, const az_request *q,
                                 const UA_Variant *tokenArg, const UA_Variant *sigArg,
                                 az_identity *who) {
    const UA_DataType *type = NULL;
    const void *tok = token_of(tokenArg, &type);
    const UA_SignatureData *sig = NULL;
    if(UA_Variant_hasScalarType(sigArg, &UA_TYPES[UA_TYPES_SIGNATUREDATA]))
        sig = sigArg->data;
    switch(q->policy) {
    case POL_SESSION:
        /* no token, or an Anonymous token of this policy */
        if(tok && (type != &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN] ||
                   !same_policy_id(&((const UA_AnonymousIdentityToken *)tok)->policyId,
                                   POL_SESSION)))
            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
        return identity_session(sessionContext, who);
    case POL_USERNAME:
        if(!tok || type != &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN] ||
           !same_policy_id(&((const UA_UserNameIdentityToken *)tok)->policyId, POL_USERNAME))
            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
        return identity_username(tok, who);
    case POL_X509:
        if(!tok || type != &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN] ||
           !same_policy_id(&((const UA_X509IdentityToken *)tok)->policyId, POL_X509) || !sig)
            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
        return identity_x509(s, tok, q, sig, who);
    case POL_COUNT:
    default:
        return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
    }
}

/* The InputArguments of the audit event: the token without its secret,
 * no UserTokenSignature. */
static UA_StatusCode finish_audit_args(const UA_Variant *input, UA_Variant out[4],
                                       UA_UserNameIdentityToken *scrub) {
    out[0] = input[0];
    out[1] = input[1];
    const UA_DataType *type = NULL;
    const void *tok = token_of(&input[2], &type);
    UA_Variant_init(&out[2]);
    UA_Variant_init(&out[3]);
    if(tok && type == &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]) {
        const UA_UserNameIdentityToken *u = tok;
        UA_UserNameIdentityToken_init(scrub);
        scrub->policyId = u->policyId;
        scrub->userName = u->userName;
        UA_Variant_setScalar(&out[2], scrub, &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]);
    } else if(tok && type) {
        UA_Variant_setScalar(&out[2], (void *)(uintptr_t)tok, type);
    }
    return UA_STATUSCODE_GOOD;
}

static GDS_METHOD(finish_request_token) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    struct gds_authz *a = s->authz;
    UA_StatusCode r = channel_ok(sessionContext);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(inputSize < 4)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if(inputSize > 4)
        return UA_STATUSCODE_BADTOOMANYARGUMENTS;
    const UA_Guid *rid = NULL;
    const UA_String *roles = NULL;
    size_t nRoles = 0;
    if(gds_arg_scalar(&input[0], &UA_TYPES[UA_TYPES_GUID], (const void **)&rid) !=
           UA_STATUSCODE_GOOD ||
       gds_arg_array(&input[1], &UA_TYPES[UA_TYPES_STRING], GDS_JWT_MAX_ROLES,
                     (const void **)&roles, &nRoles) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    az_request q;
    pthread_mutex_lock(&a->lock);
    bool found = request_take(a, rid, sessionId, &q);
    pthread_mutex_unlock(&a->lock);
    if(!found)
        return UA_STATUSCODE_BADNOTFOUND;
    r = gds_refuse_on_standby(s);
    uint8_t client[32];
    if(r == UA_STATUSCODE_GOOD && (!requestor(sessionContext) ||
                                   client_thumb(sessionContext, client) != GDS_OK))
        r = UA_STATUSCODE_BADUSERACCESSDENIED;
    if(r == UA_STATUSCODE_GOOD && locked_out(s, client))
        r = UA_STATUSCODE_BADUSERACCESSDENIED;
    az_identity who;
    memset(&who, 0, sizeof(who));
    if(r == UA_STATUSCODE_GOOD) {
        r = identity_of(s, sessionContext, &q, &input[2], &input[3], &who);
        if(r == UA_STATUSCODE_BADIDENTITYTOKENREJECTED || r == UA_STATUSCODE_BADIDENTITYTOKENINVALID)
            note_failure(s, client);
        else if(r == UA_STATUSCODE_GOOD)
            note_success(s, client);
    }
    unsigned granted = 0;
    if(r == UA_STATUSCODE_GOOD)
        r = requested_roles(s, roles, nRoles, who.roles, &granted);
    UA_Variant args[4];
    UA_UserNameIdentityToken scrub;
    (void)finish_audit_args(input, args, &scrub);
    char msg[GDS_MAX_STRING];
    (void)snprintf(msg, sizeof(msg), "AccessToken requested for %s%s%s", q.resource,
                   who.subject[0] ? " by " : "", who.subject);
    if(r != UA_STATUSCODE_BADINVALIDSTATE)
        audit(s, sessionContext, ID_AT_REQUESTED_EVENT, ID_FINISHREQUESTTOKEN, args, 4,
              r == UA_STATUSCODE_GOOD, msg);
    char resource[GDS_MAX_APPLICATION_URI + 1];
    memcpy(resource, q.resource, sizeof(resource));
    OPENSSL_cleanse(&q, sizeof(q));
    if(r != UA_STATUSCODE_GOOD)
        return r;
    who.roles = granted;
    az_tokens t;
    gds_status st = issue(s, &who, resource, client, &t);
    if(st != GDS_OK) {
        fprintf(stderr, "opengds: issuing an AccessToken failed: %s\n", gds_status_name(st));
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    r = token_outputs(&t, output);
    tokens_clear(&t);
    if(r == UA_STATUSCODE_GOOD)
        audit_issued(s, sessionContext, ID_FINISHREQUESTTOKEN, args, 4, &who, resource);
    return r;
}

/* ---- RefreshToken (§9.6.8) ---- */

static GDS_METHOD(refresh_token) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    struct gds_authz *a = s->authz;
    UA_StatusCode r = channel_ok(sessionContext);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(inputSize < 2)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if(inputSize > 2)
        return UA_STATUSCODE_BADTOOMANYARGUMENTS;
    const UA_String *res = NULL, *cur = NULL;
    if(gds_arg_string(&input[0], GDS_MAX_APPLICATION_URI, &res) != UA_STATUSCODE_GOOD ||
       gds_arg_string(&input[1], GDS_MAX_STRING, &cur) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(!resource_known(s, res))
        return UA_STATUSCODE_BADNOTFOUND;
    uint8_t client[32], hash[32];
    if(!requestor(sessionContext) || client_thumb(sessionContext, client) != GDS_OK)
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    r = gds_refuse_on_standby(s);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(cur->length == 0 || sha256(cur->data, cur->length, hash) != GDS_OK)
        return UA_STATUSCODE_BADIDENTITYTOKENREJECTED;
    /* §9.6.8: only for the client certificate it was issued to; single use */
    az_refresh got;
    bool ok = false;
    pthread_mutex_lock(&a->lock);
    az_refresh *e = refresh_find(a, hash);
    if(e && CRYPTO_memcmp(e->client, client, 32) == 0 && res->length == strlen(e->resource) &&
       memcmp(res->data, e->resource, res->length) == 0) {
        got = *e;
        ok = true;
        OPENSSL_cleanse(e, sizeof(*e));
    }
    pthread_mutex_unlock(&a->lock);
    if(!ok)
        return UA_STATUSCODE_BADIDENTITYTOKENREJECTED;
    az_identity who;
    memset(&who, 0, sizeof(who));
    who.user = got.user;
    memcpy(who.subject, got.subject, sizeof(who.subject));
    who.roles = got.roles;
    if(got.user) {
        /* the Roles in force now: a removed user or Role ends here */
        const gds_user *u = gds_users_find(gds_access_users(), got.subject);
        if(!u) {
            OPENSSL_cleanse(&got, sizeof(got));
            return UA_STATUSCODE_BADIDENTITYTOKENREJECTED;
        }
        who.roles &= gds_user_roles(u);
    }
    char resource[GDS_MAX_APPLICATION_URI + 1];
    memcpy(resource, got.resource, sizeof(resource));
    OPENSSL_cleanse(&got, sizeof(got));
    az_tokens t;
    gds_status st = issue(s, &who, resource, client, &t);
    if(st != GDS_OK) {
        fprintf(stderr, "opengds: refreshing an AccessToken failed: %s\n", gds_status_name(st));
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    r = token_outputs(&t, output);
    tokens_clear(&t);
    if(r == UA_STATUSCODE_GOOD) {
        UA_Variant args[2];
        args[0] = input[0];
        UA_Variant_init(&args[1]); /* never the RefreshToken */
        audit_issued(s, sessionContext, ID_REFRESHTOKEN, args, 2, &who, resource);
    }
    return r;
}

/* ---- the address space ---- */

static bool node_exists(gds_server *s, UA_NodeId id) {
    UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
    return UA_Server_readNodeClass(s->ua, id, &nc) == UA_STATUSCODE_GOOD;
}

static UA_StatusCode optional_rule(gds_server *s, UA_NodeId node) {
    UA_ExpandedNodeId optional = UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_MODELLINGRULE_OPTIONAL);
    UA_StatusCode r = UA_Server_addReference(s->ua, node, UA_NS0ID(HASMODELLINGRULE), optional,
                                             true);
    return r == UA_STATUSCODE_BADDUPLICATEREFERENCENOTALLOWED ? UA_STATUSCODE_GOOD : r;
}

/* The v1.05 members that the pinned NodeSet lacks. */
static UA_StatusCode add_type_members(gds_server *s) {
    UA_NodeId type = UA_NODEID_NUMERIC(s->ns, UA_GDSID_AUTHORIZATIONSERVICETYPE);
    static const gds_method_arg startIn[] = {{"ResourceId", UA_NS0ID_STRING, false},
                                             {"PolicyId", UA_NS0ID_STRING, false},
                                             {"RequestorData", UA_NS0ID_BYTESTRING, false}};
    static const gds_method_arg startOut[] = {{"ServiceData", UA_NS0ID_BYTESTRING, false},
                                              {"RequestId", UA_NS0ID_GUID, false}};
    static const gds_method_arg finishIn[] = {
        {"RequestId", UA_NS0ID_GUID, false},
        {"RequestedRoles", UA_NS0ID_STRING, true},
        {"UserIdentityToken", UA_NS0ID_USERIDENTITYTOKEN, false},
        {"UserTokenSignature", UA_NS0ID_SIGNATUREDATA, false}};
    static const gds_method_arg tokenOut[] = {{"AccessToken", UA_NS0ID_STRING, false},
                                              {"AccessTokenExpiryTime", UA_NS0ID_DATETIME, false},
                                              {"RefreshToken", UA_NS0ID_STRING, false},
                                              {"RefreshTokenExpiryTime", UA_NS0ID_DATETIME, false}};
    static const gds_method_arg refreshIn[] = {{"ResourceId", UA_NS0ID_STRING, false},
                                               {"CurrentRefreshToken", UA_NS0ID_STRING, false}};
    static const gds_method_arg refreshOut[] = {
        {"AccessToken", UA_NS0ID_STRING, false},
        {"AccessTokenExpiryTime", UA_NS0ID_DATETIME, false},
        {"NewRefreshToken", UA_NS0ID_STRING, false},
        {"NewRefreshTokenExpiryTime", UA_NS0ID_DATETIME, false}};
    struct {
        UA_UInt32 id, inId, outId;
        const char *name;
        const gds_method_arg *in, *out;
        size_t nIn, nOut;
    } m[] = {
        {ID_STARTREQUESTTOKEN, ID_STARTREQUEST_IN, ID_STARTREQUEST_OUT, "StartRequestToken",
         startIn, startOut, 3, 2},
        {ID_FINISHREQUESTTOKEN, ID_FINISHREQUEST_IN, ID_FINISHREQUEST_OUT, "FinishRequestToken",
         finishIn, tokenOut, 4, 4},
        {ID_REFRESHTOKEN, ID_REFRESHTOKEN_IN, ID_REFRESHTOKEN_OUT, "RefreshToken", refreshIn,
         refreshOut, 2, 4},
    };
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < GDS_ARRAY_SIZE(m) && r == UA_STATUSCODE_GOOD; i++) {
        UA_NodeId id = UA_NODEID_NUMERIC(s->ns, m[i].id);
        if(node_exists(s, id))
            continue;
        r = gds_add_method(s, id, type, m[i].name, m[i].in, m[i].nIn,
                           UA_NODEID_NUMERIC(s->ns, m[i].inId), m[i].out, m[i].nOut,
                           UA_NODEID_NUMERIC(s->ns, m[i].outId));
        if(r == UA_STATUSCODE_GOOD)
            r = optional_rule(s, id);
    }
    UA_NodeId roles = UA_NODEID_NUMERIC(s->ns, ID_SUPPORTEDROLES);
    if(r == UA_STATUSCODE_GOOD && !node_exists(s, roles)) {
        UA_VariableAttributes va = UA_VariableAttributes_default;
        va.displayName = UA_LOCALIZEDTEXT("", "SupportedRoles");
        va.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
        va.valueRank = UA_VALUERANK_ONE_DIMENSION;
        UA_UInt32 dims = 0;
        va.arrayDimensions = &dims;
        va.arrayDimensionsSize = 1;
        UA_Variant_setArray(&va.value, UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_STRING]);
        r = UA_Server_addVariableNode(s->ua, roles, type, UA_NS0ID(HASPROPERTY),
                                      UA_QUALIFIEDNAME(s->ns, "SupportedRoles"),
                                      UA_NS0ID(PROPERTYTYPE), va, NULL, NULL);
        if(r == UA_STATUSCODE_GOOD)
            r = optional_rule(s, roles);
    }
    UA_NodeId ev = UA_NODEID_NUMERIC(s->ns, ID_AT_REQUESTED_EVENT);
    if(r == UA_STATUSCODE_GOOD && !node_exists(s, ev)) {
        UA_ObjectTypeAttributes ta = UA_ObjectTypeAttributes_default;
        ta.displayName = UA_LOCALIZEDTEXT("", "AccessTokenRequestedAuditEventType");
        ta.isAbstract = true; /* as the v1.05.07 NodeSet */
        r = UA_Server_addObjectTypeNode(s->ua, ev,
                                        UA_NODEID_NUMERIC(0, UA_NS0ID_AUDITUPDATEMETHODEVENTTYPE),
                                        UA_NS0ID(HASSUBTYPE),
                                        UA_QUALIFIEDNAME(s->ns, "AccessTokenRequestedAuditEventType"),
                                        ta, NULL, NULL);
    }
    return r;
}

static UA_NodeId child_id(gds_server *s, const char *name) {
    char id[96];
    (void)snprintf(id, sizeof(id), NODE_PREFIX ".%s", name);
    return UA_NODEID_STRING_ALLOC(s->ns, id);
}

static UA_StatusCode add_property(gds_server *s, const char *name, const void *value, size_t n,
                                  const UA_DataType *t, bool array) {
    UA_VariableAttributes va = UA_VariableAttributes_default;
    va.displayName = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)name);
    va.dataType = t->typeId;
    va.valueRank = array ? UA_VALUERANK_ONE_DIMENSION : UA_VALUERANK_SCALAR;
    UA_UInt32 dims = 0;
    if(array) {
        va.arrayDimensions = &dims;
        va.arrayDimensionsSize = 1;
    }
    va.accessLevel = UA_ACCESSLEVELMASK_READ;
    if(array)
        UA_Variant_setArray(&va.value, (void *)(uintptr_t)value, n, t);
    else
        UA_Variant_setScalar(&va.value, (void *)(uintptr_t)value, t);
    UA_NodeId id = child_id(s, name);
    UA_StatusCode r = UA_Server_addVariableNode(s->ua, id, s->authz->object, UA_NS0ID(HASPROPERTY),
                                                UA_QUALIFIEDNAME(s->ns, (char *)(uintptr_t)name),
                                                UA_NS0ID(PROPERTYTYPE), va, NULL, NULL);
    UA_NodeId_clear(&id);
    return r;
}

/* Write a Mandatory Property the type instantiated. */
static UA_StatusCode set_property(gds_server *s, const char *name, const void *value,
                                  const UA_DataType *t) {
    UA_QualifiedName qn = UA_QUALIFIEDNAME(s->ns, (char *)(uintptr_t)name);
    UA_BrowsePathResult bp = UA_Server_browseSimplifiedBrowsePath(s->ua, s->authz->object, 1, &qn);
    UA_StatusCode r = bp.statusCode;
    if(r == UA_STATUSCODE_GOOD && bp.targetsSize < 1)
        r = UA_STATUSCODE_BADNOTFOUND;
    if(r == UA_STATUSCODE_GOOD) {
        UA_Variant v;
        UA_Variant_setScalar(&v, (void *)(uintptr_t)value, t);
        r = UA_Server_writeValue(s->ua, bp.targets[0].targetId.nodeId, v);
    }
    UA_BrowsePathResult_clear(&bp);
    return r;
}

static UA_StatusCode reference_method(gds_server *s, UA_UInt32 id) {
    UA_ExpandedNodeId m = UA_EXPANDEDNODEID_NUMERIC(s->ns, id);
    UA_StatusCode r = UA_Server_addReference(s->ua, s->authz->object, UA_NS0ID(HASCOMPONENT), m,
                                             true);
    if(r == UA_STATUSCODE_BADDUPLICATEREFERENCENOTALLOWED)
        r = UA_STATUSCODE_GOOD;
    return r;
}

static UA_StatusCode add_object(gds_server *s) {
    struct gds_authz *a = s->authz;
    UA_ObjectAttributes oa = UA_ObjectAttributes_default;
    oa.displayName = UA_LOCALIZEDTEXT("", SERVICE_NAME);
    a->object = UA_NODEID_STRING_ALLOC(s->ns, NODE_PREFIX);
    UA_StatusCode r =
        UA_Server_addObjectNode(s->ua, a->object, UA_NODEID_NUMERIC(s->ns, UA_GDSID_AUTHORIZATIONSERVICES),
                                UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(s->ns, SERVICE_NAME),
                                UA_NODEID_NUMERIC(s->ns, UA_GDSID_AUTHORIZATIONSERVICETYPE), oa,
                                NULL, NULL);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_String uri = UA_STRING(a->serviceUri);
    UA_ByteString cert = {a->serviceCert.len, a->serviceCert.data};
    r = set_property(s, "ServiceUri", &uri, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_property(s, "ServiceCertificate", &cert, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_UserTokenPolicy *p = NULL;
    size_t np = 0;
    if(r == UA_STATUSCODE_GOOD)
        r = policies(a, &p, &np);
    if(r == UA_STATUSCODE_GOOD)
        r = add_property(s, "UserTokenPolicies", p, np, &UA_TYPES[UA_TYPES_USERTOKENPOLICY], true);
    UA_Array_delete(p, np, &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
    /* SupportedRoles: every Role a users file can grant (OPC 10000-6
     * Table 56 roles are "unique names for roles known to the
     * Authorization Service") */
    const char *names[GDS_JWT_MAX_ROLES];
    size_t nn = role_names(s, ~0u, names, GDS_JWT_MAX_ROLES);
    UA_String rs[GDS_JWT_MAX_ROLES];
    for(size_t i = 0; i < nn; i++)
        rs[i] = UA_STRING((char *)(uintptr_t)names[i]);
    if(r == UA_STATUSCODE_GOOD)
        r = add_property(s, "SupportedRoles", rs, nn, &UA_TYPES[UA_TYPES_STRING], true);
    static const UA_UInt32 methods[] = {ID_STARTREQUESTTOKEN, ID_FINISHREQUESTTOKEN,
                                        ID_REFRESHTOKEN};
    for(size_t i = 0; i < GDS_ARRAY_SIZE(methods) && r == UA_STATUSCODE_GOOD; i++)
        r = reference_method(s, methods[i]);
    return r;
}

static UA_StatusCode bind(gds_server *s, UA_UInt32 id, UA_MethodCallback cb) {
    UA_NodeId n = UA_NODEID_NUMERIC(s->ns, id);
    UA_StatusCode r = UA_Server_setMethodNodeCallback(s->ua, n, cb);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setNodeContext(s->ua, n, s);
    return r;
}

/* The first certificate of a chain: its SHA-256 (x5t#S256) and notAfter. */
static gds_status first_cert(const gds_buf *chain, uint8_t out[32], int64_t *notAfter) {
    if(!chain->data || chain->len == 0 || chain->len > LONG_MAX)
        return GDS_EINVAL;
    const unsigned char *p = chain->data;
    X509 *x = d2i_X509(NULL, &p, (long)chain->len);
    if(!x)
        return GDS_EINVAL;
    size_t len = (size_t)(p - chain->data);
    int days = 0, secs = 0;
    gds_status r = ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(x)) == 1 ? GDS_OK
                                                                                   : GDS_EINVAL;
    *notAfter = unix_now() + (int64_t)days * 86400 + secs;
    X509_free(x);
    return r == GDS_OK ? sha256(chain->data, len, out) : r;
}

/* Take a chain (owned) as the ServiceCertificate. */
static gds_status set_chain(struct gds_authz *a, gds_buf *chain) {
    uint8_t x5t[GDS_JWT_THUMBPRINT];
    int64_t notAfter = 0;
    gds_status r = first_cert(chain, x5t, &notAfter);
    if(r != GDS_OK) {
        gds_buf_free(chain);
        return r;
    }
    pthread_mutex_lock(&a->lock);
    gds_buf old = a->serviceCert;
    a->serviceCert = *chain;
    memcpy(a->x5t, x5t, sizeof(x5t));
    a->certNotAfter = notAfter;
    pthread_mutex_unlock(&a->lock);
    gds_buf_free(&old);
    *chain = (gds_buf){0};
    return GDS_OK;
}

#define RENEW_BEFORE ((int64_t)30 * 86400)
#define RENEW_RETRY 3600

/* A certificate close to expiry is fetched again; the ServiceCertificate
 * node follows. A failure keeps the old one and tries again later. */
static void renew_chain(gds_server *s) {
    struct gds_authz *a = s->authz;
    int64_t now = unix_now();
    pthread_mutex_lock(&a->lock);
    bool due = a->chain && a->certNotAfter - now < RENEW_BEFORE && now - a->lastFetch >= RENEW_RETRY;
    if(due)
        a->lastFetch = now;
    pthread_mutex_unlock(&a->lock);
    if(!due)
        return;
    gds_buf chain = {0};
    if(a->chain(a->signCtx, a->serviceUri, &chain) != GDS_OK || set_chain(a, &chain) != GDS_OK) {
        gds_buf_free(&chain);
        fprintf(stderr, "opengds: AuthorizationService certificate renewal failed\n");
        return;
    }
    pthread_mutex_lock(&a->lock);
    UA_ByteString cert = {a->serviceCert.len, a->serviceCert.data};
    (void)set_property(s, "ServiceCertificate", &cert, &UA_TYPES[UA_TYPES_BYTESTRING]);
    pthread_mutex_unlock(&a->lock);
}

UA_StatusCode gds_authz_install(gds_server *s, const gds_authz_config *cfg,
                                const gds_buf *ownCert) {
    if(!cfg)
        return UA_STATUSCODE_GOOD;
    if(!cfg->sign || !cfg->alg || strlen(cfg->alg) >= sizeof(((struct gds_authz *)0)->alg) ||
       cfg->accessLifetime == 0 || !ownCert || !ownCert->len)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    struct gds_authz *a = calloc(1, sizeof(*a));
    if(!a)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    pthread_mutex_init(&a->lock, NULL);
    s->authz = a;
    a->sign = cfg->sign;
    a->signCtx = cfg->signCtx;
    a->chain = cfg->chain;
    memcpy(a->alg, cfg->alg, strlen(cfg->alg) + 1);
    a->accessLifetime = cfg->accessLifetime;
    a->refreshLifetime = cfg->refreshLifetime;
    a->x509 = gds_access_x509_users();
    const UA_String *appUri = &UA_Server_getConfig(s->ua)->applicationDescription.applicationUri;
    char def[GDS_MAX_APPLICATION_URI + 32];
    if(cfg->serviceUri && *cfg->serviceUri)
        (void)snprintf(def, sizeof(def), "%s", cfg->serviceUri);
    else
        (void)snprintf(def, sizeof(def), "%.*s/AuthorizationService", (int)appUri->length,
                       (const char *)appUri->data);
    a->serviceUri = strdup(def);
    if(!a->serviceUri || gds_buf_dup(ownCert->data, ownCert->len, &a->ownCert) != GDS_OK)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    gds_buf chain = {0};
    gds_status st = cfg->chain ? cfg->chain(cfg->signCtx, a->serviceUri, &chain)
                               : gds_buf_dup(cfg->serviceCertificate.data,
                                             cfg->serviceCertificate.len, &chain);
    a->lastFetch = unix_now();
    if(st == GDS_OK)
        st = set_chain(a, &chain);
    gds_buf_free(&chain);
    if(st != GDS_OK) {
        fprintf(stderr, "opengds: the AuthorizationService certificate: %s\n",
                gds_status_name(st));
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    }
    UA_StatusCode r = add_type_members(s);
    if(r == UA_STATUSCODE_GOOD)
        r = add_object(s);
    if(r == UA_STATUSCODE_GOOD)
        r = bind(s, UA_GDSID_AUTHORIZATIONSERVICETYPE_GETSERVICEDESCRIPTION,
                 get_service_description);
    if(r == UA_STATUSCODE_GOOD)
        r = bind(s, ID_STARTREQUESTTOKEN, start_request_token);
    if(r == UA_STATUSCODE_GOOD)
        r = bind(s, ID_FINISHREQUESTTOKEN, finish_request_token);
    if(r == UA_STATUSCODE_GOOD)
        r = bind(s, ID_REFRESHTOKEN, refresh_token);
    return r;
}

void gds_authz_free(gds_server *s) {
    struct gds_authz *a = s->authz;
    if(!a)
        return;
    for(size_t i = 0; i < MAX_REQUESTS; i++)
        UA_NodeId_clear(&a->req[i].session);
    UA_NodeId_clear(&a->object);
    free(a->serviceUri);
    gds_buf_free(&a->serviceCert);
    gds_buf_free(&a->ownCert);
    pthread_mutex_destroy(&a->lock);
    OPENSSL_cleanse(a, sizeof(*a));
    free(a);
    s->authz = NULL;
}
