/* OpenGDS - OPC 10000-18 §4 Role mapping rules.
 *
 * Every Role in ServerCapabilities/RoleSet that OpenGDS grants (the
 * well-known Roles of OPC 10000-3, the GDS Roles of OPC 10000-12 §6.2 /
 * §7.2, embedder Roles) gets its RoleType methods bound when its node has
 * them: AddIdentity, RemoveIdentity, AddApplication, RemoveApplication,
 * AddEndpoint, RemoveEndpoint (§4.4.5 - §4.4.10). The Identities,
 * Applications and Endpoints Properties read the rules live.
 *
 * Rules come from two places: the users file (each user's Roles read as a
 * UserName or Thumbprint rule, fixed: change the file to change them) and
 * the store (schema 6, changed with the methods). A session holds a Role
 * when an identity rule matches it and its client application and
 * Endpoint pass the Role's Applications and Endpoints lists (§4.4.1).
 * Those lists are include lists: OpenGDS has no exclude lists, so
 * ApplicationsExclude and EndpointsExclude read TRUE while a list is empty
 * (nothing excluded) and FALSE once it has entries (§4.4.1 defaults), and
 * they are not writable.
 *
 * Server-imposed restrictions (§4.4.5 Bad_RequestNotAllowed):
 *   - the Anonymous, AuthenticatedUser and TrustedApplication Roles never
 *     change (§4.3);
 *   - no Anonymous rule on any Role, and no AuthenticatedUser or
 *     TrustedApplication rule on an administrator Role (§4.4.1 "should
 *     refuse");
 *   - separation of duties (docs/architecture.md): one identity never
 *     holds SecurityAdmin, CertificateAuthorityAdmin and
 *     RegistrationAuthorityAdmin together unless `single_admin = true`;
 *   - users-file rules are not removed over OPC UA.
 * Role and GroupId rules need Access Tokens, which OpenGDS does not accept
 * yet: Bad_NotSupported.
 *
 * Every change is audited with RoleMappingRuleChangedAuditEventType (§4.5)
 * and re-evaluates the Roles of every open session (§4.4.1).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gds_internal.h"
#include "gds_roles.h"
#include "common/banned.h"

/* Copy a C string into a UA_String */
static UA_StatusCode cs_copy(const char *v, UA_String *out) {
    UA_String tmp = UA_STRING((char *)(uintptr_t)v);
    return UA_String_copy(&tmp, out);
}

#define SEVERITY_CHANGE 500
#define MAX_BOUND 256
#define MAX_PROPS 256

typedef struct {
    gds_role_rule r;
    unsigned bit;
    bool fixed; /* from the users file */
} rule_ent;

/* What a bound Property node reads */
typedef enum { P_IDENTITIES, P_APPLICATIONS, P_ENDPOINTS, P_APPS_EXCLUDE, P_EPS_EXCLUDE } prop_kind;
typedef struct {
    unsigned bit;
    prop_kind kind;
} prop_ctx;

static pthread_mutex_t rlock = PTHREAD_MUTEX_INITIALIZER;
static rule_ent *rules;
static size_t nRules, capRules;
/* bound method and secret Property nodes, fixed before the server runs */
static UA_NodeId bound[MAX_BOUND];
static size_t nBound;
static UA_NodeId secret[MAX_PROPS];
static size_t nSecret;
static prop_ctx props[MAX_PROPS];
static size_t nProps;

/* ---- the access control side ---- */

bool gds_roles_admin(const void *sessionContext) {
    const gds_session *s = sessionContext;
    return s && s->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT &&
           (gds_session_roles(s) & GDS_ROLE_SECURITY_ADMIN) != 0;
}

static bool in_list(const UA_NodeId *list, size_t n, const UA_NodeId *id) {
    for(size_t i = 0; i < n; i++)
        if(UA_NodeId_equal(&list[i], id))
            return true;
    return false;
}

bool gds_roles_is_method(const UA_NodeId *methodId) {
    return in_list(bound, nBound, methodId);
}

bool gds_roles_is_secret(const UA_NodeId *nodeId) {
    return in_list(secret, nSecret, nodeId);
}

void gds_roles_mark_method(const UA_NodeId *id) {
    if(nBound < MAX_BOUND && UA_NodeId_copy(id, &bound[nBound]) == UA_STATUSCODE_GOOD)
        nBound++;
}

void gds_roles_mark_secret(const UA_NodeId *id) {
    if(nSecret < MAX_PROPS && UA_NodeId_copy(id, &secret[nSecret]) == UA_STATUSCODE_GOOD)
        nSecret++;
}

void gds_roles_reset(void) {
    pthread_mutex_lock(&rlock);
    free(rules);
    rules = NULL;
    nRules = capRules = 0;
    pthread_mutex_unlock(&rlock);
    for(size_t i = 0; i < nBound; i++)
        UA_NodeId_clear(&bound[i]);
    for(size_t i = 0; i < nSecret; i++)
        UA_NodeId_clear(&secret[i]);
    nBound = nSecret = nProps = 0;
    gds_users_reset();
}

/* §4.4.3 Table 10: the X509Subject criteria of a name, "" if a value has
 * a '"' or the result does not fit. */
static void subject_criteria(const X509_NAME *name, char *out, size_t cap) {
    static const struct {
        int nid;
        const char *key;
    } order[] = {
        {NID_commonName, "CN"},          {NID_organizationName, "O"},
        {NID_organizationalUnitName, "OU"}, {NID_domainComponent, "DC"},
        {NID_localityName, "L"},         {NID_stateOrProvinceName, "S"},
        {NID_countryName, "C"},          {NID_dnQualifier, "dnQualifier"},
        {NID_serialNumber, "serialNumber"},
    };
    size_t len = 0;
    out[0] = '\0';
    for(size_t k = 0; k < GDS_ARRAY_SIZE(order); k++) {
        for(int i = 0; i < X509_NAME_entry_count(name); i++) {
            const X509_NAME_ENTRY *e = X509_NAME_get_entry(name, i);
            if(OBJ_obj2nid(X509_NAME_ENTRY_get_object(e)) != order[k].nid)
                continue;
            unsigned char *v = NULL;
            int vn = ASN1_STRING_to_UTF8(&v, X509_NAME_ENTRY_get_data(e));
            bool ok = vn >= 0 && memchr(v, '"', (size_t)vn) == NULL && memchr(v, 0, (size_t)vn) == NULL;
            int w = ok ? snprintf(out + len, cap - len, "%s%s=\"%.*s\"", len ? "/" : "",
                                  order[k].key, vn, (const char *)v)
                       : -1;
            OPENSSL_free(v);
            if(w < 0 || (size_t)w >= cap - len) {
                out[0] = '\0';
                return;
            }
            len += (size_t)w;
        }
    }
}

void gds_roles_cert_facts(const UA_ByteString *der, gds_session *s) {
    unsigned n = 0;
    if(!der || der->length == 0 || der->length > GDS_MAX_CERT_SIZE)
        return;
    (void)EVP_Digest(der->data, der->length, s->certSha1, &n, EVP_sha1(), NULL);
    (void)EVP_Digest(der->data, der->length, s->certSha256, &n, EVP_sha256(), NULL);
    const unsigned char *p = der->data;
    X509 *x = d2i_X509(NULL, &p, (long)der->length);
    if(!x)
        return;
    subject_criteria(X509_get_subject_name(x), s->subjectCriteria, sizeof(s->subjectCriteria));
    subject_criteria(X509_get_issuer_name(x), s->issuerCriteria, sizeof(s->issuerCriteria));
    X509_free(x);
}

static bool hex_eq(const uint8_t *b, size_t n, const char *crit) {
    static const char digits[] = "0123456789ABCDEF";
    if(strlen(crit) != 2 * n)
        return false;
    unsigned diff = 0;
    for(size_t i = 0; i < n; i++)
        diff |= (unsigned)(digits[b[i] >> 4] ^ crit[2 * i]) | (unsigned)(digits[b[i] & 15] ^ crit[2 * i + 1]);
    return diff == 0;
}

static bool cstr_eq(const char *a, const UA_String *b) {
    return strlen(a) == b->length && (b->length == 0 || memcmp(a, b->data, b->length) == 0);
}

/* §4.4.3, Table 12 */
static bool identity_matches(const gds_role_rule *r, const gds_session *s) {
    bool anon = s->anonymous || s->token == GDS_TOKEN_ANONYMOUS;
    bool x509 = s->token == GDS_TOKEN_X509;
    switch(r->criteriaType) {
    case UA_IDENTITYCRITERIATYPE_USERNAME:
        return s->token == GDS_TOKEN_USERNAME && strcmp(s->user, r->criteria) == 0;
    case UA_IDENTITYCRITERIATYPE_THUMBPRINT:
        return x509 && (hex_eq(s->certSha1, sizeof(s->certSha1), r->criteria) ||
                        hex_eq(s->certSha256, sizeof(s->certSha256), r->criteria));
    case UA_IDENTITYCRITERIATYPE_X509SUBJECT:
        return x509 && r->criteria[0] &&
               (strcmp(s->subjectCriteria, r->criteria) == 0 ||
                strcmp(s->issuerCriteria, r->criteria) == 0);
    case UA_IDENTITYCRITERIATYPE_ANONYMOUS:
        return anon;
    case UA_IDENTITYCRITERIATYPE_AUTHENTICATEDUSER:
        return !anon;
    case UA_IDENTITYCRITERIATYPE_APPLICATION:
        /* the channel's certificate, issued by the GDS CA, is trusted */
        return s->clientAppUri.length > 0 && cstr_eq(r->criteria, &s->clientAppUri);
    case UA_IDENTITYCRITERIATYPE_TRUSTEDAPPLICATION:
        return s->clientAppUri.length > 0;
    default:
        return false; /* Role and GroupId need an Access Token */
    }
}

static bool endpoint_matches(const gds_role_rule *r, const gds_session *s) {
    /* §4.4.2: fields with their default value are not compared */
    return strcmp(r->criteria, s->endpointUrl) == 0 &&
           (r->securityMode == 0 || r->securityMode == (int32_t)s->securityMode) &&
           (!r->securityPolicyUri[0] || cstr_eq(r->securityPolicyUri, &s->securityPolicyUri)) &&
           (!r->transportProfileUri[0] ||
            strcmp(r->transportProfileUri, s->transportProfileUri) == 0);
}

unsigned gds_roles_evaluate(const gds_session *s, unsigned fileRoles) {
    if(!s)
        return 0;
    unsigned granted = fileRoles, hasApps = 0, appOk = 0, hasEps = 0, epOk = 0;
    pthread_mutex_lock(&rlock);
    for(size_t i = 0; i < nRules; i++) {
        const rule_ent *e = &rules[i];
        switch(e->r.kind) {
        case GDS_RULE_IDENTITY:
            /* users-file rules are in fileRoles already */
            if(!e->fixed && identity_matches(&e->r, s))
                granted |= e->bit;
            break;
        case GDS_RULE_APPLICATION:
            hasApps |= e->bit;
            if(s->clientAppUri.length > 0 && cstr_eq(e->r.criteria, &s->clientAppUri))
                appOk |= e->bit;
            break;
        case GDS_RULE_ENDPOINT:
            hasEps |= e->bit;
            if(endpoint_matches(&e->r, s))
                epOk |= e->bit;
            break;
        default:
            break;
        }
    }
    pthread_mutex_unlock(&rlock);
    /* §4.4.1: a configured Applications / Endpoints list must admit the
     * session; Applications also needs a signed channel */
    bool signedChannel = s->securityMode == UA_MESSAGESECURITYMODE_SIGN ||
                         s->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    granted &= ~(hasApps & ~(signedChannel ? appOk : 0u));
    granted &= ~(hasEps & ~epOk);
    return granted;
}

/* ---- the rule cache ---- */

static bool rule_eq(const gds_role_rule *a, const gds_role_rule *b) {
    return strcmp(a->role, b->role) == 0 && a->kind == b->kind &&
           a->criteriaType == b->criteriaType && strcmp(a->criteria, b->criteria) == 0 &&
           a->securityMode == b->securityMode &&
           strcmp(a->securityPolicyUri, b->securityPolicyUri) == 0 &&
           strcmp(a->transportProfileUri, b->transportProfileUri) == 0;
}

/* rlock held */
static gds_status cache_add(const gds_role_rule *r, bool fixed) {
    unsigned bit = gds_role_bit_by_name(r->role);
    if(!bit)
        return GDS_ENOTFOUND; /* a Role that is gone (an embedder Role) */
    if(nRules == capRules) {
        size_t cap = capRules ? 2 * capRules : 32;
        rule_ent *n = realloc(rules, cap * sizeof(*n));
        if(!n)
            return GDS_ENOMEM;
        rules = n;
        capRules = cap;
    }
    rules[nRules].r = *r;
    rules[nRules].bit = bit;
    rules[nRules].fixed = fixed;
    nRules++;
    return GDS_OK;
}

static bool load_cb(void *ctx, const gds_role_rule *r) {
    gds_status *st = ctx;
    gds_status a = cache_add(r, false);
    if(a == GDS_ENOMEM) {
        *st = a;
        return false;
    }
    /* other errors: a rule for an embedder Role not added yet (it is
     * loaded again when gds_server_add_role adds it) */
    return true;
}

/* The users file's grants as fixed rules: UserName for password users,
 * Thumbprint (SHA-256, upper-case hex) for certificate users. */
static gds_status add_file_rules(const gds_users *users) {
    for(size_t i = 0; users && i < users->n; i++) {
        const gds_user *u = &users->users[i];
        for(size_t k = 0; k < gds_role_count(); k++) {
            UA_NodeId id;
            unsigned bit = 0;
            const char *name = NULL;
            gds_role_at(k, 0, &id, &bit, &name);
            bool has = (u->roles & bit) != 0;
            for(size_t j = 0; j < u->nEmbedRoles && !has; j++)
                has = strcmp(u->embedRoles[j], name) == 0;
            if(!has)
                continue;
            gds_role_rule r;
            memset(&r, 0, sizeof(r));
            (void)snprintf(r.role, sizeof(r.role), "%s", name);
            r.kind = GDS_RULE_IDENTITY;
            if(u->x509) {
                r.criteriaType = UA_IDENTITYCRITERIATYPE_THUMBPRINT;
                static const char digits[] = "0123456789ABCDEF";
                for(size_t b = 0; b < GDS_X509_THUMBPRINT; b++) {
                    r.criteria[2 * b] = digits[u->thumbprint[b] >> 4];
                    r.criteria[2 * b + 1] = digits[u->thumbprint[b] & 15];
                }
            } else {
                r.criteriaType = UA_IDENTITYCRITERIATYPE_USERNAME;
                (void)snprintf(r.criteria, sizeof(r.criteria), "%s", u->name);
            }
            gds_status st = cache_add(&r, true);
            if(st == GDS_ENOMEM)
                return st;
        }
    }
    return GDS_OK;
}

static const gds_users *fileUsers;

void gds_roles_reload(gds_server *s) {
    pthread_mutex_lock(&rlock);
    nRules = 0;
    gds_status st = add_file_rules(fileUsers);
    if(st == GDS_OK) {
        gds_lock(s);
        gds_status sc = gds_store_rule_scan(s->store, load_cb, &st);
        gds_unlock(s);
        if(sc != GDS_OK && sc != GDS_EUNSUPPORTED)
            fprintf(stderr, "opengds: reading the role rules failed: %s\n", gds_status_name(sc));
    }
    pthread_mutex_unlock(&rlock);
    if(st != GDS_OK)
        fprintf(stderr, "opengds: role rules: %s\n", gds_status_name(st));
    gds_users_reload(s);
}

/* ---- shared method helpers (also gds_users.c) ---- */

UA_StatusCode gds_roles_store_status(gds_status st) {
    switch(st) {
    case GDS_OK:
        return UA_STATUSCODE_GOOD;
    case GDS_ENOTLEADER:
        return UA_STATUSCODE_BADINVALIDSTATE;
    case GDS_EUNSUPPORTED:
        return UA_STATUSCODE_BADNOTSUPPORTED;
    case GDS_EEXISTS:
        return UA_STATUSCODE_BADALREADYEXISTS;
    case GDS_ENOTFOUND:
        return UA_STATUSCODE_BADNOTFOUND;
    case GDS_ENOMEM:
    case GDS_ETOOBIG:
        return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
    case GDS_EOVERFLOW:
    case GDS_EINVAL:
    case GDS_EIO:
    case GDS_EDENIED:
    case GDS_ECRYPTO:
    case GDS_ESTATE:
    case GDS_EREMOTE:
    default:
        return UA_STATUSCODE_BADINTERNALERROR;
    }
}

UA_StatusCode gds_roles_check_admin(gds_server *s, const void *sessionContext) {
    const gds_session *ss = sessionContext;
    if(!ss || ss->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;
    if(!gds_roles_admin(ss))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    return gds_refuse_on_standby(s);
}

void gds_roles_audit(gds_server *s, const void *sessionContext, UA_UInt32 type,
                     const UA_NodeId *source, const UA_NodeId *method, const UA_Variant *args,
                     size_t nArgs, UA_StatusCode result) {
    const gds_session *ss = sessionContext;
    gds_event_field f[2];
    f[0].nsIndex = 0;
    f[0].name = "MethodId";
    UA_Variant_setScalar(&f[0].value, (void *)(uintptr_t)method, &UA_TYPES[UA_TYPES_NODEID]);
    f[1].nsIndex = 0;
    f[1].name = "InputArguments";
    UA_Variant_setArray(&f[1].value, (void *)(uintptr_t)args, nArgs, &UA_TYPES[UA_TYPES_VARIANT]);
    UA_NodeId visible = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN);
    gds_audit_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.abi_major = GDS_PLUGIN_ABI_MAJOR;
    ev.abi_minor = GDS_PLUGIN_ABI_MINOR;
    ev.struct_size = sizeof(ev);
    ev.eventType = UA_NODEID_NUMERIC(0, type);
    ev.sourceNode = *source;
    ev.severity = SEVERITY_CHANGE;
    ev.message = result == UA_STATUSCODE_GOOD ? NULL : UA_StatusCode_name(result);
    ev.status = result == UA_STATUSCODE_GOOD;
    ev.fields = f;
    ev.fieldsSize = 2;
    ev.visibleTo = &visible;
    ev.visibleToSize = 1;
    const char *user = ss && !gds_session_anonymous(ss) ? ss->user : NULL;
    gds_status st = gds_audit_raise(s, user, &ev, NULL);
    if(st != GDS_OK)
        fprintf(stderr, "opengds: audit of %s: %s\n",
                type == UA_NS0ID_ROLEMAPPINGRULECHANGEDAUDITEVENTTYPE ? "a role rule change"
                                                                      : "a user change",
                gds_status_name(st));
}

/* ---- the RoleType methods ---- */

static bool admin_role(unsigned bit) {
    return (bit & (GDS_ROLE_SECURITY_ADMIN | GDS_ROLE_CONFIGURE_ADMIN | GDS_ROLE_DISCOVERY_ADMIN |
                   GDS_ROLE_CERTIFICATE_AUTHORITY_ADMIN | GDS_ROLE_REGISTRATION_AUTHORITY_ADMIN |
                   GDS_ROLE_KEY_CREDENTIAL_ADMIN | GDS_ROLE_AUTHORIZATION_SERVICE_ADMIN |
                   GDS_ROLE_SKS_ADMIN)) != 0;
}

static bool user_name_ok(const char *n) {
    size_t len = strlen(n);
    if(len == 0 || len > GDS_MAX_USER_NAME)
        return false;
    for(size_t i = 0; i < len; i++) {
        char c = n[i];
        if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
             c == '.' || c == '_' || c == '-' || c == '@'))
            return false;
    }
    return true;
}

static bool upper_hex(const char *v, size_t n) {
    if(strlen(v) != n)
        return false;
    for(size_t i = 0; i < n; i++)
        if(!((v[i] >= '0' && v[i] <= '9') || (v[i] >= 'A' && v[i] <= 'F')))
            return false;
    return true;
}

/* Copy a String into a fixed buffer: false if it holds a NUL or is too long. */
static bool to_cstr(const UA_String *v, char *out, size_t max) {
    if(v->length > max || (v->length && memchr(v->data, 0, v->length)))
        return false;
    if(v->length)
        memcpy(out, v->data, v->length);
    out[v->length] = '\0';
    return true;
}

/* §4.4.3, §4.4.4: the criteria fit the type */
static UA_StatusCode identity_ok(const gds_role_rule *r) {
    switch(r->criteriaType) {
    case UA_IDENTITYCRITERIATYPE_USERNAME:
        return user_name_ok(r->criteria) ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINVALIDARGUMENT;
    case UA_IDENTITYCRITERIATYPE_THUMBPRINT:
        /* upper case hex: the SHA-1 thumbprint, or the users file's SHA-256 */
        return upper_hex(r->criteria, 40) || upper_hex(r->criteria, 64)
                   ? UA_STATUSCODE_GOOD
                   : UA_STATUSCODE_BADINVALIDARGUMENT;
    case UA_IDENTITYCRITERIATYPE_X509SUBJECT:
        return strchr(r->criteria, '=') ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINVALIDARGUMENT;
    case UA_IDENTITYCRITERIATYPE_APPLICATION:
        return r->criteria[0] ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINVALIDARGUMENT;
    case UA_IDENTITYCRITERIATYPE_ANONYMOUS:
    case UA_IDENTITYCRITERIATYPE_AUTHENTICATEDUSER:
    case UA_IDENTITYCRITERIATYPE_TRUSTEDAPPLICATION:
        return r->criteria[0] ? UA_STATUSCODE_BADINVALIDARGUMENT : UA_STATUSCODE_GOOD;
    case UA_IDENTITYCRITERIATYPE_ROLE:
    case UA_IDENTITYCRITERIATYPE_GROUPID:
        return UA_STATUSCODE_BADNOTSUPPORTED;
    default:
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
}

#define SOD_ROLES                                                                          \
    (GDS_ROLE_SECURITY_ADMIN | GDS_ROLE_CERTIFICATE_AUTHORITY_ADMIN |                      \
     GDS_ROLE_REGISTRATION_AUTHORITY_ADMIN)

/* rlock held: the Roles this identity holds through equal identity rules */
static unsigned identity_roles(const gds_role_rule *r) {
    unsigned bits = 0;
    for(size_t i = 0; i < nRules; i++)
        if(rules[i].r.kind == GDS_RULE_IDENTITY && rules[i].r.criteriaType == r->criteriaType &&
           strcmp(rules[i].r.criteria, r->criteria) == 0)
            bits |= rules[i].bit;
    return bits;
}

typedef struct {
    gds_server *s;
    unsigned bit;
    const char *name;
    bool locked; /* Anonymous, AuthenticatedUser, TrustedApplication */
} role_ref;

/* The Role an object is: a grantable one, or one of the fixed §4.3 Roles */
static bool role_of(gds_server *s, const UA_NodeId *objectId, role_ref *out) {
    memset(out, 0, sizeof(*out));
    out->s = s;
    for(size_t i = 0; i < gds_role_count(); i++) {
        UA_NodeId id;
        gds_role_at(i, s->ns, &id, &out->bit, &out->name);
        if(UA_NodeId_equal(&id, objectId))
            return true;
    }
    static const UA_UInt32 fixedRoles[] = {UA_NS0ID_WELLKNOWNROLE_ANONYMOUS,
                                           UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER,
                                           UA_NS0ID_WELLKNOWNROLE_TRUSTEDAPPLICATION};
    for(size_t i = 0; i < GDS_ARRAY_SIZE(fixedRoles); i++) {
        UA_NodeId id = UA_NODEID_NUMERIC(0, fixedRoles[i]);
        if(UA_NodeId_equal(&id, objectId)) {
            out->locked = true;
            out->bit = 0;
            return true;
        }
    }
    return false;
}

/* Decode the method's argument into a rule for role; Good or the
 * method's result code. */
static UA_StatusCode decode_rule(gds_rule_kind kind, size_t n, const UA_Variant *in,
                                 const role_ref *role, gds_role_rule *r) {
    memset(r, 0, sizeof(*r));
    r->kind = (uint8_t)kind;
    if(n != 1)
        return n < 1 ? UA_STATUSCODE_BADARGUMENTSMISSING : UA_STATUSCODE_BADTOOMANYARGUMENTS;
    if(role->name)
        (void)snprintf(r->role, sizeof(r->role), "%s", role->name);
    switch(kind) {
    case GDS_RULE_IDENTITY: {
        if(!UA_Variant_hasScalarType(&in[0], &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]))
            return UA_STATUSCODE_BADTYPEMISMATCH;
        const UA_IdentityMappingRuleType *v = in[0].data;
        r->criteriaType = (int32_t)v->criteriaType;
        return to_cstr(&v->criteria, r->criteria, GDS_MAX_RULE_TEXT)
                   ? UA_STATUSCODE_GOOD
                   : UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    case GDS_RULE_APPLICATION:
        if(!UA_Variant_hasScalarType(&in[0], &UA_TYPES[UA_TYPES_STRING]))
            return UA_STATUSCODE_BADTYPEMISMATCH;
        return to_cstr(in[0].data, r->criteria, GDS_MAX_APPLICATION_URI)
                   ? UA_STATUSCODE_GOOD
                   : UA_STATUSCODE_BADINVALIDARGUMENT;
    case GDS_RULE_ENDPOINT: {
        if(!UA_Variant_hasScalarType(&in[0], &UA_TYPES[UA_TYPES_ENDPOINTTYPE]))
            return UA_STATUSCODE_BADTYPEMISMATCH;
        const UA_EndpointType *e = in[0].data;
        if(e->securityMode < UA_MESSAGESECURITYMODE_INVALID ||
           e->securityMode > UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        r->securityMode = (int32_t)e->securityMode;
        return to_cstr(&e->endpointUrl, r->criteria, GDS_MAX_ENDPOINT_URL) &&
                       to_cstr(&e->securityPolicyUri, r->securityPolicyUri, GDS_MAX_RULE_URI) &&
                       to_cstr(&e->transportProfileUri, r->transportProfileUri, GDS_MAX_RULE_URI)
                   ? UA_STATUSCODE_GOOD
                   : UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    default:
        return UA_STATUSCODE_BADINTERNALERROR;
    }
}

static UA_StatusCode add_rule(const role_ref *role, gds_role_rule *r) {
    gds_server *s = role->s;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(r->kind == GDS_RULE_IDENTITY) {
        res = identity_ok(r);
        if(res != UA_STATUSCODE_GOOD)
            return res;
        if(r->criteriaType == UA_IDENTITYCRITERIATYPE_ANONYMOUS ||
           (admin_role(role->bit) &&
            (r->criteriaType == UA_IDENTITYCRITERIATYPE_AUTHENTICATEDUSER ||
             r->criteriaType == UA_IDENTITYCRITERIATYPE_TRUSTEDAPPLICATION)))
            return UA_STATUSCODE_BADREQUESTNOTALLOWED;
    } else if(!r->criteria[0]) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    pthread_mutex_lock(&rlock);
    bool dup = false;
    for(size_t i = 0; i < nRules && !dup; i++)
        dup = rule_eq(&rules[i].r, r);
    if(dup)
        res = UA_STATUSCODE_BADALREADYEXISTS;
    else if(nRules >= GDS_MAX_ROLE_RULES)
        res = UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
    else if(r->kind == GDS_RULE_IDENTITY && !s->singleAdmin &&
            ((identity_roles(r) | role->bit) & SOD_ROLES) == SOD_ROLES)
        res = UA_STATUSCODE_BADREQUESTNOTALLOWED; /* separation of duties */
    pthread_mutex_unlock(&rlock);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    gds_lock(s);
    gds_status st = gds_store_rule_add(s->store, r);
    gds_unlock(s);
    if(st != GDS_OK)
        return gds_roles_store_status(st);
    pthread_mutex_lock(&rlock);
    st = cache_add(r, false);
    pthread_mutex_unlock(&rlock);
    if(st != GDS_OK) /* stored; the cache catches up at the next reload */
        fprintf(stderr, "opengds: role rule cache: %s\n", gds_status_name(st));
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode remove_rule(const role_ref *role, const gds_role_rule *r) {
    gds_server *s = role->s;
    pthread_mutex_lock(&rlock);
    size_t at = nRules;
    for(size_t i = 0; i < nRules && at == nRules; i++)
        if(rule_eq(&rules[i].r, r))
            at = i;
    bool fixed = at < nRules && rules[at].fixed;
    pthread_mutex_unlock(&rlock);
    if(at == nRules)
        return UA_STATUSCODE_BADNOTFOUND;
    if(fixed)
        return UA_STATUSCODE_BADREQUESTNOTALLOWED; /* change the users file */
    gds_lock(s);
    gds_status st = gds_store_rule_remove(s->store, r);
    gds_unlock(s);
    if(st != GDS_OK)
        return gds_roles_store_status(st);
    pthread_mutex_lock(&rlock);
    for(size_t i = 0; i < nRules; i++) {
        if(!rules[i].fixed && rule_eq(&rules[i].r, r)) {
            memmove(&rules[i], &rules[i + 1], (nRules - i - 1) * sizeof(rules[0]));
            nRules--;
            break;
        }
    }
    pthread_mutex_unlock(&rlock);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode rule_method(UA_Server *server, const UA_NodeId *sessionId,
                                 void *sessionContext, const UA_NodeId *methodId,
                                 void *methodContext, const UA_NodeId *objectId,
                                 size_t inputSize, const UA_Variant *input, gds_rule_kind kind,
                                 bool add) {
    (void)server, (void)sessionId;
    gds_server *s = gds_ctx(methodContext);
    role_ref role;
    UA_StatusCode res = gds_roles_check_admin(s, sessionContext);
    if(res == UA_STATUSCODE_GOOD && !role_of(s, objectId, &role))
        res = UA_STATUSCODE_BADMETHODINVALID;
    gds_role_rule r;
    if(res == UA_STATUSCODE_GOOD)
        res = decode_rule(kind, inputSize, input, &role, &r);
    if(res == UA_STATUSCODE_GOOD && role.locked)
        res = UA_STATUSCODE_BADREQUESTNOTALLOWED; /* §4.3 */
    if(res == UA_STATUSCODE_GOOD)
        res = add ? add_rule(&role, &r) : remove_rule(&role, &r);
    if(res == UA_STATUSCODE_GOOD)
        gds_access_reevaluate();
    /* every call that reached a Role, refused or not, is in the log */
    if(gds_server_role(s) != GDS_NODE_STANDBY)
        gds_roles_audit(s, sessionContext, UA_NS0ID_ROLEMAPPINGRULECHANGEDAUDITEVENTTYPE, objectId,
                        methodId, input, inputSize, res);
    return res;
}

#define RULE_METHOD(fn, kind, add)                                                          \
    static GDS_METHOD(fn) {                                                                \
        (void)objectContext, (void)outputSize, (void)output;                               \
        return rule_method(server, sessionId, sessionContext, methodId, methodContext,     \
                           objectId, inputSize, input, kind, add);                         \
    }
RULE_METHOD(m_add_identity, GDS_RULE_IDENTITY, true)
RULE_METHOD(m_remove_identity, GDS_RULE_IDENTITY, false)
RULE_METHOD(m_add_application, GDS_RULE_APPLICATION, true)
RULE_METHOD(m_remove_application, GDS_RULE_APPLICATION, false)
RULE_METHOD(m_add_endpoint, GDS_RULE_ENDPOINT, true)
RULE_METHOD(m_remove_endpoint, GDS_RULE_ENDPOINT, false)

/* ---- the Properties ---- */

static UA_StatusCode read_prop(UA_Server *server, const UA_NodeId *sessionId,
                               void *sessionContext, const UA_NodeId *nodeId, void *nodeContext,
                               UA_Boolean includeSourceTimeStamp, const UA_NumericRange *range,
                               UA_DataValue *value) {
    (void)server, (void)sessionId, (void)nodeId, (void)includeSourceTimeStamp;
    const prop_ctx *p = nodeContext;
    if(range) {
        value->hasStatus = true;
        value->status = UA_STATUSCODE_BADINDEXRANGEINVALID;
        return UA_STATUSCODE_GOOD;
    }
    if(!gds_roles_admin(sessionContext)) {
        value->hasStatus = true;
        value->status = UA_STATUSCODE_BADUSERACCESSDENIED;
        return UA_STATUSCODE_GOOD;
    }
    gds_rule_kind kind = p->kind == P_IDENTITIES ? GDS_RULE_IDENTITY
                         : p->kind == P_ENDPOINTS || p->kind == P_EPS_EXCLUDE
                             ? GDS_RULE_ENDPOINT
                             : GDS_RULE_APPLICATION;
    pthread_mutex_lock(&rlock);
    size_t n = 0;
    for(size_t i = 0; i < nRules; i++)
        if(rules[i].bit == p->bit && rules[i].r.kind == kind)
            n++;
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(p->kind == P_APPS_EXCLUDE || p->kind == P_EPS_EXCLUDE) {
        UA_Boolean exclude = n == 0;
        r = UA_Variant_setScalarCopy(&value->value, &exclude, &UA_TYPES[UA_TYPES_BOOLEAN]);
        pthread_mutex_unlock(&rlock);
        value->hasValue = r == UA_STATUSCODE_GOOD;
        return r;
    }
    const UA_DataType *t = kind == GDS_RULE_IDENTITY ? &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]
                           : kind == GDS_RULE_ENDPOINT ? &UA_TYPES[UA_TYPES_ENDPOINTTYPE]
                                                       : &UA_TYPES[UA_TYPES_STRING];
    void *arr = n ? UA_Array_new(n, t) : UA_EMPTY_ARRAY_SENTINEL;
    if(!arr)
        r = UA_STATUSCODE_BADOUTOFMEMORY;
    size_t k = 0;
    for(size_t i = 0; i < nRules && r == UA_STATUSCODE_GOOD; i++) {
        const gds_role_rule *e = &rules[i].r;
        if(rules[i].bit != p->bit || e->kind != kind)
            continue;
        if(kind == GDS_RULE_IDENTITY) {
            UA_IdentityMappingRuleType *v = &((UA_IdentityMappingRuleType *)arr)[k];
            v->criteriaType = (UA_IdentityCriteriaType)e->criteriaType;
            r = cs_copy(e->criteria, &v->criteria);
        } else if(kind == GDS_RULE_ENDPOINT) {
            UA_EndpointType *v = &((UA_EndpointType *)arr)[k];
            v->securityMode = (UA_MessageSecurityMode)e->securityMode;
            r = cs_copy(e->criteria, &v->endpointUrl);
            if(r == UA_STATUSCODE_GOOD)
                r = cs_copy(e->securityPolicyUri,
                                   &v->securityPolicyUri);
            if(r == UA_STATUSCODE_GOOD)
                r = cs_copy(e->transportProfileUri,
                                   &v->transportProfileUri);
        } else {
            r = cs_copy(e->criteria,
                               &((UA_String *)arr)[k]);
        }
        k++;
    }
    pthread_mutex_unlock(&rlock);
    if(r != UA_STATUSCODE_GOOD) {
        if(arr && n)
            UA_Array_delete(arr, n, t);
        return r;
    }
    UA_Variant_setArray(&value->value, arr, n, t);
    value->hasValue = true;
    return UA_STATUSCODE_GOOD;
}

/* The child of parent with this BrowseName (namespace 0); null if none. */
static UA_NodeId child(UA_Server *ua, const UA_NodeId *parent, const char *name) {
    UA_RelativePathElement el;
    UA_RelativePathElement_init(&el);
    el.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
    el.includeSubtypes = true;
    el.targetName = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)name);
    UA_BrowsePath bp;
    UA_BrowsePath_init(&bp);
    bp.startingNode = *parent;
    bp.relativePath.elements = &el;
    bp.relativePath.elementsSize = 1;
    UA_BrowsePathResult res = UA_Server_translateBrowsePathToNodeIds(ua, &bp);
    UA_NodeId out = UA_NODEID_NULL;
    if(res.statusCode == UA_STATUSCODE_GOOD && res.targetsSize >= 1 &&
       UA_ExpandedNodeId_isLocal(&res.targets[0].targetId))
        (void)UA_NodeId_copy(&res.targets[0].targetId.nodeId, &out);
    UA_BrowsePathResult_clear(&res);
    return out;
}

static UA_StatusCode gds_roles_bind_method(gds_server *s, const UA_NodeId *parent, const char *name,
                                    UA_MethodCallback cb) {
    UA_NodeId m = child(s->ua, parent, name);
    if(UA_NodeId_isNull(&m))
        return UA_STATUSCODE_GOOD; /* the Role does not offer it */
    UA_StatusCode r = UA_Server_setMethodNodeCallback(s->ua, m, cb);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setNodeContext(s->ua, m, s);
    if(r == UA_STATUSCODE_GOOD)
        gds_roles_mark_method(&m);
    UA_NodeId_clear(&m);
    return r;
}

static UA_StatusCode bind_prop(gds_server *s, const UA_NodeId *parent, const char *name,
                               unsigned bit, prop_kind kind) {
    UA_NodeId v = child(s->ua, parent, name);
    if(UA_NodeId_isNull(&v))
        return UA_STATUSCODE_GOOD;
    if(nProps == MAX_PROPS) {
        UA_NodeId_clear(&v);
        return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
    }
    prop_ctx *p = &props[nProps++];
    p->bit = bit;
    p->kind = kind;
    UA_CallbackValueSource src = {read_prop, NULL};
    UA_StatusCode r = UA_Server_setNodeContext(s->ua, v, p);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setVariableNode_callbackValueSource(s->ua, v, src);
    if(r == UA_STATUSCODE_GOOD)
        gds_roles_mark_secret(&v);
    UA_NodeId_clear(&v);
    return r;
}

static UA_StatusCode bind_role(gds_server *s, const UA_NodeId *role, unsigned bit, bool locked) {
    static const struct {
        const char *name;
        UA_MethodCallback cb;
    } methods[] = {
        {"AddIdentity", m_add_identity},       {"RemoveIdentity", m_remove_identity},
        {"AddApplication", m_add_application}, {"RemoveApplication", m_remove_application},
        {"AddEndpoint", m_add_endpoint},       {"RemoveEndpoint", m_remove_endpoint},
    };
    UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
    if(UA_Server_readNodeClass(s->ua, *role, &nc) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_GOOD; /* the Role has no node */
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < GDS_ARRAY_SIZE(methods) && r == UA_STATUSCODE_GOOD; i++)
        r = gds_roles_bind_method(s, role, methods[i].name, methods[i].cb);
    if(locked) /* §4.3: fixed Roles keep the NodeSet's Identities */
        return r;
    if(r == UA_STATUSCODE_GOOD)
        r = bind_prop(s, role, "Identities", bit, P_IDENTITIES);
    if(r == UA_STATUSCODE_GOOD)
        r = bind_prop(s, role, "Applications", bit, P_APPLICATIONS);
    if(r == UA_STATUSCODE_GOOD)
        r = bind_prop(s, role, "Endpoints", bit, P_ENDPOINTS);
    if(r == UA_STATUSCODE_GOOD)
        r = bind_prop(s, role, "ApplicationsExclude", bit, P_APPS_EXCLUDE);
    if(r == UA_STATUSCODE_GOOD)
        r = bind_prop(s, role, "EndpointsExclude", bit, P_EPS_EXCLUDE);
    return r;
}

UA_StatusCode gds_roles_install(gds_server *s, const gds_users *users) {
    fileUsers = users;
    gds_users_set_file(users);
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < gds_role_count() && r == UA_STATUSCODE_GOOD; i++) {
        UA_NodeId id;
        unsigned bit = 0;
        const char *name = NULL;
        gds_role_at(i, s->ns, &id, &bit, &name);
        r = bind_role(s, &id, bit, false);
    }
    static const UA_UInt32 fixedRoles[] = {UA_NS0ID_WELLKNOWNROLE_ANONYMOUS,
                                           UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER,
                                           UA_NS0ID_WELLKNOWNROLE_TRUSTEDAPPLICATION};
    for(size_t i = 0; i < GDS_ARRAY_SIZE(fixedRoles) && r == UA_STATUSCODE_GOOD; i++) {
        UA_NodeId id = UA_NODEID_NUMERIC(0, fixedRoles[i]);
        r = bind_role(s, &id, 0, true);
    }
    if(r == UA_STATUSCODE_GOOD)
        r = gds_users_install(s);
    if(r == UA_STATUSCODE_GOOD)
        gds_roles_reload(s);
    return r;
}

UA_StatusCode gds_roles_add_role_node(gds_server *s, const UA_NodeId *id, unsigned bit) {
    UA_StatusCode r = bind_role(s, id, bit, false);
    if(r == UA_STATUSCODE_GOOD)
        gds_roles_reload(s);
    return r;
}
