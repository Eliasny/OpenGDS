/* OpenGDS - users, roles and sessions.
 * SPDX-License-Identifier: MPL-2.0 */
#include "gds_access.h"

#include <open62541/nodeids.h>
#include <open62541/nodeids_gds.h>
#include <open62541/plugin/accesscontrol_default.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>

#include "common/safeint.h"
#include "common/banned.h"

#define MAX_USERS_FILE ((size_t)64 * 1024)
#define MIN_ITER 10000
#define MAX_ITER 10000000

/* ---- users file ---- */

static int hexval(char c) {
    if(c >= '0' && c <= '9')
        return c - '0';
    if(c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if(c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static bool unhex(const char *s, size_t sLen, uint8_t *out, size_t outLen) {
    if(sLen != 2 * outLen)
        return false;
    for(size_t i = 0; i < outLen; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if(hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return true;
}

typedef struct {
    const char *p;
    size_t n;
} span;

/* Next field separated by `sep` from *s (of *len bytes). */
static span next_field(const char **s, size_t *len, char sep) {
    while(*len > 0 && **s == sep) {
        (*s)++;
        (*len)--;
    }
    span f = {*s, 0};
    while(*len > 0 && **s != sep) {
        (*s)++;
        (*len)--;
        f.n++;
    }
    return f;
}

static bool span_eq(span f, const char *lit) {
    return f.n == strlen(lit) && memcmp(f.p, lit, f.n) == 0;
}

static bool parse_name(span f, gds_user *u) {
    if(f.n == 0 || f.n > GDS_MAX_USER_NAME)
        return false;
    for(size_t i = 0; i < f.n; i++) {
        char c = f.p[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '.' || c == '_' || c == '-' || c == '@';
        if(!ok)
            return false;
    }
    memcpy(u->name, f.p, f.n);
    u->name[f.n] = '\0';
    return true;
}

static const gds_role_info roleTable[] = {
    {"DiscoveryAdmin", GDS_ROLE_DISCOVERY_ADMIN, true, UA_GDSID_WELLKNOWNROLE_DISCOVERYADMIN},
    {"CertificateAuthorityAdmin", GDS_ROLE_CERTIFICATE_AUTHORITY_ADMIN, true,
     UA_GDSID_WELLKNOWNROLE_CERTIFICATEAUTHORITYADMIN},
    {"SecurityAdmin", GDS_ROLE_SECURITY_ADMIN, false, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN},
    {"Observer", GDS_ROLE_OBSERVER, false, UA_NS0ID_WELLKNOWNROLE_OBSERVER},
    {"Operator", GDS_ROLE_OPERATOR, false, UA_NS0ID_WELLKNOWNROLE_OPERATOR},
    {"Engineer", GDS_ROLE_ENGINEER, false, UA_NS0ID_WELLKNOWNROLE_ENGINEER},
    {"Supervisor", GDS_ROLE_SUPERVISOR, false, UA_NS0ID_WELLKNOWNROLE_SUPERVISOR},
    {"ConfigureAdmin", GDS_ROLE_CONFIGURE_ADMIN, false, UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN},
    {"RegistrationAuthorityAdmin", GDS_ROLE_REGISTRATION_AUTHORITY_ADMIN, true,
     UA_GDSID_WELLKNOWNROLE_REGISTRATIONAUTHORITYADMIN},
    {"KeyCredentialAdmin", GDS_ROLE_KEY_CREDENTIAL_ADMIN, true,
     UA_GDSID_WELLKNOWNROLE_KEYCREDENTIALADMIN},
    {"AuthorizationServiceAdmin", GDS_ROLE_AUTHORIZATION_SERVICE_ADMIN, true,
     UA_GDSID_WELLKNOWNROLE_AUTHORIZATIONSERVICEADMIN},
    {"SecurityKeyServerAdmin", GDS_ROLE_SKS_ADMIN, false,
     UA_NS0ID_WELLKNOWNROLE_SECURITYKEYSERVERADMIN},
    {"SecurityKeyServerPush", GDS_ROLE_SKS_PUSH, false,
     UA_NS0ID_WELLKNOWNROLE_SECURITYKEYSERVERPUSH},
    {"SecurityKeyServerAccess", GDS_ROLE_SKS_ACCESS, false,
     UA_NS0ID_WELLKNOWNROLE_SECURITYKEYSERVERACCESS},
};

const gds_role_info *gds_role_table(size_t *n) {
    *n = sizeof(roleTable) / sizeof(roleTable[0]);
    return roleTable;
}

/* ---- embedder Roles (A10) ----
 * Added on the server thread before the server runs and read after, so
 * they need no lock; gds_access_uninstall clears them. */
typedef struct {
    char name[GDS_MAX_ROLE_NAME + 1];
    UA_NodeId id;
} embed_role;
static embed_role embedRoles[GDS_MAX_EMBED_ROLES];
static size_t nEmbedRoles;
static const gds_users *installedUsers;

_Static_assert(sizeof(roleTable) / sizeof(roleTable[0]) == GDS_ROLE_BUILTIN_COUNT,
               "GDS_ROLE_BUILTIN_COUNT");
_Static_assert(GDS_ROLE_EMBED_FIRST_BIT + GDS_MAX_EMBED_ROLES <= 31, "role bits");

size_t gds_role_count(void) {
    return GDS_ROLE_BUILTIN_COUNT + nEmbedRoles;
}

void gds_role_at(size_t i, UA_UInt16 gdsNs, UA_NodeId *id, unsigned *bit, const char **name) {
    if(i < GDS_ROLE_BUILTIN_COUNT) {
        const gds_role_info *r = &roleTable[i];
        *id = UA_NODEID_NUMERIC(r->gdsNamespace ? gdsNs : 0, r->id);
        *bit = r->bit;
        *name = r->name;
        return;
    }
    const embed_role *e = &embedRoles[i - GDS_ROLE_BUILTIN_COUNT];
    *id = e->id;
    *bit = 1u << (GDS_ROLE_EMBED_FIRST_BIT + (i - GDS_ROLE_BUILTIN_COUNT));
    *name = e->name;
}

unsigned gds_role_bit(UA_UInt16 gdsNs, const UA_NodeId *id) {
    for(size_t i = 0; i < gds_role_count(); i++) {
        UA_NodeId r;
        unsigned bit = 0;
        const char *name = NULL;
        gds_role_at(i, gdsNs, &r, &bit, &name);
        if(UA_NodeId_equal(&r, id))
            return bit;
    }
    return 0;
}

static bool role_name_ok(span f) {
    if(f.n == 0 || f.n > GDS_MAX_ROLE_NAME || span_eq(f, "Anonymous") ||
       span_eq(f, "AuthenticatedUser") || span_eq(f, "-"))
        return false;
    for(size_t i = 0; i < f.n; i++) {
        char c = f.p[i];
        if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
             c == '.' || c == '_' || c == '-'))
            return false;
    }
    return true;
}

static unsigned role_by_name(span f) {
    for(size_t i = 0; i < gds_role_count(); i++) {
        UA_NodeId id;
        unsigned bit = 0;
        const char *name = NULL;
        gds_role_at(i, 0, &id, &bit, &name);
        if(span_eq(f, name))
            return bit;
    }
    return 0;
}

gds_status gds_access_add_role(const char *name, const UA_NodeId *id, UA_UInt16 gdsNs) {
    if(!name || !id || UA_NodeId_isNull(id))
        return GDS_EINVAL;
    span f = {name, strlen(name)};
    if(f.n > GDS_MAX_ROLE_NAME || !role_name_ok(f))
        return span_eq(f, "Anonymous") || span_eq(f, "AuthenticatedUser") ? GDS_EEXISTS
                                                                            : GDS_EINVAL;
    const UA_NodeId anon = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS);
    const UA_NodeId auth = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER);
    if(role_by_name(f) || gds_role_bit(gdsNs, id) || UA_NodeId_equal(id, &anon) ||
       UA_NodeId_equal(id, &auth))
        return GDS_EEXISTS;
    if(nEmbedRoles == GDS_MAX_EMBED_ROLES)
        return GDS_ETOOBIG;
    embed_role *e = &embedRoles[nEmbedRoles];
    if(UA_NodeId_copy(id, &e->id) != UA_STATUSCODE_GOOD)
        return GDS_ENOMEM;
    memcpy(e->name, name, f.n);
    e->name[f.n] = '\0';
    nEmbedRoles++;
    return GDS_OK;
}

void gds_access_drop_last_role(void) {
    if(nEmbedRoles == 0)
        return;
    nEmbedRoles--;
    UA_NodeId_clear(&embedRoles[nEmbedRoles].id);
    memset(&embedRoles[nEmbedRoles], 0, sizeof(embedRoles[0]));
}

static void embed_roles_clear(void) {
    for(size_t i = 0; i < nEmbedRoles; i++)
        UA_NodeId_clear(&embedRoles[i].id);
    memset(embedRoles, 0, sizeof(embedRoles));
    nEmbedRoles = 0;
}

/* The embedder Role bits of a user; 0 for names that are no Role. */
static unsigned embed_bits(const gds_user *u) {
    unsigned bits = 0;
    for(size_t i = 0; i < u->nEmbedRoles; i++) {
        span f = {u->embedRoles[i], strlen(u->embedRoles[i])};
        bits |= role_by_name(f);
    }
    return bits;
}

gds_status gds_access_check_users(void) {
    const gds_users *users = installedUsers;
    for(size_t i = 0; users && i < users->n; i++) {
        const gds_user *u = &users->users[i];
        for(size_t k = 0; k < u->nEmbedRoles; k++) {
            span f = {u->embedRoles[k], strlen(u->embedRoles[k])};
            if(!role_by_name(f)) {
                fprintf(stderr, "users file: user %s: %s is not a Role\n", u->name,
                        u->embedRoles[k]);
                return GDS_EINVAL;
            }
        }
    }
    return GDS_OK;
}

/* Built-in names become bits; any other well-formed name is kept for
 * the embedder Roles, which may be added after the file is loaded. */
static bool parse_roles(span f, gds_user *u) {
    u->roles = 0;
    u->nEmbedRoles = 0;
    if(span_eq(f, "-"))
        return true;
    const char *p = f.p;
    size_t len = f.n;
    while(len > 0) {
        span r = next_field(&p, &len, ',');
        if(r.n == 0)
            break;
        unsigned bit = 0;
        for(size_t i = 0; i < GDS_ROLE_BUILTIN_COUNT && !bit; i++)
            if(span_eq(r, roleTable[i].name))
                bit = roleTable[i].bit;
        if(bit) {
            u->roles |= bit;
            continue;
        }
        if(!role_name_ok(r) || u->nEmbedRoles == GDS_MAX_EMBED_ROLES)
            return false;
        bool dup = false;
        for(size_t i = 0; i < u->nEmbedRoles && !dup; i++)
            dup = span_eq(r, u->embedRoles[i]);
        if(dup)
            continue;
        memcpy(u->embedRoles[u->nEmbedRoles], r.p, r.n);
        u->embedRoles[u->nEmbedRoles++][r.n] = '\0';
    }
    return true;
}

/* pbkdf2-sha256:<iterations>:<salt hex>:<hash hex> or x509-sha256:<hex> */
static bool parse_credential(span f, gds_user *u) {
    const char *p = f.p;
    size_t len = f.n;
    span algo = next_field(&p, &len, ':');
    if(span_eq(algo, "x509-sha256")) {
        span thumb = next_field(&p, &len, ':');
        u->x509 = true;
        return len == 0 && unhex(thumb.p, thumb.n, u->thumbprint, sizeof(u->thumbprint));
    }
    span iter = next_field(&p, &len, ':');
    span salt = next_field(&p, &len, ':');
    span hash = next_field(&p, &len, ':');
    if(!span_eq(algo, "pbkdf2-sha256") || len != 0 || iter.n == 0 || iter.n > 8)
        return false;
    char num[9];
    memcpy(num, iter.p, iter.n);
    num[iter.n] = '\0';
    long it = 0;
    if(!gds_parse_long(num, MIN_ITER, MAX_ITER, &it))
        return false;
    u->iterations = (uint32_t)it;
    return unhex(salt.p, salt.n, u->salt, sizeof(u->salt)) &&
           unhex(hash.p, hash.n, u->hash, sizeof(u->hash));
}

/* One line; *blank is set for blank and comment lines. */
static bool parse_line(const char *line, size_t len, gds_user *u, bool *blank) {
    const char *hash = memchr(line, '#', len);
    if(hash)
        len = (size_t)(hash - line);
    while(len > 0 && (line[len - 1] == ' ' || line[len - 1] == '\t' || line[len - 1] == '\r'))
        len--;
    span name = next_field(&line, &len, ' ');
    *blank = name.n == 0;
    if(*blank)
        return true;
    span roles = next_field(&line, &len, ' ');
    span cred = next_field(&line, &len, ' ');
    span extra = next_field(&line, &len, ' ');
    memset(u, 0, sizeof(*u));
    return extra.n == 0 && parse_name(name, u) && parse_roles(roles, u) &&
           parse_credential(cred, u);
}

gds_status gds_users_load(const char *path, gds_users *out) {
    memset(out, 0, sizeof(*out));
    struct stat sb;
    if(stat(path, &sb) != 0)
        return GDS_ENOTFOUND;
    if(sb.st_mode & 0007) {
        fprintf(stderr, "users file %s is readable by others: refusing it\n", path);
        return GDS_EDENIED;
    }
    gds_buf b = {0};
    gds_status r = gds_file_read(path, MAX_USERS_FILE, &b);
    size_t pos = 0, lineNo = 0;
    while(r == GDS_OK && pos < b.len) {
        const char *line = (const char *)b.data + pos;
        const char *nl = memchr(line, '\n', b.len - pos);
        size_t len = nl ? (size_t)(nl - line) : b.len - pos;
        pos += len + 1;
        lineNo++;
        bool blank = false;
        gds_user u;
        if(!parse_line(line, len, &u, &blank)) {
            fprintf(stderr, "users file %s:%zu: malformed line\n", path, lineNo);
            r = GDS_EINVAL;
        } else if(!blank && out->n == GDS_MAX_USERS) {
            r = GDS_ETOOBIG;
        } else if(!blank) {
            for(size_t i = 0; i < out->n && r == GDS_OK; i++)
                if(strcmp(out->users[i].name, u.name) == 0 ||
                   (u.x509 && out->users[i].x509 &&
                    memcmp(out->users[i].thumbprint, u.thumbprint, sizeof(u.thumbprint)) == 0))
                    r = GDS_EEXISTS;
            if(r == GDS_OK)
                out->users[out->n++] = u;
        }
        OPENSSL_cleanse(&u, sizeof(u));
    }
    gds_buf_free_secret(&b);
    if(r != GDS_OK)
        OPENSSL_cleanse(out, sizeof(*out));
    return r;
}

static bool pbkdf2(const uint8_t *pw, size_t len, const uint8_t *salt, uint32_t iter,
                   uint8_t out[GDS_PBKDF2_HASH]) {
    if(len > INT32_MAX)
        return false;
    return PKCS5_PBKDF2_HMAC((const char *)pw, (int)len, salt, GDS_PBKDF2_SALT, (int)iter,
                             EVP_sha256(), GDS_PBKDF2_HASH, out) == 1;
}

gds_status gds_password_hash(const uint8_t *pw, size_t len, uint32_t iterations, char *out,
                             size_t outLen) {
    uint8_t salt[GDS_PBKDF2_SALT], hash[GDS_PBKDF2_HASH];
    if(iterations < MIN_ITER || iterations > MAX_ITER || len == 0)
        return GDS_EINVAL;
    if(RAND_bytes(salt, sizeof(salt)) != 1 || !pbkdf2(pw, len, salt, iterations, hash))
        return GDS_ECRYPTO;
    char sh[2 * GDS_PBKDF2_SALT + 1], hh[2 * GDS_PBKDF2_HASH + 1];
    gds_status r = gds_hex(salt, sizeof(salt), sh, sizeof(sh));
    if(r == GDS_OK)
        r = gds_hex(hash, sizeof(hash), hh, sizeof(hh));
    if(r == GDS_OK)
        r = gds_path(out, outLen, "pbkdf2-sha256:%u:%s:%s", iterations, sh, hh);
    OPENSSL_cleanse(hash, sizeof(hash));
    return r;
}

const gds_user *gds_users_check_cert(const gds_users *u, const UA_ByteString *certDer) {
    uint8_t thumb[GDS_X509_THUMBPRINT];
    unsigned len = 0;
    if(!u || !certDer || certDer->length == 0 ||
       EVP_Digest(certDer->data, certDer->length, thumb, &len, EVP_sha256(), NULL) != 1 ||
       len != sizeof(thumb))
        return NULL;
    for(size_t i = 0; i < u->n; i++)
        if(u->users[i].x509 &&
           CRYPTO_memcmp(u->users[i].thumbprint, thumb, sizeof(thumb)) == 0)
            return &u->users[i];
    return NULL;
}

const gds_user *gds_users_check(const gds_users *u, const UA_String *name, const UA_ByteString *pw) {
    const gds_user *found = NULL;
    for(size_t i = 0; i < u->n && !found; i++)
        if(!u->users[i].x509 && name->length == strlen(u->users[i].name) &&
           memcmp(name->data, u->users[i].name, name->length) == 0)
            found = &u->users[i];
    /* unknown users cost the same PBKDF2 as known ones */
    static const uint8_t dummySalt[GDS_PBKDF2_SALT] = {0};
    const uint8_t *salt = found ? found->salt : dummySalt;
    uint32_t iter = found ? found->iterations : GDS_PBKDF2_DEFAULT_ITER;
    uint8_t h[GDS_PBKDF2_HASH];
    bool ok = pw->length > 0 && pbkdf2(pw->data, pw->length, salt, iter, h) && found &&
              CRYPTO_memcmp(h, found->hash, sizeof(h)) == 0;
    OPENSSL_cleanse(h, sizeof(h));
    return ok ? found : NULL;
}

/* ---- sessions ---- */

/* Activated sessions, for audit event visibility (gds_audit.c). Written on
 * the server thread (activate, close), read from workers; sessLock is a
 * leaf lock and never held across a call into open62541. */
#define MAX_LIVE_SESSIONS 1024
typedef struct {
    UA_NodeId id;
    bool anonymous;
    unsigned roles;
    UA_DateTime notAfter;
} live_session;
static live_session live[MAX_LIVE_SESSIONS];
static size_t nLive;
static pthread_mutex_t sessLock = PTHREAD_MUTEX_INITIALIZER;

static void live_remove(const UA_NodeId *id) {
    pthread_mutex_lock(&sessLock);
    for(size_t i = 0; i < nLive; i++) {
        if(!UA_NodeId_equal(&live[i].id, id))
            continue;
        UA_NodeId_clear(&live[i].id);
        live[i] = live[--nLive];
        memset(&live[nLive], 0, sizeof(live[nLive]));
        break;
    }
    pthread_mutex_unlock(&sessLock);
}

static void live_set(const UA_NodeId *id, const gds_session *s) {
    live_remove(id);
    pthread_mutex_lock(&sessLock);
    if(nLive < MAX_LIVE_SESSIONS && UA_NodeId_copy(id, &live[nLive].id) == UA_STATUSCODE_GOOD) {
        live[nLive].anonymous = s->anonymous;
        live[nLive].roles = s->roles;
        live[nLive].notAfter = s->notAfter;
        nLive++;
    }
    pthread_mutex_unlock(&sessLock);
}

size_t gds_access_sessions_with(unsigned roles, bool anonymous, bool authenticated,
                                UA_NodeId *out, size_t max) {
    size_t n = 0;
    UA_DateTime now = UA_DateTime_now();
    pthread_mutex_lock(&sessLock);
    for(size_t i = 0; i < nLive && n < max; i++) {
        const live_session *l = &live[i];
        bool anon = l->anonymous || (l->notAfter != 0 && now > l->notAfter);
        bool match = anonymous || (authenticated && !anon) || (!anon && (l->roles & roles) != 0);
        if(match && UA_NodeId_copy(&l->id, &out[n]) == UA_STATUSCODE_GOOD)
            n++;
    }
    pthread_mutex_unlock(&sessLock);
    return n;
}

static void live_clear(void) {
    pthread_mutex_lock(&sessLock);
    for(size_t i = 0; i < nLive; i++)
        UA_NodeId_clear(&live[i].id);
    nLive = 0;
    pthread_mutex_unlock(&sessLock);
}

static void session_free(gds_session *s) {
    if(!s)
        return;
    UA_String_clear(&s->clientAppUri);
    UA_String_clear(&s->securityPolicyUri);
    for(size_t i = 0; i < GDS_SESSION_TL_HANDLES; i++)
        UA_ByteString_clear(&s->tl[i].file);
    free(s);
}

static X509 *gdsCa; /* the GDS CA, for the ApplicationSelfAdmin check */

static bool issued_by_ca(X509 *x) {
    if(!gdsCa)
        return false;
    X509_STORE *st = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    bool ok = st && ctx && X509_STORE_add_cert(st, gdsCa) == 1 &&
              X509_STORE_CTX_init(ctx, st, x, NULL) == 1 && X509_verify_cert(ctx) == 1;
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(st);
    return ok;
}

/* SAN URI of a DER certificate that the GDS CA issued, or an empty string:
 * the channel accepts any certificate (applications come for their first
 * one), so a self-made certificate must not claim an application. */
static UA_String cert_app_uri(const UA_ByteString *der) {
    UA_String out = UA_STRING_NULL;
    if(!der || der->length == 0 || der->length > GDS_MAX_CERT_SIZE)
        return out;
    const unsigned char *p = der->data;
    X509 *x = d2i_X509(NULL, &p, (long)der->length);
    if(x && (p != der->data + der->length || !issued_by_ca(x))) {
        X509_free(x);
        x = NULL;
    }
    GENERAL_NAMES *gens = x ? X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL) : NULL;
    for(int i = 0; gens && i < sk_GENERAL_NAME_num(gens) && out.length == 0; i++) {
        const GENERAL_NAME *g = sk_GENERAL_NAME_value(gens, i);
        if(g->type == GEN_URI && g->d.ia5->length > 0 &&
           (size_t)g->d.ia5->length <= GDS_MAX_APPLICATION_URI) {
            UA_String v = {(size_t)g->d.ia5->length, g->d.ia5->data};
            if(UA_String_copy(&v, &out) != UA_STATUSCODE_GOOD)
                out = UA_STRING_NULL;
        }
    }
    GENERAL_NAMES_free(gens);
    X509_free(x);
    return out;
}

bool gds_session_is_app(const void *sessionContext, const UA_String *applicationUri) {
    const gds_session *s = sessionContext;
    return s && s->clientAppUri.length > 0 && UA_String_equal(&s->clientAppUri, applicationUri);
}

static UA_StatusCode login_cb(const UA_String *userName, const UA_ByteString *password,
                              size_t n, const UA_UsernamePasswordLogin *list,
                              void **sessionContext, void *loginContext) {
    (void)n, (void)list;
    const gds_users *users = loginContext;
    gds_session *s = calloc(1, sizeof(*s));
    if(!s)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    if(userName->length == 0 && password->length == 0) {
        s->anonymous = true;
    } else {
        const gds_user *u = gds_users_check(users, userName, password);
        if(!u) {
            free(s);
            return UA_STATUSCODE_BADUSERACCESSDENIED;
        }
        memcpy(s->user, u->name, sizeof(s->user));
        s->roles = u->roles | embed_bits(u);
    }
    *sessionContext = s;
    return UA_STATUSCODE_GOOD;
}

typedef UA_StatusCode (*activate_fn)(UA_Server *, UA_AccessControl *, const UA_EndpointDescription *,
                                     const UA_ByteString *, const UA_NodeId *,
                                     const UA_ExtensionObject *, void **);
static activate_fn defaultActivate;
static bool x509Enabled;

/* The certificate's notAfter, 0 if it cannot be read. */
static UA_DateTime not_after(const UA_ByteString *der) {
    const unsigned char *p = der->data;
    X509 *x = der->length <= LONG_MAX ? d2i_X509(NULL, &p, (long)der->length) : NULL;
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    UA_DateTime t = 0;
    if(x && ASN1_TIME_to_tm(X509_get0_notAfter(x), &tm) == 1)
        t = UA_DateTime_fromUnixTime((UA_Int64)timegm(&tm));
    X509_free(x);
    return t;
}

/* An X509IdentityToken: open62541 has already checked userTokenSignature
 * (OPC 10000-4 §5.7.3.2, computed as in §6.1.8) and validated the
 * certificate against config->sessionPKI, the DefaultUserTokenGroup trust
 * list (OPC 10000-12 §7.8.3.3), with the steps of OPC 10000-4 §6.1.3
 * Table 100 (validity period, revocation). Here the certificate becomes a
 * user of the users file, or is refused. */
static UA_StatusCode activate_x509(const UA_X509IdentityToken *t, void **sessionContext) {
    if(!x509Enabled)
        return UA_STATUSCODE_BADIDENTITYTOKENREJECTED;
    const gds_user *u = gds_users_check_cert(installedUsers, &t->certificateData);
    if(!u)
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    UA_DateTime end = not_after(&t->certificateData);
    if(end == 0 || UA_DateTime_now() > end)
        return UA_STATUSCODE_BADIDENTITYTOKENREJECTED;
    gds_session *s = calloc(1, sizeof(*s));
    if(!s)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    memcpy(s->user, u->name, sizeof(s->user));
    s->roles = u->roles | embed_bits(u);
    s->notAfter = end;
    *sessionContext = s;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode activate(UA_Server *server, UA_AccessControl *ac,
                              const UA_EndpointDescription *ep, const UA_ByteString *cert,
                              const UA_NodeId *sessionId, const UA_ExtensionObject *token,
                              void **sessionContext) {
    void *old = *sessionContext;
    UA_StatusCode r = defaultActivate(server, ac, ep, cert, sessionId, token, sessionContext);
    /* the default plugin takes X.509 tokens without a session context */
    if(r == UA_STATUSCODE_GOOD && token->encoding >= UA_EXTENSIONOBJECT_DECODED &&
       token->content.decoded.type == &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN])
        r = activate_x509(token->content.decoded.data, sessionContext);
    if(r != UA_STATUSCODE_GOOD) {
        if(*sessionContext != old) {
            session_free(*sessionContext);
            *sessionContext = old;
        }
        return r;
    }
    gds_session *s = *sessionContext;
    if(s != old)
        session_free(old); /* re-activation with a new identity */
    if(s && s->clientAppUri.length == 0)
        s->clientAppUri = cert_app_uri(cert);
    if(s && ep) {
        s->securityMode = ep->securityMode;
        UA_String_clear(&s->securityPolicyUri);
        if(UA_String_copy(&ep->securityPolicyUri, &s->securityPolicyUri) != UA_STATUSCODE_GOOD)
            s->securityPolicyUri = UA_STRING_NULL;
    }
    if(s && sessionId)
        live_set(sessionId, s);
    return UA_STATUSCODE_GOOD;
}

static void close_session(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sessionId,
                          void *sessionContext) {
    (void)server, (void)ac;
    if(sessionId)
        live_remove(sessionId);
    session_free(sessionContext);
}

/* ---- the address space is read-only to clients ----
 * The default plugin lets every session add and delete nodes and
 * references, and execute every method. OpenGDS clients change nothing but
 * through the GDS methods, which check their own rights. */

static UA_Boolean deny_add_node(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sid,
                                void *sctx, const UA_AddNodesItem *item) {
    (void)server, (void)ac, (void)sid, (void)sctx, (void)item;
    return false;
}
static UA_Boolean deny_add_ref(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sid,
                               void *sctx, const UA_AddReferencesItem *item) {
    (void)server, (void)ac, (void)sid, (void)sctx, (void)item;
    return false;
}
static UA_Boolean deny_del_node(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sid,
                                void *sctx, const UA_DeleteNodesItem *item) {
    (void)server, (void)ac, (void)sid, (void)sctx, (void)item;
    return false;
}
static UA_Boolean deny_del_ref(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sid,
                               void *sctx, const UA_DeleteReferencesItem *item) {
    (void)server, (void)ac, (void)sid, (void)sctx, (void)item;
    return false;
}
static UA_UInt32 no_rights(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sid,
                           void *sctx, const UA_NodeId *nodeId, void *nctx) {
    (void)server, (void)ac, (void)sid, (void)sctx, (void)nodeId, (void)nctx;
    return 0; /* no attribute writes */
}
static UA_Byte read_only(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sid,
                         void *sctx, const UA_NodeId *nodeId, void *nctx) {
    (void)server, (void)ac, (void)sid, (void)sctx, (void)nodeId, (void)nctx;
    return UA_ACCESSLEVELMASK_READ;
}

/* Namespace 0 methods every session may call. The ServerConfiguration
 * methods (push management of the GDS's own certificate and trust lists,
 * OPC 10000-12 §7.10) are for SecurityAdmin only; the rest of namespace 0
 * is not offered. Methods in the GDS namespace check rights themselves. */
static bool ns0_method_open(UA_UInt32 id) {
    return id == UA_NS0ID_SERVER_GETMONITOREDITEMS || id == UA_NS0ID_SERVER_RESENDDATA ||
           id == UA_NS0ID_CONDITIONTYPE_CONDITIONREFRESH ||
           id == UA_NS0ID_CONDITIONTYPE_CONDITIONREFRESH2;
}

#define SC_TL(g, m) UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_##g##_TRUSTLIST_##m
static bool server_configuration_method(UA_UInt32 id) {
    static const UA_UInt32 ids[] = {
        UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE,
        UA_NS0ID_SERVERCONFIGURATION_CREATESIGNINGREQUEST,
        UA_NS0ID_SERVERCONFIGURATION_GETREJECTEDLIST,
        UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES,
        SC_TL(DEFAULTAPPLICATIONGROUP, OPEN),
        SC_TL(DEFAULTAPPLICATIONGROUP, OPENWITHMASKS),
        SC_TL(DEFAULTAPPLICATIONGROUP, READ),
        SC_TL(DEFAULTAPPLICATIONGROUP, WRITE),
        SC_TL(DEFAULTAPPLICATIONGROUP, CLOSE),
        SC_TL(DEFAULTAPPLICATIONGROUP, CLOSEANDUPDATE),
        SC_TL(DEFAULTAPPLICATIONGROUP, GETPOSITION),
        SC_TL(DEFAULTAPPLICATIONGROUP, SETPOSITION),
        SC_TL(DEFAULTAPPLICATIONGROUP, ADDCERTIFICATE),
        SC_TL(DEFAULTAPPLICATIONGROUP, REMOVECERTIFICATE),
        SC_TL(DEFAULTUSERTOKENGROUP, OPEN),
        SC_TL(DEFAULTUSERTOKENGROUP, OPENWITHMASKS),
        SC_TL(DEFAULTUSERTOKENGROUP, READ),
        SC_TL(DEFAULTUSERTOKENGROUP, WRITE),
        SC_TL(DEFAULTUSERTOKENGROUP, CLOSE),
        SC_TL(DEFAULTUSERTOKENGROUP, CLOSEANDUPDATE),
        SC_TL(DEFAULTUSERTOKENGROUP, GETPOSITION),
        SC_TL(DEFAULTUSERTOKENGROUP, SETPOSITION),
        SC_TL(DEFAULTUSERTOKENGROUP, ADDCERTIFICATE),
        SC_TL(DEFAULTUSERTOKENGROUP, REMOVECERTIFICATE),
    };
    for(size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++)
        if(ids[i] == id)
            return true;
    return false;
}

bool gds_method_executable(const struct gds_server *s, const void *sessionContext,
                           const UA_NodeId *methodId) {
    int d = gds_embed_decide(s, sessionContext, methodId);
    if(d >= 0)
        return d == 1;
    if(methodId->identifierType != UA_NODEIDTYPE_NUMERIC)
        return false;
    UA_UInt32 id = methodId->identifier.numeric;
    if(ns0_method_open(id))
        return true;
    /* answering approval dialogs (gds_approvals.c) */
    if(id == UA_NS0ID_DIALOGCONDITIONTYPE_RESPOND || id == UA_NS0ID_DIALOGCONDITIONTYPE_RESPOND2)
        return gds_session_has(sessionContext, GDS_ROLE_REGISTRATION_AUTHORITY_ADMIN);
    return gds_session_has(sessionContext, GDS_ROLE_SECURITY_ADMIN) &&
           server_configuration_method(id);
}

static UA_Boolean executable(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sid,
                             void *sctx, const UA_NodeId *methodId, void *mctx) {
    (void)ac, (void)sid, (void)mctx;
    return gds_method_executable(UA_Server_getConfig(server)->context, sctx, methodId);
}
static UA_Boolean executable_on(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sid,
                                void *sctx, const UA_NodeId *methodId, void *mctx,
                                const UA_NodeId *objectId, void *octx) {
    (void)ac, (void)sid, (void)mctx, (void)octx;
    struct gds_server *s = UA_Server_getConfig(server)->context;
    /* RolePermissions of embedder nodes (issue #49): Call on the object
     * and on the method node */
    return gds_method_executable(s, sctx, methodId) && gds_node_call_allowed(s, sctx, objectId) &&
           gds_node_call_allowed(s, sctx, methodId);
}

void gds_access_uninstall(void) {
    live_clear();
    x509Enabled = false;
    embed_roles_clear();
    installedUsers = NULL;
    X509_free(gdsCa);
    gdsCa = NULL;
}

gds_status gds_access_install(UA_ServerConfig *config, const gds_users *users,
                              const gds_buf *caCertDer, bool x509Users) {
    gds_access_uninstall();
    const unsigned char *cp = caCertDer->data;
    gdsCa = caCertDer->len ? d2i_X509(NULL, &cp, (long)caCertDer->len) : NULL;
    if(!gdsCa)
        return GDS_EINVAL;
    /* The default plugin adds the user name policy only with a login list;
     * the entry is never compared because the callback decides. */
    uint8_t rnd[32];
    if(RAND_bytes(rnd, sizeof(rnd)) != 1)
        return GDS_ECRYPTO;
    UA_UsernamePasswordLogin placeholder = {UA_STRING("\x01"), {sizeof(rnd), rnd}};
    if(config->accessControl.clear)
        config->accessControl.clear(&config->accessControl);
    /* user name tokens are encrypted with the channel's policy */
    UA_StatusCode r = UA_AccessControl_defaultWithLoginCallback(
        config, true, NULL, 1, &placeholder, login_cb, (void *)(uintptr_t)users);
    OPENSSL_cleanse(rnd, sizeof(rnd));
    if(r != UA_STATUSCODE_GOOD)
        return GDS_ENOMEM;
    installedUsers = users;
    defaultActivate = config->accessControl.activateSession;
    config->accessControl.activateSession = activate;
    config->accessControl.closeSession = close_session;
    config->accessControl.allowAddNode = deny_add_node;
    config->accessControl.allowAddReference = deny_add_ref;
    config->accessControl.allowDeleteNode = deny_del_node;
    config->accessControl.allowDeleteReference = deny_del_ref;
    config->accessControl.getUserRightsMask = no_rights;
    config->accessControl.getUserAccessLevel = read_only;
    config->accessControl.getUserExecutable = executable;
    config->accessControl.getUserExecutableOnObject = executable_on;
    /* X.509 user tokens only with a user certificate trust list */
    x509Enabled = x509Users;
    UA_AccessControl *ac = &config->accessControl;
    size_t k = 0;
    for(size_t i = 0; i < ac->userTokenPoliciesSize; i++) {
        if(!x509Users && ac->userTokenPolicies[i].tokenType == UA_USERTOKENTYPE_CERTIFICATE) {
            UA_UserTokenPolicy_clear(&ac->userTokenPolicies[i]);
            continue;
        }
        ac->userTokenPolicies[k++] = ac->userTokenPolicies[i];
    }
    ac->userTokenPoliciesSize = k;
    return GDS_OK;
}
