/* OpenGDS - opengdsd configuration file parser (see config.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "config.h"

#include <string.h>

#include "common/buf.h"
#include "common/safeint.h"
#include "common/banned.h"

#define MAX_CONFIG_FILE ((size_t)64 * 1024)
#define DEFAULT_PORT 58810

typedef enum { T_STR, T_PATH, T_BOOL, T_PORT, T_APPROVAL, T_U32 } kind;

typedef struct {
    const char *key;
    size_t off, size;
    kind k;
    bool required;
    long min, max; /* T_U32 */
} field;

#define F(name, member, k, req)                                                          \
    {name, offsetof(gdsd_config, member), sizeof(((gdsd_config *)0)->member), k, req, 0, 0}
#define U(name, member, lo, hi)                                                          \
    {name, offsetof(gdsd_config, member), sizeof(((gdsd_config *)0)->member), T_U32, false, \
     lo, hi}
#define DAY 86400L

static const field fields[] = {
    F("application_uri", applicationUri, T_STR, true),
    F("application_name", applicationName, T_STR, false),
    F("product_uri", productUri, T_STR, false),
    F("hostname", hostname, T_STR, false),
    F("data_dir", dataDir, T_PATH, true),
    F("users_file", usersFile, T_PATH, true),
    F("organization", organization, T_STR, false),
    F("ca_dir", caDir, T_PATH, true),
    F("signer", signer, T_PATH, false),
    F("signer_socket", signerSocket, T_PATH, false),
    F("ca_passphrase_file", caPassphraseFile, T_PATH, false),
    F("port", port, T_PORT, false),
    F("loopback_only", loopbackOnly, T_BOOL, false),
    F("approval", approval, T_APPROVAL, false),
    F("push", push, T_BOOL, false),
    U("push_interval", pushIntervalS, 1, DAY),
    U("push_concurrency", pushConcurrency, 1, 64),
    U("max_sessions", maxSessions, 1, 1000),
    U("push_jitter", pushJitterS, 0, DAY),
    U("push_backoff_min", pushBackoffMinS, 1, DAY),
    U("push_backoff_max", pushBackoffMaxS, 1, 30 * DAY),
    U("push_rejected_interval", pushRejectedS, 0, 30 * DAY),
    F("authorization_service", authorizationService, T_BOOL, false),
    F("authorization_service_uri", authorizationServiceUri, T_STR, false),
    U("access_token_lifetime", accessTokenLifetime, 60, DAY),
    U("refresh_token_lifetime", refreshTokenLifetime, 0, 30 * DAY),
};
#define NFIELDS (sizeof(fields) / sizeof(fields[0]))

static bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r';
}

static void trim(const char **b, const char **e) {
    while(*b < *e && is_space(**b))
        (*b)++;
    while(*e > *b && is_space((*e)[-1]))
        (*e)--;
}

static bool printable(const char *b, const char *e) {
    for(; b < e; b++)
        if((unsigned char)*b < 0x20 || (unsigned char)*b == 0x7f)
            return false;
    return true;
}

static bool set_bool(const char *v, char *dst) {
    bool b = strcmp(v, "true") == 0;
    if(!b && strcmp(v, "false") != 0)
        return false;
    memcpy(dst, &b, sizeof(b));
    return true;
}

static bool set_port(const char *v, char *dst) {
    long p = 0;
    if(!gds_parse_long(v, 0, 65535, &p))
        return false;
    uint16_t port = (uint16_t)p;
    memcpy(dst, &port, sizeof(port));
    return true;
}

static bool set_approval(const char *v, char *dst) {
    static const char *const names[] = {"auto", "renewals", "manual"};
    static const uint8_t values[] = {GDSD_APPROVE_AUTO, GDSD_APPROVE_RENEWALS, GDSD_APPROVE_MANUAL};
    for(size_t i = 0; i < sizeof(values); i++) {
        if(strcmp(v, names[i]) == 0) {
            memcpy(dst, &values[i], sizeof(uint8_t));
            return true;
        }
    }
    return false;
}

static bool set_u32(const field *f, const char *v, char *dst) {
    long n = 0;
    if(!gds_parse_long(v, f->min, f->max, &n))
        return false;
    uint32_t u = (uint32_t)n;
    memcpy(dst, &u, sizeof(u));
    return true;
}

static bool set_str(const field *f, const char *v, size_t n, char *dst) {
    if(n >= f->size || (f->k == T_PATH && v[0] != '/'))
        return false;
    memcpy(dst, v, n + 1);
    return true;
}

static bool set_value(const field *f, const char *v, size_t n, gdsd_config *c) {
    char *dst = (char *)c + f->off;
    char tmp[GDSD_MAX_VALUE];
    if(n == 0 || n >= sizeof(tmp))
        return false;
    memcpy(tmp, v, n);
    tmp[n] = '\0';
    switch(f->k) {
    case T_STR:
    case T_PATH:
        return set_str(f, tmp, n, dst);
    case T_BOOL:
        GDS_ASSERT(f->size == sizeof(bool));
        return set_bool(tmp, dst);
    case T_PORT:
        GDS_ASSERT(f->size == sizeof(uint16_t));
        return set_port(tmp, dst);
    case T_APPROVAL:
        GDS_ASSERT(f->size == sizeof(uint8_t));
        return set_approval(tmp, dst);
    case T_U32:
        GDS_ASSERT(f->size == sizeof(uint32_t));
        return set_u32(f, tmp, dst);
    default:
        return false;
    }
}

static void defaults(gdsd_config *c) {
    memset(c, 0, sizeof(*c));
    memcpy(c->applicationName, "OpenGDS", sizeof("OpenGDS"));
    memcpy(c->productUri, "https://opengds.org/opengds", sizeof("https://opengds.org/opengds"));
    c->port = DEFAULT_PORT;
    c->approval = GDSD_APPROVE_RENEWALS;
    c->pushIntervalS = 60;
    c->pushConcurrency = 4;
    c->maxSessions = 500;
    c->pushJitterS = 300;
    c->pushBackoffMinS = 60;
    c->pushBackoffMaxS = 6 * 3600;
    c->pushRejectedS = 3600;
    c->accessTokenLifetime = 3600;   /* Elias 2026-11-09 */
    c->refreshTokenLifetime = 86400; /* Elias 2026-11-09 */
}

static bool is_name_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '.' || c == '_' || c == '-';
}

/* The next space-separated word of [*b, e) */
static bool word(const char **b, const char *e, const char **wb, const char **we) {
    trim(b, &e);
    *wb = *b;
    while(*b < e && !is_space(**b))
        (*b)++;
    *we = *b;
    return *we > *wb;
}

/* keycred_service = <name> <ResourceUri> <ProfileUri>[,<ProfileUri>...] */
static bool set_keycred(const char *b, const char *e, gdsd_config *c) {
    if(c->nKeycred >= GDSD_MAX_KC)
        return false;
    gdsd_keycred k;
    memset(&k, 0, sizeof(k));
    const char *nb, *ne, *ub, *ue, *pb, *pe, *xb, *xe;
    if(!word(&b, e, &nb, &ne) || !word(&b, e, &ub, &ue) || !word(&b, e, &pb, &pe) ||
       word(&b, e, &xb, &xe))
        return false; /* three words exactly */
    size_t nl = (size_t)(ne - nb), ul = (size_t)(ue - ub), pl = (size_t)(pe - pb);
    if(nl >= sizeof(k.name) || ul >= sizeof(k.resourceUri) || pl >= sizeof(k.profiles) ||
       !memchr(ub, ':', ul))
        return false;
    for(const char *p = nb; p < ne; p++)
        if(!is_name_char(*p))
            return false;
    memcpy(k.name, nb, nl);
    memcpy(k.resourceUri, ub, ul);
    memcpy(k.profiles, pb, pl);
    size_t start = 0;
    for(size_t i = 0; i <= pl; i++) {
        if(i < pl && k.profiles[i] != ',')
            continue;
        if(i == start || k.nProfiles >= GDSD_MAX_KC_PROFILES ||
           !memchr(k.profiles + start, ':', i - start))
            return false; /* empty, too many, or not a URI */
        k.profiles[i] = '\0';
        k.profile[k.nProfiles++] = (uint16_t)start;
        start = i + 1;
    }
    for(uint8_t i = 0; i < c->nKeycred; i++)
        if(strcmp(c->keycred[i].name, k.name) == 0)
            return false; /* names are unique */
    c->keycred[c->nKeycred++] = k;
    return true;
}

/* One line; false on error. */
static bool parse_line(const char *b, const char *e, gdsd_config *c, bool *seen) {
    trim(&b, &e);
    if(b == e || *b == '#')
        return true;
    if(!printable(b, e))
        return false;
    const char *eq = memchr(b, '=', (size_t)(e - b));
    if(!eq)
        return false;
    const char *kb = b, *ke = eq, *vb = eq + 1, *ve = e;
    trim(&kb, &ke);
    trim(&vb, &ve);
    static const char kc[] = "keycred_service";
    if((size_t)(ke - kb) == sizeof(kc) - 1 && memcmp(kb, kc, sizeof(kc) - 1) == 0)
        return set_keycred(vb, ve, c); /* the one repeatable key */
    for(size_t i = 0; i < NFIELDS; i++) {
        size_t kl = strlen(fields[i].key);
        if((size_t)(ke - kb) != kl || memcmp(kb, fields[i].key, kl) != 0)
            continue;
        if(seen[i])
            return false;
        seen[i] = true;
        return set_value(&fields[i], vb, (size_t)(ve - vb), c);
    }
    return false; /* unknown key */
}

gds_status gdsd_config_parse(const char *text, size_t len, gdsd_config *out, unsigned *errLine) {
    bool seen[NFIELDS] = {0};
    defaults(out);
    *errLine = 0;
    unsigned line = 0;
    const char *p = text, *end = text + len;
    while(p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *le = nl ? nl : end;
        line++;
        if(memchr(p, '\0', (size_t)(le - p)) || !parse_line(p, le, out, seen)) {
            *errLine = line;
            return GDS_EINVAL;
        }
        p = nl ? nl + 1 : end;
    }
    for(size_t i = 0; i < NFIELDS; i++) {
        if(fields[i].required && !seen[i]) {
            *errLine = 0;
            return GDS_EINVAL;
        }
    }
    if(out->signer[0] && out->signerSocket[0])
        return GDS_EINVAL; /* one way to reach the signer */
    if(out->pushBackoffMaxS < out->pushBackoffMinS)
        return GDS_EINVAL;
    return GDS_OK;
}

gds_status gdsd_config_load(const char *path, gdsd_config *out, unsigned *errLine) {
    gds_buf b = {0};
    *errLine = 0;
    gds_status r = gds_file_read(path, MAX_CONFIG_FILE, &b);
    if(r == GDS_OK)
        r = gdsd_config_parse((const char *)b.data, b.len, out, errLine);
    gds_buf_free(&b);
    return r;
}
