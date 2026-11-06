/* OpenGDS - opengdsd configuration file parser (see config.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "config.h"

#include <string.h>

#include "common/buf.h"
#include "common/safeint.h"
#include "common/banned.h"

#define MAX_CONFIG_FILE ((size_t)64 * 1024)
#define DEFAULT_PORT 58810

typedef enum { T_STR, T_PATH, T_BOOL, T_PORT } kind;

typedef struct {
    const char *key;
    size_t off, size;
    kind k;
    bool required;
} field;

#define F(name, member, k, req)                                                          \
    {name, offsetof(gdsd_config, member), sizeof(((gdsd_config *)0)->member), k, req}

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
    F("ca_passphrase_file", caPassphraseFile, T_PATH, false),
    F("port", port, T_PORT, false),
    F("loopback_only", loopbackOnly, T_BOOL, false),
    F("auto_approve", autoApprove, T_BOOL, false),
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
        if(n >= f->size || (f->k == T_PATH && tmp[0] != '/'))
            return false;
        memcpy(dst, tmp, n + 1);
        return true;
    case T_BOOL: {
        bool b = strcmp(tmp, "true") == 0;
        if(!b && strcmp(tmp, "false") != 0)
            return false;
        GDS_ASSERT(f->size == sizeof(b));
        memcpy(dst, &b, sizeof(b));
        return true;
    }
    case T_PORT: {
        long p = 0;
        if(!gds_parse_long(tmp, 0, 65535, &p))
            return false;
        uint16_t port = (uint16_t)p;
        GDS_ASSERT(f->size == sizeof(port));
        memcpy(dst, &port, sizeof(port));
        return true;
    }
    default:
        return false;
    }
}

static void defaults(gdsd_config *c) {
    memset(c, 0, sizeof(*c));
    memcpy(c->applicationName, "OpenGDS", sizeof("OpenGDS"));
    memcpy(c->productUri, "https://opengds.org/opengds", sizeof("https://opengds.org/opengds"));
    c->port = DEFAULT_PORT;
    c->autoApprove = true;
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
