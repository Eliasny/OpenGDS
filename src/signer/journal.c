/* OpenGDS - the signer's issuance journal (UASM ask A8, issue #19). See
 * journal.h for the format.
 * SPDX-License-Identifier: MPL-2.0 */
#include "journal.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#include "common/banned.h"

#define NFIELDS 8
#define GUID_TEXT 36
#define MAX_NUMBER 20

struct gds_journal {
    int fd;
    bool broken; /* a failed write may have left a torn line */
    int64_t seq;
    uint8_t hash[GDS_AUDIT_HASH];
};

/* ---- helpers ---- */

static gds_status der_sha256(const gds_buf *der, uint8_t out[GDS_AUDIT_HASH]) {
    unsigned int n = 0;
    if(EVP_Digest(der->data, der->len, out, &n, EVP_sha256(), NULL) != 1 || n != GDS_AUDIT_HASH)
        return GDS_ECRYPTO;
    return GDS_OK;
}

static int nibble(char c) {
    if(c >= '0' && c <= '9')
        return c - '0';
    if(c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1; /* lower case is refused: the writer uses upper case only */
}

static bool unhex(const char *s, size_t n, uint8_t *out, size_t max, size_t *len) {
    if(n == 0 || n % 2 != 0 || n / 2 > max)
        return false;
    for(size_t i = 0; i < n / 2; i++) {
        int hi = nibble(s[2 * i]), lo = nibble(s[2 * i + 1]);
        if(hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    *len = n / 2;
    return true;
}

static bool number(const char *s, size_t n, int64_t *out) {
    if(n == 0 || n > MAX_NUMBER || (n > 1 && s[0] == '0'))
        return false;
    int64_t v = 0;
    for(size_t i = 0; i < n; i++) {
        if(s[i] < '0' || s[i] > '9' || v > (INT64_MAX - (s[i] - '0')) / 10)
            return false;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return true;
}

static bool guid_text(const UA_Guid *g, char out[GUID_TEXT + 1]) {
    UA_String s = UA_STRING_NULL;
    bool ok = UA_Guid_print(g, &s) == UA_STATUSCODE_GOOD && s.length == GUID_TEXT;
    if(ok) {
        memcpy(out, s.data, GUID_TEXT);
        out[GUID_TEXT] = '\0';
    }
    UA_String_clear(&s);
    return ok;
}

/* ---- parsing one line ---- */

typedef struct {
    const char *p[NFIELDS];
    size_t n[NFIELDS];
} fields;

/* Exactly NFIELDS non-empty fields separated by single spaces. */
static bool split(const char *line, size_t len, fields *f) {
    size_t k = 0, start = 0;
    for(size_t i = 0; i <= len; i++) {
        if(i < len && line[i] != ' ')
            continue;
        if(k == NFIELDS || i == start)
            return false;
        f->p[k] = line + start;
        f->n[k] = i - start;
        k++;
        start = i + 1;
    }
    return k == NFIELDS;
}

static bool parse_op(const fields *f, gds_journal_entry *e) {
    int64_t st = 0;
    if(!number(f->p[6], f->n[6], &st) || st > INT32_MAX)
        return false;
    e->status = (int)st;
    UA_String gs = {f->n[3], (UA_Byte *)(uintptr_t)f->p[3]};
    if(f->n[3] != GUID_TEXT || UA_Guid_parse(&e->requestId, gs) != UA_STATUSCODE_GOOD)
        return false;
    bool dashes = f->n[4] == 1 && f->p[4][0] == '-' && f->n[5] == 1 && f->p[5][0] == '-';
    if(f->n[2] == 7 && memcmp(f->p[2], "REFUSED", 7) == 0)
        return dashes && e->status != 0;
    size_t hl = 0;
    e->issued = true;
    return f->n[2] == 6 && memcmp(f->p[2], "ISSUED", 6) == 0 && e->status == 0 &&
           unhex(f->p[4], f->n[4], e->serial, sizeof(e->serial), &e->serialLen) &&
           unhex(f->p[5], f->n[5], e->derSha256, sizeof(e->derSha256), &hl) &&
           hl == GDS_AUDIT_HASH;
}

/* Parses and verifies one line (without its '\n') against the chain. */
static bool parse_line(const char *line, size_t len, int64_t seq, uint8_t hash[GDS_AUDIT_HASH],
                       gds_journal_entry *e) {
    fields f;
    memset(e, 0, sizeof(*e));
    if(!split(line, len, &f) || !number(f.p[0], f.n[0], &e->seq) || e->seq != seq ||
       !number(f.p[1], f.n[1], &e->time) || !parse_op(&f, e))
        return false;
    uint8_t got[GDS_AUDIT_HASH], want[GDS_AUDIT_HASH];
    size_t gl = 0;
    gds_buf body = {(uint8_t *)(uintptr_t)f.p[2], (size_t)(f.p[6] + f.n[6] - f.p[2])};
    if(!unhex(f.p[7], f.n[7], got, sizeof(got), &gl) || gl != GDS_AUDIT_HASH ||
       gds_audit_hash(hash, e->seq, e->time, &body, want) != GDS_OK ||
       memcmp(got, want, GDS_AUDIT_HASH) != 0)
        return false;
    memcpy(hash, want, GDS_AUDIT_HASH);
    return true;
}

/* Reads fp from the start; *seq and hash end at the last good entry. */
static gds_status scan(FILE *fp, gds_journal_cb cb, void *ctx, int64_t *seq,
                       uint8_t hash[GDS_AUDIT_HASH], int64_t *badSeq) {
    char line[GDS_JOURNAL_MAX_LINE + 2];
    *seq = 0;
    memset(hash, 0, GDS_AUDIT_HASH);
    *badSeq = 0;
    while(fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        gds_journal_entry e;
        if(len == 0 || line[len - 1] != '\n' ||
           !parse_line(line, len - 1, *seq + 1, hash, &e)) {
            *badSeq = *seq + 1;
            return GDS_ESTATE;
        }
        *seq = e.seq;
        if(cb && !cb(ctx, &e))
            return GDS_OK;
    }
    return ferror(fp) ? GDS_EIO : GDS_OK;
}

gds_status gds_journal_read(const char *path, gds_journal_cb cb, void *ctx, int64_t *badSeq) {
    *badSeq = 0;
    FILE *fp = fopen(path, "re");
    if(!fp)
        return errno == ENOENT ? GDS_ENOTFOUND : GDS_EIO;
    int64_t seq = 0;
    uint8_t hash[GDS_AUDIT_HASH];
    gds_status r = scan(fp, cb, ctx, &seq, hash, badSeq);
    (void)fclose(fp);
    return r;
}

/* ---- appending ---- */

gds_status gds_journal_open(const char *path, gds_journal **out) {
    *out = NULL;
    int fd = open(path, O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if(fd < 0)
        return GDS_EIO;
    if(flock(fd, LOCK_EX | LOCK_NB) != 0) {
        (void)close(fd);
        return errno == EWOULDBLOCK ? GDS_EEXISTS : GDS_EIO;
    }
    gds_journal *j = calloc(1, sizeof(*j));
    int rd = j ? dup(fd) : -1;
    FILE *fp = rd >= 0 ? fdopen(rd, "r") : NULL;
    gds_status r = j ? (fp ? GDS_OK : GDS_EIO) : GDS_ENOMEM;
    if(rd >= 0 && !fp)
        (void)close(rd);
    if(r == GDS_OK && fseek(fp, 0, SEEK_SET) != 0)
        r = GDS_EIO;
    int64_t bad = 0;
    if(r == GDS_OK)
        r = scan(fp, NULL, NULL, &j->seq, j->hash, &bad);
    if(fp)
        (void)fclose(fp);
    if(r != GDS_OK) {
        if(r == GDS_ESTATE)
            fprintf(stderr, "opengds-signer: journal %s is broken at entry %lld\n", path,
                    (long long)bad);
        free(j);
        (void)close(fd);
        return r;
    }
    j->fd = fd;
    *out = j;
    return GDS_OK;
}

void gds_journal_close(gds_journal *j) {
    if(!j)
        return;
    (void)close(j->fd); /* releases the flock */
    free(j);
}

static gds_status write_all(int fd, const char *p, size_t n) {
    while(n > 0) {
        ssize_t w = write(fd, p, n);
        if(w < 0 && errno == EINTR)
            continue;
        if(w <= 0)
            return GDS_EIO;
        p += w;
        n -= (size_t)w;
    }
    return fsync(fd) == 0 ? GDS_OK : GDS_EIO;
}

static gds_status append(gds_journal *j, const char *body) {
    if(j->broken)
        return GDS_ESTATE;
    int64_t seq = j->seq + 1, now = UA_DateTime_now();
    uint8_t h[GDS_AUDIT_HASH];
    char hh[2 * GDS_AUDIT_HASH + 1], line[GDS_JOURNAL_MAX_LINE + 2];
    gds_buf b = {(uint8_t *)(uintptr_t)body, strlen(body)};
    gds_status r = gds_audit_hash(j->hash, seq, now, &b, h);
    if(r == GDS_OK)
        r = gds_hex(h, sizeof(h), hh, sizeof(hh));
    if(r != GDS_OK)
        return r;
    int n = snprintf(line, sizeof(line), "%lld %lld %s %s\n", (long long)seq, (long long)now,
                     body, hh);
    if(n < 0 || (size_t)n > GDS_JOURNAL_MAX_LINE + 1)
        return GDS_ETOOBIG;
    r = write_all(j->fd, line, (size_t)n);
    if(r != GDS_OK) {
        j->broken = true;
        return r;
    }
    j->seq = seq;
    memcpy(j->hash, h, sizeof(h));
    return GDS_OK;
}

gds_status gds_journal_issued(gds_journal *j, const UA_Guid *requestId,
                              const gds_ca_issued *cert) {
    char gid[GUID_TEXT + 1], serial[2 * GDS_JOURNAL_MAX_SERIAL + 1];
    char dh[2 * GDS_AUDIT_HASH + 1], body[GDS_JOURNAL_MAX_LINE];
    uint8_t d[GDS_AUDIT_HASH];
    if(!j || !cert || cert->serial.len == 0 || cert->serial.len > GDS_JOURNAL_MAX_SERIAL ||
       !guid_text(requestId, gid))
        return GDS_EINVAL;
    gds_status r = der_sha256(&cert->der, d);
    if(r == GDS_OK)
        r = gds_hex(cert->serial.data, cert->serial.len, serial, sizeof(serial));
    if(r == GDS_OK)
        r = gds_hex(d, sizeof(d), dh, sizeof(dh));
    if(r != GDS_OK)
        return r;
    int n = snprintf(body, sizeof(body), "ISSUED %s %s %s 0", gid, serial, dh);
    if(n < 0 || (size_t)n >= sizeof(body))
        return GDS_ETOOBIG;
    return append(j, body);
}

gds_status gds_journal_refused(gds_journal *j, const UA_Guid *requestId, gds_status why) {
    char gid[GUID_TEXT + 1], body[GDS_JOURNAL_MAX_LINE];
    if(!j || why == GDS_OK || !guid_text(requestId, gid))
        return GDS_EINVAL;
    int n = snprintf(body, sizeof(body), "REFUSED %s - - %d", gid, (int)why);
    if(n < 0 || (size_t)n >= sizeof(body))
        return GDS_ETOOBIG;
    return append(j, body);
}
