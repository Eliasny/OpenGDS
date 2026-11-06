/* OpenGDS - gdsctl backup and restore (backup.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "backup.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/limits.h"
#include "journal.h"
#include "common/banned.h"

#define MAGIC_LEN 8
#define KDF_SCRYPT 1
#define SCRYPT_R 8
#define SCRYPT_P 1
#define SALT_LEN 16
#define NONCE_LEN 12
#define TAG_LEN 16
#define KEY_LEN 32
#define HEADER_LEN (MAGIC_LEN + 4 + SALT_LEN + NONCE_LEN)
#define CHUNK 65536
#define MAX_NAME 255
#define MAX_SCRYPT_MEM ((uint64_t)1 << 31)
#define T_END 0
#define T_STORE 1
#define T_CA 2
#define STORE_NAME "store.db"
#define LINE_TAIL 4096

/* ---- small file helpers ---- */

static bool write_all(int fd, const void *p, size_t n) {
    const uint8_t *b = p;
    while(n > 0) {
        ssize_t w = write(fd, b, n);
        if(w < 0 && errno == EINTR)
            continue;
        if(w <= 0)
            return false;
        b += w;
        n -= (size_t)w;
    }
    return true;
}

static bool read_all(int fd, void *p, size_t n) {
    uint8_t *b = p;
    while(n > 0) {
        ssize_t r = read(fd, b, n);
        if(r < 0 && errno == EINTR)
            continue;
        if(r <= 0)
            return false;
        b += r;
        n -= (size_t)r;
    }
    return true;
}

static bool exists(const char *path) {
    struct stat sb;
    return lstat(path, &sb) == 0;
}

/* fsync the directory that holds path */
static void sync_parent(const char *path) {
    char dir[GDS_MAX_PATH];
    const char *slash = strrchr(path, '/');
    if(!slash) {
        dir[0] = '.';
        dir[1] = '\0';
    } else if((size_t)(slash - path) < sizeof(dir)) {
        memcpy(dir, path, (size_t)(slash - path));
        dir[slash - path] = '\0';
        if(dir[0] == '\0') {
            dir[0] = '/';
            dir[1] = '\0';
        }
    } else {
        return;
    }
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if(fd >= 0) {
        (void)fsync(fd);
        (void)close(fd);
    }
}

static void put_be(uint8_t *p, uint64_t v, size_t n) {
    for(size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
}

static uint64_t get_be(const uint8_t *p, size_t n) {
    uint64_t v = 0;
    for(size_t i = 0; i < n; i++)
        v = v << 8 | p[i];
    return v;
}

static gds_status derive(const gds_buf *pass, const uint8_t *salt, unsigned log2N, unsigned r,
                         unsigned p, uint8_t key[KEY_LEN]) {
    if(!pass || !pass->data || pass->len == 0)
        return GDS_EINVAL;
    return EVP_PBE_scrypt((const char *)pass->data, pass->len, salt, SALT_LEN,
                          (uint64_t)1 << log2N, r, p, MAX_SCRYPT_MEM, key, KEY_LEN) == 1
               ? GDS_OK
               : GDS_ECRYPTO;
}

/* ---- backup ---- */

typedef struct {
    int fd;
    EVP_CIPHER_CTX *ctx;
    uint8_t out[CHUNK + 32];
} sealer;

static bool seal(sealer *s, const void *p, size_t n) {
    const uint8_t *b = p;
    while(n > 0) {
        size_t k = n < CHUNK ? n : CHUNK;
        int outLen = 0;
        if(EVP_EncryptUpdate(s->ctx, s->out, &outLen, b, (int)k) != 1 ||
           !write_all(s->fd, s->out, (size_t)outLen))
            return false;
        b += k;
        n -= k;
    }
    return true;
}

static gds_status seal_entry_head(sealer *s, uint8_t type, const char *name, uint64_t size) {
    size_t nameLen = strlen(name);
    if(nameLen == 0 || nameLen > MAX_NAME)
        return GDS_EINVAL;
    uint8_t h[3];
    h[0] = type;
    put_be(h + 1, nameLen, 2);
    uint8_t sz[8];
    put_be(sz, size, 8);
    return seal(s, h, sizeof(h)) && seal(s, name, nameLen) && seal(s, sz, sizeof(sz)) ? GDS_OK
                                                                                        : GDS_EIO;
}

/* A journal is copied up to its last complete line: *size shrinks to it. */
static gds_status whole_lines(int fd, uint64_t *size) {
    if(*size == 0)
        return GDS_OK;
    uint8_t tail[LINE_TAIL];
    size_t k = *size < LINE_TAIL ? (size_t)*size : LINE_TAIL;
    if(pread(fd, tail, k, (off_t)(*size - k)) != (ssize_t)k)
        return GDS_EIO;
    size_t i = k;
    while(i > 0 && tail[i - 1] != '\n')
        i--;
    if(i == 0 && k < *size)
        return GDS_EINVAL; /* no line end in the last 4 KiB */
    *size -= k - i;
    return GDS_OK;
}

static gds_status seal_stream(sealer *s, int fd, uint64_t size) {
    uint8_t *buf = malloc(CHUNK);
    gds_status r = buf ? GDS_OK : GDS_ENOMEM;
    for(uint64_t left = size; r == GDS_OK && left > 0;) {
        size_t k = left < CHUNK ? (size_t)left : CHUNK;
        if(!read_all(fd, buf, k) || !seal(s, buf, k))
            r = GDS_EIO;
        left -= k;
    }
    free(buf);
    return r;
}

static gds_status seal_file(sealer *s, uint8_t type, const char *name, const char *path,
                            bool wholeLines) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0)
        return GDS_EIO;
    struct stat sb;
    gds_status r = fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode) ? GDS_OK : GDS_EINVAL;
    uint64_t size = r == GDS_OK ? (uint64_t)sb.st_size : 0;
    if(r == GDS_OK && wholeLines)
        r = whole_lines(fd, &size);
    if(r == GDS_OK)
        r = seal_entry_head(s, type, name, size);
    if(r == GDS_OK)
        r = seal_stream(s, fd, size);
    (void)close(fd);
    return r;
}

/* An online copy of the store in one file (rollback journal, not WAL). */
static gds_status snapshot(const char *storePath, const char *out) {
    sqlite3 *src = NULL, *dst = NULL;
    int rc = sqlite3_open_v2(storePath, &src, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW, NULL);
    if(rc == SQLITE_OK)
        rc = sqlite3_open_v2(out, &dst, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if(rc == SQLITE_OK)
        (void)chmod(out, 0600);
    sqlite3_backup *b = rc == SQLITE_OK ? sqlite3_backup_init(dst, "main", src, "main") : NULL;
    if(b) {
        rc = sqlite3_backup_step(b, -1);
        int fin = sqlite3_backup_finish(b);
        rc = rc == SQLITE_DONE ? fin : rc;
    } else if(rc == SQLITE_OK) {
        rc = SQLITE_ERROR;
    }
    if(rc == SQLITE_OK)
        rc = sqlite3_exec(dst, "PRAGMA journal_mode=DELETE;", NULL, NULL, NULL);
    if(rc != SQLITE_OK)
        fprintf(stderr, "gdsctl: store snapshot: %s\n",
                dst ? sqlite3_errmsg(dst) : sqlite3_errstr(rc));
    sqlite3_close(dst);
    sqlite3_close(src);
    return rc == SQLITE_OK ? GDS_OK : GDS_EIO;
}

static int name_cmp(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

typedef struct {
    char *names[GDS_BACKUP_MAX_FILES];
    size_t n;
} name_list;

static void names_free(name_list *l) {
    for(size_t i = 0; i < l->n; i++)
        free(l->names[i]);
    l->n = 0;
}

/* The CA directory's entries, sorted; only regular files are allowed. */
static gds_status list_ca(const char *caDir, name_list *l) {
    memset(l, 0, sizeof(*l));
    DIR *d = opendir(caDir);
    if(!d)
        return GDS_ENOTFOUND;
    gds_status r = GDS_OK;
    struct dirent *e;
    while(r == GDS_OK && (e = readdir(d)) != NULL) {
        if(strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char path[GDS_MAX_PATH];
        struct stat sb;
        r = gds_path(path, sizeof(path), "%s/%s", caDir, e->d_name);
        if(r == GDS_OK && (lstat(path, &sb) != 0 || !S_ISREG(sb.st_mode))) {
            fprintf(stderr, "gdsctl: %s is not a regular file\n", path);
            r = GDS_EINVAL;
        }
        if(r == GDS_OK && (l->n == GDS_BACKUP_MAX_FILES || strlen(e->d_name) > MAX_NAME))
            r = GDS_ETOOBIG;
        if(r == GDS_OK && !(l->names[l->n++] = strdup(e->d_name)))
            r = GDS_ENOMEM;
    }
    (void)closedir(d);
    if(r == GDS_OK)
        qsort((void *)l->names, l->n, sizeof(l->names[0]), name_cmp);
    else
        names_free(l);
    return r;
}

static gds_status seal_body(sealer *s, const char *snap, const char *caDir) {
    gds_status r = seal_file(s, T_STORE, STORE_NAME, snap, false);
    name_list l;
    if(r == GDS_OK)
        r = list_ca(caDir, &l);
    if(r != GDS_OK)
        return r;
    for(size_t i = 0; i < l.n && r == GDS_OK; i++) {
        char path[GDS_MAX_PATH];
        r = gds_path(path, sizeof(path), "%s/%s", caDir, l.names[i]);
        if(r == GDS_OK)
            r = seal_file(s, T_CA, l.names[i], path, strcmp(l.names[i], GDS_JOURNAL_FILE) == 0);
    }
    names_free(&l);
    uint8_t end = T_END;
    return r == GDS_OK && !seal(s, &end, 1) ? GDS_EIO : r;
}

static const uint8_t magic[MAGIC_LEN] = {'O', 'G', 'D', 'S', 'B', 'A', 'K', '1'};

/* AES-256-GCM with the header as additional data. */
static gds_status cipher_init(EVP_CIPHER_CTX *ctx, bool enc, const uint8_t *key,
                              const uint8_t *header) {
    const uint8_t *nonce = header + MAGIC_LEN + 4 + SALT_LEN;
    int outLen = 0;
    if(EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, enc) != 1 ||
       EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
       EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce, enc) != 1 ||
       EVP_CipherUpdate(ctx, NULL, &outLen, header, HEADER_LEN) != 1)
        return GDS_ECRYPTO;
    return GDS_OK;
}

/* Header, entries and tag into the new file `partial`. */
static gds_status write_archive(const char *partial, const uint8_t *header, const uint8_t *key,
                                const char *snap, const char *caDir) {
    sealer s;
    s.fd = -1;
    s.ctx = EVP_CIPHER_CTX_new();
    gds_status r = s.ctx ? cipher_init(s.ctx, true, key, header) : GDS_ENOMEM;
    if(r == GDS_OK) {
        s.fd = open(partial, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        r = s.fd >= 0 && write_all(s.fd, header, HEADER_LEN) ? GDS_OK : GDS_EIO;
    }
    if(r == GDS_OK)
        r = seal_body(&s, snap, caDir);
    uint8_t tag[TAG_LEN];
    int outLen = 0;
    if(r == GDS_OK && (EVP_EncryptFinal_ex(s.ctx, s.out, &outLen) != 1 || outLen != 0 ||
                       EVP_CIPHER_CTX_ctrl(s.ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1))
        r = GDS_ECRYPTO;
    if(r == GDS_OK && (!write_all(s.fd, tag, TAG_LEN) || fsync(s.fd) != 0))
        r = GDS_EIO;
    if(s.fd >= 0 && close(s.fd) != 0 && r == GDS_OK)
        r = GDS_EIO;
    EVP_CIPHER_CTX_free(s.ctx);
    return r;
}

gds_status gds_backup_create(const char *storePath, const char *caDir, const char *archive,
                             const gds_buf *passphrase, unsigned log2N) {
    if(!storePath || !caDir || !archive || log2N < GDS_BACKUP_MIN_LOG2N ||
       log2N > GDS_BACKUP_MAX_LOG2N)
        return GDS_EINVAL;
    if(exists(archive))
        return GDS_EEXISTS;
    char partial[GDS_MAX_PATH], snap[GDS_MAX_PATH];
    gds_status r = gds_path(partial, sizeof(partial), "%s.partial", archive);
    if(r == GDS_OK)
        r = gds_path(snap, sizeof(snap), "%s.store", archive);
    if(r != GDS_OK)
        return r;
    if(exists(partial) || exists(snap))
        return GDS_EEXISTS;
    r = snapshot(storePath, snap);

    uint8_t header[HEADER_LEN], key[KEY_LEN];
    memcpy(header, magic, MAGIC_LEN);
    header[MAGIC_LEN] = KDF_SCRYPT;
    header[MAGIC_LEN + 1] = (uint8_t)log2N;
    header[MAGIC_LEN + 2] = SCRYPT_R;
    header[MAGIC_LEN + 3] = SCRYPT_P;
    uint8_t *salt = header + MAGIC_LEN + 4;
    if(r == GDS_OK && RAND_bytes(salt, SALT_LEN + NONCE_LEN) != 1)
        r = GDS_ECRYPTO;
    if(r == GDS_OK)
        r = derive(passphrase, salt, log2N, SCRYPT_R, SCRYPT_P, key);
    if(r == GDS_OK)
        r = write_archive(partial, header, key, snap, caDir);
    OPENSSL_cleanse(key, sizeof(key));
    if(r == GDS_OK && rename(partial, archive) != 0)
        r = GDS_EIO;
    if(r == GDS_OK)
        sync_parent(archive);
    else
        (void)unlink(partial);
    (void)unlink(snap);
    return r;
}

/* ---- restore ---- */

/* Reads and checks the header; *body is the ciphertext length. */
static gds_status read_header(int in, uint8_t *header, uint8_t *tag, uint64_t *body) {
    struct stat sb;
    if(fstat(in, &sb) != 0 || sb.st_size < HEADER_LEN + TAG_LEN || !read_all(in, header, HEADER_LEN))
        return GDS_EINVAL;
    unsigned log2N = header[MAGIC_LEN + 1], sr = header[MAGIC_LEN + 2], sp = header[MAGIC_LEN + 3];
    if(memcmp(header, magic, MAGIC_LEN) != 0 || header[MAGIC_LEN] != KDF_SCRYPT ||
       log2N < GDS_BACKUP_MIN_LOG2N || log2N > GDS_BACKUP_MAX_LOG2N || sr == 0 || sr > 32 ||
       sp == 0 || sp > 4)
        return GDS_EINVAL;
    *body = (uint64_t)sb.st_size - HEADER_LEN - TAG_LEN;
    return pread(in, tag, TAG_LEN, (off_t)(HEADER_LEN + *body)) == TAG_LEN ? GDS_OK : GDS_EIO;
}

static gds_status decrypt_body(EVP_CIPHER_CTX *ctx, int in, int out, uint64_t body,
                               uint8_t *tag) {
    uint8_t *buf = malloc(2 * CHUNK + 32);
    gds_status r = buf ? GDS_OK : GDS_ENOMEM;
    int outLen = 0;
    for(uint64_t left = body; r == GDS_OK && left > 0;) {
        size_t k = left < CHUNK ? (size_t)left : CHUNK;
        if(!read_all(in, buf, k) || EVP_DecryptUpdate(ctx, buf + CHUNK, &outLen, buf, (int)k) != 1 ||
           !write_all(out, buf + CHUNK, (size_t)outLen))
            r = GDS_EIO;
        left -= k;
    }
    if(r == GDS_OK && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1 ||
                       EVP_DecryptFinal_ex(ctx, buf, &outLen) != 1))
        r = GDS_ECRYPTO; /* wrong passphrase, or the archive was changed */
    free(buf);
    return r;
}

/* Decrypts the archive into the file plain (0600) and checks the tag. */
static gds_status open_archive(const char *archive, const gds_buf *pass, const char *plain) {
    int in = open(archive, O_RDONLY | O_CLOEXEC);
    if(in < 0)
        return GDS_ENOTFOUND;
    uint8_t header[HEADER_LEN] = {0}, tag[TAG_LEN], key[KEY_LEN];
    uint64_t body = 0;
    gds_status r = read_header(in, header, tag, &body);
    if(r == GDS_OK)
        r = derive(pass, header + MAGIC_LEN + 4, header[MAGIC_LEN + 1], header[MAGIC_LEN + 2],
                   header[MAGIC_LEN + 3], key);
    EVP_CIPHER_CTX *ctx = r == GDS_OK ? EVP_CIPHER_CTX_new() : NULL;
    if(r == GDS_OK)
        r = ctx ? cipher_init(ctx, false, key, header) : GDS_ENOMEM;
    OPENSSL_cleanse(key, sizeof(key));
    int out = -1;
    if(r == GDS_OK) {
        out = open(plain, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        r = out >= 0 ? GDS_OK : GDS_EIO;
    }
    if(r == GDS_OK)
        r = decrypt_body(ctx, in, out, body, tag);
    EVP_CIPHER_CTX_free(ctx);
    if(out >= 0 && close(out) != 0 && r == GDS_OK)
        r = GDS_EIO;
    (void)close(in);
    return r;
}

static bool name_ok(const char *n, size_t len) {
    if(len == 0 || len > MAX_NAME || (len <= 2 && n[0] == '.' && (len == 1 || n[1] == '.')))
        return false;
    for(size_t i = 0; i < len; i++)
        if(n[i] == '/' || n[i] == '\0')
            return false;
    return true;
}

static gds_status copy_out(FILE *f, uint64_t size, const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if(fd < 0)
        return GDS_EIO;
    uint8_t *buf = malloc(CHUNK);
    gds_status r = buf ? GDS_OK : GDS_ENOMEM;
    for(uint64_t left = size; r == GDS_OK && left > 0;) {
        size_t k = left < CHUNK ? (size_t)left : CHUNK;
        if(fread(buf, 1, k, f) != k || !write_all(fd, buf, k))
            r = GDS_EINVAL;
        left -= k;
    }
    free(buf);
    if(r == GDS_OK && fsync(fd) != 0)
        r = GDS_EIO;
    (void)close(fd);
    return r;
}

/* One entry head; *type is T_END at the end marker. */
static gds_status read_entry_head(FILE *f, uint8_t *type, char name[MAX_NAME + 1],
                                  uint64_t *size) {
    uint8_t h[2], sz[8];
    if(fread(type, 1, 1, f) != 1)
        return GDS_EINVAL;
    if(*type == T_END)
        return GDS_OK;
    if(fread(h, 1, 2, f) != 2)
        return GDS_EINVAL;
    size_t len = (size_t)get_be(h, 2);
    if(len > MAX_NAME || fread(name, 1, len, f) != len || fread(sz, 1, 8, f) != 8 ||
       !name_ok(name, len))
        return GDS_EINVAL;
    name[len] = '\0';
    *size = get_be(sz, 8);
    return GDS_OK;
}

/* Splits the plaintext into the staged store file and CA directory. */
static gds_status unpack(const char *plain, const char *stStore, const char *stCa, bool *journal,
                         int64_t *entries) {
    FILE *f = fopen(plain, "rb");
    if(!f)
        return GDS_EIO;
    gds_status r = mkdir(stCa, 0700) == 0 ? GDS_OK : GDS_EIO;
    bool haveStore = false;
    uint8_t type = T_STORE;
    while(r == GDS_OK) {
        char name[MAX_NAME + 1], path[GDS_MAX_PATH];
        uint64_t size = 0;
        r = read_entry_head(f, &type, name, &size);
        if(r != GDS_OK || type == T_END)
            break;
        if(type == T_STORE && !haveStore && strcmp(name, STORE_NAME) == 0) {
            haveStore = true;
            r = gds_path(path, sizeof(path), "%s", stStore);
        } else if(type == T_CA) {
            *journal = *journal || strcmp(name, GDS_JOURNAL_FILE) == 0;
            r = gds_path(path, sizeof(path), "%s/%s", stCa, name);
        } else {
            r = GDS_EINVAL;
        }
        if(r == GDS_OK)
            r = exists(path) ? GDS_EINVAL : copy_out(f, size, path);
        if(r == GDS_OK)
            (*entries)++;
    }
    uint8_t extra;
    if(r == GDS_OK && (!haveStore || fread(&extra, 1, 1, f) != 0))
        r = GDS_EINVAL;
    (void)fclose(f);
    return r;
}

static void remove_tree(const char *dir) {
    DIR *d = opendir(dir);
    if(d) {
        struct dirent *e;
        while((e = readdir(d)) != NULL) {
            char path[GDS_MAX_PATH];
            if(strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0 &&
               gds_path(path, sizeof(path), "%s/%s", dir, e->d_name) == GDS_OK)
                (void)unlink(path);
        }
        (void)closedir(d);
    }
    (void)rmdir(dir);
}

typedef struct {
    gds_va_report report;
    void *ctx;
    int64_t blocking;
} va_filter;

static void count(void *ctx, const gds_va_finding *f) {
    va_filter *v = ctx;
    if(f->kind != GDS_VA_SIGNED_NOT_COMMITTED)
        v->blocking++;
    if(v->report)
        v->report(v->ctx, f);
}

static gds_status check(const char *stStore, const char *stCa, bool journal,
                        const char *const *journals, size_t nJournals, gds_va_report report,
                        void *ctx, gds_restore_summary *sum) {
    const char *all[GDS_BACKUP_MAX_FILES + 1];
    char restored[GDS_MAX_PATH];
    if(nJournals > GDS_BACKUP_MAX_FILES)
        return GDS_ETOOBIG;
    for(size_t i = 0; i < nJournals; i++)
        all[i] = journals[i];
    size_t n = nJournals;
    if(journal) {
        gds_status r = gds_path(restored, sizeof(restored), "%s/%s", stCa, GDS_JOURNAL_FILE);
        if(r != GDS_OK)
            return r;
        all[n++] = restored;
    }
    gds_store *st = NULL;
    gds_status r = gds_store_open_readonly(stStore, &st);
    if(r != GDS_OK)
        return r;
    va_filter v = {report, ctx, 0};
    r = gds_verify_audit(st, all, n, count, &v, &sum->va);
    gds_store_close(st);
    sum->blocking = v.blocking;
    return r;
}

gds_status gds_backup_restore(const char *archive, const gds_buf *passphrase,
                              const char *storePath, const char *caDir,
                              const char *const *journals, size_t nJournals,
                              gds_va_report report, void *ctx, gds_restore_summary *sum) {
    memset(sum, 0, sizeof(*sum));
    if(!archive || !storePath || !caDir || (nJournals && !journals))
        return GDS_EINVAL;
    if(exists(storePath) || exists(caDir))
        return GDS_EEXISTS;
    char plain[GDS_MAX_PATH], stStore[GDS_MAX_PATH], stCa[GDS_MAX_PATH];
    gds_status r = gds_path(plain, sizeof(plain), "%s.restoring-plain", storePath);
    if(r == GDS_OK)
        r = gds_path(stStore, sizeof(stStore), "%s.restoring", storePath);
    if(r == GDS_OK)
        r = gds_path(stCa, sizeof(stCa), "%s.restoring", caDir);
    if(r != GDS_OK)
        return r;
    if(exists(plain) || exists(stStore) || exists(stCa))
        return GDS_EEXISTS;
    r = open_archive(archive, passphrase, plain);
    bool journal = false;
    if(r == GDS_OK)
        r = unpack(plain, stStore, stCa, &journal, &sum->entries);
    (void)unlink(plain);
    if(r == GDS_OK)
        r = check(stStore, stCa, journal, journals, nJournals, report, ctx, sum);
    if(r == GDS_OK && sum->blocking > 0)
        r = GDS_ESTATE;
    if(r == GDS_OK && rename(stStore, storePath) != 0)
        r = GDS_EIO;
    if(r == GDS_OK && rename(stCa, caDir) != 0) {
        (void)rename(storePath, stStore); /* all or nothing */
        r = GDS_EIO;
    }
    if(r == GDS_OK) {
        sync_parent(storePath);
        sync_parent(caDir);
        return GDS_OK;
    }
    (void)unlink(stStore);
    remove_tree(stCa);
    return r;
}
