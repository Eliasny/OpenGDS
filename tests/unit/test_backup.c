/* OpenGDS unit test: gdsctl backup and restore. One encrypted archive holds
 * a snapshot of the store and the CA directory, including the signer's
 * issuance journal. Restore puts them in place only after the archive
 * decrypts and authenticates, and only when the store's audit chain and
 * the journals verify.
 * SPDX-License-Identifier: MPL-2.0 */
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "backup.h"
#include "check.h"
#include "common/buf.h"
#include "common/ids.h"
#include "journal.h"
#include "store.h"
#include "common/banned.h"

extern char **environ;

#define COST 10 /* scrypt cost for the test; gdsctl defaults to 17 */

static const uint8_t keyPem[] = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nnot a real key\n";
static const uint8_t caDer[] = {0x30, 0x82, 0x01, 0x02, 0xca};
static uint8_t passBytes[] = "correct horse battery staple";
static uint8_t wrongBytes[] = "correct horse battery stapler";
static const gds_buf pass = {passBytes, sizeof(passBytes) - 1};
static const gds_buf wrong = {wrongBytes, sizeof(wrongBytes) - 1};

/* ---- a store and a journal, as in test_verify_audit.c ---- */

typedef struct {
    uint8_t serial[1];
    uint8_t der[16];
    gds_ca_issued issued;
} fake;

static void make(fake *f, uint8_t serial) {
    f->serial[0] = serial;
    memset(f->der, 'a', sizeof(f->der));
    f->der[0] = serial;
    f->issued.serial = (gds_buf){f->serial, sizeof(f->serial)};
    f->issued.der = (gds_buf){f->der, sizeof(f->der)};
    f->issued.notBefore = 1;
    f->issued.notAfter = 2;
}

static void issue(gds_journal *j, uint8_t serial) {
    fake f;
    make(&f, serial);
    UA_Guid req;
    CHECK(gds_guid_random(&req) == GDS_OK);
    CHECK(gds_journal_issued(j, &req, &f.issued) == GDS_OK);
}

static void commit(gds_store *st, const UA_Guid *app, uint8_t serial) {
    fake f;
    make(&f, serial);
    CHECK(gds_store_cert_add(st, app, 615, 12557, &f.issued.serial, &f.issued.der, 1, 2) ==
          GDS_OK);
}

static void seed_app(gds_store *st, UA_Guid *app) {
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "Backed up");
    rec.applicationUri = UA_STRING("urn:opengds:test:backup");
    rec.applicationType = UA_APPLICATIONTYPE_CLIENT;
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    CHECK(gds_guid_random(app) == GDS_OK);
    CHECK(gds_store_app_insert(st, app, &rec) == GDS_OK);
    uint8_t body[] = "register";
    gds_buf b = {body, sizeof(body) - 1};
    int64_t seq = 0;
    CHECK(gds_store_audit_append(st, 1, &b, &seq) == GDS_OK);
}

/* ---- helpers ---- */

typedef struct {
    char dir[512], db[600], ca[600], journal[700], other[600];
} paths;

static bool same_file(const char *a, const char *b, size_t *len) {
    gds_buf x = {0}, y = {0};
    bool eq = gds_file_read(a, 1 << 20, &x) == GDS_OK && gds_file_read(b, 1 << 20, &y) == GDS_OK &&
              x.len == y.len && memcmp(x.data, y.data, x.len) == 0;
    if(len)
        *len = x.len;
    gds_buf_free(&x);
    gds_buf_free(&y);
    return eq;
}

static bool exists(const char *p) {
    struct stat sb;
    return lstat(p, &sb) == 0;
}

static void clean(const char *db, const char *ca) {
    char p[1024];
    static const char *const files[] = {"ca.der", "ca.key.pem", GDS_JOURNAL_FILE};
    for(size_t i = 0; i < 3; i++)
        if(gds_path(p, sizeof(p), "%s/%s", ca, files[i]) == GDS_OK)
            (void)unlink(p);
    (void)rmdir(ca);
    (void)unlink(db);
}

/* Nothing of a failed restore is left behind. */
static void nothing_left(const char *db, const char *ca) {
    char p[1024];
    CHECK(!exists(db));
    CHECK(!exists(ca));
    CHECK(gds_path(p, sizeof(p), "%s.restoring", db) == GDS_OK && !exists(p));
    CHECK(gds_path(p, sizeof(p), "%s.restoring-plain", db) == GDS_OK && !exists(p));
    CHECK(gds_path(p, sizeof(p), "%s.restoring", ca) == GDS_OK && !exists(p));
}

static int run(char *const argv[]) {
    pid_t pid = 0;
    int status = 0;
    if(posix_spawn(&pid, argv[0], NULL, NULL, argv, environ) != 0 ||
       waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

#define ARG(s) ((char *)(uintptr_t)(s))

/* ---- cases ---- */

static void setup(const paths *p, gds_store **st, UA_Guid *app) {
    CHECK(gds_mkdirs(p->ca, 0700) == GDS_OK);
    char path[1024];
    CHECK(gds_path(path, sizeof(path), "%s/ca.key.pem", p->ca) == GDS_OK);
    CHECK(gds_file_write_atomic(path, keyPem, sizeof(keyPem) - 1, 0600) == GDS_OK);
    CHECK(gds_path(path, sizeof(path), "%s/ca.der", p->ca) == GDS_OK);
    CHECK(gds_file_write_atomic(path, caDer, sizeof(caDer), 0644) == GDS_OK);
    gds_journal *j = NULL;
    if(!CHECK(gds_store_open(p->db, st) == GDS_OK) ||
       !CHECK(gds_journal_open(p->journal, &j) == GDS_OK))
        return;
    seed_app(*st, app);
    /* serial 3 was signed, but the store never got it */
    for(uint8_t i = 1; i <= 3; i++)
        issue(j, i);
    commit(*st, app, 1);
    commit(*st, app, 2);
    gds_journal_close(j);
    /* a journal line the signer was still writing */
    FILE *f = fopen(p->journal, "ab");
    if(CHECK(f)) {
        CHECK(fputs("4 1 ISSUED 0", f) >= 0);
        CHECK(fclose(f) == 0);
    }
}

static void test_round_trip(const paths *p, const char *archive, const char *dest) {
    char db[1024], ca[1024];
    CHECK(gds_path(db, sizeof(db), "%s/restored.db", dest) == GDS_OK);
    CHECK(gds_path(ca, sizeof(ca), "%s/restored-ca", dest) == GDS_OK);
    gds_restore_summary sum;

    CHECK(gds_backup_restore(archive, &wrong, db, ca, NULL, 0, NULL, NULL, &sum) == GDS_ECRYPTO);
    nothing_left(db, ca);

    if(!CHECK(gds_backup_restore(archive, &pass, db, ca, NULL, 0, NULL, NULL, &sum) == GDS_OK))
        return;
    CHECK_EQ_INT(sum.entries, 4); /* the store and three CA files */
    CHECK_EQ_INT(sum.va.certificates, 2);
    CHECK_EQ_INT(sum.va.auditRows, 1);
    CHECK_EQ_INT(sum.va.issued, 3);
    CHECK_EQ_INT(sum.va.findings, 1); /* serial 3: signed, not committed */
    CHECK_EQ_INT(sum.blocking, 0);
    char a[1024], b[1024];
    static const char *const files[] = {"ca.der", "ca.key.pem"};
    for(size_t i = 0; i < 2; i++) {
        CHECK(gds_path(a, sizeof(a), "%s/%s", p->ca, files[i]) == GDS_OK);
        CHECK(gds_path(b, sizeof(b), "%s/%s", ca, files[i]) == GDS_OK);
        CHECK(same_file(a, b, NULL));
    }
    /* the journal up to its last complete line */
    CHECK(gds_path(b, sizeof(b), "%s/%s", ca, GDS_JOURNAL_FILE) == GDS_OK);
    size_t full = 0, cut = 0;
    CHECK(!same_file(p->journal, b, &full));
    (void)same_file(b, b, &cut);
    CHECK_EQ_INT(full, cut + strlen("4 1 ISSUED 0"));
    gds_journal *j = NULL;
    CHECK(gds_journal_open(b, &j) == GDS_OK); /* a signer can go on with it */
    gds_journal_close(j);
    struct stat sb;
    CHECK(stat(ca, &sb) == 0 && (sb.st_mode & 0777) == 0700);
    CHECK(stat(db, &sb) == 0 && (sb.st_mode & 0077) == 0);
    gds_store *st = NULL;
    int64_t rows = 0, bad = 0;
    if(CHECK(gds_store_open(db, &st) == GDS_OK)) /* the daemon opens it read-write */
        CHECK(gds_store_audit_verify(st, &rows, &bad) == GDS_OK && rows == 1 && bad == 0);
    gds_store_close(st);

    /* never over existing files */
    CHECK(gds_backup_restore(archive, &pass, db, ca, NULL, 0, NULL, NULL, &sum) == GDS_EEXISTS);
    clean(db, ca);
}

/* A changed byte anywhere: nothing is restored. */
static void test_tampered(const char *archive, const char *dest) {
    char copy[1024], db[1024], ca[1024];
    CHECK(gds_path(copy, sizeof(copy), "%s/tampered.ogdsbak", dest) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/t.db", dest) == GDS_OK);
    CHECK(gds_path(ca, sizeof(ca), "%s/t-ca", dest) == GDS_OK);
    gds_buf b = {0};
    if(!CHECK(gds_file_read(archive, 1 << 24, &b) == GDS_OK) || !CHECK(b.len > 200))
        return;
    size_t at[] = {9, 40, b.len / 2, b.len - 1};
    for(size_t i = 0; i < 4; i++) {
        b.data[at[i]] ^= 0x01;
        CHECK(gds_file_write_atomic(copy, b.data, b.len, 0600) == GDS_OK);
        gds_restore_summary sum;
        gds_status r = gds_backup_restore(copy, &pass, db, ca, NULL, 0, NULL, NULL, &sum);
        CHECK(r == GDS_ECRYPTO || r == GDS_EINVAL);
        nothing_left(db, ca);
        b.data[at[i]] ^= 0x01;
    }
    gds_buf_free(&b);
    (void)unlink(copy);
}

typedef struct {
    int notJournalled;
    size_t journal;
} seen;

static void collect(void *ctx, const gds_va_finding *f) {
    seen *s = ctx;
    if(f->kind == GDS_VA_NOT_JOURNALLED)
        s->notJournalled++;
    s->journal = f->journal;
}

/* A certificate no journal in the archive knows blocks the restore,
 * unless the other node's journal has it. */
static void test_blocking(const paths *p, gds_store *st, const UA_Guid *app, const char *dest) {
    commit(st, app, 6); /* issued by the other node */
    gds_journal *j = NULL;
    if(CHECK(gds_journal_open(p->other, &j) == GDS_OK))
        issue(j, 6);
    gds_journal_close(j);
    char archive[1024], db[1024], ca[1024];
    CHECK(gds_path(archive, sizeof(archive), "%s/second.ogdsbak", dest) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/b.db", dest) == GDS_OK);
    CHECK(gds_path(ca, sizeof(ca), "%s/b-ca", dest) == GDS_OK);
    if(!CHECK(gds_backup_create(p->db, p->ca, archive, &pass, COST) == GDS_OK))
        return;
    seen s = {0, 0};
    gds_restore_summary sum;
    CHECK(gds_backup_restore(archive, &pass, db, ca, NULL, 0, collect, &s, &sum) == GDS_ESTATE);
    CHECK_EQ_INT(s.notJournalled, 1);
    CHECK_EQ_INT(sum.blocking, 1);
    nothing_left(db, ca);
    const char *others[] = {p->other};
    s.notJournalled = 0;
    CHECK(gds_backup_restore(archive, &pass, db, ca, others, 1, collect, &s, &sum) == GDS_OK);
    CHECK_EQ_INT(s.notJournalled, 0);
    CHECK_EQ_INT(s.journal, 1); /* "signed, not committed" names the restored journal */
    CHECK_EQ_INT(sum.va.issued, 4);
    clean(db, ca);
    (void)unlink(archive);
}

static void test_gdsctl(const paths *p, const char *gdsctl, const char *dest) {
    char archive[1024], pf[1024], wf[1024], db[1024], ca[1024];
    CHECK(gds_path(archive, sizeof(archive), "%s/cli.ogdsbak", dest) == GDS_OK);
    CHECK(gds_path(pf, sizeof(pf), "%s/pass", dest) == GDS_OK);
    CHECK(gds_path(wf, sizeof(wf), "%s/wrong", dest) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/cli.db", dest) == GDS_OK);
    CHECK(gds_path(ca, sizeof(ca), "%s/cli-ca", dest) == GDS_OK);
    CHECK(gds_file_write_atomic(pf, "correct horse battery staple\n", 29, 0600) == GDS_OK);
    CHECK(gds_file_write_atomic(wf, "nope\n", 5, 0600) == GDS_OK);
    char *backup[] = {ARG(gdsctl), ARG("backup"), ARG("--store"), ARG(p->db), ARG("--ca-dir"),
                      ARG(p->ca), ARG("--out"), ARG(archive), ARG("--passphrase-file"), ARG(pf),
                      ARG("--kdf-cost"), ARG("10"), NULL};
    CHECK_EQ_INT(run(backup), 0);
    struct stat sb;
    CHECK(stat(archive, &sb) == 0 && (sb.st_mode & 0777) == 0600);
    CHECK_EQ_INT(run(backup), 2); /* never over an existing archive */
    char *bad[] = {ARG(gdsctl), ARG("restore"), ARG("--archive"), ARG(archive),
                   ARG("--passphrase-file"), ARG(wf), ARG("--store"), ARG(db), ARG("--ca-dir"),
                   ARG(ca), NULL};
    CHECK_EQ_INT(run(bad), 2);
    char *blocked[] = {ARG(gdsctl), ARG("restore"), ARG("--archive"), ARG(archive),
                       ARG("--passphrase-file"), ARG(pf), ARG("--store"), ARG(db),
                       ARG("--ca-dir"), ARG(ca), NULL};
    CHECK_EQ_INT(run(blocked), 1); /* serial 6 is in no restored journal */
    char *good[] = {ARG(gdsctl), ARG("restore"), ARG("--archive"), ARG(archive),
                    ARG("--passphrase-file"), ARG(pf), ARG("--store"), ARG(db), ARG("--ca-dir"),
                    ARG(ca), ARG("--journal"), ARG(p->other), NULL};
    CHECK_EQ_INT(run(good), 0);
    CHECK(exists(db) && exists(ca));
    clean(db, ca);
    (void)unlink(archive);
    (void)unlink(pf);
    (void)unlink(wf);
}

int main(int argc, char **argv) {
    if(argc < 3) {
        fprintf(stderr, "usage: %s <dir> <gdsctl>\n", argv[0]);
        return 2;
    }
    paths p;
    char dest[1024], archive[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(p.dir, sizeof(p.dir), "%s", argv[1]) == GDS_OK);
    CHECK(gds_path(p.db, sizeof(p.db), "%s/store.db", p.dir) == GDS_OK);
    CHECK(gds_path(p.ca, sizeof(p.ca), "%s/ca", p.dir) == GDS_OK);
    CHECK(gds_path(p.journal, sizeof(p.journal), "%s/%s", p.ca, GDS_JOURNAL_FILE) == GDS_OK);
    CHECK(gds_path(p.other, sizeof(p.other), "%s/node2.journal", p.dir) == GDS_OK);
    CHECK(gds_path(dest, sizeof(dest), "%s/dest", p.dir) == GDS_OK);
    CHECK(gds_path(archive, sizeof(archive), "%s/first.ogdsbak", dest) == GDS_OK);
    clean(p.db, p.ca);
    (void)unlink(p.other);
    (void)unlink(archive);
    CHECK(gds_mkdirs(dest, 0700) == GDS_OK);

    gds_store *st = NULL;
    UA_Guid app;
    setup(&p, &st, &app);
    if(st && CHECK(gds_backup_create(p.db, p.ca, archive, &pass, COST) == GDS_OK)) {
        CHECK(gds_backup_create(p.db, p.ca, archive, &pass, COST) == GDS_EEXISTS);
        test_round_trip(&p, archive, dest);
        test_tampered(archive, dest);
        test_blocking(&p, st, &app, dest);
        test_gdsctl(&p, argv[2], dest);
    }
    gds_store_close(st);
    (void)unlink(archive);
    return CHECK_DONE();
}
