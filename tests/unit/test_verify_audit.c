/* OpenGDS unit test: gdsctl verify-audit, one store against two signer
 * journals (UASM ask A8, issue #19). Two nodes each journal what their
 * signer issued; the shared store holds what was committed. One signature
 * never reached the store and must be reported as "signed, not committed".
 * SPDX-License-Identifier: MPL-2.0 */
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"
#include "common/buf.h"
#include "common/ids.h"
#include "journal.h"
#include "store.h"
#include "verify_audit.h"
#include "common/banned.h"

extern char **environ;

typedef struct {
    int count[GDS_VA_SIGNED_NOT_COMMITTED + 1];
    gds_va_finding last[GDS_VA_SIGNED_NOT_COMMITTED + 1];
} seen;

static void collect(void *ctx, const gds_va_finding *f) {
    seen *s = ctx;
    s->count[f->kind]++;
    s->last[f->kind] = *f;
    s->last[f->kind].serial = NULL; /* only valid during the call */
}

/* A fake certificate: the serial byte and a body; the store and the
 * journal treat the DER as opaque bytes. */
typedef struct {
    uint8_t serial[1];
    uint8_t der[16];
    gds_ca_issued issued;
} fake;

static void make(fake *f, uint8_t serial, char variant) {
    f->serial[0] = serial;
    memset(f->der, variant, sizeof(f->der));
    f->der[0] = serial;
    f->issued.serial = (gds_buf){f->serial, sizeof(f->serial)};
    f->issued.der = (gds_buf){f->der, sizeof(f->der)};
    f->issued.notBefore = 1;
    f->issued.notAfter = 2;
}

static void issue(gds_journal *j, uint8_t serial) {
    fake f;
    make(&f, serial, 'a');
    UA_Guid req;
    CHECK(gds_guid_random(&req) == GDS_OK);
    CHECK(gds_journal_issued(j, &req, &f.issued) == GDS_OK);
}

static void commit(gds_store *st, const UA_Guid *app, uint8_t serial, char variant) {
    fake f;
    make(&f, serial, variant);
    CHECK(gds_store_cert_add(st, app, 615, 12557, &f.issued.serial, &f.issued.der, 1, 2) ==
          GDS_OK);
}

static void seed_app(gds_store *st, UA_Guid *app) {
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "Audited");
    rec.applicationUri = UA_STRING("urn:opengds:test:audited");
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

static int run_gdsctl(const char *gdsctl, const char *db, const char *j1, const char *j2) {
    char *argv[] = {(char *)(uintptr_t)gdsctl, (char *)(uintptr_t)"verify-audit",
                    (char *)(uintptr_t)"--store", (char *)(uintptr_t)db,
                    (char *)(uintptr_t)"--journal", (char *)(uintptr_t)j1,
                    (char *)(uintptr_t)"--journal", (char *)(uintptr_t)j2, NULL};
    pid_t pid = 0;
    int status = 0;
    if(posix_spawn(&pid, gdsctl, NULL, NULL, argv, environ) != 0 ||
       waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static void verify(gds_store *st, const char *const *js, seen *s, gds_va_summary *sum) {
    memset(s, 0, sizeof(*s));
    CHECK(gds_verify_audit(st, js, 2, collect, s, sum) == GDS_OK);
}

/* Flip one hex digit of the hash in line `n` (1-based) of a journal. */
static void tamper(const char *path, int n) {
    gds_buf b = {0};
    if(!CHECK(gds_file_read(path, 1 << 20, &b) == GDS_OK))
        return;
    int line = 1;
    for(size_t i = 0; i < b.len; i++) {
        if(line == n && b.data[i] == '\n') {
            b.data[i - 1] = b.data[i - 1] == '0' ? '1' : '0';
            break;
        }
        line += b.data[i] == '\n';
    }
    CHECK(gds_file_write_atomic(path, b.data, b.len, 0600) == GDS_OK);
    gds_buf_free(&b);
}

int main(int argc, char **argv) {
    if(argc < 3) {
        fprintf(stderr, "usage: %s <dir> <gdsctl>\n", argv[0]);
        return 2;
    }
    char db[1024], j1[1024], j2[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(j1, sizeof(j1), "%s/node1.journal", argv[1]) == GDS_OK);
    CHECK(gds_path(j2, sizeof(j2), "%s/node2.journal", argv[1]) == GDS_OK);
    (void)unlink(db);
    (void)unlink(j1);
    (void)unlink(j2);
    const char *const js[] = {j1, j2};

    gds_store *st = NULL;
    gds_journal *n1 = NULL, *n2 = NULL;
    if(!CHECK(gds_store_open(db, &st) == GDS_OK) || !CHECK(gds_journal_open(j1, &n1) == GDS_OK) ||
       !CHECK(gds_journal_open(j2, &n2) == GDS_OK))
        return CHECK_DONE();
    UA_Guid app;
    seed_app(st, &app);

    /* node 1 was primary for serials 1-3, then node 2 for 4-5. Serial 3
     * was signed, but the store write was lost in the failover. */
    for(uint8_t i = 1; i <= 3; i++)
        issue(n1, i);
    for(uint8_t i = 4; i <= 5; i++)
        issue(n2, i);
    commit(st, &app, 1, 'a');
    commit(st, &app, 2, 'a');
    commit(st, &app, 4, 'a');
    commit(st, &app, 5, 'a');

    seen s;
    gds_va_summary sum;
    verify(st, js, &s, &sum);
    CHECK_EQ_INT(sum.certificates, 4);
    CHECK_EQ_INT(sum.auditRows, 1);
    CHECK_EQ_INT(sum.issued, 5);
    CHECK_EQ_INT(sum.findings, 1);
    CHECK_EQ_INT(s.count[GDS_VA_SIGNED_NOT_COMMITTED], 1);
    CHECK(s.last[GDS_VA_SIGNED_NOT_COMMITTED].journal == 0 &&
          s.last[GDS_VA_SIGNED_NOT_COMMITTED].seq == 3);
    CHECK_EQ_INT(run_gdsctl(argv[2], db, j1, j2), 1);

    /* committed after all: clean */
    commit(st, &app, 3, 'a');
    verify(st, js, &s, &sum);
    CHECK_EQ_INT(sum.findings, 0);
    CHECK_EQ_INT(run_gdsctl(argv[2], db, j1, j2), 0);

    /* a certificate no signer journalled, one in both journals, and one
     * whose stored DER is not what the signer issued */
    commit(st, &app, 6, 'a');
    issue(n2, 1);
    issue(n1, 7);
    commit(st, &app, 7, 'b');
    verify(st, js, &s, &sum);
    CHECK_EQ_INT(s.count[GDS_VA_NOT_JOURNALLED], 1);
    CHECK(UA_Guid_equal(&s.last[GDS_VA_NOT_JOURNALLED].appId, &app));
    CHECK_EQ_INT(s.count[GDS_VA_SEVERAL_ENTRIES], 2);
    CHECK_EQ_INT(s.count[GDS_VA_DIGEST_MISMATCH], 1);
    CHECK_EQ_INT(s.count[GDS_VA_SIGNED_NOT_COMMITTED], 0);
    CHECK_EQ_INT(sum.findings, 4);

    /* a changed journal line breaks its chain */
    gds_journal_close(n2);
    n2 = NULL;
    tamper(j2, 2);
    verify(st, js, &s, &sum);
    CHECK_EQ_INT(s.count[GDS_VA_JOURNAL_BROKEN], 1);
    CHECK(s.last[GDS_VA_JOURNAL_BROKEN].journal == 1 && s.last[GDS_VA_JOURNAL_BROKEN].seq == 2);
    CHECK(gds_journal_open(j2, &n2) == GDS_ESTATE); /* a signer will not extend it */
    CHECK_EQ_INT(run_gdsctl(argv[2], db, j1, j2), 1);

    gds_journal_close(n1);
    gds_journal_close(n2);
    gds_store_close(st);
    return CHECK_DONE();
}
