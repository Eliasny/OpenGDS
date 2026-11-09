/* OpenGDS - gdsctl, the offline host tool (docs/architecture.md).
 *
 *   gdsctl verify-audit --store <store.db> --journal <file> [--journal <file> ...]
 *   gdsctl backup --store <store.db> --ca-dir <dir> --out <archive>
 *                 --passphrase-file <file> [--kdf-cost <10..20>]
 *   gdsctl restore --archive <archive> --passphrase-file <file>
 *                  --store <store.db> --ca-dir <dir> [--journal <file> ...]
 *   gdsctl push-targets add|remove|list --store <store.db> ... (push_targets.c)
 *
 * verify-audit exit status: 0 everything verifies, 1 findings (listed on
 * stdout), 2 usage or a store or journal that cannot be read. backup: 0
 * written, 2 error. restore: 0 restored, 1 findings (nothing restored), 2
 * error. The passphrase file holds the backup passphrase (one line); it is
 * not the CA key passphrase, which stays inside the archive's CA key.
 * SPDX-License-Identifier: MPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backup.h"
#include "common/safeint.h"
#include "push_targets.h"
#include "verify_audit.h"
#include "common/banned.h"

#define MAX_JOURNALS 64
#define MAX_PASSPHRASE 1024

typedef enum { CMD_VERIFY, CMD_BACKUP, CMD_RESTORE } command;

typedef struct {
    command cmd;
    const char *store, *caDir, *out, *archive, *passFile;
    long kdfCost;
    const char *journals[MAX_JOURNALS];
    size_t nJournals;
} options;

static int usage(void) {
    fprintf(stderr,
            "usage: gdsctl verify-audit --store <store.db> --journal <file> [--journal <file> ...]\n"
            "       gdsctl backup --store <store.db> --ca-dir <dir> --out <archive>\n"
            "                     --passphrase-file <file> [--kdf-cost <10..20>]\n"
            "       gdsctl restore --archive <archive> --passphrase-file <file>\n"
            "                      --store <store.db> --ca-dir <dir> [--journal <file> ...]\n"
            "       gdsctl push-targets add|remove|list --store <store.db> ...\n");
    return 2;
}

static bool set_once(const char **dst, const char *v) {
    if(*dst)
        return false;
    *dst = v;
    return true;
}

static bool option(options *o, const char *k, const char *v) {
    if(strcmp(k, "--store") == 0)
        return set_once(&o->store, v);
    if(strcmp(k, "--ca-dir") == 0 && o->cmd != CMD_VERIFY)
        return set_once(&o->caDir, v);
    if(strcmp(k, "--out") == 0 && o->cmd == CMD_BACKUP)
        return set_once(&o->out, v);
    if(strcmp(k, "--archive") == 0 && o->cmd == CMD_RESTORE)
        return set_once(&o->archive, v);
    if(strcmp(k, "--passphrase-file") == 0 && o->cmd != CMD_VERIFY)
        return set_once(&o->passFile, v);
    if(strcmp(k, "--kdf-cost") == 0 && o->cmd == CMD_BACKUP && !o->kdfCost)
        return gds_parse_long(v, GDS_BACKUP_MIN_LOG2N, GDS_BACKUP_MAX_LOG2N, &o->kdfCost);
    if(strcmp(k, "--journal") == 0 && o->cmd != CMD_BACKUP && o->nJournals < MAX_JOURNALS) {
        o->journals[o->nJournals++] = v;
        return true;
    }
    return false;
}

static bool parse(int argc, char **argv, options *o) {
    memset(o, 0, sizeof(*o));
    if(argc < 2)
        return false;
    if(strcmp(argv[1], "verify-audit") == 0)
        o->cmd = CMD_VERIFY;
    else if(strcmp(argv[1], "backup") == 0)
        o->cmd = CMD_BACKUP;
    else if(strcmp(argv[1], "restore") == 0)
        o->cmd = CMD_RESTORE;
    else
        return false;
    for(int i = 2; i < argc; i += 2)
        if(i + 1 >= argc || !option(o, argv[i], argv[i + 1]))
            return false;
    switch(o->cmd) {
    case CMD_VERIFY: return o->store && o->nJournals > 0;
    case CMD_BACKUP: return o->store && o->caDir && o->out && o->passFile;
    case CMD_RESTORE: return o->store && o->caDir && o->archive && o->passFile;
    }
    return false;
}

static gds_status read_passphrase(const char *file, gds_buf *out) {
    gds_status r = gds_file_read(file, MAX_PASSPHRASE, out);
    while(r == GDS_OK && out->len > 0 &&
          (out->data[out->len - 1] == '\n' || out->data[out->len - 1] == '\r'))
        out->len--;
    if(r == GDS_OK && out->len == 0) {
        gds_buf_free_secret(out);
        r = GDS_EINVAL;
    }
    return r;
}

static void print_hex(const uint8_t *p, size_t n) {
    for(size_t i = 0; i < n; i++)
        printf("%02X", p[i]);
}

static void print_guid(const char *label, const UA_Guid *g) {
    UA_String s = UA_STRING_NULL;
    if(UA_Guid_print(g, &s) == UA_STATUSCODE_GOOD)
        printf(" %s=%.*s", label, (int)s.length, (const char *)s.data);
    UA_String_clear(&s);
}

static void report(void *ctx, const gds_va_finding *f) {
    const options *o = ctx;
    static const char *const names[] = {
        "", "store audit log broken", "journal broken", "certificate in no journal",
        "certificate in several journal entries", "certificate differs from journal",
        "signed, not committed"};
    printf("%s:", f->kind <= GDS_VA_SIGNED_NOT_COMMITTED ? names[f->kind] : "?");
    if(f->kind != GDS_VA_STORE_AUDIT_BROKEN && f->kind != GDS_VA_NOT_JOURNALLED)
        printf(" journal=%s",
               f->journal < o->nJournals ? o->journals[f->journal] : "(restored)");
    if(f->kind != GDS_VA_NOT_JOURNALLED)
        printf(" seq=%lld", (long long)f->seq);
    if(f->serialLen) {
        printf(" serial=");
        print_hex(f->serial, f->serialLen);
    }
    if(f->kind == GDS_VA_NOT_JOURNALLED)
        print_guid("application", &f->appId);
    if(f->kind == GDS_VA_SIGNED_NOT_COMMITTED)
        print_guid("request", &f->requestId);
    printf("\n");
}

static int backup(const options *o) {
    gds_buf pass = {0};
    gds_status r = read_passphrase(o->passFile, &pass);
    if(r != GDS_OK) {
        fprintf(stderr, "gdsctl: passphrase file %s: %s\n", o->passFile, gds_status_name(r));
        return 2;
    }
    r = gds_backup_create(o->store, o->caDir, o->out, &pass,
                          o->kdfCost ? (unsigned)o->kdfCost : GDS_BACKUP_LOG2N);
    gds_buf_free_secret(&pass);
    if(r != GDS_OK) {
        fprintf(stderr, "gdsctl: backup: %s\n", gds_status_name(r));
        return 2;
    }
    printf("backup written to %s\n", o->out);
    return 0;
}

static int restore(const options *o) {
    gds_buf pass = {0};
    gds_status r = read_passphrase(o->passFile, &pass);
    if(r != GDS_OK) {
        fprintf(stderr, "gdsctl: passphrase file %s: %s\n", o->passFile, gds_status_name(r));
        return 2;
    }
    gds_restore_summary sum;
    r = gds_backup_restore(o->archive, &pass, o->store, o->caDir, o->journals, o->nJournals,
                           report, (void *)(uintptr_t)o, &sum);
    gds_buf_free_secret(&pass);
    if(r == GDS_ESTATE) {
        printf("findings: %lld blocking; nothing restored\n", (long long)sum.blocking);
        return 1;
    }
    if(r != GDS_OK) {
        fprintf(stderr, "gdsctl: restore: %s%s\n", gds_status_name(r),
                r == GDS_ECRYPTO ? " (wrong passphrase or damaged archive)" : "");
        return 2;
    }
    printf("restored %lld files: %lld certificates, %lld audit rows, %lld issued entries, "
           "%lld signed but not committed\n",
           (long long)sum.entries, (long long)sum.va.certificates, (long long)sum.va.auditRows,
           (long long)sum.va.issued, (long long)sum.va.findings);
    return 0;
}

int main(int argc, char **argv) {
    if(argc >= 2 && strcmp(argv[1], "push-targets") == 0)
        return gdsctl_push_targets(argc, argv);
    options o;
    if(!parse(argc, argv, &o))
        return usage();
    if(o.cmd == CMD_BACKUP)
        return backup(&o);
    if(o.cmd == CMD_RESTORE)
        return restore(&o);
    gds_store *st = NULL;
    gds_status r = gds_store_open_readonly(o.store, &st);
    if(r != GDS_OK) {
        fprintf(stderr, "gdsctl: store %s: %s\n", o.store, gds_status_name(r));
        return 2;
    }
    gds_va_summary sum;
    r = gds_verify_audit(st, o.journals, o.nJournals, report, &o, &sum);
    gds_store_close(st);
    if(r != GDS_OK) {
        fprintf(stderr, "gdsctl: verify-audit: %s\n", gds_status_name(r));
        return 2;
    }
    printf("store: %lld certificates, ", (long long)sum.certificates);
    if(sum.auditRows < 0)
        printf("no audit log\n");
    else
        printf("%lld audit rows\n", (long long)sum.auditRows);
    printf("journals: %zu, %lld issued entries\n", o.nJournals, (long long)sum.issued);
    printf("findings: %lld\n", (long long)sum.findings);
    return sum.findings ? 1 : 0;
}
