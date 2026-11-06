/* OpenGDS - gdsctl, the offline host tool (docs/architecture.md).
 *
 *   gdsctl verify-audit --store <store.db> --journal <file> [--journal <file> ...]
 *
 * Exit status: 0 everything verifies, 1 findings (listed on stdout),
 * 2 usage or a store or journal that cannot be read.
 * SPDX-License-Identifier: MPL-2.0 */
#include <stdio.h>
#include <string.h>

#include "verify_audit.h"
#include "common/banned.h"

#define MAX_JOURNALS 64

typedef struct {
    const char *store;
    const char *journals[MAX_JOURNALS];
    size_t nJournals;
} options;

static int usage(void) {
    fprintf(stderr, "usage: gdsctl verify-audit --store <store.db> --journal <file> "
                    "[--journal <file> ...]\n");
    return 2;
}

static bool parse(int argc, char **argv, options *o) {
    memset(o, 0, sizeof(*o));
    if(argc < 2 || strcmp(argv[1], "verify-audit") != 0)
        return false;
    for(int i = 2; i < argc; i += 2) {
        if(i + 1 >= argc)
            return false;
        if(strcmp(argv[i], "--store") == 0 && !o->store) {
            o->store = argv[i + 1];
        } else if(strcmp(argv[i], "--journal") == 0 && o->nJournals < MAX_JOURNALS) {
            o->journals[o->nJournals++] = argv[i + 1];
        } else {
            return false;
        }
    }
    return o->store && o->nJournals > 0;
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
        printf(" journal=%s", o->journals[f->journal]);
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

int main(int argc, char **argv) {
    options o;
    if(!parse(argc, argv, &o))
        return usage();
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
