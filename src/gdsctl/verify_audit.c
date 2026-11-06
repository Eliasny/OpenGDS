/* OpenGDS - gdsctl verify-audit (UASM ask A8, issue #19).
 * SPDX-License-Identifier: MPL-2.0 */
#include "verify_audit.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

#include "common/banned.h"

#define MAX_ENTRIES ((size_t)1 << 26) /* 64 M issuances */

typedef struct {
    uint8_t serial[GDS_JOURNAL_MAX_SERIAL];
    size_t serialLen;
    uint8_t derSha256[GDS_AUDIT_HASH];
    UA_Guid requestId;
    size_t journal;
    int64_t seq;
    bool matched;
} entry;

typedef struct {
    entry *e;
    size_t n, cap;
    size_t journal; /* while reading */
    gds_status err;
    gds_va_report report;
    void *ctx;
    gds_va_summary *sum;
} state;

static void found(state *st, const gds_va_finding *f) {
    st->sum->findings++;
    st->report(st->ctx, f);
}

static int cmp_serial(const uint8_t *a, size_t an, const uint8_t *b, size_t bn) {
    if(an != bn)
        return an < bn ? -1 : 1;
    return memcmp(a, b, an);
}

static int cmp_entry(const void *a, const void *b) {
    const entry *x = a, *y = b;
    int c = cmp_serial(x->serial, x->serialLen, y->serial, y->serialLen);
    if(c != 0)
        return c;
    if(x->journal != y->journal)
        return x->journal < y->journal ? -1 : 1;
    return x->seq < y->seq ? -1 : (x->seq > y->seq);
}

static bool keep(void *ctx, const gds_journal_entry *je) {
    state *st = ctx;
    if(!je->issued)
        return true;
    if(st->n == st->cap) {
        size_t cap = st->cap ? st->cap * 2 : 256;
        entry *grown = cap <= MAX_ENTRIES ? realloc(st->e, cap * sizeof(*grown)) : NULL;
        if(!grown) {
            st->err = cap <= MAX_ENTRIES ? GDS_ENOMEM : GDS_ETOOBIG;
            return false;
        }
        st->e = grown;
        st->cap = cap;
    }
    entry *e = &st->e[st->n++];
    memset(e, 0, sizeof(*e));
    memcpy(e->serial, je->serial, je->serialLen);
    e->serialLen = je->serialLen;
    memcpy(e->derSha256, je->derSha256, GDS_AUDIT_HASH);
    e->requestId = je->requestId;
    e->journal = st->journal;
    e->seq = je->seq;
    st->sum->issued++;
    return true;
}

static gds_status read_journals(state *st, const char *const *journals, size_t n) {
    for(size_t i = 0; i < n; i++) {
        st->journal = i;
        int64_t bad = 0;
        gds_status r = gds_journal_read(journals[i], keep, st, &bad);
        if(st->err != GDS_OK)
            return st->err;
        if(r == GDS_ESTATE) {
            gds_va_finding f;
            memset(&f, 0, sizeof(f));
            f.kind = GDS_VA_JOURNAL_BROKEN;
            f.journal = i;
            f.seq = bad;
            found(st, &f);
        } else if(r != GDS_OK) {
            return r;
        }
    }
    return GDS_OK;
}

/* First entry with this serial, or n. */
static size_t lower_bound(const state *st, const gds_buf *serial) {
    size_t lo = 0, hi = st->n;
    while(lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if(cmp_serial(st->e[mid].serial, st->e[mid].serialLen, serial->data, serial->len) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

static gds_va_finding about(gds_va_kind kind, const entry *e) {
    gds_va_finding f;
    memset(&f, 0, sizeof(f));
    f.kind = kind;
    f.journal = e->journal;
    f.seq = e->seq;
    f.serial = e->serial;
    f.serialLen = e->serialLen;
    f.requestId = e->requestId;
    return f;
}

static bool check_cert(void *ctx, const gds_cert_row *row) {
    state *st = ctx;
    st->sum->certificates++;
    uint8_t d[GDS_AUDIT_HASH];
    unsigned int dl = 0;
    if(EVP_Digest(row->der.data, row->der.len, d, &dl, EVP_sha256(), NULL) != 1 ||
       dl != GDS_AUDIT_HASH) {
        st->err = GDS_ECRYPTO;
        return false;
    }
    size_t first = lower_bound(st, &row->serial), last = first;
    while(last < st->n && cmp_serial(st->e[last].serial, st->e[last].serialLen,
                                     row->serial.data, row->serial.len) == 0)
        last++;
    if(first == last) {
        gds_va_finding f;
        memset(&f, 0, sizeof(f));
        f.kind = GDS_VA_NOT_JOURNALLED;
        f.serial = row->serial.data;
        f.serialLen = row->serial.len;
        f.appId = row->appId;
        found(st, &f);
        return true;
    }
    for(size_t i = first; i < last; i++) {
        entry *e = &st->e[i];
        e->matched = true;
        gds_va_finding f = about(GDS_VA_SEVERAL_ENTRIES, e);
        f.appId = row->appId;
        if(last - first > 1)
            found(st, &f);
        if(memcmp(e->derSha256, d, sizeof(d)) != 0) {
            f.kind = GDS_VA_DIGEST_MISMATCH;
            found(st, &f);
        }
    }
    return true;
}

static void check_store_audit(state *st, gds_store *store) {
    int64_t rows = 0, bad = 0;
    gds_status r = gds_store_audit_verify(store, &rows, &bad);
    st->sum->auditRows = r == GDS_EUNSUPPORTED ? -1 : rows;
    if(r == GDS_OK || r == GDS_EUNSUPPORTED)
        return;
    gds_va_finding f;
    memset(&f, 0, sizeof(f));
    f.kind = GDS_VA_STORE_AUDIT_BROKEN;
    f.seq = bad;
    found(st, &f);
}

gds_status gds_verify_audit(gds_store *store, const char *const *journals, size_t nJournals,
                            gds_va_report report, void *ctx, gds_va_summary *sum) {
    memset(sum, 0, sizeof(*sum));
    if(!store || !report || (nJournals && !journals))
        return GDS_EINVAL;
    state st;
    memset(&st, 0, sizeof(st));
    st.report = report;
    st.ctx = ctx;
    st.sum = sum;
    st.err = GDS_OK;
    check_store_audit(&st, store);
    gds_status r = read_journals(&st, journals, nJournals);
    if(r == GDS_OK && st.n > 1)
        qsort(st.e, st.n, sizeof(*st.e), cmp_entry);
    if(r == GDS_OK)
        r = gds_store_cert_scan(store, check_cert, &st);
    if(r == GDS_OK)
        r = st.err;
    for(size_t i = 0; r == GDS_OK && i < st.n; i++) {
        if(st.e[i].matched)
            continue;
        gds_va_finding f = about(GDS_VA_SIGNED_NOT_COMMITTED, &st.e[i]);
        found(&st, &f);
    }
    free(st.e);
    return r;
}
