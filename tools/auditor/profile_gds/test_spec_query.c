/* OpenGDS spec tests: Directory queries (OPC 10000-12 §6.5.10 QueryApplications,
 * §6.5.11 QueryServers, Annex D ServerCapabilities).
 * Every test registers its own records under a URI prefix unique to the run
 * and the test, and filters on that prefix, so records of other tests and of
 * other clients never change the result.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids_gds.h>

#include <stdio.h>
#include <string.h>

#include "common/limits.h"
#include "gds_target.h"
#include "spec_tests.h"
#include "common/banned.h"

#define URI_LEN (GDS_MAX_APPLICATION_URI + 1)
#define QMAX    16 /* records a test registers at most */

typedef struct {
    UA_DateTime reset;
    UA_UInt32 next;
    UA_ApplicationDescription *apps;
    size_t n;
} qres;

static void qres_clear(qres *q) {
    if(q->apps)
        UA_Array_delete(q->apps, q->n, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
    memset(q, 0, sizeof(*q));
}

/* QueryApplications(startingRecordId, maxRecordsToReturn, applicationName,
 * applicationUri, applicationType, productUri, capabilities) */
static UA_StatusCode query_apps(gds_target *t, UA_UInt32 start, UA_UInt32 max, const char *name,
                                const char *uri, UA_UInt32 typeMask, const char *product,
                                const char *const *caps, size_t nCaps, qres *q) {
    memset(q, 0, sizeof(*q));
    UA_String sName = name ? UA_STRING((char *)(uintptr_t)name) : UA_STRING_NULL;
    UA_String sUri = uri ? UA_STRING((char *)(uintptr_t)uri) : UA_STRING_NULL;
    UA_String sProd = product ? UA_STRING((char *)(uintptr_t)product) : UA_STRING_NULL;
    UA_String capV[4];
    for(size_t i = 0; i < nCaps && i < GDS_ARRAY_SIZE(capV); i++)
        capV[i] = UA_STRING((char *)(uintptr_t)caps[i]);
    UA_Variant in[7];
    UA_Variant_setScalar(&in[0], &start, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[1], &max, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[2], &sName, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[3], &sUri, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[4], &typeMask, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[5], &sProd, &UA_TYPES[UA_TYPES_STRING]);
    if(nCaps)
        UA_Variant_setArray(&in[6], capV, nCaps, &UA_TYPES[UA_TYPES_STRING]);
    else
        UA_Variant_setArray(&in[6], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_STRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_QUERYAPPLICATIONS, 7, in, 3, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_DateTime *reset = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_DATETIME]);
    const UA_UInt32 *next = uac_out_scalar(out, outN, 1, &UA_TYPES[UA_TYPES_UINT32]);
    const void *apps = NULL;
    size_t n = 0;
    r = gds_arg_array(&out[2], &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION], GDS_MAX_QUERY_RECORDS,
                      &apps, &n);
    if(r == UA_STATUSCODE_GOOD && (!reset || !next))
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    if(r == UA_STATUSCODE_GOOD) {
        q->reset = *reset;
        q->next = *next;
        if(n > 0)
            r = UA_Array_copy(apps, n, (void **)&q->apps, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
        if(r == UA_STATUSCODE_GOOD)
            q->n = n;
    }
    gt_free_out(out, outN);
    return r;
}

static bool has_uri(const qres *q, const char *uri) {
    UA_String u = UA_STRING((char *)(uintptr_t)uri);
    for(size_t i = 0; i < q->n; i++)
        if(UA_String_equal(&q->apps[i].applicationUri, &u))
            return true;
    return false;
}

/* The records of one test: <run prefix>:<seq>:<suffix> */
typedef struct {
    char base[URI_LEN];      /* "urn:opengds:auditor:<run>:<seq>" */
    char pattern[URI_LEN];   /* base + ":%" (LIKE syntax, OPC 10000-4) */
    char uri[QMAX][URI_LEN];
    UA_NodeId id[QMAX];
    size_t n;
} qset;

static bool qset_init(ga_ctx *ctx, gds_target *t, qset *s) {
    memset(s, 0, sizeof(*s));
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: session -> %s", UA_StatusCode_name(r));
        return false;
    }
    gt_unique_uri(t, s->base, sizeof(s->base));
    if(gds_path(s->pattern, sizeof(s->pattern), "%s:%%", s->base) != GDS_OK) {
        ga_not_tested(ctx, "setup: URI too long");
        return false;
    }
    return true;
}

static void qset_clear(qset *s) {
    for(size_t i = 0; i < s->n; i++)
        UA_NodeId_clear(&s->id[i]);
}

/* Register base:<suffix> with the given type, product and capabilities. */
static bool qset_add(ga_ctx *ctx, gds_target *t, qset *s, const char *suffix,
                     UA_ApplicationType type, const char *name, const char *product,
                     const char *const *caps, size_t nCaps) {
    if(s->n >= QMAX ||
       gds_path(s->uri[s->n], sizeof(s->uri[s->n]), "%s:%s", s->base, suffix) != GDS_OK) {
        ga_not_tested(ctx, "setup: too many records");
        return false;
    }
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText nameLt;
    UA_String url;
    gt_record(&rec, s->uri[s->n], type, &nameLt, &url);
    if(name)
        nameLt = UA_LOCALIZEDTEXT("en", (char *)(uintptr_t)name);
    if(product)
        rec.productUri = UA_STRING((char *)(uintptr_t)product);
    UA_String capV[4];
    for(size_t i = 0; i < nCaps && i < GDS_ARRAY_SIZE(capV); i++)
        capV[i] = UA_STRING((char *)(uintptr_t)caps[i]);
    if(nCaps) {
        rec.serverCapabilities = capV;
        rec.serverCapabilitiesSize = nCaps;
    }
    UA_StatusCode r = gt_register_record(t, &rec, &s->id[s->n]);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: RegisterApplication(%s) -> %s", suffix, UA_StatusCode_name(r));
        return false;
    }
    s->n++;
    return true;
}

static void t_uri_pattern(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    qset s;
    if(!qset_init(ctx, t, &s))
        return;
    if(qset_add(ctx, t, &s, "a", UA_APPLICATIONTYPE_CLIENT, NULL, NULL, NULL, 0) &&
       qset_add(ctx, t, &s, "b", UA_APPLICATIONTYPE_CLIENT, NULL, NULL, NULL, 0)) {
        qres q;
        UA_StatusCode r = query_apps(t, 0, 0, NULL, s.pattern, 0, NULL, NULL, 0, &q);
        (void)gt_absent(ctx, r, false, "QueryApplications");
        if(r != UA_STATUSCODE_GOOD)
            ga_fail(ctx, "QueryApplications(applicationUri '%s') -> %s", s.pattern,
                    UA_StatusCode_name(r));
        else if(q.n != 2 || !has_uri(&q, s.uri[0]) || !has_uri(&q, s.uri[1]))
            ga_fail(ctx, "LIKE pattern '%s' returned %zu record(s), expected the 2 registered",
                    s.pattern, q.n);
        else
            ga_pass(ctx, "LIKE pattern on ApplicationUri returns exactly the 2 records");
        qres_clear(&q);
    }
    qset_clear(&s);
}

static void t_type_mask(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    qset s;
    if(!qset_init(ctx, t, &s))
        return;
    if(qset_add(ctx, t, &s, "srv", UA_APPLICATIONTYPE_SERVER, NULL, NULL, NULL, 0) &&
       qset_add(ctx, t, &s, "cli", UA_APPLICATIONTYPE_CLIENT, NULL, NULL, NULL, 0)) {
        qres qs, qc, qa;
        UA_StatusCode r1 = query_apps(t, 0, 0, NULL, s.pattern, 0x1, NULL, NULL, 0, &qs);
        UA_StatusCode r2 = query_apps(t, 0, 0, NULL, s.pattern, 0x2, NULL, NULL, 0, &qc);
        UA_StatusCode r3 = query_apps(t, 0, 0, NULL, s.pattern, 0, NULL, NULL, 0, &qa);
        if(r1 != UA_STATUSCODE_GOOD || r2 != UA_STATUSCODE_GOOD || r3 != UA_STATUSCODE_GOOD)
            ga_fail(ctx, "QueryApplications -> %s / %s / %s", UA_StatusCode_name(r1),
                    UA_StatusCode_name(r2), UA_StatusCode_name(r3));
        else if(qs.n != 1 || !has_uri(&qs, s.uri[0]))
            ga_fail(ctx, "mask 0x1 (Servers) returned %zu record(s), expected only the Server",
                    qs.n);
        else if(qc.n != 1 || !has_uri(&qc, s.uri[1]))
            ga_fail(ctx, "mask 0x2 (Clients) returned %zu record(s), expected only the Client",
                    qc.n);
        else if(qa.n != 2)
            ga_fail(ctx, "mask 0 returned %zu record(s), expected both", qa.n);
        else
            ga_pass(ctx, "ApplicationType mask 0x1, 0x2 and 0 select Servers, Clients and all");
        qres_clear(&qs);
        qres_clear(&qc);
        qres_clear(&qa);
    }
    qset_clear(&s);
}

static void t_product_uri(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    qset s;
    if(!qset_init(ctx, t, &s))
        return;
    char prod[URI_LEN];
    if(gds_path(prod, sizeof(prod), "%s:product", s.base) != GDS_OK) {
        ga_not_tested(ctx, "setup: URI too long");
        return;
    }
    if(qset_add(ctx, t, &s, "p", UA_APPLICATIONTYPE_CLIENT, NULL, prod, NULL, 0) &&
       qset_add(ctx, t, &s, "o", UA_APPLICATIONTYPE_CLIENT, NULL, NULL, NULL, 0)) {
        qres q;
        UA_StatusCode r = query_apps(t, 0, 0, NULL, s.pattern, 0, prod, NULL, 0, &q);
        if(r != UA_STATUSCODE_GOOD)
            ga_fail(ctx, "QueryApplications(productUri) -> %s", UA_StatusCode_name(r));
        else if(q.n != 1 || !has_uri(&q, s.uri[0]))
            ga_fail(ctx, "ProductUri filter (ANDed with the URI pattern) returned %zu record(s), "
                         "expected 1", q.n);
        else
            ga_pass(ctx, "ProductUri filter combines with the ApplicationUri filter (AND)");
        qres_clear(&q);
    }
    qset_clear(&s);
}

static void t_name(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    qset s;
    if(!qset_init(ctx, t, &s))
        return;
    char name[URI_LEN], pat[URI_LEN];
    if(gds_path(name, sizeof(name), "Auditor %s name", s.base + strlen("urn:opengds:auditor:")) !=
           GDS_OK ||
       gds_path(pat, sizeof(pat), "Auditor %s n%%", s.base + strlen("urn:opengds:auditor:")) !=
           GDS_OK) {
        ga_not_tested(ctx, "setup: name too long");
        return;
    }
    if(qset_add(ctx, t, &s, "n", UA_APPLICATIONTYPE_CLIENT, name, NULL, NULL, 0)) {
        qres q, qp;
        UA_StatusCode r = query_apps(t, 0, 0, name, NULL, 0, NULL, NULL, 0, &q);
        UA_StatusCode rp = query_apps(t, 0, 0, pat, NULL, 0, NULL, NULL, 0, &qp);
        if(r != UA_STATUSCODE_GOOD || rp != UA_STATUSCODE_GOOD)
            ga_fail(ctx, "QueryApplications(applicationName) -> %s / %s", UA_StatusCode_name(r),
                    UA_StatusCode_name(rp));
        else if(q.n != 1 || !has_uri(&q, s.uri[0]))
            ga_fail(ctx, "ApplicationName '%s' returned %zu record(s), expected 1", name, q.n);
        else if(qp.n != 1 || !has_uri(&qp, s.uri[0]))
            ga_fail(ctx, "ApplicationName LIKE '%s' returned %zu record(s), expected 1", pat, qp.n);
        else
            ga_pass(ctx, "ApplicationName filter matches exactly and with a LIKE pattern");
        qres_clear(&q);
        qres_clear(&qp);
    }
    qset_clear(&s);
}

/* Records come back in increasing record id order; NextRecordId continues
 * the query; LastCounterResetTime does not change between pages. */
static void t_paging(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    qset s;
    if(!qset_init(ctx, t, &s))
        return;
    if(!qset_add(ctx, t, &s, "1", UA_APPLICATIONTYPE_CLIENT, NULL, NULL, NULL, 0) ||
       !qset_add(ctx, t, &s, "2", UA_APPLICATIONTYPE_CLIENT, NULL, NULL, NULL, 0) ||
       !qset_add(ctx, t, &s, "3", UA_APPLICATIONTYPE_CLIENT, NULL, NULL, NULL, 0)) {
        qset_clear(&s);
        return;
    }
    UA_UInt32 start = 0;
    UA_DateTime reset0 = 0;
    size_t got = 0, calls = 0;
    bool order = true, resetStable = true, ended = false;
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    while(calls < 6) {
        qres q;
        r = query_apps(t, start, 1, NULL, s.pattern, 0, NULL, NULL, 0, &q);
        calls++;
        if(r != UA_STATUSCODE_GOOD)
            break;
        if(calls == 1)
            reset0 = q.reset;
        else if(q.reset != reset0)
            resetStable = false;
        if(q.n > 1) {
            ga_fail(ctx, "MaxRecordsToReturn 1 returned %zu records", q.n);
            qres_clear(&q);
            qset_clear(&s);
            return;
        }
        if(q.n == 1) {
            if(got >= 3) {
                order = false;
            } else {
                UA_String want = UA_STRING(s.uri[got]);
                if(!UA_String_equal(&q.apps[0].applicationUri, &want))
                    order = false;
            }
            got++;
        }
        UA_UInt32 next = q.next;
        qres_clear(&q);
        if(next == 0) {
            ended = true;
            break;
        }
        if(next <= start) {
            ga_fail(ctx, "NextRecordId %u does not increase (StartingRecordId %u)", next, start);
            qset_clear(&s);
            return;
        }
        start = next;
    }
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "QueryApplications page %zu -> %s", calls, UA_StatusCode_name(r));
    else if(got != 3)
        ga_fail(ctx, "paging with MaxRecordsToReturn 1 returned %zu of 3 records", got);
    else if(!order)
        ga_fail(ctx, "records not returned in creation (record id) order");
    else if(!ended)
        ga_fail(ctx, "NextRecordId never became 0 after the last record");
    else if(!resetStable)
        ga_warn(ctx, "LastCounterResetTime changed between pages without a reset");
    else
        ga_pass(ctx, "3 pages of 1 record in record id order, then NextRecordId 0");
    qset_clear(&s);
}

static void t_capabilities(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    qset s;
    if(!qset_init(ctx, t, &s))
        return;
    static const char *const da[] = {"DA"}, *const hd[] = {"HD"}, *const both[] = {"DA", "HD"};
    if(qset_add(ctx, t, &s, "da", UA_APPLICATIONTYPE_SERVER, NULL, NULL, da, 1) &&
       qset_add(ctx, t, &s, "hd", UA_APPLICATIONTYPE_SERVER, NULL, NULL, hd, 1) &&
       qset_add(ctx, t, &s, "both", UA_APPLICATIONTYPE_SERVER, NULL, NULL, both, 2)) {
        qres q1, q2;
        UA_StatusCode r1 = query_apps(t, 0, 0, NULL, s.pattern, 0, NULL, da, 1, &q1);
        UA_StatusCode r2 = query_apps(t, 0, 0, NULL, s.pattern, 0, NULL, both, 2, &q2);
        if(r1 != UA_STATUSCODE_GOOD || r2 != UA_STATUSCODE_GOOD)
            ga_fail(ctx, "QueryApplications(capabilities) -> %s / %s", UA_StatusCode_name(r1),
                    UA_StatusCode_name(r2));
        else if(q1.n != 2 || !has_uri(&q1, s.uri[0]) || !has_uri(&q1, s.uri[2]))
            ga_fail(ctx, "[DA] returned %zu record(s), expected the DA and the DA+HD Servers",
                    q1.n);
        else if(q2.n != 1 || !has_uri(&q2, s.uri[2]))
            ga_fail(ctx, "[DA, HD] returned %zu record(s), expected only the Server with both",
                    q2.n);
        else
            ga_pass(ctx, "a record passes only if it supports every listed capability");
        qres_clear(&q1);
        qres_clear(&q2);
    }
    qset_clear(&s);
}

static void t_na_excluded(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    qset s;
    if(!qset_init(ctx, t, &s))
        return;
    static const char *const na[] = {"NA"};
    if(qset_add(ctx, t, &s, "na", UA_APPLICATIONTYPE_SERVER, NULL, NULL, na, 1)) {
        qres q;
        UA_StatusCode r = query_apps(t, 0, 0, NULL, s.uri[0], 0, NULL, NULL, 0, &q);
        if(r != UA_STATUSCODE_GOOD)
            ga_fail(ctx, "QueryApplications -> %s", UA_StatusCode_name(r));
        else if(q.n != 0)
            ga_fail(ctx, "a record with ServerCapabilities NA was returned");
        else
            ga_pass(ctx, "records with ServerCapabilities NA are never returned");
        qres_clear(&q);
    }
    qset_clear(&s);
}

/* QueryServers (deprecated, still Mandatory for the Directory) */
static void t_query_servers(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    qset s;
    if(!qset_init(ctx, t, &s))
        return;
    if(!qset_add(ctx, t, &s, "srv", UA_APPLICATIONTYPE_SERVER, NULL, NULL, NULL, 0) ||
       !qset_add(ctx, t, &s, "cli", UA_APPLICATIONTYPE_CLIENT, NULL, NULL, NULL, 0)) {
        qset_clear(&s);
        return;
    }
    UA_UInt32 start = 0, max = 0;
    UA_String empty = UA_STRING_NULL, pat = UA_STRING(s.pattern);
    UA_Variant in[6];
    UA_Variant_setScalar(&in[0], &start, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[1], &max, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[2], &empty, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[3], &pat, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[4], &empty, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&in[5], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_STRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_QUERYSERVERS, 6, in, 2, &outN, &out);
    (void)gt_absent(ctx, r, false, "QueryServers");
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "QueryServers -> %s", UA_StatusCode_name(r));
        qset_clear(&s);
        return;
    }
    const void *srv = NULL;
    size_t n = 0;
    r = gds_arg_array(&out[1], &UA_TYPES[UA_TYPES_SERVERONNETWORK], GDS_MAX_QUERY_RECORDS, &srv,
                      &n);
    UA_String url = UA_STRING("opc.tcp://auditor-test.invalid:4840");
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "QueryServers result is not a ServerOnNetwork array: %s",
                UA_StatusCode_name(r));
    else if(n != 1)
        ga_fail(ctx, "QueryServers returned %zu entries for 1 Server and 1 Client", n);
    else if(!UA_String_equal(&((const UA_ServerOnNetwork *)srv)[0].discoveryUrl, &url))
        ga_fail(ctx, "QueryServers entry does not carry the registered DiscoveryUrl");
    else
        ga_pass(ctx, "QueryServers returns the Server with its DiscoveryUrl, not the Client");
    gt_free_out(out, outN);
    qset_clear(&s);
}

const ga_test spec_query_tests[] = {
    {"gds.qry.uri_pattern", "12 §6.5.10", "QueryApplications filters ApplicationUri with a LIKE pattern",
     true, false, t_uri_pattern},
    {"gds.qry.type_mask", "12 §6.5.10", "QueryApplications ApplicationType mask selects Servers or Clients",
     true, false, t_type_mask},
    {"gds.qry.product_uri", "12 §6.5.10", "QueryApplications filters by ProductUri, ANDed with other filters",
     true, false, t_product_uri},
    {"gds.qry.name", "12 §6.5.10", "QueryApplications filters by ApplicationName",
     true, false, t_name},
    {"gds.qry.paging", "12 §6.5.10", "QueryApplications pages with MaxRecordsToReturn and NextRecordId",
     true, false, t_paging},
    {"gds.qry.capabilities", "12 §6.5.10, Annex D", "QueryApplications returns only records with every listed capability",
     true, false, t_capabilities},
    {"gds.qry.na_excluded", "12 §6.5.10, Annex D", "QueryApplications never returns a record with capability NA",
     true, false, t_na_excluded},
    {"gds.qry.servers", "12 §6.5.11", "QueryServers returns registered Servers only",
     true, false, t_query_servers},
};
const size_t spec_query_count = GDS_ARRAY_SIZE(spec_query_tests);
