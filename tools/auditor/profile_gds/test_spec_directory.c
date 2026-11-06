/* OpenGDS T0 spec tests: Directory (OPC 10000-12 §6.5).
 * Written from the specification before any OpenGDS code. Black box: only
 * standard Directory methods on the target.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids_gds.h>

#include <string.h>

#include "common/limits.h"
#include "gds_target.h"
#include "spec_tests.h"
#include "common/banned.h"

#define URI_LEN (GDS_MAX_APPLICATION_URI + 1)

static bool need_session(ga_ctx *ctx, gds_target *t) {
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "cannot open a session on the target: %s", UA_StatusCode_name(r));
        return false;
    }
    return true;
}

/* FindApplications(uri) -> number of records, or SIZE_MAX on error */
static size_t find_count(gds_target *t, const char *uri, UA_StatusCode *status,
                         UA_ApplicationRecordDataType *firstOut) {
    UA_String u = UA_STRING((char *)(uintptr_t)uri);
    UA_Variant in;
    UA_Variant_setScalar(&in, &u, &UA_TYPES[UA_TYPES_STRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    *status = gt_call(t, UA_GDSID_DIRECTORY_FINDAPPLICATIONS, 1, &in, 1, &outN, &out);
    if(*status != UA_STATUSCODE_GOOD)
        return SIZE_MAX;
    const void *recs = NULL;
    size_t n = 0;
    *status = gds_arg_array(&out[0], gt_record_type(), GDS_MAX_QUERY_RECORDS, &recs, &n);
    if(*status == UA_STATUSCODE_GOOD && n > 0 && firstOut)
        *status = UA_copy(recs, firstOut, gt_record_type());
    gt_free_out(out, outN);
    return *status == UA_STATUSCODE_GOOD ? n : SIZE_MAX;
}

static void t_find_unknown(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!need_session(ctx, t))
        return;
    char uri[URI_LEN];
    gt_unique_uri(t, uri, sizeof(uri));
    UA_StatusCode r;
    size_t n = find_count(t, uri, &r, NULL);
    if(n == SIZE_MAX)
        ga_fail(ctx, "FindApplications(unknown) -> %s, expected Good with no records",
                UA_StatusCode_name(r));
    else if(n != 0)
        ga_fail(ctx, "FindApplications(unknown) returned %zu records", n);
    else
        ga_pass(ctx, "Good, empty result");
}

static void t_register_valid(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!need_session(ctx, t))
        return;
    char uri[URI_LEN];
    UA_NodeId id;
    UA_StatusCode r = gt_register(t, UA_APPLICATIONTYPE_SERVER, uri, sizeof(uri), &id);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "RegisterApplication(valid server record) -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    size_t n = find_count(t, uri, &r, &rec);
    if(n != 1)
        ga_fail(ctx, "FindApplications after register: %s, %zu record(s), expected 1",
                UA_StatusCode_name(r), n == SIZE_MAX ? 0 : n);
    else if(!UA_NodeId_equal(&rec.applicationId, &id))
        ga_fail(ctx, "FindApplications returned another ApplicationId than RegisterApplication");
    else if(rec.applicationType != UA_APPLICATIONTYPE_SERVER)
        ga_fail(ctx, "ApplicationType changed to %d", (int)rec.applicationType);
    else
        ga_pass(ctx, "registered, found by URI with the same ApplicationId");
    UA_clear(&rec, gt_record_type());
    UA_NodeId_clear(&id);
}

/* Register a deliberately broken record; the GDS must refuse it. */
static void expect_refused(ga_ctx *ctx, gds_target *t, UA_ApplicationRecordDataType *rec,
                           const char *what) {
    UA_Variant in;
    UA_Variant_setScalar(&in, rec, gt_record_type());
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_REGISTERAPPLICATION, 1, &in, 0, &outN, &out);
    gt_free_out(out, outN);
    if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "RegisterApplication accepted %s", what);
    else if(r == UA_STATUSCODE_BADINVALIDARGUMENT)
        ga_pass(ctx, "refused with BadInvalidArgument");
    else
        ga_warn(ctx, "refused with %s; the spec names BadInvalidArgument", UA_StatusCode_name(r));
}

static void t_register_empty_uri(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!need_session(ctx, t))
        return;
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    UA_String url;
    gt_record(&rec, "", UA_APPLICATIONTYPE_SERVER, &name, &url);
    rec.applicationUri = UA_STRING_NULL;
    expect_refused(ctx, t, &rec, "a record without ApplicationUri");
}

static void t_register_bad_type(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!need_session(ctx, t))
        return;
    char uri[URI_LEN];
    gt_unique_uri(t, uri, sizeof(uri));
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    UA_String url;
    gt_record(&rec, uri, UA_APPLICATIONTYPE_SERVER, &name, &url);
    /* deliberately out of range: the target must refuse it */
    rec.applicationType = (UA_ApplicationType)42; // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange)
    expect_refused(ctx, t, &rec, "ApplicationType 42");
}

static void t_register_server_no_urls(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!need_session(ctx, t))
        return;
    char uri[URI_LEN];
    gt_unique_uri(t, uri, sizeof(uri));
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    UA_String url;
    gt_record(&rec, uri, UA_APPLICATIONTYPE_SERVER, &name, &url);
    rec.discoveryUrls = NULL;
    rec.discoveryUrlsSize = 0;
    expect_refused(ctx, t, &rec, "a Server record without DiscoveryUrls");
}

static void t_register_no_names(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!need_session(ctx, t))
        return;
    char uri[URI_LEN];
    gt_unique_uri(t, uri, sizeof(uri));
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    UA_String url;
    gt_record(&rec, uri, UA_APPLICATIONTYPE_CLIENT, &name, &url);
    rec.applicationNames = NULL;
    rec.applicationNamesSize = 0;
    expect_refused(ctx, t, &rec, "a record without ApplicationNames");
}

static UA_StatusCode get_application(gds_target *t, const UA_NodeId *id,
                                     UA_ApplicationRecordDataType *rec) {
    UA_Variant in;
    UA_Variant_setScalar(&in, (void *)(uintptr_t)id, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_GETAPPLICATION, 1, &in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_ApplicationRecordDataType *got = uac_out_scalar(out, outN, 0, gt_record_type());
    r = got ? UA_copy(got, rec, gt_record_type()) : UA_STATUSCODE_BADUNEXPECTEDERROR;
    gt_free_out(out, outN);
    return r;
}

static void t_get_application(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!need_session(ctx, t))
        return;
    char uri[URI_LEN];
    UA_NodeId id;
    UA_StatusCode r = gt_register(t, UA_APPLICATIONTYPE_CLIENT, uri, sizeof(uri), &id);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: RegisterApplication -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    r = get_application(t, &id, &rec);
    UA_String want = UA_STRING(uri);
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "GetApplication -> %s", UA_StatusCode_name(r));
    else if(!UA_String_equal(&rec.applicationUri, &want) || !UA_NodeId_equal(&rec.applicationId, &id))
        ga_fail(ctx, "GetApplication returned another record");
    else
        ga_pass(ctx, "record returned unchanged");
    UA_clear(&rec, gt_record_type());
    UA_NodeId_clear(&id);
}

static void t_get_unknown(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!need_session(ctx, t))
        return;
    UA_NodeId id = UA_NODEID_GUID(t->ns, UA_Guid_random());
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_StatusCode r = get_application(t, &id, &rec);
    UA_clear(&rec, gt_record_type());
    if(r == UA_STATUSCODE_BADNOTFOUND)
        ga_pass(ctx, "BadNotFound");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "GetApplication(random id) returned a record");
    else
        ga_fail(ctx, "GetApplication(random id) -> %s, the spec requires BadNotFound",
                UA_StatusCode_name(r));
}

static void t_update_application(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!need_session(ctx, t))
        return;
    char uri[URI_LEN];
    UA_NodeId id;
    UA_StatusCode r = gt_register(t, UA_APPLICATIONTYPE_CLIENT, uri, sizeof(uri), &id);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: RegisterApplication -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    UA_String url;
    gt_record(&rec, uri, UA_APPLICATIONTYPE_CLIENT, &name, &url);
    rec.applicationId = id;
    name = UA_LOCALIZEDTEXT("en", "OpenGDS Auditor renamed application");
    UA_Variant in;
    UA_Variant_setScalar(&in, &rec, gt_record_type());
    size_t outN = 0;
    UA_Variant *out = NULL;
    r = gt_call(t, UA_GDSID_DIRECTORY_UPDATEAPPLICATION, 1, &in, 0, &outN, &out);
    gt_free_out(out, outN);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "UpdateApplication -> %s", UA_StatusCode_name(r));
        UA_NodeId_clear(&id);
        return;
    }
    UA_ApplicationRecordDataType got;
    UA_ApplicationRecordDataType_init(&got);
    r = get_application(t, &id, &got);
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "GetApplication after update -> %s", UA_StatusCode_name(r));
    else if(got.applicationNamesSize < 1 || !UA_String_equal(&got.applicationNames[0].text, &name.text))
        ga_fail(ctx, "the new ApplicationName was not stored");
    else
        ga_pass(ctx, "update visible through GetApplication");
    UA_clear(&got, gt_record_type());
    UA_NodeId_clear(&id);
}

static void t_unregister(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!need_session(ctx, t))
        return;
    char uri[URI_LEN];
    UA_NodeId id;
    UA_StatusCode r = gt_register(t, UA_APPLICATIONTYPE_CLIENT, uri, sizeof(uri), &id);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: RegisterApplication -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_Variant in;
    UA_Variant_setScalar(&in, &id, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    r = gt_call(t, UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION, 1, &in, 0, &outN, &out);
    gt_free_out(out, outN);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "UnregisterApplication -> %s", UA_StatusCode_name(r));
        UA_NodeId_clear(&id);
        return;
    }
    size_t n = find_count(t, uri, &r, NULL);
    if(n == 0)
        ga_pass(ctx, "record gone from FindApplications");
    else
        ga_fail(ctx, "FindApplications after unregister: %s, %zu record(s)", UA_StatusCode_name(r),
                n == SIZE_MAX ? 0 : n);
    UA_NodeId_clear(&id);
}

static void t_query_by_uri(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!need_session(ctx, t))
        return;
    char uri[URI_LEN];
    UA_NodeId id;
    UA_StatusCode r = gt_register(t, UA_APPLICATIONTYPE_SERVER, uri, sizeof(uri), &id);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: RegisterApplication -> %s", UA_StatusCode_name(r));
        return;
    }
    /* QueryApplications(startingRecordId, maxRecordsToReturn, applicationName,
     * applicationUri, applicationType, productUri, serverCapabilities) */
    UA_UInt32 start = 0, max = 10, typeMask = 0;
    UA_String empty = UA_STRING_NULL, u = UA_STRING(uri);
    UA_Variant in[7];
    UA_Variant_setScalar(&in[0], &start, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[1], &max, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[2], &empty, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[3], &u, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[4], &typeMask, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[5], &empty, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&in[6], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_STRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    r = gt_call(t, UA_GDSID_DIRECTORY_QUERYAPPLICATIONS, 7, in, 3, &outN, &out);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "QueryApplications -> %s", UA_StatusCode_name(r));
        UA_NodeId_clear(&id);
        return;
    }
    /* outputs: lastCounterResetTime, nextRecordId, applications[] (ApplicationDescription) */
    const void *apps = NULL;
    size_t n = 0;
    r = gds_arg_array(&out[2], &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION], GDS_MAX_QUERY_RECORDS,
                      &apps, &n);
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "QueryApplications result malformed: %s", UA_StatusCode_name(r));
    else if(n != 1)
        ga_fail(ctx, "QueryApplications(applicationUri) returned %zu applications, expected 1", n);
    else if(!UA_String_equal(&((const UA_ApplicationDescription *)apps)[0].applicationUri, &u))
        ga_fail(ctx, "QueryApplications returned another application");
    else
        ga_pass(ctx, "filter by ApplicationUri returns exactly the record");
    gt_free_out(out, outN);
    UA_NodeId_clear(&id);
}

const ga_test spec_directory_tests[] = {
    {"gds.dir.find_unknown", "12 §6.5.4", "FindApplications for an unknown URI returns no records",
     false, false, t_find_unknown},
    {"gds.dir.register_valid", "12 §6.5.6", "RegisterApplication stores a valid record",
     true, false, t_register_valid},
    {"gds.dir.register_no_uri", "12 §6.5.6", "RegisterApplication refuses a record without ApplicationUri",
     true, false, t_register_empty_uri},
    {"gds.dir.register_bad_type", "12 §6.5.6", "RegisterApplication refuses an invalid ApplicationType",
     true, false, t_register_bad_type},
    {"gds.dir.register_server_no_urls", "12 §6.5.6", "RegisterApplication refuses a Server without DiscoveryUrls",
     true, false, t_register_server_no_urls},
    {"gds.dir.register_no_names", "12 §6.5.6", "RegisterApplication refuses a record without ApplicationNames",
     true, false, t_register_no_names},
    {"gds.dir.get_application", "12 §6.5.9", "GetApplication returns the registered record",
     true, false, t_get_application},
    {"gds.dir.get_unknown", "12 §6.5.9", "GetApplication of an unknown id returns BadNotFound",
     false, false, t_get_unknown},
    {"gds.dir.update_application", "12 §6.5.7", "UpdateApplication changes the stored record",
     true, false, t_update_application},
    {"gds.dir.unregister", "12 §6.5.8", "UnregisterApplication removes the record",
     true, false, t_unregister},
    {"gds.dir.query_by_uri", "12 §6.5.10", "QueryApplications filters by ApplicationUri",
     true, false, t_query_by_uri},
};
const size_t spec_directory_count = GDS_ARRAY_SIZE(spec_directory_tests);
