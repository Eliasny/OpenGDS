/* OpenGDS unit test: QueryApplications (OPC 10000-12 §6.5.10) and
 * QueryServers (§6.5.11) on a server object, called through
 * UA_Server_call. The Auditor's gds.qry.* tests cover the same methods over
 * the wire; these cover the rules they do not: the name filter on the
 * default ApplicationName only, NextRecordId being the last record returned,
 * a new identifier on update, and one ServerOnNetwork per DiscoveryUrl.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids_gds.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <string.h>
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "common/ids.h"
#include "gds_internal.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:query"

static gds_server *S;
static gds_store *ST;

static bool own_cert(UA_ByteString *cert, UA_ByteString *key) {
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS test"), UA_STRING_STATIC("O=OpenGDS")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    return UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER,
                                NULL, key, cert) == UA_STATUSCODE_GOOD;
}

typedef struct {
    UA_ApplicationType type;
    const char *uri;
    const char *names[2]; /* the first is the default */
    const char *urls[2];
    const char *cap;
} app;

static UA_Guid add(const app *a) {
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_LocalizedText names[2];
    UA_String urls[2], cap = UA_STRING((char *)(uintptr_t)(a->cap ? a->cap : ""));
    rec.applicationUri = UA_STRING((char *)(uintptr_t)a->uri);
    rec.applicationType = a->type;
    rec.productUri = UA_STRING("urn:opengds:test:product");
    static const char *const locales[2] = {"en", "de"};
    for(size_t i = 0; i < 2 && a->names[i]; i++) {
        names[i] = UA_LOCALIZEDTEXT((char *)(uintptr_t)locales[i], (char *)(uintptr_t)a->names[i]);
        rec.applicationNamesSize = i + 1;
    }
    rec.applicationNames = names;
    for(size_t i = 0; i < 2 && a->urls[i]; i++) {
        urls[i] = UA_STRING((char *)(uintptr_t)a->urls[i]);
        rec.discoveryUrlsSize = i + 1;
    }
    rec.discoveryUrls = urls;
    if(a->cap) {
        rec.serverCapabilities = &cap;
        rec.serverCapabilitiesSize = 1;
    }
    UA_Guid g;
    UA_Guid_init(&g);
    CHECK(gds_guid_random(&g) == GDS_OK);
    CHECK(gds_store_app_insert(ST, &g, &rec) == GDS_OK);
    return g;
}

/* Call a Directory method; the caller clears res */
static UA_CallMethodResult call(UA_UInt32 method, UA_Variant *in, size_t n) {
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = UA_NODEID_NUMERIC(S->ns, UA_GDSID_DIRECTORY);
    req.methodId = UA_NODEID_NUMERIC(S->ns, method);
    req.inputArguments = in;
    req.inputArgumentsSize = n;
    return UA_Server_call(gds_server_ua(S), &req);
}

typedef struct {
    UA_UInt32 start, max;
    const char *name, *uri;
} q_in;

/* QueryApplications; returns the records, *next the NextRecordId */
static size_t query_apps(const q_in *q, UA_UInt32 *next, UA_ApplicationDescription **out,
                         UA_CallMethodResult *res) {
    UA_String name = UA_STRING((char *)(uintptr_t)(q->name ? q->name : ""));
    UA_String uri = UA_STRING((char *)(uintptr_t)(q->uri ? q->uri : ""));
    UA_String product = UA_STRING_NULL;
    UA_UInt32 mask = 0;
    UA_Variant in[7];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)&q->start, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[1], (void *)(uintptr_t)&q->max, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[2], &name, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[3], &uri, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[4], &mask, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[5], &product, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&in[6], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_STRING]);
    *res = call(UA_GDSID_DIRECTORY_QUERYAPPLICATIONS, in, 7);
    *out = NULL;
    if(!CHECK(res->statusCode == UA_STATUSCODE_GOOD) || !CHECK(res->outputArgumentsSize == 3))
        return 0;
    *next = *(UA_UInt32 *)res->outputArguments[1].data;
    *out = res->outputArguments[2].data;
    return res->outputArguments[2].arrayLength;
}

static size_t count(const q_in *q, UA_UInt32 *next) {
    UA_CallMethodResult res;
    UA_ApplicationDescription *apps = NULL;
    size_t n = query_apps(q, next, &apps, &res);
    UA_CallMethodResult_clear(&res);
    return n;
}

static void test_name_and_na(void) {
    app a = {UA_APPLICATIONTYPE_CLIENT, "urn:q:name:1", {"Alpha", "Beta"}, {NULL, NULL}, NULL};
    app na = {UA_APPLICATIONTYPE_SERVER, "urn:q:name:2", {"Alpha", NULL},
              {"opc.tcp://na.invalid:4840", NULL}, "NA"};
    (void)add(&a);
    (void)add(&na);
    UA_UInt32 next = 1;
    q_in q = {0, 0, "Alpha", "urn:q:name:%"};
    CHECK_EQ_INT(count(&q, &next), 1); /* not the NA one */
    CHECK_EQ_INT(next, 0);
    q.name = "Beta"; /* only the default name is filtered (§6.5.10) */
    CHECK_EQ_INT(count(&q, &next), 0);
    q.name = "Al%";
    CHECK_EQ_INT(count(&q, &next), 1);
}

/* NextRecordId is the last record returned; the next page starts after it */
static void test_paging_and_update(void) {
    app a = {UA_APPLICATIONTYPE_CLIENT, "urn:q:page:1", {"P1", NULL}, {NULL, NULL}, NULL};
    UA_Guid g1 = add(&a);
    a.uri = "urn:q:page:2";
    (void)add(&a);
    a.uri = "urn:q:page:3";
    (void)add(&a);
    const char *order[3] = {"urn:q:page:1", "urn:q:page:2", "urn:q:page:3"};
    q_in q = {0, 1, NULL, "urn:q:page:%"};
    for(size_t i = 0; i < 3; i++) {
        UA_CallMethodResult res;
        UA_ApplicationDescription *apps = NULL;
        UA_UInt32 next = 0;
        size_t n = query_apps(&q, &next, &apps, &res);
        UA_String want = UA_STRING((char *)(uintptr_t)order[i]);
        CHECK(n == 1 && UA_String_equal(&apps[0].applicationUri, &want));
        CHECK(i == 2 ? next == 0 : next > q.start);
        UA_CallMethodResult_clear(&res);
        q.start = next;
    }
    /* an update gives page:1 a new identifier: it comes after page:3 */
    UA_ApplicationRecordDataType rec;
    if(CHECK(gds_store_app_get(ST, &g1, &rec) == GDS_OK)) {
        UA_String_clear(&rec.productUri);
        rec.productUri = UA_STRING_ALLOC("urn:opengds:test:product2");
        CHECK(gds_store_app_update(ST, &g1, &rec) == GDS_OK);
        UA_ApplicationRecordDataType_clear(&rec);
    }
    q = (q_in){0, 0, NULL, "urn:q:page:%"};
    UA_CallMethodResult res;
    UA_ApplicationDescription *apps = NULL;
    UA_UInt32 next = 1;
    size_t n = query_apps(&q, &next, &apps, &res);
    UA_String last = UA_STRING("urn:q:page:1");
    CHECK(n == 3 && UA_String_equal(&apps[2].applicationUri, &last) && next == 0);
    UA_CallMethodResult_clear(&res);
}

static void test_query_servers(void) {
    app srv = {UA_APPLICATIONTYPE_SERVER, "urn:q:srv:1", {"Srv", NULL},
               {"opc.tcp://a.invalid:4840", "opc.tcp://b.invalid:4840"}, "LDS"};
    app both = {UA_APPLICATIONTYPE_CLIENTANDSERVER, "urn:q:srv:2", {"Both", NULL},
                {"opc.tcp://c.invalid:4840", NULL}, NULL};
    app cli = {UA_APPLICATIONTYPE_CLIENT, "urn:q:srv:3", {"Cli", NULL}, {NULL, NULL}, NULL};
    app na = {UA_APPLICATIONTYPE_SERVER, "urn:q:srv:4", {"Hidden", NULL},
              {"opc.tcp://d.invalid:4840", NULL}, "NA"};
    (void)add(&srv);
    (void)add(&both);
    (void)add(&cli);
    (void)add(&na);
    UA_UInt32 start = 0, max = 0;
    UA_String empty = UA_STRING_NULL, uri = UA_STRING("urn:q:srv:%");
    UA_Variant in[6];
    UA_Variant_setScalar(&in[0], &start, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[1], &max, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[2], &empty, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[3], &uri, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[4], &empty, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&in[5], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_STRING]);
    UA_CallMethodResult res = call(UA_GDSID_DIRECTORY_QUERYSERVERS, in, 6);
    if(CHECK(res.statusCode == UA_STATUSCODE_GOOD) && CHECK(res.outputArgumentsSize == 2) &&
       CHECK(res.outputArguments[1].type == &UA_TYPES[UA_TYPES_SERVERONNETWORK])) {
        const UA_ServerOnNetwork *o = res.outputArguments[1].data;
        size_t n = res.outputArguments[1].arrayLength;
        /* two URLs of srv, one of both; no client, no NA */
        if(CHECK_EQ_INT(n, 3)) {
            UA_String a = UA_STRING("opc.tcp://a.invalid:4840"),
                      b = UA_STRING("opc.tcp://b.invalid:4840"), name = UA_STRING("Srv"),
                      lds = UA_STRING("LDS");
            CHECK(UA_String_equal(&o[0].discoveryUrl, &a) && UA_String_equal(&o[1].discoveryUrl, &b));
            CHECK(o[0].recordId == o[1].recordId && o[2].recordId > o[1].recordId);
            CHECK(UA_String_equal(&o[0].serverName, &name));
            CHECK(o[0].serverCapabilitiesSize == 1 &&
                  UA_String_equal(&o[0].serverCapabilities[0], &lds));
        }
    }
    UA_CallMethodResult_clear(&res);
    /* six arguments are needed */
    res = call(UA_GDSID_DIRECTORY_QUERYSERVERS, in, 5);
    CHECK(res.statusCode == UA_STATUSCODE_BADARGUMENTSMISSING);
    UA_CallMethodResult_clear(&res);
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);

    static uint8_t pw[] = "query-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    if(!CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) ||
       !CHECK(gds_store_open(db, &ST) == GDS_OK) || !CHECK(own_cert(&cert, &key)))
        return CHECK_DONE();
    static gds_users users;
    gds_server_config cfg = {0};
    cfg.port = 0;
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS query test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = ST;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;
    if(CHECK(gds_server_new(&cfg, &S) == GDS_OK) && S) {
        test_name_and_na();
        test_paging_and_update();
        test_query_servers();
    }
    gds_server_delete(S);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_store_close(ST);
    gds_ca_close(ca);
    return CHECK_DONE();
}
