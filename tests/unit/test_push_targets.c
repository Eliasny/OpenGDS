/* OpenGDS unit test: the push target list (store table push_targets,
 * store ABI minor 6; gds_server_push_targets) and the push-scheduling slot
 * (gds_server_set_push_scheduler, plugin ABI minor 2).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "gds_internal.h"
#include "gds_plugin.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:push-targets"
#define DEV1 "urn:opengds:test:push-targets:press1"
#define DEV2 "urn:opengds:test:push-targets:press2"

static UA_Guid add_app(gds_store *st, const char *uri, UA_ApplicationType type) {
    UA_Guid id = UA_Guid_random();
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "Press");
    UA_String disc = UA_STRING("opc.tcp://press:4840");
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    rec.applicationUri = UA_STRING((char *)(uintptr_t)uri);
    rec.applicationType = type;
    rec.productUri = UA_STRING("urn:opengds:test:product");
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    rec.discoveryUrls = &disc;
    rec.discoveryUrlsSize = 1;
    CHECK(gds_store_app_insert(st, &id, &rec) == GDS_OK);
    return id;
}

typedef struct {
    size_t n;
    UA_Guid ids[4];
    char endpoints[4][GDS_MAX_PUSH_ENDPOINT];
    bool enabled[4];
} rows;

static bool row_cb(void *ctx, const gds_push_target_row *r) {
    rows *x = ctx;
    if(x->n < 4) {
        x->ids[x->n] = r->appId;
        (void)gds_path(x->endpoints[x->n], GDS_MAX_PUSH_ENDPOINT, "%s", r->endpoint);
        x->enabled[x->n] = r->enabled;
    }
    x->n++;
    return true;
}

static void test_store(gds_store *st, UA_Guid *dev1, UA_Guid *dev2) {
    CHECK_EQ_INT(gds_store_schema_version(st), 5); /* the latest; the table is in schema 1 */
    *dev1 = add_app(st, DEV1, UA_APPLICATIONTYPE_SERVER);
    *dev2 = add_app(st, DEV2, UA_APPLICATIONTYPE_SERVER);
    rows r = {0};
    CHECK(gds_store_push_target_scan(st, row_cb, &r) == GDS_OK);
    CHECK_EQ_INT(r.n, 0);

    CHECK(gds_store_push_target_put(st, dev1, "opc.tcp://press1:4840", true) == GDS_OK);
    CHECK(gds_store_push_target_put(st, dev2, "opc.tcp://press2:4840", false) == GDS_OK);
    /* again: replaces */
    CHECK(gds_store_push_target_put(st, dev1, "opc.tcp://press1.example:4841", true) == GDS_OK);
    memset(&r, 0, sizeof(r));
    CHECK(gds_store_push_target_scan(st, row_cb, &r) == GDS_OK);
    CHECK_EQ_INT(r.n, 2);
    for(size_t i = 0; i < 2 && i < r.n; i++) {
        if(UA_Guid_equal(&r.ids[i], dev1))
            CHECK(strcmp(r.endpoints[i], "opc.tcp://press1.example:4841") == 0 && r.enabled[i]);
        else
            CHECK(UA_Guid_equal(&r.ids[i], dev2) && !r.enabled[i]);
    }

    /* refused */
    UA_Guid nobody = UA_Guid_random();
    CHECK(gds_store_push_target_put(st, &nobody, "opc.tcp://x:1", true) == GDS_ENOTFOUND);
    CHECK(gds_store_push_target_put(st, dev1, "http://press1", true) == GDS_EINVAL);
    CHECK(gds_store_push_target_put(st, dev1, "opc.tcp://", true) == GDS_EINVAL);
    CHECK(gds_store_push_target_put(st, dev1, "opc.tcp://a b:1", true) == GDS_EINVAL);
    CHECK(gds_store_push_target_put(st, dev1, NULL, true) == GDS_EINVAL);
    char longUrl[GDS_MAX_PUSH_ENDPOINT + 8];
    memset(longUrl, 'a', sizeof(longUrl) - 1);
    memcpy(longUrl, "opc.tcp://", 10);
    longUrl[sizeof(longUrl) - 1] = '\0';
    CHECK(gds_store_push_target_put(st, dev1, longUrl, true) == GDS_EINVAL);
    CHECK(gds_store_push_target_delete(st, &nobody) == GDS_ENOTFOUND);

    /* the row goes with its application */
    UA_Guid gone = add_app(st, "urn:opengds:test:push-targets:gone", UA_APPLICATIONTYPE_SERVER);
    CHECK(gds_store_push_target_put(st, &gone, "opc.tcp://gone:4840", true) == GDS_OK);
    CHECK(gds_store_app_delete(st, &gone) == GDS_OK);
    memset(&r, 0, sizeof(r));
    CHECK(gds_store_push_target_scan(st, row_cb, &r) == GDS_OK);
    CHECK_EQ_INT(r.n, 2);
}

typedef struct {
    size_t n;
    bool sawDev1, dev2Disabled;
    UA_UInt16 ns;
} listed;

static bool list_cb(void *ctx, const UA_NodeId *id, const char *uri, const char *endpoint,
                    bool enabled) {
    listed *l = ctx;
    l->n++;
    CHECK(id->identifierType == UA_NODEIDTYPE_GUID && id->namespaceIndex == l->ns);
    if(strcmp(uri, DEV1) == 0)
        l->sawDev1 = strcmp(endpoint, "opc.tcp://press1.example:4841") == 0 && enabled;
    if(strcmp(uri, DEV2) == 0)
        l->dev2Disabled = !enabled;
    return true;
}

static size_t pick_none(void *ctx, UA_DateTime now, size_t budget, const gds_push_job *due,
                        size_t nDue, size_t *picked) {
    (void)ctx, (void)now, (void)budget, (void)due, (void)nDue, (void)picked;
    return 0;
}

static void test_server(gds_server *s) {
    listed l = {0, false, false, s->ns};
    CHECK(gds_server_push_targets(s, list_cb, &l) == GDS_OK);
    CHECK_EQ_INT(l.n, 2);
    CHECK(l.sawDev1 && l.dev2Disabled);
    CHECK(gds_server_push_targets(s, NULL, &l) == GDS_EINVAL);

    /* the slot */
    gds_push_scheduler got;
    CHECK(!gds_server_push_scheduler(s, &got)); /* built-in */
    gds_push_scheduler sc;
    memset(&sc, 0, sizeof(sc));
    sc.abi_major = GDS_PLUGIN_ABI_MAJOR;
    sc.abi_minor = GDS_PLUGIN_ABI_MINOR;
    sc.struct_size = sizeof(sc);
    CHECK(gds_server_set_push_scheduler(s, &sc) == GDS_EINVAL); /* no next_jobs */
    sc.next_jobs = pick_none;
    sc.abi_major = GDS_PLUGIN_ABI_MAJOR + 1;
    CHECK(gds_server_set_push_scheduler(s, &sc) == GDS_EINVAL);
    sc.abi_major = GDS_PLUGIN_ABI_MAJOR;
    sc.struct_size = 8;
    CHECK(gds_server_set_push_scheduler(s, &sc) == GDS_EINVAL);
    sc.struct_size = sizeof(sc);
    CHECK(gds_server_set_push_scheduler(s, &sc) == GDS_OK);
    CHECK(gds_server_push_scheduler(s, &got) && got.next_jobs == pick_none && !got.job_done);
    CHECK(gds_server_set_push_scheduler(s, NULL) == GDS_OK);
    CHECK(!gds_server_push_scheduler(s, &got));
    CHECK(gds_server_set_push_scheduler(s, &sc) == GDS_OK);
    /* fixed once the server runs */
    __atomic_store_n(&s->started, true, __ATOMIC_RELEASE);
    CHECK(gds_server_set_push_scheduler(s, NULL) == GDS_ESTATE);
    __atomic_store_n(&s->started, false, __ATOMIC_RELEASE);

    /* trusting a certificate needs the server thread; refused arguments */
    UA_ByteString empty = UA_BYTESTRING_NULL;
    CHECK(gds_server_trust_certificate(s, "test", &empty, 100) == GDS_EINVAL);
    UA_ByteString junk = UA_BYTESTRING("junk");
    CHECK(gds_server_trust_certificate(s, "", &junk, 100) == GDS_EINVAL);
    CHECK(gds_server_trust_certificate(s, "test", &junk, 100) == GDS_EREMOTE); /* not running */
    CHECK(gds_server_set_role(s, GDS_NODE_STANDBY, 100, 0) == GDS_OK);
    CHECK(gds_server_trust_certificate(s, "test", &junk, 100) == GDS_ENOTLEADER);
    CHECK(gds_server_set_role(s, GDS_NODE_STANDALONE, 255, 0) == GDS_OK);
}

/* A backend before minor 6 has no push targets */
static void test_old_backend(void) {
    gds_store_backend be;
    memset(&be, 0, sizeof(be));
    CHECK(offsetof(gds_store_backend, push_target_put) > offsetof(gds_store_backend, tl_put));
}

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);
    gds_store *st = NULL;
    if(!CHECK(gds_store_open(db, &st) == GDS_OK))
        return CHECK_DONE();
    UA_Guid dev1, dev2;
    test_store(st, &dev1, &dev2);
    test_old_backend();

    static uint8_t pw[] = "push-targets-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS test")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    if(CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) &&
       CHECK(UA_CreateCertificate(UA_Log_Stdout, subject, 1, san, 2, UA_CERTIFICATEFORMAT_DER,
                                  NULL, &key, &cert) == UA_STATUSCODE_GOOD)) {
        static gds_users users;
        gds_server_config cfg = {0};
        cfg.loopbackOnly = true;
        cfg.applicationUri = TEST_URI;
        cfg.productUri = "urn:opengds:test";
        cfg.applicationName = "OpenGDS push targets test";
        cfg.ownCert = (gds_buf){cert.data, cert.length};
        cfg.ownKey = (gds_buf){key.data, key.length};
        cfg.store = st;
        cfg.ca = ca;
        cfg.users = &users;
        cfg.approval = GDS_APPROVE_MANUAL;
        gds_server *s = NULL;
        if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s)
            test_server(s);
        gds_server_delete(s);
    }
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_store_close(st);
    gds_ca_close(ca);
    return CHECK_DONE();
}
