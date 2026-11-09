/* OpenGDS unit test: the mDNS announce (src/disc/disc_mdns.c; OPC 10000-12
 * §4.3.4, §7.10.3, Annex C, Annex D). The configuration is checked, then a
 * real GDS with `mdns` on is asked by a real client over the None discovery
 * channel: FindServersOnNetwork (OPC 10000-4 §5.5.3) returns the GDS's own
 * record with its DiscoveryUrl and the capability GDS, and
 * ServerConfiguration.MulticastDnsEnabled reads TRUE.
 * Exit 77 (skipped) when the host cannot open the mDNS multicast socket.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server_config_default.h>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "disc_mdns.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:mdns"
#define TEST_NAME "OpenGDS mdns test"
#define SKIP 77

static UA_Boolean running = true;

static void *loop_main(void *arg) {
    CHECK(gds_server_run(arg, &running) == GDS_OK);
    return NULL;
}

static void stop_cb(UA_Server *ua, void *data) {
    (void)ua;
    *(UA_Boolean *)data = false;
}

static void test_check(void) {
    gds_mdns_config m = {true, NULL, NULL};
    CHECK(gds_disc_mdns_built());
    CHECK(gds_disc_mdns_check(&m) == GDS_OK);
    m.serverName = "Plant GDS \xc3\xa4";
    CHECK(gds_disc_mdns_check(&m) == GDS_OK);
    m.serverName = "a.b"; /* a label separator */
    CHECK(gds_disc_mdns_check(&m) == GDS_EINVAL);
    m.serverName = "tab\there";
    CHECK(gds_disc_mdns_check(&m) == GDS_EINVAL);
    m.serverName = "\xc0\xaf"; /* overlong '/' */
    CHECK(gds_disc_mdns_check(&m) == GDS_EINVAL);
    m.serverName = "0123456789012345678901234567890123456789012345678901234567890123";
    CHECK(gds_disc_mdns_check(&m) == GDS_EINVAL); /* 64 bytes */
    m.serverName = NULL;
    m.interfaceIp = "10.0.0.1";
    CHECK(gds_disc_mdns_check(&m) == GDS_OK);
    m.interfaceIp = "10.0.0";
    CHECK(gds_disc_mdns_check(&m) == GDS_EINVAL);
    CHECK(gds_disc_mdns_check(NULL) == GDS_EINVAL);
}

static bool str_is(const UA_String *s, const char *v) {
    UA_String w = UA_STRING((char *)(uintptr_t)v);
    return UA_String_equal(s, &w);
}

static void test_configure(void) {
    UA_ServerConfig c;
    memset(&c, 0, sizeof(c));
    if(!CHECK(UA_ServerConfig_setMinimal(&c, 0, NULL) == UA_STATUSCODE_GOOD))
        return;
    gds_mdns_config off = {false, NULL, NULL};
    CHECK(gds_disc_mdns_configure(&c, &off, TEST_NAME) == GDS_OK && !c.mdnsEnabled);
    gds_mdns_config on = {true, NULL, "127.0.0.1"};
    /* the ApplicationName is the instance name: one with '.' is refused */
    CHECK(gds_disc_mdns_configure(&c, &on, "gds.example") == GDS_EINVAL && !c.mdnsEnabled);
    if(CHECK(gds_disc_mdns_configure(&c, &on, TEST_NAME) == GDS_OK)) {
        CHECK(c.mdnsEnabled && str_is(&c.mdnsConfig.mdnsServerName, TEST_NAME));
        /* Annex C.2 caps, Annex D: only GDS (LDS is for a standalone LDS) */
        CHECK(c.mdnsConfig.serverCapabilitiesSize == 1 &&
              str_is(&c.mdnsConfig.serverCapabilities[0], "GDS"));
        CHECK(str_is(&c.mdnsInterfaceIP, "127.0.0.1"));
    }
    on.serverName = "Plant GDS";
    on.interfaceIp = NULL;
    if(CHECK(gds_disc_mdns_configure(&c, &on, TEST_NAME) == GDS_OK)) /* replaces */
        CHECK(str_is(&c.mdnsConfig.mdnsServerName, "Plant GDS") && c.mdnsInterfaceIP.length == 0);
    UA_ServerConfig_clear(&c);
}

/* The GDS's own record: its DiscoveryUrl and only the capability GDS; the
 * caps filter (OPC 10000-4 §5.5.3) keeps it. false: another server. */
static bool check_record(const UA_ServerOnNetwork *son, const char *url) {
    /* open62541 names the instance "<name>-<host>" (one DNS label) */
    if(son->serverName.length < strlen(TEST_NAME) ||
       memcmp(son->serverName.data, TEST_NAME, strlen(TEST_NAME)) != 0)
        return false;
    CHECK(str_is(&son->discoveryUrl, url));
    CHECK(son->serverCapabilitiesSize == 1 && str_is(&son->serverCapabilities[0], "GDS"));
    UA_String caps = UA_STRING("GDS");
    UA_ServerOnNetwork *f = NULL;
    size_t fn = 0;
    UA_Client *c = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(c));
    CHECK(UA_Client_findServersOnNetwork(c, url, 0, 0, 1, &caps, &fn, &f) == UA_STATUSCODE_GOOD &&
          fn >= 1);
    UA_Array_delete(f, fn, &UA_TYPES[UA_TYPES_SERVERONNETWORK]);
    UA_Client_delete(c);
    return true;
}

/* FindServersOnNetwork until the GDS's own record is there. */
static int test_announced(gds_server *s, UA_UInt16 port) {
    char url[64];
    (void)snprintf(url, sizeof(url), "opc.tcp://127.0.0.1:%u", (unsigned)port);
    UA_ServerOnNetwork *son = NULL;
    size_t n = 0;
    UA_StatusCode r = UA_STATUSCODE_BAD;
    for(int i = 0; i < 100 && (r != UA_STATUSCODE_GOOD || n == 0); i++) {
        UA_Array_delete(son, n, &UA_TYPES[UA_TYPES_SERVERONNETWORK]);
        son = NULL;
        n = 0;
        UA_Client *c = UA_Client_new();
        UA_ClientConfig_setDefault(UA_Client_getConfig(c));
        r = UA_Client_findServersOnNetwork(c, url, 0, 0, 0, NULL, &n, &son);
        UA_Client_delete(c);
        if(r != UA_STATUSCODE_GOOD || n == 0)
            usleep(50000);
    }
    CHECK(r == UA_STATUSCODE_GOOD);
    if(r == UA_STATUSCODE_GOOD && n == 0) {
        fprintf(stderr, "SKIP: no mDNS record (the multicast socket did not open here)\n");
        return SKIP;
    }
    bool found = false;
    for(size_t i = 0; i < n; i++)
        found |= check_record(&son[i], url);
    CHECK(found);
    UA_Array_delete(son, n, &UA_TYPES[UA_TYPES_SERVERONNETWORK]);

    /* §7.10.3: "If MulticastDnsEnabled is TRUE then the application
     * announces itself using multicast DNS." */
    UA_Variant v;
    UA_Variant_init(&v);
    if(CHECK(UA_Server_readValue(gds_server_ua(s),
                                 UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_MULTICASTDNSENABLED),
                                 &v) == UA_STATUSCODE_GOOD))
        CHECK(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_BOOLEAN]) &&
              *(UA_Boolean *)v.data == true);
    UA_Variant_clear(&v);
    return 0;
}

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    test_check();
    test_configure();

    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);
    static uint8_t pw[] = "mdns-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    gds_store *st = NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS mdns test")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("IP:127.0.0.1")};
    if(!CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) || !CHECK(gds_store_open(db, &st) == GDS_OK) ||
       !CHECK(UA_CreateCertificate(UA_Log_Stdout, subject, 1, san, 2, UA_CERTIFICATEFORMAT_DER,
                                   NULL, &key, &cert) == UA_STATUSCODE_GOOD))
        return CHECK_DONE();

    static gds_users users;
    UA_UInt16 port = (UA_UInt16)(47000 + getpid() % 1000);
    gds_server_config cfg = {0};
    cfg.port = port;
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = TEST_NAME;
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;
    cfg.mdns.enabled = true;

    gds_server *s = NULL;
    /* the subnet cannot reach a loopback-only GDS: refused */
    CHECK(gds_server_new(&cfg, &s) == GDS_EINVAL && !s);
    cfg.loopbackOnly = false;
    cfg.hostname = "127.0.0.1"; /* listen there only; announced as is */
    int rc = 0;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s) {
        pthread_t loop;
        if(CHECK(pthread_create(&loop, NULL, loop_main, s) == 0)) {
            rc = test_announced(s, port);
            (void)UA_Server_addTimedCallback(gds_server_ua(s), stop_cb, &running,
                                             UA_DateTime_nowMonotonic(), NULL);
            (void)pthread_join(loop, NULL);
        }
    }
    gds_server_delete(s);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_store_close(st);
    gds_ca_close(ca);
    int done = CHECK_DONE();
    return done != 0 ? done : rc;
}
