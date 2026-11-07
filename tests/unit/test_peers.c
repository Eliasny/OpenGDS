/* OpenGDS unit test: FindServers returns the other servers of a
 * non-transparent redundant server set (UASM ask A15; OPC 10000-4
 * §6.6.2.4.5.1, §5.5.2.2). A real client asks over the None discovery
 * channel: the server first, then its peers with their own DiscoveryUrls,
 * also when the request carries an EndpointUrl; the serverUris filter
 * applies to the peers; bad lists are refused and an empty one clears.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "gds_internal.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:peers:a"
#define PEER_B "urn:opengds:test:peers:b"
#define PEER_C "urn:opengds:test:peers:c"

static UA_Boolean running = true;

static void *loop_main(void *arg) {
    CHECK(gds_server_run(arg, &running) == GDS_OK);
    return NULL;
}

/* UA_Server_run reads *running without atomics: cleared on its thread. */
static void stop_cb(UA_Server *ua, void *data) {
    (void)ua;
    *(UA_Boolean *)data = false;
}

static void peer(UA_ApplicationDescription *d, const char *uri, UA_String *url) {
    UA_ApplicationDescription_init(d);
    d->applicationUri = UA_STRING((char *)(uintptr_t)uri);
    d->applicationType = UA_APPLICATIONTYPE_SERVER;
    d->applicationName = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)uri);
    d->discoveryUrls = url;
    d->discoveryUrlsSize = 1;
}

/* FindServers; *out and *n as the client returns them. */
static UA_StatusCode find(const char *url, const char *filter, UA_ApplicationDescription **out,
                          size_t *n) {
    UA_Client *c = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(c));
    UA_String f = filter ? UA_STRING((char *)(uintptr_t)filter) : UA_STRING_NULL;
    UA_StatusCode r = UA_Client_findServers(c, url, filter ? 1 : 0, filter ? &f : NULL, 0, NULL, n,
                                            out);
    UA_Client_delete(c);
    return r;
}

static bool has_url(const UA_ApplicationDescription *d, const char *url) {
    UA_String u = UA_STRING((char *)(uintptr_t)url);
    for(size_t i = 0; i < d->discoveryUrlsSize; i++)
        if(UA_String_equal(&d->discoveryUrls[i], &u))
            return true;
    return false;
}

static bool uri_is(const UA_ApplicationDescription *d, const char *uri) {
    UA_String u = UA_STRING((char *)(uintptr_t)uri);
    return UA_String_equal(&d->applicationUri, &u);
}

static void test_refusals(gds_server *s) {
    UA_String url = UA_STRING("opc.tcp://b:4840");
    UA_ApplicationDescription p[2];
    peer(&p[0], TEST_URI, &url); /* itself */
    CHECK(gds_server_set_peer_servers(s, p, 1) == GDS_EINVAL);
    peer(&p[0], PEER_B, &url);
    p[0].applicationType = UA_APPLICATIONTYPE_CLIENT;
    CHECK(gds_server_set_peer_servers(s, p, 1) == GDS_EINVAL);
    peer(&p[0], PEER_B, &url);
    p[0].discoveryUrlsSize = 0;
    CHECK(gds_server_set_peer_servers(s, p, 1) == GDS_EINVAL);
    peer(&p[0], PEER_B, &url);
    peer(&p[1], PEER_B, &url); /* twice */
    CHECK(gds_server_set_peer_servers(s, p, 2) == GDS_EINVAL);
    CHECK(gds_server_set_peer_servers(s, NULL, 1) == GDS_EINVAL);
    CHECK(gds_server_set_peer_servers(s, p, GDS_MAX_PEER_SERVERS + 1) == GDS_ETOOBIG);
}

static void free_found(UA_ApplicationDescription **out, size_t *n) {
    UA_Array_delete(*out, *n, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
    *out = NULL;
    *n = 0;
}

static void test_alone(const char *url) {
    UA_ApplicationDescription *out = NULL;
    size_t n = 0;
    /* no peers: itself only (the server thread may still be starting) */
    UA_StatusCode r = UA_STATUSCODE_BADCONNECTIONREJECTED;
    for(int i = 0; i < 100 && r != UA_STATUSCODE_GOOD; i++) {
        r = find(url, NULL, &out, &n);
        if(r != UA_STATUSCODE_GOOD)
            usleep(50000);
    }
    if(CHECK(r == UA_STATUSCODE_GOOD))
        CHECK(n == 1 && uri_is(&out[0], TEST_URI));
    free_found(&out, &n);
}

static void test_with_peers(gds_server *s, const char *url) {
    UA_ApplicationDescription *out = NULL;
    size_t n = 0;
    UA_String ub = UA_STRING("opc.tcp://node-b:4840"), uc = UA_STRING("opc.tcp://node-c:4840");
    UA_ApplicationDescription p[2];
    peer(&p[0], PEER_B, &ub);
    peer(&p[1], PEER_C, &uc);
    CHECK(gds_server_set_peer_servers(s, p, 2) == GDS_OK);
    /* the request carries our EndpointUrl: only our own entry mirrors it */
    if(CHECK(find(url, NULL, &out, &n) == UA_STATUSCODE_GOOD) && CHECK_EQ_INT(n, 3)) {
        CHECK(uri_is(&out[0], TEST_URI) && has_url(&out[0], url));
        CHECK(uri_is(&out[1], PEER_B) && out[1].discoveryUrlsSize == 1 &&
              has_url(&out[1], "opc.tcp://node-b:4840"));
        CHECK(uri_is(&out[2], PEER_C) && out[2].discoveryUrlsSize == 1 &&
              has_url(&out[2], "opc.tcp://node-c:4840"));
    }
    free_found(&out, &n);
}

static void test_filter(const char *url) {
    UA_ApplicationDescription *out = NULL;
    size_t n = 0;
    /* serverUris filter: one peer, or only itself */
    if(CHECK(find(url, PEER_C, &out, &n) == UA_STATUSCODE_GOOD))
        CHECK(n == 1 && uri_is(&out[0], PEER_C) && has_url(&out[0], "opc.tcp://node-c:4840"));
    free_found(&out, &n);
    if(CHECK(find(url, TEST_URI, &out, &n) == UA_STATUSCODE_GOOD))
        CHECK(n == 1 && uri_is(&out[0], TEST_URI));
    free_found(&out, &n);
}

static void test_replace(gds_server *s, const char *url) {
    UA_ApplicationDescription *out = NULL;
    size_t n = 0;
    UA_String uc = UA_STRING("opc.tcp://node-c:4840");
    UA_ApplicationDescription p;
    peer(&p, PEER_C, &uc);
    /* the set shrank: replaced, then cleared */
    CHECK(gds_server_set_peer_servers(s, &p, 1) == GDS_OK);
    if(CHECK(find(url, NULL, &out, &n) == UA_STATUSCODE_GOOD))
        CHECK(n == 2 && uri_is(&out[1], PEER_C));
    free_found(&out, &n);
    CHECK(gds_server_set_peer_servers(s, NULL, 0) == GDS_OK);
    if(CHECK(find(url, NULL, &out, &n) == UA_STATUSCODE_GOOD))
        CHECK_EQ_INT(n, 1);
    free_found(&out, &n);
}

static void test_served(gds_server *s, UA_UInt16 port) {
    char url[64];
    (void)snprintf(url, sizeof(url), "opc.tcp://127.0.0.1:%u", (unsigned)port);
    test_alone(url);
    test_with_peers(s, url);
    test_filter(url);
    test_replace(s, url);
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

    static uint8_t pw[] = "peers-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    gds_store *st = NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS test")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    if(!CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) || !CHECK(gds_store_open(db, &st) == GDS_OK) ||
       !CHECK(UA_CreateCertificate(UA_Log_Stdout, subject, 1, san, 2, UA_CERTIFICATEFORMAT_DER,
                                   NULL, &key, &cert) == UA_STATUSCODE_GOOD))
        return CHECK_DONE();

    static gds_users users;
    UA_UInt16 port = (UA_UInt16)(49000 + getpid() % 1000);
    gds_server_config cfg = {0};
    cfg.port = port;
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS peers test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;

    gds_server *s = NULL;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s) {
        test_refusals(s);
        pthread_t loop;
        if(CHECK(pthread_create(&loop, NULL, loop_main, s) == 0)) {
            test_served(s, port);
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
    return CHECK_DONE();
}
