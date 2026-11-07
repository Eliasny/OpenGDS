/* OpenGDS unit test: X.509 user certificates as user identity (UASM ask
 * A11, issue #68). Real clients over SignAndEncrypt activate sessions with
 * X509IdentityTokens (OPC 10000-4 §7.40.5). The server checks them against
 * the DefaultUserTokenGroup trust list (OPC 10000-12 §7.8.3.3), and the
 * users file maps each certificate, by SHA-256 thumbprint, to a user and
 * its Roles.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/nodeids.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <openssl/evp.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "gds_internal.h"
#include "gds_plugin.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:x509users"
#define CLIENT_URI "urn:opengds:test:x509users:client"
#define ADMIN_NS "urn:opengds:test:admin"
#define PASSWORD "x509-users-test-pw"
#define OBJ 1
#define SWITCHOVER 2

static UA_UInt16 ns;
static int calls;
static char lastUser[GDS_MAX_USER_NAME + 1];
static pthread_mutex_t lastLock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    UA_ByteString cert, key;
} pair;

/* ---- the plugin: a SecurityAdmin method, as uasmctl switchover ---- */

static UA_StatusCode switchover(void *ctx, const gds_caller *c, const UA_NodeId *objectId,
                                size_t nIn, const UA_Variant *in, size_t nOut, UA_Variant *out) {
    (void)ctx, (void)objectId, (void)nIn, (void)in, (void)nOut, (void)out;
    pthread_mutex_lock(&lastLock);
    (void)snprintf(lastUser, sizeof(lastUser), "%s", c->userName ? c->userName : "");
    pthread_mutex_unlock(&lastLock);
    __atomic_add_fetch(&calls, 1, __ATOMIC_SEQ_CST);
    return UA_STATUSCODE_GOOD;
}

static void setup(gds_server *s) {
    CHECK(gds_server_add_namespace(s, ADMIN_NS, &ns) == GDS_OK);
    UA_NodeId objects = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    UA_NodeId obj = UA_NODEID_NUMERIC(ns, OBJ);
    CHECK(gds_server_add_object(s, &obj, &objects, "Cluster", NULL) == GDS_OK);
    UA_NodeId admin = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN);
    gds_method_def d;
    memset(&d, 0, sizeof(d));
    d.abi_major = GDS_PLUGIN_ABI_MAJOR;
    d.abi_minor = GDS_PLUGIN_ABI_MINOR;
    d.struct_size = sizeof(d);
    d.methodId = UA_NODEID_NUMERIC(ns, SWITCHOVER);
    d.parentId = obj;
    d.browseName = "Switchover";
    d.roles = &admin;
    d.rolesSize = 1;
    d.fn = switchover;
    CHECK(gds_server_add_method(s, &d) == GDS_OK);
}

/* ---- the server thread ---- */

static UA_Boolean running = true;

static void *loop_main(void *arg) {
    CHECK(gds_server_run(arg, &running) == GDS_OK);
    return NULL;
}

/* UA_Server_run reads *running without atomics, so the flag is cleared on
 * the server thread itself, from a callback. */
static void stop_cb(UA_Server *ua, void *data) {
    (void)ua;
    *(UA_Boolean *)data = false;
}

/* ---- certificates and clients ---- */

static bool make_cert(const char *cn, const char *uri, pair *p) {
    UA_String subject[] = {UA_STRING((char *)(uintptr_t)cn), UA_STRING_STATIC("O=OpenGDS")};
    UA_String san[] = {UA_STRING((char *)(uintptr_t)uri), UA_STRING_STATIC("DNS:localhost")};
    return UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER,
                                NULL, &p->key, &p->cert) == UA_STATUSCODE_GOOD;
}

static void pair_clear(pair *p) {
    UA_ByteString_clear(&p->cert);
    UA_ByteString_clear(&p->key);
}

static bool thumbprint_hex(const UA_ByteString *der, char *out, size_t outLen) {
    uint8_t md[32];
    unsigned len = 0;
    return EVP_Digest(der->data, der->length, md, &len, EVP_sha256(), NULL) == 1 &&
           len == sizeof(md) && gds_hex(md, sizeof(md), out, outLen) == GDS_OK;
}

static UA_Client *new_client(const pair *app, UA_ByteString *serverCert) {
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    if(UA_ClientConfig_setDefault(&cfg) != UA_STATUSCODE_GOOD ||
       UA_ClientConfig_setDefaultEncryption(&cfg, app->cert, app->key, serverCert, 1, NULL, 0) !=
           UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    cfg.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    UA_String_clear(&cfg.securityPolicyUri);
    cfg.securityPolicyUri =
        UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    UA_String_clear(&cfg.clientDescription.applicationUri);
    cfg.clientDescription.applicationUri = UA_STRING_ALLOC(CLIENT_URI);
    UA_Client *c = UA_Client_newWithConfig(&cfg);
    if(!c)
        UA_ClientConfig_clear(&cfg);
    return c;
}

/* Signs in with a user certificate (the key may be the wrong one), or
 * with the password user when user is NULL, and calls Switchover. The
 * result is that of the first step that failed. */
static UA_StatusCode switch_as(const char *url, const pair *app, UA_ByteString *serverCert,
                               const UA_ByteString *userCert, const UA_ByteString *userKey) {
    UA_Client *c = new_client(app, serverCert);
    if(!c)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(userCert)
        r = UA_ClientConfig_setAuthenticationCert(UA_Client_getConfig(c), *userCert, *userKey);
    if(r == UA_STATUSCODE_GOOD)
        r = userCert ? UA_Client_connect(c, url) : UA_Client_connectUsername(c, url, "pw", PASSWORD);
    if(r == UA_STATUSCODE_GOOD) {
        size_t nOut = 0;
        UA_Variant *out = NULL;
        r = UA_Client_call(c, UA_NODEID_NUMERIC(ns, OBJ), UA_NODEID_NUMERIC(ns, SWITCHOVER), 0,
                           NULL, &nOut, &out);
        UA_Array_delete(out, nOut, &UA_TYPES[UA_TYPES_VARIANT]);
        (void)UA_Client_disconnect(c);
    }
    UA_Client_delete(c);
    return r;
}

static bool last_user_is(const char *name) {
    pthread_mutex_lock(&lastLock);
    bool eq = strcmp(lastUser, name) == 0;
    lastUser[0] = '\0';
    pthread_mutex_unlock(&lastLock);
    return eq;
}

/* ---- users ---- */

static bool write_file(const char *path, const char *text) {
    return CHECK(gds_file_write_atomic(path, text, strlen(text), 0600) == GDS_OK);
}

static bool users_text(const pair *admin, const pair *untrusted, char *out, size_t outLen) {
    char cred[256], a[65], u[65];
    static const uint8_t pw[] = PASSWORD;
    if(!CHECK(gds_password_hash(pw, sizeof(pw) - 1, 10000, cred, sizeof(cred)) == GDS_OK) ||
       !CHECK(thumbprint_hex(&admin->cert, a, sizeof(a))) ||
       !CHECK(thumbprint_hex(&untrusted->cert, u, sizeof(u))))
        return false;
    int n = snprintf(out, outLen,
                     "pw SecurityAdmin %s\n"
                     "admin SecurityAdmin,Operator x509-sha256:%s\n"
                     "untrusted SecurityAdmin x509-sha256:%s\n",
                     cred, a, u);
    return CHECK(n > 0 && (size_t)n < outLen);
}

static void test_users_file(const char *dir, const pair *admin) {
    char path[1024], line[256], a[65];
    if(!CHECK(gds_path(path, sizeof(path), "%s/users-bad", dir) == GDS_OK) ||
       !CHECK(thumbprint_hex(&admin->cert, a, sizeof(a))))
        return;
    gds_users u;
    /* one certificate names one user */
    (void)snprintf(line, sizeof(line), "a - x509-sha256:%s\nb - x509-sha256:%s\n", a, a);
    if(write_file(path, line))
        CHECK(gds_users_load(path, &u) == GDS_EEXISTS);
    static const char *const bad[] = {"a - x509-sha256:00\n", "a - x509-sha256:\n",
                                      "a - x509-sha1:00112233445566778899aabbccddeeff00112233\n"};
    for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        if(write_file(path, bad[i]))
            CHECK(gds_users_load(path, &u) == GDS_EINVAL);
    /* a certificate user has no password */
    (void)snprintf(line, sizeof(line), "a Operator x509-sha256:%s\n", a);
    if(write_file(path, line) && CHECK(gds_users_load(path, &u) == GDS_OK)) {
        CHECK(u.users[0].x509);
        UA_String name = UA_STRING_STATIC("a");
        UA_ByteString empty = UA_BYTESTRING_NULL;
        CHECK(gds_users_check(&u, &name, &empty) == NULL);
        CHECK(gds_users_check_cert(&u, &admin->cert) == &u.users[0]);
    }
    (void)unlink(path);
}

/* An expired X.509 session keeps only the Anonymous Role (§7.40.5). */
static void test_expiry(void) {
    gds_session s;
    memset(&s, 0, sizeof(s));
    s.roles = GDS_ROLE_SECURITY_ADMIN;
    s.notAfter = UA_DateTime_now() + UA_DATETIME_SEC * 3600;
    CHECK(gds_session_has(&s, GDS_ROLE_SECURITY_ADMIN));
    CHECK(!gds_session_anonymous(&s));
    s.notAfter = UA_DateTime_now() - UA_DATETIME_SEC;
    CHECK(!gds_session_has(&s, GDS_ROLE_SECURITY_ADMIN));
    CHECK(gds_session_anonymous(&s));
    CHECK_EQ_INT(gds_session_roles(&s), 0);
}

/* ---- servers ---- */

typedef struct {
    gds_store *store;
    gds_ca *ca;
    pair own, app, admin, stranger, untrusted;
} fixture;

static gds_server *new_server(fixture *f, gds_users *users, UA_UInt16 port, const char *pki) {
    gds_server_config cfg = {0};
    cfg.port = port;
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS X.509 users test";
    cfg.ownCert = (gds_buf){f->own.cert.data, f->own.cert.length};
    cfg.ownKey = (gds_buf){f->own.key.data, f->own.key.length};
    cfg.userPkiDir = pki;
    cfg.store = f->store;
    cfg.ca = f->ca;
    cfg.users = users;
    cfg.approval = GDS_APPROVE_ALL;
    gds_server *s = NULL;
    return CHECK(gds_server_new(&cfg, &s) == GDS_OK) ? s : NULL;
}

/* Trusts the admin's and the stranger's certificates, not "untrusted". */
static bool trust(const char *pki, fixture *f) {
    char dir[1024], path[1024];
    if(!CHECK(gds_path(dir, sizeof(dir), "%s/UserTokenCerts/trusted/certs", pki) == GDS_OK) ||
       !CHECK(gds_mkdirs(dir, 0700) == GDS_OK))
        return false;
    const pair *t[] = {&f->admin, &f->stranger};
    for(size_t i = 0; i < 2; i++)
        if(!CHECK(gds_path(path, sizeof(path), "%s/user%zu.der", dir, i) == GDS_OK) ||
           !CHECK(gds_file_write_atomic(path, t[i]->cert.data, t[i]->cert.length, 0600) == GDS_OK))
            return false;
    return true;
}

/* The server thread opens its socket a little after it starts: wait for
 * it (up to 10 s), or the first connect can be refused on a slow host. */
static bool wait_listening(UA_UInt16 port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for(int i = 0; i < 200; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        bool up = fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0;
        if(fd >= 0)
            (void)close(fd);
        if(up)
            return true;
        (void)usleep(50000);
    }
    return false;
}

static void serve(fixture *f, gds_server *s, UA_UInt16 port, bool x509) {
    setup(s);
    running = true;
    pthread_t loop;
    if(!CHECK(pthread_create(&loop, NULL, loop_main, s) == 0))
        return;
    char url[64];
    (void)snprintf(url, sizeof(url), "opc.tcp://127.0.0.1:%u", (unsigned)port);
    CHECK(wait_listening(port));
    UA_ByteString *sc = &f->own.cert;
    if(x509) {
        /* the admin's certificate gives the admin's Roles */
        CHECK_EQ_INT(switch_as(url, &f->app, sc, &f->admin.cert, &f->admin.key),
                     UA_STATUSCODE_GOOD);
        CHECK(last_user_is("admin"));
        /* trusted, but in no users file entry */
        CHECK_EQ_INT(switch_as(url, &f->app, sc, &f->stranger.cert, &f->stranger.key),
                     UA_STATUSCODE_BADUSERACCESSDENIED);
        /* in the users file, but not in the trust list */
        CHECK_EQ_INT(switch_as(url, &f->app, sc, &f->untrusted.cert, &f->untrusted.key),
                     UA_STATUSCODE_BADIDENTITYTOKENREJECTED);
        /* the admin's certificate with another key: userTokenSignature fails */
        CHECK_EQ_INT(switch_as(url, &f->app, sc, &f->admin.cert, &f->stranger.key),
                     UA_STATUSCODE_BADUSERSIGNATUREINVALID);
        CHECK_EQ_INT(__atomic_load_n(&calls, __ATOMIC_SEQ_CST), 1);
    } else {
        /* no user certificate trust list: no X.509 user tokens */
        CHECK(switch_as(url, &f->app, sc, &f->admin.cert, &f->admin.key) != UA_STATUSCODE_GOOD);
    }
    /* the password user is unchanged */
    CHECK_EQ_INT(switch_as(url, &f->app, sc, NULL, NULL), UA_STATUSCODE_GOOD);
    CHECK(last_user_is("pw"));
    (void)UA_Server_addTimedCallback(gds_server_ua(s), stop_cb, &running,
                                     UA_DateTime_nowMonotonic(), NULL);
    (void)pthread_join(loop, NULL);
}

static void test_served(fixture *f, const char *dir) {
    static gds_users users;
    char text[1024], path[1024], pki[1024];
    if(!users_text(&f->admin, &f->untrusted, text, sizeof(text)) ||
       !CHECK(gds_path(path, sizeof(path), "%s/users", dir) == GDS_OK) ||
       !write_file(path, text) || !CHECK(gds_users_load(path, &users) == GDS_OK) ||
       !CHECK(gds_path(pki, sizeof(pki), "%s/pki", dir) == GDS_OK) || !trust(pki, f))
        return;
    UA_UInt16 port = (UA_UInt16)(50000 + getpid() % 1000);
    gds_server *s = new_server(f, &users, port, pki);
    if(s)
        serve(f, s, port, true);
    gds_server_delete(s);
    port = (UA_UInt16)(51000 + getpid() % 1000);
    s = new_server(f, &users, port, NULL);
    if(s)
        serve(f, s, port, false);
    gds_server_delete(s);
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    /* clients and server share this process (see test_audit.c) */
    CHECK(setenv("TZ", "UTC", 1) == 0);
    tzset();
    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);

    static uint8_t pw[] = "x509-users-ca-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    fixture f;
    memset(&f, 0, sizeof(f));
    if(CHECK(gds_ca_openssl_open(&cc, &f.ca) == GDS_OK) &&
       CHECK(gds_store_open(db, &f.store) == GDS_OK) &&
       CHECK(make_cert("CN=OpenGDS X.509 users test", "URI:" TEST_URI, &f.own)) &&
       CHECK(make_cert("CN=Client", "URI:" CLIENT_URI, &f.app)) &&
       CHECK(make_cert("CN=Admin", "URI:urn:opengds:test:user:admin", &f.admin)) &&
       CHECK(make_cert("CN=Stranger", "URI:urn:opengds:test:user:stranger", &f.stranger)) &&
       CHECK(make_cert("CN=Untrusted", "URI:urn:opengds:test:user:untrusted", &f.untrusted))) {
        test_users_file(argv[1], &f.admin);
        test_expiry();
        test_served(&f, argv[1]);
    }
    pair *all[] = {&f.own, &f.app, &f.admin, &f.stranger, &f.untrusted};
    for(size_t i = 0; i < 5; i++)
        pair_clear(all[i]);
    gds_store_close(f.store);
    gds_ca_close(f.ca);
    return CHECK_DONE();
}
