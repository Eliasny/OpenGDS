/* OpenGDS unit test: embedder-defined grantable Roles (UASM ask A10, issue
 * #63). Two Roles as an OPC 10000-21 onboarding plugin would add them:
 * RegistrarAdmin (a new RoleType object) and SoftwareUpdateAdmin (an
 * existing object, linked into the RoleSet). The users file grants
 * RegistrarAdmin by name; real clients over SignAndEncrypt call a method
 * restricted to it and browse Server/ServerCapabilities/RoleSet.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/nodeids.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define TEST_URI "urn:opengds:test:roles"
#define CLIENT_URI "urn:opengds:test:roles:client"
#define ONB_NS "urn:opengds:test:onboarding"
#define PASSWORD "roles-pw-for-the-test"
#define OBJ 1
#define REGISTER 2
#define REGISTRAR_ROLE 10
#define UPDATE_ROLE 20

static UA_UInt16 ns;
static int calls;
static int sawRegistrar = -1, sawUpdate = -1;

/* ---- the plugin ---- */

static UA_StatusCode register_tickets(void *ctx, const gds_caller *c, const UA_NodeId *objectId,
                                      size_t nIn, const UA_Variant *in, size_t nOut,
                                      UA_Variant *out) {
    (void)ctx, (void)objectId, (void)nIn, (void)in, (void)nOut, (void)out;
    UA_NodeId reg = UA_NODEID_NUMERIC(ns, REGISTRAR_ROLE), upd = UA_NODEID_NUMERIC(ns, UPDATE_ROLE);
    __atomic_store_n(&sawRegistrar, gds_caller_has_role(c, &reg) ? 1 : 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&sawUpdate, gds_caller_has_role(c, &upd) ? 1 : 0, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&calls, 1, __ATOMIC_SEQ_CST);
    return UA_STATUSCODE_GOOD;
}

static void setup(gds_server *s) {
    CHECK(gds_server_add_namespace(s, ONB_NS, &ns) == GDS_OK);
    UA_NodeId objects = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    UA_NodeId obj = UA_NODEID_NUMERIC(ns, OBJ);
    UA_NodeId reg = UA_NODEID_NUMERIC(ns, REGISTRAR_ROLE), upd = UA_NODEID_NUMERIC(ns, UPDATE_ROLE);
    CHECK(gds_server_add_object(s, &obj, &objects, "Onboarding", NULL) == GDS_OK);
    /* as if a NodeSet had defined it: an object outside the RoleSet */
    CHECK(gds_server_add_object(s, &upd, &objects, "SoftwareUpdateAdmin", NULL) == GDS_OK);

    /* a method of an unknown Role is refused until the Role exists */
    gds_method_def d;
    memset(&d, 0, sizeof(d));
    d.abi_major = GDS_PLUGIN_ABI_MAJOR;
    d.abi_minor = GDS_PLUGIN_ABI_MINOR;
    d.struct_size = sizeof(d);
    d.methodId = UA_NODEID_NUMERIC(ns, REGISTER);
    d.parentId = obj;
    d.browseName = "RegisterTickets";
    d.roles = &reg;
    d.rolesSize = 1;
    d.fn = register_tickets;
    CHECK(gds_server_add_method(s, &d) == GDS_EINVAL);

    size_t before = gds_role_count();
    CHECK(gds_server_add_role(s, "RegistrarAdmin", &reg) == GDS_OK);
    CHECK(gds_server_add_role(s, "SoftwareUpdateAdmin", &upd) == GDS_OK);
    CHECK_EQ_INT(gds_role_count(), before + 2);

    /* refused: taken names and NodeIds, the GDS namespace, bad input */
    UA_NodeId other = UA_NODEID_NUMERIC(ns, 30);
    UA_NodeId op = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_OPERATOR);
    UA_NodeId anon = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS);
    UA_NodeId gdsRole = UA_NODEID_NUMERIC(s->ns, 99999);
    UA_NodeId status = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS); /* a Variable */
    UA_NodeId null = UA_NODEID_NULL;
    CHECK(gds_server_add_role(s, "RegistrarAdmin", &other) == GDS_EEXISTS);
    CHECK(gds_server_add_role(s, "Other", &reg) == GDS_EEXISTS);
    CHECK(gds_server_add_role(s, "Operator", &other) == GDS_EEXISTS);
    CHECK(gds_server_add_role(s, "Anonymous", &other) == GDS_EEXISTS);
    CHECK(gds_server_add_role(s, "Other", &op) == GDS_EEXISTS);
    CHECK(gds_server_add_role(s, "Other", &anon) == GDS_EEXISTS);
    CHECK(gds_server_add_role(s, "Other", &gdsRole) == GDS_EDENIED);
    CHECK(gds_server_add_role(s, "Other", &status) == GDS_EINVAL);
    CHECK(gds_server_add_role(s, "Other", &null) == GDS_EINVAL);
    CHECK(gds_server_add_role(s, "bad name", &other) == GDS_EINVAL);
    CHECK(gds_server_add_role(s, "", &other) == GDS_EINVAL);
    CHECK_EQ_INT(gds_role_count(), before + 2);

    CHECK(gds_server_add_method(s, &d) == GDS_OK);
    /* RolePermissions may name an embedder Role too */
    gds_role_permission rp[] = {{reg, UA_PERMISSIONTYPE_CALL}, {upd, UA_PERMISSIONTYPE_BROWSE}};
    CHECK(gds_server_set_role_permissions(s, &obj, rp, 2) == GDS_OK);
}

/* ---- the server thread ---- */

static UA_Boolean running = true;
static gds_status runResult = GDS_EIO;

static void *loop_main(void *arg) {
    runResult = gds_server_run(arg, &running);
    return NULL;
}

/* ---- clients ---- */

static bool make_cert(const char *cn, const char *uri, UA_ByteString *cert, UA_ByteString *key) {
    UA_String subject[] = {UA_STRING((char *)(uintptr_t)cn), UA_STRING_STATIC("O=OpenGDS")};
    UA_String san[] = {UA_STRING((char *)(uintptr_t)uri), UA_STRING_STATIC("DNS:localhost")};
    return UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER,
                                NULL, key, cert) == UA_STATUSCODE_GOOD;
}

static UA_Client *new_client(const UA_ByteString *cert, const UA_ByteString *key,
                             UA_ByteString *serverCert) {
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    if(UA_ClientConfig_setDefault(&cfg) != UA_STATUSCODE_GOOD ||
       UA_ClientConfig_setDefaultEncryption(&cfg, *cert, *key, serverCert, 1, NULL, 0) !=
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

/* Connects as user (NULL: anonymous) and calls RegisterTickets. */
static UA_StatusCode call_as(const char *user, const char *url, const UA_ByteString *cert,
                             const UA_ByteString *key, UA_ByteString *serverCert) {
    UA_Client *c = new_client(cert, key, serverCert);
    if(!c)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode r = user ? UA_Client_connectUsername(c, url, user, PASSWORD)
                           : UA_Client_connect(c, url);
    if(r == UA_STATUSCODE_GOOD) {
        size_t nOut = 0;
        UA_Variant *out = NULL;
        r = UA_Client_call(c, UA_NODEID_NUMERIC(ns, OBJ), UA_NODEID_NUMERIC(ns, REGISTER), 0,
                           NULL, &nOut, &out);
        UA_Array_delete(out, nOut, &UA_TYPES[UA_TYPES_VARIANT]);
        (void)UA_Client_disconnect(c);
    }
    UA_Client_delete(c);
    return r;
}

/* The RoleSet's components hold both Roles, RegistrarAdmin by name. */
static void browse_roleset(const char *url, const UA_ByteString *cert, const UA_ByteString *key,
                           UA_ByteString *serverCert) {
    UA_Client *c = new_client(cert, key, serverCert);
    if(!CHECK(c) || !CHECK(UA_Client_connect(c, url) == UA_STATUSCODE_GOOD)) {
        UA_Client_delete(c);
        return;
    }
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET);
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);
    bd.includeSubtypes = true;
    bd.resultMask = UA_BROWSERESULTMASK_ALL;
    UA_BrowseResult br = UA_Client_browse(c, NULL, 0, &bd);
    bool reg = false, upd = false, op = false;
    UA_NodeId regId = UA_NODEID_NUMERIC(ns, REGISTRAR_ROLE), updId = UA_NODEID_NUMERIC(ns, UPDATE_ROLE);
    UA_NodeId opId = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_OPERATOR);
    UA_String regName = UA_STRING_STATIC("RegistrarAdmin");
    for(size_t i = 0; i < br.referencesSize; i++) {
        const UA_ReferenceDescription *rd = &br.references[i];
        if(UA_NodeId_equal(&rd->nodeId.nodeId, &regId))
            reg = UA_String_equal(&rd->browseName.name, &regName) &&
                  rd->browseName.namespaceIndex == ns;
        upd = upd || UA_NodeId_equal(&rd->nodeId.nodeId, &updId);
        op = op || UA_NodeId_equal(&rd->nodeId.nodeId, &opId);
    }
    CHECK_EQ_INT(br.statusCode, UA_STATUSCODE_GOOD);
    CHECK(reg);
    CHECK(upd);
    CHECK(op); /* the well-known Roles stay */
    UA_BrowseResult_clear(&br);
    (void)UA_Client_disconnect(c);
    UA_Client_delete(c);
}

static void run_clients(gds_server *s, UA_ByteString *serverCert, const char *url) {
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    if(!CHECK(make_cert("CN=OpenGDS roles client", "URI:" CLIENT_URI, &cert, &key)))
        return;
    /* the users file grants RegistrarAdmin to reg only */
    CHECK_EQ_INT(call_as("reg", url, &cert, &key, serverCert), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(__atomic_load_n(&calls, __ATOMIC_SEQ_CST), 1);
    CHECK_EQ_INT(__atomic_load_n(&sawRegistrar, __ATOMIC_SEQ_CST), 1); /* the caller view */
    CHECK_EQ_INT(__atomic_load_n(&sawUpdate, __ATOMIC_SEQ_CST), 0);
    CHECK_EQ_INT(call_as("both", url, &cert, &key, serverCert), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(__atomic_load_n(&sawUpdate, __ATOMIC_SEQ_CST), 1);
    CHECK_EQ_INT(call_as("plain", url, &cert, &key, serverCert), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(call_as(NULL, url, &cert, &key, serverCert), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(__atomic_load_n(&calls, __ATOMIC_SEQ_CST), 2);
    browse_roleset(url, &cert, &key, serverCert);
    /* too late once the server runs */
    UA_NodeId late = UA_NODEID_NUMERIC(ns, 40);
    CHECK(gds_server_add_role(s, "Late", &late) == GDS_ESTATE);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
}

/* ---- users, servers ---- */

/* One user per entry: "<name> <roles>", all with PASSWORD. */
static bool write_users(const char *dir, const char *const *users, size_t nUsers, gds_users *u) {
    char path[1024], cred[256], text[1024];
    static const uint8_t pw[] = PASSWORD;
    if(!CHECK(gds_path(path, sizeof(path), "%s/users", dir) == GDS_OK) ||
       !CHECK(gds_password_hash(pw, sizeof(pw) - 1, 10000, cred, sizeof(cred)) == GDS_OK))
        return false;
    size_t len = 0;
    for(size_t i = 0; i < nUsers; i++) {
        int n = snprintf(text + len, sizeof(text) - len, "%s %s\n", users[i], cred);
        if(!CHECK(n > 0 && (size_t)n < sizeof(text) - len))
            return false;
        len += (size_t)n;
    }
    return CHECK(gds_file_write_atomic(path, text, len, 0600) == GDS_OK) &&
           CHECK(gds_users_load(path, u) == GDS_OK);
}

typedef struct {
    gds_store *store;
    gds_ca *ca;
    UA_ByteString cert, key;
} fixture;

static gds_server *new_server(fixture *f, gds_users *users, UA_UInt16 port) {
    gds_server_config cfg = {0};
    cfg.port = port;
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS roles test";
    cfg.ownCert = (gds_buf){f->cert.data, f->cert.length};
    cfg.ownKey = (gds_buf){f->key.data, f->key.length};
    cfg.store = f->store;
    cfg.ca = f->ca;
    cfg.users = users;
    cfg.approval = GDS_APPROVE_ALL;
    gds_server *s = NULL;
    return CHECK(gds_server_new(&cfg, &s) == GDS_OK) ? s : NULL;
}

static void test_served(fixture *f, const char *dir) {
    static gds_users users;
    static const char *const lines[] = {"reg RegistrarAdmin,Operator",
                                        "both Operator,SoftwareUpdateAdmin,RegistrarAdmin",
                                        "plain Operator"};
    if(!write_users(dir, lines, 3, &users))
        return;
    UA_UInt16 port = (UA_UInt16)(48000 + getpid() % 1000);
    gds_server *s = new_server(f, &users, port);
    if(!s)
        return;
    setup(s);
    pthread_t loop;
    if(CHECK(pthread_create(&loop, NULL, loop_main, s) == 0)) {
        char url[64];
        (void)snprintf(url, sizeof(url), "opc.tcp://127.0.0.1:%u", (unsigned)port);
        run_clients(s, &f->cert, url);
        __atomic_store_n(&running, false, __ATOMIC_SEQ_CST);
        (void)pthread_join(loop, NULL);
        CHECK_EQ_INT(runResult, GDS_OK);
    }
    gds_server_delete(s);
    /* the Roles went with the server */
    CHECK_EQ_INT(gds_role_count(), GDS_ROLE_BUILTIN_COUNT);
}

/* A users file naming a Role nobody added keeps the server from starting. */
static void test_unknown_role(fixture *f, const char *dir) {
    static gds_users users;
    static const char *const lines[] = {"x Operator,RegistrarAdmin"};
    if(!write_users(dir, lines, 1, &users))
        return;
    gds_server *s = new_server(f, &users, (UA_UInt16)(49000 + getpid() % 1000));
    UA_Boolean run = true;
    if(s)
        CHECK(gds_server_run(s, &run) == GDS_EINVAL);
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

    static uint8_t pw[] = "roles-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    fixture f = {NULL, NULL, UA_BYTESTRING_NULL, UA_BYTESTRING_NULL};
    if(CHECK(gds_ca_openssl_open(&cc, &f.ca) == GDS_OK) &&
       CHECK(gds_store_open(db, &f.store) == GDS_OK) &&
       CHECK(make_cert("CN=OpenGDS roles test", "URI:" TEST_URI, &f.cert, &f.key))) {
        test_served(&f, argv[1]);
        test_unknown_role(&f, argv[1]);
    }
    UA_ByteString_clear(&f.cert);
    UA_ByteString_clear(&f.key);
    gds_store_close(f.store);
    gds_ca_close(f.ca);
    return CHECK_DONE();
}
