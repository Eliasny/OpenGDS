/* OpenGDS unit test: embedder address space and plugin methods (UASM ask
 * A5, issue #16). Methods added or bound through gds_plugin.h run on the
 * plugin worker pool, never on the thread that runs the server loop; they
 * get the access checks (Roles, Privileges, security mode, standby) and
 * open62541's argument checks (OPC 10000-4 §5.11.2) before the callback.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "common/ua_args.h"
#include "gds_internal.h"
#include "gds_plugin.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:embed"
#define EMBED_NS "urn:opengds:test:embedder"
#define PRIV_X "urn:opengds:test:embedder#X"
#define MAX_ECHO 16

static pthread_t loopThread;
static int echoCalls;
static bool echoOffLoop = true;

static bool own_cert(UA_ByteString *cert, UA_ByteString *key) {
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS test"), UA_STRING_STATIC("O=OpenGDS")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    return UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER,
                                NULL, key, cert) == UA_STATUSCODE_GOOD;
}

/* Echo(String) -> String, at most MAX_ECHO bytes. */
static UA_StatusCode echo(void *ctx, const gds_caller *c, const UA_NodeId *objectId,
                          size_t inputSize, const UA_Variant *input, size_t outputSize,
                          UA_Variant *output) {
    (void)ctx, (void)c, (void)objectId;
    __atomic_add_fetch(&echoCalls, 1, __ATOMIC_RELAXED);
    if(pthread_equal(pthread_self(), loopThread))
        echoOffLoop = false;
    const UA_String *in = NULL;
    if(inputSize != 1 || outputSize != 1)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_StatusCode r = gds_arg_string(&input[0], MAX_ECHO, &in);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    return UA_Variant_setScalarCopy(&output[0], in, &UA_TYPES[UA_TYPES_STRING]);
}

static gds_status grant_x(void *ctx, const gds_caller *c, gds_privilege_set *set) {
    (void)ctx;
    return c->userName && strcmp(c->userName, "bob") == 0 ? gds_privilege_set_add(set, PRIV_X)
                                                          : GDS_OK;
}

/* ---- calling through the server loop ---- */

typedef struct {
    bool done;
    UA_StatusCode status;
    UA_String out;
} call_result;

static void on_result(UA_Server *server, void *ctx, const UA_CallMethodResult *r) {
    (void)server;
    call_result *cr = ctx;
    cr->done = true;
    cr->status = r->statusCode;
    if(r->statusCode == UA_STATUSCODE_GOOD && r->outputArgumentsSize == 1 &&
       UA_Variant_hasScalarType(&r->outputArguments[0], &UA_TYPES[UA_TYPES_STRING]))
        (void)UA_String_copy(r->outputArguments[0].data, &cr->out);
}

/* Calls as `sess` (the local session's context) and runs the loop on this
 * thread until the answer arrives. */
static UA_StatusCode call(gds_server *s, gds_session *sess, const UA_NodeId *obj,
                          const UA_NodeId *method, const UA_Variant *in, size_t nIn,
                          UA_String *out) {
    UA_Server *ua = gds_server_ua(s);
    UA_Server_setAdminSessionContext(ua, sess);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = *obj;
    req.methodId = *method;
    req.inputArguments = (UA_Variant *)(uintptr_t)in;
    req.inputArgumentsSize = nIn;
    call_result cr = {false, 0, UA_STRING_NULL};
    UA_StatusCode r = UA_Server_call_async(ua, &req, on_result, &cr, 0);
    for(int i = 0; r == UA_STATUSCODE_GOOD && !cr.done && i < 2000; i++)
        (void)UA_Server_run_iterate(ua, true);
    UA_Server_setAdminSessionContext(ua, NULL);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(!cr.done)
        return UA_STATUSCODE_BADTIMEOUT;
    if(out)
        *out = cr.out;
    else
        UA_String_clear(&cr.out);
    return cr.status;
}

static gds_method_def echo_def(UA_UInt16 ns, UA_UInt32 id, const char *name) {
    static UA_Argument in, out;
    UA_Argument_init(&in);
    in.name = UA_STRING("Text");
    in.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
    in.valueRank = UA_VALUERANK_SCALAR;
    out = in;
    gds_method_def d;
    memset(&d, 0, sizeof(d));
    d.abi_major = GDS_PLUGIN_ABI_MAJOR;
    d.abi_minor = GDS_PLUGIN_ABI_MINOR;
    d.struct_size = sizeof(d);
    d.methodId = UA_NODEID_NUMERIC(ns, id);
    d.parentId = UA_NODEID_NUMERIC(ns, 1);
    d.browseName = name;
    d.inputArguments = &in;
    d.inputArgumentsSize = 1;
    d.outputArguments = &out;
    d.outputArgumentsSize = 1;
    d.fn = echo;
    return d;
}

static UA_NodeId sksAdmin(void) {
    return UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYKEYSERVERADMIN);
}

/* ---- registration ---- */

static UA_UInt16 setup(gds_server *s) {
    UA_UInt16 ns = 0;
    CHECK(gds_server_add_namespace(s, EMBED_NS, &ns) == GDS_OK && ns > 1);
    UA_UInt16 again = 0;
    CHECK(gds_server_add_namespace(s, EMBED_NS, &again) == GDS_OK && again == ns);
    CHECK(gds_server_add_namespace(s, "http://opcfoundation.org/UA/GDS/", &again) == GDS_EDENIED);
    UA_NodeId obj = UA_NODEID_NUMERIC(ns, 1), objects = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    CHECK(gds_server_add_object(s, &obj, &objects, "Embedder", NULL) == GDS_OK);
    CHECK(gds_server_add_object(s, &obj, &objects, "Embedder", NULL) == GDS_EEXISTS);

    UA_NodeId roles[] = {sksAdmin()};
    gds_method_def d = echo_def(ns, 10, "Echo");
    d.roles = roles;
    d.rolesSize = 1;
    CHECK(gds_server_add_method(s, &d) == GDS_OK);
    CHECK(gds_server_add_method(s, &d) == GDS_EEXISTS);

    gds_method_def p = echo_def(ns, 11, "EchoX");
    static const char *const privs[] = {PRIV_X};
    p.privileges = privs;
    p.privilegesSize = 1;
    CHECK(gds_server_add_method(s, &p) == GDS_OK);

    gds_method_def r = echo_def(ns, 12, "EchoReadOnly");
    r.roles = roles;
    r.rolesSize = 1;
    r.flags = GDS_METHOD_READ_ONLY;
    CHECK(gds_server_add_method(s, &r) == GDS_OK);

    gds_method_def sign = echo_def(ns, 13, "EchoSign");
    UA_NodeId anon = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS);
    sign.roles = &anon;
    sign.rolesSize = 1;
    sign.minSecurityMode = GDS_SECURITY_MODE_SIGN;
    CHECK(gds_server_add_method(s, &sign) == GDS_OK);

    /* refused definitions */
    gds_method_def bad = echo_def(ns, 20, "Bad");
    CHECK(gds_server_add_method(s, &bad) == GDS_EINVAL); /* nobody could call it */
    UA_NodeId unknownRole = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    bad.roles = &unknownRole;
    bad.rolesSize = 1;
    CHECK(gds_server_add_method(s, &bad) == GDS_EINVAL);
    bad.roles = roles;
    bad.abi_major = GDS_PLUGIN_ABI_MAJOR + 1;
    CHECK(gds_server_add_method(s, &bad) == GDS_EINVAL);
    bad.abi_major = GDS_PLUGIN_ABI_MAJOR;
    bad.fn = NULL;
    CHECK(gds_server_add_method(s, &bad) == GDS_EINVAL);
    bad.fn = echo;
    bad.flags = 0x80;
    CHECK(gds_server_add_method(s, &bad) == GDS_EINVAL);
    bad.flags = 0;
    bad.browseName = "";
    CHECK(gds_server_add_method(s, &bad) == GDS_EINVAL);
    bad.browseName = "Bad";
    bad.parentId = UA_NODEID_NUMERIC(ns, 999);
    CHECK(gds_server_add_method(s, &bad) == GDS_ENOTFOUND);
    CHECK(gds_embed_find(s, &bad.methodId) == NULL);
    return ns;
}

static void test_bind(gds_server *s, UA_UInt16 ns) {
    gds_session sec = {0};
    sec.roles = GDS_ROLE_SKS_ADMIN;
    sec.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    UA_NodeId roles[] = {sksAdmin()};

    /* namespace 0: this build has no PublishSubscribe object, so the
     * embedder adds it and the OPC 10000-14 GetSecurityKeys method (as a
     * NodeSet would), then binds it; offered only once bound */
    UA_NodeId server = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    UA_NodeId pubsub = UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE);
    UA_NodeId gsk = UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_GETSECURITYKEYS);
    gds_method_def d = echo_def(0, UA_NS0ID_PUBLISHSUBSCRIBE_GETSECURITYKEYS, NULL);
    d.roles = roles;
    d.rolesSize = 1;
    CHECK(gds_server_bind_method(s, &d) == GDS_ENOTFOUND);
    CHECK(gds_server_add_object(s, &pubsub, &server, "PublishSubscribe", NULL) == GDS_OK);
    UA_MethodAttributes gma = UA_MethodAttributes_default;
    gma.executable = true;
    CHECK(UA_Server_addMethodNode(gds_server_ua(s), gsk, pubsub,
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                  UA_QUALIFIEDNAME(0, "GetSecurityKeys"), gma, NULL, 0, NULL, 0,
                                  NULL, NULL, NULL) == UA_STATUSCODE_GOOD);
    CHECK(!gds_method_executable(s, &sec, &gsk));
    CHECK(gds_server_bind_method(s, &d) == GDS_OK);
    CHECK(gds_method_executable(s, &sec, &gsk));
    CHECK(gds_server_bind_method(s, &d) == GDS_EEXISTS);

    /* a NodeSet method stays closed until bound */
    UA_MethodAttributes ma = UA_MethodAttributes_default;
    ma.executable = true;
    UA_NodeId loose = UA_NODEID_NUMERIC(ns, 30);
    CHECK(UA_Server_addMethodNode(gds_server_ua(s), loose, UA_NODEID_NUMERIC(ns, 1),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                  UA_QUALIFIEDNAME(ns, "Loose"), ma, NULL, 0, NULL, 0, NULL,
                                  NULL, NULL) == UA_STATUSCODE_GOOD);
    CHECK(!gds_method_executable(s, &sec, &loose));
    d.methodId = loose;
    CHECK(gds_server_bind_method(s, &d) == GDS_OK);
    CHECK(gds_method_executable(s, &sec, &loose));

    /* never the GDS's own methods; only method nodes */
    d.methodId = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_FINDAPPLICATIONS);
    CHECK(gds_server_bind_method(s, &d) == GDS_EDENIED);
    d.methodId = UA_NODEID_NUMERIC(ns, 1);
    CHECK(gds_server_bind_method(s, &d) == GDS_EINVAL);
    d.methodId = UA_NODEID_NUMERIC(ns, 4040);
    CHECK(gds_server_bind_method(s, &d) == GDS_ENOTFOUND);
}

/* ---- calls ---- */

static void test_access(gds_server *s, UA_UInt16 ns) {
    gds_session anon = {0}, sks = {0}, bob = {0}, eve = {0};
    anon.anonymous = true;
    anon.securityMode = sks.securityMode = bob.securityMode = eve.securityMode =
        UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    memcpy(sks.user, "sks", 4);
    sks.roles = GDS_ROLE_SKS_ADMIN;
    memcpy(bob.user, "bob", 4);
    memcpy(eve.user, "eve", 4);
    eve.roles = GDS_ROLE_SECURITY_ADMIN | GDS_ROLE_SKS_ACCESS;

    UA_NodeId obj = UA_NODEID_NUMERIC(ns, 1);
    UA_NodeId m = UA_NODEID_NUMERIC(ns, 10), mx = UA_NODEID_NUMERIC(ns, 11);
    UA_String hello = UA_STRING_STATIC("hello");
    UA_Variant in;
    UA_Variant_setScalar(&in, &hello, &UA_TYPES[UA_TYPES_STRING]);

    /* the Role: SecurityKeyServerAdmin only */
    UA_String out = UA_STRING_NULL;
    CHECK_EQ_INT(call(s, &sks, &obj, &m, &in, 1, &out), UA_STATUSCODE_GOOD);
    CHECK(UA_String_equal(&out, &hello));
    UA_String_clear(&out);
    int before = echoCalls;
    CHECK_EQ_INT(call(s, &anon, &obj, &m, &in, 1, NULL), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(call(s, &eve, &obj, &m, &in, 1, NULL), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(call(s, NULL, &obj, &m, &in, 1, NULL), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(echoCalls, before); /* the callback never ran */
    CHECK(!gds_method_executable(s, &eve, &m));
    CHECK(gds_method_executable(s, &sks, &m));

    /* the Privilege: granted by a provider on the worker */
    CHECK_EQ_INT(call(s, &bob, &obj, &mx, &in, 1, NULL), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(call(s, &sks, &obj, &mx, &in, 1, NULL), UA_STATUSCODE_BADUSERACCESSDENIED);

    /* the security mode */
    UA_NodeId ms = UA_NODEID_NUMERIC(ns, 13);
    gds_session none = anon;
    none.securityMode = UA_MESSAGESECURITYMODE_NONE;
    CHECK_EQ_INT(call(s, &anon, &obj, &ms, &in, 1, NULL), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(call(s, &none, &obj, &ms, &in, 1, NULL), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK(!gds_method_executable(s, &none, &ms));
    CHECK(echoOffLoop);
}

static void test_arguments(gds_server *s, UA_UInt16 ns) {
    gds_session sks = {0};
    sks.roles = GDS_ROLE_SKS_ADMIN;
    sks.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    UA_NodeId obj = UA_NODEID_NUMERIC(ns, 1), m = UA_NODEID_NUMERIC(ns, 10);
    UA_Int32 wrong = 7;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &wrong, &UA_TYPES[UA_TYPES_INT32]);
    int before = echoCalls;
    /* open62541 checks count and type before the callback (Part 4 §5.11.2) */
    UA_StatusCode r = call(s, &sks, &obj, &m, in, 1, NULL);
    CHECK(r == UA_STATUSCODE_BADINVALIDARGUMENT || r == UA_STATUSCODE_BADTYPEMISMATCH);
    CHECK_EQ_INT(call(s, &sks, &obj, &m, in, 0, NULL), UA_STATUSCODE_BADARGUMENTSMISSING);
    UA_String t = UA_STRING_STATIC("t");
    UA_Variant_setScalar(&in[0], &t, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &t, &UA_TYPES[UA_TYPES_STRING]);
    CHECK_EQ_INT(call(s, &sks, &obj, &m, in, 2, NULL), UA_STATUSCODE_BADTOOMANYARGUMENTS);
    CHECK_EQ_INT(echoCalls, before);
    /* the callback's own limit, through gds_arg_string */
    UA_String big = UA_STRING_STATIC("longer than sixteen bytes");
    UA_Variant_setScalar(&in[0], &big, &UA_TYPES[UA_TYPES_STRING]);
    CHECK_EQ_INT(call(s, &sks, &obj, &m, in, 1, NULL), UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
}

static void test_standby(gds_server *s, UA_UInt16 ns) {
    gds_session sks = {0};
    sks.roles = GDS_ROLE_SKS_ADMIN;
    sks.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    UA_NodeId obj = UA_NODEID_NUMERIC(ns, 1);
    UA_NodeId m = UA_NODEID_NUMERIC(ns, 10), ro = UA_NODEID_NUMERIC(ns, 12);
    UA_String t = UA_STRING_STATIC("t");
    UA_Variant in;
    UA_Variant_setScalar(&in, &t, &UA_TYPES[UA_TYPES_STRING]);
    CHECK(gds_server_set_role(s, GDS_NODE_STANDBY, 150, 0) == GDS_OK);
    CHECK_EQ_INT(call(s, &sks, &obj, &m, &in, 1, NULL), UA_STATUSCODE_BADINVALIDSTATE);
    CHECK_EQ_INT(call(s, &sks, &obj, &ro, &in, 1, NULL), UA_STATUSCODE_GOOD);
    CHECK(gds_server_set_role(s, GDS_NODE_STANDALONE, 255, 0) == GDS_OK);
    CHECK_EQ_INT(call(s, &sks, &obj, &m, &in, 1, NULL), UA_STATUSCODE_GOOD);
}

/* Many calls at once, then shutdown with calls in flight (ASan/TSan). */
static void test_load(gds_server *s, UA_UInt16 ns) {
    static gds_session sks;
    sks.roles = GDS_ROLE_SKS_ADMIN;
    sks.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    UA_Server *ua = gds_server_ua(s);
    UA_String t = UA_STRING_STATIC("t");
    UA_Variant in;
    UA_Variant_setScalar(&in, &t, &UA_TYPES[UA_TYPES_STRING]);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = UA_NODEID_NUMERIC(ns, 1);
    req.methodId = UA_NODEID_NUMERIC(ns, 10);
    req.inputArguments = &in;
    req.inputArgumentsSize = 1;
    static call_result rs[64];
    UA_Server_setAdminSessionContext(ua, &sks);
    for(size_t i = 0; i < 64; i++)
        CHECK(UA_Server_call_async(ua, &req, on_result, &rs[i], 0) == UA_STATUSCODE_GOOD);
    size_t done = 0;
    for(int k = 0; k < 4000 && done < 32; k++) {
        (void)UA_Server_run_iterate(ua, true);
        done = 0;
        for(size_t i = 0; i < 64; i++)
            done += rs[i].done;
    }
    CHECK(done >= 32);
    for(size_t i = 0; i < 64; i++)
        if(rs[i].done)
            CHECK_EQ_INT(rs[i].status, UA_STATUSCODE_GOOD);
    UA_Server_setAdminSessionContext(ua, NULL);
    for(size_t i = 0; i < 64; i++)
        UA_String_clear(&rs[i].out);
    /* the rest is cancelled by gds_server_delete */
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    loopThread = pthread_self();
    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);

    static uint8_t pw[] = "embed-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    gds_store *st = NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    if(!CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) ||
       !CHECK(gds_store_open(db, &st) == GDS_OK) || !CHECK(own_cert(&cert, &key)))
        return CHECK_DONE();

    static gds_users users;
    gds_server_config cfg = {0};
    cfg.port = (UA_UInt16)(42000 + getpid() % 2000);
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS embed test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;
    gds_server *s = NULL;
    static gds_privilege_provider px = {GDS_PLUGIN_ABI_MAJOR, GDS_PLUGIN_ABI_MINOR,
                                        sizeof(gds_privilege_provider), NULL, grant_x};
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s &&
       CHECK(gds_server_add_privilege_provider(s, &px) == GDS_OK)) {
        UA_UInt16 ns = setup(s);
        test_bind(s, ns);
        if(CHECK(UA_Server_run_startup(gds_server_ua(s)) == UA_STATUSCODE_GOOD)) {
            test_access(s, ns);
            test_arguments(s, ns);
            test_standby(s, ns);
            test_load(s, ns);
            (void)UA_Server_run_shutdown(gds_server_ua(s));
        }
    }
    gds_server_delete(s);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_store_close(st);
    gds_ca_close(ca);
    return CHECK_DONE();
}
