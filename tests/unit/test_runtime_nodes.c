/* OpenGDS unit test: embedder nodes added and removed while the server
 * runs (UASM ask A9, issue #49). An AddGroup method, running on a plugin
 * worker, creates one group object with a Rotate method and per-group
 * RolePermissions, as OPC 10000-14 §8.5.2 AddSecurityGroup does for a
 * SecurityGroupType object; RemoveGroup deletes it again.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

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

#define TEST_URI "urn:opengds:test:runtime"
#define SKS_NS "urn:opengds:test:sks"
#define SKS_OBJ 1
#define ADD_GROUP 10
#define REMOVE_GROUP 11
#define GROUP_BASE 1000
#define ROTATE_BASE 2000

static UA_UInt16 ns;
static int rotations;
static int permittedSeen = -1;

static bool own_cert(UA_ByteString *cert, UA_ByteString *key) {
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS test"), UA_STRING_STATIC("O=OpenGDS")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    return UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER,
                                NULL, key, cert) == UA_STATUSCODE_GOOD;
}

static UA_NodeId role(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

static UA_Argument groupArg(void) {
    UA_Argument a;
    UA_Argument_init(&a);
    a.name = UA_STRING("Group");
    a.dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
    a.valueRank = UA_VALUERANK_SCALAR;
    return a;
}

static gds_method_def def(UA_UInt32 id, UA_UInt32 parent, const char *name, gds_method_fn fn,
                          void *ctx) {
    static UA_Argument in;
    in = groupArg();
    gds_method_def d;
    memset(&d, 0, sizeof(d));
    d.abi_major = GDS_PLUGIN_ABI_MAJOR;
    d.abi_minor = GDS_PLUGIN_ABI_MINOR;
    d.struct_size = sizeof(d);
    d.methodId = UA_NODEID_NUMERIC(ns, id);
    d.parentId = UA_NODEID_NUMERIC(ns, parent);
    d.browseName = name;
    d.inputArguments = &in;
    d.inputArgumentsSize = 1;
    d.fn = fn;
    d.ctx = ctx;
    return d;
}

static UA_StatusCode as_ua(gds_status st) {
    return st == GDS_OK ? UA_STATUSCODE_GOOD : gds_status_to_ua(st);
}

/* ---- the plugin's methods (plugin workers) ---- */

static UA_StatusCode rotate(void *ctx, const gds_caller *c, const UA_NodeId *objectId,
                            size_t nIn, const UA_Variant *in, size_t nOut, UA_Variant *out) {
    (void)nIn, (void)in, (void)nOut, (void)out;
    gds_server *s = ctx;
    __atomic_add_fetch(&rotations, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&permittedSeen,
                     gds_caller_permitted(s, c, objectId, UA_PERMISSIONTYPE_CALL) ? 1 : 0,
                     __ATOMIC_RELAXED);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode add_group(void *ctx, const gds_caller *c, const UA_NodeId *objectId,
                               size_t nIn, const UA_Variant *in, size_t nOut, UA_Variant *out) {
    (void)c, (void)objectId, (void)nIn, (void)nOut, (void)out;
    gds_server *s = ctx;
    UA_UInt32 g = *(const UA_UInt32 *)in[0].data;
    UA_NodeId group = UA_NODEID_NUMERIC(ns, GROUP_BASE + g);
    UA_NodeId parent = UA_NODEID_NUMERIC(ns, SKS_OBJ);
    char name[32];
    (void)snprintf(name, sizeof(name), "Group%u", (unsigned)g);
    gds_status st = gds_server_add_object(s, &group, &parent, name, NULL);
    UA_NodeId roles[] = {role(UA_NS0ID_WELLKNOWNROLE_OPERATOR),
                         role(UA_NS0ID_WELLKNOWNROLE_ENGINEER)};
    gds_method_def d = def(ROTATE_BASE + g, GROUP_BASE + g, "Rotate", rotate, s);
    d.roles = roles;
    d.rolesSize = 2;
    if(st == GDS_OK)
        st = gds_server_add_method(s, &d);
    /* the group's own RolePermissions: only Operator may Call on it */
    gds_role_permission rp = {role(UA_NS0ID_WELLKNOWNROLE_OPERATOR), UA_PERMISSIONTYPE_CALL};
    if(st == GDS_OK)
        st = gds_server_set_role_permissions(s, &group, &rp, 1);
    return as_ua(st);
}

static UA_StatusCode remove_group(void *ctx, const gds_caller *c, const UA_NodeId *objectId,
                                  size_t nIn, const UA_Variant *in, size_t nOut,
                                  UA_Variant *out) {
    (void)c, (void)objectId, (void)nIn, (void)nOut, (void)out;
    UA_NodeId group = UA_NODEID_NUMERIC(ns, GROUP_BASE + *(const UA_UInt32 *)in[0].data);
    return as_ua(gds_server_remove_node(ctx, &group));
}

/* ---- calling through the server loop (as test_embed.c) ---- */

typedef struct {
    bool done;
    UA_StatusCode status;
} call_result;

static void on_result(UA_Server *server, void *ctx, const UA_CallMethodResult *r) {
    (void)server;
    call_result *cr = ctx;
    cr->done = true;
    cr->status = r->statusCode;
}

static UA_StatusCode call(gds_server *s, gds_session *sess, UA_UInt32 obj, UA_UInt32 method,
                          UA_UInt32 group) {
    UA_Server *ua = gds_server_ua(s);
    UA_Variant in;
    UA_Variant_setScalar(&in, &group, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Server_setAdminSessionContext(ua, sess);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = UA_NODEID_NUMERIC(ns, obj);
    req.methodId = UA_NODEID_NUMERIC(ns, method);
    req.inputArguments = &in;
    req.inputArgumentsSize = 1;
    call_result cr = {false, 0};
    UA_StatusCode r = UA_Server_call_async(ua, &req, on_result, &cr, 0);
    for(int i = 0; r == UA_STATUSCODE_GOOD && !cr.done && i < 2000; i++)
        (void)UA_Server_run_iterate(ua, true);
    UA_Server_setAdminSessionContext(ua, NULL);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    return cr.done ? cr.status : UA_STATUSCODE_BADTIMEOUT;
}

/* ---- cases ---- */

static gds_session sess(unsigned roles) {
    gds_session x;
    memset(&x, 0, sizeof(x));
    x.roles = roles;
    x.anonymous = roles == 0;
    if(roles)
        memcpy(x.user, "u", 2);
    x.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    return x;
}

static void setup(gds_server *s) {
    CHECK(gds_server_add_namespace(s, SKS_NS, &ns) == GDS_OK);
    UA_NodeId obj = UA_NODEID_NUMERIC(ns, SKS_OBJ), objects = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    CHECK(gds_server_add_object(s, &obj, &objects, "Sks", NULL) == GDS_OK);
    UA_NodeId admin = role(UA_NS0ID_WELLKNOWNROLE_SECURITYKEYSERVERADMIN);
    gds_method_def a = def(ADD_GROUP, SKS_OBJ, "AddGroup", add_group, s);
    a.roles = &admin;
    a.rolesSize = 1;
    CHECK(gds_server_add_method(s, &a) == GDS_OK);
    gds_method_def r = def(REMOVE_GROUP, SKS_OBJ, "RemoveGroup", remove_group, s);
    r.roles = &admin;
    r.rolesSize = 1;
    CHECK(gds_server_add_method(s, &r) == GDS_OK);
}

static void test_group(gds_server *s) {
    gds_session admin = sess(GDS_ROLE_SKS_ADMIN), op = sess(GDS_ROLE_OPERATOR),
                eng = sess(GDS_ROLE_ENGINEER), anon = sess(0);
    UA_NodeId rot = UA_NODEID_NUMERIC(ns, ROTATE_BASE + 1);
    CHECK_EQ_INT(call(s, &op, SKS_OBJ, ADD_GROUP, 1), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(call(s, &admin, SKS_OBJ, ADD_GROUP, 1), UA_STATUSCODE_GOOD);
    CHECK(gds_embed_bound(s, &rot));
    CHECK_EQ_INT(call(s, &admin, SKS_OBJ, ADD_GROUP, 1), UA_STATUSCODE_BADALREADYEXISTS);

    /* the method allows Operator and Engineer; the group only Operator */
    CHECK_EQ_INT(call(s, &op, GROUP_BASE + 1, ROTATE_BASE + 1, 1), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(permittedSeen, 1);
    int before = rotations;
    CHECK_EQ_INT(call(s, &eng, GROUP_BASE + 1, ROTATE_BASE + 1, 1),
                 UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(call(s, &anon, GROUP_BASE + 1, ROTATE_BASE + 1, 1),
                 UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(rotations, before);

    /* changed while running: Engineer too, then no RolePermissions at all */
    UA_NodeId group = UA_NODEID_NUMERIC(ns, GROUP_BASE + 1);
    gds_role_permission rp[] = {{role(UA_NS0ID_WELLKNOWNROLE_OPERATOR), UA_PERMISSIONTYPE_CALL},
                                {role(UA_NS0ID_WELLKNOWNROLE_ENGINEER),
                                 UA_PERMISSIONTYPE_CALL | UA_PERMISSIONTYPE_BROWSE}};
    CHECK(gds_server_set_role_permissions(s, &group, rp, 2) == GDS_OK);
    CHECK_EQ_INT(call(s, &eng, GROUP_BASE + 1, ROTATE_BASE + 1, 1), UA_STATUSCODE_GOOD);
    CHECK(gds_server_set_role_permissions(s, &group, NULL, 0) == GDS_OK);
    CHECK_EQ_INT(call(s, &eng, GROUP_BASE + 1, ROTATE_BASE + 1, 1), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(call(s, &anon, GROUP_BASE + 1, ROTATE_BASE + 1, 1),
                 UA_STATUSCODE_BADUSERACCESSDENIED); /* the method's Roles still hold */

    /* removed from a worker: the method goes with its group */
    CHECK_EQ_INT(call(s, &admin, SKS_OBJ, REMOVE_GROUP, 1), UA_STATUSCODE_GOOD);
    CHECK(!gds_embed_bound(s, &rot));
    CHECK(call(s, &op, GROUP_BASE + 1, ROTATE_BASE + 1, 1) != UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(call(s, &admin, SKS_OBJ, REMOVE_GROUP, 1), UA_STATUSCODE_BADNOTFOUND);
    CHECK_EQ_INT(s->nPerms, 0);
}

static void test_refused(gds_server *s) {
    UA_NodeId server = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    UA_NodeId gdsNode = UA_NODEID_NUMERIC(s->ns, 1);
    UA_NodeId unknown = UA_NODEID_NUMERIC(ns, 99999);
    UA_NodeId obj = UA_NODEID_NUMERIC(ns, SKS_OBJ);
    CHECK(gds_server_remove_node(s, &server) == GDS_EDENIED);
    CHECK(gds_server_remove_node(s, &gdsNode) == GDS_EDENIED);
    CHECK(gds_server_remove_node(s, &unknown) == GDS_ENOTFOUND);
    gds_role_permission rp = {role(UA_NS0ID_WELLKNOWNROLE_OPERATOR), UA_PERMISSIONTYPE_CALL};
    CHECK(gds_server_set_role_permissions(s, &gdsNode, &rp, 1) == GDS_EDENIED);
    CHECK(gds_server_set_role_permissions(s, &unknown, &rp, 1) == GDS_ENOTFOUND);
    rp.permissions = 0x20000u; /* not a PermissionType bit */
    CHECK(gds_server_set_role_permissions(s, &obj, &rp, 1) == GDS_EINVAL);
    rp = (gds_role_permission){server, UA_PERMISSIONTYPE_CALL}; /* not a Role */
    CHECK(gds_server_set_role_permissions(s, &obj, &rp, 1) == GDS_EINVAL);
    CHECK_EQ_INT(s->nPerms, 0);
}

/* Churn: groups come and go; ASan and TSan watch the bindings. */
static void test_churn(gds_server *s) {
    gds_session admin = sess(GDS_ROLE_SKS_ADMIN), op = sess(GDS_ROLE_OPERATOR);
    for(UA_UInt32 g = 10; g < 30; g++) {
        CHECK_EQ_INT(call(s, &admin, SKS_OBJ, ADD_GROUP, g), UA_STATUSCODE_GOOD);
        CHECK_EQ_INT(call(s, &op, GROUP_BASE + g, ROTATE_BASE + g, g), UA_STATUSCODE_GOOD);
        CHECK_EQ_INT(call(s, &admin, SKS_OBJ, REMOVE_GROUP, g), UA_STATUSCODE_GOOD);
    }
    CHECK_EQ_INT(s->nBindings, 2); /* AddGroup and RemoveGroup */
    CHECK_EQ_INT(s->nPerms, 0);
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

    static uint8_t pw[] = "runtime-test-passphrase";
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
    cfg.port = (UA_UInt16)(46000 + getpid() % 2000);
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS runtime nodes test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;
    gds_server *s = NULL;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s) {
        setup(s);
        if(CHECK(UA_Server_run_startup(gds_server_ua(s)) == UA_STATUSCODE_GOOD)) {
            test_group(s);
            test_refused(s);
            test_churn(s);
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
