/* OpenGDS unit test: Role Booleans (UASM ask A17, gds_nodes.c).
 *
 * An embedder Boolean variable, such as the UserWritable Property of an
 * OPC 10000-20 FileType trust list on the Part 21 DeviceRegistrar, reads
 * TRUE for a session that holds one of its Roles and FALSE for any other,
 * including anonymous sessions and internal reads; writes are refused.
 * The refused calls: namespace 0 and the GDS namespace, no such node, not
 * a Boolean variable, no Roles, a Role no session can hold.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
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

#define TEST_URI "urn:opengds:test:roleboolean"
#define ONB_NS "urn:opengds:test:onboarding"
#define WRITABLE 1360
#define OTHER 1396
#define NUMBER 1400
#define ROLE 2000

static UA_UInt16 ns;

static void add_variable(gds_server *s, UA_UInt32 id, const char *name, const void *v,
                         const UA_DataType *t) {
    UA_VariableAttributes a = UA_VariableAttributes_default;
    UA_Variant_setScalar(&a.value, (void *)(uintptr_t)v, t);
    a.dataType = t->typeId;
    a.accessLevel = UA_ACCESSLEVELMASK_READ;
    CHECK(UA_Server_addVariableNode(gds_server_ua(s), UA_NODEID_NUMERIC(ns, id),
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                                    UA_QUALIFIEDNAME(ns, (char *)(uintptr_t)name),
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE), a, NULL,
                                    NULL) == UA_STATUSCODE_GOOD);
}

/* The value as this session reads it; -1 for an error. */
static int read_as(gds_server *s, gds_session *as, UA_UInt32 id) {
    UA_Server_setAdminSessionContext(gds_server_ua(s), as);
    UA_Variant v;
    UA_Variant_init(&v);
    int out = -1;
    if(UA_Server_readValue(gds_server_ua(s), UA_NODEID_NUMERIC(ns, id), &v) ==
           UA_STATUSCODE_GOOD &&
       UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_BOOLEAN]))
        out = *(UA_Boolean *)v.data ? 1 : 0;
    UA_Variant_clear(&v);
    UA_Server_setAdminSessionContext(gds_server_ua(s), NULL);
    return out;
}

static void test_roles(gds_server *s) {
    UA_NodeId registrar = UA_NODEID_NUMERIC(ns, ROLE);
    CHECK(gds_server_add_role(s, "RegistrarAdmin", &registrar) == GDS_OK);
    UA_Boolean f = false, t = true;
    UA_Int32 num = 7;
    add_variable(s, WRITABLE, "UserWritable", &f, &UA_TYPES[UA_TYPES_BOOLEAN]);
    add_variable(s, OTHER, "UserWritable2", &t, &UA_TYPES[UA_TYPES_BOOLEAN]);
    add_variable(s, NUMBER, "Number", &num, &UA_TYPES[UA_TYPES_INT32]);

    UA_NodeId w = UA_NODEID_NUMERIC(ns, WRITABLE), o = UA_NODEID_NUMERIC(ns, OTHER);
    CHECK(gds_server_set_role_boolean(s, &w, &registrar, 1) == GDS_OK);
    UA_NodeId authenticated = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER);
    CHECK(gds_server_set_role_boolean(s, &o, &authenticated, 1) == GDS_OK);

    unsigned bit = 0;
    for(size_t i = 0; i < gds_role_count(); i++) {
        UA_NodeId id;
        unsigned b = 0;
        const char *name = NULL;
        gds_role_at(i, s->ns, &id, &b, &name);
        if(UA_NodeId_equal(&id, &registrar))
            bit = b;
    }
    CHECK(bit != 0);
    gds_session holder, plain, anon;
    memset(&holder, 0, sizeof(holder));
    memset(&plain, 0, sizeof(plain));
    memset(&anon, 0, sizeof(anon));
    holder.roles = bit | GDS_ROLE_SECURITY_ADMIN;
    holder.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    memcpy(holder.user, "registrar", sizeof("registrar"));
    plain.roles = GDS_ROLE_SECURITY_ADMIN;
    plain.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    memcpy(plain.user, "admin", sizeof("admin"));
    anon.anonymous = true;
    /* an anonymous session holds only what OPC 10000-18 Application rules
     * grant it (gds_roles.c): none here */
    anon.roles = 0;

    CHECK_EQ_INT(read_as(s, &holder, WRITABLE), 1);
    CHECK_EQ_INT(read_as(s, &plain, WRITABLE), 0);
    CHECK_EQ_INT(read_as(s, &anon, WRITABLE), 0);
    CHECK_EQ_INT(read_as(s, NULL, WRITABLE), 0);
    CHECK_EQ_INT(read_as(s, &plain, OTHER), 1);
    CHECK_EQ_INT(read_as(s, &anon, OTHER), 0);

    /* writes are refused */
    UA_Variant v;
    UA_Variant_setScalar(&v, &t, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Server_setAdminSessionContext(gds_server_ua(s), &holder);
    CHECK(UA_Server_writeValue(gds_server_ua(s), w, v) != UA_STATUSCODE_GOOD);
    UA_Server_setAdminSessionContext(gds_server_ua(s), NULL);
    CHECK_EQ_INT(read_as(s, &plain, WRITABLE), 0);

    /* calling again replaces the Roles */
    UA_NodeId secAdmin = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN);
    CHECK(gds_server_set_role_boolean(s, &w, &secAdmin, 1) == GDS_OK);
    CHECK_EQ_INT(read_as(s, &plain, WRITABLE), 1);

    /* refused */
    UA_NodeId n0 = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_STATE);
    UA_NodeId gds = UA_NODEID_NUMERIC(s->ns, 1);
    UA_NodeId missing = UA_NODEID_NUMERIC(ns, 9999), number = UA_NODEID_NUMERIC(ns, NUMBER);
    UA_NodeId noRole = UA_NODEID_NUMERIC(ns, 4242);
    CHECK(gds_server_set_role_boolean(s, &n0, &registrar, 1) == GDS_EDENIED);
    CHECK(gds_server_set_role_boolean(s, &gds, &registrar, 1) == GDS_EDENIED);
    CHECK(gds_server_set_role_boolean(s, &missing, &registrar, 1) == GDS_ENOTFOUND);
    CHECK(gds_server_set_role_boolean(s, &number, &registrar, 1) == GDS_EINVAL);
    CHECK(gds_server_set_role_boolean(s, &w, &registrar, 0) == GDS_EINVAL);
    CHECK(gds_server_set_role_boolean(s, &w, &noRole, 1) == GDS_EINVAL);
    CHECK_EQ_INT(read_as(s, &plain, WRITABLE), 1); /* unchanged */

    /* removed with its node */
    CHECK(gds_server_remove_node(s, &o) == GDS_OK);
    CHECK_EQ_INT(s->nRoleBools, 1);
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

    static uint8_t pw[] = "role-boolean-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    gds_store *st = NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS role boolean test")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    if(!CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) || !CHECK(gds_store_open(db, &st) == GDS_OK) ||
       !CHECK(UA_CreateCertificate(UA_Log_Stdout, subject, 1, san, 2, UA_CERTIFICATEFORMAT_DER,
                                   NULL, &key, &cert) == UA_STATUSCODE_GOOD))
        return CHECK_DONE();

    static gds_users users;
    gds_server_config cfg = {0};
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS role boolean test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;

    gds_server *s = NULL;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s &&
       CHECK(gds_server_add_namespace(s, ONB_NS, &ns) == GDS_OK))
        test_roles(s);
    gds_server_delete(s);

    gds_store_close(st);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_ca_close(ca);
    return CHECK_DONE();
}
