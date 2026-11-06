/* OpenGDS unit test: the plugin caller view (UASM ask A6, issue #17).
 * Checks the gds_caller each identity gets: Roles (OPC 10000-18 §4.3
 * default mappings, OPC 10000-12 §6.2 Table 1), the application behind
 * the channel and ApplicationSelfAdmin (OPC 10000-12 §6.2 Table 2),
 * plugin privileges, the security mode, and that the view's memory is
 * the call's own (ASan reports a leak or a use after free).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "gds_internal.h"
#include "gds_plugin.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:plugin"
#define APP_URI "urn:opengds:test:app"
#define PRIV_DCA "http://opcfoundation.org/UA/Onboarding/#DCA"

static bool own_cert(UA_ByteString *cert, UA_ByteString *key) {
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS test"), UA_STRING_STATIC("O=OpenGDS")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    return UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER,
                                NULL, key, cert) == UA_STATUSCODE_GOOD;
}

static bool has_role(const gds_caller *c, UA_UInt16 ns, UA_UInt32 id) {
    UA_NodeId r = UA_NODEID_NUMERIC(ns, id);
    return gds_caller_has_role(c, &r);
}

static void check_header(const gds_caller *c) {
    CHECK_EQ_INT(c->abi_major, GDS_PLUGIN_ABI_MAJOR);
    CHECK_EQ_INT(c->abi_minor, GDS_PLUGIN_ABI_MINOR);
    CHECK(c->struct_size == sizeof(gds_caller));
    CHECK(c->sessionId != NULL && c->securityPolicyUri != NULL && c->applicationId != NULL);
}

static void test_anonymous(gds_server *s) {
    gds_session ss = {0};
    ss.anonymous = true;
    ss.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    ss.securityPolicyUri = UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    UA_NodeId sid = UA_NODEID_NUMERIC(1, 4711);
    gds_caller_buf b;
    if(CHECK(gds_caller_build(s, &sid, &ss, &b) == GDS_OK)) {
        const gds_caller *c = &b.view;
        check_header(c);
        CHECK(UA_NodeId_equal(c->sessionId, &sid));
        CHECK(c->userName == NULL);
        CHECK_EQ_INT(c->rolesSize, 1);
        CHECK(gds_caller_has_ns0_role(c, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS));
        CHECK(!gds_caller_has_ns0_role(c, UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER));
        CHECK(c->applicationUri == NULL && UA_NodeId_isNull(c->applicationId));
        CHECK_EQ_INT(c->privilegesSize, 0);
        CHECK(!gds_caller_has_privilege(c, GDS_PRIVILEGE_APPLICATION_SELF_ADMIN));
        CHECK_EQ_INT(c->securityMode, GDS_SECURITY_MODE_SIGN_AND_ENCRYPT);
        CHECK(strcmp(c->securityPolicyUri,
                     "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256") == 0);
    }
    gds_caller_buf_clear(&b);
    UA_String_clear(&ss.securityPolicyUri);
    /* no session: refused */
    CHECK(gds_caller_build(s, &sid, NULL, &b) == GDS_EDENIED);
}

static void check_alice(const gds_server *s, const gds_caller *c) {
    check_header(c);
    CHECK(c->userName && strcmp(c->userName, "alice") == 0);
    CHECK_EQ_INT(c->rolesSize, 5);
    CHECK(c->rolesSize > 0 && c->roles[0].identifier.numeric == UA_NS0ID_WELLKNOWNROLE_ANONYMOUS);
    CHECK(gds_caller_has_ns0_role(c, UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER));
    CHECK(gds_caller_has_ns0_role(c, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN));
    CHECK(gds_caller_has_ns0_role(c, UA_NS0ID_WELLKNOWNROLE_SECURITYKEYSERVERADMIN));
    CHECK(!gds_caller_has_ns0_role(c, UA_NS0ID_WELLKNOWNROLE_SECURITYKEYSERVERACCESS));
    /* GDS Roles are in the GDS namespace, never in namespace 0 */
    CHECK(has_role(c, s->ns, UA_GDSID_WELLKNOWNROLE_DISCOVERYADMIN));
    CHECK(!has_role(c, 0, UA_GDSID_WELLKNOWNROLE_DISCOVERYADMIN));
    CHECK(!has_role(c, s->ns, UA_GDSID_WELLKNOWNROLE_CERTIFICATEAUTHORITYADMIN));
    CHECK_EQ_INT(c->securityMode, GDS_SECURITY_MODE_SIGN);
    CHECK(strcmp(c->securityPolicyUri, "") == 0);
    CHECK(c->applicationUri == NULL);
}

static void test_user(gds_server *s) {
    gds_session ss = {0};
    memcpy(ss.user, "alice", 6);
    ss.roles = GDS_ROLE_SECURITY_ADMIN | GDS_ROLE_DISCOVERY_ADMIN | GDS_ROLE_SKS_ADMIN;
    ss.securityMode = UA_MESSAGESECURITYMODE_SIGN;
    gds_caller_buf b;
    if(CHECK(gds_caller_build(s, NULL, &ss, &b) == GDS_OK))
        check_alice(s, &b.view);
    gds_caller_buf_clear(&b);

    /* every grantable Role maps to its NodeId */
    size_t n = 0;
    const gds_role_info *t = gds_role_table(&n);
    unsigned all = 0;
    for(size_t i = 0; i < n; i++)
        all |= t[i].bit;
    ss.roles = all;
    if(CHECK(gds_caller_build(s, NULL, &ss, &b) == GDS_OK)) {
        CHECK_EQ_INT(b.view.rolesSize, n + 2);
        CHECK(b.view.rolesSize <= GDS_MAX_CALLER_ROLES);
        for(size_t i = 0; i < n; i++)
            CHECK(has_role(&b.view, t[i].gdsNamespace ? s->ns : 0, t[i].id));
    }
    gds_caller_buf_clear(&b);
}

static void test_application(gds_server *s, gds_store *st) {
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_Guid id = UA_Guid_random();
    rec.applicationUri = UA_STRING(APP_URI);
    rec.applicationType = UA_APPLICATIONTYPE_SERVER;
    rec.productUri = UA_STRING("urn:opengds:test:product");
    CHECK(gds_store_app_insert(st, &id, &rec) == GDS_OK);

    gds_session ss = {0};
    ss.anonymous = true;
    ss.clientAppUri = UA_STRING_ALLOC(APP_URI);
    gds_caller_buf b;
    if(CHECK(gds_caller_build(s, NULL, &ss, &b) == GDS_OK)) {
        const gds_caller *c = &b.view;
        UA_NodeId want = UA_NODEID_GUID(s->ns, id);
        CHECK(c->applicationUri && strcmp(c->applicationUri, APP_URI) == 0);
        CHECK(UA_NodeId_equal(c->applicationId, &want));
        CHECK(gds_caller_has_privilege(c, GDS_PRIVILEGE_APPLICATION_SELF_ADMIN));
        CHECK_EQ_INT(c->privilegesSize, 1);
    }
    gds_caller_buf_clear(&b);
    UA_String_clear(&ss.clientAppUri);

    /* named by its certificate but not registered: no ApplicationId */
    ss.clientAppUri = UA_STRING_ALLOC("urn:opengds:test:unregistered");
    if(CHECK(gds_caller_build(s, NULL, &ss, &b) == GDS_OK)) {
        CHECK(UA_NodeId_isNull(b.view.applicationId));
        CHECK(gds_caller_has_privilege(&b.view, GDS_PRIVILEGE_APPLICATION_SELF_ADMIN));
    }
    gds_caller_buf_clear(&b);
    UA_String_clear(&ss.clientAppUri);

    /* a URI with a NUL byte never reaches a plugin */
    static UA_Byte nul[] = {'u', 'r', 'n', 0, 'x'};
    ss.clientAppUri = (UA_String){sizeof(nul), nul};
    CHECK(gds_caller_build(s, NULL, &ss, &b) == GDS_EINVAL);
    CHECK(b.view.roles == NULL);
}

/* ---- privilege providers ---- */

typedef struct {
    int calls;
    bool sawSelfAdmin;
    gds_status fail;
} prov_state;

static gds_status grant_dca(void *ctx, const gds_caller *c, gds_privilege_set *set) {
    prov_state *p = ctx;
    p->calls++;
    p->sawSelfAdmin = gds_caller_has_privilege(c, GDS_PRIVILEGE_APPLICATION_SELF_ADMIN);
    if(p->fail != GDS_OK)
        return p->fail;
    if(c->applicationUri == NULL)
        return GDS_OK;
    gds_status r = gds_privilege_set_add(set, PRIV_DCA);
    if(r == GDS_OK)
        r = gds_privilege_set_add(set, PRIV_DCA); /* twice is fine */
    return r;
}

static gds_status grant_bad(void *ctx, const gds_caller *c, gds_privilege_set *set) {
    (void)ctx, (void)c;
    int bad = 0;
    bad += gds_privilege_set_add(set, "") == GDS_EINVAL;
    bad += gds_privilege_set_add(set, "has space") == GDS_EINVAL;
    bad += gds_privilege_set_add(set, "tab\t") == GDS_EINVAL;
    bad += gds_privilege_set_add(set, "\xc3\xa4") == GDS_EINVAL;
    bad += gds_privilege_set_add(NULL, "x") == GDS_EINVAL;
    bad += gds_privilege_set_add(set, NULL) == GDS_EINVAL;
    char longName[GDS_MAX_PRIVILEGE_NAME + 2];
    memset(longName, 'a', sizeof(longName) - 1);
    longName[sizeof(longName) - 1] = '\0';
    bad += gds_privilege_set_add(set, longName) == GDS_EINVAL;
    longName[GDS_MAX_PRIVILEGE_NAME] = '\0';
    bad += gds_privilege_set_add(set, longName) == GDS_OK;
    return bad == 8 ? GDS_OK : GDS_EINVAL;
}

static gds_status grant_many(void *ctx, const gds_caller *c, gds_privilege_set *set) {
    (void)ctx, (void)c;
    char name[32];
    gds_status r = GDS_OK;
    for(int i = 0; r == GDS_OK; i++) {
        (void)snprintf(name, sizeof(name), "urn:x#p%d", i);
        r = gds_privilege_set_add(set, name);
    }
    return r == GDS_ETOOBIG ? GDS_OK : GDS_EINVAL;
}

static void test_providers(gds_server *s) {
    static prov_state ps;
    gds_privilege_provider p = {GDS_PLUGIN_ABI_MAJOR, GDS_PLUGIN_ABI_MINOR,
                                sizeof(gds_privilege_provider), &ps, grant_dca};
    gds_privilege_provider wrong = p;
    wrong.abi_major = GDS_PLUGIN_ABI_MAJOR + 1;
    CHECK(gds_server_add_privilege_provider(s, &wrong) == GDS_EINVAL);
    wrong = p;
    wrong.struct_size = offsetof(gds_privilege_provider, grant);
    CHECK(gds_server_add_privilege_provider(s, &wrong) == GDS_EINVAL);
    wrong = p;
    wrong.grant = NULL;
    CHECK(gds_server_add_privilege_provider(s, &wrong) == GDS_EINVAL);
    CHECK(gds_server_add_privilege_provider(s, NULL) == GDS_EINVAL);
    CHECK(gds_server_add_privilege_provider(s, &p) == GDS_OK);

    gds_session ss = {0};
    ss.anonymous = true;
    ss.clientAppUri = UA_STRING_ALLOC(APP_URI);
    gds_caller_buf b;
    if(CHECK(gds_caller_build(s, NULL, &ss, &b) == GDS_OK)) {
        CHECK_EQ_INT(ps.calls, 1);
        CHECK(ps.sawSelfAdmin); /* providers run after the core's privileges */
        CHECK(gds_caller_has_privilege(&b.view, PRIV_DCA));
        CHECK_EQ_INT(b.view.privilegesSize, 2);
    }
    gds_caller_buf_clear(&b);

    /* a failing provider refuses the call (fail closed) */
    ps.fail = GDS_EIO;
    CHECK(gds_caller_build(s, NULL, &ss, &b) == GDS_EDENIED);
    CHECK(b.view.roles == NULL && b.priv.n == 0);
    ps.fail = GDS_OK;
    UA_String_clear(&ss.clientAppUri);

    gds_privilege_provider pb = p, pm = p;
    pb.grant = grant_bad;
    pm.grant = grant_many;
    CHECK(gds_server_add_privilege_provider(s, &pb) == GDS_OK);
    CHECK(gds_server_add_privilege_provider(s, &pm) == GDS_OK);
    if(CHECK(gds_caller_build(s, NULL, &ss, &b) == GDS_OK))
        CHECK_EQ_INT(b.view.privilegesSize, GDS_MAX_PRIVILEGES);
    gds_caller_buf_clear(&b);

    for(int i = 3; i < GDS_MAX_PRIVILEGE_PROVIDERS; i++)
        CHECK(gds_server_add_privilege_provider(s, &p) == GDS_OK);
    CHECK(gds_server_add_privilege_provider(s, &p) == GDS_ETOOBIG);
}

/* ---- users file: the other parts' Roles ---- */

static void test_users_file(const char *dir) {
    char path[1024], cred[256], line[512];
    CHECK(gds_path(path, sizeof(path), "%s/users", dir) == GDS_OK);
    static const uint8_t pw[] = "pw-for-the-test";
    if(!CHECK(gds_password_hash(pw, sizeof(pw) - 1, 10000, cred, sizeof(cred)) == GDS_OK))
        return;
    int n = snprintf(line, sizeof(line),
                     "sks SecurityKeyServerAdmin,SecurityKeyServerAccess,Operator %s\n"
                     "ra RegistrationAuthorityAdmin,KeyCredentialAdmin %s\n",
                     cred, cred);
    CHECK(n > 0 && (size_t)n < sizeof(line));
    gds_buf b = {NULL, (size_t)n};
    CHECK(gds_file_write_atomic(path, line, b.len, 0600) == GDS_OK);
    gds_users u;
    if(CHECK(gds_users_load(path, &u) == GDS_OK) && CHECK_EQ_INT(u.n, 2)) {
        CHECK_EQ_INT(u.users[0].roles, GDS_ROLE_SKS_ADMIN | GDS_ROLE_SKS_ACCESS | GDS_ROLE_OPERATOR);
        CHECK_EQ_INT(u.users[1].roles,
                     GDS_ROLE_REGISTRATION_AUTHORITY_ADMIN | GDS_ROLE_KEY_CREDENTIAL_ADMIN);
    }
    /* never from the file: implicit Roles and unknown names */
    static const char *const refused[] = {"Anonymous", "AuthenticatedUser", "TrustedApplication",
                                          "securitykeyserveradmin", "Nobody"};
    for(size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        n = snprintf(line, sizeof(line), "x %s %s\n", refused[i], cred);
        b.len = (size_t)n;
        CHECK(gds_file_write_atomic(path, line, b.len, 0600) == GDS_OK);
        CHECK(gds_users_load(path, &u) == GDS_EINVAL);
    }
    (void)unlink(path);
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

    test_users_file(argv[1]);

    static uint8_t pw[] = "plugin-test-passphrase";
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
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS plugin test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.autoApprove = true;
    gds_server *s = NULL;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s) {
        test_anonymous(s);
        test_user(s);
        test_application(s, st);
        test_providers(s);
    }
    gds_server_delete(s);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_store_close(st);
    gds_ca_close(ca);
    return CHECK_DONE();
}
