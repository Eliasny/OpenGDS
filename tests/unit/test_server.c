/* OpenGDS unit test: the server object. Endpoint security, the GDS method
 * wiring and the node role / ServiceLevel slot (issue #14, OPC 10000-4
 * §6.6.2.4.2 bands; OPC 10000-5 §6.3.1 EstimatedReturnTime).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <string.h>
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "gds_internal.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#if defined(__has_include)
#if __has_include(<open62541/nodeids_di.h>)
#include <open62541/nodeids_di.h>
#define HAVE_DI 1
#endif
#endif

#define TEST_URI "urn:opengds:test:server"

static bool own_cert(UA_ByteString *cert, UA_ByteString *key) {
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS test"), UA_STRING_STATIC("O=OpenGDS")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    UA_StatusCode r = UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2,
                                           UA_CERTIFICATEFORMAT_DER, NULL, key, cert);
    return r == UA_STATUSCODE_GOOD;
}

static int read_level(gds_server *s) {
    UA_Variant v;
    UA_Variant_init(&v);
    int out = -1;
    if(UA_Server_readValue(gds_server_ua(s), UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVICELEVEL),
                           &v) == UA_STATUSCODE_GOOD &&
       UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_BYTE]))
        out = *(UA_Byte *)v.data;
    UA_Variant_clear(&v);
    return out;
}

static UA_DateTime read_ert(gds_server *s, bool *ok) {
    UA_Variant v;
    UA_Variant_init(&v);
    UA_DateTime out = -1;
    *ok = UA_Server_readValue(gds_server_ua(s),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_ESTIMATEDRETURNTIME),
                              &v) == UA_STATUSCODE_GOOD &&
          UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_DATETIME]);
    if(*ok)
        out = *(UA_DateTime *)v.data;
    UA_Variant_clear(&v);
    return out;
}

static void test_service_level(gds_server *s) {
    bool ok = false;
    /* standalone default: Healthy 255, no return time */
    CHECK_EQ_INT(gds_server_role(s), GDS_NODE_STANDALONE);
    CHECK_EQ_INT(read_level(s), 255);
    CHECK(read_ert(s, &ok) == 0 && ok);

    CHECK(gds_server_set_role(s, GDS_NODE_PRIMARY, 210, 0) == GDS_OK);
    CHECK_EQ_INT(read_level(s), 210);
    CHECK(gds_server_set_service_level(s, 255, 0) == GDS_OK);
    CHECK_EQ_INT(read_level(s), 255);
    CHECK(gds_server_set_service_level(s, 150, 0) == GDS_OK); /* Degraded primary */
    CHECK_EQ_INT(read_level(s), 150);

    /* a standby is never Healthy; a refusal changes nothing */
    CHECK(gds_server_set_role(s, GDS_NODE_STANDBY, 200, 0) == GDS_EINVAL);
    CHECK_EQ_INT(gds_server_role(s), GDS_NODE_PRIMARY);
    CHECK_EQ_INT(read_level(s), 150);
    CHECK(gds_server_set_role(s, GDS_NODE_STANDBY, 199, 0) == GDS_OK);
    CHECK_EQ_INT(read_level(s), 199);
    CHECK(gds_server_set_service_level(s, 255, 0) == GDS_EINVAL);
    CHECK_EQ_INT(read_level(s), 199);
    CHECK(gds_server_set_service_level(s, GDS_SERVICE_LEVEL_NO_DATA, 0) == GDS_OK);
    CHECK_EQ_INT(read_level(s), 1);

    /* Maintenance carries the return time; any other level must not */
    UA_DateTime back = UA_DateTime_now() + (UA_DateTime)600 * UA_DATETIME_SEC;
    CHECK(gds_server_set_service_level(s, 5, back) == GDS_EINVAL);
    CHECK(gds_server_set_service_level(s, GDS_SERVICE_LEVEL_MAINTENANCE, back) == GDS_OK);
    CHECK_EQ_INT(read_level(s), 0);
    CHECK(read_ert(s, &ok) == back && ok);
    CHECK(gds_server_set_role(s, GDS_NODE_PRIMARY, 255, 0) == GDS_OK);
    CHECK(read_ert(s, &ok) == 0 && ok);

    /* an out-of-range role from a plugin must be refused */
    CHECK(gds_server_set_role(s, (gds_node_role)7, 100, 0) == GDS_EINVAL); // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange)
    CHECK(gds_server_set_role(NULL, GDS_NODE_PRIMARY, 255, 0) == GDS_EINVAL);
    CHECK_EQ_INT(gds_server_role(s), GDS_NODE_PRIMARY);
}

/* Sessions only over SignAndEncrypt; None only for discovery. */
static void test_endpoints(gds_server *s) {
    UA_ServerConfig *c = UA_Server_getConfig(gds_server_ua(s));
    size_t none = 0, secure = 0, other = 0;
    for(size_t i = 0; i < c->endpointsSize; i++) {
        const UA_EndpointDescription *e = &c->endpoints[i];
        if(e->securityMode == UA_MESSAGESECURITYMODE_NONE)
            none++;
        else if(e->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
            secure++;
        else
            other++; /* Sign-only */
    }
    CHECK_EQ_INT(other, 0);
    CHECK_EQ_INT(none, 1);
    CHECK_EQ_INT(secure, 3);
    CHECK(c->securityPolicyNoneDiscoveryOnly);
    CHECK(!c->allowNonePolicyPassword);
    CHECK_EQ_INT(c->applicationDescription.applicationType, UA_APPLICATIONTYPE_DISCOVERYSERVER);
    /* no X.509 user tokens in T1, and no user name token over None */
    const UA_AccessControl *ac = &c->accessControl;
    for(size_t i = 0; i < ac->userTokenPoliciesSize; i++) {
        const UA_UserTokenPolicy *p = &ac->userTokenPolicies[i];
        CHECK(p->tokenType != UA_USERTOKENTYPE_CERTIFICATE);
        UA_String noneUri = UA_STRING_STATIC("http://opcfoundation.org/UA/SecurityPolicy#None");
        CHECK(p->tokenType != UA_USERTOKENTYPE_USERNAME ||
              !UA_String_equal(&p->securityPolicyUri, &noneUri));
    }
}

/* Clients change the address space only through the GDS methods. */
static void test_read_only(gds_server *s) {
    UA_AccessControl *ac = &UA_Server_getConfig(gds_server_ua(s))->accessControl;
    gds_session anon = {0}, secadmin = {0};
    anon.anonymous = true;
    secadmin.roles = GDS_ROLE_SECURITY_ADMIN;
    UA_AddNodesItem add;
    UA_AddNodesItem_init(&add);
    UA_DeleteNodesItem del;
    UA_DeleteNodesItem_init(&del);
    CHECK(!ac->allowAddNode(NULL, ac, NULL, &anon, &add));
    CHECK(!ac->allowDeleteNode(NULL, ac, NULL, &secadmin, &del));
    UA_NodeId status = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS);
    CHECK_EQ_INT(ac->getUserRightsMask(NULL, ac, NULL, &secadmin, &status, NULL), 0);
    CHECK_EQ_INT(ac->getUserAccessLevel(NULL, ac, NULL, &anon, &status, NULL),
                 UA_ACCESSLEVELMASK_READ);

    UA_NodeId upd = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE);
    UA_NodeId add_cert = UA_NODEID_NUMERIC(
        0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_ADDCERTIFICATE);
    UA_NodeId monitored = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_GETMONITOREDITEMS);
    UA_NodeId find = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_FINDAPPLICATIONS);
    CHECK(!gds_method_executable(s, &anon, &upd));
    CHECK(!gds_method_executable(s, NULL, &add_cert));
    CHECK(gds_method_executable(s, &secadmin, &upd));
    CHECK(gds_method_executable(s, &secadmin, &add_cert));
    CHECK(gds_method_executable(s, &anon, &monitored));
    CHECK(gds_method_executable(s, &anon, &find));
    UA_NodeId str = UA_NODEID_STRING(0, "x");
    CHECK(!gds_method_executable(s, &secadmin, &str));
}

/* FindApplications is open to every session and is wired to OpenGDS. */
static void test_find(gds_server *s) {
    UA_Variant in;
    UA_String uri = UA_STRING_STATIC("urn:nobody");
    UA_Variant_setScalar(&in, &uri, &UA_TYPES[UA_TYPES_STRING]);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY);
    req.methodId = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_FINDAPPLICATIONS);
    req.inputArguments = &in;
    req.inputArgumentsSize = 1;
    UA_CallMethodResult res = UA_Server_call(gds_server_ua(s), &req);
    CHECK(res.statusCode == UA_STATUSCODE_GOOD);
    CHECK(res.outputArgumentsSize == 1 && UA_Variant_isEmpty(&res.outputArguments[0]) == false &&
          res.outputArguments[0].arrayLength == 0);
    UA_CallMethodResult_clear(&res);
}

/* Companion models next to GDS (UASM ask A12, scripts/build_open62541.sh
 * MODELS): the GDS namespace index is looked up by URI, so it is right
 * whatever else is autoloaded; with DI loaded, an embedder can instantiate
 * DI types such as the OPC 10000-100 SoftwareUpdateType. */
static void test_models(gds_server *s) {
    UA_Server *ua = gds_server_ua(s);
    size_t gdsNs = 0;
    UA_String gdsUri = UA_STRING_STATIC(GDS_NS_URI);
    CHECK(UA_Server_getNamespaceByName(ua, gdsUri, &gdsNs) == UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(gdsNs, s->ns);
    UA_QualifiedName bn;
    CHECK(UA_Server_readBrowseName(ua, UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY), &bn) ==
          UA_STATUSCODE_GOOD);
    UA_QualifiedName_clear(&bn);
#ifdef HAVE_DI
    size_t di = 0;
    UA_String diUri = UA_STRING_STATIC("http://opcfoundation.org/UA/DI/");
    UA_String typeName = UA_STRING_STATIC("SoftwareUpdateType");
    if(!CHECK(UA_Server_getNamespaceByName(ua, diUri, &di) == UA_STATUSCODE_GOOD))
        return;
    UA_NodeId type = UA_NODEID_NUMERIC((UA_UInt16)di, UA_DIID_SOFTWAREUPDATETYPE);
    CHECK(UA_Server_readBrowseName(ua, type, &bn) == UA_STATUSCODE_GOOD &&
          UA_String_equal(&bn.name, &typeName));
    UA_QualifiedName_clear(&bn);
    UA_ObjectAttributes oa = UA_ObjectAttributes_default;
    UA_NodeId out = UA_NODEID_NULL;
    CHECK(UA_Server_addObjectNode(ua, UA_NODEID_NULL, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                                  UA_QUALIFIEDNAME((UA_UInt16)di, "SoftwareUpdate"), type, oa, NULL,
                                  &out) == UA_STATUSCODE_GOOD);
    CHECK(UA_Server_deleteNode(ua, out, true) == UA_STATUSCODE_GOOD);
    UA_NodeId_clear(&out);
    printf("# DI model loaded (namespace %zu)\n", di);
#endif
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

    static uint8_t pw[] = "server-test-passphrase";
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

    static gds_users users; /* nobody: anonymous only */
    gds_server_config cfg = {0};
    cfg.port = 0;
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;

    gds_server *s = NULL;
    gds_server_config bad = cfg;
    bad.ca = NULL;
    CHECK(gds_server_new(&bad, &s) == GDS_EINVAL && !s);
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s) {
        test_endpoints(s);
        test_service_level(s);
        test_read_only(s);
        test_find(s);
        test_models(s);
    }
    gds_server_delete(s);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_store_close(st);
    gds_ca_close(ca);
    return CHECK_DONE();
}
