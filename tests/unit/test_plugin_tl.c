/* OpenGDS unit test: plugin trust lists (UASM ask A18, gds_plugin_tl.c).
 *
 * A plugin adds a CertificateGroup ("SksPushTargets") under its object.
 * Over real clients, a SecurityAdmin adds and removes certificates
 * (AddCertificate, RemoveCertificate by SHA-1 thumbprint), reads the list
 * (Open, Read, Close), and replaces it (Open Write|EraseExisting, Write,
 * CloseAndUpdate); another session may not write while it is open, a
 * session without the Role may not call at all, and UserWritable follows
 * the Role. gds_server_get_trust_list reads the group, and the list
 * survives a restart (file store).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/nodeids.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <openssl/evp.h>

#include <pthread.h>
#include <stdio.h>
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

#define TEST_URI "urn:opengds:test:plugintl"
#define CLIENT_URI "urn:opengds:test:plugintl:client"
#define PLUGIN_NS "urn:opengds:test:plugintl:sks"
#define PASSWORD "plugin-tl-pw-for-the-test"

static UA_UInt16 ns;

typedef struct {
    gds_store *store;
    gds_ca *ca;
    UA_ByteString cert, key; /* the server's */
    UA_ByteString a, b, c;   /* entries */
    UA_ByteString caCert;    /* an issuer */
    char pki[1024];
} fixture;

static bool make_cert(const char *cn, const char *uri, UA_ByteString *cert, UA_ByteString *key) {
    UA_String subject[] = {UA_STRING((char *)(uintptr_t)cn), UA_STRING_STATIC("O=OpenGDS")};
    UA_String san[] = {UA_STRING((char *)(uintptr_t)uri), UA_STRING_STATIC("DNS:localhost")};
    return UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER, NULL,
                                key, cert) == UA_STATUSCODE_GOOD;
}

static void thumbprint(const UA_ByteString *der, char out[41]) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    out[0] = '\0';
    if(EVP_Digest(der->data, der->length, md, &n, EVP_sha1(), NULL) == 1 && n == 20)
        for(size_t i = 0; i < 20; i++)
            (void)snprintf(out + (2 * i), 3, "%02X", md[i]);
}

static bool free_key(UA_ByteString *k) {
    UA_ByteString_clear(k);
    return true;
}

/* ---- server ---- */

static UA_NodeId group_id(void) {
    return UA_NODEID_STRING(ns, "SksPushTargets");
}

static UA_NodeId tl_of(gds_server *s) {
    UA_QualifiedName qn = UA_QUALIFIEDNAME(0, "TrustList");
    UA_BrowsePathResult bp =
        UA_Server_browseSimplifiedBrowsePath(gds_server_ua(s), group_id(), 1, &qn);
    UA_NodeId id = UA_NODEID_NULL;
    if(bp.statusCode == UA_STATUSCODE_GOOD && bp.targetsSize == 1)
        (void)UA_NodeId_copy(&bp.targets[0].targetId.nodeId, &id);
    UA_BrowsePathResult_clear(&bp);
    return id;
}

static gds_trust_list_def def_of(fixture *f, const UA_NodeId *roles, size_t n) {
    gds_trust_list_def d;
    memset(&d, 0, sizeof(d));
    d.abi_major = GDS_PLUGIN_ABI_MAJOR;
    d.abi_minor = GDS_PLUGIN_ABI_MINOR;
    d.struct_size = sizeof(d);
    d.groupId = group_id();
    d.parentId = UA_NODEID_STRING(ns, "KeyService");
    d.name = "SksPushTargets";
    d.pkiDir = f->pki;
    d.roles = roles;
    d.rolesSize = n;
    return d;
}

static void setup(gds_server *s, fixture *f, bool refusals) {
    CHECK(gds_server_add_namespace(s, PLUGIN_NS, &ns) == GDS_OK);
    UA_NodeId src = UA_NODEID_STRING(ns, "KeyService");
    UA_NodeId objects = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    CHECK(gds_server_add_object(s, &src, &objects, "KeyService", NULL) == GDS_OK);
    static const UA_NodeId secAdmin = {0, UA_NODEIDTYPE_NUMERIC,
                                       {UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN}};
    gds_trust_list_def d = def_of(f, &secAdmin, 1);
    CHECK(gds_server_add_trust_list(s, &d) == GDS_OK);
    if(!refusals)
        return;
    CHECK(gds_server_add_trust_list(s, &d) == GDS_EEXISTS);
    gds_trust_list_def bad = d;
    bad.groupId = UA_NODEID_NUMERIC(0, 4711);
    CHECK(gds_server_add_trust_list(s, &bad) == GDS_EDENIED);
    bad = d;
    bad.groupId = UA_NODEID_STRING(ns, "Other");
    bad.parentId = UA_NODEID_STRING(ns, "NoSuchObject");
    CHECK(gds_server_add_trust_list(s, &bad) == GDS_ENOTFOUND);
    bad = d;
    bad.rolesSize = 0;
    CHECK(gds_server_add_trust_list(s, &bad) == GDS_EINVAL);
    UA_NodeId other = UA_NODEID_STRING(ns, "NoSuchGroup");
    UA_TrustListDataType tl;
    CHECK(gds_server_get_trust_list(s, &other, &tl) == GDS_ENOTFOUND);
}

static bool get_list(gds_server *s, UA_TrustListDataType *tl) {
    UA_NodeId g = group_id();
    return gds_server_get_trust_list(s, &g, tl) == GDS_OK;
}

/* ---- clients ---- */

static UA_Client *connect_as(const char *user, const char *url, UA_ByteString *serverCert) {
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    UA_Client *c = NULL;
    if(make_cert("CN=plugin tl client", "URI:" CLIENT_URI, &cert, &key) &&
       UA_ClientConfig_setDefault(&cfg) == UA_STATUSCODE_GOOD &&
       UA_ClientConfig_setDefaultEncryption(&cfg, cert, key, serverCert, 1, NULL, 0) ==
           UA_STATUSCODE_GOOD) {
        cfg.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        UA_String_clear(&cfg.securityPolicyUri);
        cfg.securityPolicyUri =
            UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
        UA_String_clear(&cfg.clientDescription.applicationUri);
        cfg.clientDescription.applicationUri = UA_STRING_ALLOC(CLIENT_URI);
        c = UA_Client_newWithConfig(&cfg);
    }
    if(!c)
        UA_ClientConfig_clear(&cfg);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    UA_StatusCode r = UA_STATUSCODE_BADINTERNALERROR;
    for(int i = 0; c && i < 50 && r != UA_STATUSCODE_GOOD; i++) {
        r = UA_Client_connectUsername(c, url, user, PASSWORD);
        if(r != UA_STATUSCODE_GOOD)
            usleep(100000);
    }
    if(c && !CHECK_EQ_INT(r, UA_STATUSCODE_GOOD)) {
        UA_Client_delete(c);
        c = NULL;
    }
    return c;
}

static void disconnect(UA_Client *c) {
    if(c) {
        (void)UA_Client_disconnect(c);
        UA_Client_delete(c);
    }
}

/* Calls a TrustList method; the first output, if any, goes to *out. */
static UA_StatusCode tl_call(UA_Client *c, const UA_NodeId *tl, UA_UInt32 method, UA_Variant *in,
                             size_t n, UA_Variant *out) {
    size_t nOut = 0;
    UA_Variant *o = NULL;
    UA_StatusCode r = UA_Client_call(c, *tl, UA_NODEID_NUMERIC(0, method), n, in, &nOut, &o);
    if(out) {
        UA_Variant_init(out);
        if(r == UA_STATUSCODE_GOOD && nOut > 0) {
            *out = o[0];
            UA_Variant_init(&o[0]);
        }
    }
    UA_Array_delete(o, nOut, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

static UA_StatusCode add_cert(UA_Client *c, const UA_NodeId *tl, UA_ByteString *cert,
                              UA_Boolean trusted) {
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], cert, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[1], &trusted, &UA_TYPES[UA_TYPES_BOOLEAN]);
    return tl_call(c, tl, UA_NS0ID_TRUSTLISTTYPE_ADDCERTIFICATE, in, 2, NULL);
}

static UA_StatusCode remove_cert(UA_Client *c, const UA_NodeId *tl, const UA_ByteString *cert,
                                 UA_Boolean trusted) {
    char hex[41];
    thumbprint(cert, hex);
    UA_String t = UA_STRING(hex);
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &t, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &trusted, &UA_TYPES[UA_TYPES_BOOLEAN]);
    return tl_call(c, tl, UA_NS0ID_TRUSTLISTTYPE_REMOVECERTIFICATE, in, 2, NULL);
}

static UA_StatusCode open_tl(UA_Client *c, const UA_NodeId *tl, UA_Byte mode, UA_UInt32 *h) {
    UA_Variant in, out;
    UA_Variant_setScalar(&in, &mode, &UA_TYPES[UA_TYPES_BYTE]);
    UA_StatusCode r = tl_call(c, tl, UA_NS0ID_FILETYPE_OPEN, &in, 1, &out);
    *h = 0;
    if(r == UA_STATUSCODE_GOOD && out.data &&
       UA_Variant_hasScalarType(&out, &UA_TYPES[UA_TYPES_UINT32]))
        *h = *(UA_UInt32 *)out.data;
    UA_Variant_clear(&out);
    return r;
}

static UA_StatusCode h_call(UA_Client *c, const UA_NodeId *tl, UA_UInt32 method, UA_UInt32 h,
                            UA_Variant *arg, UA_Variant *out) {
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &h, &UA_TYPES[UA_TYPES_UINT32]);
    if(arg)
        in[1] = *arg;
    return tl_call(c, tl, method, in, arg ? 2 : 1, out);
}

/* Reads the whole file of an open handle and decodes it. */
static bool read_all(UA_Client *c, const UA_NodeId *tl, UA_UInt32 h, UA_TrustListDataType *tl_out) {
    UA_Int32 len = 1 << 20;
    UA_Variant arg, out;
    UA_Variant_setScalar(&arg, &len, &UA_TYPES[UA_TYPES_INT32]);
    bool ok = h_call(c, tl, UA_NS0ID_FILETYPE_READ, h, &arg, &out) == UA_STATUSCODE_GOOD &&
              UA_Variant_hasScalarType(&out, &UA_TYPES[UA_TYPES_BYTESTRING]) &&
              UA_decodeBinary((UA_ByteString *)out.data, tl_out,
                              &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL) == UA_STATUSCODE_GOOD;
    UA_Variant_clear(&out);
    return ok;
}

static int user_writable(UA_Client *c, const UA_NodeId *tl) {
    UA_BrowsePath bp;
    UA_BrowsePath_init(&bp);
    UA_RelativePathElement el;
    UA_RelativePathElement_init(&el);
    el.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY);
    el.targetName = UA_QUALIFIEDNAME(0, "UserWritable");
    bp.startingNode = *tl;
    bp.relativePath.elements = &el;
    bp.relativePath.elementsSize = 1;
    UA_TranslateBrowsePathsToNodeIdsRequest req;
    UA_TranslateBrowsePathsToNodeIdsRequest_init(&req);
    req.browsePaths = &bp;
    req.browsePathsSize = 1;
    UA_TranslateBrowsePathsToNodeIdsResponse res = UA_Client_Service_translateBrowsePathsToNodeIds(c, req);
    int v = -1;
    if(res.resultsSize == 1 && res.results[0].targetsSize == 1) {
        UA_Variant val;
        UA_Variant_init(&val);
        if(UA_Client_readValueAttribute(c, res.results[0].targets[0].targetId.nodeId, &val) ==
               UA_STATUSCODE_GOOD &&
           UA_Variant_hasScalarType(&val, &UA_TYPES[UA_TYPES_BOOLEAN]))
            v = *(UA_Boolean *)val.data ? 1 : 0;
        UA_Variant_clear(&val);
    }
    UA_TranslateBrowsePathsToNodeIdsResponse_clear(&res);
    return v;
}

/* Open Write|EraseExisting, Write in two chunks, CloseAndUpdate; then a
 * file that does not decode changes nothing. */
static void test_replace(gds_server *s, fixture *f, UA_Client *admin, UA_Client *admin2,
                         const UA_NodeId *tlp) {
    UA_NodeId tl = *tlp;
    UA_UInt32 h = 0, h2 = 0;
    UA_TrustListDataType got;
    /* replacing the trusted certificates */
    CHECK_EQ_INT(open_tl(admin, &tl, 0x06, &h), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(open_tl(admin2, &tl, 1, &h2), UA_STATUSCODE_BADNOTREADABLE);
    UA_TrustListDataType put;
    UA_TrustListDataType_init(&put);
    put.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES;
    put.trustedCertificates = &f->b;
    put.trustedCertificatesSize = 1;
    UA_ByteString file = UA_BYTESTRING_NULL;
    CHECK(UA_encodeBinary(&put, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &file, NULL) ==
          UA_STATUSCODE_GOOD);
    /* in two chunks */
    size_t half = file.length / 2;
    UA_ByteString part1 = {half, file.data}, part2 = {file.length - half, file.data + half};
    UA_Variant arg, out;
    UA_Variant_setScalar(&arg, &part1, &UA_TYPES[UA_TYPES_BYTESTRING]);
    CHECK_EQ_INT(h_call(admin, &tl, UA_NS0ID_FILETYPE_WRITE, h, &arg, NULL), UA_STATUSCODE_GOOD);
    UA_Variant_setScalar(&arg, &part2, &UA_TYPES[UA_TYPES_BYTESTRING]);
    CHECK_EQ_INT(h_call(admin, &tl, UA_NS0ID_FILETYPE_WRITE, h, &arg, NULL), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(h_call(admin, &tl, UA_NS0ID_TRUSTLISTTYPE_CLOSEANDUPDATE, h, NULL, &out),
                 UA_STATUSCODE_GOOD);
    CHECK(out.data && UA_Variant_hasScalarType(&out, &UA_TYPES[UA_TYPES_BOOLEAN]) &&
          *(UA_Boolean *)out.data == false); /* applyChangesRequired */
    UA_Variant_clear(&out);
    UA_ByteString_clear(&file);
    UA_TrustListDataType_init(&got);
    if(CHECK(get_list(s, &got))) {
        CHECK(got.trustedCertificatesSize == 1 &&
              UA_ByteString_equal(&got.trustedCertificates[0], &f->b));
        CHECK_EQ_INT(got.issuerCertificatesSize, 1); /* not specified: kept */
    }
    UA_TrustListDataType_clear(&got);

    /* a bad file changes nothing */
    CHECK_EQ_INT(open_tl(admin, &tl, 0x06, &h), UA_STATUSCODE_GOOD);
    UA_ByteString garbage = UA_BYTESTRING("\x01\x00\x00\x00\x05\x00\x00\x00junk");
    UA_Variant_setScalar(&arg, &garbage, &UA_TYPES[UA_TYPES_BYTESTRING]);
    CHECK_EQ_INT(h_call(admin, &tl, UA_NS0ID_FILETYPE_WRITE, h, &arg, NULL), UA_STATUSCODE_GOOD);
    CHECK(h_call(admin, &tl, UA_NS0ID_TRUSTLISTTYPE_CLOSEANDUPDATE, h, NULL, NULL) !=
          UA_STATUSCODE_GOOD);
    UA_TrustListDataType_init(&got);
    CHECK(get_list(s, &got) && got.trustedCertificatesSize == 1);
    UA_TrustListDataType_clear(&got);

}

/* Encodes a TrustListDataType with these trusted certificates. */
static bool encode_trusted(UA_ByteString *certs, size_t n, UA_ByteString *file) {
    UA_TrustListDataType put;
    UA_TrustListDataType_init(&put);
    put.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES;
    put.trustedCertificates = certs;
    put.trustedCertificatesSize = n;
    *file = UA_BYTESTRING_NULL;
    return UA_encodeBinary(&put, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], file, NULL) ==
           UA_STATUSCODE_GOOD;
}

static gds_status set_trusted(gds_server *s, const UA_NodeId *group, UA_ByteString *cert) {
    UA_TrustListDataType put;
    UA_TrustListDataType_init(&put);
    put.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES;
    put.trustedCertificates = cert;
    put.trustedCertificatesSize = 1;
    return gds_server_set_trust_list(s, group, &put);
}

static bool trusted_is(gds_server *s, const UA_ByteString *cert) {
    UA_TrustListDataType got;
    UA_TrustListDataType_init(&got);
    bool ok = get_list(s, &got) && got.trustedCertificatesSize == 1 &&
              UA_ByteString_equal(&got.trustedCertificates[0], cert);
    UA_TrustListDataType_clear(&got);
    return ok;
}

/* gds_server_set_trust_list and the STANDBY rule (A20). Expects trusted
 * [b] and leaves it so. */
static void test_sync(gds_server *s, fixture *f, UA_Client *admin, const UA_NodeId *tlp) {
    UA_NodeId tl = *tlp, group = group_id(), other = UA_NODEID_NUMERIC(ns, 4242);
    UA_TrustListDataType bad;
    UA_TrustListDataType_init(&bad);
    CHECK(set_trusted(s, &other, &f->a) == GDS_ENOTFOUND);
    UA_ByteString junk = UA_BYTESTRING("not a certificate");
    CHECK(set_trusted(s, &group, &junk) == GDS_EINVAL);
    bad.specifiedLists = 0x40;
    CHECK(gds_server_set_trust_list(s, &group, &bad) == GDS_EINVAL);
    CHECK(trusted_is(s, &f->b));

    /* a writer that opened before a replacement cannot land its edit */
    UA_UInt32 h = 0;
    UA_ByteString file;
    UA_Variant arg;
    CHECK_EQ_INT(open_tl(admin, &tl, 0x06, &h), UA_STATUSCODE_GOOD);
    CHECK(set_trusted(s, &group, &f->a) == GDS_OK);
    CHECK(trusted_is(s, &f->a));
    if(CHECK(encode_trusted(&f->c, 1, &file))) {
        UA_Variant_setScalar(&arg, &file, &UA_TYPES[UA_TYPES_BYTESTRING]);
        CHECK_EQ_INT(h_call(admin, &tl, UA_NS0ID_FILETYPE_WRITE, h, &arg, NULL),
                     UA_STATUSCODE_GOOD);
    }
    CHECK_EQ_INT(h_call(admin, &tl, UA_NS0ID_TRUSTLISTTYPE_CLOSEANDUPDATE, h, NULL, NULL),
                 UA_STATUSCODE_BADINVALIDSTATE);
    CHECK(trusted_is(s, &f->a));
    /* a writer that opened after it can */
    CHECK_EQ_INT(open_tl(admin, &tl, 0x06, &h), UA_STATUSCODE_GOOD);
    UA_Variant_setScalar(&arg, &file, &UA_TYPES[UA_TYPES_BYTESTRING]);
    CHECK_EQ_INT(h_call(admin, &tl, UA_NS0ID_FILETYPE_WRITE, h, &arg, NULL), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(h_call(admin, &tl, UA_NS0ID_TRUSTLISTTYPE_CLOSEANDUPDATE, h, NULL, NULL),
                 UA_STATUSCODE_GOOD);
    CHECK(trusted_is(s, &f->c));
    UA_ByteString_clear(&file);

    /* STANDBY: read-only over OPC UA, the embedder still syncs */
    gds_node_role was = gds_server_role(s);
    CHECK(gds_server_set_role(s, GDS_NODE_STANDBY, 100, 0) == GDS_OK);
    CHECK_EQ_INT(open_tl(admin, &tl, 0x06, &h), UA_STATUSCODE_BADINVALIDSTATE);
    CHECK_EQ_INT(add_cert(admin, &tl, &f->a, true), UA_STATUSCODE_BADINVALIDSTATE);
    CHECK_EQ_INT(remove_cert(admin, &tl, &f->c, true), UA_STATUSCODE_BADINVALIDSTATE);
    CHECK_EQ_INT(open_tl(admin, &tl, 1, &h), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(h_call(admin, &tl, UA_NS0ID_FILETYPE_CLOSE, h, NULL, NULL), UA_STATUSCODE_GOOD);
    CHECK(set_trusted(s, &group, &f->b) == GDS_OK);
    CHECK(trusted_is(s, &f->b));
    CHECK(gds_server_set_role(s, was, 255, 0) == GDS_OK);
}

static void test_methods(gds_server *s, fixture *f, const char *url) {
    UA_NodeId tl = tl_of(s);
    UA_Client *admin = connect_as("admin", url, &f->cert);
    UA_Client *admin2 = connect_as("admin", url, &f->cert);
    UA_Client *plain = connect_as("plain", url, &f->cert);
    if(!CHECK(admin && admin2 && plain && !UA_NodeId_isNull(&tl)))
        goto out;

    CHECK_EQ_INT(user_writable(admin, &tl), 1);
    CHECK_EQ_INT(user_writable(plain, &tl), 0);
    UA_UInt32 h = 0;
    CHECK_EQ_INT(open_tl(plain, &tl, 1, &h), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(add_cert(plain, &tl, &f->a, true), UA_STATUSCODE_BADUSERACCESSDENIED);

    /* AddCertificate */
    CHECK_EQ_INT(add_cert(admin, &tl, &f->a, true), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(add_cert(admin, &tl, &f->caCert, false), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(add_cert(admin, &tl, &f->b, false), UA_STATUSCODE_BADCERTIFICATEINVALID);
    UA_ByteString junk = UA_BYTESTRING("not a certificate");
    CHECK_EQ_INT(add_cert(admin, &tl, &junk, true), UA_STATUSCODE_BADCERTIFICATEINVALID);
    UA_TrustListDataType got;
    UA_TrustListDataType_init(&got);
    if(CHECK(get_list(s, &got))) {
        CHECK_EQ_INT(got.trustedCertificatesSize, 1);
        CHECK_EQ_INT(got.issuerCertificatesSize, 1);
        CHECK(got.trustedCertificatesSize == 1 &&
              UA_ByteString_equal(&got.trustedCertificates[0], &f->a));
    }
    UA_TrustListDataType_clear(&got);

    /* reading; nobody writes meanwhile */
    CHECK_EQ_INT(open_tl(admin, &tl, 1, &h), UA_STATUSCODE_GOOD);
    UA_TrustListDataType_init(&got);
    if(CHECK(read_all(admin, &tl, h, &got)))
        CHECK(got.trustedCertificatesSize == 1 && got.issuerCertificatesSize == 1);
    UA_TrustListDataType_clear(&got);
    UA_UInt32 h2 = 0;
    CHECK_EQ_INT(open_tl(admin2, &tl, 0x06, &h2), UA_STATUSCODE_BADNOTWRITABLE);
    CHECK_EQ_INT(add_cert(admin2, &tl, &f->b, true), UA_STATUSCODE_BADINVALIDSTATE);
    CHECK_EQ_INT(h_call(admin2, &tl, UA_NS0ID_FILETYPE_CLOSE, h, NULL, NULL),
                 UA_STATUSCODE_BADINVALIDARGUMENT); /* another session's handle */
    CHECK_EQ_INT(open_tl(admin, &tl, 0x02, &h2), UA_STATUSCODE_BADINVALIDARGUMENT); /* mode */
    CHECK_EQ_INT(h_call(admin, &tl, UA_NS0ID_FILETYPE_CLOSE, h, NULL, NULL), UA_STATUSCODE_GOOD);

    test_replace(s, f, admin, admin2, &tl);
    test_sync(s, f, admin, &tl);

    /* RemoveCertificate */
    CHECK_EQ_INT(remove_cert(admin, &tl, &f->b, true), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(remove_cert(admin, &tl, &f->b, true), UA_STATUSCODE_BADINVALIDARGUMENT);
    CHECK_EQ_INT(remove_cert(admin, &tl, &f->caCert, false), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(add_cert(admin, &tl, &f->c, true), UA_STATUSCODE_GOOD); /* for the restart */
    UA_TrustListDataType_init(&got);
    if(CHECK(get_list(s, &got)))
        CHECK(got.trustedCertificatesSize == 1 && got.issuerCertificatesSize == 0 &&
              UA_ByteString_equal(&got.trustedCertificates[0], &f->c));
    UA_TrustListDataType_clear(&got);

    /* a session that closes with an open handle does not block writers */
    CHECK_EQ_INT(open_tl(admin2, &tl, 1, &h2), UA_STATUSCODE_GOOD);
    disconnect(admin2);
    admin2 = NULL;
    for(int i = 0; i < 20; i++)
        (void)UA_Client_run_iterate(admin, 20);
    CHECK_EQ_INT(open_tl(admin, &tl, 0x06, &h), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(h_call(admin, &tl, UA_NS0ID_FILETYPE_CLOSE, h, NULL, NULL), UA_STATUSCODE_GOOD);
out:
    disconnect(admin);
    disconnect(admin2);
    disconnect(plain);
    UA_NodeId_clear(&tl);
}

/* ---- the server thread ---- */

static UA_Boolean running = true;
static gds_status runResult = GDS_EIO;

static void *loop_main(void *arg) {
    runResult = gds_server_run(arg, &running);
    return NULL;
}

static void stop_cb(UA_Server *ua, void *data) {
    (void)ua;
    *(UA_Boolean *)data = false;
}

static gds_server *new_server(fixture *f, gds_users *users, UA_UInt16 port) {
    gds_server_config cfg = {0};
    cfg.port = port;
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS plugin trust list test";
    cfg.ownCert = (gds_buf){f->cert.data, f->cert.length};
    cfg.ownKey = (gds_buf){f->key.data, f->key.length};
    cfg.store = f->store;
    cfg.ca = f->ca;
    cfg.users = users;
    cfg.approval = GDS_APPROVE_ALL;
    gds_server *s = NULL;
    return CHECK(gds_server_new(&cfg, &s) == GDS_OK) ? s : NULL;
}

static bool write_users(const char *dir, gds_users *u) {
    char path[1024], cred[256], text[1024];
    static const uint8_t pw[] = PASSWORD;
    if(!CHECK(gds_path(path, sizeof(path), "%s/users", dir) == GDS_OK) ||
       !CHECK(gds_password_hash(pw, sizeof(pw) - 1, 10000, cred, sizeof(cred)) == GDS_OK))
        return false;
    int n = snprintf(text, sizeof(text), "admin SecurityAdmin %s\nplain - %s\n", cred, cred);
    return CHECK(n > 0 && (size_t)n < sizeof(text)) &&
           CHECK(gds_file_write_atomic(path, text, (size_t)n, 0600) == GDS_OK) &&
           CHECK(gds_users_load(path, u) == GDS_OK);
}

static void served(fixture *f, gds_users *users, bool first) {
    UA_UInt16 port = (UA_UInt16)(46000 + getpid() % 1000 + (first ? 0 : 1));
    gds_server *s = new_server(f, users, port);
    if(!s)
        return;
    setup(s, f, first);
    if(first) {
        pthread_t loop;
        running = true;
        if(CHECK(pthread_create(&loop, NULL, loop_main, s) == 0)) {
            char url[64];
            (void)snprintf(url, sizeof(url), "opc.tcp://127.0.0.1:%u", (unsigned)port);
            test_methods(s, f, url);
            (void)UA_Server_addTimedCallback(gds_server_ua(s), stop_cb, &running,
                                             UA_DateTime_nowMonotonic(), NULL);
            (void)pthread_join(loop, NULL);
            CHECK_EQ_INT(runResult, GDS_OK);
        }
    } else {
        /* the file store kept the list */
        UA_TrustListDataType got;
        UA_TrustListDataType_init(&got);
        if(CHECK(get_list(s, &got)))
            CHECK(got.trustedCertificatesSize == 1 &&
                  UA_ByteString_equal(&got.trustedCertificates[0], &f->c));
        UA_TrustListDataType_clear(&got);
    }
    gds_server_delete(s);
}

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    CHECK(setenv("TZ", "UTC", 1) == 0);
    tzset();
    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);

    static uint8_t pw[] = "plugin-tl-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    fixture f;
    memset(&f, 0, sizeof(f));
    /* a fresh store per run: the list persists */
    CHECK(gds_path(f.pki, sizeof(f.pki), "%s/sks-pki-%ld", argv[1], (long)getpid()) == GDS_OK);
    UA_ByteString k = UA_BYTESTRING_NULL;
    gds_buf caBuf = {NULL, 0};
    static gds_users users;
    if(CHECK(gds_ca_openssl_open(&cc, &f.ca) == GDS_OK) &&
       CHECK(gds_store_open(db, &f.store) == GDS_OK) &&
       CHECK(make_cert("CN=OpenGDS plugin tl test", "URI:" TEST_URI, &f.cert, &f.key)) &&
       CHECK(make_cert("CN=push target a", "URI:urn:a", &f.a, &k)) && free_key(&k) &&
       CHECK(make_cert("CN=push target b", "URI:urn:b", &f.b, &k)) && free_key(&k) &&
       CHECK(make_cert("CN=push target c", "URI:urn:c", &f.c, &k)) &&
       CHECK(gds_ca_get_ca_cert(f.ca, &caBuf) == GDS_OK) && write_users(argv[1], &users)) {
        f.caCert = (UA_ByteString){caBuf.len, caBuf.data};
        served(&f, &users, true);
        served(&f, &users, false);
    }
    UA_ByteString_clear(&k);
    gds_buf_free(&caBuf);
    UA_ByteString_clear(&f.cert);
    UA_ByteString_clear(&f.key);
    UA_ByteString_clear(&f.a);
    UA_ByteString_clear(&f.b);
    UA_ByteString_clear(&f.c);
    gds_store_close(f.store);
    gds_ca_close(f.ca);
    return CHECK_DONE();
}
