/* OpenGDS Auditor - minimal mock GDS (seed of the client profile's fake_gds.c)
 * SPDX-License-Identifier: MPL-2.0
 *
 * Lets the pull test client run without a full GDS. It implements the Part 12
 * methods the pull workflow needs on the standard GDS nodes (namespace
 * http://opcfoundation.org/UA/GDS/): FindApplications, RegisterApplication,
 * GetCertificateGroups, GetCertificateStatus, StartSigningRequest,
 * FinishRequest, GetTrustList, and DefaultApplicationGroup TrustList
 * Open/Read/Close. FinishRequest answers Bad_NothingToDo for the first
 * --approve-after polls to simulate an administrator approving the request.
 *
 * NOT A GDS: in-memory records, no roles, a test CA. It accepts any client
 * certificate on the channel (Annex G.1 step 1) and therefore listens on the
 * loopback interface unless --listen-any is given.
 *
 * Usage: mock_gds [--port 4850] [--ca-dir ./demo-ca] [--user registrar:secret]
 *                 [--approve-after 2] [--listen-any] [--anonymous]
 * --anonymous also accepts Anonymous sessions, as a GDS does for an
 * application that renews with its issued certificate (ApplicationSelfAdmin,
 * 12 §7.6 "Connect"); the mock has no roles, so it checks nothing more.
 */
#include <open62541/nodeids_gds.h>
#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/types_gds_generated.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "common/limits.h"
#include "common/safeint.h"
#include "common/ua_args.h"
#include "test_ca.h"
#include "common/banned.h"

#define GDS_NS_URI "http://opcfoundation.org/UA/GDS/"
#define GDS_APP_URI "urn:opengds:test:mockgds"
#define MAX_APPS 512 /* the GDS spec tests register a few hundred records per run */
#define MAX_REQS 32

/* Single-threaded server: the state below is touched only from method
 * callbacks on the server thread. */
static testca_t ca;
static UA_UInt16 ns;
static long approveAfter = 2;

typedef struct {
    UA_ApplicationRecordDataType rec;
    UA_Boolean hasCert;
} App;
static App apps[MAX_APPS];
static size_t appsN = 0;

typedef struct {
    UA_NodeId requestId, appId;
    gds_buf csr;
    long polls;
    UA_Boolean done;
} Req;
static Req reqs[MAX_REQS];
static size_t reqsN = 0;

/* One open handle on the TrustList file is enough for the fixture */
static UA_ByteString tlFile;
static size_t tlPos;
static UA_UInt32 tlHandle = 0;

static const UA_DataType *recType(void) {
    return &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE];
}

static App *findApp(const UA_NodeId *id) {
    for(size_t i = 0; i < appsN; i++)
        if(UA_NodeId_equal(&apps[i].rec.applicationId, id))
            return &apps[i];
    return NULL;
}

#define METHOD(name)                                                                     \
    static UA_StatusCode name(UA_Server *server, const UA_NodeId *sessionId,             \
                              void *sessionContext, const UA_NodeId *methodId,           \
                              void *methodContext, const UA_NodeId *objectId,            \
                              void *objectContext, size_t inputSize,                     \
                              const UA_Variant *input, size_t outputSize, UA_Variant *output)
#define UNUSED_ARGS                                                                      \
    (void)server; (void)sessionId; (void)sessionContext; (void)methodId;                 \
    (void)methodContext; (void)objectId; (void)objectContext; (void)outputSize; \
    (void)input; (void)output; (void)inputSize
/* Every input checked before use (docs/architecture.md, input validation) */
#define NEED_INPUTS(n)                                                                   \
    if(inputSize < (n))                                                                  \
        return UA_STATUSCODE_BADARGUMENTSMISSING;
#define ARG(i, type, var)                                                                \
    const type *var = NULL; /* NOLINT(bugprone-macro-parentheses): type name */          \
    do {                                                                                 \
        const void *p_ = NULL;                                                           \
        UA_StatusCode r_ = gds_arg_scalar(&input[i], &UA_TYPES[UA_TYPES_##type##_IDX], &p_); \
        if(r_ != UA_STATUSCODE_GOOD)                                                     \
            return r_;                                                                   \
        (var) = p_;                                                                      \
    } while(0)

/* map from type name to UA_TYPES index for ARG() */
#define UA_TYPES_UA_NodeId_IDX UA_TYPES_NODEID
#define UA_TYPES_UA_Byte_IDX UA_TYPES_BYTE
#define UA_TYPES_UA_UInt32_IDX UA_TYPES_UINT32
#define UA_TYPES_UA_Int32_IDX UA_TYPES_INT32

METHOD(findApplications) {
    UNUSED_ARGS;
    NEED_INPUTS(1);
    const UA_String *uri = NULL;
    UA_StatusCode r = gds_arg_string(&input[0], GDS_MAX_APPLICATION_URI, &uri);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    size_t n = 0;
    for(size_t i = 0; i < appsN; i++)
        if(UA_String_equal(&apps[i].rec.applicationUri, uri))
            n++;
    UA_ApplicationRecordDataType *res = NULL;
    if(n) {
        res = UA_Array_new(n, recType());
        if(!res)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        size_t k = 0;
        for(size_t i = 0; i < appsN && r == UA_STATUSCODE_GOOD; i++)
            if(UA_String_equal(&apps[i].rec.applicationUri, uri))
                r = UA_copy(&apps[i].rec, &res[k++], recType());
        if(r != UA_STATUSCODE_GOOD) {
            UA_Array_delete(res, n, recType());
            return r;
        }
        UA_Variant_setArray(&output[0], res, n, recType());
    } else {
        UA_Variant_setArray(&output[0], UA_EMPTY_ARRAY_SENTINEL, 0, recType());
    }
    printf("[mock-gds] FindApplications(%.*s) -> %zu record(s)\n", (int)uri->length,
           (const char *)uri->data, n);
    return UA_STATUSCODE_GOOD;
}

METHOD(registerApplication) {
    UNUSED_ARGS;
    NEED_INPUTS(1);
    const void *p = NULL;
    UA_StatusCode r = gds_arg_scalar(&input[0], recType(), &p);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_ApplicationRecordDataType *in = p;
    if(in->applicationUri.length == 0 || in->applicationUri.length > GDS_MAX_APPLICATION_URI)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(appsN == MAX_APPS)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    App *a = &apps[appsN];
    memset(a, 0, sizeof(*a));
    if((r = UA_copy(in, &a->rec, recType())) != UA_STATUSCODE_GOOD)
        return r;
    UA_NodeId_clear(&a->rec.applicationId);
    a->rec.applicationId = UA_NODEID_GUID(ns, UA_Guid_random());
    if((r = UA_Variant_setScalarCopy(&output[0], &a->rec.applicationId,
                                     &UA_TYPES[UA_TYPES_NODEID])) != UA_STATUSCODE_GOOD) {
        UA_clear(&a->rec, recType());
        return r;
    }
    appsN++;
    printf("[mock-gds] RegisterApplication(%.*s) -> new record\n",
           (int)a->rec.applicationUri.length, (const char *)a->rec.applicationUri.data);
    return UA_STATUSCODE_GOOD;
}

METHOD(getCertificateGroups) {
    UNUSED_ARGS;
    NEED_INPUTS(1);
    ARG(0, UA_NodeId, appId);
    if(!findApp(appId))
        return UA_STATUSCODE_BADNOTFOUND;
    UA_NodeId g = UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    return UA_Variant_setArrayCopy(&output[0], &g, 1, &UA_TYPES[UA_TYPES_NODEID]);
}

METHOD(getCertificateStatus) {
    UNUSED_ARGS;
    NEED_INPUTS(1);
    ARG(0, UA_NodeId, appId);
    App *a = findApp(appId);
    if(!a)
        return UA_STATUSCODE_BADNOTFOUND;
    UA_Boolean update = !a->hasCert;
    return UA_Variant_setScalarCopy(&output[0], &update, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

METHOD(startSigningRequest) {
    UNUSED_ARGS;
    NEED_INPUTS(4);
    ARG(0, UA_NodeId, appId);
    if(!findApp(appId))
        return UA_STATUSCODE_BADNOTFOUND;
    const UA_ByteString *csr = NULL;
    UA_StatusCode r = gds_arg_bytes(&input[3], GDS_MAX_CSR_SIZE, &csr);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(csr->length == 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(reqsN == MAX_REQS)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    Req *q = &reqs[reqsN];
    memset(q, 0, sizeof(*q));
    if(gds_buf_dup(csr->data, csr->length, &q->csr) != GDS_OK)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    if(UA_NodeId_copy(appId, &q->appId) != UA_STATUSCODE_GOOD) {
        gds_buf_free(&q->csr);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    q->requestId = UA_NODEID_GUID(ns, UA_Guid_random());
    r = UA_Variant_setScalarCopy(&output[0], &q->requestId, &UA_TYPES[UA_TYPES_NODEID]);
    if(r != UA_STATUSCODE_GOOD) {
        gds_buf_free(&q->csr);
        UA_NodeId_clear(&q->appId);
        return r;
    }
    reqsN++;
    printf("[mock-gds] StartSigningRequest: CSR %zu bytes queued, awaiting approval\n",
           csr->length);
    return UA_STATUSCODE_GOOD;
}

METHOD(finishRequest) {
    UNUSED_ARGS;
    NEED_INPUTS(2);
    ARG(0, UA_NodeId, appId);
    ARG(1, UA_NodeId, requestId);
    App *a = findApp(appId);
    if(!a)
        return UA_STATUSCODE_BADNOTFOUND;
    Req *q = NULL;
    for(size_t i = 0; i < reqsN && !q; i++)
        if(UA_NodeId_equal(&reqs[i].requestId, requestId) && UA_NodeId_equal(&reqs[i].appId, appId))
            q = &reqs[i];
    if(!q)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(q->done)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(q->polls < approveAfter) {
        q->polls++;
        return UA_STATUSCODE_BADNOTHINGTODO;
    }
    printf("[mock-gds] request approved by (simulated) administrator\n");

    /* The SAN URI comes from the registered record, not from the CSR */
    char uri[GDS_MAX_APPLICATION_URI + 1];
    if(gds_path(uri, sizeof(uri), "%.*s", (int)a->rec.applicationUri.length,
                (const char *)a->rec.applicationUri.data) != GDS_OK)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    gds_buf cert = {0}, caDer = {0};
    if(testca_sign_csr(&ca, &q->csr, uri, TESTCA_MAX_DAYS, &cert) != GDS_OK)
        return UA_STATUSCODE_BADREQUESTNOTALLOWED; /* CSR invalid / no proof of possession */
    if(testca_cert_der(&ca, &caDer) != GDS_OK) {
        gds_buf_free(&cert);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_ByteString c = {cert.len, cert.data}, empty = UA_BYTESTRING_NULL;
    UA_ByteString issuer = {caDer.len, caDer.data};
    UA_StatusCode r = UA_Variant_setScalarCopy(&output[0], &c, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD) /* CSR flow: no private key */
        r = UA_Variant_setScalarCopy(&output[1], &empty, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setArrayCopy(&output[2], &issuer, 1, &UA_TYPES[UA_TYPES_BYTESTRING]);
    gds_buf_free(&caDer);
    gds_buf_free(&cert);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    q->done = true;
    a->hasCert = true;
    printf("[mock-gds] FinishRequest: certificate issued for %s\n", uri);
    return UA_STATUSCODE_GOOD;
}

METHOD(getTrustList) {
    UNUSED_ARGS;
    NEED_INPUTS(1);
    ARG(0, UA_NodeId, appId);
    if(!findApp(appId))
        return UA_STATUSCODE_BADNOTFOUND;
    UA_NodeId tl =
        UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST);
    return UA_Variant_setScalarCopy(&output[0], &tl, &UA_TYPES[UA_TYPES_NODEID]);
}

/* TrustList (FileType) read access: the file content is the binary encoded
 * TrustListDataType (OPC 10000-12 §7.8.2). */
METHOD(tlOpen) {
    UNUSED_ARGS;
    NEED_INPUTS(1);
    ARG(0, UA_Byte, mode);
    if(*mode != 0x01)
        return UA_STATUSCODE_BADNOTWRITABLE; /* read only here */
    if(tlHandle)
        return UA_STATUSCODE_BADINVALIDSTATE;
    gds_buf caDer = {0}, crl = {0};
    if(testca_cert_der(&ca, &caDer) != GDS_OK || testca_crl_der(&ca, &crl) != GDS_OK) {
        gds_buf_free(&caDer);
        gds_buf_free(&crl);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_ByteString c = {caDer.len, caDer.data}, l = {crl.len, crl.data};
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    tl.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    tl.trustedCertificates = &c;
    tl.trustedCertificatesSize = 1;
    tl.trustedCrls = &l;
    tl.trustedCrlsSize = 1;
    UA_ByteString_clear(&tlFile);
    UA_StatusCode res = UA_encodeBinary(&tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &tlFile, NULL);
    gds_buf_free(&caDer);
    gds_buf_free(&crl);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    UA_UInt32 h = 0;
    while(h == 0) /* random, non-zero handle */
        if(RAND_bytes((unsigned char *)&h, sizeof(h)) != 1)
            return UA_STATUSCODE_BADINTERNALERROR;
    tlPos = 0;
    tlHandle = h;
    return UA_Variant_setScalarCopy(&output[0], &tlHandle, &UA_TYPES[UA_TYPES_UINT32]);
}

METHOD(tlRead) {
    UNUSED_ARGS;
    NEED_INPUTS(2);
    ARG(0, UA_UInt32, handle);
    ARG(1, UA_Int32, len);
    if(!tlHandle || *handle != tlHandle || *len < 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    GDS_ASSERT(tlPos <= tlFile.length);
    size_t n = tlFile.length - tlPos;
    if((size_t)*len < n)
        n = (size_t)*len;
    UA_ByteString chunk = {n, n ? tlFile.data + tlPos : NULL};
    UA_StatusCode r = UA_Variant_setScalarCopy(&output[0], &chunk, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        tlPos += n;
    return r;
}

METHOD(tlClose) {
    UNUSED_ARGS;
    NEED_INPUTS(1);
    ARG(0, UA_UInt32, handle);
    if(!tlHandle || *handle != tlHandle)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    tlHandle = 0;
    return UA_STATUSCODE_GOOD;
}

static int usage(const char *argv0) {
    fprintf(stderr, "usage: %s [--port N] [--ca-dir DIR] [--user u:p] [--approve-after N] [--listen-any] [--anonymous]\n",
            argv0);
    return 2;
}

/* Self-test main: one linear script of steps, kept in one place on purpose. */
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
int main(int argc, char **argv) {
    long port = 4850;
    const char *caDir = "./demo-ca";
    char userSpec[160] = "registrar:secret";
    bool listenAny = false, anonymous = false;
    for(int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if(!strcmp(a, "--listen-any")) {
            listenAny = true;
            continue;
        }
        if(!strcmp(a, "--anonymous")) {
            anonymous = true;
            continue;
        }
        const char *v = i + 1 < argc ? argv[++i] : NULL;
        if(!v)
            return usage(argv[0]);
        if(!strcmp(a, "--port")) {
            if(!gds_parse_long(v, 1, 65535, &port))
                return usage(argv[0]);
        } else if(!strcmp(a, "--ca-dir")) {
            caDir = v;
        } else if(!strcmp(a, "--user")) {
            if(gds_path(userSpec, sizeof(userSpec), "%s", v) != GDS_OK)
                return usage(argv[0]);
        } else if(!strcmp(a, "--approve-after")) {
            if(!gds_parse_long(v, 0, 1000, &approveAfter))
                return usage(argv[0]);
        } else {
            return usage(argv[0]);
        }
    }
    char *colon = strchr(userSpec, ':');
    if(!colon || colon == userSpec) {
        fprintf(stderr, "--user expects user:password\n");
        return 2;
    }
    *colon = '\0';
    printf("[mock-gds] OpenGDS Auditor fixture, not a GDS\n");

    if(testca_load_or_create(&ca, caDir, "OpenGDS Auditor TEST CA") != GDS_OK) {
        fprintf(stderr, "test CA failed\n");
        return 1;
    }
    /* Export the CRL next to the CA so clients can pin both */
    {
        gds_buf crl = {0};
        char path[GDS_MAX_PATH];
        if(testca_crl_der(&ca, &crl) != GDS_OK ||
           gds_path(path, sizeof(path), "%s/ca.crl", caDir) != GDS_OK ||
           gds_file_write_atomic(path, crl.data, crl.len, 0644) != GDS_OK) {
            fprintf(stderr, "cannot write CRL\n");
            return 1;
        }
        gds_buf_free(&crl);
    }

    /* Own application certificate, issued by the test CA */
    gds_buf cert = {0}, key = {0};
    if(testca_identity(&ca, caDir, "mockgds", "OpenGDS Mock GDS", GDS_APP_URI, &cert, &key) != GDS_OK) {
        fprintf(stderr, "cannot issue GDS certificate\n");
        return 1;
    }

    UA_Server *server = UA_Server_new();
    if(!server)
        return 1;
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ByteString c = {cert.len, cert.data}, k = {key.len, key.data};
    UA_StatusCode res = UA_ServerConfig_setDefaultWithSecureSecurityPolicies(
        config, (UA_UInt16)port, &c, &k, NULL, 0, NULL, 0, NULL, 0);
    if(res != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "config: %s\n", UA_StatusCode_name(res));
        return 1;
    }
    if(!listenAny) {
        char url[64];
        if(gds_path(url, sizeof(url), "opc.tcp://127.0.0.1:%ld", port) != GDS_OK)
            return 1;
        UA_Array_delete(config->serverUrls, config->serverUrlsSize, &UA_TYPES[UA_TYPES_STRING]);
        config->serverUrls = UA_String_new();
        if(!config->serverUrls)
            return 1;
        *config->serverUrls = UA_STRING_ALLOC(url);
        config->serverUrlsSize = 1;
    }
    /* setDefaultWithSecureSecurityPolicies adds #None for GetEndpoints and
     * FindServers only, never for a session (carried patch, see
     * docs/upstream/02-secure-policies-none-discovery.md) */
    config->allowNonePolicyPassword = false;
    UA_String_clear(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri = UA_STRING_ALLOC(GDS_APP_URI);
    UA_LocalizedText_clear(&config->applicationDescription.applicationName);
    config->applicationDescription.applicationName = UA_LOCALIZEDTEXT_ALLOC("en", "OpenGDS Mock GDS");
    config->applicationDescription.applicationType = UA_APPLICATIONTYPE_SERVER;

    /* Applications that come to a GDS for their first certificate are not
     * yet trusted: accept any client certificate on the channel and
     * authenticate the user instead (Part 12 §7.4, Annex G.1 step 1). */
    config->secureChannelPKI.clear(&config->secureChannelPKI);
    UA_CertificateGroup_AcceptAll(&config->secureChannelPKI);
    config->sessionPKI.clear(&config->sessionPKI);
    UA_CertificateGroup_AcceptAll(&config->sessionPKI);

    UA_UsernamePasswordLogin login = {UA_STRING(userSpec), UA_STRING(colon + 1)};
    config->accessControl.clear(&config->accessControl);
    UA_String policyUri = UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss");
    if(UA_AccessControl_default(config, anonymous, &policyUri, 1, &login) != UA_STATUSCODE_GOOD)
        return 1;

    ns = UA_Server_addNamespace(server, GDS_NS_URI); /* returns the existing index */

    struct {
        UA_UInt32 id;
        UA_MethodCallback cb;
    } m[] = {
        {UA_GDSID_DIRECTORY_FINDAPPLICATIONS, findApplications},
        {UA_GDSID_DIRECTORY_REGISTERAPPLICATION, registerApplication},
        {UA_GDSID_DIRECTORY_GETCERTIFICATEGROUPS, getCertificateGroups},
        {UA_GDSID_DIRECTORY_GETCERTIFICATESTATUS, getCertificateStatus},
        {UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, startSigningRequest},
        {UA_GDSID_DIRECTORY_FINISHREQUEST, finishRequest},
        {UA_GDSID_DIRECTORY_GETTRUSTLIST, getTrustList},
        {UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPEN, tlOpen},
        {UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_READ, tlRead},
        {UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSE, tlClose},
    };
    for(size_t i = 0; i < GDS_ARRAY_SIZE(m); i++) {
        res = UA_Server_setMethodNodeCallback(server, UA_NODEID_NUMERIC(ns, m[i].id), m[i].cb);
        if(res != UA_STATUSCODE_GOOD) {
            fprintf(stderr, "method ns=%u;i=%u: %s\n", ns, m[i].id, UA_StatusCode_name(res));
            return 1;
        }
    }
    printf("[mock-gds] listening on opc.tcp://%s:%ld  (GDS ns=%u, approve after %ld polls)\n",
           listenAny ? "0.0.0.0" : "127.0.0.1", port, ns, approveAfter);
    fflush(stdout);

    res = UA_Server_runUntilInterrupt(server);
    UA_Server_delete(server);
    UA_ByteString_clear(&tlFile);
    for(size_t i = 0; i < appsN; i++)
        UA_clear(&apps[i].rec, recType());
    for(size_t i = 0; i < reqsN; i++) {
        gds_buf_free(&reqs[i].csr);
        UA_NodeId_clear(&reqs[i].requestId);
        UA_NodeId_clear(&reqs[i].appId);
    }
    gds_buf_free(&cert);
    gds_buf_free_secret(&key);
    testca_free(&ca);
    return res == UA_STATUSCODE_GOOD ? 0 : 1;
}
