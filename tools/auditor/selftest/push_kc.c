/* OpenGDS Auditor self-test target: KeyCredential push (OPC 10000-12 §8.6).
 * SPDX-License-Identifier: MPL-2.0
 *
 * The KeyCredentialConfiguration Object of every open62541 server gets a
 * working CreateCredential (§8.6.3); each credential is an Object of
 * KeyCredentialConfigurationType with ResourceUri, ProfileUri,
 * EndpointUrls, CredentialId and ServiceStatus, and the methods
 * GetEncryptingKey, UpdateCredential and DeleteCredential (§8.6.5 -
 * §8.6.8). Secrets must come encrypted for the target's certificate
 * (RsaEncryptedSecret, OPC 10000-4 §7.40.2.4); a plaintext secret is
 * refused, which §8.6.7 allows. ServiceStatus is the result of a TCP
 * connect to the first EndpointUrl every second, for loopback hosts only.
 *
 * Single-threaded like push_mgmt.c: callbacks run on the server thread. */
#include "push_kc.h"

#include <open62541/plugin/log_stdout.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/buf.h"
#include "common/compiler.h"
#include "common/enc_secret.h"
#include "common/limits.h"
#include "common/safeint.h"
#include "x509util.h"
#include "common/banned.h"

#define PK_MAX 8
#define PK_MAX_STR 1024
#define PK_MAX_URLS 4
#define PK_PROBE_MS 1000.0
#define PK_CONNECT_MS 300
#define PK_MAX_NAME 128

typedef struct {
    bool used;
    UA_NodeId node;
    char url[PK_MAX_STR + 1]; /* the first EndpointUrl ("" none) */
    UA_ByteString secret;     /* decrypted */
    bool hasSecret;
} pk_cred;

static struct {
    UA_Server *server;
    ps_admin_fn isAdmin;
    pm_mode_fn modeOf;
    pk_cred cred[PK_MAX];
    UA_UInt64 probe;
} K;

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

static bool breaking(const char *name) {
    return pm_breaking(name);
}

#define METHOD_ARGS                                                                        \
    UA_Server *server, const UA_NodeId *sessionId, void *sessionContext,                   \
        const UA_NodeId *methodId, void *methodContext, const UA_NodeId *objectId,         \
        void *objectContext, size_t inputSize, const UA_Variant *input, size_t outputSize, \
        UA_Variant *output
#define UNUSED_ARGS                                                                          \
    (void)server, (void)sessionContext, (void)methodId, (void)methodContext, (void)objectId, \
        (void)objectContext, (void)outputSize

/* Every method of §8.6: an encrypted channel and SecurityAdmin (§8.2) */
static UA_StatusCode access_check(const UA_NodeId *sessionId) {
    if(K.modeOf && K.modeOf(sessionId) < UA_MESSAGESECURITYMODE_SIGNANDENCRYPT &&
       !breaking("allow-none") && !breaking("sign-is-enough"))
        return UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;
    if(!breaking("kc-no-secadmin") && !(K.isAdmin && K.isAdmin(sessionId)))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    return UA_STATUSCODE_GOOD;
}

static bool scalar(const UA_Variant *in, size_t inN, size_t i, const UA_DataType *t) {
    return i < inN && UA_Variant_hasScalarType(&in[i], t);
}

/* ---------------- Argument checks (§8.6.3) ---------------- */

static bool scheme_char(UA_Byte c, bool first) {
    bool alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    return first ? alpha : alpha || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.';
}

/* The end of an RFC 3986 scheme (the ':'), or 0 */
static size_t scheme_end(const UA_String *s) {
    for(size_t i = 0; i < s->length; i++) {
        if(s->data[i] == ':')
            return i;
        if(!scheme_char(s->data[i], i == 0))
            return 0;
    }
    return 0;
}

/* An absolute URI: scheme ':' and a rest of visible ASCII */
static bool valid_uri(const UA_String *s) {
    if(s->length == 0 || s->length > PK_MAX_STR)
        return false;
    size_t e = scheme_end(s);
    if(e == 0 || e + 1 >= s->length)
        return false;
    for(size_t i = e + 1; i < s->length; i++)
        if(s->data[i] <= ' ' || s->data[i] >= 0x7f)
            return false;
    return true;
}

/* A URL: a URI with "//" and a host after the scheme */
static bool valid_url(const UA_String *s) {
    if(!valid_uri(s))
        return false;
    size_t e = scheme_end(s);
    return s->length > e + 3 && s->data[e + 1] == '/' && s->data[e + 2] == '/' &&
           s->data[e + 3] != '/' && s->data[e + 3] != ':';
}

static bool valid_name(const UA_String *s) {
    if(s->length == 0 || s->length > PK_MAX_NAME)
        return false;
    for(size_t i = 0; i < s->length; i++)
        if(s->data[i] < ' ' || s->data[i] == 0x7f)
            return false;
    return true;
}

/* CreateCredential's inputs: Name, ResourceUri, ProfileUri, EndpointUrls */
static UA_StatusCode create_args(size_t inN, const UA_Variant *in) {
    for(size_t i = 0; i < 3; i++)
        if(!scalar(in, inN, i, &UA_TYPES[UA_TYPES_STRING]))
            return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(inN < 4 || in[3].type != &UA_TYPES[UA_TYPES_STRING] || UA_Variant_isScalar(&in[3]) ||
       in[3].arrayLength > PK_MAX_URLS)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(!valid_name(in[0].data))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(breaking("kc-no-uri-check"))
        return UA_STATUSCODE_GOOD;
    if(!valid_uri(in[1].data) || !valid_uri(in[2].data))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    const UA_String *urls = in[3].data;
    for(size_t i = 0; i < in[3].arrayLength; i++)
        if(!valid_url(&urls[i]))
            return UA_STATUSCODE_BADINVALIDARGUMENT;
    return UA_STATUSCODE_GOOD;
}

/* ---------------- Credentials ---------------- */

static pk_cred *find(const UA_NodeId *node) {
    for(size_t i = 0; i < PK_MAX; i++)
        if(K.cred[i].used && UA_NodeId_equal(&K.cred[i].node, node))
            return &K.cred[i];
    return NULL;
}

static void cred_clear(pk_cred *c) {
    if(c->secret.length)
        OPENSSL_cleanse(c->secret.data, c->secret.length);
    UA_ByteString_clear(&c->secret);
    UA_NodeId_clear(&c->node);
    memset(c, 0, sizeof(*c));
}

static UA_StatusCode add_prop(const UA_NodeId *obj, const char *name, const UA_Variant *value,
                              UA_Byte access) {
    UA_VariableAttributes a = UA_VariableAttributes_default;
    a.displayName = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)name);
    a.value = *value;
    a.dataType = value->type->typeId;
    UA_UInt32 dims[1] = {0};
    a.valueRank = UA_VALUERANK_SCALAR;
    if(!UA_Variant_isScalar(value)) {
        a.valueRank = UA_VALUERANK_ONE_DIMENSION;
        a.arrayDimensions = dims;
        a.arrayDimensionsSize = 1;
    }
    a.accessLevel = access;
    return UA_Server_addVariableNode(K.server, UA_NODEID_NUMERIC(1, 0), *obj,
                                     ns0(UA_NS0ID_HASPROPERTY),
                                     UA_QUALIFIEDNAME(0, (char *)(uintptr_t)name),
                                     ns0(UA_NS0ID_PROPERTYTYPE), a, NULL, NULL);
}

static UA_StatusCode set_prop(const UA_NodeId *obj, const char *name, const void *v,
                              const UA_DataType *type) {
    UA_QualifiedName qn = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)name);
    UA_BrowsePathResult bpr = UA_Server_browseSimplifiedBrowsePath(K.server, *obj, 1, &qn);
    UA_StatusCode r = bpr.statusCode;
    if(r == UA_STATUSCODE_GOOD && bpr.targetsSize < 1)
        r = UA_STATUSCODE_BADNOTFOUND;
    if(r == UA_STATUSCODE_GOOD) {
        UA_Variant val;
        UA_Variant_setScalar(&val, (void *)(uintptr_t)v, type);
        r = UA_Server_writeValue(K.server, bpr.targets[0].targetId.nodeId, val);
    }
    UA_BrowsePathResult_clear(&bpr);
    return r;
}

/* The optional children of §8.6.5 the instantiation leaves out */
static UA_StatusCode add_children(const UA_NodeId *obj, const UA_Variant *urls) {
    UA_String empty = UA_STRING_NULL;
    UA_StatusCode st = UA_STATUSCODE_BADWAITINGFORINITIALDATA;
    UA_Variant v;
    UA_StatusCode r = add_prop(obj, "EndpointUrls", urls, UA_ACCESSLEVELMASK_READ);
    UA_Variant_setScalar(&v, &empty, &UA_TYPES[UA_TYPES_STRING]);
    r |= add_prop(obj, "CredentialId", &v, UA_ACCESSLEVELMASK_READ);
    UA_Variant_setScalar(&v, &st, &UA_TYPES[UA_TYPES_STATUSCODE]);
    r |= add_prop(obj, "ServiceStatus", &v, UA_ACCESSLEVELMASK_READ);
    static const UA_UInt32 methods[3] = {UA_NS0ID_KEYCREDENTIALCONFIGURATIONTYPE_GETENCRYPTINGKEY,
                                         UA_NS0ID_KEYCREDENTIALCONFIGURATIONTYPE_UPDATECREDENTIAL,
                                         UA_NS0ID_KEYCREDENTIALCONFIGURATIONTYPE_DELETECREDENTIAL};
    for(size_t i = 0; i < 3; i++)
        r |= UA_Server_addReference(K.server, *obj, ns0(UA_NS0ID_HASCOMPONENT),
                                    UA_EXPANDEDNODEID_NUMERIC(0, methods[i]), true);
    return r == UA_STATUSCODE_GOOD ? r : UA_STATUSCODE_BADINTERNALERROR;
}

static UA_StatusCode add_object(const UA_Variant *in, UA_NodeId *out) {
    const UA_String *name = in[0].data;
    char bn[PK_MAX_NAME + 1];
    memcpy(bn, name->data, name->length);
    bn[name->length] = '\0';
    UA_ObjectAttributes oa = UA_ObjectAttributes_default;
    oa.displayName = UA_LOCALIZEDTEXT("", bn);
    UA_StatusCode r = UA_Server_addObjectNode(
        K.server, UA_NODEID_NUMERIC(1, 0), ns0(UA_NS0ID_KEYCREDENTIALCONFIGURATION),
        ns0(UA_NS0ID_HASCOMPONENT), UA_QUALIFIEDNAME(1, bn),
        ns0(UA_NS0ID_KEYCREDENTIALCONFIGURATIONTYPE), oa, NULL, out);
    if(r != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "CreateCredential: Object %s",
                       UA_StatusCode_name(r));
        return r;
    }
    r = set_prop(out, "ResourceUri", in[1].data, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_prop(out, "ProfileUri", in[2].data, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = add_children(out, &in[3]);
    if(r != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "CreateCredential: %s",
                       UA_StatusCode_name(r));
        (void)UA_Server_deleteNode(K.server, *out, true);
        UA_NodeId_clear(out);
    }
    return r;
}

static pk_cred *free_slot(void) {
    for(size_t i = 0; i < PK_MAX; i++)
        if(!K.cred[i].used)
            return &K.cred[i];
    return NULL;
}

/* CreateCredential (12 §8.6.3) */
static UA_StatusCode kcCreate(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode r = access_check(sessionId);
    if(r == UA_STATUSCODE_GOOD)
        r = create_args(inputSize, input);
    pk_cred *c = r == UA_STATUSCODE_GOOD ? free_slot() : NULL;
    if(r == UA_STATUSCODE_GOOD && !c)
        r = UA_STATUSCODE_BADTOOMANYOPERATIONS;
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_NodeId node = UA_NODEID_NUMERIC(1, 0x7ffff000u);
    if(!breaking("kc-create-noop")) { /* the mutant answers with a NodeId that names nothing */
        r = add_object(input, &node);
        if(r != UA_STATUSCODE_GOOD)
            return r;
        c->used = true;
        c->node = node;
        const UA_String *urls = input[3].data;
        if(input[3].arrayLength > 0 && urls[0].length <= PK_MAX_STR) {
            memcpy(c->url, urls[0].data, urls[0].length);
            c->url[urls[0].length] = '\0';
        }
    }
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "CreateCredential: a new credential");
    return UA_Variant_setScalarCopy(&output[0], &node, &UA_TYPES[UA_TYPES_NODEID]);
}

/* ---------------- The target's own certificates ---------------- */

/* The certificate the policy uses (NULL: no such policy). Borrowed. */
static const UA_ByteString *own_cert(const UA_String *policy) {
    UA_ServerConfig *cfg = UA_Server_getConfig(K.server);
    for(size_t i = 0; i < cfg->securityPoliciesSize; i++)
        if(UA_String_equal(&cfg->securityPolicies[i].policyUri, policy) &&
           cfg->securityPolicies[i].localCertificate.length)
            return &cfg->securityPolicies[i].localCertificate;
    return NULL;
}

static bool hex_equal(const char *upper, const UA_Byte *any) {
    for(size_t i = 0; i < GDS_SHA1_HEX - 1; i++) {
        UA_Byte c = any[i] >= 'a' && any[i] <= 'f' ? (UA_Byte)(any[i] - 'a' + 'A') : any[i];
        if(c != (UA_Byte)upper[i])
            return false;
    }
    return true;
}

/* Is thumb (SHA1 hex, any case) one of the certificates the target uses? */
static const UA_ByteString *own_cert_by_thumb(const UA_String *thumb) {
    UA_ServerConfig *cfg = UA_Server_getConfig(K.server);
    if(thumb->length != GDS_SHA1_HEX - 1)
        return NULL;
    for(size_t i = 0; i < cfg->securityPoliciesSize; i++) {
        const UA_ByteString *c = &cfg->securityPolicies[i].localCertificate;
        char hex[GDS_SHA1_HEX];
        gds_buf b = {c->data, c->length};
        if(c->length && gds_sha1_hex(&b, hex) == GDS_OK &&
           hex_equal(hex, thumb->data))
            return c;
    }
    return NULL;
}

/* GetEncryptingKey (12 §8.6.6): the certificate of the requested RSA
 * policy, or of Aes256_Sha256_RsaPss */
static UA_StatusCode kcGetKey(METHOD_ARGS) {
    UNUSED_ARGS;
    UA_StatusCode r = access_check(sessionId);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(!find(objectId))
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    if(!scalar(input, inputSize, 0, &UA_TYPES[UA_TYPES_STRING]) ||
       !scalar(input, inputSize, 1, &UA_TYPES[UA_TYPES_STRING]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    const UA_String *id = input[0].data, *req = input[1].data;
    if(id->length == 0 || id->length > PK_MAX_NAME)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_String pol = UA_STRING(GDS_POLICY_AES256_RSAPSS);
    if(req->length && gds_enc_secret_policy_ok((const char *)req->data, req->length) &&
       own_cert(req))
        pol = *req;
    const UA_ByteString *cert = own_cert(&pol);
    if(!cert)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_ByteString empty = UA_BYTESTRING_NULL;
    r = UA_Variant_setScalarCopy(&output[0], breaking("kc-empty-key") ? &empty : cert,
                                 &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[1], &pol, &UA_TYPES[UA_TYPES_STRING]);
    return r;
}

/* ---------------- UpdateCredential (12 §8.6.7) ---------------- */

static UA_StatusCode update_args(size_t inN, const UA_Variant *in) {
    if(!scalar(in, inN, 0, &UA_TYPES[UA_TYPES_STRING]) ||
       !scalar(in, inN, 1, &UA_TYPES[UA_TYPES_BYTESTRING]) ||
       !scalar(in, inN, 2, &UA_TYPES[UA_TYPES_STRING]) ||
       !scalar(in, inN, 3, &UA_TYPES[UA_TYPES_STRING]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    const UA_String *id = in[0].data;
    const UA_ByteString *sec = in[1].data;
    if(id->length == 0 || id->length > PK_MAX_NAME || sec->length == 0 ||
       sec->length > GDS_MAX_SECRET * 2)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return UA_STATUSCODE_GOOD;
}

/* The secret in plain text: decrypted when a policy is given */
static UA_StatusCode update_secret(const UA_Variant *in, UA_ByteString *plain) {
    const UA_ByteString *sec = in[1].data;
    const UA_String *thumb = in[2].data, *pol = in[3].data;
    if(pol->length == 0) /* plaintext (§8.6.7 allows it; this target does not) */
        return breaking("kc-accept-plaintext") ? UA_ByteString_copy(sec, plain)
                                               : UA_STATUSCODE_BADSECURITYPOLICYREJECTED;
    bool known = gds_enc_secret_policy_ok((const char *)pol->data, pol->length);
    if(!known && !breaking("kc-any-policy"))
        return UA_STATUSCODE_BADSECURITYPOLICYREJECTED;
    const UA_ByteString *cert = own_cert_by_thumb(thumb);
    if(!cert && !breaking("kc-any-thumbprint"))
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    if(!known || !cert) /* a mutant let it through: keep the bytes as they are */
        return UA_ByteString_copy(sec, plain);
    const UA_ByteString *key = pm_own_key();
    gds_buf kb = {key->data, key->length}, cb = {cert->data, cert->length};
    gds_buf blob = {sec->data, sec->length}, out = {0};
    EVP_PKEY *k = x509_parse_key(&kb);
    gds_status gs = k ? gds_enc_secret_rsa_decrypt((const char *)pol->data, pol->length, &cb, k,
                                                   &blob, &out)
                      : GDS_ECRYPTO;
    EVP_PKEY_free(k);
    ERR_clear_error();
    if(gs != GDS_OK)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    plain->data = out.data;
    plain->length = out.len;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode kcUpdate(METHOD_ARGS) {
    UNUSED_ARGS;
    (void)output;
    UA_StatusCode r = access_check(sessionId);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    pk_cred *c = find(objectId);
    if(!c)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    r = update_args(inputSize, input);
    if(r == UA_STATUSCODE_GOOD && breaking("kc-update-refuse"))
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_ByteString plain = UA_BYTESTRING_NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = update_secret(input, &plain);
    if(r == UA_STATUSCODE_GOOD)
        r = set_prop(objectId, "CredentialId", input[0].data, &UA_TYPES[UA_TYPES_STRING]);
    if(r != UA_STATUSCODE_GOOD) {
        if(plain.length)
            OPENSSL_cleanse(plain.data, plain.length);
        UA_ByteString_clear(&plain);
        return r;
    }
    if(c->secret.length)
        OPENSSL_cleanse(c->secret.data, c->secret.length);
    UA_ByteString_clear(&c->secret);
    c->secret = plain;
    c->hasSecret = true;
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "UpdateCredential: a secret of %zu bytes", plain.length);
    return UA_STATUSCODE_GOOD;
}

/* DeleteCredential (12 §8.6.8) */
static UA_StatusCode kcDelete(METHOD_ARGS) {
    UNUSED_ARGS;
    (void)inputSize, (void)input, (void)output;
    UA_StatusCode r = access_check(sessionId);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    pk_cred *c = find(objectId);
    if(!c)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    if(breaking("kc-delete-noop"))
        return UA_STATUSCODE_GOOD;
    r = UA_Server_deleteNode(K.server, c->node, true);
    if(r == UA_STATUSCODE_GOOD)
        cred_clear(c);
    return r;
}

/* ---------------- ServiceStatus (12 §8.6.5) ---------------- */

/* The port of a loopback URL (scheme://127.0.0.1:port or localhost), or 0 */
static unsigned loopback_port(const char *url) {
    const char *h = strstr(url, "://");
    if(!h)
        return 0;
    h += 3;
    const char *rest = NULL;
    if(strncmp(h, "127.0.0.1:", 10) == 0 || strncmp(h, "localhost:", 10) == 0)
        rest = h + 10;
    if(!rest)
        return 0;
    char digits[6];
    size_t n = 0;
    while(n < 5 && rest[n] >= '0' && rest[n] <= '9') {
        digits[n] = rest[n];
        n++;
    }
    digits[n] = '\0';
    long port = 0;
    if(n == 0 || (rest[n] != '\0' && rest[n] != '/') || !gds_parse_long(digits, 1, 65535, &port))
        return 0;
    return (unsigned)port;
}

/* Bad_NoCommunication unless something accepts a TCP connection */
static UA_StatusCode probe(unsigned port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
        return UA_STATUSCODE_BADNOCOMMUNICATION;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fl = fcntl(fd, F_GETFL, 0);
    UA_StatusCode st = UA_STATUSCODE_BADNOCOMMUNICATION;
    if(fl >= 0 && fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0) {
        int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
        if(rc == 0) {
            st = UA_STATUSCODE_GOOD;
        } else if(errno == EINPROGRESS) {
            struct pollfd pf = {fd, POLLOUT, 0};
            int err = 0;
            socklen_t el = sizeof(err);
            if(poll(&pf, 1, PK_CONNECT_MS) == 1 &&
               getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0)
                st = UA_STATUSCODE_GOOD;
        }
    }
    close(fd);
    return st;
}

static void probe_all(UA_Server *server, void *data) {
    (void)server, (void)data;
    if(breaking("kc-status-stale"))
        return;
    for(size_t i = 0; i < PK_MAX; i++) {
        pk_cred *c = &K.cred[i];
        unsigned port = c->used ? loopback_port(c->url) : 0;
        if(!port)
            continue;
        UA_StatusCode st = probe(port);
        (void)set_prop(&c->node, "ServiceStatus", &st, &UA_TYPES[UA_TYPES_STATUSCODE]);
    }
}

/* ---------------- Install ---------------- */

UA_StatusCode pk_install(UA_Server *server, ps_admin_fn isAdmin, pm_mode_fn modeOf) {
    memset(&K, 0, sizeof(K));
    K.server = server;
    K.isAdmin = isAdmin;
    K.modeOf = modeOf;
    UA_StatusCode r = UA_Server_setMethodNodeCallback(
        server, ns0(UA_NS0ID_KEYCREDENTIALCONFIGURATION_CREATECREDENTIAL), kcCreate);
    r |= UA_Server_setMethodNodeCallback(
        server, ns0(UA_NS0ID_KEYCREDENTIALCONFIGURATIONTYPE_GETENCRYPTINGKEY), kcGetKey);
    r |= UA_Server_setMethodNodeCallback(
        server, ns0(UA_NS0ID_KEYCREDENTIALCONFIGURATIONTYPE_UPDATECREDENTIAL), kcUpdate);
    r |= UA_Server_setMethodNodeCallback(
        server, ns0(UA_NS0ID_KEYCREDENTIALCONFIGURATIONTYPE_DELETECREDENTIAL), kcDelete);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_addRepeatedCallback(server, probe_all, NULL, PK_PROBE_MS, &K.probe);
    return r == UA_STATUSCODE_GOOD ? r : UA_STATUSCODE_BADINTERNALERROR;
}

void pk_clear(void) {
    for(size_t i = 0; i < PK_MAX; i++)
        cred_clear(&K.cred[i]);
}
