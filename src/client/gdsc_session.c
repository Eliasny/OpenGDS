/* OpenGDS libgdsclient - secure sessions to a GDS or a push-managed Server.
 * SPDX-License-Identifier: MPL-2.0 */
#include "gdsc_session.h"

#include <open62541/client_config_default.h>
#include <open62541/plugin/log_stdout.h>
#include <openssl/crypto.h>
#include <openssl/x509v3.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/limits.h"
#include "common/banned.h"

#define DEFAULT_TIMEOUT_MS 10000u
#define POLICY_PREFIX "http://opcfoundation.org/UA/SecurityPolicy#"

struct gdsc_session {
    UA_Client *client;
    UA_String policy;
};

/* Strongest first. ECC policies need an ECC certificate; the usable list
 * from our own client configuration filters them out for an RSA one.
 * Refused: None, and the deprecated Basic128Rsa15 and Basic256 (OPC 10000-7
 * security policy facets; Auditor SRV-SEC-08). */
static const struct {
    const char *name;
    int rank;
} policyRanks[] = {
    {"ECC_nistP384", 70},
    {"ECC_brainpoolP384r1", 65},
    {"ECC_nistP256", 60},
    {"ECC_brainpoolP256r1", 55},
    {"Aes256_Sha256_RsaPss", 40},
    {"Basic256Sha256", 30},
    {"Aes128_Sha256_RsaOaep", 20},
};

int gdsc_policy_rank(const UA_String *policyUri) {
    const size_t pl = sizeof(POLICY_PREFIX) - 1;
    if(!policyUri || policyUri->length <= pl ||
       memcmp(policyUri->data, POLICY_PREFIX, pl) != 0)
        return 0;
    const UA_Byte *name = policyUri->data + pl;
    size_t nameLen = policyUri->length - pl;
    for(size_t i = 0; i < GDS_ARRAY_SIZE(policyRanks); i++) {
        if(strlen(policyRanks[i].name) == nameLen &&
           memcmp(policyRanks[i].name, name, nameLen) == 0)
            return policyRanks[i].rank;
    }
    return 0;
}

static bool is_usable(const UA_String *policy, const UA_String *usable, size_t usableN) {
    for(size_t i = 0; i < usableN; i++)
        if(UA_String_equal(policy, &usable[i]))
            return true;
    return false;
}

static bool offers_token(const UA_EndpointDescription *e, gdsc_identity identity) {
    UA_UserTokenType want = UA_USERTOKENTYPE_ANONYMOUS;
    switch(identity) {
    case GDSC_IDENTITY_APP_CERT: want = UA_USERTOKENTYPE_ANONYMOUS; break;
    case GDSC_IDENTITY_X509: want = UA_USERTOKENTYPE_CERTIFICATE; break;
    case GDSC_IDENTITY_USERNAME: want = UA_USERTOKENTYPE_USERNAME; break;
    }
    for(size_t i = 0; i < e->userIdentityTokensSize; i++)
        if(e->userIdentityTokens[i].tokenType == want)
            return true;
    return false;
}

UA_StatusCode gdsc_select_endpoint(const UA_EndpointDescription *eps, size_t n,
                                   const UA_String *usable, size_t usableN,
                                   gdsc_identity identity, size_t *idx) {
    int best = 0;
    bool anyPolicy = false;
    for(size_t i = 0; i < n; i++) {
        const UA_EndpointDescription *e = &eps[i];
        if(e->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT ||
           e->serverCertificate.length == 0 ||
           e->serverCertificate.length > GDS_MAX_CERT_SIZE * GDS_MAX_CHAIN_LEN)
            continue;
        int rank = gdsc_policy_rank(&e->securityPolicyUri);
        if(rank == 0 || !is_usable(&e->securityPolicyUri, usable, usableN))
            continue;
        anyPolicy = true;
        if(rank > best && offers_token(e, identity)) {
            best = rank;
            *idx = i;
        }
    }
    if(best > 0)
        return UA_STATUSCODE_GOOD;
    return anyPolicy ? UA_STATUSCODE_BADIDENTITYTOKENINVALID
                     : UA_STATUSCODE_BADSECURITYPOLICYREJECTED;
}

static UA_ByteString *borrow_list(const gds_buf *items, size_t n) {
    UA_ByteString *l = calloc(n ? n : 1, sizeof(UA_ByteString));
    if(!l)
        return NULL;
    for(size_t i = 0; i < n; i++) {
        l[i].data = items[i].data;
        l[i].length = items[i].len;
    }
    return l;
}

/* open62541 takes C strings; the copy is wiped after it copied them */
static UA_StatusCode config_username(UA_ClientConfig *cfg, const char *user,
                                     const gds_buf *pw) {
    if(!user || !pw || !pw->data || pw->len == 0 || pw->len > GDS_MAX_STRING ||
       memchr(pw->data, '\0', pw->len))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    char *tmp = malloc(pw->len + 1);
    if(!tmp)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    memcpy(tmp, pw->data, pw->len);
    tmp[pw->len] = '\0';
    UA_StatusCode r = UA_ClientConfig_setAuthenticationUsername(cfg, user, tmp);
    OPENSSL_cleanse(tmp, pw->len + 1);
    free(tmp);
    return r;
}

static UA_StatusCode config_identity(UA_ClientConfig *cfg, const gdsc_session_cfg *pc) {
    UA_ByteString uc = {pc->cert->len, pc->cert->data}, uk = {pc->key->len, pc->key->data};
    switch(pc->identity) {
    case GDSC_IDENTITY_APP_CERT:
        return UA_STATUSCODE_GOOD; /* Anonymous token is the default */
    case GDSC_IDENTITY_X509:
        return UA_ClientConfig_setAuthenticationCert(cfg, uc, uk);
    case GDSC_IDENTITY_USERNAME:
        return config_username(cfg, pc->userName, pc->password);
    }
    return UA_STATUSCODE_BADINVALIDARGUMENT;
}

/* Client with our certificate, the explicit trust list and SignAndEncrypt */
static UA_Client *client_new(const gdsc_session_cfg *pc) {
    char uriBuf[GDS_MAX_APPLICATION_URI];
    const char *appUri = pc->applicationUri;
    if(!appUri) {
        if(gdsc_cert_uri(pc->cert, uriBuf, sizeof(uriBuf)) != GDS_OK)
            return NULL;
        appUri = uriBuf;
    }
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    /* Errors only: every failure is returned as a status code, and the
     * warnings for ECC policies an RSA certificate cannot use are noise */
    cfg.logging = UA_Log_Stdout_new(UA_LOGLEVEL_ERROR);
    if(!cfg.logging || UA_ClientConfig_setDefault(&cfg) != UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    UA_ByteString *tl = borrow_list(pc->trust, pc->trustN);
    UA_ByteString *rl = borrow_list(pc->crls, pc->crlN);
    UA_StatusCode r = UA_STATUSCODE_BADOUTOFMEMORY;
    if(tl && rl) {
        UA_ByteString uc = {pc->cert->len, pc->cert->data}, uk = {pc->key->len, pc->key->data};
        r = UA_ClientConfig_setDefaultEncryption(&cfg, uc, uk, tl, pc->trustN, rl, pc->crlN);
    }
    free(tl);
    free(rl);
    if(r == UA_STATUSCODE_GOOD)
        r = config_identity(&cfg, pc);
    if(r == UA_STATUSCODE_GOOD) {
        cfg.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        cfg.timeout = pc->timeoutMs ? pc->timeoutMs : DEFAULT_TIMEOUT_MS;
        UA_String_clear(&cfg.clientDescription.applicationUri);
        cfg.clientDescription.applicationUri = UA_STRING_ALLOC(appUri);
        if(!cfg.clientDescription.applicationUri.data)
            r = UA_STATUSCODE_BADOUTOFMEMORY;
    }
    if(r != UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    UA_Client *c = UA_Client_newWithConfig(&cfg);
    if(!c)
        UA_ClientConfig_clear(&cfg);
    return c;
}

gds_status gdsc_cert_uri(const gds_buf *certDer, char *out, size_t outLen) {
    if(!certDer || !certDer->data || certDer->len > GDS_MAX_CERT_SIZE || outLen == 0)
        return GDS_EINVAL;
    out[0] = '\0';
    const unsigned char *p = certDer->data;
    X509 *x = d2i_X509(NULL, &p, (long)certDer->len);
    if(!x)
        return GDS_ECRYPTO;
    GENERAL_NAMES *names = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
    gds_status s = GDS_ENOTFOUND;
    for(int i = 0; names && s == GDS_ENOTFOUND && i < sk_GENERAL_NAME_num(names); i++) {
        const GENERAL_NAME *g = sk_GENERAL_NAME_value(names, i);
        if(g->type != GEN_URI)
            continue;
        const unsigned char *d = ASN1_STRING_get0_data(g->d.uniformResourceIdentifier);
        int n = ASN1_STRING_length(g->d.uniformResourceIdentifier);
        if(n <= 0 || (size_t)n >= outLen || memchr(d, '\0', (size_t)n))
            s = GDS_ETOOBIG;
        else {
            memcpy(out, d, (size_t)n);
            out[n] = '\0';
            s = GDS_OK;
        }
    }
    GENERAL_NAMES_free(names);
    X509_free(x);
    return s;
}

static bool cfg_valid(const gdsc_session_cfg *pc) {
    return pc && pc->endpointUrl && pc->cert && pc->cert->data && pc->key && pc->key->data &&
           (pc->trustN == 0 || pc->trust) && (pc->crlN == 0 || pc->crls) &&
           (!pc->applicationUri || strlen(pc->applicationUri) < GDS_MAX_APPLICATION_URI);
}

static bool server_uri_matches(const UA_EndpointDescription *e, const char *serverUri) {
    if(!serverUri)
        return true;
    size_t n = strlen(serverUri);
    return e->server.applicationUri.length == n &&
           memcmp(e->server.applicationUri.data, serverUri, n) == 0;
}

/* GetEndpoints over the discovery channel and choose one (no session) */
static UA_StatusCode choose_policy(UA_Client *c, const gdsc_session_cfg *pc, UA_String *policy) {
    size_t n = 0, idx = 0;
    UA_EndpointDescription *eps = NULL;
    UA_StatusCode r = UA_Client_getEndpoints(c, pc->endpointUrl, &n, &eps);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_ClientConfig *cc = UA_Client_getConfig(c);
    UA_String *usable = calloc(cc->securityPoliciesSize ? cc->securityPoliciesSize : 1,
                               sizeof(UA_String));
    if(!usable)
        r = UA_STATUSCODE_BADOUTOFMEMORY;
    for(size_t i = 0; usable && i < cc->securityPoliciesSize; i++)
        usable[i] = cc->securityPolicies[i].policyUri; /* borrowed */
    if(r == UA_STATUSCODE_GOOD)
        r = gdsc_select_endpoint(eps, n, usable, cc->securityPoliciesSize, pc->identity, &idx);
    if(r == UA_STATUSCODE_GOOD && !server_uri_matches(&eps[idx], pc->serverUri))
        r = UA_STATUSCODE_BADSERVERURIINVALID;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_String_copy(&eps[idx].securityPolicyUri, policy);
    free(usable);
    UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    UA_Client_disconnect(c);
    return r;
}

UA_StatusCode gdsc_session_open(const gdsc_session_cfg *pc, gdsc_session **out) {
    *out = NULL;
    if(!cfg_valid(pc))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    gdsc_session *s = calloc(1, sizeof(*s));
    if(!s)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode r = UA_STATUSCODE_BADOUTOFMEMORY;
    s->client = client_new(pc);
    if(s->client)
        r = choose_policy(s->client, pc, &s->policy);
    if(r == UA_STATUSCODE_GOOD) {
        UA_ClientConfig *cc = UA_Client_getConfig(s->client);
        UA_String_clear(&cc->securityPolicyUri);
        r = UA_String_copy(&s->policy, &cc->securityPolicyUri);
    }
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_connect(s->client, pc->endpointUrl);
    if(r != UA_STATUSCODE_GOOD) {
        gdsc_session_close(s);
        return r;
    }
    *out = s;
    return UA_STATUSCODE_GOOD;
}

UA_Client *gdsc_session_client(gdsc_session *s) {
    return s ? s->client : NULL;
}

const UA_String *gdsc_session_policy(const gdsc_session *s) {
    return &s->policy;
}

void gdsc_session_close(gdsc_session *s) {
    if(!s)
        return;
    if(s->client) {
        UA_Client_disconnect(s->client);
        UA_Client_delete(s->client);
    }
    UA_String_clear(&s->policy);
    free(s);
}

/* Every SignAndEncrypt endpoint's certificate starts with `cert` (the field
 * may carry the chain after the leaf, OPC 10000-4 §7.10) */
static UA_StatusCode endpoints_present(const char *url, const gds_buf *cert) {
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(UA_LOGLEVEL_ERROR);
    if(!cfg.logging || UA_ClientConfig_setDefault(&cfg) != UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cfg);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    UA_Client *c = UA_Client_newWithConfig(&cfg);
    if(!c) {
        UA_ClientConfig_clear(&cfg);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    size_t n = 0, found = 0;
    UA_EndpointDescription *eps = NULL;
    UA_StatusCode r = UA_Client_getEndpoints(c, url, &n, &eps);
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && i < n; i++) {
        const UA_ByteString *sc = &eps[i].serverCertificate;
        if(eps[i].securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
            continue;
        if(sc->length < cert->len || memcmp(sc->data, cert->data, cert->len) != 0)
            r = UA_STATUSCODE_BADCERTIFICATEINVALID;
        found++;
    }
    if(r == UA_STATUSCODE_GOOD && found == 0)
        r = UA_STATUSCODE_BADNOTFOUND;
    if(eps)
        UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    UA_Client_delete(c);
    return r;
}

UA_StatusCode gdsc_wait_presents(const char *endpointUrl, const gds_buf *cert,
                                 UA_UInt32 timeoutMs) {
    if(!endpointUrl || !cert || !cert->data || cert->len == 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    const struct timespec step = {0, 200L * 1000L * 1000L};
    UA_UInt32 waited = 0;
    UA_StatusCode r;
    for(;;) {
        r = endpoints_present(endpointUrl, cert);
        if(r == UA_STATUSCODE_GOOD || waited >= timeoutMs)
            return r;
        nanosleep(&step, NULL);
        waited += 200;
    }
}
