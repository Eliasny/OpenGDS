/* OpenGDS unit tests - push endpoint selection (src/push/gdsc_session.c):
 * SignAndEncrypt only, strongest usable policy, deprecated policies refused.
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include "check.h"
#include "client/gdsc_session.h"
#include "common/banned.h"

#define P "http://opcfoundation.org/UA/SecurityPolicy#"

static UA_Byte certByte = 0x30;
static UA_UserTokenPolicy anonOnly = {.tokenType = UA_USERTOKENTYPE_ANONYMOUS};

static UA_EndpointDescription ep(const char *policy, UA_MessageSecurityMode mode) {
    UA_EndpointDescription e;
    UA_EndpointDescription_init(&e);
    e.securityPolicyUri = UA_STRING((char *)(uintptr_t)policy);
    e.securityMode = mode;
    e.serverCertificate.data = &certByte;
    e.serverCertificate.length = 1;
    e.userIdentityTokens = &anonOnly;
    e.userIdentityTokensSize = 1;
    return e;
}

static void test_rank(void) {
    UA_String none = UA_STRING(P "None"), b15 = UA_STRING(P "Basic128Rsa15"),
              b256 = UA_STRING(P "Basic256"), pss = UA_STRING(P "Aes256_Sha256_RsaPss"),
              b256s = UA_STRING(P "Basic256Sha256"), ecc = UA_STRING(P "ECC_nistP384"),
              odd = UA_STRING("urn:x#Aes256_Sha256_RsaPss"), longer = UA_STRING(P "Basic256Sha2560");
    CHECK_EQ_INT(gdsc_policy_rank(&none), 0);
    CHECK_EQ_INT(gdsc_policy_rank(&b15), 0);
    CHECK_EQ_INT(gdsc_policy_rank(&b256), 0);
    CHECK_EQ_INT(gdsc_policy_rank(&odd), 0);
    CHECK_EQ_INT(gdsc_policy_rank(&longer), 0);
    CHECK(gdsc_policy_rank(&pss) > gdsc_policy_rank(&b256s));
    CHECK(gdsc_policy_rank(&ecc) > gdsc_policy_rank(&pss));
    CHECK_EQ_INT(gdsc_policy_rank(NULL), 0);
}

/* 12 §7.8.4: which CertificateType an endpoint's policy presents */
static void test_cert_type(void) {
    static const struct {
        const char *policy;
        UA_UInt32 type; /* 0: none */
    } cases[] = {
        {P "Basic128Rsa15", UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE},
        {P "Basic256", UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE},
        {P "Basic256Sha256", UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE},
        {P "Aes128_Sha256_RsaOaep", UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE},
        {P "Aes256_Sha256_RsaPss", UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE},
        {P "ECC_nistP256", UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE},
        {P "ECC_nistP384", UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE},
        {P "ECC_brainpoolP256r1", UA_NS0ID_ECCBRAINPOOLP256R1APPLICATIONCERTIFICATETYPE},
        {P "ECC_brainpoolP384r1", UA_NS0ID_ECCBRAINPOOLP384R1APPLICATIONCERTIFICATETYPE},
        {P "ECC_curve25519", UA_NS0ID_ECCCURVE25519APPLICATIONCERTIFICATETYPE},
        {P "ECC_curve448", UA_NS0ID_ECCCURVE448APPLICATIONCERTIFICATETYPE},
        {P "None", 0},
        {P "Basic256Sha2560", 0},
        {"urn:x#Basic256Sha256", 0},
    };
    for(size_t i = 0; i < GDS_ARRAY_SIZE(cases); i++) {
        UA_String u = UA_STRING((char *)(uintptr_t)cases[i].policy);
        UA_NodeId got = gdsc_policy_cert_type(&u);
        UA_NodeId want = cases[i].type ? UA_NODEID_NUMERIC(0, cases[i].type) : UA_NODEID_NULL;
        CHECK(UA_NodeId_equal(&got, &want));
    }
    UA_NodeId nul = gdsc_policy_cert_type(NULL);
    CHECK(UA_NodeId_isNull(&nul));
}

static void test_select(void) {
    UA_EndpointDescription eps[] = {
        ep(P "None", UA_MESSAGESECURITYMODE_NONE),
        ep(P "Aes256_Sha256_RsaPss", UA_MESSAGESECURITYMODE_SIGN),
        ep(P "Basic256Sha256", UA_MESSAGESECURITYMODE_SIGNANDENCRYPT),
        ep(P "Aes256_Sha256_RsaPss", UA_MESSAGESECURITYMODE_SIGNANDENCRYPT),
        ep(P "ECC_nistP256", UA_MESSAGESECURITYMODE_SIGNANDENCRYPT),
        ep(P "Basic256", UA_MESSAGESECURITYMODE_SIGNANDENCRYPT),
    };
    UA_String rsa[] = {UA_STRING(P "None"), UA_STRING(P "Basic256Sha256"),
                       UA_STRING(P "Aes256_Sha256_RsaPss"), UA_STRING(P "Basic256")};
    size_t idx = 99;
    /* ECC is stronger but our RSA certificate cannot use it */
    CHECK_EQ_INT(gdsc_select_endpoint(eps, GDS_ARRAY_SIZE(eps), rsa, GDS_ARRAY_SIZE(rsa),
                                      GDSC_IDENTITY_APP_CERT, &idx),
                 UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(idx, 3);

    /* Only None, Sign and a deprecated policy: refused */
    UA_EndpointDescription weak[] = {eps[0], eps[1], eps[5]};
    CHECK_EQ_INT(gdsc_select_endpoint(weak, GDS_ARRAY_SIZE(weak), rsa, GDS_ARRAY_SIZE(rsa),
                                      GDSC_IDENTITY_APP_CERT, &idx),
                 UA_STATUSCODE_BADSECURITYPOLICYREJECTED);

    /* An endpoint without a server certificate is never chosen */
    UA_EndpointDescription nocert[] = {eps[3]};
    nocert[0].serverCertificate.length = 0;
    CHECK_EQ_INT(gdsc_select_endpoint(nocert, 1, rsa, GDS_ARRAY_SIZE(rsa),
                                      GDSC_IDENTITY_APP_CERT, &idx),
                 UA_STATUSCODE_BADSECURITYPOLICYREJECTED);

    /* X509IdentityToken wanted, only Anonymous offered */
    CHECK_EQ_INT(gdsc_select_endpoint(eps, GDS_ARRAY_SIZE(eps), rsa, GDS_ARRAY_SIZE(rsa),
                                      GDSC_IDENTITY_X509, &idx),
                 UA_STATUSCODE_BADIDENTITYTOKENINVALID);
    UA_UserTokenPolicy both[] = {{.tokenType = UA_USERTOKENTYPE_ANONYMOUS},
                                 {.tokenType = UA_USERTOKENTYPE_CERTIFICATE}};
    eps[2].userIdentityTokens = both;
    eps[2].userIdentityTokensSize = 2;
    CHECK_EQ_INT(gdsc_select_endpoint(eps, GDS_ARRAY_SIZE(eps), rsa, GDS_ARRAY_SIZE(rsa),
                                      GDSC_IDENTITY_X509, &idx),
                 UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(idx, 2);

    CHECK_EQ_INT(gdsc_select_endpoint(eps, 0, rsa, GDS_ARRAY_SIZE(rsa),
                                      GDSC_IDENTITY_APP_CERT, &idx),
                 UA_STATUSCODE_BADSECURITYPOLICYREJECTED);
}

int main(void) {
    test_rank();
    test_cert_type();
    test_select();
    return check_done();
}
