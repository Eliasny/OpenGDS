/* OpenGDS - X.509 building blocks for the CA.
 * SPDX-License-Identifier: MPL-2.0 */
#include "ca_x509.h"

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "common/limits.h"
#include "common/banned.h"

#define SERIAL_BYTES 20
#define MAX_HOST 253

gds_status cax_set_random_serial(X509 *x, gds_buf *serialOut) {
    unsigned char b[SERIAL_BYTES];
    if(RAND_bytes(b, sizeof(b)) != 1)
        return GDS_ECRYPTO;
    b[0] &= 0x7fu; /* positive */
    if(b[0] == 0)
        b[0] = 1; /* non-zero, and always the full 20 octets */
    BIGNUM *bn = BN_bin2bn(b, sizeof(b), NULL);
    ASN1_INTEGER *ai = bn ? BN_to_ASN1_INTEGER(bn, NULL) : NULL;
    BN_free(bn);
    gds_status r = GDS_ECRYPTO;
    if(ai && X509_set_serialNumber(x, ai) == 1)
        r = serialOut ? gds_buf_dup(b, sizeof(b), serialOut) : GDS_OK;
    ASN1_INTEGER_free(ai);
    return r;
}

gds_status cax_set_validity(X509 *x, int64_t notBefore, int64_t notAfter) {
    if(notAfter <= notBefore)
        return GDS_EINVAL;
    if(!ASN1_TIME_set(X509_getm_notBefore(x), (time_t)notBefore) ||
       !ASN1_TIME_set(X509_getm_notAfter(x), (time_t)notAfter))
        return GDS_ECRYPTO;
    return GDS_OK;
}

gds_status cax_make_name(const UA_String *cn, const char *org, X509_NAME **out) {
    *out = NULL;
    if(!cn || cn->length == 0 || memchr(cn->data, 0, cn->length))
        return GDS_EINVAL;
    size_t len = cn->length;
    if(len > CAX_MAX_CN) {
        len = CAX_MAX_CN;
        /* never cut inside a UTF-8 sequence */
        while(len > 0 && (cn->data[len] & 0xC0u) == 0x80u)
            len--;
        if(len == 0)
            return GDS_EINVAL;
    }
    X509_NAME *n = X509_NAME_new();
    if(!n)
        return GDS_ENOMEM;
    if(X509_NAME_add_entry_by_NID(n, NID_commonName, MBSTRING_UTF8, cn->data, (int)len, -1,
                                  0) != 1 ||
       (org && org[0] &&
        X509_NAME_add_entry_by_NID(n, NID_organizationName, MBSTRING_UTF8,
                                   (const unsigned char *)org, -1, -1, 0) != 1)) {
        X509_NAME_free(n);
        return GDS_EINVAL;
    }
    *out = n;
    return GDS_OK;
}

gds_status cax_add_basic_constraints(X509 *x, bool isCa) {
    BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
    if(!bc)
        return GDS_ENOMEM;
    bc->ca = isCa ? 0xFF : 0;
    int ok = X509_add1_ext_i2d(x, NID_basic_constraints, bc, 1, X509V3_ADD_REPLACE);
    BASIC_CONSTRAINTS_free(bc);
    return ok == 1 ? GDS_OK : GDS_ECRYPTO;
}

gds_status cax_add_key_usage(X509 *x, unsigned bits) {
    ASN1_BIT_STRING *ku = ASN1_BIT_STRING_new();
    if(!ku)
        return GDS_ENOMEM;
    int ok = 1;
    for(int i = 0; i < 9 && ok; i++)
        if(bits & (1u << i))
            ok = ASN1_BIT_STRING_set_bit(ku, i, 1);
    if(ok)
        ok = X509_add1_ext_i2d(x, NID_key_usage, ku, 1, X509V3_ADD_REPLACE);
    ASN1_BIT_STRING_free(ku);
    return ok == 1 ? GDS_OK : GDS_ECRYPTO;
}

gds_status cax_add_ext_key_usage(X509 *x, bool serverAuth, bool clientAuth) {
    EXTENDED_KEY_USAGE *eku = sk_ASN1_OBJECT_new_null();
    if(!eku)
        return GDS_ENOMEM;
    /* OBJ_nid2obj returns static objects: the stack is freed without them */
    int ok = 1;
    if(serverAuth)
        ok = sk_ASN1_OBJECT_push(eku, OBJ_nid2obj(NID_server_auth)) > 0;
    if(ok && clientAuth)
        ok = sk_ASN1_OBJECT_push(eku, OBJ_nid2obj(NID_client_auth)) > 0;
    if(ok)
        ok = X509_add1_ext_i2d(x, NID_ext_key_usage, eku, 0, X509V3_ADD_REPLACE) == 1;
    sk_ASN1_OBJECT_free(eku);
    return ok ? GDS_OK : GDS_ECRYPTO;
}

gds_status cax_add_key_ids(X509 *x, X509 *issuer) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = 0;
    /* RFC 5280 §4.2.1.2 method (1): SHA-1 of the subjectPublicKey bits; an
     * identifier, not a security function */
    if(X509_pubkey_digest(x, EVP_sha1(), md, &mdLen) != 1)
        return GDS_ECRYPTO;
    ASN1_OCTET_STRING *skid = ASN1_OCTET_STRING_new();
    AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
    gds_status r = GDS_ECRYPTO;
    if(!skid || !akid || ASN1_OCTET_STRING_set(skid, md, (int)mdLen) != 1)
        goto done;
    const ASN1_OCTET_STRING *issuerKid = issuer ? X509_get0_subject_key_id(issuer) : skid;
    if(!issuerKid) {
        r = GDS_EINVAL;
        goto done;
    }
    akid->keyid = ASN1_OCTET_STRING_dup(issuerKid);
    if(akid->keyid && X509_add1_ext_i2d(x, NID_subject_key_identifier, skid, 0,
                                        X509V3_ADD_REPLACE) == 1 &&
       X509_add1_ext_i2d(x, NID_authority_key_identifier, akid, 0, X509V3_ADD_REPLACE) == 1)
        r = GDS_OK;
done:
    ASN1_OCTET_STRING_free(skid);
    AUTHORITY_KEYID_free(akid);
    return r;
}

static bool is_host_char(unsigned char c, bool bracketed) {
    if(bracketed)
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
               c == ':' || c == '.';
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           c == '-' || c == '.';
}

static size_t scheme_len(const UA_String *url) {
    static const char *const schemes[] = {"opc.tcp://", "opc.https://", "https://",
                                          "opc.wss://"};
    for(size_t i = 0; i < sizeof(schemes) / sizeof(schemes[0]); i++) {
        size_t n = strlen(schemes[i]);
        if(url->length > n && strncasecmp((const char *)url->data, schemes[i], n) == 0)
            return n;
    }
    return 0;
}

gds_status cax_url_host(const UA_String *url, char *host, size_t hostLen, bool *isIp) {
    size_t pos = scheme_len(url);
    if(pos == 0)
        return GDS_EINVAL;
    bool bracketed = url->data[pos] == '[';
    if(bracketed)
        pos++;
    size_t start = pos;
    while(pos < url->length && is_host_char(url->data[pos], bracketed))
        pos++;
    size_t n = pos - start;
    if(n == 0 || n > MAX_HOST || n >= hostLen)
        return GDS_EINVAL;
    if(bracketed) {
        if(pos >= url->length || url->data[pos] != ']')
            return GDS_EINVAL;
        pos++;
    }
    if(pos < url->length && url->data[pos] != ':' && url->data[pos] != '/')
        return GDS_EINVAL;
    memcpy(host, url->data + start, n);
    host[n] = '\0';
    ASN1_OCTET_STRING *ip = a2i_IPADDRESS(host);
    *isIp = ip != NULL;
    ASN1_OCTET_STRING_free(ip);
    if(bracketed && !*isIp)
        return GDS_EINVAL;
    return GDS_OK;
}

static gds_status push_ia5(GENERAL_NAMES *gens, int type, const unsigned char *s, size_t len) {
    for(size_t i = 0; i < len; i++)
        if(s[i] < 0x21 || s[i] > 0x7e) /* IA5, printable, no spaces */
            return GDS_EINVAL;
    GENERAL_NAME *g = GENERAL_NAME_new();
    ASN1_IA5STRING *v = ASN1_IA5STRING_new();
    if(!g || !v || ASN1_STRING_set(v, s, (int)len) != 1) {
        GENERAL_NAME_free(g);
        ASN1_IA5STRING_free(v);
        return GDS_ENOMEM;
    }
    GENERAL_NAME_set0_value(g, type, v);
    if(sk_GENERAL_NAME_push(gens, g) <= 0) {
        GENERAL_NAME_free(g);
        return GDS_ENOMEM;
    }
    return GDS_OK;
}

static gds_status push_ip(GENERAL_NAMES *gens, const char *host) {
    ASN1_OCTET_STRING *ip = a2i_IPADDRESS(host);
    GENERAL_NAME *g = ip ? GENERAL_NAME_new() : NULL;
    if(!g) {
        ASN1_OCTET_STRING_free(ip);
        return GDS_EINVAL;
    }
    GENERAL_NAME_set0_value(g, GEN_IPADD, ip);
    if(sk_GENERAL_NAME_push(gens, g) <= 0) {
        GENERAL_NAME_free(g);
        return GDS_ENOMEM;
    }
    return GDS_OK;
}

static gds_status push_hosts(GENERAL_NAMES *gens, const UA_ApplicationRecordDataType *rec) {
    char seen[GDS_MAX_ARRAY_FIELD][MAX_HOST + 1];
    size_t nSeen = 0;
    if(rec->discoveryUrlsSize > GDS_MAX_ARRAY_FIELD)
        return GDS_ETOOBIG;
    for(size_t i = 0; i < rec->discoveryUrlsSize; i++) {
        char host[MAX_HOST + 1];
        bool isIp = false;
        gds_status r = cax_url_host(&rec->discoveryUrls[i], host, sizeof(host), &isIp);
        if(r != GDS_OK)
            return r;
        bool dup = false;
        for(size_t j = 0; j < nSeen && !dup; j++)
            dup = strcasecmp(seen[j], host) == 0;
        if(dup)
            continue;
        memcpy(seen[nSeen++], host, strlen(host) + 1);
        r = isIp ? push_ip(gens, host)
                 : push_ia5(gens, GEN_DNS, (const unsigned char *)host, strlen(host));
        if(r != GDS_OK)
            return r;
    }
    return GDS_OK;
}

gds_status cax_add_san(X509 *x, const UA_ApplicationRecordDataType *rec) {
    if(rec->applicationUri.length == 0 || rec->applicationUri.length > GDS_MAX_APPLICATION_URI)
        return GDS_EINVAL;
    GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
    if(!gens)
        return GDS_ENOMEM;
    gds_status r = push_ia5(gens, GEN_URI, rec->applicationUri.data, rec->applicationUri.length);
    if(r == GDS_OK)
        r = push_hosts(gens, rec);
    if(r == GDS_OK && X509_add1_ext_i2d(x, NID_subject_alt_name, gens, 0, X509V3_ADD_REPLACE) != 1)
        r = GDS_ECRYPTO;
    GENERAL_NAMES_free(gens);
    return r;
}

/* The SubjectPublicKeyInfo parameters X509_set_pubkey writes: NULL for
 * rsaEncryption, the curve OID for id-ecPublicKey. */
/* RSAPublicKey in DER: the generic decoder's own DER encoding of it is
 * byte for byte the same (no long-form or indefinite lengths). */
static bool rsa_bits_der(const unsigned char *bits, int len) {
    const unsigned char *p = bits;
    ASN1_SEQUENCE_ANY *seq = d2i_ASN1_SEQUENCE_ANY(NULL, &p, len);
    unsigned char *again = NULL;
    int n = seq && p == bits + len && sk_ASN1_TYPE_num(seq) == 2
                ? i2d_ASN1_SEQUENCE_ANY(seq, &again)
                : -1;
    bool ok = n == len && memcmp(again, bits, (size_t)len) == 0;
    OPENSSL_free(again);
    sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
    return ok;
}

/* What X509_set_pubkey would write for the key: rsaEncryption with NULL
 * parameters and a DER RSAPublicKey, or id-ecPublicKey with a named curve
 * (P-256 or P-384) and an uncompressed point. */
static bool spki_canonical(const ASN1_OBJECT *alg, int ptype, const void *pval,
                           const unsigned char *bits, int len) {
    int nid = OBJ_obj2nid(alg);
    if(nid == NID_rsaEncryption)
        return ptype == V_ASN1_NULL && rsa_bits_der(bits, len);
    if(nid != NID_X9_62_id_ecPublicKey || ptype != V_ASN1_OBJECT)
        return false;
    int curve = OBJ_obj2nid(pval);
    int point = curve == NID_X9_62_prime256v1 ? 65 : curve == NID_secp384r1 ? 97 : 0;
    return len == point && bits[0] == 0x04; /* POINT_CONVERSION_UNCOMPRESSED */
}

gds_status cax_set_pubkey_from_req(X509 *x, X509_REQ *req, EVP_PKEY *pk) {
    const unsigned char *bits = NULL;
    int bitsLen = 0;
    X509_ALGOR *alg = NULL;
    const ASN1_OBJECT *algObj = NULL;
    const void *pval = NULL;
    int ptype = V_ASN1_UNDEF;
    if(X509_PUBKEY_get0_param(NULL, &bits, &bitsLen, &alg, X509_REQ_get_X509_PUBKEY(req)) != 1 ||
       !alg || !bits || bitsLen <= 0)
        return GDS_EINVAL;
    X509_ALGOR_get0(&algObj, &ptype, &pval, alg);
    if(!algObj || !spki_canonical(algObj, ptype, pval, bits, bitsLen))
        return X509_set_pubkey(x, pk) == 1 ? GDS_OK : GDS_ECRYPTO;
    ASN1_OBJECT *o = OBJ_dup(algObj);
    ASN1_OBJECT *curve = ptype == V_ASN1_OBJECT ? OBJ_dup(pval) : NULL;
    unsigned char *copy = OPENSSL_memdup(bits, (size_t)bitsLen);
    /* set0_param takes o, curve and copy only when it succeeds */
    if(!o || (ptype == V_ASN1_OBJECT && !curve) || !copy ||
       X509_PUBKEY_set0_param(X509_get_X509_PUBKEY(x), o, ptype, curve, copy, bitsLen) != 1) {
        ASN1_OBJECT_free(o);
        ASN1_OBJECT_free(curve);
        OPENSSL_free(copy);
        return GDS_ENOMEM;
    }
    return GDS_OK;
}

gds_status cax_cert_der(X509 *x, gds_buf *out) {
    memset(out, 0, sizeof(*out));
    int n = i2d_X509(x, NULL);
    if(n <= 0)
        return GDS_ECRYPTO;
    if((size_t)n > GDS_MAX_CERT_SIZE)
        return GDS_ETOOBIG;
    out->data = malloc((size_t)n);
    if(!out->data)
        return GDS_ENOMEM;
    unsigned char *p = out->data;
    if(i2d_X509(x, &p) != n) {
        gds_buf_free(out);
        return GDS_ECRYPTO;
    }
    out->len = (size_t)n;
    return GDS_OK;
}

gds_status cax_crl_der(X509_CRL *c, gds_buf *out) {
    memset(out, 0, sizeof(*out));
    int n = i2d_X509_CRL(c, NULL);
    if(n <= 0)
        return GDS_ECRYPTO;
    if((size_t)n > GDS_MAX_CRL_SIZE)
        return GDS_ETOOBIG;
    out->data = malloc((size_t)n);
    if(!out->data)
        return GDS_ENOMEM;
    unsigned char *p = out->data;
    if(i2d_X509_CRL(c, &p) != n) {
        gds_buf_free(out);
        return GDS_ECRYPTO;
    }
    out->len = (size_t)n;
    return GDS_OK;
}
