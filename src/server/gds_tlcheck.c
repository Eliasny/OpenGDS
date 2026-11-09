/* OpenGDS - checks a CertificateGroup trust list before it is stored
 * (OPC 10000-12 §7.8.2.5 CloseAndUpdate, §7.8.2.6 AddCertificate):
 * "each Certificate is validated as described in OPC 10000-4" and the new
 * list is discarded on the first error. The steps of OPC 10000-4 §6.1.3
 * that apply to a list held by the GDS:
 *   - Certificate Structure: every certificate and CRL parses as DER, with
 *     nothing after it (Bad_CertificateInvalid);
 *   - an issuer certificate is a CA (basicConstraints cA TRUE)
 *     (Bad_CertificateInvalid);
 *   - Build Certificate Chain / Signature: a certificate is self-signed
 *     (its own signature verifies) or signed by a CA certificate of the
 *     list or by one of the GDS's issuing CAs (RSA, P-256, P-384) (Bad_CertificateChainIncomplete if no CA of
 *     the issuer's name is there, Bad_CertificateInvalid if the signature
 *     does not verify); a CRL likewise;
 *   - Validity Period: now within notBefore..notAfter
 *     (Bad_CertificateTimeInvalid, Bad_CertificateIssuerTimeInvalid for a
 *     certificate of an issuer list);
 *   - Find Revocation List: a certificate on a CRL of its issuer in the
 *     list is Bad_CertificateRevoked.
 * Host name, URI and key usage checks belong to a connection, not to a
 * trust list, and are not made here.
 * SPDX-License-Identifier: MPL-2.0 */
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdlib.h>

#include "gds_tlcheck.h"
#include "common/banned.h"

typedef struct {
    X509 **certs;
    bool *issuer; /* from an issuer list */
    size_t nCerts;
    X509_CRL **crls;
    size_t nCrls;
} parsed;

static void parsed_free(parsed *p) {
    for(size_t i = 0; i < p->nCerts; i++)
        X509_free(p->certs[i]);
    for(size_t i = 0; i < p->nCrls; i++)
        X509_CRL_free(p->crls[i]);
    free((void *)p->certs);
    free(p->issuer);
    free((void *)p->crls);
}

X509 *gds_tl_parse_cert(const UA_ByteString *b) {
    const unsigned char *p = b->data;
    X509 *x = b->length ? d2i_X509(NULL, &p, (long)b->length) : NULL;
    if(x && p != b->data + b->length) {
        X509_free(x);
        x = NULL;
    }
    return x;
}

X509_CRL *gds_tl_parse_crl(const UA_ByteString *b) {
    const unsigned char *p = b->data;
    X509_CRL *c = b->length ? d2i_X509_CRL(NULL, &p, (long)b->length) : NULL;
    if(c && p != b->data + b->length) {
        X509_CRL_free(c);
        c = NULL;
    }
    return c;
}

bool gds_tl_is_ca(X509 *x) {
    return (X509_get_extension_flags(x) & EXFLAG_CA) != 0;
}

static UA_StatusCode add_certs(parsed *p, const UA_ByteString *list, size_t n, bool issuer) {
    for(size_t i = 0; i < n; i++) {
        X509 *x = gds_tl_parse_cert(&list[i]);
        if(!x)
            return UA_STATUSCODE_BADCERTIFICATEINVALID;
        p->certs[p->nCerts] = x;
        p->issuer[p->nCerts++] = issuer;
        if(issuer && !gds_tl_is_ca(x))
            return UA_STATUSCODE_BADCERTIFICATEINVALID;
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode add_crls(parsed *p, const UA_ByteString *list, size_t n) {
    for(size_t i = 0; i < n; i++) {
        X509_CRL *c = gds_tl_parse_crl(&list[i]);
        if(!c)
            return UA_STATUSCODE_BADCERTIFICATEINVALID;
        p->crls[p->nCrls++] = c;
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode parse_all(const UA_TrustListDataType *tl, X509 *const *gdsCas, size_t nGds,
                               parsed *p) {
    size_t nc = tl->trustedCertificatesSize + tl->issuerCertificatesSize + nGds;
    size_t nl = tl->trustedCrlsSize + tl->issuerCrlsSize;
    p->certs = (X509 **)calloc(nc, sizeof(X509 *)); // NOLINT(bugprone-sizeof-expression): an array of pointers
    p->issuer = calloc(nc, sizeof(*p->issuer));
    p->crls = (X509_CRL **)calloc(nl ? nl : 1, sizeof(X509_CRL *)); // NOLINT(bugprone-sizeof-expression): an array of pointers
    if(!p->certs || !p->issuer || !p->crls)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    for(size_t i = 0; i < nGds; i++) { /* trusted as they are: they issue the group */
        if(!X509_up_ref(gdsCas[i]))
            return UA_STATUSCODE_BADOUTOFMEMORY;
        p->certs[p->nCerts] = gdsCas[i];
        p->issuer[p->nCerts++] = true;
    }
    UA_StatusCode r = add_certs(p, tl->trustedCertificates, tl->trustedCertificatesSize, false);
    if(r == UA_STATUSCODE_GOOD)
        r = add_certs(p, tl->issuerCertificates, tl->issuerCertificatesSize, true);
    if(r == UA_STATUSCODE_GOOD)
        r = add_crls(p, tl->trustedCrls, tl->trustedCrlsSize);
    if(r == UA_STATUSCODE_GOOD)
        r = add_crls(p, tl->issuerCrls, tl->issuerCrlsSize);
    return r;
}

/* A CA certificate of the list named `name` whose key verifies the
 * signature: Good; a CA of that name but no matching key: Invalid; none:
 * ChainIncomplete. */
static UA_StatusCode find_signer(const parsed *p, const X509_NAME *name, X509 *cert,
                                 X509_CRL *crl) {
    UA_StatusCode r = UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE;
    for(size_t i = 0; i < p->nCerts; i++) {
        X509 *ca = p->certs[i];
        if(ca == cert || !gds_tl_is_ca(ca) || X509_NAME_cmp(X509_get_subject_name(ca), name) != 0)
            continue;
        EVP_PKEY *k = X509_get0_pubkey(ca);
        if(k && (cert ? X509_verify(cert, k) : X509_CRL_verify(crl, k)) == 1)
            return UA_STATUSCODE_GOOD;
        r = UA_STATUSCODE_BADCERTIFICATEINVALID;
    }
    return r;
}

static UA_StatusCode check_chain(const parsed *p, X509 *x) {
    const X509_NAME *iss = X509_get_issuer_name(x);
    if(X509_NAME_cmp(X509_get_subject_name(x), iss) == 0) {
        EVP_PKEY *k = X509_get0_pubkey(x);
        if(k && X509_verify(x, k) == 1)
            return UA_STATUSCODE_GOOD; /* self-signed */
    }
    return find_signer(p, iss, x, NULL);
}

static UA_StatusCode check_time(X509 *x, bool issuer) {
    if(X509_cmp_current_time(X509_get0_notBefore(x)) >= 0 ||
       X509_cmp_current_time(X509_get0_notAfter(x)) <= 0)
        return issuer ? UA_STATUSCODE_BADCERTIFICATEISSUERTIMEINVALID
                      : UA_STATUSCODE_BADCERTIFICATETIMEINVALID;
    return UA_STATUSCODE_GOOD;
}

static bool revoked(const parsed *p, X509 *x) {
    for(size_t i = 0; i < p->nCrls; i++) {
        X509_REVOKED *e = NULL;
        if(X509_NAME_cmp(X509_CRL_get_issuer(p->crls[i]), X509_get_issuer_name(x)) == 0 &&
           X509_CRL_get0_by_cert(p->crls[i], &e, x) == 1)
            return true;
    }
    return false;
}

static UA_StatusCode check_all(const parsed *p, size_t nGds) {
    for(size_t i = 0; i < p->nCrls; i++) {
        UA_StatusCode r = find_signer(p, X509_CRL_get_issuer(p->crls[i]), NULL, p->crls[i]);
        if(r != UA_STATUSCODE_GOOD)
            return r;
    }
    for(size_t i = nGds; i < p->nCerts; i++) { /* [0, nGds) are the GDS CAs */
        X509 *x = p->certs[i];
        UA_StatusCode r = check_time(x, p->issuer[i]);
        if(r == UA_STATUSCODE_GOOD)
            r = check_chain(p, x);
        if(r == UA_STATUSCODE_GOOD && revoked(p, x))
            r = UA_STATUSCODE_BADCERTIFICATEREVOKED;
        if(r != UA_STATUSCODE_GOOD)
            return r;
    }
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode gds_tl_validate(const UA_TrustListDataType *tl, X509 *const *gdsCas,
                              size_t nGdsCas) {
    if(!gdsCas || nGdsCas == 0)
        return UA_STATUSCODE_BADINTERNALERROR;
    for(size_t i = 0; i < nGdsCas; i++)
        if(!gdsCas[i])
            return UA_STATUSCODE_BADINTERNALERROR;
    parsed p = {0};
    UA_StatusCode r = parse_all(tl, gdsCas, nGdsCas, &p);
    if(r == UA_STATUSCODE_GOOD)
        r = check_all(&p, nGdsCas);
    parsed_free(&p);
    return r;
}
