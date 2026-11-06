/* OpenGDS Auditor self-test target: the CSR of CreateSigningRequest.
 * SPDX-License-Identifier: MPL-2.0 */
#include "push_csr.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string.h>

#include "common/limits.h"
#include "common/banned.h"

#define PC_MAX_RDN 64

/* "CN=a,O=b" (12 §7.6.4) into an X509_NAME. No escapes: a value with a
 * comma, quote or backslash is refused. */
static X509_NAME *parse_subject(const UA_String *s) {
    if(s->length == 0 || s->length > 512)
        return NULL;
    X509_NAME *n = X509_NAME_new();
    size_t i = 0;
    while(n && i < s->length) {
        size_t end = i;
        while(end < s->length && s->data[end] != ',')
            end++;
        size_t eq = i;
        while(eq < end && s->data[eq] != '=')
            eq++;
        char key[PC_MAX_RDN], val[256];
        size_t kl = eq - i, vl = eq < end ? end - eq - 1 : 0;
        while(kl > 0 && s->data[i] == ' ') { /* "CN=a, O=b" */
            i++;
            kl--;
        }
        bool ok = eq < end && kl > 0 && kl < sizeof(key) && vl > 0 && vl < sizeof(val);
        if(ok) {
            memcpy(key, s->data + i, kl);
            key[kl] = '\0';
            memcpy(val, s->data + eq + 1, vl);
            val[vl] = '\0';
            ok = strpbrk(val, "\"\\") == NULL &&
                 X509_NAME_add_entry_by_txt(n, key, MBSTRING_UTF8, (const unsigned char *)val,
                                            -1, -1, 0) == 1;
        }
        if(!ok) {
            X509_NAME_free(n);
            ERR_clear_error();
            return NULL;
        }
        i = end + 1;
    }
    return n;
}

static UA_StatusCode add_san(X509_REQ *req, X509 *cur) {
    int idx = X509_get_ext_by_NID(cur, NID_subject_alt_name, -1);
    if(idx < 0)
        return UA_STATUSCODE_GOOD;
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    X509_EXTENSION *e = X509_EXTENSION_dup(X509_get_ext(cur, idx));
    bool ok = exts && e && sk_X509_EXTENSION_push(exts, e) > 0;
    if(ok)
        e = NULL; /* owned by exts */
    ok = ok && X509_REQ_add_extensions(req, exts) == 1;
    X509_EXTENSION_free(e);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return ok ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINTERNALERROR;
}

static UA_StatusCode fill(X509_REQ *req, X509 *cur, EVP_PKEY *key, const UA_String *subject,
                          bool emptySubject, bool noSan) {
    X509_NAME *name = NULL;
    if(emptySubject)
        name = X509_NAME_new();
    else if(subject && subject->length > 0) {
        if(!(name = parse_subject(subject)))
            return UA_STATUSCODE_BADINVALIDARGUMENT;
    } else
        name = X509_NAME_dup(X509_get_subject_name(cur));
    bool ok = name && X509_REQ_set_version(req, X509_REQ_VERSION_1) == 1 &&
              X509_REQ_set_subject_name(req, name) == 1 && X509_REQ_set_pubkey(req, key) == 1;
    X509_NAME_free(name);
    if(!ok)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_StatusCode r = noSan ? UA_STATUSCODE_GOOD : add_san(req, cur);
    if(r == UA_STATUSCODE_GOOD && X509_REQ_sign(req, key, EVP_sha256()) <= 0)
        r = UA_STATUSCODE_BADINTERNALERROR;
    return r;
}

UA_StatusCode pc_build(const UA_ByteString *current, EVP_PKEY *key, const UA_String *subject,
                       bool emptySubject, bool noSan, UA_ByteString *csr) {
    UA_ByteString_init(csr);
    if(!current || current->length == 0 || current->length > GDS_MAX_CERT_SIZE || !key)
        return UA_STATUSCODE_BADINTERNALERROR;
    const unsigned char *p = current->data;
    X509 *cur = d2i_X509(NULL, &p, (long)current->length);
    X509_REQ *req = X509_REQ_new();
    UA_StatusCode r = cur && req ? fill(req, cur, key, subject, emptySubject, noSan)
                                 : UA_STATUSCODE_BADINTERNALERROR;
    unsigned char *der = NULL;
    int len = r == UA_STATUSCODE_GOOD ? i2d_X509_REQ(req, &der) : 0;
    if(r == UA_STATUSCODE_GOOD && (len <= 0 || (size_t)len > GDS_MAX_CSR_SIZE))
        r = UA_STATUSCODE_BADINTERNALERROR;
    if(r == UA_STATUSCODE_GOOD) {
        UA_ByteString tmp = {(size_t)len, der};
        r = UA_ByteString_copy(&tmp, csr);
    }
    OPENSSL_free(der);
    X509_REQ_free(req);
    X509_free(cur);
    ERR_clear_error();
    return r;
}
