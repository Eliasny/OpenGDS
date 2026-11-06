/* OpenGDS - the GDS's own application instance certificate.
 *
 * The GDS registers itself in its own store and gets its certificate from
 * its own CA through the same path as every application (record -> request
 * -> CA slot), so the signer's rule "sign only what the store holds" has
 * no exception. The key is generated here and never leaves data_dir/own/.
 * Renewed when less than RENEW_DAYS remain.
 * SPDX-License-Identifier: MPL-2.0 */
#include "own_cert.h"

#include <open62541/nodeids.h>
#include <open62541/nodeids_gds.h>
#include <open62541/types_gds_generated.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common/ids.h"
#include "common/limits.h"
#include "common/banned.h"

#define RENEW_DAYS 30
#define OWN_KEY_BITS 2048

static bool still_valid(const gds_buf *der) {
    const unsigned char *p = der->data;
    X509 *x = d2i_X509(NULL, &p, (long)der->len);
    bool ok = false;
    if(x) {
        time_t limit = time(NULL) + (time_t)RENEW_DAYS * 86400;
        ok = X509_cmp_time(X509_get0_notAfter(x), &limit) > 0 &&
             X509_cmp_current_time(X509_get0_notBefore(x)) < 0;
    }
    X509_free(x);
    return ok;
}

static gds_status make_key_csr(gds_buf *keyDer, gds_buf *csrDer) {
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)OWN_KEY_BITS);
    X509_REQ *req = X509_REQ_new();
    gds_status r = GDS_ECRYPTO;
    unsigned char *k = NULL, *c = NULL;
    int kl = -1, cl = -1;
    if(key && req && X509_REQ_set_pubkey(req, key) == 1 &&
       X509_REQ_sign(req, key, EVP_sha256()) > 0) {
        kl = i2d_PrivateKey(key, &k);
        cl = i2d_X509_REQ(req, &c);
    }
    if(kl > 0 && cl > 0 && gds_buf_dup(k, (size_t)kl, keyDer) == GDS_OK) {
        r = gds_buf_dup(c, (size_t)cl, csrDer);
        if(r != GDS_OK)
            gds_buf_free_secret(keyDer);
    }
    if(k)
        OPENSSL_clear_free(k, (size_t)kl);
    OPENSSL_free(c);
    X509_REQ_free(req);
    EVP_PKEY_free(key);
    return r;
}

/* The GDS's record, registered on first start. */
static gds_status own_record(const gdsd_own_params *p, gds_store *st, UA_Guid *id) {
    UA_String uri = UA_STRING((char *)(uintptr_t)p->applicationUri);
    UA_ApplicationRecordDataType *found = NULL;
    size_t n = 0;
    gds_status r = gds_store_app_find_uri(st, &uri, 1, &found, &n);
    if(r == GDS_OK && n == 1) {
        *id = found[0].applicationId.identifier.guid;
        UA_Array_delete(found, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
        return GDS_OK;
    }
    UA_Array_delete(found, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    if(r != GDS_OK && r != GDS_ENOTFOUND)
        return r;

    char url[GDS_MAX_PATH];
    if(gds_path(url, sizeof(url), "opc.tcp://%s:%u", p->host, (unsigned)p->port) != GDS_OK)
        return GDS_ETOOBIG;
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_LocalizedText name = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)p->applicationName);
    UA_String durl = UA_STRING(url);
    UA_String cap = UA_STRING("GDS");
    rec.applicationUri = uri;
    rec.applicationType = UA_APPLICATIONTYPE_DISCOVERYSERVER;
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    rec.productUri = UA_STRING((char *)(uintptr_t)p->productUri);
    rec.discoveryUrls = &durl;
    rec.discoveryUrlsSize = 1;
    rec.serverCapabilities = &cap;
    rec.serverCapabilitiesSize = 1;
    r = gds_guid_random(id);
    if(r == GDS_OK)
        r = gds_store_app_insert(st, id, &rec);
    return r;
}

static gds_status issue(const gdsd_own_params *p, gds_store *st, gds_ca *ca, gds_buf *cert,
                        gds_buf *key) {
    gds_request q;
    memset(&q, 0, sizeof(q));
    q.groupId = UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP;
    q.certType = UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE;
    q.state = GDS_REQ_RECEIVED;
    gds_status r = own_record(p, st, &q.appId);
    if(r == GDS_OK)
        r = gds_guid_random(&q.id);
    if(r == GDS_OK)
        r = make_key_csr(key, &q.csr);
    if(r == GDS_OK)
        r = gds_store_req_insert(st, &q);
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    if(r == GDS_OK)
        r = gds_store_app_get(st, &q.appId, &rec);
    gds_ca_issued is;
    memset(&is, 0, sizeof(is));
    if(r == GDS_OK) {
        gds_ca_subject subj = {&q.id, &rec, q.groupId, q.certType};
        r = gds_ca_sign_csr(ca, &subj, &q.csr, &is);
    }
    if(r == GDS_OK)
        r = gds_store_cert_add(st, &q.appId, q.groupId, q.certType, &is.serial, &is.der,
                               is.notBefore, is.notAfter);
    if(r == GDS_OK)
        r = gds_store_req_set_state(st, &q.id, GDS_REQ_ISSUED, &is.der, UA_STATUSCODE_GOOD);
    if(r == GDS_OK)
        r = gds_store_req_set_state(st, &q.id, GDS_REQ_DELIVERED, &is.der, UA_STATUSCODE_GOOD);
    if(r == GDS_OK) {
        *cert = is.der;
        is.der = (gds_buf){0};
    } else {
        gds_buf_free_secret(key);
    }
    gds_ca_issued_clear(&is);
    UA_ApplicationRecordDataType_clear(&rec);
    gds_request_clear(&q);
    return r;
}

gds_status gdsd_own_cert(const gdsd_own_params *p, gds_store *st, gds_ca *ca, gds_buf *cert,
                         gds_buf *key) {
    char dir[GDS_MAX_PATH], certPath[GDS_MAX_PATH], keyPath[GDS_MAX_PATH];
    gds_status r = gds_path(dir, sizeof(dir), "%s/own", p->dataDir);
    if(r == GDS_OK)
        r = gds_path(certPath, sizeof(certPath), "%s/cert.der", dir);
    if(r == GDS_OK)
        r = gds_path(keyPath, sizeof(keyPath), "%s/key.der", dir);
    if(r == GDS_OK)
        r = gds_mkdirs(dir, 0700);
    if(r != GDS_OK)
        return r;
    if(gds_file_read(certPath, GDS_MAX_CERT_SIZE, cert) == GDS_OK) {
        if(still_valid(cert) && gds_file_read(keyPath, GDS_MAX_CERT_SIZE, key) == GDS_OK)
            return GDS_OK;
        gds_buf_free(cert);
    }
    fprintf(stderr, "opengdsd: issuing the GDS's own certificate\n");
    r = issue(p, st, ca, cert, key);
    if(r == GDS_OK)
        r = gds_file_write_atomic(keyPath, key->data, key->len, 0600);
    if(r == GDS_OK)
        r = gds_file_write_atomic(certPath, cert->data, cert->len, 0644);
    if(r != GDS_OK) {
        gds_buf_free(cert);
        gds_buf_free_secret(key);
    }
    return r;
}
