/* OpenGDS - RevokeCertificate (OPC 10000-12 §7.9.6) and the revocation done
 * by UnregisterApplication (§6.5.8).
 *
 * Order: the store marks the certificate revoked first, then the CA (in
 * opengdsd: opengds-signer, which revokes only a serial the store marks
 * revoked) puts it on the CRL. Both steps are idempotent, so a call that
 * failed at the CA can simply be made again. Trust lists read the CRL from
 * the CA, so they carry the new entry from the next read on.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/server.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/limits.h"
#include "common/ua_args.h"
#include "gds_internal.h"
#include "common/banned.h"

typedef struct {
    gds_buf *serials;
    gds_ca_issuer *issuers; /* the CA that issued serials[i] */
    size_t n, cap;
    gds_status err;
    UA_Guid app; /* the scan's filter */
} serial_list;

static bool add_serial(serial_list *l, const gds_buf *serial, gds_ca_issuer issuer) {
    if(l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 4;
        gds_buf *p = realloc(l->serials, cap * sizeof(*p));
        if(p)
            l->serials = p;
        gds_ca_issuer *q = p ? realloc(l->issuers, cap * sizeof(*q)) : NULL;
        if(!q) {
            l->err = GDS_ENOMEM;
            return false;
        }
        l->issuers = q;
        l->cap = cap;
    }
    l->err = gds_buf_dup(serial->data, serial->len, &l->serials[l->n]);
    if(l->err != GDS_OK)
        return false;
    l->issuers[l->n++] = issuer;
    return true;
}

/* revoke_app's visit: the serials alone, for a store without cert_scan;
 * every certificate issued then was RSA. */
static bool collect_serial(void *ctx, const gds_buf *serial) {
    return add_serial(ctx, serial, GDS_CA_ISSUER_RSA);
}

/* With cert_scan: the revoked certificates of the application and the CA
 * of each one's CertificateType. */
static bool collect_row(void *ctx, const gds_cert_row *row) {
    serial_list *l = ctx;
    gds_ca_issuer issuer = GDS_CA_ISSUER_RSA;
    if(!row->revoked || !UA_Guid_equal(&row->appId, &l->app))
        return true;
    (void)gds_ca_issuer_of(row->certType, &issuer);
    return add_serial(l, &row->serial, issuer);
}

static void serial_list_clear(serial_list *l) {
    for(size_t i = 0; i < l->n; i++)
        gds_buf_free(&l->serials[i]);
    free(l->serials);
    free(l->issuers);
    memset(l, 0, sizeof(*l));
}

/* Every revoked certificate of appId with its issuer. */
static gds_status revoked_of(gds_server *s, const UA_Guid *appId, serial_list *l) {
    gds_lock(s);
    gds_status st = gds_store_cert_revoke_app(s->store, appId, collect_serial, l);
    if(st == GDS_OK)
        st = l->err;
    if(st == GDS_OK) {
        serial_list scan;
        memset(&scan, 0, sizeof(scan));
        scan.app = *appId;
        gds_status sc = gds_store_cert_scan(s->store, collect_row, &scan);
        if(sc == GDS_OK)
            sc = scan.err;
        if(sc == GDS_OK) {
            serial_list_clear(l);
            *l = scan;
        } else {
            serial_list_clear(&scan);
            if(sc != GDS_EUNSUPPORTED)
                st = sc;
        }
    }
    gds_unlock(s);
    return st;
}

/* The CA that issued `der`, by its issuer name; RSA if none matches. */
static gds_ca_issuer issuer_of_cert(const gds_server *s, const gds_buf *der) {
    const unsigned char *p = der->data;
    X509 *x = d2i_X509(NULL, &p, (long)der->len);
    gds_ca_issuer r = GDS_CA_ISSUER_RSA;
    for(unsigned i = 0; x && i < GDS_CA_ISSUERS; i++) {
        const unsigned char *q = s->issuerCert[i].data;
        X509 *ca = s->issuerCert[i].len ? d2i_X509(NULL, &q, (long)s->issuerCert[i].len) : NULL;
        if(ca && X509_NAME_cmp(X509_get_issuer_name(x), X509_get_subject_name(ca)) == 0)
            r = (gds_ca_issuer)i; // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange): i < GDS_CA_ISSUERS
        X509_free(ca);
    }
    X509_free(x);
    return r;
}

/* A CA refusal is never the caller's fault: the store has already checked
 * the certificate. */
static UA_StatusCode ca_status(gds_status st) {
    if(st == GDS_EUNSUPPORTED)
        return UA_STATUSCODE_BADNOTSUPPORTED; /* a CA backend without revoke */
    if(st == GDS_ENOTLEADER || st == GDS_ESTATE)
        return UA_STATUSCODE_BADINVALIDSTATE;
    return UA_STATUSCODE_BADINTERNALERROR;
}

UA_StatusCode gds_revoke_app_certs(gds_server *s, const UA_Guid *appId) {
    serial_list l;
    memset(&l, 0, sizeof(l));
    gds_status st = revoked_of(s, appId, &l);
    if(st != GDS_OK) {
        serial_list_clear(&l);
        return gds_status_to_ua(st);
    }
    /* outside storeLock: the signer reads the store */
    for(size_t i = 0; st == GDS_OK && i < l.n; i++)
        st = gds_ca_revoke_issuer(s->ca, l.issuers[i], &l.serials[i]);
    serial_list_clear(&l);
    if(st != GDS_OK) {
        fprintf(stderr, "opengds: revoking the certificates of an application: %s\n",
                gds_status_name(st));
        return ca_status(st);
    }
    return UA_STATUSCODE_GOOD;
}

/* RevokeCertificate(ApplicationId, Certificate): CertificateAuthorityAdmin
 * only. Bad_NotFound for an unknown application, Bad_InvalidArgument for a
 * certificate this CertificateManager did not issue to it. */
static GDS_METHOD(revoke_certificate) {
    GDS_METHOD_UNUSED;
    (void)output;
    gds_server *s = gds_ctx(methodContext);
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(!gds_session_has(sessionContext, GDS_ROLE_CERTIFICATE_AUTHORITY_ADMIN))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    UA_Guid appId;
    UA_StatusCode r = gds_in_guid(s, inputSize, input, 0, &appId);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_ApplicationRecordDataType rec;
    r = gds_load_app(s, &appId, &rec); /* Bad_NotFound if not registered */
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_ApplicationRecordDataType_clear(&rec);
    const UA_ByteString *cert = NULL;
    if(inputSize < 2)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if(gds_arg_bytes(&input[1], GDS_MAX_CERT_SIZE, &cert) != UA_STATUSCODE_GOOD ||
       cert->length == 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    gds_buf der = {cert->data, cert->length}, serial = {0};
    gds_lock(s);
    gds_status st = gds_store_cert_revoke(s->store, &appId, &der, &serial);
    gds_unlock(s);
    if(st == GDS_ENOTFOUND)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(st != GDS_OK)
        return gds_status_to_ua(st);
    st = gds_ca_revoke_issuer(s->ca, issuer_of_cert(s, &der), &serial); /* outside storeLock */
    gds_buf_free(&serial);
    if(st != GDS_OK) {
        fprintf(stderr, "opengds: RevokeCertificate: %s\n", gds_status_name(st));
        return ca_status(st);
    }
    return UA_STATUSCODE_GOOD;
}

gds_status gds_server_revoke_serial(gds_server *s, const UA_ByteString *serial,
                                    const UA_ByteString *certificate,
                                    const UA_NodeId *certificateType) {
    if(!s || !serial || !serial->data || serial->length == 0 ||
       serial->length > GDS_MAX_SERIAL_SIZE)
        return GDS_EINVAL;
    if(certificate && (!certificate->data || certificate->length == 0 ||
                       certificate->length > GDS_MAX_CERT_SIZE))
        return GDS_EINVAL;
    if(gds_server_role(s) == GDS_NODE_STANDBY)
        return GDS_ESTATE;
    gds_buf sn = {serial->data, serial->length};
    if(certificate) {
        gds_buf der = {certificate->data, certificate->length};
        return gds_ca_revoke_issuer(s->ca, issuer_of_cert(s, &der), &sn);
    }
    if(certificateType) {
        gds_ca_issuer issuer;
        if(certificateType->namespaceIndex != 0 ||
           certificateType->identifierType != UA_NODEIDTYPE_NUMERIC ||
           !gds_ca_issuer_of(certificateType->identifier.numeric, &issuer))
            return GDS_EINVAL;
        return gds_ca_revoke_issuer(s->ca, issuer, &sn);
    }
    gds_status st = GDS_OK;
    bool any = false;
    for(unsigned i = 0; st == GDS_OK && i < GDS_CA_ISSUERS; i++) {
        if(s->issuerCert[i].len == 0)
            continue;
        any = true;
        st = gds_ca_revoke_issuer(s->ca, (gds_ca_issuer)i, &sn); // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange): i < GDS_CA_ISSUERS
    }
    return any ? st : gds_ca_revoke(s->ca, &sn);
}

UA_StatusCode gds_revoke_install(gds_server *s) {
    static const gds_method_entry m[] = {
        {UA_GDSID_DIRECTORY_REVOKECERTIFICATE, revoke_certificate},
    };
    /* Optional on CertificateDirectoryType (§7.9.6): not in the nodeset */
    static const gds_method_arg in[] = {{"ApplicationId", UA_NS0ID_NODEID, false},
                                        {"Certificate", UA_NS0ID_BYTESTRING, false}};
    UA_StatusCode r = gds_add_directory_method(s, UA_GDSID_DIRECTORY_REVOKECERTIFICATE,
                                               "RevokeCertificate", in, 2, NULL, 0);
    return r == UA_STATUSCODE_GOOD ? gds_install_methods(s, m, GDS_ARRAY_SIZE(m)) : r;
}
