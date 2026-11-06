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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/limits.h"
#include "common/ua_args.h"
#include "gds_internal.h"
#include "common/banned.h"

typedef struct {
    gds_buf *serials;
    size_t n, cap;
    gds_status err;
} serial_list;

static bool collect_serial(void *ctx, const gds_buf *serial) {
    serial_list *l = ctx;
    if(l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 4;
        gds_buf *p = realloc(l->serials, cap * sizeof(*p));
        if(!p) {
            l->err = GDS_ENOMEM;
            return false;
        }
        l->serials = p;
        l->cap = cap;
    }
    l->err = gds_buf_dup(serial->data, serial->len, &l->serials[l->n]);
    if(l->err != GDS_OK)
        return false;
    l->n++;
    return true;
}

static void serial_list_clear(serial_list *l) {
    for(size_t i = 0; i < l->n; i++)
        gds_buf_free(&l->serials[i]);
    free(l->serials);
    memset(l, 0, sizeof(*l));
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
    gds_lock(s);
    gds_status st = gds_store_cert_revoke_app(s->store, appId, collect_serial, &l);
    gds_unlock(s);
    if(st == GDS_OK)
        st = l.err;
    if(st != GDS_OK) {
        serial_list_clear(&l);
        return gds_status_to_ua(st);
    }
    /* outside storeLock: the signer reads the store */
    for(size_t i = 0; st == GDS_OK && i < l.n; i++)
        st = gds_ca_revoke(s->ca, &l.serials[i]);
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
    st = gds_ca_revoke(s->ca, &serial); /* outside storeLock */
    gds_buf_free(&serial);
    if(st != GDS_OK) {
        fprintf(stderr, "opengds: RevokeCertificate: %s\n", gds_status_name(st));
        return ca_status(st);
    }
    return UA_STATUSCODE_GOOD;
}

/* RevokeCertificate is Optional on CertificateDirectoryType (§7.9.6), so
 * the GDS nodeset does not create it on the Directory object; it is added
 * here with the arguments of RevokeCertificateMethodType. */
static UA_StatusCode add_method_node(gds_server *s) {
    UA_NodeId id = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_REVOKECERTIFICATE);
    UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
    if(UA_Server_readNodeClass(s->ua, id, &nc) == UA_STATUSCODE_GOOD)
        return nc == UA_NODECLASS_METHOD ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADNODECLASSINVALID;
    UA_Argument in[2];
    UA_Argument_init(&in[0]);
    in[0].name = UA_STRING("ApplicationId");
    in[0].dataType = UA_TYPES[UA_TYPES_NODEID].typeId;
    in[0].valueRank = UA_VALUERANK_SCALAR;
    UA_Argument_init(&in[1]);
    in[1].name = UA_STRING("Certificate");
    in[1].dataType = UA_TYPES[UA_TYPES_BYTESTRING].typeId;
    in[1].valueRank = UA_VALUERANK_SCALAR;
    UA_MethodAttributes ma = UA_MethodAttributes_default;
    ma.displayName = UA_LOCALIZEDTEXT("", "RevokeCertificate");
    ma.executable = true;
    ma.userExecutable = true;
    return UA_Server_addMethodNode(s->ua, id, UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY),
                                   UA_NS0ID(HASCOMPONENT),
                                   UA_QUALIFIEDNAME(s->ns, "RevokeCertificate"), ma, NULL, 2, in,
                                   0, NULL, NULL, NULL);
}

UA_StatusCode gds_revoke_install(gds_server *s) {
    static const gds_method_entry m[] = {
        {UA_GDSID_DIRECTORY_REVOKECERTIFICATE, revoke_certificate},
    };
    UA_StatusCode r = add_method_node(s);
    return r == UA_STATUSCODE_GOOD ? gds_install_methods(s, m, GDS_ARRAY_SIZE(m)) : r;
}
