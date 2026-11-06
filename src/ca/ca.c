/* OpenGDS - the CA slot wrapper: one backend behind one interface.
 * SPDX-License-Identifier: MPL-2.0 */
#include "ca.h"

#include <stdlib.h>
#include <string.h>

#include "common/limits.h"
#include "common/banned.h"

struct gds_ca {
    gds_ca_backend b;
    void *ctx;
};

void gds_ca_issued_clear(gds_ca_issued *c) {
    gds_buf_free(&c->der);
    gds_buf_free(&c->serial);
    c->notBefore = 0;
    c->notAfter = 0;
}

gds_status gds_ca_wrap(const gds_ca_backend *backend, void *ctx, gds_ca **out) {
    *out = NULL;
    if(!backend || backend->abiVersion != GDS_CA_ABI_VERSION || !backend->sign_csr ||
       !backend->get_ca_cert || !backend->get_crl || !backend->destroy) {
        if(backend && backend->destroy)
            backend->destroy(ctx);
        return GDS_EINVAL;
    }
    gds_ca *ca = calloc(1, sizeof(*ca));
    if(!ca) {
        backend->destroy(ctx);
        return GDS_ENOMEM;
    }
    ca->b = *backend;
    ca->ctx = ctx;
    *out = ca;
    return GDS_OK;
}

void gds_ca_close(gds_ca *ca) {
    if(!ca)
        return;
    ca->b.destroy(ca->ctx);
    free(ca);
}

gds_status gds_ca_sign_csr(gds_ca *ca, const gds_ca_subject *subj, const gds_buf *csrDer,
                           gds_ca_issued *out) {
    memset(out, 0, sizeof(*out));
    if(!subj || !subj->record || !subj->requestId || !csrDer || !csrDer->data)
        return GDS_EINVAL;
    if(ca->b.pre_sign) {
        gds_status r = ca->b.pre_sign(ca->ctx, GDS_CA_OP_SIGN_CSR, subj);
        if(r != GDS_OK)
            return r;
    }
    gds_status r = ca->b.sign_csr(ca->ctx, subj, csrDer, out);
    if(r != GDS_OK)
        gds_ca_issued_clear(out);
    return r;
}

gds_status gds_ca_get_ca_cert(gds_ca *ca, gds_buf *out) {
    memset(out, 0, sizeof(*out));
    return ca->b.get_ca_cert(ca->ctx, out);
}

gds_status gds_ca_get_crl(gds_ca *ca, gds_buf *out) {
    memset(out, 0, sizeof(*out));
    return ca->b.get_crl(ca->ctx, out);
}

gds_status gds_ca_revoke(gds_ca *ca, const gds_buf *serial) {
    if(!serial || !serial->data || serial->len == 0 || serial->len > GDS_MAX_SERIAL_SIZE)
        return GDS_EINVAL;
    if(!ca->b.revoke)
        return GDS_EUNSUPPORTED;
    return ca->b.revoke(ca->ctx, serial);
}
