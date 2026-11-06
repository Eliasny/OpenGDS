/* OpenGDS - opengds-signer request handling.
 * SPDX-License-Identifier: MPL-2.0 */
#include "signer.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "proto.h"
#include "common/banned.h"

/* SIGN_CSR: re-read everything from the store, then sign. */
static gds_status sign_from_store(gds_signer *s, const UA_Guid *reqId, gds_ca_issued *out) {
    gds_request q;
    memset(&q, 0, sizeof(q));
    gds_status r = gds_store_req_get(s->store, reqId, &q);
    if(r != GDS_OK)
        return r;
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    if(q.state != GDS_REQ_RECEIVED) {
        r = GDS_ESTATE; /* already signed, delivered or failed: never twice */
    } else {
        r = gds_store_app_get(s->store, &q.appId, &rec);
    }
    if(r == GDS_OK) {
        gds_ca_subject subj = {reqId, &rec, q.groupId, q.certType};
        r = gds_ca_sign_csr(s->ca, &subj, &q.csr, out);
    }
    UA_ApplicationRecordDataType_clear(&rec);
    gds_request_clear(&q);
    return r;
}

gds_status gds_signer_handle(gds_signer *s, const uint8_t *msg, size_t len, gds_buf *reply) {
    memset(reply, 0, sizeof(*reply));
    gds_sigp_op op = GDS_SIGP_SIGN_CSR;
    UA_Guid reqId;
    gds_status r = gds_sigp_decode_request(msg, len, &op, &reqId);
    if(r != GDS_OK) /* malformed: answer as SIGN_CSR, the peer drops it */
        return gds_sigp_encode_reply(GDS_SIGP_SIGN_CSR, r, NULL, NULL, reply);
    gds_ca_issued issued;
    memset(&issued, 0, sizeof(issued));
    gds_buf der = {0};
    switch(op) {
    case GDS_SIGP_SIGN_CSR:
        r = sign_from_store(s, &reqId, &issued);
        break;
    case GDS_SIGP_GET_CHAIN:
        r = gds_ca_get_ca_cert(s->ca, &der);
        break;
    case GDS_SIGP_ISSUE_CRL:
        r = gds_ca_get_crl(s->ca, &der);
        break;
    default:
        r = GDS_EUNSUPPORTED;
        break;
    }
    gds_status e = gds_sigp_encode_reply(op, r, &issued, &der, reply);
    gds_ca_issued_clear(&issued);
    gds_buf_free(&der);
    return e;
}

gds_status gds_signer_serve(gds_signer *s, int fd) {
    uint8_t *msg = malloc(GDS_SIGP_MAX_MSG);
    if(!msg)
        return GDS_ENOMEM;
    gds_status r = GDS_OK;
    for(;;) {
        /* MSG_TRUNC: the real length, so an oversized datagram is refused */
        ssize_t n = recv(fd, msg, GDS_SIGP_MAX_MSG, MSG_TRUNC);
        if(n == 0)
            break; /* peer closed */
        if(n < 0) {
            if(errno == EINTR)
                continue;
            r = GDS_EIO;
            break;
        }
        gds_buf reply = {0};
        size_t len = (size_t)n > GDS_SIGP_MAX_MSG ? 0 : (size_t)n;
        r = gds_signer_handle(s, msg, len, &reply);
        if(r == GDS_OK && send(fd, reply.data, reply.len, MSG_NOSIGNAL) != (ssize_t)reply.len)
            r = GDS_EIO;
        gds_buf_free(&reply);
        if(r != GDS_OK)
            break;
    }
    free(msg);
    return r;
}
