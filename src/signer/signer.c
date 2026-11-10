/* OpenGDS - opengds-signer request handling.
 * SPDX-License-Identifier: MPL-2.0 */
#include "signer.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "proto.h"
#include "common/banned.h"

static gds_status store_result(gds_signer *s, gds_status r) {
    if(r == GDS_EIO)
        s->storeFailed = true;
    return r;
}

/* SIGN_CSR: re-read everything from the store, then sign. */
static gds_status sign_from_store(gds_signer *s, const UA_Guid *reqId, gds_ca_issued *out) {
    gds_request q;
    memset(&q, 0, sizeof(q));
    gds_status r = store_result(s, gds_store_req_get(s->store, reqId, &q));
    if(r != GDS_OK)
        return r;
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    if(q.state != GDS_REQ_RECEIVED) {
        r = GDS_ESTATE; /* already signed, delivered or failed: never twice */
    } else {
        r = store_result(s, gds_store_app_get(s->store, &q.appId, &rec));
    }
    if(r == GDS_OK) {
        gds_ca_subject subj = {reqId, &rec, q.groupId, q.certType};
        r = gds_ca_sign_csr(s->ca, &subj, &q.csr, out);
    }
    UA_ApplicationRecordDataType_clear(&rec);
    gds_request_clear(&q);
    return r;
}

/* NEW_KEY_PAIR: a Received request without a CSR (StartNewKeyPairRequest);
 * the record from the store, only format and password from opengdsd. */
static gds_status key_pair_from_store(gds_signer *s, const gds_sigp_request *m,
                                      gds_ca_issued *out, gds_buf *key) {
    gds_request q;
    memset(&q, 0, sizeof(q));
    gds_status r = store_result(s, gds_store_req_get(s->store, &m->requestId, &q));
    if(r != GDS_OK)
        return r;
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    if(q.state != GDS_REQ_RECEIVED)
        r = GDS_ESTATE;
    else if(q.csr.len != 0)
        r = GDS_EDENIED; /* a signing request: its key is the client's */
    else
        r = store_result(s, gds_store_app_get(s->store, &q.appId, &rec));
    if(r == GDS_OK) {
        gds_ca_subject subj = {&m->requestId, &rec, q.groupId, q.certType};
        gds_ca_keyreq kr = {m->format, &m->password};
        r = gds_ca_new_key_pair(s->ca, &subj, &kr, out, key);
    }
    UA_ApplicationRecordDataType_clear(&rec);
    gds_request_clear(&q);
    return r;
}

static gds_status journal(gds_signer *s, const UA_Guid *reqId, gds_status r,
                          gds_ca_issued *issued) {
    if(!s->journal)
        return r;
    if(r != GDS_OK) {
        if(gds_journal_refused(s->journal, reqId, r) != GDS_OK)
            fprintf(stderr, "opengds-signer: journal write failed (refusal)\n");
        return r;
    }
    if(gds_journal_issued(s->journal, reqId, issued) == GDS_OK)
        return GDS_OK;
    fprintf(stderr, "opengds-signer: journal write failed; certificate dropped\n");
    gds_ca_issued_clear(issued);
    return GDS_EIO;
}

/* REVOKE: only a serial the store marks revoked, so opengdsd cannot put an
 * arbitrary serial on the CRL. Replies with the new CRL. */
static gds_status revoke_from_store(gds_signer *s, gds_ca_issuer issuer, const gds_buf *serial,
                                    gds_buf *crl) {
    bool revoked = false;
    gds_status r = store_result(s, gds_store_cert_is_revoked(s->store, serial, &revoked));
    if(r != GDS_OK)
        return r;
    if(!revoked)
        return GDS_EDENIED;
    r = gds_ca_revoke_issuer(s->ca, issuer, serial);
    return r == GDS_OK ? gds_ca_get_issuer_crl(s->ca, issuer, crl) : r;
}

gds_status gds_signer_handle(gds_signer *s, const uint8_t *msg, size_t len, gds_buf *reply) {
    memset(reply, 0, sizeof(*reply));
    gds_sigp_request m;
    gds_status r = gds_sigp_decode(msg, len, &m);
    if(r != GDS_OK) /* malformed: answer as SIGN_CSR, the peer drops it */
        return gds_sigp_encode_reply(GDS_SIGP_SIGN_CSR, r, NULL, NULL, reply);
    gds_ca_issued issued;
    memset(&issued, 0, sizeof(issued));
    gds_buf der = {0}, key = {0};
    switch(m.op) {
    case GDS_SIGP_SIGN_CSR:
        r = journal(s, &m.requestId, sign_from_store(s, &m.requestId, &issued), &issued);
        break;
    case GDS_SIGP_NEW_KEY_PAIR:
        r = journal(s, &m.requestId, key_pair_from_store(s, &m, &issued, &key), &issued);
        break;
    case GDS_SIGP_REVOKE:
        r = revoke_from_store(s, m.issuer, &m.serial, &der);
        break;
    case GDS_SIGP_GET_CHAIN:
        r = gds_ca_get_issuer_cert(s->ca, m.issuer, &der);
        break;
    case GDS_SIGP_ISSUE_CRL:
        r = gds_ca_get_issuer_crl(s->ca, m.issuer, &der);
        break;
    case GDS_SIGP_TOKEN_CHAIN:
        r = gds_ca_token_chain(s->ca, (const char *)m.data.data, &der);
        break;
    case GDS_SIGP_TOKEN_SIGN: /* gds_ca_token_sign refuses anything but a JWS input */
        r = gds_ca_token_sign(s->ca, &m.data, &der);
        break;
    case GDS_SIGP_EXPORT_KEYS: /* only to the signer's own recipients */
        r = s->nExportRecipients
                ? gds_ca_export_keys(s->ca, s->exportRecipients, s->nExportRecipients, &der)
                : GDS_EDENIED;
        fprintf(stderr, "opengds-signer: CA key export to %zu recipient(s): %s\n",
                s->nExportRecipients, gds_status_name(r));
        break;
    default:
        r = GDS_EUNSUPPORTED;
        break;
    }
    gds_status e = m.op == GDS_SIGP_NEW_KEY_PAIR
                       ? gds_sigp_encode_key_reply(r, &issued, &key, reply)
                       : gds_sigp_encode_reply(m.op, r, &issued, &der, reply);
    gds_ca_issued_clear(&issued);
    gds_buf_free(&der);
    gds_buf_free_secret(&key);
    gds_sigp_request_clear(&m);
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
        if(r == GDS_OK && s->storeFailed)
            r = GDS_EIO; /* the reply went out; a restart reopens the store */
        if(r != GDS_OK)
            break;
    }
    free(msg);
    return r;
}
