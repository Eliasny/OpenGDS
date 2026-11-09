/* OpenGDS - the CA slot in opengdsd: forwards to opengds-signer over a
 * SOCK_SEQPACKET socket (decision G1). Only the request id crosses for
 * SIGN_CSR; the signer re-reads the request and the record from the store.
 * One request at a time per socket.
 * SPDX-License-Identifier: MPL-2.0 */
#include "ca_ipc.h"

#include <openssl/crypto.h>

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "proto.h"
#include "common/banned.h"

typedef struct {
    int fd;
    int timeoutMs;
    pthread_mutex_t lock;
    uint8_t *rx;
} ipc_ca;

static gds_status recv_reply(ipc_ca *c, size_t *len) {
    struct pollfd p = {c->fd, POLLIN, 0};
    int pr;
    do {
        pr = poll(&p, 1, c->timeoutMs);
    } while(pr < 0 && errno == EINTR);
    if(pr == 0)
        return GDS_EREMOTE; /* signer did not answer in time */
    if(pr < 0)
        return GDS_EIO;
    ssize_t n = recv(c->fd, c->rx, GDS_SIGP_MAX_MSG, MSG_TRUNC);
    if(n <= 0 || (size_t)n > GDS_SIGP_MAX_MSG)
        return GDS_EREMOTE;
    *len = (size_t)n;
    return GDS_OK;
}

/* Send one encoded request (taken) and decode its reply into issued or der. */
static gds_status exchange(ipc_ca *c, gds_sigp_op op, gds_buf req, gds_ca_issued *issued,
                           gds_buf *der) {
    gds_status r = GDS_OK;
    pthread_mutex_lock(&c->lock);
    size_t len = 0;
    if(send(c->fd, req.data, req.len, MSG_NOSIGNAL) != (ssize_t)req.len)
        r = GDS_EREMOTE;
    if(r == GDS_OK)
        r = recv_reply(c, &len);
    gds_status remote = GDS_EREMOTE;
    if(r == GDS_OK)
        r = gds_sigp_decode_reply(op, c->rx, len, &remote, issued, der);
    pthread_mutex_unlock(&c->lock);
    gds_buf_free(&req);
    return r == GDS_OK ? remote : r;
}

static gds_status call(ipc_ca *c, gds_sigp_op op, const UA_Guid *reqId, gds_ca_issued *issued,
                       gds_buf *der) {
    gds_buf req = {0};
    gds_status r = gds_sigp_encode_request(op, reqId, &req);
    return r == GDS_OK ? exchange(c, op, req, issued, der) : r;
}

static gds_status ipc_sign_csr(void *ctx, const gds_ca_subject *subj, const gds_buf *csrDer,
                               gds_ca_issued *out) {
    (void)csrDer; /* the signer reads the CSR from the store */
    return call(ctx, GDS_SIGP_SIGN_CSR, subj->requestId, out, NULL);
}

/* The key is generated and encrypted in the signer; opengdsd only relays
 * the format and the password. The receive buffer is wiped afterwards. */
static gds_status ipc_new_key_pair(void *ctx, const gds_ca_subject *subj, const gds_ca_keyreq *kr,
                                   gds_ca_issued *out, gds_buf *key) {
    ipc_ca *c = ctx;
    gds_buf req = {0};
    gds_status r = gds_sigp_encode_new_key_pair(subj->requestId, kr->format, kr->password, &req);
    if(r != GDS_OK)
        return r;
    pthread_mutex_lock(&c->lock);
    size_t len = 0;
    if(send(c->fd, req.data, req.len, MSG_NOSIGNAL) != (ssize_t)req.len)
        r = GDS_EREMOTE;
    if(r == GDS_OK)
        r = recv_reply(c, &len);
    gds_status remote = GDS_EREMOTE;
    if(r == GDS_OK)
        r = gds_sigp_decode_key_reply(c->rx, len, &remote, out, key);
    OPENSSL_cleanse(c->rx, len);
    pthread_mutex_unlock(&c->lock);
    gds_buf_free_secret(&req); /* it carried the password */
    return r == GDS_OK ? remote : r;
}

static gds_status ipc_get_ca_cert(void *ctx, gds_buf *out) {
    return call(ctx, GDS_SIGP_GET_CHAIN, NULL, NULL, out);
}

static gds_status ipc_get_crl(void *ctx, gds_buf *out) {
    return call(ctx, GDS_SIGP_ISSUE_CRL, NULL, NULL, out);
}

static gds_status ipc_revoke(void *ctx, const gds_buf *serial) {
    gds_buf req = {0};
    gds_status r = gds_sigp_encode_revoke(serial, &req);
    if(r != GDS_OK)
        return r;
    gds_buf crl = {0}; /* the new CRL; trust lists fetch it again */
    r = exchange(ctx, GDS_SIGP_REVOKE, req, NULL, &crl);
    gds_buf_free(&crl);
    return r;
}

static gds_status ipc_issuer_get(void *ctx, gds_sigp_op op, gds_ca_issuer issuer, gds_buf *out) {
    gds_buf req = {0};
    gds_status r = gds_sigp_encode_issuer_request(op, issuer, &req);
    return r == GDS_OK ? exchange(ctx, op, req, NULL, out) : r;
}

static gds_status ipc_get_issuer_cert(void *ctx, gds_ca_issuer issuer, gds_buf *out) {
    return ipc_issuer_get(ctx, GDS_SIGP_GET_CHAIN, issuer, out);
}

static gds_status ipc_get_issuer_crl(void *ctx, gds_ca_issuer issuer, gds_buf *out) {
    return ipc_issuer_get(ctx, GDS_SIGP_ISSUE_CRL, issuer, out);
}

static gds_status ipc_revoke_issuer(void *ctx, gds_ca_issuer issuer, const gds_buf *serial) {
    gds_buf req = {0};
    gds_status r = gds_sigp_encode_revoke_issuer(issuer, serial, &req);
    if(r != GDS_OK)
        return r;
    gds_buf crl = {0}; /* the new CRL; trust lists fetch it again */
    r = exchange(ctx, GDS_SIGP_REVOKE, req, NULL, &crl);
    gds_buf_free(&crl);
    return r;
}

static gds_status ipc_token(void *ctx, gds_sigp_op op, const gds_buf *data, gds_buf *out) {
    gds_buf req = {0};
    gds_status r = gds_sigp_encode_token(op, data, &req);
    return r == GDS_OK ? exchange(ctx, op, req, NULL, out) : r;
}

static gds_status ipc_token_chain(void *ctx, const char *serviceUri, gds_buf *out) {
    gds_buf uri = {(uint8_t *)(uintptr_t)serviceUri, strlen(serviceUri)};
    return ipc_token(ctx, GDS_SIGP_TOKEN_CHAIN, &uri, out);
}

static gds_status ipc_token_sign(void *ctx, const gds_buf *input, gds_buf *sig) {
    return ipc_token(ctx, GDS_SIGP_TOKEN_SIGN, input, sig);
}

static void ipc_destroy(void *ctx) {
    ipc_ca *c = ctx;
    if(!c)
        return;
    if(c->fd >= 0)
        close(c->fd);
    pthread_mutex_destroy(&c->lock);
    free(c->rx);
    free(c);
}

static const gds_ca_backend ipc_backend = {
    .abiVersion = GDS_CA_ABI_VERSION,
    .pre_sign = NULL, /* runs in the signer, next to the key */
    .sign_csr = ipc_sign_csr,
    .get_ca_cert = ipc_get_ca_cert,
    .get_crl = ipc_get_crl,
    .destroy = ipc_destroy,
    .revoke = ipc_revoke,
    .new_key_pair = ipc_new_key_pair,
    .get_issuer_cert = ipc_get_issuer_cert,
    .get_issuer_crl = ipc_get_issuer_crl,
    .revoke_issuer = ipc_revoke_issuer,
    .token_chain = ipc_token_chain,
    .token_sign = ipc_token_sign,
};

gds_status gds_ca_ipc_open(int fd, int timeoutMs, gds_ca **out) {
    *out = NULL;
    if(fd < 0 || timeoutMs <= 0) {
        if(fd >= 0)
            close(fd);
        return GDS_EINVAL;
    }
    ipc_ca *c = calloc(1, sizeof(*c));
    uint8_t *rx = malloc(GDS_SIGP_MAX_MSG);
    if(!c || !rx || pthread_mutex_init(&c->lock, NULL) != 0) {
        free(c);
        free(rx);
        close(fd);
        return GDS_ENOMEM;
    }
    c->fd = fd;
    c->timeoutMs = timeoutMs;
    c->rx = rx;
    return gds_ca_wrap(&ipc_backend, c, out);
}
