/* OpenGDS fuzz target: the opengdsd <-> opengds-signer messages
 * (docs/architecture.md, fuzz_signer_ipc.c; src/signer/proto.h).
 *
 * The first input byte picks the side, the rest is one datagram:
 *   even  request to the signer: gds_signer_handle against a real store
 *         and CA. It must always answer with a well-formed reply to the
 *         request's op (SIGN_CSR for a malformed request), and a request
 *         that decodes must re-encode to the same bytes.
 *   odd   reply to opengdsd (the ca_ipc client side): gds_sigp_decode_reply
 *         for the op in bits 1-3. A reply that decodes must re-encode to
 *         the same bytes.
 * The fixture (store with one application and one Received request, CA) is
 * created once, with fixed ids so seeds can name the stored request.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>

#include <stdio.h>
#include <string.h>

#include "ca.h"
#include "common/limits.h"
#include "fuzz.h"
#include "proto.h"
#include "signer.h"
#include "store.h"
#include "common/banned.h"

static gds_signer signer;

static gds_status seed_store(gds_store *st) {
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "Fuzz Client");
    rec.applicationUri = UA_STRING("urn:opengds:fuzz:client");
    rec.applicationType = UA_APPLICATIONTYPE_CLIENT;
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    const UA_Guid appId = FUZZ_APP_ID, reqId = FUZZ_REQ_ID;
    gds_status r = gds_store_app_insert(st, &appId, &rec);
    gds_request q;
    memset(&q, 0, sizeof(q));
    q.id = reqId;
    q.appId = appId;
    q.groupId = 615;
    q.certType = UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE;
    q.state = GDS_REQ_RECEIVED;
    if(r == GDS_OK)
        r = fuzz_make_csr(&q.csr);
    if(r == GDS_OK)
        r = gds_store_req_insert(st, &q);
    gds_buf_free(&q.csr);
    return r;
}

static gds_status open_ca(const char *dir) {
    static gds_buf pass;
    size_t passLen = 0;
    const uint8_t *pw = fuzz_passphrase(&passLen);
    pass.data = (uint8_t *)(uintptr_t)pw;
    pass.len = passLen;
    char caDir[GDS_MAX_PATH];
    gds_status r = gds_path(caDir, sizeof(caDir), "%s/ca", dir);
    if(r != GDS_OK)
        return r;
    gds_ca_config cfg;
    gds_ca_config_init(&cfg);
    cfg.dir = caDir;
    cfg.caKeyBits = 2048;
    cfg.keyPassphrase = &pass;
    return gds_ca_openssl_open(&cfg, &signer.ca);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc, (void)argv;
    char dir[GDS_MAX_PATH], db[GDS_MAX_PATH];
    gds_status r = fuzz_tmpdir(dir, sizeof(dir));
    if(r == GDS_OK)
        r = gds_path(db, sizeof(db), "%s/store.db", dir);
    if(r == GDS_OK)
        r = gds_store_open(db, &signer.store);
    if(r == GDS_OK)
        r = seed_store(signer.store);
    if(r == GDS_OK)
        r = open_ca(dir);
    if(r != GDS_OK) {
        fprintf(stderr, "fuzz_signer_msg: fixture: %s\n", gds_status_name(r));
        return 1;
    }
    return 0;
}

static bool same(const gds_buf *b, const uint8_t *data, size_t size) {
    return b->len == size && (size == 0 || memcmp(b->data, data, size) == 0);
}

/* The encoder for a decoded request. */
static gds_status reencode(const gds_sigp_request *q, gds_buf *out) {
    switch(q->op) {
    case GDS_SIGP_REVOKE:
        return gds_sigp_encode_revoke_issuer(q->issuer, &q->serial, out);
    case GDS_SIGP_NEW_KEY_PAIR:
        return gds_sigp_encode_new_key_pair(&q->requestId, q->format, &q->password, out);
    case GDS_SIGP_GET_CHAIN:
    case GDS_SIGP_ISSUE_CRL:
        return gds_sigp_encode_issuer_request(q->op, q->issuer, out);
    case GDS_SIGP_TOKEN_CHAIN:
    case GDS_SIGP_TOKEN_SIGN:
        return gds_sigp_encode_token(q->op, &q->data, out);
    case GDS_SIGP_SIGN_CSR:
    default:
        return gds_sigp_encode_request(q->op, &q->requestId, out);
    }
}

/* A request that decodes re-encodes to the same bytes; *op is the op the
 * reply carries (SIGN_CSR for a malformed request). */
static void request_round_trip(const uint8_t *msg, size_t len, gds_sigp_op *op) {
    gds_sigp_request q;
    gds_buf again = {0};
    if(gds_sigp_decode(msg, len, &q) != GDS_OK) {
        GDS_ASSERT(!q.serial.data && !q.password.data && !q.data.data);
        *op = GDS_SIGP_SIGN_CSR;
        return;
    }
    *op = q.op;
    GDS_ASSERT(reencode(&q, &again) == GDS_OK);
    GDS_ASSERT(same(&again, msg, len));
    gds_buf_free_secret(&again);
    gds_sigp_request_clear(&q);
}

static void fuzz_request(const uint8_t *msg, size_t len) {
    gds_sigp_op op = GDS_SIGP_SIGN_CSR;
    request_round_trip(msg, len, &op);
    gds_buf reply = {0};
    GDS_ASSERT(gds_signer_handle(&signer, msg, len, &reply) == GDS_OK);
    gds_status st = GDS_OK;
    gds_ca_issued issued;
    gds_buf der = {0};
    if(op == GDS_SIGP_NEW_KEY_PAIR)
        GDS_ASSERT(gds_sigp_decode_key_reply(reply.data, reply.len, &st, &issued, &der) == GDS_OK);
    else
        GDS_ASSERT(gds_sigp_decode_reply(op, reply.data, reply.len, &st, &issued, &der) == GDS_OK);
    gds_ca_issued_clear(&issued);
    gds_buf_free_secret(&der);
    gds_buf_free_secret(&reply);
}

static void fuzz_reply(gds_sigp_op op, const uint8_t *msg, size_t len) {
    gds_status st = GDS_OK;
    gds_ca_issued issued;
    gds_buf der = {0};
    if(gds_sigp_decode_reply(op, msg, len, &st, &issued, &der) != GDS_OK)
        return;
    gds_buf again = {0};
    GDS_ASSERT(gds_sigp_encode_reply(op, st, &issued, &der, &again) == GDS_OK);
    GDS_ASSERT(same(&again, msg, len));
    gds_buf_free(&again);
    gds_ca_issued_clear(&issued);
    gds_buf_free(&der);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if(size == 0 || size - 1 > GDS_SIGP_MAX_MSG + 1)
        return 0;
    static const gds_sigp_op ops[] = {GDS_SIGP_SIGN_CSR,   GDS_SIGP_GET_CHAIN,
                                      GDS_SIGP_ISSUE_CRL,  GDS_SIGP_REVOKE,
                                      GDS_SIGP_TOKEN_CHAIN, GDS_SIGP_TOKEN_SIGN,
                                      GDS_SIGP_SIGN_CSR,   GDS_SIGP_GET_CHAIN};
    if(data[0] & 1u)
        fuzz_reply(ops[(data[0] >> 1) & 7u], data + 1, size - 1);
    else
        fuzz_request(data + 1, size - 1);
    return 0;
}
