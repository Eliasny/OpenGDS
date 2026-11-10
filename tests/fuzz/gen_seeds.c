/* OpenGDS fuzz targets - writes the binary seeds of tests/fuzz/corpus.
 * Not run by the tests; rerun it when a message format changes:
 *   build/tests/fuzz/fuzz_gen_seeds tests/fuzz/corpus
 * The text seeds (daemon config, users file) are written by hand.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/types.h>
#include <open62541/types_gds_generated.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/limits.h"
#include "fuzz.h"
#include "proto.h"
#include "common/banned.h"

static const char *root;

static gds_status put(const char *target, const char *name, const uint8_t *prefix,
                      size_t prefixLen, const uint8_t *data, size_t len) {
    char dir[GDS_MAX_PATH], path[GDS_MAX_PATH];
    gds_buf b = {0};
    gds_status r = gds_path(dir, sizeof(dir), "%s/%s", root, target);
    if(r == GDS_OK)
        r = gds_mkdirs(dir, 0755);
    if(r == GDS_OK)
        r = gds_path(path, sizeof(path), "%s/%s", dir, name);
    if(r == GDS_OK)
        r = gds_buf_append(&b, prefix, prefixLen, GDS_MAX_TRUSTLIST_SIZE);
    if(r == GDS_OK)
        r = gds_buf_append(&b, data, len, GDS_MAX_TRUSTLIST_SIZE);
    if(r == GDS_OK)
        r = gds_file_write_atomic(path, b.data, b.len, 0644);
    gds_buf_free(&b);
    if(r != GDS_OK)
        fprintf(stderr, "%s/%s: %s\n", target, name, gds_status_name(r));
    return r;
}

static gds_status put_ua(const char *target, const char *name, const void *v,
                         const UA_DataType *t) {
    UA_ByteString enc = UA_BYTESTRING_NULL;
    if(UA_encodeBinary(v, t, &enc, NULL) != UA_STATUSCODE_GOOD)
        return GDS_EINVAL;
    gds_status r = put(target, name, NULL, 0, enc.data, enc.length);
    UA_ByteString_clear(&enc);
    return r;
}

/* ---- fuzz_csr ---- */

static gds_status ec_csr(gds_buf *out) {
    memset(out, 0, sizeof(*out));
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    X509_REQ *req = X509_REQ_new();
    unsigned char *der = NULL;
    int len = 0;
    if(key && req && X509_REQ_set_pubkey(req, key) == 1 &&
       X509_REQ_sign(req, key, EVP_sha256()) > 0)
        len = i2d_X509_REQ(req, &der);
    gds_status r = len > 0 ? gds_buf_dup(der, (size_t)len, out) : GDS_ECRYPTO;
    OPENSSL_free(der);
    X509_REQ_free(req);
    EVP_PKEY_free(key);
    return r;
}

static gds_status seeds_csr(void) {
    gds_buf rsa = {0}, ec = {0};
    gds_status r = fuzz_make_csr(&rsa);
    if(r == GDS_OK)
        r = put("fuzz_csr", "rsa2048.der", NULL, 0, rsa.data, rsa.len);
    if(r == GDS_OK) /* trailing byte after the DER */
        r = put("fuzz_csr", "rsa2048-trailing.der", rsa.data, rsa.len, (const uint8_t *)"", 1);
    if(r == GDS_OK && rsa.len > 40) /* signature broken */
        rsa.data[rsa.len - 20] ^= 0x55u;
    if(r == GDS_OK)
        r = put("fuzz_csr", "rsa2048-badsig.der", NULL, 0, rsa.data, rsa.len);
    if(r == GDS_OK)
        r = ec_csr(&ec);
    if(r == GDS_OK)
        r = put("fuzz_csr", "p256.der", NULL, 0, ec.data, ec.len);
    gds_buf_free(&rsa);
    gds_buf_free(&ec);
    return r;
}

/* ---- fuzz_app_record ---- */

static gds_status seeds_app_record(void) {
    const UA_DataType *t = &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE];
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_LocalizedText names[2] = {UA_LOCALIZEDTEXT("en", "Fuzz Server"),
                                 UA_LOCALIZEDTEXT("de", "Fuzz-Server")};
    UA_String urls[3] = {UA_STRING("opc.tcp://plc1.example.com:4840"),
                         UA_STRING("opc.tcp://[fe80::1]:4840/ua"),
                         UA_STRING("opc.https://192.0.2.7:443")};
    UA_String caps[2] = {UA_STRING("DA"), UA_STRING("HD")};
    rec.applicationId = UA_NODEID_NUMERIC(2, 1);
    rec.applicationUri = UA_STRING("urn:opengds:fuzz:server");
    rec.applicationType = UA_APPLICATIONTYPE_SERVER;
    rec.applicationNames = names;
    rec.applicationNamesSize = 2;
    rec.productUri = UA_STRING("https://opengds.org/fuzz");
    rec.discoveryUrls = urls;
    rec.discoveryUrlsSize = 3;
    rec.serverCapabilities = caps;
    rec.serverCapabilitiesSize = 2;
    gds_status r = put_ua("fuzz_app_record", "server.bin", &rec, t);
    rec.applicationType = UA_APPLICATIONTYPE_CLIENT;
    rec.applicationNamesSize = 1;
    rec.discoveryUrlsSize = 0;
    rec.serverCapabilitiesSize = 0;
    rec.applicationUri = UA_STRING("urn:opengds:fuzz:client");
    if(r == GDS_OK)
        r = put_ua("fuzz_app_record", "client.bin", &rec, t);
    rec.applicationType = UA_APPLICATIONTYPE_DISCOVERYSERVER; /* no URL: refused */
    if(r == GDS_OK)
        r = put_ua("fuzz_app_record", "discovery-no-url.bin", &rec, t);
    return r;
}

/* ---- fuzz_signer_msg: first byte 0 = request, 1/3/5/7/9/11 = reply ---- */

static const uint8_t SIDE_REQUEST[1] = {0};

static gds_status put_request(const char *name, gds_sigp_op op, const UA_Guid *id) {
    gds_buf m = {0};
    gds_status r = gds_sigp_encode_request(op, id, &m);
    if(r == GDS_OK)
        r = put("fuzz_signer_msg", name, SIDE_REQUEST, 1, m.data, m.len);
    gds_buf_free(&m);
    return r;
}

static gds_status put_reply(const char *name, gds_sigp_op op, gds_status st,
                            const gds_ca_issued *issued, const gds_buf *der) {
    uint8_t side = op == GDS_SIGP_SIGN_CSR      ? 1u
                   : op == GDS_SIGP_GET_CHAIN   ? 3u
                   : op == GDS_SIGP_REVOKE      ? 7u
                   : op == GDS_SIGP_TOKEN_CHAIN ? 9u
                   : op == GDS_SIGP_TOKEN_SIGN  ? 11u
                   : op == GDS_SIGP_EXPORT_KEYS ? 15u
                                                : 5u;
    gds_buf m = {0};
    gds_status r = gds_sigp_encode_reply(op, st, issued, der, &m);
    if(r == GDS_OK)
        r = put("fuzz_signer_msg", name, &side, 1, m.data, m.len);
    gds_buf_free(&m);
    return r;
}

static gds_status seeds_signer_msg(void) {
    const UA_Guid stored = FUZZ_REQ_ID;
    UA_Guid other = stored;
    other.data1 ^= 0xffu;
    gds_status r = put_request("req-sign-stored.bin", GDS_SIGP_SIGN_CSR, &stored);
    if(r == GDS_OK)
        r = put_request("req-sign-unknown.bin", GDS_SIGP_SIGN_CSR, &other);
    if(r == GDS_OK)
        r = put_request("req-get-chain.bin", GDS_SIGP_GET_CHAIN, NULL);
    if(r == GDS_OK)
        r = put_request("req-issue-crl.bin", GDS_SIGP_ISSUE_CRL, NULL);
    uint8_t serial[20], cert[64];
    memset(serial, 0x5a, sizeof(serial));
    memset(cert, 0x30, sizeof(cert));
    gds_ca_issued issued = {{cert, sizeof(cert)}, {serial, sizeof(serial)}, 1700000000, 1731536000};
    gds_buf der = {cert, sizeof(cert)};
    if(r == GDS_OK)
        r = put_reply("reply-sign-ok.bin", GDS_SIGP_SIGN_CSR, GDS_OK, &issued, NULL);
    if(r == GDS_OK)
        r = put_reply("reply-sign-refused.bin", GDS_SIGP_SIGN_CSR, GDS_ESTATE, NULL, NULL);
    if(r == GDS_OK)
        r = put_reply("reply-chain-ok.bin", GDS_SIGP_GET_CHAIN, GDS_OK, NULL, &der);
    if(r == GDS_OK)
        r = put_reply("reply-crl-ok.bin", GDS_SIGP_ISSUE_CRL, GDS_OK, NULL, &der);
    if(r == GDS_OK)
        r = put_reply("reply-revoke-ok.bin", GDS_SIGP_REVOKE, GDS_OK, NULL, &der);
    gds_buf ser = {serial, sizeof(serial)}, m = {0};
    if(r == GDS_OK)
        r = gds_sigp_encode_revoke(&ser, &m);
    if(r == GDS_OK) /* not marked revoked in the fixture store: refused */
        r = put("fuzz_signer_msg", "req-revoke.bin", SIDE_REQUEST, 1, m.data, m.len);
    gds_buf_free(&m);
    /* the AccessToken key: chain, then a JWS input ({"alg":"RS256"}.{}) */
    static const char uri[] = "urn:opengds:fuzz:AuthorizationService";
    static const char jws[] = "eyJhbGciOiJSUzI1NiJ9.e30";
    gds_buf u = {(uint8_t *)(uintptr_t)uri, sizeof(uri) - 1};
    gds_buf j = {(uint8_t *)(uintptr_t)jws, sizeof(jws) - 1};
    if(r == GDS_OK)
        r = gds_sigp_encode_token(GDS_SIGP_TOKEN_CHAIN, &u, &m);
    if(r == GDS_OK)
        r = put("fuzz_signer_msg", "req-token-chain.bin", SIDE_REQUEST, 1, m.data, m.len);
    gds_buf_free(&m);
    if(r == GDS_OK)
        r = gds_sigp_encode_token(GDS_SIGP_TOKEN_SIGN, &j, &m);
    if(r == GDS_OK)
        r = put("fuzz_signer_msg", "req-token-sign.bin", SIDE_REQUEST, 1, m.data, m.len);
    gds_buf_free(&m);
    if(r == GDS_OK)
        r = put_reply("reply-token-chain-ok.bin", GDS_SIGP_TOKEN_CHAIN, GDS_OK, NULL, &der);
    if(r == GDS_OK)
        r = put_reply("reply-token-sign-ok.bin", GDS_SIGP_TOKEN_SIGN, GDS_OK, NULL, &der);
    if(r == GDS_OK)
        r = gds_sigp_encode_request(GDS_SIGP_EXPORT_KEYS, NULL, &m);
    if(r == GDS_OK)
        r = put("fuzz_signer_msg", "req-export-keys.bin", SIDE_REQUEST, 1, m.data, m.len);
    gds_buf_free(&m);
    if(r == GDS_OK)
        r = put_reply("reply-export-keys-ok.bin", GDS_SIGP_EXPORT_KEYS, GDS_OK, NULL, &der);
    if(r == GDS_OK)
        r = put_reply("reply-export-keys-denied.bin", GDS_SIGP_EXPORT_KEYS, GDS_EDENIED, NULL,
                      NULL);
    return r;
}

/* ---- fuzz_trustlist ---- */

static gds_status seeds_trustlist(void) {
    const UA_DataType *t = &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE];
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    gds_status r = put_ua("fuzz_trustlist", "empty.bin", &tl, t);
    UA_ByteString certs[2] = {UA_BYTESTRING("\x30\x82\x01\x00 cert one"),
                              UA_BYTESTRING("\x30\x82\x01\x00 cert two")};
    UA_ByteString crl = UA_BYTESTRING("\x30\x82\x00\x10 crl");
    tl.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    tl.trustedCertificates = certs;
    tl.trustedCertificatesSize = 2;
    tl.trustedCrls = &crl;
    tl.trustedCrlsSize = 1;
    tl.issuerCertificates = certs;
    tl.issuerCertificatesSize = 1;
    if(r == GDS_OK)
        r = put_ua("fuzz_trustlist", "all.bin", &tl, t);
    return r;
}

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "usage: %s <corpus dir>\n", argv[0]);
        return 2;
    }
    root = argv[1];
    gds_status r = seeds_csr();
    if(r == GDS_OK)
        r = seeds_app_record();
    if(r == GDS_OK)
        r = seeds_signer_msg();
    if(r == GDS_OK)
        r = seeds_trustlist();
    return r == GDS_OK ? 0 : 1;
}
