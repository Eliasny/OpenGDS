/* OpenGDS fuzz target: the CSR checks of the CA (docs/architecture.md,
 * fuzz_csr.c). The input is a raw DER CSR, given to the built-in OpenSSL
 * backend through gds_ca_sign_csr, as opengds-signer does: exact DER, proof
 * of possession, key type and size. A CSR it accepts must come out as a
 * certificate that parses and carries the CSR's public key.
 * The CA is created once, in a private temporary directory.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <string.h>

#include "ca.h"
#include "common/limits.h"
#include "fuzz.h"
#include "common/banned.h"

static gds_ca *ca;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc, (void)argv;
    char dir[GDS_MAX_PATH], caDir[GDS_MAX_PATH];
    static gds_buf pass;
    size_t passLen = 0;
    const uint8_t *pw = fuzz_passphrase(&passLen);
    pass.data = (uint8_t *)(uintptr_t)pw;
    pass.len = passLen;
    gds_status r = fuzz_tmpdir(dir, sizeof(dir));
    if(r == GDS_OK)
        r = gds_path(caDir, sizeof(caDir), "%s/ca", dir);
    if(r == GDS_OK) {
        gds_ca_config cfg;
        gds_ca_config_init(&cfg);
        cfg.dir = caDir;
        cfg.caKeyBits = 2048;
        cfg.organization = "OpenGDS fuzz";
        cfg.keyPassphrase = &pass;
        r = gds_ca_openssl_open(&cfg, &ca);
    }
    if(r != GDS_OK) {
        fprintf(stderr, "fuzz_csr: CA fixture: %s\n", gds_status_name(r));
        return 1;
    }
    return 0;
}

/* The issued certificate parses and holds the CSR's key. */
static void check_issued(const uint8_t *data, size_t size, const gds_ca_issued *out) {
    GDS_ASSERT(out->der.len > 0 && out->der.len <= GDS_MAX_CERT_SIZE);
    GDS_ASSERT(out->serial.len > 0 && out->notAfter > out->notBefore);
    const unsigned char *p = out->der.data;
    X509 *x = d2i_X509(NULL, &p, (long)out->der.len);
    GDS_ASSERT(x && p == out->der.data + out->der.len);
    p = data;
    X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)size);
    GDS_ASSERT(req);
    EVP_PKEY *a = X509_get0_pubkey(x);
    EVP_PKEY *b = X509_REQ_get0_pubkey(req);
    GDS_ASSERT(a && b && EVP_PKEY_eq(a, b) == 1);
    X509_REQ_free(req);
    X509_free(x);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if(size > GDS_MAX_CSR_SIZE + 1)
        return 0; /* the limit itself is checked; far above it is not interesting */
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "Fuzz Server");
    UA_String url = UA_STRING("opc.tcp://fuzz.example.com:4840");
    rec.applicationUri = UA_STRING("urn:opengds:fuzz:server");
    rec.applicationType = UA_APPLICATIONTYPE_SERVER;
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    rec.discoveryUrls = &url;
    rec.discoveryUrlsSize = 1;
    UA_Guid reqId = UA_GUID_NULL;
    gds_ca_subject subj = {&reqId, &rec, 615, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE};
    gds_buf csr = {(uint8_t *)(uintptr_t)data, size};
    gds_ca_issued out;
    memset(&out, 0, sizeof(out));
    if(gds_ca_sign_csr(ca, &subj, &csr, &out) == GDS_OK)
        check_issued(data, size, &out);
    gds_ca_issued_clear(&out);
    return 0;
}
