/* OpenGDS - the audit chain hash (store.h, issue #18).
 * SPDX-License-Identifier: MPL-2.0 */
#include <openssl/evp.h>

#include "store.h"
#include "common/banned.h"

static void be64(int64_t v, uint8_t out[8]) {
    uint64_t u = (uint64_t)v;
    for(int i = 7; i >= 0; i--) {
        out[i] = (uint8_t)(u & 0xffu);
        u >>= 8;
    }
}

gds_status gds_audit_hash(const uint8_t prev[GDS_AUDIT_HASH], int64_t seq, int64_t time,
                          const gds_buf *body, uint8_t out[GDS_AUDIT_HASH]) {
    uint8_t s8[8], t8[8];
    be64(seq, s8);
    be64(time, t8);
    unsigned int len = 0;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    bool ok = c && EVP_DigestInit_ex(c, EVP_sha256(), NULL) == 1 &&
              EVP_DigestUpdate(c, prev, GDS_AUDIT_HASH) == 1 &&
              EVP_DigestUpdate(c, s8, sizeof(s8)) == 1 && EVP_DigestUpdate(c, t8, sizeof(t8)) == 1 &&
              (body->len == 0 || EVP_DigestUpdate(c, body->data, body->len) == 1) &&
              EVP_DigestFinal_ex(c, out, &len) == 1 && len == GDS_AUDIT_HASH;
    EVP_MD_CTX_free(c);
    return ok ? GDS_OK : GDS_ECRYPTO;
}
