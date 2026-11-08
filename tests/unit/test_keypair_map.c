/* OpenGDS unit test: the in-memory secrets of StartNewKeyPairRequest
 * (gds_keypair.c). The password lives until the key exists, the key is
 * handed over once, and a missing entry is GDS_ENOTFOUND.
 * SPDX-License-Identifier: MPL-2.0 */
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "common/ids.h"
#include "gds_internal.h"
#include "common/banned.h"

/* Password until the key exists, then the key once. */
static void test_lifecycle(gds_server *s) {
    UA_Guid id, other;
    CHECK(gds_guid_random(&id) == GDS_OK && gds_guid_random(&other) == GDS_OK);
    UA_String pw = UA_STRING("secret");
    CHECK(gds_kp_add(s, &id, GDS_CA_KEY_PEM, &pw) == GDS_OK);

    gds_ca_key_format f = GDS_CA_KEY_PFX;
    gds_buf got = {0}, key = {0};
    CHECK(gds_kp_password(s, &other, &f, &got) == GDS_ENOTFOUND);
    CHECK(gds_kp_take_key(s, &id, &key) == GDS_ENOTFOUND); /* not generated yet */
    CHECK(gds_kp_password(s, &id, &f, &got) == GDS_OK && f == GDS_CA_KEY_PEM);
    CHECK(got.len == 6 && memcmp(got.data, "secret", 6) == 0);
    gds_buf_free_secret(&got);

    gds_buf gen = {0};
    CHECK(gds_buf_dup("KEY", 3, &gen) == GDS_OK);
    CHECK(gds_kp_set_key(s, &id, &gen) == GDS_OK && gen.data == NULL);
    CHECK(gds_kp_password(s, &id, &f, &got) == GDS_ENOTFOUND); /* password gone */
    CHECK(gds_kp_set_key(s, &id, &gen) == GDS_ENOTFOUND);
    CHECK(gds_kp_take_key(s, &id, &key) == GDS_OK && key.len == 3);
    gds_buf_free_secret(&key);
    CHECK(gds_kp_take_key(s, &id, &key) == GDS_ENOTFOUND); /* once only */
}

/* The table is bounded. */
static void test_full(gds_server *s) {
    UA_Guid other;
    UA_String none = UA_STRING_NULL;
    gds_ca_key_format f = GDS_CA_KEY_PEM;
    gds_buf got = {0};
    CHECK(gds_guid_random(&other) == GDS_OK);
    UA_Guid ids[GDS_MAX_KEYPAIR_REQUESTS];
    for(size_t i = 0; i < GDS_MAX_KEYPAIR_REQUESTS; i++) {
        CHECK(gds_guid_random(&ids[i]) == GDS_OK);
        CHECK(gds_kp_add(s, &ids[i], GDS_CA_KEY_PFX, &none) == GDS_OK);
    }
    CHECK(gds_kp_add(s, &other, GDS_CA_KEY_PFX, &none) == GDS_ETOOBIG);
    gds_kp_drop(s, &ids[0]);
    CHECK(gds_kp_add(s, &other, GDS_CA_KEY_PFX, &none) == GDS_OK);
    CHECK(gds_kp_password(s, &other, &f, &got) == GDS_OK && got.len == 0 && f == GDS_CA_KEY_PFX);
}

int main(void) {
    gds_server *s = calloc(1, sizeof(*s));
    if(!CHECK(s != NULL))
        return CHECK_DONE();
    pthread_mutex_init(&s->kpLock, NULL);
    test_lifecycle(s);
    test_full(s);
    gds_kp_free(s);
    pthread_mutex_destroy(&s->kpLock);
    free(s);
    return CHECK_DONE();
}
