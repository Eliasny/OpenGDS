/* OpenGDS fuzz target: the opengdsd configuration parser
 * (docs/architecture.md, fuzz_config.c; src/daemon/config.h). A text it
 * accepts must give a configuration that keeps the documented rules:
 * every value NUL-terminated inside its field, required keys present,
 * paths absolute, at most one way to reach the signer.
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include "config.h"
#include "fuzz.h"
#include "common/banned.h"

/* Text fields: terminated inside the field, no control characters. */
static bool str_ok(const char *s, size_t size, bool required) {
    size_t n = strnlen(s, size);
    if(n == size || (required && n == 0))
        return false;
    for(size_t i = 0; i < n; i++)
        if((unsigned char)s[i] < 0x20 || (unsigned char)s[i] == 0x7f)
            return false;
    return true;
}

static bool path_ok(const char *s, size_t size, bool required) {
    return str_ok(s, size, required) && (s[0] == '\0' || s[0] == '/');
}

#define STR_OK(c, m, req) str_ok((c)->m, sizeof((c)->m), req)
#define PATH_OK(c, m, req) path_ok((c)->m, sizeof((c)->m), req)

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc, (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    gdsd_config c;
    unsigned line = 0;
    if(gdsd_config_parse((const char *)data, size, &c, &line) != GDS_OK)
        return 0;
    GDS_ASSERT(line == 0);
    GDS_ASSERT(STR_OK(&c, applicationUri, true) && STR_OK(&c, applicationName, true) &&
               STR_OK(&c, productUri, true) && STR_OK(&c, hostname, false) &&
               STR_OK(&c, organization, false));
    GDS_ASSERT(PATH_OK(&c, dataDir, true) && PATH_OK(&c, usersFile, true) &&
               PATH_OK(&c, caDir, true) && PATH_OK(&c, signer, false) &&
               PATH_OK(&c, signerSocket, false) && PATH_OK(&c, caPassphraseFile, false));
    GDS_ASSERT(!(c.signer[0] && c.signerSocket[0]));
    return 0;
}
