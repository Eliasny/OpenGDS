/* OpenGDS libgdsclient - an administrator's session to a GDS (gdsc_connect.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "gdsc_connect.h"

#include <open62541/client_config_default.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <openssl/crypto.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/limits.h"
#include "common/banned.h"

#define DEFAULT_TIMEOUT_MS 10000
#define MAX_PASSWORD 1024
#define CLIENT_URI "urn:opengds:gdsadm"

static UA_ByteString *borrow_list(const gds_buf *items, size_t n) {
    UA_ByteString *l = calloc(n ? n : 1, sizeof(UA_ByteString));
    if(!l)
        return NULL;
    for(size_t i = 0; i < n; i++) {
        l[i].data = items[i].data;
        l[i].length = items[i].len;
    }
    return l;
}

/* A self-signed certificate for this channel only. */
static UA_StatusCode channel_cert(UA_ByteString *cert, UA_ByteString *key) {
    UA_String subject[] = {UA_STRING_STATIC("CN=gdsadm"), UA_STRING_STATIC("O=OpenGDS")};
    UA_String san[] = {UA_STRING_STATIC("URI:" CLIENT_URI), UA_STRING_STATIC("DNS:localhost")};
    return UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER, NULL,
                                key, cert);
}

static UA_Client *client_new(const gdsc_admin_cfg *ac) {
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(UA_LOGLEVEL_ERROR);
    if(!cfg.logging || UA_ClientConfig_setDefault(&cfg) != UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_ByteString *tl = borrow_list(ac->trust, ac->trustN);
    UA_ByteString *rl = borrow_list(ac->crls, ac->crlN);
    UA_StatusCode r = tl && rl ? channel_cert(&cert, &key) : UA_STATUSCODE_BADOUTOFMEMORY;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_ClientConfig_setDefaultEncryption(&cfg, cert, key, tl, ac->trustN, rl, ac->crlN);
    free(tl);
    free(rl);
    UA_ByteString_clear(&cert);
    if(key.data)
        OPENSSL_cleanse(key.data, key.length);
    UA_ByteString_clear(&key);
    if(r == UA_STATUSCODE_GOOD) {
        cfg.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        cfg.timeout = ac->timeoutMs ? ac->timeoutMs : DEFAULT_TIMEOUT_MS;
        UA_String_clear(&cfg.clientDescription.applicationUri);
        cfg.clientDescription.applicationUri = UA_STRING_ALLOC(CLIENT_URI);
        if(!cfg.clientDescription.applicationUri.data)
            r = UA_STATUSCODE_BADOUTOFMEMORY;
    }
    if(r != UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    UA_Client *c = UA_Client_newWithConfig(&cfg);
    if(!c)
        UA_ClientConfig_clear(&cfg);
    return c;
}

UA_StatusCode gdsc_admin_connect(const gdsc_admin_cfg *ac, UA_Client **out) {
    *out = NULL;
    if(!ac || !ac->url || !ac->user || !ac->password || !ac->password->len ||
       ac->password->len > MAX_PASSWORD || ac->trustN == 0 || !ac->trust ||
       (ac->crlN && !ac->crls))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Client *c = client_new(ac);
    if(!c)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    /* open62541 takes a C string for the password */
    char pw[MAX_PASSWORD + 1];
    memcpy(pw, ac->password->data, ac->password->len);
    pw[ac->password->len] = '\0';
    UA_StatusCode r = UA_Client_connectUsername(c, ac->url, ac->user, pw);
    OPENSSL_cleanse(pw, sizeof(pw));
    if(r != UA_STATUSCODE_GOOD) {
        UA_Client_delete(c);
        return r;
    }
    *out = c;
    return UA_STATUSCODE_GOOD;
}

void gdsc_admin_close(UA_Client *c) {
    if(!c)
        return;
    (void)UA_Client_disconnect(c);
    UA_Client_delete(c);
}
