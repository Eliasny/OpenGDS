/* OpenGDS Auditor client profile - the probe server. See probe.h.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "probe.h"

#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

#include <stdio.h>
#include <string.h>

#include "common/limits.h"
#include "test_ca.h"
#include "common/banned.h"

static struct {
    UA_Server *server;
    bool connected;
    gds_buf clientCert;
    gds_buf lastChain; /* as sent in OpenSecureChannel (the server keeps only the leaf) */
    char url[64];
    UA_StatusCode (*origActivate)(UA_Server *, UA_AccessControl *, const UA_EndpointDescription *,
                                  const UA_ByteString *, const UA_NodeId *,
                                  const UA_ExtensionObject *, void **);
} P;

const char *probe_url(void) { return P.url; }
bool probe_connected(void) { return P.connected; }
const gds_buf *probe_client_cert(void) { return &P.clientCert; }

/* AcceptAll, but remember the certificate chain the client sent */
static UA_StatusCode probe_verify(UA_CertificateGroup *cg, const UA_ByteString *chain) {
    (void)cg;
    gds_buf_free(&P.lastChain);
    if(chain && chain->length && chain->length <= GDS_MAX_CERT_SIZE * GDS_MAX_CHAIN_LEN &&
       gds_buf_dup(chain->data, chain->length, &P.lastChain) != GDS_OK)
        P.lastChain.len = 0;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode probe_activate(UA_Server *server, UA_AccessControl *ac,
                                    const UA_EndpointDescription *ep, const UA_ByteString *cert,
                                    const UA_NodeId *sessionId, const UA_ExtensionObject *token,
                                    void **sessionContext) {
    UA_StatusCode r = P.origActivate(server, ac, ep, cert, sessionId, token, sessionContext);
    if(r == UA_STATUSCODE_GOOD && !P.connected) {
        P.connected = true;
        /* the full chain sent in OpenSecureChannel when it starts with
         * this certificate; else the certificate alone */
        gds_buf src = P.lastChain;
        if(cert && cert->length &&
           !(P.lastChain.len > cert->length &&
             memcmp(P.lastChain.data, cert->data, cert->length) == 0))
            src = (gds_buf){cert->data, cert->length};
        if(src.len && src.len <= GDS_MAX_CERT_SIZE * GDS_MAX_CHAIN_LEN &&
           gds_buf_dup(src.data, src.len, &P.clientCert) != GDS_OK)
            P.clientCert.len = 0;
    }
    return r;
}

static UA_StatusCode configure(UA_ServerConfig *c, long port, const gds_buf *cert,
                               const gds_buf *key) {
    UA_ByteString uc = {cert->len, cert->data}, uk = {key->len, key->data};
    UA_StatusCode r = UA_ServerConfig_setDefaultWithSecureSecurityPolicies(
        c, (UA_UInt16)port, &uc, &uk, NULL, 0, NULL, 0, NULL, 0);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Array_delete(c->serverUrls, c->serverUrlsSize, &UA_TYPES[UA_TYPES_STRING]);
    c->serverUrls = UA_String_new();
    if(!c->serverUrls)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    *c->serverUrls = UA_STRING_ALLOC(P.url);
    c->serverUrlsSize = 1;
    UA_String_clear(&c->applicationDescription.applicationUri);
    c->applicationDescription.applicationUri = UA_STRING_ALLOC(PROBE_APP_URI);
    c->secureChannelPKI.clear(&c->secureChannelPKI);
    UA_CertificateGroup_AcceptAll(&c->secureChannelPKI);
    c->secureChannelPKI.verifyCertificate = probe_verify;
    c->sessionPKI.clear(&c->sessionPKI);
    UA_CertificateGroup_AcceptAll(&c->sessionPKI);
    c->accessControl.clear(&c->accessControl);
    if((r = UA_AccessControl_default(c, true, NULL, 0, NULL)) != UA_STATUSCODE_GOOD)
        return r;
    P.origActivate = c->accessControl.activateSession;
    c->accessControl.activateSession = probe_activate;
    return UA_STATUSCODE_GOOD;
}

gds_status probe_start(long port, fg_ca_id issuer) {
    probe_stop();
    const testca_t *ca = fg_ca(issuer);
    if(!ca)
        return GDS_EINVAL;
    /* 127.0.0.1 as the host: the identity names it (DNS and the URL agree) */
    if(gds_path(P.url, sizeof(P.url), "opc.tcp://localhost:%ld", port) != GDS_OK)
        return GDS_EINVAL;
    gds_buf cert = {0}, key = {0};
    gds_status s = testca_issue(ca, "OpenGDS Auditor TEST probe server", PROBE_APP_URI,
                                "localhost", 1, &cert, &key);
    if(s != GDS_OK)
        return s;
    s = probe_start_identity(port, &cert, &key);
    gds_buf_free(&cert);
    gds_buf_free_secret(&key);
    return s;
}

gds_status probe_start_identity(long port, const gds_buf *cert, const gds_buf *key) {
    probe_stop();
    if(gds_path(P.url, sizeof(P.url), "opc.tcp://localhost:%ld", port) != GDS_OK)
        return GDS_EINVAL;
    UA_ServerConfig sc;
    memset(&sc, 0, sizeof(sc));
    sc.logging = UA_Log_Stdout_new(UA_LOGLEVEL_FATAL);
    UA_StatusCode r = sc.logging ? configure(&sc, port, cert, key) : UA_STATUSCODE_BADOUTOFMEMORY;
    if(r != UA_STATUSCODE_GOOD) {
        UA_ServerConfig_clear(&sc);
        fprintf(stderr, "probe server config: %s\n", UA_StatusCode_name(r));
        return GDS_EREMOTE;
    }
    fflush(stdout); /* the nodeset autoloader prints to stdout: keep it off TAP */
    P.server = fg_new_server_quietly(&sc);
    if(!P.server)
        return GDS_ENOMEM;
    if((r = UA_Server_run_startup(P.server)) != UA_STATUSCODE_GOOD) {
        probe_stop();
        fprintf(stderr, "probe server: %s\n", UA_StatusCode_name(r));
        return GDS_EREMOTE;
    }
    return GDS_OK;
}

void probe_iterate(void) {
    if(P.server)
        (void)UA_Server_run_iterate(P.server, false);
}

void probe_stop(void) {
    if(P.server) {
        (void)UA_Server_run_shutdown(P.server);
        UA_Server_delete(P.server);
        P.server = NULL;
    }
    gds_buf_free(&P.clientCert);
    gds_buf_free(&P.lastChain);
    P.connected = false;
}
