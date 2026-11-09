/* OpenGDS Auditor - "gdsaudit discover" (discover.h).
 *
 * Every reply comes from a target that may be hostile: array sizes are
 * bounded, text is cleaned and cut before it is printed, and only opc.tcp
 * DiscoveryUrls are followed, at most GA_DISCOVER_MAX_URLS of them.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "discover.h"

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/plugin/log_stdout.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/buf.h"
#include "common/limits.h"
#include "x509util.h"

#include "common/banned.h"

typedef struct {
    const char *url;
    const char *certsDir;
    bool network;
    /* URLs already asked for endpoints (--url first) */
    char *seen[GA_DISCOVER_MAX_URLS + 1];
    size_t nSeen;
    size_t endpoints;
} discover;

static int usage(void) {
    fprintf(stderr, "usage: gdsaudit discover --url URL [--network] [--certs DIR]\n");
    return 2;
}

/* Print target text: tabs and control characters become spaces, cut at
 * GA_DISCOVER_MAX_TEXT bytes on a UTF-8 character boundary. */
static void put_text(const UA_String *s) {
    size_t len = s->length;
    if(len > GA_DISCOVER_MAX_TEXT) {
        len = GA_DISCOVER_MAX_TEXT;
        while(len > 0 && (s->data[len] & 0xC0) == 0x80)
            len--;
    }
    for(size_t i = 0; i < len; i++) {
        unsigned char c = s->data[i];
        putchar(c < 0x20 || c == 0x7f ? ' ' : c);
    }
}

static void put_cstr(const char *s) {
    UA_String u = {strlen(s), (UA_Byte *)(uintptr_t)s};
    put_text(&u);
}

static UA_Client *new_client(void) {
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(UA_LOGLEVEL_FATAL);
    if(!cfg.logging || UA_ClientConfig_setDefault(&cfg) != UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    cfg.timeout = 5000; /* ms per request */
    UA_Client *c = UA_Client_newWithConfig(&cfg);
    if(!c)
        UA_ClientConfig_clear(&cfg);
    return c;
}

static void put_error(const char *step, const char *url, UA_StatusCode st) {
    printf("error\t%s\t", step);
    put_cstr(url);
    printf("\t%s\n", UA_StatusCode_name(st));
}

static const char *app_type(UA_ApplicationType t) {
    switch(t) {
    case UA_APPLICATIONTYPE_SERVER:
        return "server";
    case UA_APPLICATIONTYPE_CLIENT:
        return "client";
    case UA_APPLICATIONTYPE_CLIENTANDSERVER:
        return "clientandserver";
    case UA_APPLICATIONTYPE_DISCOVERYSERVER:
        return "discoveryserver";
    case __UA_APPLICATIONTYPE_FORCE32BIT:
    default:
        return "unknown";
    }
}

static const char *mode_name(UA_MessageSecurityMode m) {
    switch(m) {
    case UA_MESSAGESECURITYMODE_NONE:
        return "none";
    case UA_MESSAGESECURITYMODE_SIGN:
        return "sign";
    case UA_MESSAGESECURITYMODE_SIGNANDENCRYPT:
        return "signandencrypt";
    case UA_MESSAGESECURITYMODE_INVALID:
    case __UA_MESSAGESECURITYMODE_FORCE32BIT:
    default:
        return "invalid";
    }
}

static const char *token_name(UA_UserTokenType t) {
    switch(t) {
    case UA_USERTOKENTYPE_ANONYMOUS:
        return "anonymous";
    case UA_USERTOKENTYPE_USERNAME:
        return "username";
    case UA_USERTOKENTYPE_CERTIFICATE:
        return "certificate";
    case UA_USERTOKENTYPE_ISSUEDTOKEN:
        return "issuedtoken";
    case __UA_USERTOKENTYPE_FORCE32BIT:
    default:
        return "unknown";
    }
}

static bool is_opc_tcp(const UA_String *s) {
    static const char prefix[] = "opc.tcp://";
    return s->length > sizeof(prefix) - 1 && s->length <= GA_DISCOVER_MAX_TEXT &&
           memcmp(s->data, prefix, sizeof(prefix) - 1) == 0 &&
           memchr(s->data, '\0', s->length) == NULL;
}

/* Remember url; false if already asked or the list is full. */
static bool mark_seen(discover *d, const char *url) {
    for(size_t i = 0; i < d->nSeen; i++)
        if(strcmp(d->seen[i], url) == 0)
            return false;
    if(d->nSeen > GA_DISCOVER_MAX_URLS)
        return false;
    char *copy = strdup(url);
    if(!copy)
        return false;
    d->seen[d->nSeen++] = copy;
    return true;
}

/* The certificate's file name under --certs ("" if none was written). */
static void save_cert(const discover *d, const gds_buf *der, const char *thumb, char *file,
                      size_t fileLen) {
    file[0] = '\0';
    if(!d->certsDir || !thumb[0])
        return;
    if(gds_mkdirs(d->certsDir, 0700) != GDS_OK ||
       gds_path(file, fileLen, "%s/%s.der", d->certsDir, thumb) != GDS_OK ||
       gds_file_write_atomic(file, der->data, der->len, 0644) != GDS_OK) {
        fprintf(stderr, "gdsaudit discover: cannot write %s/%s.der\n", d->certsDir, thumb);
        file[0] = '\0';
    }
}

static void put_endpoint(discover *d, const UA_EndpointDescription *ep) {
    char thumb[X509_THUMBPRINT_LEN] = "";
    char desc[512] = "";
    char file[4096] = "";
    const UA_ByteString *cert = &ep->serverCertificate;
    if(cert->length > 0 && cert->length <= GDS_MAX_CERT_SIZE) {
        gds_buf der = {cert->data, cert->length}; /* borrowed */
        if(x509_thumbprint(&der, thumb) != GDS_OK)
            thumb[0] = '\0';
        else {
            x509_describe(&der, desc, sizeof(desc));
            save_cert(d, &der, thumb, file, sizeof(file));
        }
    }
    printf("endpoint\t");
    put_text(&ep->endpointUrl);
    putchar('\t');
    put_text(&ep->securityPolicyUri);
    printf("\t%s\t%u\t%s\t", mode_name(ep->securityMode), (unsigned)ep->securityLevel, thumb);
    size_t nTokens = ep->userIdentityTokensSize;
    if(nTokens > GA_DISCOVER_MAX_ITEMS)
        nTokens = GA_DISCOVER_MAX_ITEMS;
    for(size_t i = 0; i < nTokens; i++)
        printf("%s%s", i ? "," : "", token_name(ep->userIdentityTokens[i].tokenType));
    putchar('\t');
    put_cstr(file);
    putchar('\t');
    put_cstr(desc);
    putchar('\n');
    d->endpoints++;
}

static void get_endpoints(discover *d, const char *url) {
    UA_Client *c = new_client();
    if(!c) {
        put_error("getendpoints", url, UA_STATUSCODE_BADOUTOFMEMORY);
        return;
    }
    size_t n = 0;
    UA_EndpointDescription *eps = NULL;
    UA_StatusCode st = UA_Client_getEndpoints(c, url, &n, &eps);
    if(st != UA_STATUSCODE_GOOD)
        put_error("getendpoints", url, st);
    else
        for(size_t i = 0; i < n && i < GA_DISCOVER_MAX_ITEMS; i++)
            put_endpoint(d, &eps[i]);
    UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    UA_Client_delete(c);
}

static void put_server(const UA_ApplicationDescription *app) {
    printf("server\t");
    put_text(&app->applicationUri);
    putchar('\t');
    put_text(&app->applicationName.text);
    printf("\t%s\t", app_type(app->applicationType));
    size_t nUrls = app->discoveryUrlsSize;
    if(nUrls > GA_DISCOVER_MAX_ITEMS)
        nUrls = GA_DISCOVER_MAX_ITEMS;
    for(size_t j = 0; j < nUrls; j++) {
        if(j)
            putchar(' ');
        put_text(&app->discoveryUrls[j]);
    }
    putchar('\n');
}

/* FindServers on --url; returns the opc.tcp DiscoveryUrls to follow. */
static void find_servers(discover *d, char **follow, size_t *nFollow) {
    UA_Client *c = new_client();
    if(!c) {
        put_error("findservers", d->url, UA_STATUSCODE_BADOUTOFMEMORY);
        return;
    }
    size_t n = 0;
    UA_ApplicationDescription *apps = NULL;
    UA_StatusCode st = UA_Client_findServers(c, d->url, 0, NULL, 0, NULL, &n, &apps);
    if(st != UA_STATUSCODE_GOOD)
        put_error("findservers", d->url, st);
    for(size_t i = 0; st == UA_STATUSCODE_GOOD && i < n && i < GA_DISCOVER_MAX_ITEMS; i++) {
        put_server(&apps[i]);
        for(size_t j = 0; j < apps[i].discoveryUrlsSize && j < GA_DISCOVER_MAX_ITEMS; j++) {
            const UA_String *u = &apps[i].discoveryUrls[j];
            if(*nFollow < GA_DISCOVER_MAX_URLS && is_opc_tcp(u)) {
                char *s = malloc(u->length + 1);
                if(!s)
                    continue;
                memcpy(s, u->data, u->length);
                s[u->length] = '\0';
                follow[(*nFollow)++] = s;
            }
        }
    }
    UA_Array_delete(apps, n, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
    UA_Client_delete(c);
}

static void find_on_network(const discover *d) {
    UA_Client *c = new_client();
    if(!c) {
        put_error("network", d->url, UA_STATUSCODE_BADOUTOFMEMORY);
        return;
    }
    size_t n = 0;
    UA_ServerOnNetwork *son = NULL;
    UA_StatusCode st = UA_Client_findServersOnNetwork(c, d->url, 0, GA_DISCOVER_MAX_ITEMS, 0,
                                                      NULL, &n, &son);
    if(st != UA_STATUSCODE_GOOD)
        put_error("network", d->url, st);
    for(size_t i = 0; st == UA_STATUSCODE_GOOD && i < n && i < GA_DISCOVER_MAX_ITEMS; i++) {
        printf("network\t%u\t", (unsigned)son[i].recordId);
        put_text(&son[i].serverName);
        putchar('\t');
        put_text(&son[i].discoveryUrl);
        putchar('\t');
        size_t nCaps = son[i].serverCapabilitiesSize;
        for(size_t j = 0; j < nCaps && j < GA_DISCOVER_MAX_ITEMS; j++) {
            if(j)
                putchar(',');
            put_text(&son[i].serverCapabilities[j]);
        }
        putchar('\n');
    }
    UA_Array_delete(son, n, &UA_TYPES[UA_TYPES_SERVERONNETWORK]);
    UA_Client_delete(c);
}

static bool parse_args(int argc, char **argv, discover *d) {
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--url") == 0 && i + 1 < argc)
            d->url = argv[++i];
        else if(strcmp(argv[i], "--certs") == 0 && i + 1 < argc)
            d->certsDir = argv[++i];
        else if(strcmp(argv[i], "--network") == 0)
            d->network = true;
        else
            return false;
    }
    return d->url && strncmp(d->url, "opc.tcp://", 10) == 0 &&
           strlen(d->url) <= GA_DISCOVER_MAX_TEXT;
}

int discover_main(int argc, char **argv) {
    discover d;
    memset(&d, 0, sizeof(d));
    if(!parse_args(argc, argv, &d))
        return usage();
    char *follow[GA_DISCOVER_MAX_URLS];
    size_t nFollow = 0;
    find_servers(&d, follow, &nFollow);
    if(d.network)
        find_on_network(&d);
    if(mark_seen(&d, d.url))
        get_endpoints(&d, d.url);
    for(size_t i = 0; i < nFollow; i++) {
        if(mark_seen(&d, follow[i]))
            get_endpoints(&d, follow[i]);
        free(follow[i]);
    }
    for(size_t i = 0; i < d.nSeen; i++)
        free(d.seen[i]);
    fflush(stdout);
    return d.endpoints > 0 ? 0 : 1;
}
