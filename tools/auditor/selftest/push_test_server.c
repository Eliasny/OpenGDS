/* OpenGDS Auditor self-test target: PUSH test server
 * SPDX-License-Identifier: MPL-2.0
 *
 * A known-good OPC UA server that a GDS (CertificateManager) manages with
 * Part 12 PushManagement (OPC 10000-12 §7.7, §7.10). TEST TARGET, NOT A
 * PRODUCT: it exists so the Auditor's server profile has a reference to
 * pass against (and, from AT1, --break mutants to fail against).
 *   - ServerConfiguration: CreateSigningRequest and GetRejectedList from
 *     open62541's push support; UpdateCertificate, ApplyChanges and
 *     CancelChanges from push_mgmt.c (spec transaction rules)
 *   - DefaultApplicationGroup TrustList: the FileType methods and
 *     OpenWithMasks/CloseAndUpdate from push_mgmt.c; AddCertificate and
 *     RemoveCertificate from open62541
 * Added around the library:
 *   - SignAndEncrypt sessions only; None for GetEndpoints only
 *   - only SecurityAdmin may call ServerConfiguration/TrustList methods
 *     (an admin user, or the GDS's application certificate per Annex G.3)
 *   - an Annex F.1 directory PKI, so pushed state survives a restart
 *   - --break <mutant>: one deliberate fault, named in the Auditor's server
 *     catalogue (docs/auditor/server-profile.md, Mutant column). With a
 *     mutant active the server listens on 127.0.0.1 only.
 *
 * Usage:
 *   push_test_server --port 4841 --pki ./pki-push \
 *       [--trust ca.der]... [--crl ca.crl]... \
 *       [--admin user:password]... [--user user:password]...
 *       [--admin-cert gds.der]... [--no-anonymous] [--accept-keys] [--break <mutant>]
 *       [--list-mutants]
 */
#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <openssl/crypto.h>

#include "common/limits.h"
#include "common/safeint.h"
#include "push_mgmt.h"
#include "x509util.h"
#include "common/banned.h"

#define APP_URI "urn:opengds:test:pushserver"
#define MAX_ADMINS 16
#define MAX_CRED 64
#define MAX_SEED 16

static const char *brk = NULL; /* active --break mutant (push_mgmt.c), set while parsing */

/* ---------------- Admin policy (SecurityAdmin) ---------------- */

typedef struct {
    char user[MAX_CRED];
    char pass[MAX_CRED];
    bool admin; /* --admin: SecurityAdmin; --user: authenticated, no SecurityAdmin */
} AdminUser;

/* Process-wide configuration, written only while parsing arguments, before
 * the server starts. The server runs single-threaded (UA_Server_run on the
 * main thread), so the session list below needs no lock. */
static AdminUser adminUsers[MAX_ADMINS];
static size_t adminUsersSize = 0;
static char adminThumbs[MAX_ADMINS][X509_THUMBPRINT_LEN];
static size_t adminThumbsSize = 0;

/* Per-session admin flag, keyed by session id (test target: small list) */
typedef struct SessionFlag {
    UA_NodeId sessionId;
    UA_Boolean admin;
    UA_MessageSecurityMode mode;
    struct SessionFlag *next;
} SessionFlag;
static SessionFlag *sessionFlags = NULL;

static UA_Boolean isAdminSession(const UA_NodeId *sessionId) {
    for(SessionFlag *s = sessionFlags; s; s = s->next)
        if(UA_NodeId_equal(&s->sessionId, sessionId))
            return s->admin;
    return false;
}

static UA_MessageSecurityMode sessionMode(const UA_NodeId *sessionId) {
    for(SessionFlag *s = sessionFlags; s; s = s->next)
        if(UA_NodeId_equal(&s->sessionId, sessionId))
            return s->mode;
    return UA_MESSAGESECURITYMODE_INVALID;
}

/* The original callbacks of the default plugin, wrapped below */
static UA_StatusCode (*origActivate)(UA_Server *, UA_AccessControl *,
                                     const UA_EndpointDescription *, const UA_ByteString *,
                                     const UA_NodeId *, const UA_ExtensionObject *, void **);
static void (*origClose)(UA_Server *, UA_AccessControl *, const UA_NodeId *, void *);

static UA_StatusCode
activateSession( // NOLINT(readability-function-cognitive-complexity)
                UA_Server *server, UA_AccessControl *ac, const UA_EndpointDescription *ed,
                const UA_ByteString *remoteCert, const UA_NodeId *sessionId,
                const UA_ExtensionObject *token, void **sessionContext) {
    /* Only SignAndEncrypt sessions (OPC 10000-12 §7.4). Mutants open Sign
     * (sign-is-enough, sign-for-apply) or every mode (allow-none). */
    UA_MessageSecurityMode least = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    if(pm_breaking("sign-is-enough") || pm_breaking("sign-for-apply"))
        least = UA_MESSAGESECURITYMODE_SIGN;
    if(pm_breaking("allow-none"))
        least = UA_MESSAGESECURITYMODE_NONE;
    if(ed->securityMode < least)
        return UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;

    UA_StatusCode res =
        origActivate(server, ac, ed, remoteCert, sessionId, token, sessionContext);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Boolean admin = false;
    const char *why = "none";
    /* 1. Admin user name (password already verified by the default plugin) */
    if(token->encoding == UA_EXTENSIONOBJECT_DECODED &&
       token->content.decoded.type == &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]) {
        const UA_UserNameIdentityToken *t = token->content.decoded.data;
        if(pm_breaking("no-secadmin")) { /* any authenticated user */
            admin = true;
            why = "mutant no-secadmin";
        }
        for(size_t i = 0; i < adminUsersSize && !admin; i++) {
            if(adminUsers[i].admin && strlen(adminUsers[i].user) == t->userName.length &&
               memcmp(adminUsers[i].user, t->userName.data, t->userName.length) == 0) {
                admin = true;
                why = "admin user";
            }
        }
    }
    /* 2. Trusted GDS application certificate (Annex G.3) */
    if(!admin && remoteCert && remoteCert->length > 0) {
        char tp[X509_THUMBPRINT_LEN];
        gds_buf b = {remoteCert->data, remoteCert->length};
        if(x509_thumbprint(&b, tp) == GDS_OK) {
            for(size_t i = 0; i < adminThumbsSize && !admin; i++) {
                if(strcmp(tp, adminThumbs[i]) == 0) {
                    admin = true;
                    why = "GDS application certificate";
                }
            }
        }
    }

    if(!admin && pm_breaking("anon-admin") &&
       (token->encoding != UA_EXTENSIONOBJECT_DECODED ||
        token->content.decoded.type == &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN])) {
        admin = true;
        why = "mutant anon-admin";
    }
    if(!admin && pm_breaking("allow-none") && ed->securityMode == UA_MESSAGESECURITYMODE_NONE) {
        admin = true;
        why = "mutant allow-none";
    }

    SessionFlag *f = calloc(1, sizeof(SessionFlag));
    if(!f)
        return UA_STATUSCODE_BADOUTOFMEMORY; /* fail closed */
    if(UA_NodeId_copy(sessionId, &f->sessionId) != UA_STATUSCODE_GOOD) {
        free(f);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    f->admin = admin;
    f->mode = ed->securityMode;
    f->next = sessionFlags;
    sessionFlags = f;
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Session activated, SecurityAdmin=%s (%s)",
                admin ? "yes" : "no", why);
    return UA_STATUSCODE_GOOD;
}

static void closeSession(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sessionId,
                         void *sessionContext) {
    pm_session_closed(sessionId); /* its transaction ends with it (12 §7.10.2) */
    SessionFlag **pp = &sessionFlags;
    while(*pp) {
        if(UA_NodeId_equal(&(*pp)->sessionId, sessionId)) {
            SessionFlag *d = *pp;
            *pp = d->next;
            UA_NodeId_clear(&d->sessionId);
            free(d);
            break;
        }
        pp = &(*pp)->next;
    }
    origClose(server, ac, sessionId, sessionContext);
}

static UA_Boolean isProtectedObject(const UA_NodeId *objectId) {
    static const UA_UInt32 ids[] = {
        UA_NS0ID_SERVERCONFIGURATION,
        UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST,
        UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST,
        UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST,
    };
    if(objectId->namespaceIndex != 0 || objectId->identifierType != UA_NODEIDTYPE_NUMERIC)
        return false;
    for(size_t i = 0; i < GDS_ARRAY_SIZE(ids); i++)
        if(objectId->identifier.numeric == ids[i])
            return true;
    return false;
}

/* trustlist-read-any: reading the trust list needs no SecurityAdmin */
static UA_Boolean isReadMethod(const UA_NodeId *methodId) {
    static const UA_UInt32 ids[] = {
        UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPENWITHMASKS,
        UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_READ,
        UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSE,
    };
    if(methodId->namespaceIndex != 0 || methodId->identifierType != UA_NODEIDTYPE_NUMERIC)
        return false;
    for(size_t i = 0; i < GDS_ARRAY_SIZE(ids); i++)
        if(methodId->identifier.numeric == ids[i])
            return true;
    return false;
}

/* TransactionDiagnostics (12 §7.10.3) is for SecurityAdmin only */
static UA_Boolean isDiagnosticsNode(const UA_NodeId *n) {
    if(n->namespaceIndex != 0 || n->identifierType != UA_NODEIDTYPE_NUMERIC)
        return false;
    UA_UInt32 id = n->identifier.numeric;
    return id == UA_NS0ID_SERVERCONFIGURATION_TRANSACTIONDIAGNOSTICS ||
           (id >= UA_NS0ID_SERVERCONFIGURATION_TRANSACTIONDIAGNOSTICS_STARTTIME &&
            id <= UA_NS0ID_SERVERCONFIGURATION_TRANSACTIONDIAGNOSTICS_ERRORS);
}

static UA_Byte (*origAccessLevel)(UA_Server *, UA_AccessControl *, const UA_NodeId *, void *,
                                  const UA_NodeId *, void *);

static UA_Byte getUserAccessLevel(UA_Server *server, UA_AccessControl *ac,
                                  const UA_NodeId *sessionId, void *sessionContext,
                                  const UA_NodeId *nodeId, void *nodeContext) {
    if(isDiagnosticsNode(nodeId) && !isAdminSession(sessionId) && !pm_breaking("diag-public"))
        return 0;
    return origAccessLevel(server, ac, sessionId, sessionContext, nodeId, nodeContext);
}

static UA_Boolean
getUserExecutableOnObject(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sessionId,
                          void *sessionContext, const UA_NodeId *methodId, void *methodContext,
                          const UA_NodeId *objectId, void *objectContext) {
    (void)server; (void)ac; (void)sessionContext; (void)methodContext;
    (void)objectContext;
    if(pm_breaking("trustlist-read-any") && isReadMethod(methodId))
        return true;
    if(isProtectedObject(objectId) && !isAdminSession(sessionId)) {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                       "Rejected push method call from a non-admin session");
        return false;
    }
    return true;
}

/* ---------------- Own certificate (Annex F.1 store) ---------------- */

/* Each own certificate in own/certs/<name>.der has its key in
 * own/private/<name>.key. open62541's filestore writes the pair on
 * UpdateCertificate, also when the CSR kept the key (carried patch, see
 * docs/upstream/01-filestore-key-kept-csr.md). Load the newest pair, preferring
 * a CA-issued certificate over the initial self-signed one. */
static gds_status loadOwnFromStore(const char *pki, gds_buf *certOut, gds_buf *keyOut) {
    char dir[GDS_MAX_PATH];
    gds_status r;
    if((r = gds_path(dir, sizeof(dir), "%s/ApplCerts/own/certs", pki)) != GDS_OK)
        return r;
    DIR *d = opendir(dir);
    if(!d)
        return GDS_ENOTFOUND;
    struct dirent *e;
    gds_buf best = {0}, bestKey = {0};
    time_t bestTime = 0;
    bool bestIssued = false;
    while((e = readdir(d))) {
        size_t n = strlen(e->d_name);
        if(n < 5 || strcmp(e->d_name + n - 4, ".der") != 0)
            continue;
        char p[GDS_MAX_PATH], kp[GDS_MAX_PATH];
        struct stat st;
        gds_buf c = {0}, k = {0};
        if(gds_path(p, sizeof(p), "%s/%s", dir, e->d_name) != GDS_OK ||
           gds_path(kp, sizeof(kp), "%s/ApplCerts/own/private/%.*s.key", pki,
                    (int)(n - 4), e->d_name) != GDS_OK ||
           stat(p, &st) != 0 || gds_file_read(p, GDS_MAX_CERT_SIZE, &c) != GDS_OK)
            continue;
        if(gds_file_read(kp, GDS_MAX_KEY_SIZE, &k) != GDS_OK || !x509_key_matches(&c, &k)) {
            gds_buf_free(&c); /* no key with this name, or not its pair */
            gds_buf_free_secret(&k);
            continue;
        }
        bool issued = !x509_is_self_signed(&c);
        if((!issued && bestIssued) || (issued == bestIssued && best.data && st.st_mtime < bestTime)) {
            gds_buf_free(&c);
            gds_buf_free_secret(&k);
            continue;
        }
        gds_buf_free(&best);
        gds_buf_free_secret(&bestKey);
        best = c;
        bestKey = k;
        bestTime = st.st_mtime;
        bestIssued = issued;
    }
    closedir(d);
    if(!best.data)
        return GDS_ENOTFOUND;
    *certOut = best;
    *keyOut = bestKey;
    return GDS_OK;
}

/* Store the initial self-signed pair under one name in own/certs and
 * own/private, the layout the filestore uses */
static gds_status saveOwnToStore(const char *pki, const UA_ByteString *cert,
                                 const UA_ByteString *key) {
    char dir[GDS_MAX_PATH], path[GDS_MAX_PATH], tp[X509_THUMBPRINT_LEN];
    gds_buf c = {cert->data, cert->length};
    gds_status r;
    if((r = x509_thumbprint(&c, tp)) != GDS_OK ||
       (r = gds_path(dir, sizeof(dir), "%s/ApplCerts/own/private", pki)) != GDS_OK ||
       (r = gds_mkdirs(dir, 0700)) != GDS_OK ||
       (r = gds_path(path, sizeof(path), "%s/selfsigned[%s].key", dir, tp)) != GDS_OK ||
       (r = gds_file_write_atomic(path, key->data, key->length, 0600)) != GDS_OK)
        return r;
    if((r = gds_path(dir, sizeof(dir), "%s/ApplCerts/own/certs", pki)) != GDS_OK ||
       (r = gds_mkdirs(dir, 0700)) != GDS_OK ||
       (r = gds_path(path, sizeof(path), "%s/selfsigned[%s].der", dir, tp)) != GDS_OK)
        return r;
    return gds_file_write_atomic(path, c.data, c.len, 0644);
}

static gds_status addFileToStore(const char *pki, const char *sub, const char *src) {
    gds_buf b = {0};
    gds_status r = gds_file_read(src, GDS_MAX_CRL_SIZE, &b);
    if(r != GDS_OK) {
        fprintf(stderr, "cannot read %s: %s\n", src, gds_status_name(r));
        return r;
    }
    char dir[GDS_MAX_PATH], path[GDS_MAX_PATH];
    const char *base = strrchr(src, '/');
    if((r = gds_path(dir, sizeof(dir), "%s/ApplCerts/%s", pki, sub)) == GDS_OK &&
       (r = gds_mkdirs(dir, 0700)) == GDS_OK &&
       (r = gds_path(path, sizeof(path), "%s/%s", dir, base ? base + 1 : src)) == GDS_OK)
        r = gds_file_write_atomic(path, b.data, b.len, 0644);
    gds_buf_free(&b);
    return r;
}

/* Remove Basic128Rsa15 and Basic256 (deprecated) policies and endpoints. */
static UA_StatusCode dropDeprecatedPolicies(UA_ServerConfig *c) {
    const UA_String dep[2] = {UA_STRING_STATIC("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"),
                              UA_STRING_STATIC("http://opcfoundation.org/UA/SecurityPolicy#Basic256")};
    size_t k = 0;
    for(size_t i = 0; i < c->endpointsSize; i++) {
        bool drop = UA_String_equal(&c->endpoints[i].securityPolicyUri, &dep[0]) ||
                    UA_String_equal(&c->endpoints[i].securityPolicyUri, &dep[1]);
        if(drop)
            UA_EndpointDescription_clear(&c->endpoints[i]);
        else
            c->endpoints[k++] = c->endpoints[i];
    }
    c->endpointsSize = k;
    k = 0;
    for(size_t i = 0; i < c->securityPoliciesSize; i++) {
        UA_SecurityPolicy *sp = &c->securityPolicies[i];
        bool drop = UA_String_equal(&sp->policyUri, &dep[0]) || UA_String_equal(&sp->policyUri, &dep[1]);
        if(drop)
            sp->clear(sp);
        else
            c->securityPolicies[k++] = *sp;
    }
    c->securityPoliciesSize = k;
    return UA_STATUSCODE_GOOD;
}

static int usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s [--port N] [--pki DIR] [--trust cert.der]... [--crl x.crl]...\n"
            "          [--admin user:password]... [--user user:password]...\n"
            "          [--admin-cert gds.der]... [--no-anonymous] [--accept-keys]\n"
            "          [--break MUTANT] [--list-mutants]\n",
            argv0);
    return 2;
}

/* Self-test main: one linear script of steps, kept in one place on purpose. */
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
int main(int argc, char **argv) {
    long port = 4841;
    const char *pki = "./pki-push";
    const char *trust[MAX_SEED], *crls[MAX_SEED];
    size_t trustN = 0, crlN = 0;
    bool allowAnonymous = true; /* anonymous sessions are non-admin; used by refusal tests */

    for(int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if(!strcmp(a, "--no-anonymous")) {
            allowAnonymous = false;
            continue;
        }
        if(!strcmp(a, "--accept-keys")) { /* SupportedPrivateKeyFormats ["PEM"] */
            pm_accept_keys(true);
            continue;
        }
        if(!strcmp(a, "--list-mutants")) {
            pm_mutant_list();
            return 0;
        }
        if(!v)
            return usage(argv[0]);
        i++;
        if(!strcmp(a, "--port")) {
            if(!gds_parse_long(v, 1, 65535, &port))
                return usage(argv[0]);
        } else if(!strcmp(a, "--break")) {
            if(!pm_mutant_known(v)) {
                fprintf(stderr, "unknown mutant '%s' (see --list-mutants)\n", v);
                return 2;
            }
            brk = v;
        } else if(!strcmp(a, "--pki")) {
            pki = v;
        } else if(!strcmp(a, "--trust") && trustN < MAX_SEED) {
            trust[trustN++] = v;
        } else if(!strcmp(a, "--crl") && crlN < MAX_SEED) {
            crls[crlN++] = v;
        } else if((!strcmp(a, "--admin") || !strcmp(a, "--user")) && adminUsersSize < MAX_ADMINS) {
            const char *c = strchr(v, ':');
            AdminUser *u = &adminUsers[adminUsersSize];
            if(!c || (size_t)(c - v) >= MAX_CRED || strlen(c + 1) >= MAX_CRED || c == v) {
                fprintf(stderr, "%s expects user:password (each under %d bytes)\n", a, MAX_CRED);
                return 2;
            }
            u->admin = !strcmp(a, "--admin");
            memcpy(u->user, v, (size_t)(c - v));
            u->user[c - v] = '\0';
            memcpy(u->pass, c + 1, strlen(c + 1) + 1);
            adminUsersSize++;
        } else if(!strcmp(a, "--admin-cert") && adminThumbsSize < MAX_ADMINS) {
            gds_buf b = {0};
            if(gds_file_read(v, GDS_MAX_CERT_SIZE, &b) != GDS_OK ||
               x509_thumbprint(&b, adminThumbs[adminThumbsSize]) != GDS_OK) {
                fprintf(stderr, "cannot read certificate %s\n", v);
                gds_buf_free(&b);
                return 1;
            }
            adminThumbsSize++;
            gds_buf_free(&b);
        } else {
            return usage(argv[0]);
        }
    }
    printf("push_test_server: OpenGDS Auditor self-test target, not a product\n");
    if(brk)
        printf("push_test_server: MUTANT '%s' active, listening on 127.0.0.1 only\n", brk);

    /* Seed the trust store from the command line (initial out-of-band trust) */
    for(size_t i = 0; i < trustN; i++)
        if(addFileToStore(pki, "trusted/certs", trust[i]) != GDS_OK)
            return 1;
    for(size_t i = 0; i < crlN; i++)
        if(addFileToStore(pki, "trusted/crl", crls[i]) != GDS_OK)
            return 1;

    /* Own certificate: from the store, or a fresh self-signed one */
    gds_buf ownCert = {0}, ownKey = {0};
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    if(loadOwnFromStore(pki, &ownCert, &ownKey) == GDS_OK) {
        cert.data = ownCert.data;
        cert.length = ownCert.len;
        key.data = ownKey.data;
        key.length = ownKey.len;
    } else {
        UA_String subject[3] = {UA_STRING_STATIC("C=FI"), UA_STRING_STATIC("O=OpenGDS Test"),
                                UA_STRING_STATIC("CN=OpenGDS Push Test Server")};
        UA_String san[2] = {UA_STRING_STATIC("URI:" APP_URI), UA_STRING_STATIC("DNS:localhost")};
        UA_StatusCode r = UA_CreateCertificate(UA_Log_Stdout, subject, 3, san, 2,
                                               UA_CERTIFICATEFORMAT_DER, NULL, &key, &cert);
        if(r != UA_STATUSCODE_GOOD || saveOwnToStore(pki, &cert, &key) != GDS_OK) {
            fprintf(stderr, "cannot create or save the initial certificate\n");
            return 1;
        }
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Created a self-signed application certificate (initial state, before GDS push)");
    }
    {
        char desc[512], tp[X509_THUMBPRINT_LEN] = "?";
        gds_buf b = {cert.data, cert.length};
        x509_describe(&b, desc, sizeof(desc));
        if(x509_thumbprint(&b, tp) != GDS_OK)
            tp[0] = '\0';
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Own certificate %s  %s", tp, desc);
    }

    UA_Server *server = UA_Server_new();
    if(!server)
        return 1;
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_StatusCode res = UA_ServerConfig_setDefaultWithFilestore(
        config, (UA_UInt16)port, &cert, &key, UA_STRING((char *)(uintptr_t)pki));
    /* the config holds its own copies now; wipe ours (the wire-old-cert
     * mutant keeps one in push_mgmt.c) */
    res |= pm_install(server, brk, &key, sessionMode);
    if(res == UA_STATUSCODE_GOOD && pm_breaking("deprecated-policy")) {
        res = UA_ServerConfig_addSecurityPolicyBasic256(config, &cert, &key);
        if(res == UA_STATUSCODE_GOOD)
            res = UA_ServerConfig_addEndpoint(
                config, UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#Basic256"),
                UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);
    }
    gds_buf kb = {key.data, key.length}, cb = {cert.data, cert.length};
    gds_buf_free_secret(&kb);
    gds_buf_free(&cb);
    if(res != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "server config failed: %s\n", UA_StatusCode_name(res));
        UA_Server_delete(server);
        return 1;
    }

    /* A mutant never listens beyond loopback (docs/architecture.md, "The
     * Auditor under these rules") */
    if(brk) {
        char u[64];
        if(gds_path(u, sizeof(u), "opc.tcp://127.0.0.1:%ld", port) != GDS_OK) {
            UA_Server_delete(server);
            return 1;
        }
        UA_Array_delete(config->serverUrls, config->serverUrlsSize, &UA_TYPES[UA_TYPES_STRING]);
        config->serverUrls = UA_String_new();
        config->serverUrlsSize = 0;
        if(!config->serverUrls) {
            UA_Server_delete(server);
            return 1;
        }
        *config->serverUrls = UA_STRING_ALLOC(u);
        config->serverUrlsSize = 1;
    }

    /* Identity */
    UA_String_clear(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri = UA_STRING_ALLOC(APP_URI);
    UA_LocalizedText_clear(&config->applicationDescription.applicationName);
    config->applicationDescription.applicationName =
        UA_LOCALIZEDTEXT_ALLOC("en", "OpenGDS Push Test Server");

    /* Policy None only for discovery (GetEndpoints), never for sessions */
    config->securityPolicyNoneDiscoveryOnly = !pm_breaking("allow-none");
    /* No deprecated SecurityPolicy (OPC 10000-7; SRV-SEC-08) */
    if(!pm_breaking("deprecated-policy") && dropDeprecatedPolicies(config) != UA_STATUSCODE_GOOD) {
        UA_Server_delete(server);
        return 1;
    }
    config->allowNonePolicyPassword = false;

    /* Access control: default plugin (user/password check) + admin wrapper */
    UA_UsernamePasswordLogin logins[MAX_ADMINS];
    for(size_t i = 0; i < adminUsersSize; i++) {
        logins[i].username = UA_STRING(adminUsers[i].user);
        logins[i].password = UA_STRING(adminUsers[i].pass);
    }
    UA_String policyUri = UA_STRING_NULL; /* encrypt user tokens with the channel policy */
    config->accessControl.clear(&config->accessControl);
    res = UA_AccessControl_default(config, allowAnonymous, &policyUri, adminUsersSize, logins);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Server_delete(server);
        return 1;
    }
    origActivate = config->accessControl.activateSession;
    origClose = config->accessControl.closeSession;
    config->accessControl.activateSession = activateSession;
    config->accessControl.closeSession = closeSession;
    config->accessControl.getUserExecutableOnObject = getUserExecutableOnObject;
    origAccessLevel = config->accessControl.getUserAccessLevel;
    config->accessControl.getUserAccessLevel = getUserAccessLevel;

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "Push test server on opc.tcp://localhost:%ld  (pki=%s, %zu admin users, %zu admin certs)",
                port, pki, adminUsersSize, adminThumbsSize);
    res = UA_Server_runUntilInterrupt(server);
    UA_Server_delete(server);
    pm_clear();
    while(sessionFlags) {
        SessionFlag *n = sessionFlags->next;
        UA_NodeId_clear(&sessionFlags->sessionId);
        free(sessionFlags);
        sessionFlags = n;
    }
    for(size_t i = 0; i < adminUsersSize; i++)
        OPENSSL_cleanse(adminUsers[i].pass, sizeof(adminUsers[i].pass));
    return res == UA_STATUSCODE_GOOD ? 0 : 1;
}
