/* OpenGDS push engine - the rejected-list harvest (push_rejected.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "push_rejected.h"

#include <open62541/nodeids.h>
#include <open62541/nodeids_gds.h>
#include <open62541/server.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/limits.h"
#include "gds_plugin.h"
#include "common/banned.h"

#define DEFAULT_OPEN 64u
#define DEFAULT_TRUST_TIMEOUT_MS 10000u
#define MAX_REMEMBERED 1024u /* certificates answered or open */
#define SHA256_LEN 32
#define MAX_CN 128
#define MAX_TEXT 2048
#define SEVERITY 400
#define ANSWER_TRUST 0
#define ANSWER_IGNORE 1

typedef enum { ENTRY_OPEN, ENTRY_ANSWERED, ENTRY_CLOSED } entry_state;

typedef struct {
    uint8_t thumb[SHA256_LEN];
    UA_NodeId dialogId;
    UA_ByteString cert;
    char uri[GDS_MAX_APPLICATION_URI + 1];
    char name[MAX_CN];
    entry_state state;
} entry;

struct push_rejected {
    push_rejected_cfg cfg;
    UA_UInt16 ns;
    UA_NodeId pushObject, discoveryAdmin;
    pthread_mutex_t lock; /* entries; never held across a gds_server call */
    entry *entries;
    size_t n;
};

/* ---- certificates ---- */

static X509 *parse(const UA_ByteString *der) {
    if(!der || der->length == 0 || der->length > GDS_MAX_CERT_SIZE)
        return NULL;
    const unsigned char *p = der->data;
    X509 *x = d2i_X509(NULL, &p, (long)der->length);
    if(x && p != der->data + der->length) { /* trailing bytes */
        X509_free(x);
        x = NULL;
    }
    return x;
}

static bool is_ca(X509 *x) {
    return X509_check_ca(x) != 0;
}

/* The URI SubjectAltName (the ApplicationUri, OPC 10000-6 §6.2.2) */
static bool uri_of(X509 *x, char *out, size_t len) {
    GENERAL_NAMES *names = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
    bool ok = false;
    for(int i = 0; names && !ok && i < sk_GENERAL_NAME_num(names); i++) {
        const GENERAL_NAME *g = sk_GENERAL_NAME_value(names, i);
        if(g->type != GEN_URI)
            continue;
        const unsigned char *d = ASN1_STRING_get0_data(g->d.uniformResourceIdentifier);
        int n = ASN1_STRING_length(g->d.uniformResourceIdentifier);
        if(n <= 0 || (size_t)n >= len || memchr(d, 0, (size_t)n))
            continue;
        bool printable = true;
        for(int k = 0; k < n; k++)
            printable = printable && d[k] > 0x20 && d[k] < 0x7f;
        if(!printable)
            continue;
        memcpy(out, d, (size_t)n);
        out[n] = '\0';
        ok = true;
    }
    GENERAL_NAMES_free(names);
    return ok;
}

static void cn_of(X509 *x, char *out, size_t len) {
    out[0] = '\0';
    X509_NAME *nm = X509_get_subject_name(x);
    int i = nm ? X509_NAME_get_index_by_NID(nm, NID_commonName, -1) : -1;
    if(i < 0)
        return;
    const ASN1_STRING *s = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(nm, i));
    unsigned char *utf8 = NULL;
    int n = ASN1_STRING_to_UTF8(&utf8, s);
    if(n > 0 && (size_t)n < len && !memchr(utf8, 0, (size_t)n)) {
        memcpy(out, utf8, (size_t)n);
        out[n] = '\0';
    }
    OPENSSL_free(utf8);
}

static bool thumb_of(const UA_ByteString *der, uint8_t out[SHA256_LEN]) {
    unsigned int n = 0;
    return EVP_Digest(der->data, der->length, out, &n, EVP_sha256(), NULL) == 1 &&
           n == SHA256_LEN;
}

/* Signed by one of the trust list's CA certificates (trusted or issuer):
 * the client is trusted already; the Server refused it for another
 * reason, such as a stale trust list, which the push fixes. */
static bool issued_by_list(X509 *x, const UA_ByteString *cas, size_t n) {
    for(size_t i = 0; i < n; i++) {
        X509 *ca = parse(&cas[i]);
        bool hit = false;
        if(ca && is_ca(ca) && X509_check_issued(ca, x) == X509_V_OK) {
            EVP_PKEY *k = X509_get0_pubkey(ca);
            hit = k && X509_verify(x, k) == 1;
        }
        X509_free(ca);
        if(hit)
            return true;
    }
    return false;
}

static bool known_to(const UA_TrustListDataType *tl, const UA_ByteString *der, X509 *x) {
    if(!tl)
        return false;
    for(size_t i = 0; i < tl->trustedCertificatesSize; i++)
        if(UA_ByteString_equal(&tl->trustedCertificates[i], der))
            return true;
    return issued_by_list(x, tl->trustedCertificates, tl->trustedCertificatesSize) ||
           issued_by_list(x, tl->issuerCertificates, tl->issuerCertificatesSize);
}

/* ---- entries (lock held) ---- */

static entry *find_thumb(push_rejected *r, const uint8_t t[SHA256_LEN]) {
    for(size_t i = 0; i < r->n; i++)
        if(memcmp(r->entries[i].thumb, t, SHA256_LEN) == 0)
            return &r->entries[i];
    return NULL;
}

static entry *find_dialog(push_rejected *r, const UA_NodeId *id) {
    for(size_t i = 0; i < r->n; i++)
        if(r->entries[i].state != ENTRY_CLOSED && UA_NodeId_equal(&r->entries[i].dialogId, id))
            return &r->entries[i];
    return NULL;
}

static size_t count_open(const push_rejected *r) {
    size_t k = 0;
    for(size_t i = 0; i < r->n; i++)
        k += r->entries[i].state == ENTRY_OPEN;
    return k;
}

static void entry_clear(entry *e) {
    UA_NodeId_clear(&e->dialogId);
    UA_ByteString_clear(&e->cert);
}

/* Room for one more: forget the oldest closed entry when full. */
static entry *slot(push_rejected *r) {
    if(r->n == MAX_REMEMBERED) {
        size_t i = 0;
        while(i < r->n && r->entries[i].state != ENTRY_CLOSED)
            i++;
        if(i == r->n)
            return NULL;
        entry_clear(&r->entries[i]);
        memmove(&r->entries[i], &r->entries[i + 1], (r->n - i - 1) * sizeof(entry));
        r->n--;
    }
    if(!r->entries) {
        r->entries = calloc(MAX_REMEMBERED, sizeof(entry));
        if(!r->entries)
            return NULL;
    }
    entry *e = &r->entries[r->n];
    memset(e, 0, sizeof(*e));
    return e;
}

/* ---- the answer ---- */

static UA_StatusCode register_and_trust(push_rejected *r, const gds_caller *caller,
                                        const entry *e) {
    const char *actor = caller && caller->userName && caller->userName[0] ? caller->userName
                                                                          : PUSH_REJECTED_ACTOR;
    UA_LocalizedText name = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)(e->name[0] ? e->name : e->uri));
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    rec.applicationUri = UA_STRING((char *)(uintptr_t)e->uri);
    rec.applicationType = UA_APPLICATIONTYPE_CLIENT;
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    UA_NodeId appId = UA_NODEID_NULL;
    bool created = false;
    gds_status st = gds_server_register_application(r->cfg.server, actor, &rec, &appId, &created);
    UA_NodeId_clear(&appId);
    if(st == GDS_OK)
        st = gds_server_trust_certificate(r->cfg.server, actor, &e->cert, r->cfg.trustTimeoutMs);
    if(st == GDS_OK)
        return UA_STATUSCODE_GOOD;
    if(st == GDS_ENOTLEADER || st == GDS_ESTATE)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(st == GDS_EINVAL)
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    if(st == GDS_EREMOTE)
        return UA_STATUSCODE_BADTIMEOUT;
    return UA_STATUSCODE_BADINTERNALERROR;
}

static UA_StatusCode respond(void *ctx, const gds_caller *caller, const UA_NodeId *dialogId,
                             int32_t selected, const UA_LocalizedText *comment) {
    (void)comment;
    push_rejected *r = ctx;
    if(selected != ANSWER_TRUST && selected != ANSWER_IGNORE)
        return UA_STATUSCODE_BADDIALOGRESPONSEINVALID;
    entry copy;
    memset(&copy, 0, sizeof(copy));
    pthread_mutex_lock(&r->lock);
    entry *e = find_dialog(r, dialogId);
    bool open = e && e->state == ENTRY_OPEN;
    UA_StatusCode res = open ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADDIALOGNOTACTIVE;
    if(open && selected == ANSWER_TRUST) {
        memcpy(copy.uri, e->uri, sizeof(copy.uri));
        memcpy(copy.name, e->name, sizeof(copy.name));
        res = UA_ByteString_copy(&e->cert, &copy.cert);
    }
    pthread_mutex_unlock(&r->lock);
    if(res == UA_STATUSCODE_GOOD && selected == ANSWER_TRUST)
        res = register_and_trust(r, caller, &copy);
    UA_ByteString_clear(&copy.cert);
    if(res != UA_STATUSCODE_GOOD)
        return res; /* the dialog stays active: another answer may follow */
    pthread_mutex_lock(&r->lock);
    e = find_dialog(r, dialogId);
    if(e && e->state == ENTRY_OPEN)
        e->state = ENTRY_ANSWERED;
    pthread_mutex_unlock(&r->lock);
    return UA_STATUSCODE_GOOD;
}

/* ---- the dialogs ---- */

static void hex(const uint8_t *d, size_t n, char *out) {
    static const char digits[] = "0123456789ABCDEF";
    for(size_t i = 0; i < n; i++) {
        out[2 * i] = digits[d[i] >> 4];
        out[2 * i + 1] = digits[d[i] & 15];
    }
    out[2 * n] = '\0';
}

static gds_status open_dialog(push_rejected *r, const char *serverUri, entry *e) {
    static const char *const options[] = {"Register and trust", "Ignore"};
    char name[64], thumb[2 * SHA256_LEN + 1], msg[MAX_TEXT];
    hex(e->thumb, SHA256_LEN, thumb);
    if(gds_path(name, sizeof(name), "Rejected_%.16s", thumb) != GDS_OK ||
       gds_path(msg, sizeof(msg),
                "%s refused the client certificate of %s (%s, SHA-256 %s). Register the client "
                "and trust its certificate?",
                serverUri, e->uri, e->name[0] ? e->name : "no common name", thumb) != GDS_OK)
        return GDS_ETOOBIG;
    gds_dialog_def d;
    memset(&d, 0, sizeof(d));
    d.abi_major = GDS_PLUGIN_ABI_MAJOR;
    d.abi_minor = GDS_PLUGIN_ABI_MINOR;
    d.struct_size = sizeof(d);
    d.dialogId = UA_NODEID_NULL; /* a new one in the push namespace */
    d.sourceNode = r->pushObject;
    d.name = name;
    d.message = msg;
    d.prompt = "Register and trust this client?";
    d.responseOptions = options;
    d.responseOptionsSize = 2;
    d.defaultResponse = ANSWER_IGNORE;
    d.okResponse = ANSWER_TRUST;
    d.cancelResponse = ANSWER_IGNORE;
    d.severity = SEVERITY;
    d.respondRoles = &r->discoveryAdmin;
    d.respondRolesSize = 1;
    d.visibleTo = &r->discoveryAdmin;
    d.visibleToSize = 1;
    d.respond = respond;
    d.ctx = r;
    return gds_server_add_dialog(r->cfg.server, &d, &e->dialogId);
}

size_t push_rejected_offer(push_rejected *r, const char *serverUri, const UA_ByteString *certs,
                           size_t n, const UA_TrustListDataType *tl) {
    size_t opened = 0;
    for(size_t i = 0; r && serverUri && i < n; i++) {
        uint8_t t[SHA256_LEN];
        X509 *x = parse(&certs[i]);
        entry e;
        memset(&e, 0, sizeof(e));
        bool offer = x && !is_ca(x) && uri_of(x, e.uri, sizeof(e.uri)) &&
                     thumb_of(&certs[i], t) && !known_to(tl, &certs[i], x);
        if(offer)
            cn_of(x, e.name, sizeof(e.name));
        X509_free(x);
        if(!offer)
            continue;
        pthread_mutex_lock(&r->lock);
        bool seen = find_thumb(r, t) != NULL;
        bool full = count_open(r) >= r->cfg.maxOpen;
        entry *slotp = seen || full ? NULL : slot(r);
        if(slotp) {
            memcpy(e.thumb, t, SHA256_LEN);
            e.state = ENTRY_OPEN;
            *slotp = e;
            r->n++; /* reserved; the dialog id is filled in below */
        }
        pthread_mutex_unlock(&r->lock);
        if(!slotp)
            continue;
        /* the entry is reserved by its thumbprint; build the dialog
         * outside the lock (gds_server_add_dialog may call back) */
        UA_ByteString cert = UA_BYTESTRING_NULL;
        UA_NodeId id = UA_NODEID_NULL;
        entry tmp = e;
        tmp.dialogId = UA_NODEID_NULL;
        gds_status st = UA_ByteString_copy(&certs[i], &cert) == UA_STATUSCODE_GOOD
                            ? open_dialog(r, serverUri, &tmp)
                            : GDS_ENOMEM;
        id = tmp.dialogId;
        pthread_mutex_lock(&r->lock);
        entry *mine = find_thumb(r, t);
        if(mine && st == GDS_OK) {
            mine->dialogId = id;
            mine->cert = cert;
            opened++;
        } else {
            if(mine) /* not opened: forget it, so a later harvest tries again */
                mine->state = ENTRY_CLOSED, memset(mine->thumb, 0, SHA256_LEN);
            UA_ByteString_clear(&cert);
            UA_NodeId_clear(&id);
            if(st != GDS_OK)
                fprintf(stderr, "opengds: push: dialog for a rejected certificate: %s\n",
                        gds_status_name(st));
        }
        pthread_mutex_unlock(&r->lock);
    }
    return opened;
}

void push_rejected_tick(push_rejected *r) {
    if(!r)
        return;
    for(;;) {
        UA_NodeId id = UA_NODEID_NULL;
        pthread_mutex_lock(&r->lock);
        for(size_t i = 0; i < r->n; i++) {
            entry *e = &r->entries[i];
            if(e->state == ENTRY_ANSWERED) {
                e->state = ENTRY_CLOSED;
                id = e->dialogId; /* moved out */
                e->dialogId = UA_NODEID_NULL;
                UA_ByteString_clear(&e->cert);
                break;
            }
        }
        pthread_mutex_unlock(&r->lock);
        if(UA_NodeId_isNull(&id))
            return;
        if(gds_server_remove_dialog(r->cfg.server, &id) != GDS_OK)
            fprintf(stderr, "opengds: push: could not remove a rejected-push dialog\n");
        UA_NodeId_clear(&id);
    }
}

size_t push_rejected_open(push_rejected *r) {
    if(!r)
        return 0;
    pthread_mutex_lock(&r->lock);
    size_t k = count_open(r);
    pthread_mutex_unlock(&r->lock);
    return k;
}

static gds_status setup_nodes(push_rejected *r) {
    gds_server *s = r->cfg.server;
    gds_status st = gds_server_add_namespace(s, PUSH_NS_URI, &r->ns);
    if(st != GDS_OK)
        return st;
    size_t gi = 0;
    if(UA_Server_getNamespaceByName(gds_server_ua(s), UA_STRING((char *)(uintptr_t)"http://opcfoundation.org/UA/GDS/"),
                                    &gi) != UA_STATUSCODE_GOOD ||
       gi > UA_UINT16_MAX)
        return GDS_EINVAL;
    r->discoveryAdmin = UA_NODEID_NUMERIC((UA_UInt16)gi, UA_GDSID_WELLKNOWNROLE_DISCOVERYADMIN);
    r->pushObject = UA_NODEID_NUMERIC(r->ns, PUSH_NODE_PUSH);
    UA_NodeId objects = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    UA_NodeClass cls;
    if(UA_Server_readNodeClass(gds_server_ua(s), r->pushObject, &cls) == UA_STATUSCODE_GOOD)
        return GDS_OK; /* added by an earlier engine on this server */
    return gds_server_add_object(s, &r->pushObject, &objects, "Push", NULL);
}

gds_status push_rejected_new(const push_rejected_cfg *cfg, push_rejected **out) {
    *out = NULL;
    if(!cfg || !cfg->server)
        return GDS_EINVAL;
    push_rejected *r = calloc(1, sizeof(*r));
    if(!r)
        return GDS_ENOMEM;
    r->cfg = *cfg;
    if(!r->cfg.maxOpen)
        r->cfg.maxOpen = DEFAULT_OPEN;
    if(r->cfg.maxOpen > MAX_REMEMBERED / 2)
        r->cfg.maxOpen = MAX_REMEMBERED / 2;
    if(!r->cfg.trustTimeoutMs)
        r->cfg.trustTimeoutMs = DEFAULT_TRUST_TIMEOUT_MS;
    pthread_mutex_init(&r->lock, NULL);
    gds_status st = setup_nodes(r);
    if(st != GDS_OK) {
        pthread_mutex_destroy(&r->lock);
        free(r);
        return st;
    }
    *out = r;
    return GDS_OK;
}

void push_rejected_free(push_rejected *r) {
    if(!r)
        return;
    for(size_t i = 0; i < r->n; i++) {
        entry *e = &r->entries[i];
        if(e->state != ENTRY_CLOSED && !UA_NodeId_isNull(&e->dialogId) &&
           gds_server_remove_dialog(r->cfg.server, &e->dialogId) != GDS_OK)
            fprintf(stderr, "opengds: push: could not remove a rejected-push dialog\n");
        entry_clear(e);
    }
    free(r->entries);
    pthread_mutex_destroy(&r->lock);
    free(r);
}
