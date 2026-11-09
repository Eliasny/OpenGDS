/* OpenGDS libgdsclient - the Annex G.1 pull agent (see gdsc_pull_agent.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "gdsc_pull_agent.h"

#include <open62541/client_highlevel.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string.h>
#include <time.h>

#include "gdsc_gds.h"
#include "gdsc_push.h"
#include "gdsc_session.h"
#include "common/ua_args.h"
#include "common/banned.h"

#define DEFAULT_FINISH_REPEAT 2u
#define DEFAULT_FINISH_DELAY_MS 1000u
#define CN_MAX 64

void gdsc_pull_state_clear(gdsc_pull_state *st) {
    gds_buf_free(&st->cert);
    gds_buf_free_secret(&st->key);
    for(size_t i = 0; i < st->issuersN && i < GDS_MAX_CHAIN_LEN; i++)
        gds_buf_free(&st->issuers[i]);
    UA_NodeId_clear(&st->applicationId);
    UA_NodeId_clear(&st->pendingRequest);
    gds_buf_free_secret(&st->pendingKey);
    UA_TrustListDataType_clear(&st->trustList);
    memset(st, 0, sizeof(*st));
}

const char *gdsc_pull_step_name(gdsc_pull_step s) {
    switch(s) {
    case GDSC_PULL_STEP_NONE: return "none";
    case GDSC_PULL_STEP_CONNECT: return "connect";
    case GDSC_PULL_STEP_REGISTER: return "FindApplications/RegisterApplication";
    case GDSC_PULL_STEP_GROUPS: return "GetCertificateGroups";
    case GDSC_PULL_STEP_STATUS: return "GetCertificateStatus";
    case GDSC_PULL_STEP_CSR: return "create CSR";
    case GDSC_PULL_STEP_SIGN: return "StartSigningRequest/FinishRequest";
    case GDSC_PULL_STEP_TRUSTLIST: return "GetTrustList";
    case GDSC_PULL_STEP_PERSIST: return "persist";
    }
    return "?";
}

/* ---- key pair and CSR ---- */

static EVP_PKEY *new_key(const UA_NodeId *t) {
    if(t->namespaceIndex != 0 || t->identifierType != UA_NODEIDTYPE_NUMERIC)
        return NULL;
    switch(t->identifier.numeric) {
    case UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE:
    case UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE:
    case UA_NS0ID_APPLICATIONCERTIFICATETYPE:
        return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    case UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE:
        return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    case UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE:
        return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");
    default:
        return NULL;
    }
}

static gds_status der_out(unsigned char *p, int n, gds_buf *out, bool secret) {
    if(n <= 0 || !p)
        return GDS_ECRYPTO;
    gds_status s = gds_buf_dup(p, (size_t)n, out);
    if(secret)
        OPENSSL_cleanse(p, (size_t)n);
    OPENSSL_free(p);
    return s;
}

gds_status gdsc_make_csr(const UA_NodeId *certType, const char *applicationUri,
                         const char *commonName, gds_buf *keyOut, gds_buf *csrOut) {
    memset(keyOut, 0, sizeof(*keyOut));
    memset(csrOut, 0, sizeof(*csrOut));
    if(!certType || !applicationUri || !commonName ||
       strlen(applicationUri) >= GDS_MAX_APPLICATION_URI || strlen(commonName) > CN_MAX)
        return GDS_EINVAL;
    EVP_PKEY *pk = new_key(certType);
    if(!pk)
        return GDS_EUNSUPPORTED;
    X509_REQ *req = X509_REQ_new();
    X509_NAME *name = X509_NAME_new();
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    GENERAL_NAMES *gens = GENERAL_NAMES_new();
    GENERAL_NAME *gn = GENERAL_NAME_new();
    ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
    gds_status s = GDS_ECRYPTO;
    if(req && name && exts && gens && gn && ia5 &&
       ASN1_STRING_set(ia5, applicationUri, (int)strlen(applicationUri)) == 1) {
        GENERAL_NAME_set0_value(gn, GEN_URI, ia5);
        ia5 = NULL;
        if(sk_GENERAL_NAME_push(gens, gn) > 0) {
            gn = NULL;
            X509_EXTENSION *ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
            if(ext && sk_X509_EXTENSION_push(exts, ext) > 0 &&
               X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                          (const unsigned char *)commonName, -1, -1, 0) == 1 &&
               X509_REQ_set_version(req, X509_REQ_VERSION_1) == 1 &&
               X509_REQ_set_subject_name(req, name) == 1 && X509_REQ_set_pubkey(req, pk) == 1 &&
               X509_REQ_add_extensions(req, exts) == 1 &&
               X509_REQ_sign(req, pk, EVP_sha256()) > 0) {
                /* i2d first: the order in which a call's arguments are
                 * evaluated is unspecified (C11 6.5.2.2p10), and clang
                 * reads d before i2d sets it */
                unsigned char *d = NULL;
                int n = i2d_X509_REQ(req, &d);
                s = der_out(d, n, csrOut, false);
                d = NULL;
                if(s == GDS_OK) {
                    n = i2d_PrivateKey(pk, &d);
                    s = der_out(d, n, keyOut, true);
                }
            } else if(ext && sk_X509_EXTENSION_num(exts) == 0) {
                X509_EXTENSION_free(ext);
            }
        }
    }
    ASN1_IA5STRING_free(ia5);
    GENERAL_NAME_free(gn);
    GENERAL_NAMES_free(gens);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    X509_NAME_free(name);
    X509_REQ_free(req);
    EVP_PKEY_free(pk);
    if(s != GDS_OK) {
        gds_buf_free(csrOut);
        gds_buf_free_secret(keyOut);
    }
    return s;
}

/* ---- one run ---- */

typedef struct {
    const gdsc_pull_cfg *cfg;
    gdsc_pull_state *st;
    gdsc_pull_result *res;
    UA_Client *c;
    UA_UInt16 ns;
    UA_NodeId group, type;
    bool dirty; /* the state changed and must be persisted */
} run_ctx;

static UA_StatusCode failed(run_ctx *x, gdsc_pull_step step, UA_StatusCode r) {
    x->res->failedStep = step;
    x->res->failedCode = r;
    return r;
}

static bool cfg_valid(const gdsc_pull_cfg *c, const gdsc_pull_state *st) {
    return c && st && c->gdsUrl && c->trust && c->trustN > 0 && (c->crlN == 0 || c->crls) &&
           c->record && c->record->applicationUri.length > 0 &&
           c->record->applicationUri.length < GDS_MAX_APPLICATION_URI && c->persist &&
           (!c->userName || c->password) && st->cert.data && st->key.data;
}

/* §7.6 Connect. User credentials only until the GDS issued us a certificate
 * (Annex G.1: afterwards the certificate is used in lieu of them). */
static UA_StatusCode connect(const gdsc_pull_cfg *cfg, const gdsc_pull_state *st,
                             gdsc_session **s) {
    gdsc_session_cfg c;
    memset(&c, 0, sizeof(c));
    c.endpointUrl = cfg->gdsUrl;
    c.serverUri = cfg->gdsUri;
    c.cert = &st->cert;
    c.key = &st->key;
    c.trust = cfg->trust;
    c.trustN = cfg->trustN;
    c.crls = cfg->crls;
    c.crlN = cfg->crlN;
    c.timeoutMs = cfg->timeoutMs;
    char uri[GDS_MAX_APPLICATION_URI];
    memcpy(uri, cfg->record->applicationUri.data, cfg->record->applicationUri.length);
    uri[cfg->record->applicationUri.length] = '\0';
    c.applicationUri = uri;
    if(cfg->userName && st->issuersN == 0) {
        c.identity = GDSC_IDENTITY_USERNAME;
        c.userName = cfg->userName;
        c.password = cfg->password;
    } else {
        c.identity = GDSC_IDENTITY_APP_CERT;
    }
    return gdsc_session_open(&c, s);
}

static UA_StatusCode find_or_register(run_ctx *x) {
    char uri[GDS_MAX_APPLICATION_URI];
    const UA_String *u = &x->cfg->record->applicationUri;
    memcpy(uri, u->data, u->length);
    uri[u->length] = '\0';
    UA_ApplicationRecordDataType *recs = NULL;
    size_t n = 0;
    UA_StatusCode r = gdsc_find_applications(x->c, x->ns, uri, &recs, &n);
    if(r == UA_STATUSCODE_GOOD && n > 1)
        r = UA_STATUSCODE_BADDUPLICATEREFERENCENOTALLOWED; /* ambiguous */
    if(r == UA_STATUSCODE_GOOD && n == 1 &&
       !UA_NodeId_equal(&recs[0].applicationId, &x->st->applicationId)) {
        UA_NodeId_clear(&x->st->applicationId);
        r = UA_NodeId_copy(&recs[0].applicationId, &x->st->applicationId);
        x->dirty = true;
    }
    UA_Array_delete(recs, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    if(r != UA_STATUSCODE_GOOD || n == 1)
        return r;
    UA_NodeId id;
    r = gdsc_register_application(x->c, x->ns, x->cfg->record, &id);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_NodeId_clear(&x->st->applicationId);
    x->st->applicationId = id;
    x->res->registered = true;
    x->dirty = true;
    /* a request of an earlier registration is void */
    UA_NodeId_clear(&x->st->pendingRequest);
    gds_buf_free_secret(&x->st->pendingKey);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode check_groups(run_ctx *x) {
    UA_NodeId *groups = NULL;
    size_t n = 0;
    UA_StatusCode r = gdsc_get_certificate_groups(x->c, x->ns, &x->st->applicationId, &groups, &n);
    bool found = false;
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && i < n; i++)
        found = found || UA_NodeId_equal(&groups[i], &x->group);
    UA_Array_delete(groups, n, &UA_TYPES[UA_TYPES_NODEID]);
    if(r == UA_STATUSCODE_GOOD && !found)
        r = UA_STATUSCODE_BADNOTFOUND;
    return r;
}

/* Take the issued certificate and the key it was requested with */
static void take(run_ctx *x, gds_buf *cert, gds_buf *issuers, size_t issuersN) {
    gdsc_pull_state *st = x->st;
    gds_buf_free(&st->cert);
    gds_buf_free_secret(&st->key);
    for(size_t i = 0; i < st->issuersN; i++)
        gds_buf_free(&st->issuers[i]);
    st->cert = *cert;
    st->key = st->pendingKey;
    memset(&st->pendingKey, 0, sizeof(st->pendingKey));
    for(size_t i = 0; i < issuersN; i++)
        st->issuers[i] = issuers[i];
    st->issuersN = issuersN;
    UA_NodeId_clear(&st->pendingRequest);
    x->res->certificateIssued = true;
    x->dirty = true;
}

/* FinishRequest up to `repeat` more times while Bad_NothingToDo */
static UA_StatusCode finish(run_ctx *x, unsigned repeat) {
    const UA_UInt32 delay = x->cfg->finishDelayMs ? x->cfg->finishDelayMs : DEFAULT_FINISH_DELAY_MS;
    const struct timespec step = {(time_t)(delay / 1000u), (long)(delay % 1000u) * 1000000L};
    for(unsigned i = 0;; i++) {
        gds_buf cert = {0}, issuers[GDS_MAX_CHAIN_LEN];
        size_t issuersN = 0;
        UA_StatusCode r = gdsc_finish_request(x->c, x->ns, &x->st->applicationId,
                                              &x->st->pendingRequest, &cert, issuers, &issuersN);
        if(r == UA_STATUSCODE_GOOD) {
            take(x, &cert, issuers, issuersN);
            x->res->pending = false;
            return r;
        }
        if(r != UA_STATUSCODE_BADNOTHINGTODO) {
            /* Table 21: any other Bad result -> a new request next cycle */
            UA_NodeId_clear(&x->st->pendingRequest);
            gds_buf_free_secret(&x->st->pendingKey);
            x->dirty = true;
            return r;
        }
        if(i >= repeat) {
            x->res->pending = true; /* the RequestId stays persisted */
            return UA_STATUSCODE_GOOD;
        }
        nanosleep(&step, NULL);
    }
}

static UA_StatusCode request_certificate(run_ctx *x) {
    char uri[GDS_MAX_APPLICATION_URI], cn[CN_MAX + 1];
    const UA_ApplicationRecordDataType *rec = x->cfg->record;
    memcpy(uri, rec->applicationUri.data, rec->applicationUri.length);
    uri[rec->applicationUri.length] = '\0';
    size_t cl = 0;
    if(rec->applicationNamesSize > 0 && rec->applicationNames[0].text.length > 0) {
        cl = rec->applicationNames[0].text.length > CN_MAX ? CN_MAX
                                                            : rec->applicationNames[0].text.length;
        memcpy(cn, rec->applicationNames[0].text.data, cl);
    }
    cn[cl] = '\0';
    gds_buf key = {0}, csr = {0};
    if(gdsc_make_csr(&x->type, uri, cl ? cn : uri, &key, &csr) != GDS_OK)
        return failed(x, GDSC_PULL_STEP_CSR, UA_STATUSCODE_BADINTERNALERROR);
    UA_NodeId req;
    UA_StatusCode r = gdsc_start_signing_request(x->c, x->ns, &x->st->applicationId, &x->group,
                                                 &x->type, &csr, &req);
    gds_buf_free(&csr);
    if(r != UA_STATUSCODE_GOOD) {
        gds_buf_free_secret(&key);
        return failed(x, GDSC_PULL_STEP_SIGN, r);
    }
    gds_buf_free_secret(&x->st->pendingKey);
    UA_NodeId_clear(&x->st->pendingRequest);
    x->st->pendingKey = key;
    x->st->pendingRequest = req;
    x->dirty = true;
    const unsigned repeat = x->cfg->finishRepeat ? x->cfg->finishRepeat : DEFAULT_FINISH_REPEAT;
    r = finish(x, repeat);
    return r == UA_STATUSCODE_GOOD ? r : failed(x, GDSC_PULL_STEP_SIGN, r);
}

static UA_StatusCode read_child(UA_Client *c, const UA_NodeId *tl, const char *name,
                                UA_Variant *v) {
    UA_NodeId n;
    UA_StatusCode r = gdsc_find_child(c, tl, name, &n);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_readValueAttribute(c, n, v);
    UA_NodeId_clear(&n);
    return r;
}

/* Table 21 GetTrustList: LastUpdateTime first, the content only if it
 * changed; UpdateFrequency gives the next run */
static UA_StatusCode trust_list(run_ctx *x, bool force) {
    UA_NodeId tl;
    UA_StatusCode r = gdsc_get_trust_list_id(x->c, x->ns, &x->st->applicationId, &x->group, &tl);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Variant v;
    UA_Variant_init(&v);
    UA_DateTime last = 0;
    bool known = false; /* the GDS gave a LastUpdateTime (MinValue = never changed) */
    const void *p = NULL;
    if(read_child(x->c, &tl, "LastUpdateTime", &v) == UA_STATUSCODE_GOOD &&
       gds_arg_scalar(&v, &UA_TYPES[UA_TYPES_DATETIME], &p) == UA_STATUSCODE_GOOD) {
        last = *(const UA_DateTime *)p;
        known = true;
    }
    UA_Variant_clear(&v);
    if(read_child(x->c, &tl, "UpdateFrequency", &v) == UA_STATUSCODE_GOOD &&
       gds_arg_scalar(&v, &UA_TYPES[UA_TYPES_DOUBLE], &p) == UA_STATUSCODE_GOOD &&
       *(const UA_Double *)p > 0)
        x->res->nextRunMs = *(const UA_Double *)p;
    UA_Variant_clear(&v);
    /* Download when we have no list yet, the time is unknown, or it moved */
    const bool have = x->st->trustList.specifiedLists != 0;
    if(force || !have || !known || last != x->st->trustListTime) {
        UA_TrustListDataType t;
        r = gdsc_trustlist_read(x->c, &tl, &t);
        if(r == UA_STATUSCODE_GOOD) {
            UA_TrustListDataType_clear(&x->st->trustList);
            x->st->trustList = t;
            x->st->trustListTime = last;
            x->res->trustListDownloaded = true;
            x->dirty = true;
        }
    }
    UA_NodeId_clear(&tl);
    return r;
}

static UA_StatusCode run_steps(run_ctx *x) {
    UA_StatusCode r = find_or_register(x);
    if(r != UA_STATUSCODE_GOOD)
        return failed(x, GDSC_PULL_STEP_REGISTER, r);
    r = check_groups(x);
    if(r != UA_STATUSCODE_GOOD)
        return failed(x, GDSC_PULL_STEP_GROUPS, r);
    if(!UA_NodeId_isNull(&x->st->pendingRequest)) {
        /* Table 21 SigningRequestPending: repeat count 0 */
        r = finish(x, 0);
        if(r != UA_STATUSCODE_GOOD)
            r = UA_STATUSCODE_GOOD; /* dropped: a new request below */
        if(x->res->pending)
            return UA_STATUSCODE_GOOD; /* still waiting: nothing else to do */
    }
    bool update = false;
    r = gdsc_get_certificate_status(x->c, x->ns, &x->st->applicationId, &x->group, &x->type,
                                    &update);
    if(r != UA_STATUSCODE_GOOD)
        return failed(x, GDSC_PULL_STEP_STATUS, r);
    x->res->updateRequired = update;
    if(update && !x->res->certificateIssued) {
        r = request_certificate(x);
        if(r != UA_STATUSCODE_GOOD || x->res->pending)
            return r;
    }
    /* A new certificate goes with the trust list it was issued against */
    r = trust_list(x, x->res->certificateIssued);
    return r == UA_STATUSCODE_GOOD ? r : failed(x, GDSC_PULL_STEP_TRUSTLIST, r);
}

UA_StatusCode gdsc_pull_agent_run(const gdsc_pull_cfg *cfg, gdsc_pull_state *st,
                                  gdsc_pull_result *res) {
    memset(res, 0, sizeof(*res));
    if(!cfg_valid(cfg, st))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    run_ctx x;
    memset(&x, 0, sizeof(x));
    x.cfg = cfg;
    x.st = st;
    x.res = res;
    x.type = UA_NodeId_isNull(&cfg->certificateType)
                 ? UA_NODEID_NUMERIC(0, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE)
                 : cfg->certificateType;
    gdsc_session *s = NULL;
    UA_StatusCode r = connect(cfg, st, &s);
    if(r != UA_STATUSCODE_GOOD)
        return failed(&x, GDSC_PULL_STEP_CONNECT, r);
    x.c = gdsc_session_client(s);
    r = gdsc_gds_bind(x.c, &x.ns);
    if(r != UA_STATUSCODE_GOOD)
        failed(&x, GDSC_PULL_STEP_CONNECT, r);
    else {
        x.group = gdsc_gds_default_group(x.ns);
        r = run_steps(&x);
    }
    gdsc_session_close(s);
    /* Persist what changed, also after a later step failed (a pending
     * RequestId and its key must survive) */
    if(x.dirty) {
        gds_status ps = cfg->persist(cfg->persistCtx, st);
        if(ps != GDS_OK && r == UA_STATUSCODE_GOOD)
            r = failed(&x, GDSC_PULL_STEP_PERSIST, gds_status_to_ua(ps));
    }
    return r;
}
