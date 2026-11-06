/* OpenGDS Auditor client profile - the fake GDS. See fake_gds.h.
 * Grown from the demo's mock_gds.c (which stays as the GDS profile's fixture).
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "fake_gds.h"

#include <open62541/nodeids_gds.h>
#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/types_gds_generated.h>

#include <openssl/rand.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "common/limits.h"
#include "common/ua_args.h"
#include "test_ca.h"
#include "x509util.h"
#include "common/banned.h"

#define GDS_NS_URI "http://opcfoundation.org/UA/GDS/"
#define FG_APP_URI "urn:opengds:auditor:fakegds"
#define FG_MAX_APPS 32
#define FG_MAX_REQS 64
#define FG_MAX_EVENTS 2048
#define FG_MAX_ARGS_BYTES ((size_t)64 * 1024)
#define FG_MAX_SESSIONS 256

typedef struct {
    UA_ApplicationRecordDataType rec;
    bool hasCert;
} fg_app;

typedef struct {
    UA_NodeId requestId, appId;
    gds_buf csr;
    long polls;
    bool done, rejected;
} fg_req;

/* Single instance; touched only from the Auditor thread (method callbacks
 * run inside fg_iterate on the same thread). */
static struct {
    UA_Server *server;
    testca_t ca;
    UA_UInt16 ns;
    fg_behaviour b;
    fg_app apps[FG_MAX_APPS];
    size_t appsN;
    fg_req reqs[FG_MAX_REQS];
    size_t reqsN;
    fg_event ev[FG_MAX_EVENTS];
    size_t evN;
    UA_ByteString tlFile;
    size_t tlPos;
    UA_UInt32 tlHandle;
    size_t tlSession; /* the session that holds tlHandle */
    gds_buf cert, key;
    fg_session sess[FG_MAX_SESSIONS];
    size_t sessN;
    UA_StatusCode (*origActivate)(UA_Server *, UA_AccessControl *, const UA_EndpointDescription *,
                                  const UA_ByteString *, const UA_NodeId *,
                                  const UA_ExtensionObject *, void **);
    void (*origClose)(UA_Server *, UA_AccessControl *, const UA_NodeId *, void *);
    char url[64], caPath[GDS_MAX_PATH], crlPath[GDS_MAX_PATH], pwPath[GDS_MAX_PATH];
} G;

static const char *const methodNames[FG_M_COUNT] = {
    "FindApplications", "RegisterApplication", "GetCertificateGroups", "GetCertificateStatus",
    "StartSigningRequest", "StartNewKeyPairRequest", "FinishRequest", "GetTrustList",
    "TrustList.Open", "TrustList.Read", "TrustList.Close"};

const char *fg_method_name(fg_method m) {
    return (size_t)m < FG_M_COUNT ? methodNames[m] : "?";
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static const UA_DataType *rec_type(void) {
    return &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE];
}

UA_NodeId fg_default_group(void) {
    return UA_NODEID_NUMERIC(G.ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
}

UA_NodeId fg_listed_cert_type(void) {
    return UA_NODEID_NUMERIC(0, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
}

const char *fg_url(void) { return G.url; }
const char *fg_ca_path(void) { return G.caPath; }
const char *fg_crl_path(void) { return G.crlPath; }
const char *fg_password_path(void) { return G.pwPath; }

static UA_StatusCode touch_trustlist(void) {
    UA_DateTime t = UA_DateTime_now();
    UA_Variant v;
    UA_Variant_setScalar(&v, &t, &UA_TYPES[UA_TYPES_DATETIME]);
    return UA_Server_writeValue(
        G.server,
        UA_NODEID_NUMERIC(G.ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_LASTUPDATETIME),
        v);
}

void fg_set_behaviour(const fg_behaviour *b) {
    G.b = *b;
    if(b->tlChanged && G.server && touch_trustlist() != UA_STATUSCODE_GOOD)
        fprintf(stderr, "fake GDS: cannot set TrustList.LastUpdateTime\n");
}

size_t fg_session_count(void) {
    return G.sessN;
}

const fg_session *fg_session_at(size_t i) {
    return i < G.sessN ? &G.sess[i] : NULL;
}

static size_t find_session(const UA_NodeId *id) {
    for(size_t i = G.sessN; id && i-- > 0;)
        if(UA_NodeId_equal(&G.sess[i].id, id))
            return i;
    return FG_NO_SESSION;
}

size_t fg_event_count(void) {
    return G.evN;
}

const fg_event *fg_event_at(size_t i) {
    return i < G.evN ? &G.ev[i] : NULL;
}

static fg_app *find_app(const UA_NodeId *id) {
    for(size_t i = 0; i < G.appsN; i++)
        if(UA_NodeId_equal(&G.apps[i].rec.applicationId, id))
            return &G.apps[i];
    return NULL;
}

static void copy_uri(char *dst, const UA_String *s) {
    size_t n = s->length < FG_MAX_URI - 1 ? s->length : FG_MAX_URI - 1;
    if(n)
        memcpy(dst, s->data, n);
    dst[n] = '\0';
}

/* Remember which record a call names (its ApplicationUri, type, URLs). */
static void note_app(fg_event *ev, const fg_app *a) {
    if(!a)
        return;
    copy_uri(ev->appUri, &a->rec.applicationUri);
    ev->appType = a->rec.applicationType;
    ev->discoveryUrlsN = a->rec.discoveryUrlsSize;
    if(a->rec.discoveryUrlsSize > 0)
        copy_uri(ev->discoveryUrl0, &a->rec.discoveryUrls[0]);
}

/* Keep every ByteString and String argument for the private key scan. */
static void capture_args(fg_event *ev, size_t inN, const UA_Variant *in) {
    for(size_t i = 0; i < inN; i++) {
        if(!UA_Variant_isScalar(&in[i]))
            continue;
        const UA_DataType *t = in[i].type;
        if(t != &UA_TYPES[UA_TYPES_BYTESTRING] && t != &UA_TYPES[UA_TYPES_STRING])
            continue;
        const UA_ByteString *b = (const UA_ByteString *)in[i].data;
        if(b->length && gds_buf_append(&ev->args, b->data, b->length, FG_MAX_ARGS_BYTES) != GDS_OK)
            return; /* bounded: the scan sees the first 64 KiB */
    }
}

typedef UA_StatusCode (*fg_handler)(fg_event *ev, size_t inN, const UA_Variant *in,
                                    UA_Variant *out);

static UA_StatusCode dispatch(fg_method m, fg_handler h, const UA_NodeId *sessionId, size_t inN,
                              const UA_Variant *in, UA_Variant *out) {
    if(G.evN == FG_MAX_EVENTS)
        return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
    fg_event *ev = &G.ev[G.evN++];
    memset(ev, 0, sizeof(*ev));
    ev->method = m;
    ev->tMs = now_ms();
    ev->session = find_session(sessionId);
    capture_args(ev, inN, in);
    ev->result = h(ev, inN, in, out);
    return ev->result;
}

/* ---- Directory methods ---------------------------------------------- */

static UA_StatusCode h_find(fg_event *ev, size_t inN, const UA_Variant *in, UA_Variant *out) {
    if(inN < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const UA_String *uri = NULL;
    UA_StatusCode r = gds_arg_string(&in[0], GDS_MAX_APPLICATION_URI, &uri);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    copy_uri(ev->appUri, uri);
    for(size_t i = 0; i < G.appsN; i++) {
        if(UA_String_equal(&G.apps[i].rec.applicationUri, uri)) {
            note_app(ev, &G.apps[i]);
            return UA_Variant_setArrayCopy(&out[0], &G.apps[i].rec, 1, rec_type());
        }
    }
    UA_Variant_setArray(&out[0], UA_EMPTY_ARRAY_SENTINEL, 0, rec_type());
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode h_register(fg_event *ev, size_t inN, const UA_Variant *in,
                                UA_Variant *out) {
    if(inN < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const void *p = NULL;
    UA_StatusCode r = gds_arg_scalar(&in[0], rec_type(), &p);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_ApplicationRecordDataType *rec = p;
    if(rec->applicationUri.length == 0 || rec->applicationUri.length > GDS_MAX_APPLICATION_URI ||
       rec->discoveryUrlsSize > GDS_MAX_ARRAY_FIELD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    for(size_t i = 0; i < G.appsN; i++)
        if(UA_String_equal(&G.apps[i].rec.applicationUri, &rec->applicationUri))
            return UA_STATUSCODE_BADENTRYEXISTS; /* 12 §6.5.6 */
    if(G.appsN == FG_MAX_APPS)
        return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
    fg_app *a = &G.apps[G.appsN];
    memset(a, 0, sizeof(*a));
    if((r = UA_copy(rec, &a->rec, rec_type())) != UA_STATUSCODE_GOOD)
        return r;
    UA_NodeId_clear(&a->rec.applicationId);
    a->rec.applicationId = UA_NODEID_GUID(G.ns, UA_Guid_random());
    r = UA_Variant_setScalarCopy(&out[0], &a->rec.applicationId, &UA_TYPES[UA_TYPES_NODEID]);
    if(r != UA_STATUSCODE_GOOD) {
        UA_clear(&a->rec, rec_type());
        return r;
    }
    G.appsN++;
    note_app(ev, a);
    return UA_STATUSCODE_GOOD;
}

/* The first argument of most Directory methods: a known ApplicationId */
static UA_StatusCode arg_app(fg_event *ev, size_t inN, const UA_Variant *in, size_t need,
                             fg_app **a) {
    if(inN < need)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const void *p = NULL;
    UA_StatusCode r = gds_arg_scalar(&in[0], &UA_TYPES[UA_TYPES_NODEID], &p);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    *a = find_app(p);
    if(!*a)
        return UA_STATUSCODE_BADNOTFOUND;
    note_app(ev, *a);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode h_groups(fg_event *ev, size_t inN, const UA_Variant *in, UA_Variant *out) {
    fg_app *a = NULL;
    UA_StatusCode r = arg_app(ev, inN, in, 1, &a);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_NodeId g = fg_default_group();
    return UA_Variant_setArrayCopy(&out[0], &g, 1, &UA_TYPES[UA_TYPES_NODEID]);
}

static UA_StatusCode h_status(fg_event *ev, size_t inN, const UA_Variant *in, UA_Variant *out) {
    fg_app *a = NULL;
    UA_StatusCode r = arg_app(ev, inN, in, 1, &a);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Boolean update = G.b.forceUpdateRequired || !a->hasCert;
    return UA_Variant_setScalarCopy(&out[0], &update, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

/* Group and type NodeIds of a signing or key pair request */
static UA_StatusCode note_group_type(fg_event *ev, const UA_Variant *in) {
    const void *g = NULL, *t = NULL;
    UA_StatusCode r = gds_arg_scalar(&in[1], &UA_TYPES[UA_TYPES_NODEID], &g);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_scalar(&in[2], &UA_TYPES[UA_TYPES_NODEID], &t);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_NodeId_copy(g, &ev->group);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_NodeId_copy(t, &ev->certType);
    return r;
}

static UA_StatusCode new_request(const UA_NodeId *appId, const gds_buf *csr, UA_NodeId *idOut,
                                 UA_Variant *out) {
    if(G.reqsN == FG_MAX_REQS)
        return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
    fg_req *q = &G.reqs[G.reqsN];
    memset(q, 0, sizeof(*q));
    if(gds_buf_dup(csr->data, csr->len, &q->csr) != GDS_OK)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    if(UA_NodeId_copy(appId, &q->appId) != UA_STATUSCODE_GOOD) {
        gds_buf_free(&q->csr);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    q->requestId = UA_NODEID_GUID(G.ns, UA_Guid_random());
    UA_StatusCode r = UA_Variant_setScalarCopy(&out[0], &q->requestId, &UA_TYPES[UA_TYPES_NODEID]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_NodeId_copy(&q->requestId, idOut);
    if(r != UA_STATUSCODE_GOOD) {
        gds_buf_free(&q->csr);
        UA_NodeId_clear(&q->appId);
        return r;
    }
    G.reqsN++;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode h_sign(fg_event *ev, size_t inN, const UA_Variant *in, UA_Variant *out) {
    fg_app *a = NULL;
    UA_StatusCode r = arg_app(ev, inN, in, 4, &a);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_ByteString *csr = NULL;
    if((r = note_group_type(ev, in)) != UA_STATUSCODE_GOOD ||
       (r = gds_arg_bytes(&in[3], GDS_MAX_CSR_SIZE, &csr)) != UA_STATUSCODE_GOOD)
        return r;
    if(csr->length && gds_buf_dup(csr->data, csr->length, &ev->csr) != GDS_OK)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    if(G.b.signResult != UA_STATUSCODE_GOOD)
        return G.b.signResult; /* fault on cue */
    if(csr->length == 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return new_request(&a->rec.applicationId, &ev->csr, &ev->requestId, out);
}

/* The fake GDS issues certificates only from CSRs (12 §7.9.4 allows a
 * CertificateManager to refuse with Bad_RequestNotAllowed). The call is
 * recorded, which is what CLI-CSR-09 looks for. */
static UA_StatusCode h_newkeypair(fg_event *ev, size_t inN, const UA_Variant *in,
                                  UA_Variant *out) {
    (void)out;
    fg_app *a = NULL;
    UA_StatusCode r = arg_app(ev, inN, in, 3, &a);
    if(r == UA_STATUSCODE_GOOD)
        r = note_group_type(ev, in);
    return r != UA_STATUSCODE_GOOD ? r : UA_STATUSCODE_BADREQUESTNOTALLOWED;
}

static UA_StatusCode issue(fg_app *a, fg_req *q, UA_Variant *out) {
    char uri[GDS_MAX_APPLICATION_URI + 1];
    if(gds_path(uri, sizeof(uri), "%.*s", (int)a->rec.applicationUri.length,
                (const char *)a->rec.applicationUri.data) != GDS_OK)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    gds_buf cert = {0}, caDer = {0};
    if(testca_sign_csr(&G.ca, &q->csr, uri, TESTCA_MAX_DAYS, &cert) != GDS_OK)
        return UA_STATUSCODE_BADREQUESTNOTALLOWED; /* no proof of possession */
    if(testca_cert_der(&G.ca, &caDer) != GDS_OK) {
        gds_buf_free(&cert);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_ByteString c = {cert.len, cert.data}, empty = UA_BYTESTRING_NULL;
    UA_ByteString issuer = {caDer.len, caDer.data};
    UA_StatusCode r = UA_Variant_setScalarCopy(&out[0], &c, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&out[1], &empty, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setArrayCopy(&out[2], &issuer, 1, &UA_TYPES[UA_TYPES_BYTESTRING]);
    gds_buf_free(&caDer);
    gds_buf_free(&cert);
    if(r == UA_STATUSCODE_GOOD) {
        q->done = true;
        a->hasCert = true;
    }
    return r;
}

static UA_StatusCode h_finish(fg_event *ev, size_t inN, const UA_Variant *in, UA_Variant *out) {
    fg_app *a = NULL;
    UA_StatusCode r = arg_app(ev, inN, in, 2, &a);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const void *rid = NULL;
    if((r = gds_arg_scalar(&in[1], &UA_TYPES[UA_TYPES_NODEID], &rid)) != UA_STATUSCODE_GOOD ||
       (r = UA_NodeId_copy(rid, &ev->requestId)) != UA_STATUSCODE_GOOD)
        return r;
    fg_req *q = NULL;
    for(size_t i = 0; i < G.reqsN && !q; i++)
        if(UA_NodeId_equal(&G.reqs[i].requestId, rid) &&
           UA_NodeId_equal(&G.reqs[i].appId, &a->rec.applicationId))
            q = &G.reqs[i];
    if(!q)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(q->done)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(q->rejected)
        return UA_STATUSCODE_BADREQUESTNOTALLOWED;
    if(G.b.finishResult != UA_STATUSCODE_GOOD) {
        q->rejected = true; /* the CertificateManager rejected it (12 §7.9.5) */
        return G.b.finishResult;
    }
    if(q->polls < G.b.approveAfter) {
        q->polls++;
        return UA_STATUSCODE_BADNOTHINGTODO;
    }
    return issue(a, q, out);
}

static UA_StatusCode h_trustlist(fg_event *ev, size_t inN, const UA_Variant *in,
                                 UA_Variant *out) {
    fg_app *a = NULL;
    UA_StatusCode r = arg_app(ev, inN, in, 1, &a);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_NodeId tl = UA_NODEID_NUMERIC(
        G.ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST);
    return UA_Variant_setScalarCopy(&out[0], &tl, &UA_TYPES[UA_TYPES_NODEID]);
}

/* ---- TrustList (FileType, read only): the CA and its CRL ------------ */

static UA_StatusCode encode_trustlist(void) {
    gds_buf caDer = {0}, crl = {0};
    if(testca_cert_der(&G.ca, &caDer) != GDS_OK || testca_crl_der(&G.ca, &crl) != GDS_OK) {
        gds_buf_free(&caDer);
        gds_buf_free(&crl);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_ByteString c = {caDer.len, caDer.data}, l = {crl.len, crl.data};
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    tl.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    tl.trustedCertificates = &c;
    tl.trustedCertificatesSize = 1;
    tl.trustedCrls = &l;
    tl.trustedCrlsSize = 1;
    UA_ByteString_clear(&G.tlFile);
    UA_StatusCode r = UA_encodeBinary(&tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &G.tlFile, NULL);
    gds_buf_free(&caDer);
    gds_buf_free(&crl);
    return r;
}

size_t fg_trustlist_size(void) {
    if(G.tlFile.length == 0 && encode_trustlist() != UA_STATUSCODE_GOOD)
        return 0;
    return G.tlFile.length;
}

static UA_StatusCode h_tl_open(fg_event *ev, size_t inN, const UA_Variant *in, UA_Variant *out) {
    if(inN < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const void *mode = NULL;
    UA_StatusCode r = gds_arg_scalar(&in[0], &UA_TYPES[UA_TYPES_BYTE], &mode);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(*(const UA_Byte *)mode != 0x01)
        return UA_STATUSCODE_BADNOTWRITABLE;
    /* One open handle per session; a handle left open by a session that
     * has ended (CLI-TL-02) does not block the next cycle. */
    if(G.tlHandle && G.tlSession == ev->session)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if((r = encode_trustlist()) != UA_STATUSCODE_GOOD)
        return r;
    UA_UInt32 h = 0;
    while(h == 0)
        if(RAND_bytes((unsigned char *)&h, sizeof(h)) != 1)
            return UA_STATUSCODE_BADINTERNALERROR;
    G.tlPos = 0;
    G.tlHandle = h;
    G.tlSession = ev->session;
    return UA_Variant_setScalarCopy(&out[0], &G.tlHandle, &UA_TYPES[UA_TYPES_UINT32]);
}

static UA_StatusCode h_tl_read(fg_event *ev, size_t inN, const UA_Variant *in, UA_Variant *out) {
    if(inN < 2)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const void *hp = NULL, *lp = NULL;
    UA_StatusCode r = gds_arg_scalar(&in[0], &UA_TYPES[UA_TYPES_UINT32], &hp);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_scalar(&in[1], &UA_TYPES[UA_TYPES_INT32], &lp);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Int32 len = *(const UA_Int32 *)lp;
    if(!G.tlHandle || *(const UA_UInt32 *)hp != G.tlHandle || len < 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    size_t n = G.tlFile.length - G.tlPos;
    if((size_t)len < n)
        n = (size_t)len;
    if(G.b.tlReadMax && n > G.b.tlReadMax)
        n = G.b.tlReadMax; /* allowed: OPC 10000-20 §4.2.4 */
    ev->bytes = n;
    UA_ByteString chunk = {n, n ? G.tlFile.data + G.tlPos : NULL};
    r = UA_Variant_setScalarCopy(&out[0], &chunk, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        G.tlPos += n;
    return r;
}

static UA_StatusCode h_tl_close(fg_event *ev, size_t inN, const UA_Variant *in,
                                UA_Variant *out) {
    (void)ev;
    (void)out;
    if(inN < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const void *hp = NULL;
    UA_StatusCode r = gds_arg_scalar(&in[0], &UA_TYPES[UA_TYPES_UINT32], &hp);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(!G.tlHandle || *(const UA_UInt32 *)hp != G.tlHandle)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    G.tlHandle = 0;
    return UA_STATUSCODE_GOOD;
}

/* ---- server glue ----------------------------------------------------- */

#define CALLBACK(name, m, h)                                                                \
    static UA_StatusCode name(UA_Server *server, const UA_NodeId *sessionId,                \
                              void *sessionContext, const UA_NodeId *methodId,              \
                              void *methodContext, const UA_NodeId *objectId,               \
                              void *objectContext, size_t inputSize,                        \
                              const UA_Variant *input, size_t outputSize,                   \
                              UA_Variant *output) {                                         \
        (void)server; (void)sessionContext; (void)methodId;                \
        (void)methodContext; (void)objectId; (void)objectContext; (void)outputSize;         \
        return dispatch(m, h, sessionId, inputSize, input, output);                                    \
    }
CALLBACK(cb_find, FG_M_FIND, h_find)
CALLBACK(cb_register, FG_M_REGISTER, h_register)
CALLBACK(cb_groups, FG_M_GROUPS, h_groups)
CALLBACK(cb_status, FG_M_STATUS, h_status)
CALLBACK(cb_sign, FG_M_SIGN, h_sign)
CALLBACK(cb_newkeypair, FG_M_NEWKEYPAIR, h_newkeypair)
CALLBACK(cb_finish, FG_M_FINISH, h_finish)
CALLBACK(cb_trustlist, FG_M_TRUSTLIST, h_trustlist)
CALLBACK(cb_tl_open, FG_M_TL_OPEN, h_tl_open)
CALLBACK(cb_tl_read, FG_M_TL_READ, h_tl_read)
CALLBACK(cb_tl_close, FG_M_TL_CLOSE, h_tl_close)

static gds_status write_files(const fg_config *cfg) {
    gds_buf crl = {0};
    char caDir[GDS_MAX_PATH];
    gds_status r;
    if((r = gds_path(caDir, sizeof(caDir), "%s/ca", cfg->workDir)) != GDS_OK ||
       (r = gds_path(G.caPath, sizeof(G.caPath), "%s/ca.der", caDir)) != GDS_OK ||
       (r = gds_path(G.crlPath, sizeof(G.crlPath), "%s/ca.crl", caDir)) != GDS_OK ||
       (r = gds_path(G.pwPath, sizeof(G.pwPath), "%s/registrar.pw", cfg->workDir)) != GDS_OK)
        return r;
    if((r = testca_load_or_create(&G.ca, caDir, "OpenGDS Auditor TEST fake GDS CA")) != GDS_OK)
        return r;
    if((r = testca_crl_der(&G.ca, &crl)) == GDS_OK)
        r = gds_file_write_atomic(G.crlPath, crl.data, crl.len, 0644);
    gds_buf_free(&crl);
    if(r == GDS_OK)
        r = gds_file_write_atomic(G.pwPath, cfg->password, strlen(cfg->password), 0600);
    if(r == GDS_OK)
        r = testca_identity(&G.ca, caDir, "fakegds", "OpenGDS Auditor TEST fake GDS", FG_APP_URI,
                            &G.cert, &G.key);
    return r;
}

static fg_token token_type(const UA_ExtensionObject *t) {
    if(!t || t->encoding == UA_EXTENSIONOBJECT_ENCODED_NOBODY)
        return FG_TOKEN_ANONYMOUS;
    if(t->encoding < UA_EXTENSIONOBJECT_DECODED)
        return FG_TOKEN_OTHER;
    const UA_DataType *ty = t->content.decoded.type;
    if(ty == &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN])
        return FG_TOKEN_ANONYMOUS;
    if(ty == &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN])
        return FG_TOKEN_USERNAME;
    if(ty == &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN])
        return FG_TOKEN_X509;
    return FG_TOKEN_OTHER;
}

/* Record every activated session: its channel security, its client
 * certificate and the kind of identity token (Annex G.1, 12 §6.3). */
static UA_StatusCode fg_activate(UA_Server *server, UA_AccessControl *ac,
                                 const UA_EndpointDescription *ep, const UA_ByteString *cert,
                                 const UA_NodeId *sessionId, const UA_ExtensionObject *token,
                                 void **sessionContext) {
    UA_StatusCode r = G.origActivate(server, ac, ep, cert, sessionId, token, sessionContext);
    if(r != UA_STATUSCODE_GOOD || find_session(sessionId) != FG_NO_SESSION ||
       G.sessN == FG_MAX_SESSIONS)
        return r;
    fg_session *s = &G.sess[G.sessN];
    memset(s, 0, sizeof(*s));
    if(UA_NodeId_copy(sessionId, &s->id) != UA_STATUSCODE_GOOD)
        return r;
    s->mode = ep ? ep->securityMode : UA_MESSAGESECURITYMODE_INVALID;
    s->token = token_type(token);
    s->tOpen = now_ms();
    if(cert && cert->length && cert->length <= GDS_MAX_CERT_SIZE) {
        gds_buf c = {cert->data, cert->length};
        if(x509_san_uri(&c, s->certUri, sizeof(s->certUri)) != GDS_OK)
            s->certUri[0] = '\0';
    }
    G.sessN++;
    return r;
}

static void fg_close(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sessionId,
                     void *sessionContext) {
    size_t i = find_session(sessionId);
    if(i != FG_NO_SESSION && !G.sess[i].closed) {
        G.sess[i].closed = true;
        G.sess[i].tClose = now_ms();
    }
    G.origClose(server, ac, sessionId, sessionContext);
}

static UA_StatusCode configure(UA_ServerConfig *config, const fg_config *cfg) {
    UA_ByteString c = {G.cert.len, G.cert.data}, k = {G.key.len, G.key.data};
    UA_StatusCode r = UA_ServerConfig_setDefaultWithSecureSecurityPolicies(
        config, (UA_UInt16)cfg->port, &c, &k, NULL, 0, NULL, 0, NULL, 0);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(gds_path(G.url, sizeof(G.url), "opc.tcp://%s:%ld", cfg->listenAny ? "localhost" : "127.0.0.1",
                cfg->port) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    if(!cfg->listenAny) {
        UA_Array_delete(config->serverUrls, config->serverUrlsSize, &UA_TYPES[UA_TYPES_STRING]);
        config->serverUrls = UA_String_new();
        if(!config->serverUrls)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        *config->serverUrls = UA_STRING_ALLOC(G.url);
        config->serverUrlsSize = 1;
    }
    if((r = UA_ServerConfig_addSecurityPolicyNone(config, &c)) != UA_STATUSCODE_GOOD)
        return r;
    config->securityPolicyNoneDiscoveryOnly = true;
    config->allowNonePolicyPassword = false;
    UA_String_clear(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri = UA_STRING_ALLOC(FG_APP_URI);
    config->applicationDescription.applicationType = UA_APPLICATIONTYPE_SERVER;
    /* A client comes for its first certificate before it is trusted
     * (Annex G.1 step 2): accept any client certificate, check the user. */
    config->secureChannelPKI.clear(&config->secureChannelPKI);
    UA_CertificateGroup_AcceptAll(&config->secureChannelPKI);
    config->sessionPKI.clear(&config->sessionPKI);
    UA_CertificateGroup_AcceptAll(&config->sessionPKI);
    UA_UsernamePasswordLogin login = {UA_STRING((char *)(uintptr_t)cfg->user),
                                      UA_STRING((char *)(uintptr_t)cfg->password)};
    config->accessControl.clear(&config->accessControl);
    UA_String policy = UA_STRING_STATIC("http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss");
    /* Anonymous too: a client that holds its certificate renews as
     * ApplicationSelfAdmin (Annex G.1) */
    UA_StatusCode r2 = UA_AccessControl_default(config, true, &policy, 1, &login);
    if(r2 != UA_STATUSCODE_GOOD)
        return r2;
    G.origActivate = config->accessControl.activateSession;
    G.origClose = config->accessControl.closeSession;
    config->accessControl.activateSession = fg_activate;
    config->accessControl.closeSession = fg_close;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode bind_methods(void) {
    const struct {
        UA_UInt32 id;
        UA_MethodCallback cb;
    } m[] = {
        {UA_GDSID_DIRECTORY_FINDAPPLICATIONS, cb_find},
        {UA_GDSID_DIRECTORY_REGISTERAPPLICATION, cb_register},
        {UA_GDSID_DIRECTORY_GETCERTIFICATEGROUPS, cb_groups},
        {UA_GDSID_DIRECTORY_GETCERTIFICATESTATUS, cb_status},
        {UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, cb_sign},
        {UA_GDSID_DIRECTORY_STARTNEWKEYPAIRREQUEST, cb_newkeypair},
        {UA_GDSID_DIRECTORY_FINISHREQUEST, cb_finish},
        {UA_GDSID_DIRECTORY_GETTRUSTLIST, cb_trustlist},
        {UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPEN, cb_tl_open},
        {UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_READ, cb_tl_read},
        {UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSE, cb_tl_close},
    };
    for(size_t i = 0; i < GDS_ARRAY_SIZE(m); i++) {
        UA_StatusCode r =
            UA_Server_setMethodNodeCallback(G.server, UA_NODEID_NUMERIC(G.ns, m[i].id), m[i].cb);
        if(r != UA_STATUSCODE_GOOD)
            return r;
    }
    /* DefaultApplicationGroup.CertificateTypes: the one type it issues */
    UA_NodeId t = fg_listed_cert_type();
    UA_Variant v;
    UA_Variant_setArray(&v, &t, 1, &UA_TYPES[UA_TYPES_NODEID]);
    return UA_Server_writeValue(
        G.server,
        UA_NODEID_NUMERIC(G.ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_CERTIFICATETYPES),
        v);
}

/* The nodeset autoloader logs to the global UA_Log_Stdout, whatever the
 * config says; stdout carries TAP, so it goes to /dev/null meanwhile. */
static UA_Server *new_server_quietly(UA_ServerConfig *sc) {
    fflush(stdout);
    int saved = dup(STDOUT_FILENO);
    int null = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if(saved >= 0 && null >= 0)
        (void)dup2(null, STDOUT_FILENO);
    UA_Server *server = UA_Server_newWithConfig(sc);
    fflush(stdout);
    if(saved >= 0) {
        (void)dup2(saved, STDOUT_FILENO);
        close(saved);
    }
    if(null >= 0)
        close(null);
    return server;
}

gds_status fg_start(const fg_config *cfg) {
    memset(&G, 0, sizeof(G));
    gds_status s = write_files(cfg);
    if(s != GDS_OK)
        return s;
    /* Quiet logger: stdout carries the TAP report */
    UA_ServerConfig sc;
    memset(&sc, 0, sizeof(sc));
    sc.logging = UA_Log_Stdout_new(UA_LOGLEVEL_FATAL);
    if(!sc.logging)
        return GDS_ENOMEM;
    UA_StatusCode r = configure(&sc, cfg);
    if(r != UA_STATUSCODE_GOOD) {
        UA_ServerConfig_clear(&sc);
        fprintf(stderr, "fake GDS config: %s\n", UA_StatusCode_name(r));
        return GDS_EREMOTE;
    }
    G.server = new_server_quietly(&sc);
    if(!G.server)
        return GDS_ENOMEM;
    if(r == UA_STATUSCODE_GOOD) {
        G.ns = UA_Server_addNamespace(G.server, GDS_NS_URI);
        r = bind_methods();
        if(r == UA_STATUSCODE_GOOD)
            r = touch_trustlist();
    }
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_run_startup(G.server);
    if(r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "fake GDS: %s\n", UA_StatusCode_name(r));
        fg_stop();
        return GDS_EREMOTE;
    }
    return GDS_OK;
}

void fg_iterate(void) {
    if(G.server)
        (void)UA_Server_run_iterate(G.server, true);
}

void fg_stop(void) {
    if(G.server) {
        (void)UA_Server_run_shutdown(G.server);
        UA_Server_delete(G.server);
        G.server = NULL;
    }
    UA_ByteString_clear(&G.tlFile);
    for(size_t i = 0; i < G.appsN; i++)
        UA_clear(&G.apps[i].rec, rec_type());
    for(size_t i = 0; i < G.reqsN; i++) {
        gds_buf_free(&G.reqs[i].csr);
        UA_NodeId_clear(&G.reqs[i].requestId);
        UA_NodeId_clear(&G.reqs[i].appId);
    }
    for(size_t i = 0; i < G.evN; i++) {
        gds_buf_free(&G.ev[i].csr);
        gds_buf_free(&G.ev[i].args);
        UA_NodeId_clear(&G.ev[i].group);
        UA_NodeId_clear(&G.ev[i].certType);
        UA_NodeId_clear(&G.ev[i].requestId);
    }
    for(size_t i = 0; i < G.sessN; i++)
        UA_NodeId_clear(&G.sess[i].id);
    G.appsN = G.reqsN = G.evN = G.sessN = 0;
    gds_buf_free(&G.cert);
    gds_buf_free_secret(&G.key);
    testca_free(&G.ca);
}
