/* OpenGDS unit test: SQLite store (src/store).
 * SPDX-License-Identifier: MPL-2.0 */
#include <sqlite3.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"
#include "common/buf.h"
#include "common/ids.h"
#include "store.h"
#include "store_backend.h"
#include "common/banned.h"

static UA_Guid rnd_guid(void) {
    UA_Guid g;
    UA_Guid_init(&g);
    CHECK(gds_guid_random(&g) == GDS_OK);
    return g;
}

static void make_record(UA_ApplicationRecordDataType *rec, const char *uri,
                        UA_LocalizedText *name) {
    UA_ApplicationRecordDataType_init(rec);
    rec->applicationUri = UA_STRING((char *)(uintptr_t)uri);
    rec->applicationType = UA_APPLICATIONTYPE_CLIENT;
    *name = UA_LOCALIZEDTEXT("en", "Unit test app");
    rec->applicationNames = name;
    rec->applicationNamesSize = 1;
    rec->productUri = UA_STRING("urn:opengds:test:product");
}

static void test_apps(gds_store *s, const UA_Guid *id, const UA_Guid *id2) {
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    make_record(&rec, "urn:opengds:test:a", &name);
    CHECK(gds_store_app_insert(s, id, &rec) == GDS_OK);
    CHECK(gds_store_app_insert(s, id2, &rec) == GDS_EEXISTS);

    UA_ApplicationRecordDataType *found = NULL;
    size_t n = 0;
    UA_String uri = UA_STRING("urn:opengds:test:a");
    CHECK(gds_store_app_find_uri(s, &uri, 10, &found, &n) == GDS_OK);
    if(CHECK_EQ_INT(n, 1)) {
        CHECK(found[0].applicationId.identifierType == UA_NODEIDTYPE_GUID &&
              UA_Guid_equal(&found[0].applicationId.identifier.guid, id));
        CHECK(UA_String_equal(&found[0].applicationUri, &uri));
        CHECK_EQ_INT(found[0].applicationNamesSize, 1);
    }
    UA_Array_delete(found, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    UA_String none = UA_STRING("urn:opengds:test:none");
    CHECK(gds_store_app_find_uri(s, &none, 10, &found, &n) == GDS_OK && n == 0 && !found);

    UA_ApplicationRecordDataType got;
    CHECK(gds_store_app_get(s, id, &got) == GDS_OK);
    CHECK(UA_String_equal(&got.applicationUri, &uri));
    UA_ApplicationRecordDataType_clear(&got);
    CHECK(gds_store_app_get(s, id2, &got) == GDS_ENOTFOUND);
}

/* Received -> Issued */
static void test_requests(gds_store *s, const UA_Guid *appId) {
    gds_request q;
    memset(&q, 0, sizeof(q));
    q.id = rnd_guid();
    q.appId = *appId;
    q.groupId = 615;
    q.certType = 12557;
    q.state = GDS_REQ_RECEIVED;
    uint8_t csr[] = {0x30, 0x03, 0x02, 0x01, 0x00};
    q.csr.data = csr;
    q.csr.len = sizeof(csr);
    CHECK(gds_store_req_insert(s, &q) == GDS_OK);
    gds_request next;
    CHECK(gds_store_req_next_received(s, &next) == GDS_OK);
    CHECK(UA_Guid_equal(&next.id, &q.id) && next.csr.len == sizeof(csr));
    gds_request_clear(&next);
    gds_buf cert = {csr, sizeof(csr)};
    CHECK(gds_store_req_set_state(s, &q.id, GDS_REQ_ISSUED, &cert, UA_STATUSCODE_GOOD) == GDS_OK);
    CHECK(gds_store_req_next_received(s, &next) == GDS_ENOTFOUND);
    CHECK(gds_store_req_get(s, &q.id, &next) == GDS_OK);
    CHECK_EQ_INT(next.state, GDS_REQ_ISSUED);
    CHECK_EQ_INT(next.cert.len, sizeof(csr));
    gds_request_clear(&next);
    UA_Guid unknown = rnd_guid();
    CHECK(gds_store_req_set_state(s, &unknown, GDS_REQ_ISSUED, NULL, 0) == GDS_ENOTFOUND);
}

/* A24: the certificate and Received -> Issued together, once. */
static void issue_checks(gds_store *s, const UA_Guid *appId, const char *what, uint8_t tag) {
    gds_request q;
    memset(&q, 0, sizeof(q));
    q.id = rnd_guid();
    q.appId = *appId;
    q.groupId = 615;
    q.certType = 12557;
    q.state = GDS_REQ_RECEIVED;
    uint8_t csr[] = {0x30, 0x03, 0x02, 0x01, 0x07};
    q.csr = (gds_buf){csr, sizeof(csr)};
    CHECK(gds_store_req_insert(s, &q) == GDS_OK);
    uint8_t ser[] = {0x4a, tag}, ser2[] = {0x4b, tag};
    uint8_t der[] = {0x30, 0x03, 0x02, 0x01, tag};
    gds_buf sb = {ser, sizeof(ser)}, sb2 = {ser2, sizeof(ser2)}, db = {der, sizeof(der)};
    CHECK(gds_store_cert_issue(s, &q.id, appId, 615, 12557, &sb, &db, 10, 20) == GDS_OK);
    gds_request got;
    CHECK(gds_store_req_get(s, &q.id, &got) == GDS_OK);
    CHECK_EQ_INT(got.state, GDS_REQ_ISSUED);
    CHECK(got.cert.len == sizeof(der) && memcmp(got.cert.data, der, sizeof(der)) == 0);
    gds_request_clear(&got);
    bool revoked = true;
    CHECK(gds_store_cert_is_revoked(s, &sb, &revoked) == GDS_OK && !revoked);
    /* Issued already: a second signing of the same request stores nothing */
    CHECK(gds_store_cert_issue(s, &q.id, appId, 615, 12557, &sb2, &db, 10, 20) == GDS_ESTATE);
    revoked = true;
    CHECK(gds_store_cert_is_revoked(s, &sb2, &revoked) == GDS_OK && !revoked); /* no row */
    UA_Guid unknown = rnd_guid();
    CHECK(gds_store_cert_issue(s, &unknown, appId, 615, 12557, &sb2, &db, 10, 20) ==
          GDS_ENOTFOUND);
    /* a taken serial: nothing written, the request stays Received */
    gds_request q2 = q;
    q2.id = rnd_guid();
    CHECK(gds_store_req_insert(s, &q2) == GDS_OK);
    CHECK(gds_store_cert_issue(s, &q2.id, appId, 615, 12557, &sb, &db, 10, 20) == GDS_EEXISTS);
    CHECK(gds_store_req_get(s, &q2.id, &got) == GDS_OK);
    CHECK_EQ_INT(got.state, GDS_REQ_RECEIVED);
    gds_request_clear(&got);
    CHECK(gds_store_req_set_state(s, &q2.id, GDS_REQ_FAILED, NULL, 0) == GDS_OK);
    CHECK(gds_store_cert_issue(s, &q2.id, appId, 615, 12557, &sb2, &db, 10, 20) == GDS_ESTATE);
    CHECK(gds_store_cert_issue(s, NULL, appId, 615, 12557, &sb2, &db, 10, 20) == GDS_EINVAL);
    fprintf(stderr, "cert_issue (%s) checked\n", what);
}

static void test_issue(gds_store *s, const UA_Guid *appId, const char *path) {
    issue_checks(s, appId, "minor 7", 7);
    /* A backend before minor 7: the same answers, from two transactions. */
    gds_store_backend old = gds_store_sqlite_backend;
    old.abi_minor = 6;
    old.struct_size = offsetof(gds_store_backend, cert_issue);
    void *ctx = NULL;
    gds_store *o = NULL;
    if(CHECK(gds_store_sqlite_open(path, false, &ctx) == GDS_OK) &&
       CHECK(gds_store_open_backend(&old, ctx, &o) == GDS_OK) && o) {
        issue_checks(o, appId, "minor 6", 6);
        gds_store_close(o);
    }
}

static bool count_req_cb(void *ctx, const gds_request *r) {
    (void)r;
    (*(int *)ctx)++;
    return true;
}
static bool first_cb(void *ctx, const gds_request *r) {
    *(UA_Guid *)ctx = r->id;
    return false; /* stop after one */
}

/* Pending -> Received, and the scan by state */
static void test_pending(gds_store *s, const UA_Guid *appId) {
    gds_request q;
    memset(&q, 0, sizeof(q));
    q.appId = *appId;
    q.groupId = 615;
    q.certType = 12557;
    q.state = GDS_REQ_PENDING;
    UA_Guid ids[3];
    for(int i = 0; i < 3; i++) {
        ids[i] = q.id = rnd_guid();
        CHECK(gds_store_req_insert(s, &q) == GDS_OK);
    }
    int n = 0;
    CHECK(gds_store_req_scan(s, GDS_REQ_PENDING, count_req_cb, &n) == GDS_OK);
    CHECK_EQ_INT(n, 3);
    UA_Guid first = UA_GUID_NULL;
    CHECK(gds_store_req_scan(s, GDS_REQ_PENDING, first_cb, &first) == GDS_OK);
    CHECK(UA_Guid_equal(&first, &ids[0])); /* oldest first */
    gds_request next;
    CHECK(gds_store_req_next_received(s, &next) == GDS_ENOTFOUND); /* not approved */
    CHECK(gds_store_req_set_state(s, &ids[1], GDS_REQ_RECEIVED, NULL, 0) == GDS_OK);
    CHECK(gds_store_req_next_received(s, &next) == GDS_OK && UA_Guid_equal(&next.id, &ids[1]));
    gds_request_clear(&next);
    CHECK(gds_store_req_set_state(s, &ids[1], GDS_REQ_ISSUED, NULL, 0) == GDS_OK);
    n = 0;
    CHECK(gds_store_req_scan(s, GDS_REQ_PENDING, count_req_cb, &n) == GDS_OK);
    CHECK_EQ_INT(n, 2);
    CHECK(gds_store_req_get(s, &ids[2], &next) == GDS_OK && next.state == GDS_REQ_PENDING);
    gds_request_clear(&next);
}

static void test_certs(gds_store *s, const UA_Guid *id, const UA_Guid *id2) {
    uint8_t serial[] = {1, 2, 3};
    uint8_t body[] = {0x30, 0x03, 0x02, 0x01, 0x00};
    gds_buf ser = {serial, sizeof(serial)};
    gds_buf cert = {body, sizeof(body)};
    CHECK(gds_store_cert_add(s, id, 615, 12557, &ser, &cert, 100, 200) == GDS_OK);
    gds_buf der = {0};
    int64_t notAfter = 0;
    CHECK(gds_store_cert_latest(s, id, 615, 12557, &der, &notAfter) == GDS_OK);
    CHECK(der.len == sizeof(body) && notAfter == 200);
    gds_buf_free(&der);
    CHECK(gds_store_cert_latest(s, id2, 615, 12557, &der, &notAfter) == GDS_ENOTFOUND);
}

static bool count_serial_cb(void *ctx, const gds_buf *serial) {
    int *n = ctx;
    CHECK(serial->len > 0);
    (*n)++;
    return true;
}

static void test_revoke(gds_store *s, const UA_Guid *id, const UA_Guid *id2) {
    uint8_t serial2[] = {4, 5, 6};
    uint8_t body2[] = {0x30, 0x03, 0x02, 0x01, 0x01};
    gds_buf ser2 = {serial2, sizeof(serial2)}, cert2 = {body2, sizeof(body2)};
    CHECK(gds_store_cert_add(s, id, 615, 12557, &ser2, &cert2, 150, 300) == GDS_OK);
    bool revoked = true;
    CHECK(gds_store_cert_is_revoked(s, &ser2, &revoked) == GDS_OK && !revoked);
    /* another application's certificate, or one never issued */
    gds_buf serial = {0};
    CHECK(gds_store_cert_revoke(s, id2, &cert2, &serial) == GDS_ENOTFOUND && !serial.data);
    uint8_t other[] = {0x30, 0x00};
    gds_buf none = {other, sizeof(other)};
    CHECK(gds_store_cert_revoke(s, id, &none, &serial) == GDS_ENOTFOUND);
    /* the newest is revoked: cert_latest falls back to the older one */
    CHECK(gds_store_cert_revoke(s, id, &cert2, &serial) == GDS_OK);
    CHECK(serial.len == sizeof(serial2) && memcmp(serial.data, serial2, sizeof(serial2)) == 0);
    gds_buf_free(&serial);
    CHECK(gds_store_cert_is_revoked(s, &ser2, &revoked) == GDS_OK && revoked);
    CHECK(gds_store_cert_revoke(s, id, &cert2, &serial) == GDS_OK); /* idempotent */
    gds_buf_free(&serial);
    gds_buf der = {0};
    int64_t notAfter = 0;
    CHECK(gds_store_cert_latest(s, id, 615, 12557, &der, &notAfter) == GDS_OK && notAfter == 200);
    gds_buf_free(&der);
    /* every certificate of the application, listed again on a second call */
    int n = 0;
    CHECK(gds_store_cert_revoke_app(s, id, count_serial_cb, &n) == GDS_OK);
    CHECK_EQ_INT(n, 2);
    n = 0;
    CHECK(gds_store_cert_revoke_app(s, id, count_serial_cb, &n) == GDS_OK);
    CHECK_EQ_INT(n, 2);
    CHECK(gds_store_cert_latest(s, id, 615, 12557, &der, &notAfter) == GDS_ENOTFOUND);
    n = 0;
    CHECK(gds_store_cert_revoke_app(s, id2, count_serial_cb, &n) == GDS_OK && n == 0);
    uint8_t unknown[] = {9};
    gds_buf unk = {unknown, 1};
    CHECK(gds_store_cert_is_revoked(s, &unk, &revoked) == GDS_OK && !revoked);
    CHECK(gds_store_cert_is_revoked(s, &(gds_buf){0}, &revoked) == GDS_EINVAL);
}

typedef struct {
    int n;
    int64_t last;
} scan_ctx;

static bool count_cb(void *ctx, int64_t id, const UA_ApplicationRecordDataType *rec) {
    scan_ctx *c = ctx;
    CHECK(id > c->last && rec->applicationUri.length > 0);
    c->last = id;
    c->n++;
    return true;
}

/* ---- the audit log (issue #18) ---- */

typedef struct {
    int n;
    int64_t lastSeq;
} audit_count;

static bool count_row(void *ctx, const gds_audit_row *row) {
    audit_count *c = ctx;
    c->n++;
    c->lastSeq = row->seq;
    return true;
}

static void test_audit(gds_store *s, const char *path) {
    static uint8_t b1[] = "first", b2[] = "second", b3[] = "third";
    gds_buf body1 = {b1, sizeof(b1)}, body2 = {b2, sizeof(b2)}, body3 = {b3, sizeof(b3)};
    int64_t seq = 0, rows = 0, bad = 0;
    CHECK(gds_store_audit_verify(s, &rows, &bad) == GDS_OK && rows == 0); /* empty log */
    CHECK(gds_store_audit_append(s, 1000, &body1, &seq) == GDS_OK && seq == 1);
    CHECK(gds_store_audit_append(s, 2000, &body2, &seq) == GDS_OK && seq == 2);
    CHECK(gds_store_audit_append(s, 3000, &body3, &seq) == GDS_OK && seq == 3);
    gds_buf empty = {NULL, 0};
    CHECK(gds_store_audit_append(s, 1, &empty, &seq) == GDS_EINVAL);
    gds_buf huge = {b1, GDS_MAX_AUDIT_BODY + 1};
    CHECK(gds_store_audit_append(s, 1, &huge, &seq) == GDS_ETOOBIG);
    audit_count c = {0, 0};
    CHECK(gds_store_audit_scan(s, 2, count_row, &c) == GDS_OK && c.n == 2 && c.lastSeq == 3);
    CHECK(gds_store_audit_verify(s, &rows, &bad) == GDS_OK && rows == 3);

    /* the chain by hand: row 1 hashes over 32 zero bytes */
    uint8_t zero[GDS_AUDIT_HASH] = {0}, h1[GDS_AUDIT_HASH], h1b[GDS_AUDIT_HASH];
    CHECK(gds_audit_hash(zero, 1, 1000, &body1, h1) == GDS_OK);
    CHECK(gds_audit_hash(zero, 1, 1001, &body1, h1b) == GDS_OK);
    CHECK(memcmp(h1, h1b, sizeof(h1)) != 0); /* the time is covered */

    /* append-only: the store refuses to change a row */
    sqlite3 *db = NULL;
    if(!CHECK(sqlite3_open(path, &db) == SQLITE_OK))
        return;
    CHECK(sqlite3_exec(db, "UPDATE audit SET time = 5 WHERE seq = 2", NULL, NULL, NULL) != SQLITE_OK);
    CHECK(sqlite3_exec(db, "DELETE FROM audit WHERE seq = 3", NULL, NULL, NULL) != SQLITE_OK);
    /* someone who drops the triggers and edits a row is found */
    CHECK(sqlite3_exec(db, "DROP TRIGGER audit_no_update; "
                           "UPDATE audit SET body = x'00' WHERE seq = 2",
                       NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(db);
    CHECK(gds_store_audit_verify(s, &rows, &bad) == GDS_ESTATE && bad == 2 && rows == 1);
}

static void test_update_delete(gds_store *s) {
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    make_record(&rec, "urn:opengds:test:b", &name);
    UA_Guid b = rnd_guid(), unknown = rnd_guid();
    CHECK(gds_store_app_insert(s, &b, &rec) == GDS_OK);
    /* rename and change the URI */
    UA_LocalizedText newName = UA_LOCALIZEDTEXT("en", "Renamed");
    rec.applicationNames = &newName;
    rec.applicationUri = UA_STRING("urn:opengds:test:b2");
    CHECK(gds_store_app_update(s, &b, &rec) == GDS_OK);
    UA_ApplicationRecordDataType got;
    CHECK(gds_store_app_get(s, &b, &got) == GDS_OK);
    UA_String want = UA_STRING("urn:opengds:test:b2");
    CHECK(UA_String_equal(&got.applicationUri, &want));
    CHECK(got.applicationNamesSize == 1 && UA_String_equal(&got.applicationNames[0].text,
                                                           &newName.text));
    UA_ApplicationRecordDataType_clear(&got);
    /* the URI of another record is taken */
    rec.applicationUri = UA_STRING("urn:opengds:test:a");
    CHECK(gds_store_app_update(s, &b, &rec) == GDS_EEXISTS);
    CHECK(gds_store_app_update(s, &unknown, &rec) == GDS_ENOTFOUND);
    scan_ctx c = {0, 0};
    CHECK(gds_store_app_scan(s, 0, count_cb, &c) == GDS_OK);
    CHECK_EQ_INT(c.n, 2);
    /* records after the given identifier only (12 §6.5.10) */
    scan_ctx tail = {0, c.last - 1};
    CHECK(gds_store_app_scan(s, c.last - 1, count_cb, &tail) == GDS_OK);
    CHECK_EQ_INT(tail.n, 1);
    scan_ctx none = {0, c.last};
    CHECK(gds_store_app_scan(s, c.last, count_cb, &none) == GDS_OK);
    CHECK_EQ_INT(none.n, 0);
    /* an update gives the record a new, higher identifier; b was updated
     * last, so it is last in the scan */
    int64_t before = c.last;
    rec.applicationUri = UA_STRING("urn:opengds:test:b3");
    CHECK(gds_store_app_update(s, &b, &rec) == GDS_OK);
    scan_ctx after = {0, before};
    CHECK(gds_store_app_scan(s, before, count_cb, &after) == GDS_OK);
    CHECK_EQ_INT(after.n, 1);
    CHECK(after.last > before);
    CHECK(gds_store_app_delete(s, &b) == GDS_OK);
    /* and identifiers are not reused after a delete */
    UA_Guid c2 = rnd_guid();
    rec.applicationUri = UA_STRING("urn:opengds:test:c");
    CHECK(gds_store_app_insert(s, &c2, &rec) == GDS_OK);
    scan_ctx newer = {0, after.last};
    CHECK(gds_store_app_scan(s, after.last, count_cb, &newer) == GDS_OK);
    CHECK_EQ_INT(newer.n, 1);
    CHECK(gds_store_app_delete(s, &c2) == GDS_OK);
    CHECK(gds_store_app_delete(s, &b) == GDS_ENOTFOUND);
    CHECK(gds_store_app_get(s, &b, &got) == GDS_ENOTFOUND);
}

/* A schema 2 store (before record_id) keeps its records, in their old
 * order, and gets the counter on top of them. */
static void test_migrate_from_2(const char *dir) {
    char path[1024];
    if(!CHECK(gds_path(path, sizeof(path), "%s/v2.db", dir) == GDS_OK))
        return;
    (void)unlink(path);
    gds_store *s = NULL;
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    UA_Guid a = rnd_guid(), b = rnd_guid(), c = rnd_guid();
    if(!CHECK(gds_store_open(path, &s) == GDS_OK) || !s)
        return;
    make_record(&rec, "urn:opengds:test:m1", &name);
    CHECK(gds_store_app_insert(s, &a, &rec) == GDS_OK);
    rec.applicationUri = UA_STRING("urn:opengds:test:m2");
    CHECK(gds_store_app_insert(s, &b, &rec) == GDS_OK);
    gds_store_close(s);
    /* back to schema 2 by hand */
    sqlite3 *db = NULL;
    if(!CHECK(sqlite3_open(path, &db) == SQLITE_OK))
        return;
    CHECK(sqlite3_exec(db,
                       "DROP TABLE kc_credentials; DROP TABLE kc_requests; "
                       "DROP TABLE trust_lists; DROP TRIGGER applications_record_id_insert; "
                       "DROP TRIGGER applications_record_id_update; DROP TABLE record_counter; "
                       "DROP INDEX applications_record_id; "
                       "ALTER TABLE applications DROP COLUMN record_id; PRAGMA user_version = 2",
                       NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(db);
    if(!CHECK(gds_store_open(path, &s) == GDS_OK) || !s)
        return;
    CHECK_EQ_INT(gds_store_schema_version(s), 5);
    scan_ctx all = {0, 0};
    CHECK(gds_store_app_scan(s, 0, count_cb, &all) == GDS_OK);
    CHECK_EQ_INT(all.n, 2);
    rec.applicationUri = UA_STRING("urn:opengds:test:m3");
    CHECK(gds_store_app_insert(s, &c, &rec) == GDS_OK);
    scan_ctx newer = {0, all.last};
    CHECK(gds_store_app_scan(s, all.last, count_cb, &newer) == GDS_OK);
    CHECK_EQ_INT(newer.n, 1);
    gds_store_close(s);
}

/* Schema 4: one trust list blob per CertificateGroup */
static void test_trust_lists(gds_store *s) {
    gds_buf got = {0};
    int64_t lu = -1;
    CHECK(gds_store_tl_get(s, 615, &got, &lu) == GDS_ENOTFOUND);
    CHECK(got.len == 0 && lu == 0);
    uint8_t a[] = {1, 2, 3}, b[] = {4, 5};
    gds_buf ba = {a, sizeof(a)}, bb = {b, sizeof(b)}, empty = {0};
    CHECK(gds_store_tl_put(s, 615, &empty, 1) == GDS_EINVAL);
    CHECK(gds_store_tl_put(s, 615, &ba, 100) == GDS_OK);
    CHECK(gds_store_tl_put(s, 616, &bb, 200) == GDS_OK);
    CHECK(gds_store_tl_get(s, 615, &got, &lu) == GDS_OK);
    CHECK(got.len == 3 && memcmp(got.data, a, 3) == 0 && lu == 100);
    gds_buf_free(&got);
    CHECK(gds_store_tl_put(s, 615, &bb, 300) == GDS_OK); /* replaces */
    CHECK(gds_store_tl_get(s, 615, &got, &lu) == GDS_OK);
    CHECK(got.len == 2 && memcmp(got.data, b, 2) == 0 && lu == 300);
    gds_buf_free(&got);
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    char path[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(path, sizeof(path), "%s/store.db", argv[1]) == GDS_OK);
    (void)unlink(path);

    gds_store *s = NULL;
    if(!CHECK(gds_store_open(path, &s) == GDS_OK) || !s)
        return CHECK_DONE();
    CHECK_EQ_INT(gds_store_schema_version(s), 5);
    struct stat sb;
    CHECK(stat(path, &sb) == 0 && (sb.st_mode & 0777) == 0640); /* group read: the signer */

    UA_Guid id = rnd_guid(), id2 = rnd_guid();
    test_apps(s, &id, &id2);
    test_requests(s, &id);
    test_pending(s, &id);
    test_certs(s, &id, &id2);
    test_revoke(s, &id, &id2);
    test_update_delete(s);
    test_audit(s, path);
    test_trust_lists(s);
    test_issue(s, &id, path);
    {
        char wal[1040];
        CHECK(gds_path(wal, sizeof(wal), "%s-wal", path) == GDS_OK);
        CHECK(stat(wal, &sb) == 0 && (sb.st_mode & 0777) == 0640); /* SQLite copies the mode */
    }
    gds_store_close(s);
    /* the mode is enforced on every open, not only at creation */
    CHECK(chmod(path, 0600) == 0);
    if(CHECK(gds_store_open(path, &s) == GDS_OK) && s)
        gds_store_close(s);
    CHECK(stat(path, &sb) == 0 && (sb.st_mode & 0777) == 0640);

    /* everything survives a reopen */
    if(CHECK(gds_store_open(path, &s) == GDS_OK) && s) {
        UA_ApplicationRecordDataType got;
        CHECK(gds_store_app_get(s, &id, &got) == GDS_OK);
        UA_ApplicationRecordDataType_clear(&got);
        gds_buf tl = {0};
        int64_t lu = 0;
        CHECK(gds_store_tl_get(s, 615, &tl, &lu) == GDS_OK && tl.len == 2 && lu == 300);
        gds_buf_free(&tl);
        gds_store_close(s);
    }
    test_migrate_from_2(argv[1]);
    return CHECK_DONE();
}
