/* OpenGDS - store on SQLite (WAL, foreign keys, defensive mode).
 * Every statement is prepared with bound parameters; no SQL is built from
 * input. Records are stored as the binary encoding of the standard
 * ApplicationRecordDataType, with the indexed columns next to them.
 * SPDX-License-Identifier: MPL-2.0 */
#include "store.h"

#include <sqlite3.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common/limits.h"
#include "migrate.h"
#include "store_backend.h"
#include "common/banned.h"

typedef struct sq_store sq_store;
struct sq_store {
    sqlite3 *db;
    int version;
};

static const UA_DataType *rec_type(void) {
    return &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE];
}

static void sq_close(void *ctx_);

static int64_t now_s(void) {
    return (int64_t)time(NULL);
}

static gds_status db_err(sq_store *s, const char *what, int rc) {
    fprintf(stderr, "store: %s: %s (%d)\n", what, sqlite3_errmsg(s->db), rc);
    if(rc == SQLITE_CONSTRAINT)
        return GDS_EEXISTS;
    if(rc == SQLITE_NOMEM)
        return GDS_ENOMEM;
    if(rc == SQLITE_TOOBIG)
        return GDS_ETOOBIG;
    return GDS_EIO;
}

/* Create the file with 0640 before SQLite opens it, and enforce the mode on
 * every open (no umask surprises). Group read is for opengds-signer, which
 * runs as its own user in the daemon's group and reads the store to check
 * each request it signs (decision G1). SQLite gives the -wal and -shm files
 * the database file's mode. The store holds no private keys: should one
 * ever be stored (StartNewKeyPairRequest), it must be encrypted first. */
#define STORE_MODE 0640
static gds_status create_store_file(const char *path) {
    int fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, STORE_MODE);
    if(fd < 0)
        return GDS_EIO;
    gds_status r = fchmod(fd, STORE_MODE) == 0 ? GDS_OK : GDS_EIO;
    close(fd);
    return r;
}

/* Open the connection with the defensive settings shared by both modes. */
static gds_status open_db(const char *path, int flags, sq_store **out) {
    *out = NULL;
    sq_store *s = calloc(1, sizeof(*s));
    if(!s)
        return GDS_ENOMEM;
    int rc = sqlite3_open_v2(path, &s->db, flags | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW,
                             NULL);
    if(rc != SQLITE_OK) {
        gds_status r = s->db ? db_err(s, "open", rc) : GDS_ENOMEM;
        sq_close(s);
        return r;
    }
    /* Defensive settings: no schema tricks from a tampered file, bounded rows */
    sqlite3_db_config(s->db, SQLITE_DBCONFIG_DEFENSIVE, 1, NULL);
    sqlite3_db_config(s->db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, NULL);
    sqlite3_db_config(s->db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, NULL);
    sqlite3_limit(s->db, SQLITE_LIMIT_LENGTH, (int)GDS_MAX_TRUSTLIST_SIZE);
    sqlite3_extended_result_codes(s->db, 0);
    sqlite3_busy_timeout(s->db, 5000);
    *out = s;
    return GDS_OK;
}

static gds_status sq_open_readonly(const char *path, sq_store **out) {
    *out = NULL;
    sq_store *s = NULL;
    gds_status r = open_db(path, SQLITE_OPEN_READONLY, &s);
    if(r != GDS_OK)
        return r;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db, "PRAGMA user_version", -1, &st, NULL);
    if(rc == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
        s->version = sqlite3_column_int(st, 0);
    else
        r = db_err(s, "user_version", rc);
    sqlite3_finalize(st);
    /* a reader never migrates: the writer must have brought the schema up */
    if(r == GDS_OK && s->version != gds_migrate_latest())
        r = GDS_ESTATE;
    if(r != GDS_OK) {
        sq_close(s);
        return r;
    }
    *out = s;
    return GDS_OK;
}

static gds_status sq_open(const char *path, sq_store **out) {
    *out = NULL;
    gds_status r = create_store_file(path);
    if(r != GDS_OK)
        return r;
    sq_store *s = NULL;
    r = open_db(path, SQLITE_OPEN_READWRITE, &s);
    if(r != GDS_OK)
        return r;
    int rc;
    char *err = NULL;
    rc = sqlite3_exec(s->db,
                      "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; "
                      "PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;",
                      NULL, NULL, &err);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "store: pragmas: %s\n", err ? err : "?");
        sqlite3_free(err);
        r = GDS_EIO;
        goto fail;
    }
    if((r = gds_migrate(s->db, &s->version)) != GDS_OK)
        goto fail;
    *out = s;
    return GDS_OK;
fail:
    sq_close(s);
    return r;
}

static void sq_close(void *ctx_) {
    sq_store *s = ctx_;
    if(!s)
        return;
    sqlite3_close_v2(s->db);
    free(s);
}

static int sq_schema_version(void *ctx_) {
    sq_store *s = ctx_;
    return s->version;
}

/* --- helpers ---------------------------------------------------------- */

static int bind_guid(sqlite3_stmt *st, int i, const UA_Guid *g) {
    return sqlite3_bind_blob(st, i, g, (int)sizeof(*g), SQLITE_TRANSIENT);
}

static bool column_guid(sqlite3_stmt *st, int i, UA_Guid *out) {
    if(sqlite3_column_bytes(st, i) != (int)sizeof(*out))
        return false;
    memcpy(out, sqlite3_column_blob(st, i), sizeof(*out));
    return true;
}

static int bind_text(sqlite3_stmt *st, int i, const UA_String *s) {
    if(s->length > (size_t)INT32_MAX)
        return SQLITE_TOOBIG;
    return sqlite3_bind_text(st, i, s->length ? (const char *)s->data : "", (int)s->length,
                             SQLITE_TRANSIENT);
}

static int bind_buf(sqlite3_stmt *st, int i, const gds_buf *b) {
    if(!b || !b->data || b->len == 0)
        return sqlite3_bind_null(st, i);
    if(b->len > (size_t)INT32_MAX)
        return SQLITE_TOOBIG;
    return sqlite3_bind_blob(st, i, b->data, (int)b->len, SQLITE_TRANSIENT);
}

static gds_status column_buf(sqlite3_stmt *st, int i, size_t max, gds_buf *out) {
    out->data = NULL;
    out->len = 0;
    int n = sqlite3_column_bytes(st, i);
    if(n <= 0)
        return GDS_OK;
    if((size_t)n > max)
        return GDS_ETOOBIG;
    return gds_buf_dup(sqlite3_column_blob(st, i), (size_t)n, out);
}

static gds_status decode_record(sqlite3_stmt *st, int col, UA_ApplicationRecordDataType *out) {
    UA_ApplicationRecordDataType_init(out);
    int n = sqlite3_column_bytes(st, col);
    if(n <= 0 || (size_t)n > GDS_MAX_RECORD_SIZE)
        return GDS_EINVAL;
    UA_ByteString bs = {(size_t)n, (UA_Byte *)(uintptr_t)sqlite3_column_blob(st, col)};
    if(UA_decodeBinary(&bs, out, rec_type(), NULL) != UA_STATUSCODE_GOOD)
        return GDS_EINVAL;
    return GDS_OK;
}

/* --- applications ----------------------------------------------------- */

/* The searchable names of an application, inside the caller's transaction. */
static int insert_names(sq_store *s, const UA_Guid *id, const UA_ApplicationRecordDataType *rec) {
    sqlite3_stmt *name = NULL;
    int rc = sqlite3_prepare_v2(s->db, "INSERT INTO app_names(app_id, locale, text) VALUES(?1, ?2, ?3)",
                                -1, &name, NULL);
    for(size_t i = 0; rc == SQLITE_OK && i < rec->applicationNamesSize; i++) {
        sqlite3_reset(name);
        rc = bind_guid(name, 1, id);
        if(rc == SQLITE_OK)
            rc = bind_text(name, 2, &rec->applicationNames[i].locale);
        if(rc == SQLITE_OK)
            rc = bind_text(name, 3, &rec->applicationNames[i].text);
        if(rc == SQLITE_OK && (rc = sqlite3_step(name)) == SQLITE_DONE)
            rc = SQLITE_OK;
    }
    sqlite3_finalize(name);
    return rc;
}

static gds_status encode_record(const UA_ApplicationRecordDataType *rec, UA_ByteString *enc) {
    /* The record is stored without its id; the id column is the truth */
    UA_ApplicationRecordDataType copy = *rec;
    UA_NodeId_init(&copy.applicationId);
    *enc = UA_BYTESTRING_NULL;
    if(UA_encodeBinary(&copy, rec_type(), enc, NULL) != UA_STATUSCODE_GOOD)
        return GDS_ENOMEM;
    if(enc->length > GDS_MAX_RECORD_SIZE) {
        UA_ByteString_clear(enc);
        return GDS_ETOOBIG;
    }
    return GDS_OK;
}

static gds_status sq_app_insert(void *ctx_, const UA_Guid *id,
                                const UA_ApplicationRecordDataType *rec) {
    sq_store *s = ctx_;
    UA_ByteString enc;
    gds_status r = encode_record(rec, &enc);
    if(r != GDS_OK)
        return r;
    sqlite3_stmt *ins = NULL;
    int64_t t = now_s();
    int rc = sqlite3_exec(s->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    if(rc != SQLITE_OK) {
        r = db_err(s, "begin", rc);
        goto cleanup;
    }
    rc = sqlite3_prepare_v2(s->db,
                            "INSERT INTO applications(id, uri, type, record, created, updated) "
                            "VALUES(?1, ?2, ?3, ?4, ?5, ?5)",
                            -1, &ins, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(ins, 1, id);
    if(rc == SQLITE_OK)
        rc = bind_text(ins, 2, &rec->applicationUri);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int(ins, 3, (int)rec->applicationType);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_blob(ins, 4, enc.data, (int)enc.length, SQLITE_STATIC);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(ins, 5, t);
    if(rc == SQLITE_OK && (rc = sqlite3_step(ins)) == SQLITE_DONE)
        rc = SQLITE_OK;
    if(rc == SQLITE_OK)
        rc = insert_names(s, id, rec);
    if(rc == SQLITE_OK)
        rc = sqlite3_exec(s->db, "COMMIT", NULL, NULL, NULL);
    if(rc != SQLITE_OK) {
        r = db_err(s, "insert application", rc);
        (void)sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
    }
cleanup:
    sqlite3_finalize(ins);
    UA_ByteString_clear(&enc);
    return r;
}

static gds_status sq_app_get(void *ctx_, const UA_Guid *id, UA_ApplicationRecordDataType *out) {
    sq_store *s = ctx_;
    UA_ApplicationRecordDataType_init(out);
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db, "SELECT record FROM applications WHERE id = ?1", -1, &st,
                                NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, id);
    gds_status r;
    if(rc != SQLITE_OK)
        r = db_err(s, "get application", rc);
    else if((rc = sqlite3_step(st)) == SQLITE_ROW)
        r = decode_record(st, 0, out);
    else
        r = rc == SQLITE_DONE ? GDS_ENOTFOUND : db_err(s, "get application", rc);
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_app_find_uri(void *ctx_, const UA_String *uri, size_t max,
                                  UA_ApplicationRecordDataType **out, size_t *n) {
    sq_store *s = ctx_;
    *out = NULL;
    *n = 0;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT id, record FROM applications WHERE uri = ?1 "
                                "ORDER BY created LIMIT ?2",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_text(st, 1, uri);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 2, (sqlite3_int64)max);
    if(rc != SQLITE_OK) {
        gds_status r = db_err(s, "find application", rc);
        sqlite3_finalize(st);
        return r;
    }
    gds_status r = GDS_OK;
    UA_ApplicationRecordDataType *arr = NULL;
    size_t cnt = 0;
    while(r == GDS_OK && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        if(cnt >= max)
            break;
        UA_ApplicationRecordDataType *grown =
            UA_realloc(arr, (cnt + 1) * sizeof(UA_ApplicationRecordDataType));
        if(!grown) {
            r = GDS_ENOMEM;
            break;
        }
        arr = grown;
        r = decode_record(st, 1, &arr[cnt]);
        if(r == GDS_OK) {
            UA_Guid g;
            if(column_guid(st, 0, &g))
                arr[cnt].applicationId = UA_NODEID_GUID(0, g); /* caller sets the namespace */
            else
                r = GDS_EINVAL;
            cnt++;
        }
    }
    if(r == GDS_OK && rc != SQLITE_ROW && rc != SQLITE_DONE)
        r = db_err(s, "find application", rc);
    sqlite3_finalize(st);
    if(r != GDS_OK) {
        if(arr)
            UA_Array_delete(arr, cnt, rec_type());
        return r;
    }
    *out = arr;
    *n = cnt;
    return GDS_OK;
}

/* --- requests --------------------------------------------------------- */

void gds_request_clear(gds_request *r) {
    if(!r)
        return;
    gds_buf_free(&r->csr);
    gds_buf_free(&r->cert);
    memset(r, 0, sizeof(*r));
}

static gds_status sq_req_insert(void *ctx_, const gds_request *q) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "INSERT INTO requests(id, app_id, group_id, cert_type, state, csr, "
                                "cert, error, created, updated) "
                                "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, &q->id);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 2, &q->appId);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 3, q->groupId);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 4, q->certType);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int(st, 5, (int)q->state);
    if(rc == SQLITE_OK)
        rc = bind_buf(st, 6, &q->csr);
    if(rc == SQLITE_OK)
        rc = bind_buf(st, 7, &q->cert);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 8, q->error);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 9, now_s());
    if(rc == SQLITE_OK && (rc = sqlite3_step(st)) == SQLITE_DONE)
        rc = SQLITE_OK;
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "insert request", rc);
    sqlite3_finalize(st);
    return r;
}

#define REQ_COLUMNS "id, app_id, group_id, cert_type, state, csr, cert, error"

static gds_status read_request(sqlite3_stmt *st, gds_request *out) {
    memset(out, 0, sizeof(*out));
    if(!column_guid(st, 0, &out->id) || !column_guid(st, 1, &out->appId))
        return GDS_EINVAL;
    sqlite3_int64 g = sqlite3_column_int64(st, 2), t = sqlite3_column_int64(st, 3);
    int state = sqlite3_column_int(st, 4);
    if(g < 0 || g > UINT32_MAX || t < 0 || t > UINT32_MAX || state < GDS_REQ_RECEIVED ||
       state > GDS_REQ_PENDING)
        return GDS_EINVAL;
    out->groupId = (uint32_t)g;
    out->certType = (uint32_t)t;
    out->state = (gds_req_state)state;
    out->error = (UA_StatusCode)sqlite3_column_int64(st, 7);
    gds_status r = column_buf(st, 5, GDS_MAX_CSR_SIZE, &out->csr);
    if(r == GDS_OK)
        r = column_buf(st, 6, GDS_MAX_CERT_SIZE, &out->cert);
    if(r != GDS_OK)
        gds_request_clear(out);
    return r;
}

static gds_status one_request(sq_store *s, sqlite3_stmt *st, int rc, gds_request *out) {
    gds_status r;
    if(rc != SQLITE_OK)
        r = db_err(s, "request", rc);
    else if((rc = sqlite3_step(st)) == SQLITE_ROW)
        r = read_request(st, out);
    else
        r = rc == SQLITE_DONE ? GDS_ENOTFOUND : db_err(s, "request", rc);
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_req_get(void *ctx_, const UA_Guid *id, gds_request *out) {
    sq_store *s = ctx_;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db, "SELECT " REQ_COLUMNS " FROM requests WHERE id = ?1", -1,
                                &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, id);
    return one_request(s, st, rc, out);
}

static gds_status sq_req_next_received(void *ctx_, gds_request *out) {
    sq_store *s = ctx_;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT " REQ_COLUMNS " FROM requests WHERE state = 1 "
                                "ORDER BY created, rowid LIMIT 1",
                                -1, &st, NULL);
    return one_request(s, st, rc, out);
}

static gds_status sq_req_scan(void *ctx_, gds_req_state state, gds_store_req_cb cb,
                              void *cbCtx) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT " REQ_COLUMNS " FROM requests WHERE state = ?1 "
                                "ORDER BY created, rowid",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int(st, 1, (int)state);
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "request scan", rc);
    while(r == GDS_OK && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        gds_request q;
        r = read_request(st, &q);
        if(r != GDS_OK)
            break;
        bool more = cb(cbCtx, &q);
        gds_request_clear(&q);
        if(!more)
            break;
    }
    if(r == GDS_OK && rc != SQLITE_ROW && rc != SQLITE_DONE)
        r = db_err(s, "request scan", rc);
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_req_set_state(void *ctx_, const UA_Guid *id, gds_req_state state,
                                   const gds_buf *cert, UA_StatusCode error) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "UPDATE requests SET state = ?2, cert = COALESCE(?3, cert), "
                                "error = ?4, updated = ?5 WHERE id = ?1",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, id);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int(st, 2, (int)state);
    if(rc == SQLITE_OK)
        rc = bind_buf(st, 3, cert);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 4, error);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 5, now_s());
    if(rc == SQLITE_OK && (rc = sqlite3_step(st)) == SQLITE_DONE)
        rc = SQLITE_OK;
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "update request", rc);
    if(r == GDS_OK && sqlite3_changes(s->db) != 1)
        r = GDS_ENOTFOUND;
    sqlite3_finalize(st);
    return r;
}

/* --- certificates ----------------------------------------------------- */

static gds_status sq_cert_add(void *ctx_, const UA_Guid *appId, uint32_t groupId,
                              uint32_t certType, const gds_buf *serial, const gds_buf *der,
                              int64_t notBefore, int64_t notAfter) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "INSERT INTO certificates(serial, app_id, group_id, cert_type, der, "
                                "not_before, not_after) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_buf(st, 1, serial);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 2, appId);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 3, groupId);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 4, certType);
    if(rc == SQLITE_OK)
        rc = bind_buf(st, 5, der);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 6, notBefore);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 7, notAfter);
    if(rc == SQLITE_OK && (rc = sqlite3_step(st)) == SQLITE_DONE)
        rc = SQLITE_OK;
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "add certificate", rc);
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_cert_latest(void *ctx_, const UA_Guid *appId, uint32_t groupId,
                                 uint32_t certType, gds_buf *der, int64_t *notAfter) {
    sq_store *s = ctx_;
    der->data = NULL;
    der->len = 0;
    *notAfter = 0;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT der, not_after FROM certificates WHERE app_id = ?1 AND "
                                "group_id = ?2 AND cert_type = ?3 AND revoked = 0 "
                                "ORDER BY not_before DESC, rowid DESC LIMIT 1",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, appId);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 2, groupId);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 3, certType);
    gds_status r;
    if(rc != SQLITE_OK) {
        r = db_err(s, "latest certificate", rc);
    } else if((rc = sqlite3_step(st)) == SQLITE_ROW) {
        r = column_buf(st, 0, GDS_MAX_CERT_SIZE, der);
        *notAfter = sqlite3_column_int64(st, 1);
    } else {
        r = rc == SQLITE_DONE ? GDS_ENOTFOUND : db_err(s, "latest certificate", rc);
    }
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_cert_scan(void *ctx_, gds_cert_scan_cb cb, void *cbCtx) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT serial, app_id, group_id, cert_type, der, not_before, "
                                "not_after, revoked FROM certificates ORDER BY serial",
                                -1, &st, NULL);
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "scan certificates", rc);
    while(r == GDS_OK && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        gds_cert_row row;
        memset(&row, 0, sizeof(row));
        int ns = sqlite3_column_bytes(st, 0), nd = sqlite3_column_bytes(st, 4);
        row.serial.data = (uint8_t *)(uintptr_t)sqlite3_column_blob(st, 0);
        row.serial.len = ns > 0 ? (size_t)ns : 0;
        row.der.data = (uint8_t *)(uintptr_t)sqlite3_column_blob(st, 4);
        row.der.len = nd > 0 ? (size_t)nd : 0;
        if(!column_guid(st, 1, &row.appId)) {
            r = GDS_ESTATE;
            break;
        }
        row.groupId = (uint32_t)sqlite3_column_int64(st, 2);
        row.certType = (uint32_t)sqlite3_column_int64(st, 3);
        row.notBefore = sqlite3_column_int64(st, 5);
        row.notAfter = sqlite3_column_int64(st, 6);
        row.revoked = sqlite3_column_int64(st, 7) != 0;
        if(!cb(cbCtx, &row)) {
            rc = SQLITE_DONE;
            break;
        }
    }
    if(r == GDS_OK && rc != SQLITE_DONE)
        r = db_err(s, "scan certificates", rc);
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_tl_get(void *ctx_, uint32_t groupId, gds_buf *data, int64_t *lastUpdate) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT data, last_update FROM trust_lists WHERE group_id = ?1",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 1, groupId);
    gds_status r;
    if(rc != SQLITE_OK) {
        r = db_err(s, "read trust list", rc);
    } else if((rc = sqlite3_step(st)) == SQLITE_ROW) {
        r = column_buf(st, 0, GDS_MAX_TRUSTLIST_SIZE, data);
        *lastUpdate = sqlite3_column_int64(st, 1);
    } else {
        r = rc == SQLITE_DONE ? GDS_ENOTFOUND : db_err(s, "read trust list", rc);
    }
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_tl_put(void *ctx_, uint32_t groupId, const gds_buf *data,
                            int64_t lastUpdate) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "INSERT INTO trust_lists (group_id, data, last_update) "
                                "VALUES (?1, ?2, ?3) ON CONFLICT(group_id) DO UPDATE SET "
                                "data = excluded.data, last_update = excluded.last_update",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 1, groupId);
    if(rc == SQLITE_OK)
        rc = bind_buf(st, 2, data);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 3, lastUpdate);
    if(rc == SQLITE_OK && (rc = sqlite3_step(st)) == SQLITE_DONE)
        rc = SQLITE_OK;
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "write trust list", rc);
    sqlite3_finalize(st);
    return r;
}

/* --- push targets (schema 1 table push_targets) ----------------------- */

static gds_status sq_push_target_put(void *ctx_, const UA_Guid *appId, const char *endpoint,
                                     bool enabled) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "INSERT INTO push_targets (app_id, endpoint, enabled) "
                                "SELECT ?1, ?2, ?3 WHERE EXISTS "
                                "(SELECT 1 FROM applications WHERE id = ?1) "
                                "ON CONFLICT(app_id) DO UPDATE SET "
                                "endpoint = excluded.endpoint, enabled = excluded.enabled",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, appId);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_text(st, 2, endpoint, -1, SQLITE_TRANSIENT);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int(st, 3, enabled ? 1 : 0);
    if(rc == SQLITE_OK && (rc = sqlite3_step(st)) == SQLITE_DONE)
        rc = SQLITE_OK;
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "write push target", rc);
    if(r == GDS_OK && sqlite3_changes(s->db) == 0)
        r = GDS_ENOTFOUND;
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_push_target_delete(void *ctx_, const UA_Guid *appId) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db, "DELETE FROM push_targets WHERE app_id = ?1", -1, &st,
                                NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, appId);
    if(rc == SQLITE_OK && (rc = sqlite3_step(st)) == SQLITE_DONE)
        rc = SQLITE_OK;
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "delete push target", rc);
    if(r == GDS_OK && sqlite3_changes(s->db) == 0)
        r = GDS_ENOTFOUND;
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_push_target_scan(void *ctx_, gds_push_target_cb cb, void *cbCtx) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT app_id, endpoint, enabled FROM push_targets "
                                "ORDER BY app_id",
                                -1, &st, NULL);
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "scan push targets", rc);
    while(r == GDS_OK && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        gds_push_target_row row;
        memset(&row, 0, sizeof(row));
        const unsigned char *e = sqlite3_column_text(st, 1);
        if(!column_guid(st, 0, &row.appId) || !e ||
           (size_t)sqlite3_column_bytes(st, 1) >= GDS_MAX_PUSH_ENDPOINT) {
            r = GDS_EINVAL; /* a damaged row */
            break;
        }
        row.endpoint = (const char *)e;
        row.enabled = sqlite3_column_int(st, 2) != 0;
        if(!cb(cbCtx, &row)) {
            rc = SQLITE_DONE;
            break;
        }
    }
    if(r == GDS_OK && rc != SQLITE_DONE)
        r = db_err(s, "scan push targets", rc);
    sqlite3_finalize(st);
    return r;
}

/* One UPDATE binding the application id as ?1 and optionally der as ?2. */
static gds_status mark_revoked(sq_store *s, const char *sql, const UA_Guid *appId,
                               const gds_buf *der, int *changed) {
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db, sql, -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, appId);
    if(rc == SQLITE_OK && der)
        rc = bind_buf(st, 2, der);
    if(rc == SQLITE_OK && (rc = sqlite3_step(st)) == SQLITE_DONE)
        rc = SQLITE_OK;
    *changed = rc == SQLITE_OK ? sqlite3_changes(s->db) : 0;
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "revoke certificate", rc);
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_cert_revoke(void *ctx_, const UA_Guid *appId, const gds_buf *der,
                                 gds_buf *serial) {
    sq_store *s = ctx_;
    int changed = 0;
    gds_status r = mark_revoked(s,
                                "UPDATE certificates SET revoked = 1 WHERE app_id = ?1 AND "
                                "der = ?2",
                                appId, der, &changed);
    if(r != GDS_OK)
        return r;
    if(changed == 0)
        return GDS_ENOTFOUND;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT serial FROM certificates WHERE app_id = ?1 AND der = ?2 "
                                "ORDER BY rowid LIMIT 1",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, appId);
    if(rc == SQLITE_OK)
        rc = bind_buf(st, 2, der);
    if(rc != SQLITE_OK)
        r = db_err(s, "revoke certificate", rc);
    else if((rc = sqlite3_step(st)) == SQLITE_ROW)
        r = column_buf(st, 0, GDS_MAX_SERIAL_SIZE, serial);
    else
        r = rc == SQLITE_DONE ? GDS_ENOTFOUND : db_err(s, "revoke certificate", rc);
    if(r == GDS_OK && serial->len == 0)
        r = GDS_EINVAL;
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_cert_revoke_app(void *ctx_, const UA_Guid *appId, gds_store_serial_cb cb,
                                     void *cbCtx) {
    sq_store *s = ctx_;
    int changed = 0;
    gds_status r = mark_revoked(s, "UPDATE certificates SET revoked = 1 WHERE app_id = ?1",
                                appId, NULL, &changed);
    if(r != GDS_OK)
        return r;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT serial FROM certificates WHERE app_id = ?1 AND "
                                "revoked = 1 ORDER BY rowid",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, appId);
    r = rc == SQLITE_OK ? GDS_OK : db_err(s, "revoke certificates", rc);
    while(r == GDS_OK && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        gds_buf serial = {0};
        r = column_buf(st, 0, GDS_MAX_SERIAL_SIZE, &serial);
        if(r != GDS_OK)
            break;
        bool more = serial.len == 0 || cb(cbCtx, &serial);
        gds_buf_free(&serial);
        if(!more)
            break;
    }
    if(r == GDS_OK && rc != SQLITE_ROW && rc != SQLITE_DONE)
        r = db_err(s, "revoke certificates", rc);
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_cert_is_revoked(void *ctx_, const gds_buf *serial, bool *revoked) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db, "SELECT revoked FROM certificates WHERE serial = ?1", -1,
                                &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_buf(st, 1, serial);
    if(rc == SQLITE_OK && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        *revoked = sqlite3_column_int64(st, 0) != 0;
        rc = SQLITE_DONE;
    }
    gds_status r = rc == SQLITE_DONE ? GDS_OK : db_err(s, "certificate state", rc);
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_app_update(void *ctx_, const UA_Guid *id,
                                const UA_ApplicationRecordDataType *rec) {
    sq_store *s = ctx_;
    UA_ByteString enc;
    gds_status r = encode_record(rec, &enc);
    if(r != GDS_OK)
        return r;
    sqlite3_stmt *up = NULL, *del = NULL;
    int rc = sqlite3_exec(s->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    if(rc == SQLITE_OK)
        rc = sqlite3_prepare_v2(s->db,
                                "UPDATE applications SET uri = ?2, type = ?3, record = ?4, "
                                "updated = ?5 WHERE id = ?1",
                                -1, &up, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(up, 1, id);
    if(rc == SQLITE_OK)
        rc = bind_text(up, 2, &rec->applicationUri);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int(up, 3, (int)rec->applicationType);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_blob(up, 4, enc.data, (int)enc.length, SQLITE_STATIC);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(up, 5, now_s());
    if(rc == SQLITE_OK && (rc = sqlite3_step(up)) == SQLITE_DONE)
        rc = SQLITE_OK;
    bool found = rc == SQLITE_OK && sqlite3_changes(s->db) == 1;
    if(rc == SQLITE_OK && found)
        rc = sqlite3_prepare_v2(s->db, "DELETE FROM app_names WHERE app_id = ?1", -1, &del, NULL);
    if(rc == SQLITE_OK && found)
        rc = bind_guid(del, 1, id);
    if(rc == SQLITE_OK && found && (rc = sqlite3_step(del)) == SQLITE_DONE)
        rc = SQLITE_OK;
    if(rc == SQLITE_OK && found)
        rc = insert_names(s, id, rec);
    if(rc == SQLITE_OK && found)
        rc = sqlite3_exec(s->db, "COMMIT", NULL, NULL, NULL);
    if(rc != SQLITE_OK || !found) {
        r = rc != SQLITE_OK ? db_err(s, "update application", rc) : GDS_ENOTFOUND;
        (void)sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
    }
    sqlite3_finalize(up);
    sqlite3_finalize(del);
    UA_ByteString_clear(&enc);
    return r;
}

static gds_status sq_app_delete(void *ctx_, const UA_Guid *id) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db, "DELETE FROM applications WHERE id = ?1", -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, id);
    if(rc == SQLITE_OK && (rc = sqlite3_step(st)) == SQLITE_DONE)
        rc = SQLITE_OK;
    gds_status r = GDS_OK;
    if(rc != SQLITE_OK)
        r = db_err(s, "delete application", rc);
    else if(sqlite3_changes(s->db) != 1)
        r = GDS_ENOTFOUND;
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_app_scan(void *ctx_, int64_t afterRecordId, gds_store_scan_cb cb,
                              void *ctx) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT record_id, id, record FROM applications "
                                "WHERE record_id > ?1 ORDER BY record_id",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 1, afterRecordId);
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "scan applications", rc);
    while(r == GDS_OK && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        if(sqlite3_column_bytes(st, 1) != (int)sizeof(UA_Guid)) {
            r = GDS_EINVAL;
            break;
        }
        UA_Guid g;
        memcpy(&g, sqlite3_column_blob(st, 1), sizeof(g));
        UA_ApplicationRecordDataType rec;
        r = decode_record(st, 2, &rec);
        if(r != GDS_OK)
            break;
        rec.applicationId = UA_NODEID_GUID(0, g);
        bool more = cb(ctx, sqlite3_column_int64(st, 0), &rec);
        UA_ApplicationRecordDataType_clear(&rec);
        if(!more)
            break;
    }
    if(r == GDS_OK && rc != SQLITE_ROW && rc != SQLITE_DONE)
        r = db_err(s, "scan applications", rc);
    sqlite3_finalize(st);
    return r;
}

/* --- audit log (issue #18) ---------------------------------------------- */

static gds_status last_audit(sq_store *s, int64_t *seq, uint8_t hash[GDS_AUDIT_HASH]) {
    *seq = 0;
    memset(hash, 0, GDS_AUDIT_HASH);
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db, "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = sqlite3_step(st);
    gds_status r = GDS_OK;
    if(rc == SQLITE_ROW) {
        *seq = sqlite3_column_int64(st, 0);
        if(sqlite3_column_bytes(st, 1) == GDS_AUDIT_HASH)
            memcpy(hash, sqlite3_column_blob(st, 1), GDS_AUDIT_HASH);
        else
            r = GDS_ESTATE;
    } else if(rc != SQLITE_DONE) {
        r = db_err(s, "audit tail", rc);
    }
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_audit_append(void *ctx_, int64_t time, const gds_buf *body, int64_t *seq) {
    sq_store *s = ctx_;
    int rc = sqlite3_exec(s->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    if(rc != SQLITE_OK)
        return db_err(s, "begin", rc);
    int64_t last = 0;
    uint8_t prev[GDS_AUDIT_HASH], hash[GDS_AUDIT_HASH];
    gds_status r = last_audit(s, &last, prev);
    if(r == GDS_OK)
        r = gds_audit_hash(prev, last + 1, time, body, hash);
    sqlite3_stmt *st = NULL;
    if(r == GDS_OK) {
        rc = sqlite3_prepare_v2(s->db,
                                "INSERT INTO audit(seq, time, body, prev_hash, hash) "
                                "VALUES(?1, ?2, ?3, ?4, ?5)",
                                -1, &st, NULL);
        if(rc == SQLITE_OK)
            rc = sqlite3_bind_int64(st, 1, last + 1);
        if(rc == SQLITE_OK)
            rc = sqlite3_bind_int64(st, 2, time);
        if(rc == SQLITE_OK)
            rc = bind_buf(st, 3, body);
        if(rc == SQLITE_OK)
            rc = sqlite3_bind_blob(st, 4, prev, GDS_AUDIT_HASH, SQLITE_STATIC);
        if(rc == SQLITE_OK)
            rc = sqlite3_bind_blob(st, 5, hash, GDS_AUDIT_HASH, SQLITE_STATIC);
        if(rc == SQLITE_OK && (rc = sqlite3_step(st)) == SQLITE_DONE)
            rc = SQLITE_OK;
        if(rc != SQLITE_OK)
            r = db_err(s, "append audit", rc);
        sqlite3_finalize(st);
    }
    if(r == GDS_OK && (rc = sqlite3_exec(s->db, "COMMIT", NULL, NULL, NULL)) != SQLITE_OK)
        r = db_err(s, "commit", rc);
    if(r != GDS_OK) {
        (void)sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
        return r;
    }
    *seq = last + 1;
    return GDS_OK;
}

static gds_status sq_audit_scan(void *ctx_, int64_t fromSeq, gds_audit_scan_cb cb, void *cbCtx) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT seq, time, body, prev_hash, hash FROM audit "
                                "WHERE seq >= ?1 ORDER BY seq",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 1, fromSeq);
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "scan audit", rc);
    while(r == GDS_OK && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        gds_audit_row row;
        memset(&row, 0, sizeof(row));
        row.seq = sqlite3_column_int64(st, 0);
        row.time = sqlite3_column_int64(st, 1);
        int n = sqlite3_column_bytes(st, 2);
        row.body.data = (uint8_t *)(uintptr_t)sqlite3_column_blob(st, 2);
        row.body.len = n > 0 ? (size_t)n : 0;
        if(sqlite3_column_bytes(st, 3) != GDS_AUDIT_HASH ||
           sqlite3_column_bytes(st, 4) != GDS_AUDIT_HASH) {
            r = GDS_ESTATE;
            break;
        }
        memcpy(row.prevHash, sqlite3_column_blob(st, 3), GDS_AUDIT_HASH);
        memcpy(row.hash, sqlite3_column_blob(st, 4), GDS_AUDIT_HASH);
        if(!cb(cbCtx, &row)) {
            rc = SQLITE_DONE;
            break;
        }
    }
    if(r == GDS_OK && rc != SQLITE_DONE)
        r = db_err(s, "scan audit", rc);
    sqlite3_finalize(st);
    return r;
}

/* --- KeyCredentials (schema 5) ----------------------------------------- */

static int bind_cstr(sqlite3_stmt *st, int i, const char *v) {
    return sqlite3_bind_text(st, i, v, -1, SQLITE_TRANSIENT);
}

/* Copy a text column into a fixed buffer; false if it does not fit. */
static bool column_cstr(sqlite3_stmt *st, int i, char *out, size_t size) {
    const unsigned char *t = sqlite3_column_text(st, i);
    int n = sqlite3_column_bytes(st, i);
    if(n < 0 || (size_t)n >= size)
        return false;
    if(n > 0)
        memcpy(out, t, (size_t)n);
    out[n] = '\0';
    return true;
}

static gds_status step_done(sq_store *s, sqlite3_stmt *st, int rc, const char *what) {
    if(rc == SQLITE_OK && (rc = sqlite3_step(st)) == SQLITE_DONE)
        rc = SQLITE_OK;
    return rc == SQLITE_OK ? GDS_OK : db_err(s, what, rc);
}

static gds_status sq_kc_req_insert(void *ctx_, const gds_kc_request *q) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "INSERT INTO kc_requests(id, app_id, service, state, public_key, "
                                "policy, caller, created, updated) "
                                "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
                                -1, &st, NULL);
    gds_buf caller = {(uint8_t *)(uintptr_t)q->caller, q->hasCaller ? GDS_KC_CALLER : 0};
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, &q->id);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 2, &q->appId);
    if(rc == SQLITE_OK)
        rc = bind_cstr(st, 3, q->service);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int(st, 4, (int)q->state);
    if(rc == SQLITE_OK)
        rc = bind_buf(st, 5, &q->publicKey);
    if(rc == SQLITE_OK)
        rc = bind_cstr(st, 6, q->policy);
    if(rc == SQLITE_OK)
        rc = bind_buf(st, 7, &caller);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 8, now_s());
    gds_status r = step_done(s, st, rc, "insert key credential request");
    sqlite3_finalize(st);
    return r;
}

#define KC_REQ_COLUMNS "id, app_id, service, state, public_key, policy, caller, credential_id, created"

static gds_status read_kc_request(sqlite3_stmt *st, gds_kc_request *out) {
    memset(out, 0, sizeof(*out));
    int state = sqlite3_column_int(st, 3);
    int callerLen = sqlite3_column_bytes(st, 6);
    if(!column_guid(st, 0, &out->id) || !column_guid(st, 1, &out->appId) ||
       !column_cstr(st, 2, out->service, sizeof(out->service)) || state < GDS_KC_PENDING ||
       state > GDS_KC_CANCELLED || !column_cstr(st, 5, out->policy, sizeof(out->policy)) ||
       (callerLen != 0 && callerLen != GDS_KC_CALLER) ||
       !column_cstr(st, 7, out->credentialId, sizeof(out->credentialId)))
        return GDS_EINVAL;
    out->state = (gds_kc_state)state;
    out->hasCaller = callerLen == GDS_KC_CALLER;
    if(out->hasCaller)
        memcpy(out->caller, sqlite3_column_blob(st, 6), GDS_KC_CALLER);
    out->created = sqlite3_column_int64(st, 8);
    gds_status r = column_buf(st, 4, GDS_MAX_CERT_SIZE, &out->publicKey);
    if(r != GDS_OK)
        gds_kc_request_clear(out);
    return r;
}

static gds_status sq_kc_req_get(void *ctx_, const UA_Guid *id, gds_kc_request *out) {
    sq_store *s = ctx_;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db, "SELECT " KC_REQ_COLUMNS " FROM kc_requests WHERE id = ?1",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, id);
    gds_status r;
    if(rc != SQLITE_OK)
        r = db_err(s, "key credential request", rc);
    else if((rc = sqlite3_step(st)) == SQLITE_ROW)
        r = read_kc_request(st, out);
    else
        r = rc == SQLITE_DONE ? GDS_ENOTFOUND : db_err(s, "key credential request", rc);
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_kc_req_set_state(void *ctx_, const UA_Guid *id, gds_kc_state state) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "UPDATE kc_requests SET state = ?2, updated = ?3 WHERE id = ?1",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(st, 1, id);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int(st, 2, (int)state);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(st, 3, now_s());
    gds_status r = step_done(s, st, rc, "update key credential request");
    if(r == GDS_OK && sqlite3_changes(s->db) != 1)
        r = GDS_ENOTFOUND;
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_kc_req_scan(void *ctx_, gds_kc_state state, gds_store_kc_req_cb cb,
                                 void *cbCtx) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT " KC_REQ_COLUMNS " FROM kc_requests WHERE state = ?1 "
                                "ORDER BY created, rowid",
                                -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int(st, 1, (int)state);
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "key credential request scan", rc);
    while(r == GDS_OK && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        gds_kc_request q;
        r = read_kc_request(st, &q);
        if(r != GDS_OK)
            break;
        bool more = cb(cbCtx, &q);
        gds_kc_request_clear(&q);
        if(!more)
            break;
    }
    if(r == GDS_OK && rc != SQLITE_ROW && rc != SQLITE_DONE)
        r = db_err(s, "key credential request scan", rc);
    sqlite3_finalize(st);
    return r;
}

/* One step that returns no row: SQLITE_OK when done. */
static int run_done(sqlite3_stmt *st) {
    int rc = sqlite3_step(st);
    return rc == SQLITE_DONE ? SQLITE_OK : rc;
}

/* sq_kc_deliver's steps, inside its transaction; each returns an SQLite
 * code and finalizes its own statements. */
static int kc_check_request(sqlite3 *db, const UA_Guid *requestId, const gds_kc_cred *cred,
                            UA_Guid *appId, char service[GDS_MAX_KC_SERVICE + 1], gds_status *r) {
    sqlite3_stmt *sel = NULL;
    int rc = sqlite3_prepare_v2(db, "SELECT app_id, service, state FROM kc_requests WHERE id = ?1",
                                -1, &sel, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(sel, 1, requestId);
    if(rc == SQLITE_OK)
        rc = sqlite3_step(sel);
    if(rc == SQLITE_DONE)
        *r = GDS_ENOTFOUND;
    else if(rc == SQLITE_ROW) {
        bool read = column_guid(sel, 0, appId) &&
                    column_cstr(sel, 1, service, GDS_MAX_KC_SERVICE + 1);
        bool same = read && UA_Guid_equal(appId, &cred->appId) &&
                    strcmp(service, cred->service) == 0;
        if(read && sqlite3_column_int(sel, 2) != GDS_KC_APPROVED)
            *r = GDS_ESTATE;
        else if(!same)
            *r = GDS_EINVAL; /* unreadable, or another application or service */
    }
    sqlite3_finalize(sel);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? SQLITE_OK : rc;
}

/* The application's earlier credential for this service, if any. */
static int kc_old_cred(sqlite3 *db, const UA_Guid *appId, const char *service,
                       char replaced[GDS_MAX_KC_ID + 1]) {
    sqlite3_stmt *old = NULL;
    int rc = sqlite3_prepare_v2(db,
                                "SELECT id FROM kc_credentials WHERE app_id = ?1 AND service = ?2 "
                                "ORDER BY created DESC, rowid DESC LIMIT 1",
                                -1, &old, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(old, 1, appId);
    if(rc == SQLITE_OK)
        rc = bind_cstr(old, 2, service);
    if(rc == SQLITE_OK)
        rc = sqlite3_step(old);
    if(rc == SQLITE_ROW && !column_cstr(old, 0, replaced, GDS_MAX_KC_ID + 1))
        replaced[0] = '\0';
    sqlite3_finalize(old);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? SQLITE_OK : rc;
}

/* Deletes the application's credentials for the service, inserts cred. */
static int kc_replace_cred(sqlite3 *db, const UA_Guid *appId, const char *service,
                           const gds_kc_cred *cred) {
    sqlite3_stmt *del = NULL, *ins = NULL;
    int rc = sqlite3_prepare_v2(db, "DELETE FROM kc_credentials WHERE app_id = ?1 AND service = ?2",
                                -1, &del, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(del, 1, appId);
    if(rc == SQLITE_OK)
        rc = bind_cstr(del, 2, service);
    if(rc == SQLITE_OK)
        rc = run_done(del);
    if(rc == SQLITE_OK)
        rc = sqlite3_prepare_v2(db,
                                "INSERT INTO kc_credentials(id, app_id, service, verifier, created) "
                                "VALUES(?1, ?2, ?3, ?4, ?5)",
                                -1, &ins, NULL);
    if(rc == SQLITE_OK)
        rc = bind_cstr(ins, 1, cred->id);
    if(rc == SQLITE_OK)
        rc = bind_guid(ins, 2, appId);
    if(rc == SQLITE_OK)
        rc = bind_cstr(ins, 3, service);
    if(rc == SQLITE_OK)
        rc = bind_cstr(ins, 4, cred->verifier);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(ins, 5, now_s());
    if(rc == SQLITE_OK)
        rc = run_done(ins);
    sqlite3_finalize(del);
    sqlite3_finalize(ins);
    return rc;
}

static int kc_mark_delivered(sqlite3 *db, const UA_Guid *requestId, const char *credId) {
    sqlite3_stmt *up = NULL;
    int rc = sqlite3_prepare_v2(db,
                                "UPDATE kc_requests SET state = 3, credential_id = ?2, updated = ?3 "
                                "WHERE id = ?1",
                                -1, &up, NULL);
    if(rc == SQLITE_OK)
        rc = bind_guid(up, 1, requestId);
    if(rc == SQLITE_OK)
        rc = bind_cstr(up, 2, credId);
    if(rc == SQLITE_OK)
        rc = sqlite3_bind_int64(up, 3, now_s());
    if(rc == SQLITE_OK)
        rc = run_done(up);
    sqlite3_finalize(up);
    return rc;
}

static gds_status sq_kc_deliver(void *ctx_, const UA_Guid *requestId, const gds_kc_cred *cred,
                                char replaced[GDS_MAX_KC_ID + 1]) {
    sq_store *s = ctx_;
    gds_status r = GDS_OK;
    UA_Guid appId;
    char service[GDS_MAX_KC_SERVICE + 1];
    replaced[0] = '\0';
    int rc = sqlite3_exec(s->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    if(rc == SQLITE_OK)
        rc = kc_check_request(s->db, requestId, cred, &appId, service, &r);
    if(rc == SQLITE_OK && r == GDS_OK)
        rc = kc_old_cred(s->db, &appId, service, replaced);
    if(rc == SQLITE_OK && r == GDS_OK)
        rc = kc_replace_cred(s->db, &appId, service, cred);
    if(rc == SQLITE_OK && r == GDS_OK)
        rc = kc_mark_delivered(s->db, requestId, cred->id);
    if(rc == SQLITE_OK && r == GDS_OK)
        rc = sqlite3_exec(s->db, "COMMIT", NULL, NULL, NULL);
    if(rc != SQLITE_OK && r == GDS_OK)
        r = rc == SQLITE_CONSTRAINT ? GDS_EEXISTS : db_err(s, "deliver key credential", rc);
    if(r != GDS_OK) {
        replaced[0] = '\0';
        (void)sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
    }
    return r;
}

static gds_status read_kc_cred(sqlite3_stmt *st, gds_kc_cred *out) {
    memset(out, 0, sizeof(*out));
    if(!column_cstr(st, 0, out->id, sizeof(out->id)) || !column_guid(st, 1, &out->appId) ||
       !column_cstr(st, 2, out->service, sizeof(out->service)) ||
       !column_cstr(st, 3, out->verifier, sizeof(out->verifier)))
        return GDS_EINVAL;
    out->created = sqlite3_column_int64(st, 4);
    return GDS_OK;
}

#define KC_CRED_COLUMNS "id, app_id, service, verifier, created"

static gds_status sq_kc_cred_get(void *ctx_, const char *id, gds_kc_cred *out) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT " KC_CRED_COLUMNS " FROM kc_credentials WHERE id = ?1", -1,
                                &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_cstr(st, 1, id);
    gds_status r;
    if(rc != SQLITE_OK)
        r = db_err(s, "key credential", rc);
    else if((rc = sqlite3_step(st)) == SQLITE_ROW)
        r = read_kc_cred(st, out);
    else
        r = rc == SQLITE_DONE ? GDS_ENOTFOUND : db_err(s, "key credential", rc);
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_kc_cred_delete(void *ctx_, const char *id) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db, "DELETE FROM kc_credentials WHERE id = ?1", -1, &st, NULL);
    if(rc == SQLITE_OK)
        rc = bind_cstr(st, 1, id);
    gds_status r = step_done(s, st, rc, "delete key credential");
    if(r == GDS_OK && sqlite3_changes(s->db) != 1)
        r = GDS_ENOTFOUND;
    sqlite3_finalize(st);
    return r;
}

static gds_status sq_kc_cred_scan(void *ctx_, gds_store_kc_cred_cb cb, void *cbCtx) {
    sq_store *s = ctx_;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->db,
                                "SELECT " KC_CRED_COLUMNS " FROM kc_credentials "
                                "ORDER BY created, rowid",
                                -1, &st, NULL);
    gds_status r = rc == SQLITE_OK ? GDS_OK : db_err(s, "key credential scan", rc);
    while(r == GDS_OK && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        gds_kc_cred c;
        r = read_kc_cred(st, &c);
        if(r != GDS_OK || !cb(cbCtx, &c))
            break;
    }
    if(r == GDS_OK && rc != SQLITE_ROW && rc != SQLITE_DONE)
        r = db_err(s, "key credential scan", rc);
    sqlite3_finalize(st);
    return r;
}

/* --- the built-in backend ---------------------------------------------- */

const gds_store_backend gds_store_sqlite_backend = {
    .abi_major = GDS_STORE_ABI_MAJOR,
    .abi_minor = GDS_STORE_ABI_MINOR,
    .struct_size = sizeof(gds_store_backend),
    .close = sq_close,
    .schema_version = sq_schema_version,
    .app_insert = sq_app_insert,
    .app_get = sq_app_get,
    .app_find_uri = sq_app_find_uri,
    .app_update = sq_app_update,
    .app_delete = sq_app_delete,
    .app_scan = sq_app_scan,
    .req_insert = sq_req_insert,
    .req_get = sq_req_get,
    .req_next_received = sq_req_next_received,
    .req_scan = sq_req_scan,
    .req_set_state = sq_req_set_state,
    .cert_add = sq_cert_add,
    .cert_latest = sq_cert_latest,
    .audit_append = sq_audit_append,
    .audit_scan = sq_audit_scan,
    .cert_revoke = sq_cert_revoke,
    .cert_revoke_app = sq_cert_revoke_app,
    .cert_is_revoked = sq_cert_is_revoked,
    .cert_scan = sq_cert_scan,
    .tl_get = sq_tl_get,
    .tl_put = sq_tl_put,
    .push_target_put = sq_push_target_put,
    .push_target_delete = sq_push_target_delete,
    .push_target_scan = sq_push_target_scan,
    .kc_req_insert = sq_kc_req_insert,
    .kc_req_get = sq_kc_req_get,
    .kc_req_set_state = sq_kc_req_set_state,
    .kc_req_scan = sq_kc_req_scan,
    .kc_deliver = sq_kc_deliver,
    .kc_cred_get = sq_kc_cred_get,
    .kc_cred_delete = sq_kc_cred_delete,
    .kc_cred_scan = sq_kc_cred_scan,
};

gds_status gds_store_sqlite_open(const char *path, bool readonly, void **ctx) {
    sq_store *s = NULL;
    gds_status r = readonly ? sq_open_readonly(path, &s) : sq_open(path, &s);
    *ctx = s;
    return r;
}
