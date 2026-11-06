-- OpenGDS store schema 2: the hash-chained audit log (issue #18).
-- SPDX-License-Identifier: MPL-2.0
-- Each row's hash is SHA-256(prev_hash || seq || time || body), with
-- seq and time as 8-byte big-endian integers and 32 zero bytes before the
-- first row. body is the OPC UA binary encoding of the event (see
-- src/store/audit.h); the row is appended in the writer's transaction.
CREATE TABLE audit (
    seq       INTEGER PRIMARY KEY,     -- 1, 2, 3 ... without gaps
    time      INTEGER NOT NULL,        -- UA_DateTime (100 ns since 1601)
    body      BLOB NOT NULL,
    prev_hash BLOB NOT NULL CHECK (length(prev_hash) = 32),
    hash      BLOB NOT NULL CHECK (length(hash) = 32)
);
-- The log is append-only: the store refuses to change or delete rows.
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
    BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
    BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
