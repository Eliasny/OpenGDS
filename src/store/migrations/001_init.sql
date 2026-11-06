-- OpenGDS store schema 1 (T1 thin path). SPDX-License-Identifier: MPL-2.0
-- Identifiers are 16-byte GUIDs (the NodeId identifiers on the wire).
CREATE TABLE applications (
    id       BLOB PRIMARY KEY CHECK (length(id) = 16),
    uri      TEXT NOT NULL UNIQUE,
    type     INTEGER NOT NULL,
    record   BLOB NOT NULL,            -- binary-encoded ApplicationRecordDataType
    created  INTEGER NOT NULL,
    updated  INTEGER NOT NULL
);
CREATE TABLE app_names (
    app_id   BLOB NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    locale   TEXT NOT NULL,
    text     TEXT NOT NULL
);
CREATE INDEX app_names_text ON app_names(text);
CREATE TABLE requests (
    id        BLOB PRIMARY KEY CHECK (length(id) = 16),
    app_id    BLOB NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    group_id  INTEGER NOT NULL,
    cert_type INTEGER NOT NULL,
    state     INTEGER NOT NULL,        -- 1 received, 2 issued, 3 delivered, 4 failed
    csr       BLOB,
    cert      BLOB,
    error     INTEGER NOT NULL DEFAULT 0,
    created   INTEGER NOT NULL,
    updated   INTEGER NOT NULL
);
CREATE INDEX requests_state ON requests(state, created);
CREATE TABLE certificates (
    serial     BLOB PRIMARY KEY,
    app_id     BLOB NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    group_id   INTEGER NOT NULL,
    cert_type  INTEGER NOT NULL,
    der        BLOB NOT NULL,
    not_before INTEGER NOT NULL,
    not_after  INTEGER NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX certificates_app ON certificates(app_id, group_id, cert_type);
CREATE TABLE crls (
    group_id INTEGER PRIMARY KEY,
    number   INTEGER NOT NULL,
    der      BLOB NOT NULL,
    updated  INTEGER NOT NULL
);
CREATE TABLE push_targets (
    app_id   BLOB PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL,
    enabled  INTEGER NOT NULL DEFAULT 1
);
