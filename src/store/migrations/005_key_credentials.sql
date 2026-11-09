-- OpenGDS store schema 5: KeyCredentials (OPC 10000-12 §8.5).
-- SPDX-License-Identifier: MPL-2.0
-- kc_requests: StartRequest rows. state 1 pending (waits for an
-- administrator), 2 approved, 3 delivered (FinishRequest returned the
-- credential), 4 rejected, 5 cancelled. caller is the SHA-256 of the
-- SecureChannel certificate that called StartRequest (§8.5.6: FinishRequest
-- comes over the same certificate). The secret is never stored: it is made
-- when FinishRequest delivers it.
CREATE TABLE kc_requests (
    id            BLOB PRIMARY KEY CHECK (length(id) = 16),
    app_id        BLOB NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    service       TEXT NOT NULL,
    state         INTEGER NOT NULL,
    public_key    BLOB,
    policy        TEXT NOT NULL DEFAULT '',
    caller        BLOB,
    credential_id TEXT,
    created       INTEGER NOT NULL,
    updated       INTEGER NOT NULL
);
CREATE INDEX kc_requests_state ON kc_requests(state, created);
-- kc_credentials: delivered KeyCredentials. verifier is a salted hash of
-- the secret (mosquitto_passwd's PBKDF2-SHA512 "$7$" form), never the
-- secret itself. One live credential per application and service: a new
-- delivery replaces the old one.
CREATE TABLE kc_credentials (
    id       TEXT PRIMARY KEY,
    app_id   BLOB NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    service  TEXT NOT NULL,
    verifier TEXT NOT NULL,
    created  INTEGER NOT NULL
);
CREATE INDEX kc_credentials_app ON kc_credentials(app_id, service);
