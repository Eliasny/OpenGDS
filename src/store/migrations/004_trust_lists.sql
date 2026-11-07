-- OpenGDS store schema 4: the CertificateGroup trust lists.
-- SPDX-License-Identifier: MPL-2.0
-- OPC 10000-12 §7.8.2: a CertificateGroup's TrustList can be written with
-- Open/Write/CloseAndUpdate, AddCertificate and RemoveCertificate. One row
-- per group holds the entries an administrator put there, as the OPC UA
-- binary encoding of a TrustListDataType (opaque to the store), and the
-- list's LastUpdateTime. The GDS CA certificate and its CRL are not
-- stored here: the server always adds them.
CREATE TABLE trust_lists (
    group_id    INTEGER PRIMARY KEY,
    data        BLOB NOT NULL,
    last_update INTEGER NOT NULL
);
