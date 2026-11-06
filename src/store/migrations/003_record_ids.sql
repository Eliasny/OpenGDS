-- OpenGDS store schema 3: QueryApplications record identifiers.
-- SPDX-License-Identifier: MPL-2.0
-- OPC 10000-12 §6.5.10 and §6.5.11: "each time the GDS creates or updates a
-- record it assigns a monotonically increasing identifier", and a query
-- returns records with an identifier greater than StartingRecordId. The
-- rowid stays the same on UPDATE, so record_id is a separate column, set by
-- triggers from a counter that never goes back (not even after a delete).
ALTER TABLE applications ADD COLUMN record_id INTEGER;
UPDATE applications SET record_id = rowid;
CREATE UNIQUE INDEX applications_record_id ON applications(record_id);
CREATE TABLE record_counter (
    one  INTEGER PRIMARY KEY CHECK (one = 1),
    next INTEGER NOT NULL
);
INSERT INTO record_counter VALUES (1, (SELECT coalesce(max(record_id), 0) + 1 FROM applications));
CREATE TRIGGER applications_record_id_insert AFTER INSERT ON applications
BEGIN
    UPDATE applications SET record_id = (SELECT next FROM record_counter)
        WHERE rowid = NEW.rowid;
    UPDATE record_counter SET next = next + 1;
END;
-- Only the record's own columns: the trigger's own UPDATE of record_id does
-- not fire it again.
CREATE TRIGGER applications_record_id_update AFTER UPDATE OF uri, type, record ON applications
BEGIN
    UPDATE applications SET record_id = (SELECT next FROM record_counter)
        WHERE rowid = NEW.rowid;
    UPDATE record_counter SET next = next + 1;
END;
