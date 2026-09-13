ALTER TABLE sessions ADD COLUMN raw_provenance_status TEXT NOT NULL DEFAULT 'unknown' CHECK(raw_provenance_status IN ('none', 'available', 'unresolved', 'unknown'));
UPDATE schema_meta SET value = '3' WHERE key = 'schema_version';
