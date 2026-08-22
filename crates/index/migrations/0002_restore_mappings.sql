CREATE TABLE session_restore_mappings (
  id TEXT PRIMARY KEY,
  source_session_id TEXT NOT NULL REFERENCES sessions(id),
  target_agent TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN ('nativeIdentity','continuation','archiveOnly')),
  source_native_id TEXT,
  target_native_id TEXT,
  source_provider TEXT,
  target_provider TEXT,
  source_hash TEXT NOT NULL,
  target_hash TEXT,
  reason_code TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(source_session_id, target_agent, outcome, target_native_id)
);
CREATE INDEX idx_restore_mappings_source ON session_restore_mappings(source_session_id, created_at DESC);
UPDATE schema_meta SET value = '2' WHERE key = 'schema_version';
