CREATE TABLE schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT INTO schema_meta(key, value) VALUES ('schema_version', '1');

CREATE TABLE scan_runs (
  id TEXT PRIMARY KEY,
  adapter_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('running','complete','partial','failed')),
  started_at TEXT NOT NULL,
  completed_at TEXT,
  indexed_count INTEGER NOT NULL DEFAULT 0,
  quarantined_count INTEGER NOT NULL DEFAULT 0,
  retryable_count INTEGER NOT NULL DEFAULT 0,
  rejected_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE agent_installs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  executable_version TEXT NOT NULL,
  authorized_root_uri TEXT NOT NULL,
  adapter_version TEXT NOT NULL,
  schema_fingerprint TEXT NOT NULL,
  capabilities_json TEXT NOT NULL,
  quarantine_reason TEXT
);

CREATE TABLE workspaces (
  id TEXT PRIMARY KEY,
  path_native TEXT NOT NULL,
  canonical_uri TEXT NOT NULL,
  git_commit TEXT
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  install_id TEXT NOT NULL REFERENCES agent_installs(id),
  workspace_id TEXT REFERENCES workspaces(id),
  source_session_id TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  title TEXT,
  archived INTEGER NOT NULL CHECK(archived IN (0,1)),
  completeness TEXT NOT NULL,
  canonical_hash TEXT NOT NULL,
  canonical_json TEXT NOT NULL,
  search_title TEXT NOT NULL,
  search_body TEXT NOT NULL,
  model_provider TEXT,
  model_name TEXT,
  revision INTEGER NOT NULL,
  stale INTEGER NOT NULL DEFAULT 0 CHECK(stale IN (0,1)),
  last_scan_id TEXT,
  UNIQUE(install_id, source_session_id)
);

CREATE TABLE messages (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  role TEXT NOT NULL,
  raw_role TEXT,
  visible_text TEXT NOT NULL,
  raw_ref TEXT NOT NULL,
  message_json TEXT NOT NULL,
  UNIQUE(session_id, ordinal)
);

CREATE TABLE tool_events (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  tool_name TEXT NOT NULL,
  status TEXT NOT NULL,
  visible_input TEXT,
  visible_output TEXT,
  raw_ref TEXT NOT NULL,
  UNIQUE(session_id, ordinal)
);

CREATE TABLE attachments (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  source_locator TEXT NOT NULL,
  media_type TEXT,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  raw_ref TEXT NOT NULL
);

CREATE TABLE source_records (
  id TEXT PRIMARY KEY,
  raw_sha256 TEXT NOT NULL,
  session_id TEXT,
  source_locator TEXT NOT NULL,
  source_record_id TEXT,
  ordinal INTEGER NOT NULL,
  cas_object_id TEXT NOT NULL,
  adapter_version TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  UNIQUE(source_locator, snapshot_id)
);

CREATE TABLE quarantines (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scan_runs(id),
  source_locator TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  raw_sha256 TEXT NOT NULL,
  cas_object_id TEXT NOT NULL
);

CREATE TABLE secret_findings (
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  class TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  start_offset INTEGER NOT NULL,
  end_offset INTEGER NOT NULL
);

CREATE TABLE verification_records (
  scan_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  object_id TEXT NOT NULL,
  object_type INTEGER NOT NULL,
  plaintext_hash TEXT NOT NULL,
  size INTEGER NOT NULL,
  session_json TEXT,
  canonical_hash TEXT,
  sanitized_title TEXT,
  sanitized_body TEXT,
  PRIMARY KEY(scan_id, object_id)
);

CREATE VIRTUAL TABLE session_fts USING fts5(
  session_id UNINDEXED,
  title,
  body,
  tokenize = 'unicode61 remove_diacritics 2'
);
