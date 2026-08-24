use std::collections::BTreeSet;

use agentark_canonical::{
    AgentInstall, AgentKind, CanonicalMessage, CanonicalSchemaVersion, CanonicalSession,
    Completeness, Sha256Digest, canonical_hash,
};
use agentark_index::{IndexDb, RestoreMapping, SessionIndex, SessionIngest};
use agentark_migration::RestoreOutcome;
use agentark_security::{DatasetBootstrap, MemoryMasterKeyStore};
use rusqlite::{Connection, params};
use tempfile::TempDir;
use uuid::Uuid;

struct TempIndex {
    directory: TempDir,
    key: [u8; 32],
}

impl TempIndex {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = MemoryMasterKeyStore::empty();
        let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
        let key = *bootstrap.unlock(&store).unwrap().sqlcipher_key();
        Self { directory, key }
    }

    fn path(&self) -> std::path::PathBuf {
        self.directory.path().join("agentark.db")
    }

    fn open(&self) -> IndexDb {
        IndexDb::open(&self.path(), &self.key).unwrap()
    }

    fn raw_connection(&self) -> Connection {
        let connection = Connection::open(self.path()).unwrap();
        let key_sql = format!("PRAGMA key = \"x'{}'\";", hex::encode(self.key));
        connection.execute_batch(&key_sql).unwrap();
        connection
    }
}

fn indexed_session() -> (AgentInstall, CanonicalSession, Sha256Digest) {
    let install = AgentInstall {
        id: Uuid::from_u128(1),
        kind: AgentKind::Codex,
        executable_version: "0.146.0".into(),
        authorized_root_uri: "file:///fixture".into(),
        adapter_version: "0.1.0".into(),
        schema_fingerprint: "sha256:fixture".into(),
        capabilities: BTreeSet::new(),
        quarantine_reason: None,
    };
    let session = CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id: Uuid::from_u128(2),
        install_id: install.id,
        source_session_id: "source-native-session".into(),
        source_kind: "codex".into(),
        workspace: None,
        title: Some("fixture".into()),
        archived: false,
        created_at_raw: None,
        updated_at_raw: None,
        model_provider: Some("openai".into()),
        model_name: Some("fixture".into()),
        completeness: Completeness::Complete,
        messages: vec![CanonicalMessage::text_fixture(1, "same", "fixture")],
        tool_events: Vec::new(),
        attachments: Vec::new(),
        raw_extra: Default::default(),
    };
    let hash = canonical_hash("session", &session).unwrap();
    (install, session, hash)
}

fn insert_indexed_session(index: &mut IndexDb) -> CanonicalSession {
    insert_indexed_session_with(index, Uuid::from_u128(2), "source-native-session")
}

fn insert_indexed_session_with(
    index: &mut IndexDb,
    session_id: Uuid,
    source_session_id: &str,
) -> CanonicalSession {
    let (install, mut session, _) = indexed_session();
    session.id = session_id;
    session.source_session_id = source_session_id.into();
    session.messages[0].id = Uuid::new_v5(&session.id, b"fixture-message");
    let hash = canonical_hash("session", &session).unwrap();
    index
        .ingest_session(SessionIngest {
            install: &install,
            session: &session,
            source_records: &[],
            sanitized_title: "fixture",
            sanitized_body: "fixture",
            findings: &[],
            canonical_hash: &hash,
        })
        .unwrap();
    session
}

fn continuation_mapping(source_session_id: Uuid) -> RestoreMapping {
    RestoreMapping {
        source_session_id,
        target_agent: AgentKind::ClaudeCode,
        outcome: RestoreOutcome::Continuation,
        source_native_id: Some("source-native-session".into()),
        target_native_id: Some("target-native-session".into()),
        source_provider: Some("openai".into()),
        target_provider: Some("anthropic".into()),
        source_hash: Sha256Digest::from_bytes(b"source"),
        target_hash: Some(Sha256Digest::from_bytes(b"target")),
        reason_code: "target-default-continuation".into(),
        created_at: "2026-08-23T00:00:00Z".into(),
    }
}

#[test]
fn records_and_reopens_continuation_mapping() {
    let fixture = TempIndex::new();
    let mut index = fixture.open();
    let session = insert_indexed_session(&mut index);
    let mapping = continuation_mapping(session.id);

    index.record_restore_mapping(&mapping).unwrap();
    drop(index);

    let index = fixture.open();
    assert_eq!(
        index
            .restore_mappings_for(mapping.source_session_id)
            .unwrap(),
        vec![mapping]
    );
}

#[test]
fn ignores_repeated_continuation_and_archive_only_mappings() {
    let fixture = TempIndex::new();
    let mut index = fixture.open();
    let continuation_session = insert_indexed_session(&mut index);
    let archive_session =
        insert_indexed_session_with(&mut index, Uuid::from_u128(3), "archive-native-session");
    let continuation = continuation_mapping(continuation_session.id);
    let archive_only = RestoreMapping {
        source_session_id: archive_session.id,
        source_native_id: Some("archive-native-session".into()),
        target_agent: AgentKind::OpenCode,
        outcome: RestoreOutcome::ArchiveOnly,
        target_native_id: None,
        target_provider: None,
        target_hash: None,
        reason_code: "continuation-writer-unavailable".into(),
        ..continuation.clone()
    };

    index.record_restore_mapping(&continuation).unwrap();
    index.record_restore_mapping(&continuation).unwrap();
    index.record_restore_mapping(&archive_only).unwrap();
    index.record_restore_mapping(&archive_only).unwrap();

    assert_eq!(
        index
            .restore_mappings_for(continuation.source_session_id)
            .unwrap(),
        vec![continuation]
    );
    assert_eq!(
        index
            .restore_mappings_for(archive_only.source_session_id)
            .unwrap(),
        vec![archive_only]
    );
}

#[test]
fn upgrades_version_one_index_without_losing_existing_session() {
    let fixture = TempIndex::new();
    let connection = fixture.raw_connection();
    connection
        .execute_batch(include_str!("../migrations/0001_init.sql"))
        .unwrap();
    let session_id = Uuid::from_u128(9);
    connection
        .execute(
            "INSERT INTO agent_installs(id, kind, executable_version, authorized_root_uri,
             adapter_version, schema_fingerprint, capabilities_json, quarantine_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                Uuid::from_u128(8).to_string(),
                "\"codex\"",
                "0.146.0",
                "file:///fixture",
                "0.1.0",
                "sha256:fixture",
                "[]",
                Option::<String>::None,
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO sessions(id, install_id, workspace_id, source_session_id, source_kind,
             title, archived, completeness, canonical_hash, canonical_json, search_title,
             search_body, model_provider, model_name, revision, stale, last_scan_id)
             VALUES (?1, ?2, NULL, ?3, ?4, NULL, 0, ?5, ?6, ?7, '', '', NULL, NULL, 1, 0, NULL)",
            params![
                session_id.to_string(),
                Uuid::from_u128(8).to_string(),
                "pre-existing",
                "codex",
                "complete",
                Sha256Digest::from_bytes(b"version-one").as_str(),
                "{}",
            ],
        )
        .unwrap();
    drop(connection);

    drop(fixture.open());
    let connection = fixture.raw_connection();
    assert_eq!(
        connection
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "2"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT source_session_id FROM sessions WHERE id = ?1",
                [session_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "pre-existing"
    );
}
