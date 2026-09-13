use std::{collections::BTreeSet, fs};

use agentark_canonical::{
    AgentInstall, AgentKind, CanonicalMessage, CanonicalSchemaVersion, CanonicalSession,
    Completeness, ContentPart, ContentPartKind, SourceRecord, Workspace, canonical_hash,
    workspace_id,
};
use agentark_index::{IndexDb, RawProvenanceStatus, SessionIndex, SessionIngest, SessionQuery};
use agentark_security::{DatasetBootstrap, MemoryMasterKeyStore, SanitizedText};
use tempfile::tempdir;
use uuid::Uuid;

fn fixture() -> (AgentInstall, CanonicalSession, SanitizedText) {
    let install = AgentInstall {
        id: Uuid::new_v4(),
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
        id: Uuid::new_v4(),
        install_id: install.id,
        source_session_id: "thread_fixture".into(),
        source_kind: "cli".into(),
        workspace: None,
        title: Some("CanonicalVisibleCanary".into()),
        archived: false,
        created_at_raw: None,
        updated_at_raw: None,
        model_provider: Some("openai".into()),
        model_name: Some("fixture".into()),
        completeness: Completeness::Complete,
        messages: vec![CanonicalMessage::text_fixture(
            1,
            "same",
            "CanonicalVisibleCanary",
        )],
        tool_events: Vec::new(),
        attachments: Vec::new(),
        raw_extra: Default::default(),
    };
    let sanitized = SanitizedText {
        text: "[REDACTED:vendor-token]".into(),
        findings: Vec::new(),
    };
    (install, session, sanitized)
}

#[test]
fn encrypts_canonical_text_and_searches_only_sanitized_fts() {
    let dir = tempdir().unwrap();
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
    let keys = bootstrap.unlock(&store).unwrap();
    let db_path = dir.path().join("agentark.db");
    let mut db = IndexDb::open(&db_path, keys.sqlcipher_key()).unwrap();
    let (install, session, _sanitized) = fixture();
    let body = "[REDACTED:vendor-token]";
    let title = "[REDACTED:vendor-token]";
    let canonical_hash = canonical_hash("session", &session).unwrap();
    db.ingest_session(SessionIngest {
        install: &install,
        session: &session,
        source_records: &[],
        sanitized_title: title,
        sanitized_body: body,
        findings: &[],
        canonical_hash: &canonical_hash,
    })
    .unwrap();
    let file = fs::read(db_path).unwrap();
    assert!(
        !file
            .windows("CanonicalVisibleCanary".len())
            .any(|window| window == b"CanonicalVisibleCanary")
    );
    assert_eq!(db.search("vendor-token", 10).unwrap().len(), 1);
    assert_eq!(db.search("CanonicalVisibleCanary", 10).unwrap().len(), 0);
    assert!(db.cipher_version().unwrap().starts_with("4."));
    assert!(db.fts5_enabled().unwrap());
}

#[test]
fn reopens_existing_encrypted_index_without_reapplying_migrations() {
    let dir = tempdir().unwrap();
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
    let keys = bootstrap.unlock(&store).unwrap();
    let db_path = dir.path().join("agentark.db");
    let first = IndexDb::open(&db_path, keys.sqlcipher_key()).unwrap();
    assert!(first.fts5_enabled().unwrap());
    drop(first);
    let second = IndexDb::open(&db_path, keys.sqlcipher_key()).unwrap();
    assert!(second.fts5_enabled().unwrap());
}

#[test]
fn restores_bundle_sessions_into_searchable_archive() {
    let dir = tempdir().unwrap();
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
    let keys = bootstrap.unlock(&store).unwrap();
    let mut db = IndexDb::open(&dir.path().join("agentark.db"), keys.sqlcipher_key()).unwrap();
    let (_install, session, _) = fixture();
    let scan_id = db.restore_sessions(std::slice::from_ref(&session)).unwrap();
    assert!(db.show_session(session.id).is_ok());
    assert_eq!(
        db.show_session(session.id).unwrap().raw_provenance_status,
        RawProvenanceStatus::Unresolved
    );
    assert_eq!(db.search("CanonicalVisibleCanary", 10).unwrap().len(), 1);
    let snapshot = db.verification_snapshot(scan_id).unwrap();
    assert_eq!(snapshot.status, "complete");
    assert_eq!(snapshot.records.len(), 1);
    assert_eq!(snapshot.indexed_count, 1);
}

#[test]
fn restore_sanitizes_all_persisted_session_text() {
    let dir = tempdir().unwrap();
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
    let keys = bootstrap.unlock(&store).unwrap();
    let mut db = IndexDb::open(&dir.path().join("agentark.db"), keys.sqlcipher_key()).unwrap();
    let (install, mut session, _) = fixture();
    let secret = "api_key=sk-proj-abcdefghijklmnopqrstuvwxyz";
    session.title = Some(secret.into());
    session.messages[0].content = vec![ContentPart {
        kind: ContentPartKind::Text,
        text: Some(secret.into()),
        attachment_id: None,
        raw_extra: Default::default(),
    }];
    session
        .raw_extra
        .insert("credentials".into(), serde_json::json!({"token": secret}));
    db.restore_sessions(std::slice::from_ref(&session)).unwrap();
    let detail = db.show_session(session.id).unwrap();
    let serialized = serde_json::to_string(&detail.session).unwrap();
    assert!(!serialized.contains("abcdefghijklmnopqrstuvwxyz"));
    assert!(serialized.contains("[REDACTED:"));
    let _ = install;
}

#[test]
fn raw_provenance_status_distinguishes_none_and_available() {
    let dir = tempdir().unwrap();
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
    let keys = bootstrap.unlock(&store).unwrap();
    let mut db = IndexDb::open(&dir.path().join("agentark.db"), keys.sqlcipher_key()).unwrap();
    let (install, mut empty, _) = fixture();
    empty.messages.clear();
    empty.id = Uuid::from_u128(101);
    empty.source_session_id = "empty-provenance".into();
    let empty_hash = canonical_hash("session", &empty).unwrap();
    db.ingest_session(SessionIngest {
        install: &install,
        session: &empty,
        source_records: &[],
        sanitized_title: "empty",
        sanitized_body: "empty",
        findings: &[],
        canonical_hash: &empty_hash,
    })
    .unwrap();
    assert_eq!(
        db.show_session(empty.id).unwrap().raw_provenance_status,
        RawProvenanceStatus::None
    );

    let (available_install, mut available_session, _) = fixture();
    let source_record = SourceRecord {
        source_locator: "fixture.jsonl".into(),
        source_record_id: Some("record-1".into()),
        ordinal: 0,
        raw_sha256: available_session.messages[0].raw_ref.clone(),
        cas_object_id: "dataset-object".into(),
        adapter_version: "fixture".into(),
        snapshot_id: "snapshot-1".into(),
    };
    available_session.id = Uuid::from_u128(102);
    available_session.source_session_id = "available-provenance".into();
    let session_hash = canonical_hash("session", &available_session).unwrap();
    db.ingest_session(SessionIngest {
        install: &available_install,
        session: &available_session,
        source_records: std::slice::from_ref(&source_record),
        sanitized_title: "available",
        sanitized_body: "available",
        findings: &[],
        canonical_hash: &session_hash,
    })
    .unwrap();
    assert_eq!(
        db.show_session(available_session.id)
            .unwrap()
            .raw_provenance_status,
        RawProvenanceStatus::Available
    );
    assert!(db.list_sessions(10, 0).unwrap().iter().any(|summary| {
        summary.id == available_session.id
            && summary.raw_provenance_status == RawProvenanceStatus::Available
    }));

    let (_, unresolved_session, _) = fixture();
    assert!(
        db.restore_sessions_with_provenance(
            std::slice::from_ref(&unresolved_session),
            RawProvenanceStatus::Available,
        )
        .is_err()
    );
    assert!(
        db.restore_sessions_with_provenance(
            std::slice::from_ref(&unresolved_session),
            RawProvenanceStatus::None,
        )
        .is_err()
    );
    db.restore_sessions_with_provenance(
        std::slice::from_ref(&unresolved_session),
        RawProvenanceStatus::Unresolved,
    )
    .unwrap();
}

#[test]
fn filters_sessions_and_projects_by_agent_kind() {
    let dir = tempdir().unwrap();
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
    let keys = bootstrap.unlock(&store).unwrap();
    let mut db = IndexDb::open(&dir.path().join("agentark.db"), keys.sqlcipher_key()).unwrap();
    let (codex_install, mut codex_session, _) = fixture();
    codex_session.workspace = Some(Workspace {
        id: workspace_id("file:///C:/codex"),
        path_native: "C:\\codex".into(),
        canonical_uri: "file:///C:/codex".into(),
        git_commit: None,
    });
    let codex_hash = canonical_hash("session", &codex_session).unwrap();
    db.ingest_session(SessionIngest {
        install: &codex_install,
        session: &codex_session,
        source_records: &[],
        sanitized_title: "codex",
        sanitized_body: "shared shared shared codex",
        findings: &[],
        canonical_hash: &codex_hash,
    })
    .unwrap();
    let (mut claude_install, mut claude_session, _) = fixture();
    claude_install.kind = AgentKind::ClaudeCode;
    claude_session.install_id = claude_install.id;
    claude_session.source_kind = "claude-code".into();
    claude_session.source_session_id = "claude-session".into();
    claude_session.messages[0].id = Uuid::new_v4();
    claude_session.workspace = Some(Workspace {
        id: workspace_id("file:///C:/claude"),
        path_native: "C:\\claude".into(),
        canonical_uri: "file:///C:/claude".into(),
        git_commit: None,
    });
    let claude_hash = canonical_hash("session", &claude_session).unwrap();
    db.ingest_session(SessionIngest {
        install: &claude_install,
        session: &claude_session,
        source_records: &[],
        sanitized_title: "claude",
        sanitized_body: "shared claude",
        findings: &[],
        canonical_hash: &claude_hash,
    })
    .unwrap();
    assert_eq!(
        db.list_sessions_filtered(Some(AgentKind::Codex), 10, 0)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        db.list_sessions_filtered(Some(AgentKind::ClaudeCode), 10, 0)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        db.list_workspaces_filtered(Some(AgentKind::Codex), 10, 0)
            .unwrap()[0]
            .path_native,
        "C:\\codex"
    );
    assert_eq!(
        db.search_filtered("codex", Some(AgentKind::Codex), 10)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        db.search_filtered("codex", Some(AgentKind::ClaudeCode), 10)
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        db.search_filtered("claude", Some(AgentKind::ClaudeCode), 10)
            .unwrap()
            .len(),
        1
    );
    let filtered = db
        .search_filtered("shared", Some(AgentKind::ClaudeCode), 1)
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].session_id, claude_session.id);
}

#[test]
fn search_limit_is_applied_after_rank_ordering() {
    let dir = tempdir().unwrap();
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
    let keys = bootstrap.unlock(&store).unwrap();
    let mut db = IndexDb::open(&dir.path().join("agentark.db"), keys.sqlcipher_key()).unwrap();
    let (install, mut best, _) = fixture();
    best.id = Uuid::from_u128(10);
    best.source_session_id = "best".into();
    let best_hash = canonical_hash("session", &best).unwrap();
    db.ingest_session(SessionIngest {
        install: &install,
        session: &best,
        source_records: &[],
        sanitized_title: "best",
        sanitized_body: "needle needle needle",
        findings: &[],
        canonical_hash: &best_hash,
    })
    .unwrap();
    let mut weaker = best.clone();
    weaker.id = Uuid::from_u128(11);
    weaker.source_session_id = "weaker".into();
    weaker.messages.clear();
    let weaker_hash = canonical_hash("session", &weaker).unwrap();
    db.ingest_session(SessionIngest {
        install: &install,
        session: &weaker,
        source_records: &[],
        sanitized_title: "weaker",
        sanitized_body: "needle",
        findings: &[],
        canonical_hash: &weaker_hash,
    })
    .unwrap();
    let hits = db.search("needle", 1).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].session_id, best.id);
}
