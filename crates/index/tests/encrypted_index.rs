use std::{collections::BTreeSet, fs};

use agentark_canonical::{
    AgentInstall, AgentKind, CanonicalMessage, CanonicalSchemaVersion, CanonicalSession,
    Completeness, canonical_hash,
};
use agentark_index::{IndexDb, SessionIndex, SessionIngest, SessionQuery};
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
    assert_eq!(db.search("CanonicalVisibleCanary", 10).unwrap().len(), 1);
    assert_eq!(
        db.connection()
            .query_row(
                "SELECT status FROM scan_runs WHERE id = ?1",
                [scan_id.to_string()],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "complete"
    );
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
