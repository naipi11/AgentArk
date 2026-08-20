use std::collections::BTreeSet;

use agentark_canonical::{
    AgentInstall, AgentKind, CanonicalMessage, CanonicalSchemaVersion, CanonicalSession,
    Completeness, canonical_hash,
};
use agentark_index::{
    IndexDb, ScanManifest, ScanManifestStatus, SessionIndex, SessionIngest, SessionQuery,
};
use agentark_security::{DatasetBootstrap, MemoryMasterKeyStore};
use tempfile::tempdir;
use uuid::Uuid;

fn session(install_id: Uuid, messages: Vec<CanonicalMessage>) -> CanonicalSession {
    CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id: Uuid::new_v4(),
        install_id,
        source_session_id: "thread_tx".into(),
        source_kind: "synthetic".into(),
        workspace: None,
        title: Some("transaction".into()),
        archived: false,
        created_at_raw: None,
        updated_at_raw: None,
        model_provider: None,
        model_name: None,
        completeness: Completeness::Complete,
        messages,
        tool_events: Vec::new(),
        attachments: Vec::new(),
        raw_extra: Default::default(),
    }
}

#[test]
fn duplicate_ordinals_rollback_without_removing_the_previous_revision() {
    let dir = tempdir().unwrap();
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
    let keys = bootstrap.unlock(&store).unwrap();
    let db_path = dir.path().join("agentark.db");
    let mut db = IndexDb::open(&db_path, keys.sqlcipher_key()).unwrap();
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
    let first = session(
        install.id,
        vec![CanonicalMessage::text_fixture(1, "same", "first")],
    );
    let first_hash = canonical_hash("session", &first).unwrap();
    db.ingest_session(SessionIngest {
        install: &install,
        session: &first,
        source_records: &[],
        sanitized_title: "transaction",
        sanitized_body: "first",
        findings: &[],
        canonical_hash: &first_hash,
    })
    .unwrap();
    let invalid = session(
        install.id,
        vec![
            CanonicalMessage::text_fixture(1, "same", "one"),
            CanonicalMessage::text_fixture(1, "same", "two"),
        ],
    );
    let invalid_hash = canonical_hash("session", &invalid).unwrap();
    assert!(
        db.ingest_session(SessionIngest {
            install: &install,
            session: &invalid,
            source_records: &[],
            sanitized_title: "transaction",
            sanitized_body: "invalid",
            findings: &[],
            canonical_hash: &invalid_hash,
        })
        .is_err()
    );
    let detail = db.show_session(first.id).unwrap();
    assert_eq!(detail.session.messages[0].visible_text(), "first");
}

#[test]
fn out_of_order_ordinals_are_rejected_before_publication() {
    let dir = tempdir().unwrap();
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
    let keys = bootstrap.unlock(&store).unwrap();
    let db_path = dir.path().join("agentark.db");
    let mut db = IndexDb::open(&db_path, keys.sqlcipher_key()).unwrap();
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
    let session = session(
        install.id,
        vec![
            CanonicalMessage::text_fixture(2, "same", "second"),
            CanonicalMessage::text_fixture(1, "same", "first"),
        ],
    );
    let hash = canonical_hash("session", &session).unwrap();
    assert!(
        db.ingest_session(SessionIngest {
            install: &install,
            session: &session,
            source_records: &[],
            sanitized_title: "transaction",
            sanitized_body: "out-of-order",
            findings: &[],
            canonical_hash: &hash,
        })
        .is_err()
    );
    assert_eq!(db.list_sessions(10, 0).unwrap().len(), 0);
}

#[test]
fn failed_scan_marks_retained_sessions_stale() {
    let dir = tempdir().unwrap();
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
    let keys = bootstrap.unlock(&store).unwrap();
    let db_path = dir.path().join("agentark.db");
    let mut db = IndexDb::open(&db_path, keys.sqlcipher_key()).unwrap();
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
    let scan_id = Uuid::new_v4();
    db.begin_scan(scan_id, "fixture", "snapshot").unwrap();
    let session = session(
        install.id,
        vec![CanonicalMessage::text_fixture(1, "same", "retained")],
    );
    let hash = canonical_hash("session", &session).unwrap();
    db.ingest_session(SessionIngest {
        install: &install,
        session: &session,
        source_records: &[],
        sanitized_title: "retained",
        sanitized_body: "retained",
        findings: &[],
        canonical_hash: &hash,
    })
    .unwrap();
    db.finish_scan(&ScanManifest {
        id: scan_id,
        status: ScanManifestStatus::Complete,
        completed_at: "now".into(),
        indexed_count: 1,
        quarantined_count: 0,
        retryable_count: 0,
        rejected_count: 0,
    })
    .unwrap();
    let failed_scan = Uuid::new_v4();
    db.begin_scan(failed_scan, "fixture", "snapshot-2").unwrap();
    db.fail_scan(failed_scan).unwrap();
    assert!(db.list_sessions(10, 0).unwrap()[0].stale);
}
