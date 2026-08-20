use std::collections::BTreeSet;
use std::fs;
use std::time::Instant;

use agentark_canonical::{
    AgentInstall, AgentKind, CanonicalSchemaVersion, CanonicalSession, Completeness, canonical_hash,
};
use agentark_index::{IndexDb, SessionIndex, SessionIngest, SessionQuery};
use agentark_security::{DatasetBootstrap, MemoryMasterKeyStore};
use serde::Serialize;
use tempfile::tempdir;
use uuid::Uuid;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BenchResult {
    sessions: u64,
    message_parts: u64,
    p50_ms: f64,
    p95_ms: f64,
}

fn main() {
    let temp = tempdir().expect("tempdir");
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).expect("bootstrap");
    let keys = bootstrap.unlock(&store).expect("keys");
    let db_path = temp.path().join("bench.db");
    let mut db = IndexDb::open(&db_path, keys.sqlcipher_key()).expect("db");
    let install = AgentInstall {
        id: Uuid::new_v4(),
        kind: AgentKind::Codex,
        executable_version: "fixture".into(),
        authorized_root_uri: "file:///bench".into(),
        adapter_version: "0.1.0".into(),
        schema_fingerprint: "sha256:bench".into(),
        capabilities: BTreeSet::new(),
        quarantine_reason: None,
    };
    for ordinal in 0..1_000u128 {
        let session = CanonicalSession {
            schema_version: CanonicalSchemaVersion::V0_1_0,
            id: Uuid::from_u128(ordinal + 1),
            install_id: install.id,
            source_session_id: format!("bench-{ordinal}"),
            source_kind: "synthetic".into(),
            workspace: None,
            title: Some("deterministic needle".into()),
            archived: false,
            created_at_raw: None,
            updated_at_raw: None,
            model_provider: None,
            model_name: None,
            completeness: Completeness::Complete,
            messages: Vec::new(),
            tool_events: Vec::new(),
            attachments: Vec::new(),
            raw_extra: Default::default(),
        };
        let hash = canonical_hash("session", &session).expect("hash");
        db.ingest_session(SessionIngest {
            install: &install,
            session: &session,
            source_records: &[],
            sanitized_title: "deterministic needle",
            sanitized_body: "deterministic needle",
            findings: &[],
            canonical_hash: &hash,
        })
        .expect("ingest");
    }
    for _ in 0..5 {
        let _ = db.search("deterministic needle", 50);
    }
    let mut samples = Vec::new();
    for _ in 0..100 {
        let start = Instant::now();
        let hits = db.search("deterministic needle", 50).expect("search");
        assert_eq!(hits.len(), 50);
        samples.push(start.elapsed().as_secs_f64() * 1_000.0);
    }
    samples.sort_by(f64::total_cmp);
    let result = BenchResult {
        sessions: 1_000,
        message_parts: 0,
        p50_ms: samples[49],
        p95_ms: samples[94],
    };
    let path = std::env::var_os("AGENTARK_BENCH_OUTPUT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/agentark-bench/search.json")
        });
    fs::create_dir_all(path.parent().expect("parent")).expect("bench dir");
    fs::write(path, serde_json::to_vec_pretty(&result).expect("json")).expect("report");
    if std::env::var_os("AGENTARK_ENFORCE_BENCH").is_some() && result.p95_ms > 150.0 {
        std::process::exit(1);
    }
}
