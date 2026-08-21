use std::collections::BTreeSet;
use std::fs;
use std::time::Instant;

use agentark_canonical::{
    AgentInstall, AgentKind, CanonicalMessage, CanonicalRole, CanonicalSchemaVersion,
    CanonicalSession, Completeness, ContentPart, ContentPartKind, Sha256Digest, canonical_hash,
    message_id,
};
use agentark_index::{IndexDb, SessionQuery};
use agentark_security::{DatasetBootstrap, MemoryMasterKeyStore};
use rusqlite::params;
use serde::Serialize;
use tempfile::tempdir;
use uuid::Uuid;

const SESSION_COUNT: u64 = 100_000;
const MESSAGE_PARTS_PER_SESSION: u64 = 10;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BenchResult {
    sessions: u64,
    message_parts: u64,
    p50_ms: f64,
    p95_ms: f64,
}

fn main() {
    let session_count = std::env::var("AGENTARK_BENCH_SESSIONS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(SESSION_COUNT);
    let message_parts_per_session = std::env::var("AGENTARK_BENCH_MESSAGE_PARTS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(MESSAGE_PARTS_PER_SESSION);
    let temp = tempdir().expect("tempdir");
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).expect("bootstrap");
    let keys = bootstrap.unlock(&store).expect("keys");
    let db_path = temp.path().join("bench.db");
    let db = IndexDb::open(&db_path, keys.sqlcipher_key()).expect("db");
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
    let transaction = db
        .connection()
        .unchecked_transaction()
        .expect("bulk transaction");
    let install_json = serde_json::to_string(&install.kind).expect("install kind");
    let capabilities_json = serde_json::to_string(&install.capabilities).expect("capabilities");
    transaction
        .execute(
            "INSERT INTO agent_installs(id, kind, executable_version, authorized_root_uri,
             adapter_version, schema_fingerprint, capabilities_json, quarantine_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                install.id.to_string(),
                install_json,
                install.executable_version,
                install.authorized_root_uri,
                install.adapter_version,
                install.schema_fingerprint,
                capabilities_json,
                install.quarantine_reason,
            ],
        )
        .expect("install");
    for ordinal in 0..session_count as u128 {
        let session_id = Uuid::from_u128(ordinal + 1);
        let messages = (0..message_parts_per_session)
            .map(|message_ordinal| {
                let text = if ordinal % 100 == 0 {
                    format!("deterministic needle {ordinal}-{message_ordinal}")
                } else {
                    format!("background fixture {ordinal}-{message_ordinal}")
                };
                let raw_ref = Sha256Digest::from_bytes(text.as_bytes());
                CanonicalMessage {
                    id: message_id(
                        session_id,
                        Some(&format!("bench:{message_ordinal}")),
                        message_ordinal,
                        &raw_ref,
                    ),
                    source_record_id: Some(format!("bench:{message_ordinal}")),
                    ordinal: message_ordinal,
                    role: if message_ordinal == 0 {
                        CanonicalRole::User
                    } else {
                        CanonicalRole::Assistant
                    },
                    raw_role: Some("assistant".into()),
                    created_at_raw: None,
                    content: vec![ContentPart {
                        kind: ContentPartKind::Text,
                        text: Some(text),
                        attachment_id: None,
                        raw_extra: Default::default(),
                    }],
                    raw_ref,
                }
            })
            .collect::<Vec<_>>();
        let session = CanonicalSession {
            schema_version: CanonicalSchemaVersion::V0_1_0,
            id: session_id,
            install_id: install.id,
            source_session_id: format!("bench-{ordinal}"),
            source_kind: "synthetic".into(),
            workspace: None,
            title: Some(format!("bench session {ordinal}")),
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
        };
        let hash = canonical_hash("session", &session).expect("hash");
        let sanitized_body = session.searchable_text();
        let canonical_json = serde_json::to_string(&session).expect("canonical json");
        transaction
            .execute(
                "INSERT INTO sessions(id, install_id, source_session_id, source_kind,
                 title, archived, completeness, canonical_hash, canonical_json, search_title,
                 search_body, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, 'complete', ?6, ?7, ?8, ?9, 1)",
                params![
                    session.id.to_string(),
                    install.id.to_string(),
                    session.source_session_id,
                    session.source_kind,
                    session.title,
                    hash.as_str(),
                    canonical_json,
                    session.title.as_deref().unwrap_or("session"),
                    sanitized_body,
                ],
            )
            .expect("session");
        for message in &session.messages {
            transaction
                .execute(
                    "INSERT INTO messages(id, session_id, ordinal, role, raw_role, visible_text,
                     raw_ref, message_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        message.id.to_string(),
                        session.id.to_string(),
                        message.ordinal as i64,
                        serde_json::to_string(&message.role).expect("role"),
                        message.raw_role,
                        message.visible_text(),
                        message.raw_ref.as_str(),
                        serde_json::to_string(message).expect("message json"),
                    ],
                )
                .expect("message");
        }
        transaction
            .execute(
                "INSERT INTO session_fts(session_id, title, body) VALUES (?1, ?2, ?3)",
                params![
                    session.id.to_string(),
                    session.title.as_deref().unwrap_or("session"),
                    sanitized_body,
                ],
            )
            .expect("fts");
    }
    transaction.commit().expect("bulk commit");
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
        sessions: session_count,
        message_parts: session_count * message_parts_per_session,
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
