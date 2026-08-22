use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use agentark_adapter_codex::{build_rollout_lines, write_rollout_atomic};
use agentark_canonical::{
    CanonicalMessage, CanonicalRole, CanonicalSchemaVersion, CanonicalSession, Completeness,
    ContentPart, ContentPartKind, Sha256Digest, Workspace,
};
use serde_json::{Value, json};
use tempfile::tempdir;
use uuid::Uuid;

fn fixture_session() -> CanonicalSession {
    let session_id = Uuid::from_u128(1);
    let raw_ref = Sha256Digest::from_bytes(b"fixture");
    let message = |id: u128, ordinal: u64, role: CanonicalRole, text: &str| CanonicalMessage {
        id: Uuid::from_u128(id),
        source_record_id: Some(format!("message-{ordinal}")),
        ordinal,
        role,
        raw_role: None,
        created_at_raw: Some("2026-08-23T00:00:00Z".into()),
        content: vec![ContentPart {
            kind: ContentPartKind::Text,
            text: Some(text.into()),
            attachment_id: None,
            raw_extra: BTreeMap::new(),
        }],
        raw_ref: raw_ref.clone(),
    };
    let mut raw_extra = BTreeMap::new();
    raw_extra.insert("secret".into(), json!("fixture-secret-value"));
    raw_extra.insert("hiddenReasoning".into(), json!("hidden-reasoning-value"));
    CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id: session_id,
        install_id: Uuid::from_u128(2),
        source_session_id: "source-session-1".into(),
        source_kind: "app-server".into(),
        workspace: Some(Workspace {
            id: Uuid::from_u128(3),
            path_native: r"C:\restore\project".into(),
            canonical_uri: "file:///C:/restore/project".into(),
            git_commit: None,
        }),
        title: Some("Imported fixture".into()),
        archived: false,
        created_at_raw: Some("2026-08-23T00:00:00Z".into()),
        updated_at_raw: Some("2026-08-23T00:01:00Z".into()),
        model_provider: Some("openai".into()),
        model_name: Some("gpt-5.6-sol".into()),
        completeness: Completeness::Complete,
        messages: vec![
            message(10, 1, CanonicalRole::User, "Imported user message"),
            message(
                11,
                2,
                CanonicalRole::Assistant,
                "Imported assistant message",
            ),
        ],
        tool_events: Vec::new(),
        attachments: Vec::new(),
        raw_extra,
    }
}

#[test]
fn materializes_user_and_assistant_turn_events() {
    let session = fixture_session();
    let lines = build_rollout_lines(
        &session,
        "01native-thread",
        Path::new(r"C:\restore\project"),
    )
    .unwrap();
    let values: Vec<Value> = lines
        .iter()
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert!(values.iter().any(|value| value["type"] == "session_meta"));
    assert!(values
        .iter()
        .any(|value| value["type"] == "event_msg" && value["payload"]["type"] == "user_message"));
    assert!(values.iter().any(|value| {
        value["type"] == "event_msg" && value["payload"]["type"] == "agent_message"
    }));
    assert!(values.iter().any(|value| {
        value["type"] == "event_msg" && value["payload"]["type"] == "task_complete"
    }));
}

#[test]
fn materializer_excludes_credentials_and_hidden_reasoning() {
    let session = fixture_session();
    let bytes = build_rollout_lines(
        &session,
        "01native-thread",
        Path::new(r"C:\restore\project"),
    )
    .unwrap()
    .concat();
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains("fixture-secret-value"));
    assert!(!text.contains("hidden-reasoning-value"));
}

#[test]
fn atomic_rollout_write_returns_stable_hash_and_preserves_bytes() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("rollout.jsonl");
    let lines = build_rollout_lines(
        &fixture_session(),
        "01native-thread",
        Path::new(r"C:\restore\project"),
    )
    .unwrap();
    let digest = write_rollout_atomic(&path, &lines).unwrap();
    assert_eq!(fs::read(&path).unwrap(), lines.concat());
    assert_eq!(digest, Sha256Digest::from_bytes(&fs::read(&path).unwrap()));
}
