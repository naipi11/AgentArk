use std::collections::BTreeMap;
use std::fs;

use agentark_adapter_codex::{
    NativeRolloutPayload, collect_native_rollouts, restore_native_rollouts,
    rewrite_native_workspace_paths, sanitize_rollout_bytes,
};
use agentark_canonical::{
    CanonicalSchemaVersion, CanonicalSession, Completeness, Sha256Digest, Workspace,
};
use agentark_security::SecretScanner;
use serde_json::json;
use tempfile::tempdir;
use uuid::Uuid;

fn fixture_session() -> CanonicalSession {
    CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id: Uuid::from_u128(201),
        install_id: Uuid::from_u128(202),
        source_session_id: "source-session-201".into(),
        source_kind: "app-server".into(),
        workspace: Some(Workspace {
            id: Uuid::from_u128(203),
            path_native: r"C:\source\project".into(),
            canonical_uri: "file:///C:/source/project".into(),
            git_commit: None,
        }),
        title: Some("Native payload fixture".into()),
        archived: false,
        created_at_raw: None,
        updated_at_raw: None,
        model_provider: None,
        model_name: None,
        completeness: Completeness::Complete,
        messages: Vec::new(),
        tool_events: Vec::new(),
        attachments: Vec::new(),
        raw_extra: BTreeMap::new(),
    }
}

#[test]
fn collects_matching_rollout_and_sanitizes_json_string_values() {
    let root = tempdir().unwrap();
    let sessions = root
        .path()
        .join("sessions")
        .join("2026")
        .join("08")
        .join("23");
    fs::create_dir_all(&sessions).unwrap();
    let source = sessions.join("rollout-2026-08-23T00-00-00-source-session-201.jsonl");
    let raw = [
        json!({"type":"session_meta","payload":{"session_id":"source-session-201","cwd":"C:\\source\\project"}}),
        json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"api_key=fixture-secret-value"}]}}),
    ]
    .iter()
    .map(|value| serde_json::to_string(value).unwrap())
    .collect::<Vec<_>>()
    .join("\n");
    fs::write(&source, format!("{raw}\n")).unwrap();
    let scanner = SecretScanner::v1().unwrap();
    let payloads = collect_native_rollouts(root.path(), &[fixture_session()], &scanner).unwrap();
    assert_eq!(payloads.len(), 1);
    assert!(String::from_utf8_lossy(&payloads[0].bytes).contains("[REDACTED:structured-value]"));
    assert!(!String::from_utf8_lossy(&payloads[0].bytes).contains("fixture-secret-value"));
    assert!(payloads[0].redaction_count > 0);
}

#[test]
fn rewrites_only_workspace_fields_in_native_jsonl() {
    let raw = br#"{"type":"turn_context","payload":{"cwd":"C:\\source\\project","workspace_roots":["C:\\source\\project"],"message":"keep C:\\source\\project"}}
"#;
    let rewritten = rewrite_native_workspace_paths(
        raw,
        &[(r"C:\source\project".into(), r"C:\target\project".into())],
    )
    .unwrap();
    let text = String::from_utf8(rewritten).unwrap();
    assert!(text.contains(r#""cwd":"C:\\target\\project""#));
    assert!(text.contains(r#""message":"keep C:\\source\\project""#));
}

#[test]
fn sanitation_preserves_the_complete_prefix_when_final_jsonl_record_is_partial() {
    let scanner = SecretScanner::v1().unwrap();
    let raw = b"{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"thread\",\"cwd\":\"C:\\\\source\"}}\n{\"type\":\"event_msg\"";
    let (sanitized, _) = sanitize_rollout_bytes(raw, &scanner).unwrap();
    let text = String::from_utf8(sanitized).unwrap();
    assert!(text.contains("session_meta"));
    assert!(!text.contains("event_msg"));
}

#[test]
fn restores_native_rollout_to_codex_home_with_mapping() {
    let root = tempdir().unwrap();
    let payload = NativeRolloutPayload {
        session_id: Uuid::from_u128(204),
        relative_path: "2026/08/23/rollout-native.jsonl".into(),
        bytes: br#"{"type":"session_meta","payload":{"session_id":"native-thread","cwd":"C:\\source\\project"}}
"#
        .to_vec(),
        source_hash: Sha256Digest::from_bytes(b"source"),
        redaction_count: 0,
    };
    let report = restore_native_rollouts(
        &root.path().join("codex"),
        &[payload],
        &[(r"C:\source\project".into(), r"C:\target\project".into())],
        &root.path().join("backups"),
    )
    .unwrap();
    assert_eq!(report.imported_count, 1);
    let restored = root
        .path()
        .join("codex")
        .join("sessions")
        .join("2026")
        .join("08")
        .join("23")
        .join("rollout-native.jsonl");
    let text = fs::read_to_string(restored).unwrap();
    assert!(text.contains(r#""cwd":"C:\\target\\project""#));
    assert!(report.backup_path.is_some());
    assert_eq!(report.written_paths.len(), 1);
}

#[test]
fn restore_rejects_different_existing_rollout_without_overwriting() {
    let root = tempdir().unwrap();
    let codex_home = root.path().join("codex");
    let destination = codex_home
        .join("sessions")
        .join("2026")
        .join("08")
        .join("23")
        .join("rollout-native.jsonl");
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    fs::write(
        &destination,
        br#"{"type":"session_meta","payload":{"session_id":"other-thread","cwd":"C:\\other"}}
"#,
    )
    .unwrap();
    let payload = NativeRolloutPayload {
        session_id: Uuid::from_u128(205),
        relative_path: "2026/08/23/rollout-native.jsonl".into(),
        bytes: br#"{"type":"session_meta","payload":{"session_id":"native-thread","cwd":"C:\\source\\project"}}
"#
        .to_vec(),
        source_hash: Sha256Digest::from_bytes(b"source"),
        redaction_count: 0,
    };
    let result =
        restore_native_rollouts(&codex_home, &[payload], &[], &root.path().join("backups"));
    assert!(matches!(
        result,
        Err(agentark_adapter_codex::NativePayloadError::Conflict)
    ));
    assert!(String::from_utf8_lossy(&fs::read(destination).unwrap()).contains("other-thread"));
}
