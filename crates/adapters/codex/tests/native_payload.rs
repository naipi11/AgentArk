use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(windows)]
use std::process::Command;

use agentark_adapter_codex::{
    NativeImportError, NativePayloadError, NativeRolloutPayload,
    build_canonical_continuation_source, canonical_visible_history, collect_native_rollouts,
    native_thread_expectation, restore_native_rollouts, restore_native_rollouts_guarded,
    rewrite_native_workspace_paths, sanitize_rollout_bytes,
};
use agentark_canonical::{
    Attachment, CanonicalMessage, CanonicalRole, CanonicalSchemaVersion, CanonicalSession,
    Completeness, ContentPart, ContentPartKind, Sha256Digest, ToolEvent, Workspace,
};
use agentark_security::SecretScanner;
use serde_json::json;
use tempfile::tempdir;
use uuid::Uuid;

#[cfg(windows)]
fn link_directory(link: &Path, target: &Path) {
    let status = Command::new("cmd.exe")
        .args([
            "/C",
            "mklink",
            "/J",
            link.to_string_lossy().as_ref(),
            target.to_string_lossy().as_ref(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(unix)]
fn link_directory(link: &Path, target: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

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

fn visible_message(ordinal: u64, role: CanonicalRole, text: &str) -> CanonicalMessage {
    CanonicalMessage {
        id: Uuid::from_u128(300 + ordinal as u128),
        source_record_id: Some(format!("visible-{ordinal}")),
        ordinal,
        role,
        raw_role: None,
        created_at_raw: None,
        content: vec![ContentPart {
            kind: ContentPartKind::Text,
            text: Some(text.into()),
            attachment_id: None,
            raw_extra: BTreeMap::new(),
        }],
        raw_ref: Sha256Digest::from_bytes(text.as_bytes()),
    }
}

#[test]
fn canonical_builder_preserves_exact_visible_order_without_native_payload() {
    let mut session = fixture_session();
    session.messages = vec![
        visible_message(2, CanonicalRole::Assistant, "assistant exact\ntext"),
        visible_message(1, CanonicalRole::User, "user exact text"),
        visible_message(3, CanonicalRole::User, "second user"),
    ];
    session.title = Some("Sanitized continuation title".into());
    let target_cwd = PathBuf::from(r"C:\restored\project");

    let first =
        build_canonical_continuation_source(&session, &target_cwd, "openai", "gpt-5").unwrap();
    let second =
        build_canonical_continuation_source(&session, &target_cwd, "openai", "gpt-5").unwrap();

    assert_eq!(first.thread_id, second.thread_id);
    assert_eq!(first.bytes, second.bytes);
    assert_eq!(first.visible_history.message_count, 3);
    assert_eq!(first.title.as_deref(), Some("Sanitized continuation title"));
    let records = first
        .bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 7);
    assert_eq!(records[0]["type"], "session_meta");
    assert_eq!(records[0]["payload"]["id"], first.thread_id);
    assert_eq!(
        records[0]["payload"]["cwd"],
        target_cwd.to_string_lossy().as_ref()
    );
    assert_eq!(records[0]["payload"]["model_provider"], "openai");
    assert_eq!(records[0]["payload"]["model"], "gpt-5");
    assert_eq!(
        records[0]["payload"]["agentark"]["title"],
        "Sanitized continuation title"
    );
    let response_items = records[1..]
        .iter()
        .step_by(2)
        .map(|record| {
            (
                record["payload"]["role"].as_str().unwrap(),
                record["payload"]["content"][0]["type"].as_str().unwrap(),
                record["payload"]["content"][0]["text"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        response_items,
        [
            ("user", "input_text", "user exact text"),
            ("assistant", "output_text", "assistant exact\ntext"),
            ("user", "input_text", "second user"),
        ]
    );
    assert!(
        records[1..]
            .iter()
            .step_by(2)
            .all(|record| record["type"] == "response_item"
                && record["payload"]["type"] == "message")
    );
    let visible_events = records[2..]
        .iter()
        .step_by(2)
        .map(|record| {
            (
                record["payload"]["type"].as_str().unwrap(),
                record["payload"]["message"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        visible_events,
        [
            ("user_message", "user exact text"),
            ("agent_message", "assistant exact\ntext"),
            ("user_message", "second user"),
        ]
    );
    assert!(
        records[2..]
            .iter()
            .step_by(2)
            .all(|record| record["type"] == "event_msg")
    );
}

#[test]
fn canonical_builder_excludes_every_private_or_non_visible_canary() {
    let canaries = [
        "NATIVE_BYTE_CANARY",
        "sk-proj-builder-token-canary-123456789",
        "https://private-endpoint.invalid/v1",
        "REASONING_CANARY",
        "DEVELOPER_SYSTEM_CANARY",
        "TOOL_CANARY",
        "ATTACHMENT_CANARY",
        "RAW_EXTRA_CANARY",
    ];
    let mut session = fixture_session();
    session.messages = vec![visible_message(1, CanonicalRole::User, "only visible text")];
    session.messages[0].content[0].raw_extra = BTreeMap::from([(
        "private".into(),
        json!([
            canaries[0],
            canaries[1],
            canaries[2],
            canaries[3],
            canaries[4],
            canaries[7]
        ]),
    )]);
    session.messages[0].content.push(ContentPart {
        kind: ContentPartKind::File,
        text: Some(canaries[6].into()),
        attachment_id: Some(Uuid::from_u128(999)),
        raw_extra: BTreeMap::new(),
    });
    session.tool_events = vec![ToolEvent {
        id: "tool-event".into(),
        ordinal: 2,
        tool_name: canaries[5].into(),
        status: "completed".into(),
        visible_input: Some(canaries[5].into()),
        visible_output: Some(canaries[3].into()),
        raw_ref: Sha256Digest::from_bytes(canaries[5].as_bytes()),
    }];
    session.attachments = vec![Attachment {
        id: Uuid::from_u128(999),
        source_locator: canaries[6].into(),
        media_type: Some("application/private".into()),
        size: 7,
        sha256: Sha256Digest::from_bytes(canaries[6].as_bytes()),
        raw_ref: Sha256Digest::from_bytes(canaries[6].as_bytes()),
    }];
    session.raw_extra = BTreeMap::from([(
        "private".into(),
        json!({"native": canaries[0], "token": canaries[1], "endpoint": canaries[2], "raw": canaries[7]}),
    )]);

    let source = build_canonical_continuation_source(
        &session,
        Path::new(r"C:\restored\project"),
        "openai",
        "gpt-5",
    )
    .unwrap();
    let encoded = String::from_utf8(source.bytes).unwrap();

    assert!(encoded.contains("only visible text"));
    assert_eq!(encoded.matches("only visible text").count(), 2);
    for canary in canaries {
        assert!(!encoded.contains(canary), "leaked canary: {canary}");
    }
}

#[test]
fn canonical_visible_history_hash_changes_for_each_sequence_mutation() {
    let mut session = fixture_session();
    session.messages = vec![
        visible_message(1, CanonicalRole::User, "one"),
        visible_message(2, CanonicalRole::Assistant, "two"),
    ];
    let baseline = canonical_visible_history(&session).unwrap();

    let mut changed = session.clone();
    changed.messages[1].content[0].text = Some("changed".into());
    let mut reordered = session.clone();
    reordered.messages[0].ordinal = 2;
    reordered.messages[1].ordinal = 1;
    let mut added = session.clone();
    added
        .messages
        .push(visible_message(3, CanonicalRole::User, "three"));
    let mut removed = session.clone();
    removed.messages.pop();

    for mutated in [&changed, &reordered, &added, &removed] {
        assert_ne!(
            canonical_visible_history(mutated).unwrap(),
            baseline,
            "visible-history mutation must change count or hash"
        );
    }
}

#[test]
fn canonical_visible_history_rejects_nonempty_unsupported_roles() {
    for role in [
        CanonicalRole::System,
        CanonicalRole::Tool,
        CanonicalRole::Unknown,
    ] {
        let mut session = fixture_session();
        session.messages = vec![visible_message(1, role, "must not be silently dropped")];

        assert!(canonical_visible_history(&session).is_err());
        assert!(
            build_canonical_continuation_source(
                &session,
                Path::new(r"C:\restored\project"),
                "openai",
                "gpt-5",
            )
            .is_err()
        );
    }
}

#[test]
fn generated_source_native_expectation_carries_exact_provider_history_and_rollout_hash() {
    let mut session = fixture_session();
    session.messages = vec![
        visible_message(1, CanonicalRole::User, "one"),
        visible_message(2, CanonicalRole::Assistant, "two"),
    ];
    session.title = Some("Exact title".into());
    let source = build_canonical_continuation_source(
        &session,
        Path::new(r"C:\restored\project"),
        "openai",
        "gpt-5",
    )
    .unwrap();

    let expected = native_thread_expectation(&source.bytes).unwrap();

    assert_eq!(expected.thread_id, source.thread_id);
    assert_eq!(expected.cwd, r"C:\restored\project");
    assert_eq!(expected.title.as_deref(), Some("Exact title"));
    assert_eq!(expected.model_provider, "openai");
    assert_eq!(
        expected.rollout_hash,
        Sha256Digest::from_bytes(&source.bytes)
    );
    assert_eq!(
        expected.visible_history,
        source.visible_history.expectation()
    );
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
fn native_rollout_export_rejects_linked_session_subtree() {
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let sessions = root.path().join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    link_directory(&sessions.join("linked"), outside.path());
    fs::write(
        outside.path().join("rollout-source-session-201.jsonl"),
        br#"{"type":"session_meta","payload":{"id":"source-session-201"}}
"#,
    )
    .unwrap();

    let result = collect_native_rollouts(
        root.path(),
        &[fixture_session()],
        &SecretScanner::v1().unwrap(),
    );

    assert!(matches!(result, Err(NativePayloadError::InvalidPath)));
}

#[test]
fn native_rollout_restore_rejects_linked_target_subtree() {
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let codex_home = root.path().join("codex");
    let sessions = codex_home.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    link_directory(&sessions.join("2026"), outside.path());
    let payload = NativeRolloutPayload {
        session_id: Uuid::from_u128(206),
        relative_path: "2026/08/23/rollout-native.jsonl".into(),
        bytes: br#"{"type":"session_meta","payload":{"session_id":"native-thread","cwd":"C:\\source\\project"}}
"#
        .to_vec(),
        source_hash: Sha256Digest::from_bytes(b"source"),
        redaction_count: 0,
    };

    let result =
        restore_native_rollouts(&codex_home, &[payload], &[], &root.path().join("backups"));

    assert!(matches!(result, Err(NativePayloadError::InvalidPath)));
    assert!(
        !outside
            .path()
            .join("08")
            .join("23")
            .join("rollout-native.jsonl")
            .exists()
    );
}

#[test]
fn guarded_restore_checks_before_backup_temp_write_and_target_rename() {
    let root = tempdir().unwrap();
    let codex_home = root.path().join("codex");
    let backup_root = root.path().join("backups");
    let destination = codex_home
        .join("sessions")
        .join("2026/08/23/rollout-native.jsonl");
    let payload = NativeRolloutPayload {
        session_id: Uuid::from_u128(304),
        relative_path: "2026/08/23/rollout-native.jsonl".into(),
        bytes: br#"{"type":"session_meta","payload":{"session_id":"native-thread","cwd":"C:\\source\\project"}}
"#
        .to_vec(),
        source_hash: Sha256Digest::from_bytes(b"source"),
        redaction_count: 0,
    };
    let checks = AtomicUsize::new(0);

    let report =
        restore_native_rollouts_guarded(&codex_home, &[payload], &[], &backup_root, &|| {
            match checks.fetch_add(1, Ordering::SeqCst) {
                0 => {
                    assert!(!backup_root.exists());
                    assert!(!destination.exists());
                }
                1 => {
                    assert!(backup_root.is_dir());
                    assert!(!destination.exists());
                }
                2 => {
                    let parent = destination.parent().unwrap();
                    assert!(parent.is_dir());
                    assert!(fs::read_dir(parent).unwrap().any(|entry| {
                        entry.unwrap().path().extension().and_then(|v| v.to_str()) == Some("tmp")
                    }));
                    assert!(!destination.exists());
                }
                _ => panic!("unexpected extra process guard"),
            }
            Ok(())
        })
        .unwrap();

    assert_eq!(checks.load(Ordering::SeqCst), 3);
    assert_eq!(report.imported_count, 1);
    assert!(destination.is_file());
}

#[test]
fn guarded_restore_requires_manual_intervention_when_post_commit_rollback_is_blocked() {
    let root = tempdir().unwrap();
    let codex_home = root.path().join("codex");
    let destination = codex_home
        .join("sessions")
        .join("2026/08/23/rollout-native.jsonl");
    let payload = NativeRolloutPayload {
        session_id: Uuid::from_u128(305),
        relative_path: "2026/08/23/rollout-native.jsonl".into(),
        bytes: br#"{"type":"turn_context","payload":{"cwd":"C:\\source\\project"}}
"#
        .to_vec(),
        source_hash: Sha256Digest::from_bytes(b"source"),
        redaction_count: 0,
    };
    let checks = AtomicUsize::new(0);

    let error = restore_native_rollouts_guarded(
        &codex_home,
        &[payload],
        &[],
        &root.path().join("backups"),
        &|| match checks.fetch_add(1, Ordering::SeqCst) {
            0..=2 => Ok(()),
            _ => Err(NativeImportError::CodexRunning),
        },
    )
    .unwrap_err();

    assert!(matches!(
        error,
        NativePayloadError::NativeImport(NativeImportError::ManualIntervention)
    ));
    assert_eq!(checks.load(Ordering::SeqCst), 4);
    assert!(destination.is_file());
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
