use std::fs;

use agentark_adapter_codex::{CodexAdapter, CodexError, split_complete_jsonl_prefix};
use agentark_adapter_sdk::{CaptureRequest, DetectContext, SourceAdapter};
use tempfile::tempdir;

#[test]
fn stable_jsonl_prefix_requires_complete_final_records() {
    let complete = br#"{"id":1}
"#;
    assert_eq!(split_complete_jsonl_prefix(complete).unwrap(), complete);
    let appended = br#"{"id":1}
{"id":2}
"#;
    assert_eq!(split_complete_jsonl_prefix(appended).unwrap(), appended);
    assert!(matches!(
        split_complete_jsonl_prefix(br#"{"id":"incomplete""#),
        Err(CodexError::Retryable("incomplete-final-record"))
    ));
}

#[test]
fn capture_reads_only_sessions_and_preserves_the_source_tree() {
    let root = tempdir().unwrap();
    let sessions = root.path().join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    fs::write(
        sessions.join("thread_fixture.jsonl"),
        br#"{"id":"thread_fixture"}
"#,
    )
    .unwrap();
    fs::write(root.path().join("auth.json"), b"credential-canary").unwrap();
    let before = CodexAdapter::tree_digest(root.path()).unwrap();
    let adapter = CodexAdapter::new(root.path()).unwrap();
    let install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![root.path().to_path_buf()],
            allow_detected_home: false,
        })
        .unwrap()
        .pop()
        .unwrap();
    let batch = adapter
        .capture(&CaptureRequest {
            install,
            snapshot_hint: None,
        })
        .unwrap();
    let after = CodexAdapter::tree_digest(root.path()).unwrap();
    assert_eq!(before, after);
    assert_eq!(batch.records.len(), 1);
    assert_eq!(
        batch.records[0].source_locator,
        "sessions/thread_fixture.jsonl"
    );
    assert_eq!(
        batch.records[0].source_session_id.as_deref(),
        Some("thread_fixture")
    );
}
