use std::fs;

use agentark_adapter_codex::{
    NativeThreadExpectation, backup_codex_targets, ensure_codex_not_running_from_tasklist,
    verify_thread_listing,
};
use agentark_canonical::Sha256Digest;
use serde_json::json;
use tempfile::tempdir;

#[test]
fn rollout_verification_requires_visible_threads() {
    let expected = NativeThreadExpectation {
        thread_id: "01native-thread".into(),
        cwd: r"C:\restore\project".into(),
        title: Some("Imported fixture".into()),
        visible_text_hash: Sha256Digest::from_bytes(
            b"Imported user message\nImported assistant message",
        ),
        visible_turns: 2,
    };
    let result = verify_thread_listing(&json!({"result": {"data": []}}), &expected);
    assert!(matches!(
        result,
        Err(agentark_adapter_codex::NativeImportError::Verification(_))
    ));
}

#[test]
fn process_guard_rejects_codex_client_rows() {
    let tasklist = r#""codex.exe","1234","Console","1","42,000 K"
"other.exe","5678","Console","1","10,000 K""#;
    assert!(ensure_codex_not_running_from_tasklist(tasklist).is_err());
    assert!(
        ensure_codex_not_running_from_tasklist(r#""other.exe","5678","Console","1","10,000 K""#)
            .is_ok()
    );
}

#[test]
fn backup_manifest_contains_existing_target_hashes() {
    let codex_home = tempdir().unwrap();
    let source = codex_home.path().join("sessions").join("rollout.jsonl");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(&source, b"native bytes").unwrap();
    let backup = backup_codex_targets(
        codex_home.path(),
        &codex_home.path().join("backups"),
        std::slice::from_ref(&source),
    )
    .unwrap();
    assert!(backup.join("manifest.json").is_file());
    assert!(backup.join("sessions").join("rollout.jsonl").is_file());
}
