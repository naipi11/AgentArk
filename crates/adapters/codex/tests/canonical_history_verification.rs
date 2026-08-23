use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use agentark_adapter_codex::{
    CodexContinuationRequest, CodexError, CodexTargetSessionExpectation,
    CodexVisibleHistoryExpectation, JsonRpcTransport, NativeImportError, RawJsonRpc,
    delete_thread_with_app_server_transport, fork_rollout_with_target_provider_transport,
    verify_target_session_transport,
};
use agentark_canonical::Sha256Digest;
use serde_json::{Value, json};
use tempfile::tempdir;

struct ScriptedTransport {
    sent: Arc<Mutex<Vec<Value>>>,
    responses: VecDeque<Value>,
}

impl ScriptedTransport {
    fn new(responses: Vec<Value>) -> (Self, Arc<Mutex<Vec<Value>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                sent: Arc::clone(&sent),
                responses: responses.into(),
            },
            sent,
        )
    }
}

impl JsonRpcTransport for ScriptedTransport {
    fn send_value(&mut self, value: &Value) -> Result<(), CodexError> {
        self.sent.lock().unwrap().push(value.clone());
        Ok(())
    }

    fn receive_value(&mut self) -> Result<RawJsonRpc, CodexError> {
        let value = self.responses.pop_front().ok_or(CodexError::EndOfStream)?;
        Ok(RawJsonRpc {
            bytes: serde_json::to_vec(&value).unwrap(),
            value,
        })
    }
}

fn expected(cwd: &Path, hash: Sha256Digest) -> CodexTargetSessionExpectation {
    CodexTargetSessionExpectation {
        thread_id: "019exact-target".into(),
        cwd: cwd.to_string_lossy().into_owned(),
        title: Some("Exact title".into()),
        model_provider: "openai".into(),
        rollout_hash: hash,
        visible_history: CodexVisibleHistoryExpectation {
            message_count: 2,
            content_hash: Sha256Digest::parse(
                "sha256:8fd523d37c7db825551c44f5698f3cea969aa15ddb9cdd6ddf7d680e55899c53",
            )
            .unwrap(),
        },
    }
}

fn responses(rollout: &Path, cwd: &Path, items: Value, title: &str) -> Vec<Value> {
    vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"data": [{
                "id": "019exact-target",
                "cwd": cwd,
                "name": title,
                "path": rollout,
                "modelProvider": "openai"
            }], "nextCursor": null}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"thread": {
                "id": "019exact-target",
                "cwd": cwd,
                "name": title,
                "path": rollout,
                "modelProvider": "openai",
                "turns": [{"id": "turn-1", "items": items}]
            }}
        }),
    ]
}

fn exact_items() -> Value {
    json!([
        {"type": "userMessage", "content": [{"type": "input_text", "text": "one"}]},
        {"type": "agentMessage", "text": "two"}
    ])
}

#[test]
fn existing_target_verification_accepts_exact_ordered_history_and_hash() {
    let root = tempdir().unwrap();
    let sessions = root.path().join("sessions");
    let cwd = root.path().join("project");
    let rollout = sessions.join("target.jsonl");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    fs::write(&rollout, b"exact rollout bytes").unwrap();
    let expected = expected(&cwd, Sha256Digest::from_bytes(b"exact rollout bytes"));
    let (mut transport, _) =
        ScriptedTransport::new(responses(&rollout, &cwd, exact_items(), "Exact title"));

    verify_target_session_transport(&mut transport, root.path(), &expected).unwrap();
}

#[test]
fn same_count_changed_or_reordered_history_is_rejected() {
    let root = tempdir().unwrap();
    let sessions = root.path().join("sessions");
    let cwd = root.path().join("project");
    let rollout = sessions.join("target.jsonl");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    fs::write(&rollout, b"exact rollout bytes").unwrap();
    let expected = expected(&cwd, Sha256Digest::from_bytes(b"exact rollout bytes"));
    let mutations = [
        json!([
            {"type": "userMessage", "content": [{"type": "input_text", "text": "one"}]},
            {"type": "agentMessage", "text": "changed"}
        ]),
        json!([
            {"type": "agentMessage", "text": "two"},
            {"type": "userMessage", "content": [{"type": "input_text", "text": "one"}]}
        ]),
    ];

    for items in mutations {
        let (mut transport, _) =
            ScriptedTransport::new(responses(&rollout, &cwd, items, "Exact title"));
        assert!(matches!(
            verify_target_session_transport(&mut transport, root.path(), &expected),
            Err(NativeImportError::Verification(_))
        ));
    }
}

#[test]
fn target_title_mismatch_is_rejected() {
    let root = tempdir().unwrap();
    let sessions = root.path().join("sessions");
    let cwd = root.path().join("project");
    let rollout = sessions.join("target.jsonl");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    fs::write(&rollout, b"exact rollout bytes").unwrap();
    let expected = expected(&cwd, Sha256Digest::from_bytes(b"exact rollout bytes"));
    let (mut transport, _) =
        ScriptedTransport::new(responses(&rollout, &cwd, exact_items(), "Wrong title"));

    assert!(matches!(
        verify_target_session_transport(&mut transport, root.path(), &expected),
        Err(NativeImportError::Verification(_))
    ));
}

#[test]
fn missing_unreadable_or_out_of_root_rollout_is_rejected() {
    let root = tempdir().unwrap();
    let sessions = root.path().join("sessions");
    let cwd = root.path().join("project");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    let missing = sessions.join("missing.jsonl");
    let outside = root.path().join("outside.jsonl");
    fs::write(&outside, b"outside").unwrap();
    for rollout in [missing, outside] {
        let expected = expected(&cwd, Sha256Digest::from_bytes(b"exact rollout bytes"));
        let (mut transport, _) =
            ScriptedTransport::new(responses(&rollout, &cwd, exact_items(), "Exact title"));
        assert!(matches!(
            verify_target_session_transport(&mut transport, root.path(), &expected),
            Err(NativeImportError::Verification(_))
        ));
    }
}

fn fork_responses(rollout: &Path, cwd: &Path, items: Value, listed_title: &str) -> Vec<Value> {
    vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "modelProvider": "openai",
                "model": "gpt-5",
                "thread": {"id": "019fork-target", "path": rollout}
            }
        }),
        json!({"jsonrpc": "2.0", "id": 3, "result": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "result": {"data": [{
                "id": "019fork-target",
                "cwd": cwd,
                "name": listed_title,
                "path": rollout,
                "modelProvider": "openai"
            }], "nextCursor": null}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "result": {"thread": {
                "id": "019fork-target",
                "cwd": cwd,
                "name": listed_title,
                "path": rollout,
                "modelProvider": "openai",
                "turns": [{"id": "turn-1", "items": items}]
            }}
        }),
    ]
}

fn fork_request(source: &Path, cwd: &Path) -> CodexContinuationRequest {
    CodexContinuationRequest {
        source_rollout: source.to_path_buf(),
        source_thread_id: "019fork-source".into(),
        target_cwd: cwd.to_path_buf(),
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
        title: Some("Exact title".into()),
        visible_history: CodexVisibleHistoryExpectation {
            message_count: 2,
            content_hash: Sha256Digest::parse(
                "sha256:8fd523d37c7db825551c44f5698f3cea969aa15ddb9cdd6ddf7d680e55899c53",
            )
            .unwrap(),
        },
    }
}

#[test]
fn fork_sets_title_and_reports_exact_history_and_rollout_hash() {
    let root = tempdir().unwrap();
    let sessions = root.path().join("sessions");
    let cwd = root.path().join("project");
    let source = sessions.join("source.jsonl");
    let target = sessions.join("target.jsonl");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    fs::write(&source, b"source").unwrap();
    fs::write(&target, b"fork target bytes").unwrap();
    let (mut transport, sent) =
        ScriptedTransport::new(fork_responses(&target, &cwd, exact_items(), "Exact title"));

    let report = fork_rollout_with_target_provider_transport(
        &mut transport,
        root.path(),
        &fork_request(&source, &cwd),
    )
    .unwrap();

    assert_eq!(
        report.rollout_hash,
        Sha256Digest::from_bytes(b"fork target bytes")
    );
    assert_eq!(report.visible_history.message_count, 2);
    let sent = sent.lock().unwrap();
    let name_set = sent
        .iter()
        .find(|request| request["method"] == "thread/name/set")
        .unwrap();
    assert_eq!(
        name_set["params"],
        json!({"threadId": "019fork-target", "name": "Exact title"})
    );
}

#[test]
fn fork_history_mismatch_deletes_and_confirms_only_new_target_removed() {
    let root = tempdir().unwrap();
    let sessions = root.path().join("sessions");
    let cwd = root.path().join("project");
    let source = sessions.join("source.jsonl");
    let target = sessions.join("target.jsonl");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    fs::write(&source, b"source").unwrap();
    fs::write(&target, b"fork target bytes").unwrap();
    let mut scripted = fork_responses(
        &target,
        &cwd,
        json!([
            {"type": "userMessage", "content": [{"type": "input_text", "text": "one"}]},
            {"type": "agentMessage", "text": "changed"}
        ]),
        "Exact title",
    );
    scripted.extend([
        json!({"jsonrpc": "2.0", "id": 6, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 7, "result": {"data": [], "nextCursor": null}}),
        json!({"jsonrpc": "2.0", "id": 8, "result": {"data": [], "nextCursor": null}}),
    ]);
    let (mut transport, sent) = ScriptedTransport::new(scripted);

    let error = fork_rollout_with_target_provider_transport(
        &mut transport,
        root.path(),
        &fork_request(&source, &cwd),
    )
    .unwrap_err();

    assert!(matches!(error, NativeImportError::Verification(_)));
    let sent = sent.lock().unwrap();
    let deletes = sent
        .iter()
        .filter(|request| request["method"] == "thread/delete")
        .collect::<Vec<_>>();
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0]["params"], json!({"threadId": "019fork-target"}));
    assert_eq!(
        sent.iter()
            .filter(|request| request["method"] == "thread/list")
            .count(),
        3
    );
}

#[test]
fn fork_title_mismatch_with_delete_failure_requires_manual_intervention() {
    let root = tempdir().unwrap();
    let sessions = root.path().join("sessions");
    let cwd = root.path().join("project");
    let source = sessions.join("source.jsonl");
    let target = sessions.join("target.jsonl");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    fs::write(&source, b"source").unwrap();
    fs::write(&target, b"fork target bytes").unwrap();
    let mut scripted = fork_responses(&target, &cwd, exact_items(), "Wrong title");
    scripted.truncate(4);
    scripted.push(json!({
        "jsonrpc": "2.0",
        "id": 5,
        "error": {"code": -32603, "message": "delete failed"}
    }));
    let (mut transport, _) = ScriptedTransport::new(scripted);

    let error = fork_rollout_with_target_provider_transport(
        &mut transport,
        root.path(),
        &fork_request(&source, &cwd),
    )
    .unwrap_err();

    assert!(matches!(error, NativeImportError::ManualIntervention));
}

#[test]
fn fork_missing_or_out_of_root_rollout_deletes_and_confirms_new_target_removed() {
    for outside in [false, true] {
        let root = tempdir().unwrap();
        let sessions = root.path().join("sessions");
        let cwd = root.path().join("project");
        let source = sessions.join("source.jsonl");
        let target = if outside {
            let outside = root.path().join("outside.jsonl");
            fs::write(&outside, b"outside target").unwrap();
            outside
        } else {
            sessions.join("missing.jsonl")
        };
        fs::create_dir_all(&sessions).unwrap();
        fs::create_dir_all(&cwd).unwrap();
        fs::write(&source, b"source").unwrap();
        let responses = vec![
            json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "modelProvider": "openai",
                    "model": "gpt-5",
                    "thread": {"id": "019fork-target", "path": target}
                }
            }),
            json!({"jsonrpc": "2.0", "id": 3, "result": {}}),
            json!({"jsonrpc": "2.0", "id": 4, "result": {"data": [], "nextCursor": null}}),
            json!({"jsonrpc": "2.0", "id": 5, "result": {"data": [], "nextCursor": null}}),
        ];
        let (mut transport, sent) = ScriptedTransport::new(responses);

        assert!(matches!(
            fork_rollout_with_target_provider_transport(
                &mut transport,
                root.path(),
                &fork_request(&source, &cwd),
            ),
            Err(NativeImportError::Verification(_))
        ));
        let sent = sent.lock().unwrap();
        assert_eq!(
            sent.iter()
                .filter(|request| request["method"] == "thread/delete")
                .count(),
            1
        );
    }
}

#[test]
fn delete_helper_confirms_target_absent_from_active_and_archived_lists() {
    let responses = vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 2, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 3, "result": {"data": [], "nextCursor": null}}),
        json!({"jsonrpc": "2.0", "id": 4, "result": {"data": [], "nextCursor": null}}),
    ];
    let (mut transport, sent) = ScriptedTransport::new(responses);

    delete_thread_with_app_server_transport(&mut transport, "019delete-target").unwrap();

    let sent = sent.lock().unwrap();
    assert_eq!(
        sent.iter()
            .filter(|request| request["method"] == "thread/list")
            .count(),
        2
    );
}

#[test]
fn delete_helper_requires_manual_intervention_when_target_remains_listed() {
    let responses = vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 2, "result": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"data": [{"id": "019delete-target"}], "nextCursor": null}
        }),
    ];
    let (mut transport, _) = ScriptedTransport::new(responses);

    assert!(matches!(
        delete_thread_with_app_server_transport(&mut transport, "019delete-target"),
        Err(NativeImportError::ManualIntervention)
    ));
}

#[test]
fn delete_helper_finds_target_on_second_active_page() {
    let responses = vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 2, "result": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"data": [], "nextCursor": "active-page-2"}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "result": {"data": [{"id": "019delete-target"}], "nextCursor": null}
        }),
    ];
    let (mut transport, sent) = ScriptedTransport::new(responses);

    assert!(matches!(
        delete_thread_with_app_server_transport(&mut transport, "019delete-target"),
        Err(NativeImportError::ManualIntervention)
    ));
    let sent = sent.lock().unwrap();
    let lists = sent
        .iter()
        .filter(|request| request["method"] == "thread/list")
        .collect::<Vec<_>>();
    assert_eq!(lists.len(), 2);
    assert_eq!(lists[0]["params"]["archived"], false);
    assert_eq!(lists[1]["params"]["archived"], false);
    assert_eq!(lists[1]["params"]["cursor"], "active-page-2");
}

#[test]
fn delete_helper_rejects_repeated_thread_list_cursor() {
    let responses = vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 2, "result": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"data": [], "nextCursor": "repeated"}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "result": {"data": [], "nextCursor": "repeated"}
        }),
    ];
    let (mut transport, _) = ScriptedTransport::new(responses);

    assert!(matches!(
        delete_thread_with_app_server_transport(&mut transport, "019delete-target"),
        Err(NativeImportError::ManualIntervention)
    ));
}
