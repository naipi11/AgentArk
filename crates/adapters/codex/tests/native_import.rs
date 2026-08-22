use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use agentark_adapter_codex::{
    CodexContinuationRequest, CodexError, JsonRpcTransport, NativeImportError,
    NativeThreadExpectation, RawJsonRpc, backup_codex_targets,
    delete_thread_with_app_server_transport, ensure_codex_not_running_from_tasklist,
    fork_rollout_with_target_provider_transport, verify_thread_listing,
};
use agentark_canonical::Sha256Digest;
use serde_json::{Value, json};
use tempfile::tempdir;

struct ScriptedTransport {
    sent: Arc<Mutex<Vec<Value>>>,
    responses: VecDeque<Value>,
}

#[test]
fn delete_thread_helper_initializes_and_deletes_exact_target() {
    let responses = vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 2, "result": {}}),
    ];
    let (mut transport, sent) = ScriptedTransport::new(responses);

    delete_thread_with_app_server_transport(&mut transport, "target-thread").unwrap();

    let sent = sent.lock().unwrap();
    assert_eq!(sent[0]["method"], "initialize");
    assert_eq!(sent[1]["method"], "initialized");
    assert_eq!(sent[2]["method"], "thread/delete");
    assert_eq!(sent[2]["params"], json!({"threadId": "target-thread"}));
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

fn continuation_responses(
    target_thread_id: &str,
    target_rollout: &Path,
    target_cwd: &Path,
) -> (Vec<Value>, Value) {
    let fork_response = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "result": {
            "approvalPolicy": "never",
            "approvalsReviewer": "user",
            "cwd": target_cwd,
            "model": "gpt-5",
            "modelProvider": "openai",
            "sandbox": {"type": "dangerFullAccess"},
            "thread": {
                "cliVersion": "0.146.0",
                "createdAt": 1,
                "cwd": target_cwd,
                "ephemeral": false,
                "id": target_thread_id,
                "modelProvider": "openai",
                "path": target_rollout,
                "preview": "fixture",
                "sessionId": "session-target",
                "source": "appServer",
                "status": {"type": "idle"},
                "turns": [{"id": "turn-1", "items": [], "status": "completed"}],
                "updatedAt": 1
            }
        }
    });
    let listed_thread = json!({
        "cliVersion": "0.146.0",
        "createdAt": 1,
        "cwd": target_cwd,
        "ephemeral": false,
        "id": target_thread_id,
        "modelProvider": "openai",
        "path": target_rollout,
        "preview": "fixture",
        "sessionId": "session-target",
        "source": "appServer",
        "status": {"type": "idle"},
        "turns": [],
        "updatedAt": 1
    });
    let read_thread = json!({
        "cliVersion": "0.146.0",
        "createdAt": 1,
        "cwd": target_cwd,
        "ephemeral": false,
        "id": target_thread_id,
        "modelProvider": "openai",
        "path": target_rollout,
        "preview": "fixture",
        "sessionId": "session-target",
        "source": "appServer",
        "status": {"type": "idle"},
        "turns": [{"id": "turn-1", "items": [], "status": "completed"}],
        "updatedAt": 1
    });
    (
        vec![
            json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"imageGeneration": true, "namespaceTools": true, "webSearch": true}
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "result": {
                    "data": [{
                        "defaultReasoningEffort": "medium",
                        "description": "fixture model",
                        "displayName": "GPT-5",
                        "hidden": false,
                        "id": "gpt-5",
                        "isDefault": true,
                        "model": "gpt-5",
                        "supportedReasoningEfforts": []
                    }],
                    "nextCursor": null
                }
            }),
            fork_response.clone(),
            json!({"jsonrpc": "2.0", "id": 5, "result": {"data": [], "nextCursor": null}}),
            json!({"jsonrpc": "2.0", "id": 6, "result": {"data": [listed_thread], "nextCursor": null}}),
            json!({"jsonrpc": "2.0", "id": 7, "result": {"thread": read_thread}}),
        ],
        fork_response,
    )
}

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

#[test]
fn fork_rollout_sends_selected_provider_without_secrets_and_verifies_visibility() {
    let codex_home = tempdir().unwrap();
    let sessions = codex_home.path().join("sessions");
    let source_rollout = sessions.join("source.jsonl");
    let target_rollout = sessions.join("target.jsonl");
    let target_cwd = codex_home.path().join("project");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&target_cwd).unwrap();
    fs::write(&source_rollout, b"source").unwrap();
    fs::write(&target_rollout, b"target").unwrap();
    let source_thread_id = "019source-thread";
    let target_thread_id = "019target-thread";
    let (responses, fork_response) =
        continuation_responses(target_thread_id, &target_rollout, &target_cwd);
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let request = CodexContinuationRequest {
        source_rollout: source_rollout.clone(),
        source_thread_id: source_thread_id.into(),
        target_cwd: target_cwd.clone(),
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
    };

    let report =
        fork_rollout_with_target_provider_transport(&mut transport, codex_home.path(), &request)
            .unwrap();

    let sent = sent.lock().unwrap();
    let methods = sent
        .iter()
        .filter_map(|value| value.get("method").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(
        methods,
        [
            "initialize",
            "initialized",
            "modelProvider/capabilities/read",
            "model/list",
            "thread/fork",
            "thread/list",
            "thread/list",
            "thread/read"
        ]
    );
    let list_requests = sent
        .iter()
        .filter(|value| value["method"] == "thread/list")
        .collect::<Vec<_>>();
    assert_eq!(list_requests[0]["params"]["archived"], false);
    assert_eq!(list_requests[1]["params"]["archived"], true);
    let fork_request = sent
        .iter()
        .find(|value| value["method"] == "thread/fork")
        .unwrap();
    assert_eq!(fork_request["method"], "thread/fork");
    assert_eq!(fork_request["params"]["threadId"], source_thread_id);
    assert_eq!(
        fork_request["params"]["path"],
        source_rollout.to_string_lossy().as_ref()
    );
    assert_eq!(fork_request["params"]["modelProvider"], "openai");
    assert_eq!(fork_request["params"]["model"], "gpt-5");
    assert_eq!(
        fork_request["params"]["cwd"],
        target_cwd.to_string_lossy().as_ref()
    );
    assert_eq!(fork_request["params"]["threadSource"], "user");
    assert_eq!(fork_request["params"]["ephemeral"], false);
    assert_ne!(fork_response["result"]["thread"]["id"], source_thread_id);
    assert!(
        serde_json::to_string(fork_request)
            .unwrap()
            .contains("openai")
    );
    assert!(!serde_json::to_string(fork_request).unwrap().contains("sk-"));
    assert!(
        !serde_json::to_string(fork_request)
            .unwrap()
            .contains("endpoint")
    );
    assert_eq!(report.target_thread_id, target_thread_id);
    assert_eq!(report.visible_turns, 1);
    assert!(sent.iter().all(|value| value["method"] != "thread/delete"));
}

#[test]
fn fork_rollout_omits_optional_target_provider_and_model_keys() {
    let codex_home = tempdir().unwrap();
    let sessions = codex_home.path().join("sessions");
    let source_rollout = sessions.join("source.jsonl");
    let target_rollout = sessions.join("target.jsonl");
    let target_cwd = codex_home.path().join("project");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&target_cwd).unwrap();
    fs::write(&source_rollout, b"source").unwrap();
    fs::write(&target_rollout, b"target").unwrap();
    let (responses, _) = continuation_responses("019target-thread", &target_rollout, &target_cwd);
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: None,
        target_model: None,
    };

    fork_rollout_with_target_provider_transport(&mut transport, codex_home.path(), &request)
        .unwrap();

    let sent = sent.lock().unwrap();
    let params = &sent
        .iter()
        .find(|value| value["method"] == "thread/fork")
        .unwrap()["params"];
    assert!(params.get("modelProvider").is_none());
    assert!(params.get("model").is_none());
}

#[test]
fn fork_rollout_deletes_new_target_when_post_fork_validation_fails() {
    let codex_home = tempdir().unwrap();
    let sessions = codex_home.path().join("sessions");
    let source_rollout = sessions.join("source.jsonl");
    let target_rollout = sessions.join("target.jsonl");
    let target_cwd = codex_home.path().join("project");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&target_cwd).unwrap();
    fs::write(&source_rollout, b"source").unwrap();
    fs::write(&target_rollout, b"target").unwrap();
    let target_thread_id = "019target-thread";
    let (mut responses, _) = continuation_responses(target_thread_id, &target_rollout, &target_cwd);
    responses[3]["result"]["modelProvider"] = Value::String("unexpected".into());
    responses.truncate(4);
    responses.push(json!({"jsonrpc": "2.0", "id": 5, "result": {}}));
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
    };

    let error =
        fork_rollout_with_target_provider_transport(&mut transport, codex_home.path(), &request)
            .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("thread/fork returned a different model provider")
    );
    let sent = sent.lock().unwrap();
    let deletes = sent
        .iter()
        .filter(|value| value["method"] == "thread/delete")
        .collect::<Vec<_>>();
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0]["params"], json!({"threadId": target_thread_id}));
}

#[test]
fn fork_rollout_reports_manual_intervention_when_validation_rollback_fails() {
    let codex_home = tempdir().unwrap();
    let sessions = codex_home.path().join("sessions");
    let source_rollout = sessions.join("source.jsonl");
    let target_rollout = sessions.join("target.jsonl");
    let target_cwd = codex_home.path().join("project");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&target_cwd).unwrap();
    fs::write(&source_rollout, b"source").unwrap();
    fs::write(&target_rollout, b"target").unwrap();
    let (mut responses, _) =
        continuation_responses("019target-thread", &target_rollout, &target_cwd);
    responses[3]["result"]["modelProvider"] = Value::String("unexpected".into());
    responses.truncate(4);
    responses.push(json!({
        "jsonrpc": "2.0",
        "id": 5,
        "error": {"code": -32603, "message": "fixture delete failure"}
    }));
    let (mut transport, _) = ScriptedTransport::new(responses);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
    };

    let error =
        fork_rollout_with_target_provider_transport(&mut transport, codex_home.path(), &request)
            .unwrap_err();

    assert!(matches!(error, NativeImportError::Rollback));
}

#[test]
fn fork_rollout_does_not_retry_archived_when_active_list_is_malformed() {
    let codex_home = tempdir().unwrap();
    let sessions = codex_home.path().join("sessions");
    let source_rollout = sessions.join("source.jsonl");
    let target_rollout = sessions.join("target.jsonl");
    let target_cwd = codex_home.path().join("project");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&target_cwd).unwrap();
    fs::write(&source_rollout, b"source").unwrap();
    fs::write(&target_rollout, b"target").unwrap();
    let target_thread_id = "019target-thread";
    let (mut responses, _) = continuation_responses(target_thread_id, &target_rollout, &target_cwd);
    responses[4] = json!({"jsonrpc": "2.0", "id": 5, "result": {}});
    responses.truncate(5);
    responses.push(json!({"jsonrpc": "2.0", "id": 6, "result": {}}));
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
    };

    let error =
        fork_rollout_with_target_provider_transport(&mut transport, codex_home.path(), &request)
            .unwrap_err();

    assert!(error.to_string().contains("thread/list data is missing"));
    let sent = sent.lock().unwrap();
    assert_eq!(
        sent.iter()
            .filter(|value| value["method"] == "thread/list")
            .count(),
        1
    );
    assert_eq!(
        sent.iter()
            .filter(|value| value["method"] == "thread/delete")
            .count(),
        1
    );
}

#[test]
fn fork_rollout_does_not_retry_archived_when_active_target_has_wrong_cwd() {
    let codex_home = tempdir().unwrap();
    let sessions = codex_home.path().join("sessions");
    let source_rollout = sessions.join("source.jsonl");
    let target_rollout = sessions.join("target.jsonl");
    let target_cwd = codex_home.path().join("project");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&target_cwd).unwrap();
    fs::write(&source_rollout, b"source").unwrap();
    fs::write(&target_rollout, b"target").unwrap();
    let target_thread_id = "019target-thread";
    let (mut responses, _) = continuation_responses(target_thread_id, &target_rollout, &target_cwd);
    let mut wrong_cwd_listing = responses[5].clone();
    wrong_cwd_listing["id"] = Value::from(5);
    wrong_cwd_listing["result"]["data"][0]["cwd"] = Value::String("C:/wrong".into());
    responses[4] = wrong_cwd_listing;
    responses.truncate(5);
    responses.push(json!({"jsonrpc": "2.0", "id": 6, "result": {}}));
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
    };

    let error =
        fork_rollout_with_target_provider_transport(&mut transport, codex_home.path(), &request)
            .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("forked thread cwd does not match")
    );
    let sent = sent.lock().unwrap();
    assert_eq!(
        sent.iter()
            .filter(|value| value["method"] == "thread/list")
            .count(),
        1
    );
    assert_eq!(
        sent.iter()
            .filter(|value| value["method"] == "thread/delete")
            .count(),
        1
    );
}
