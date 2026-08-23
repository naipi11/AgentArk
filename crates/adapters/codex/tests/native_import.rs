use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use agentark_adapter_codex::{
    CodexContinuationRequest, CodexError, CodexTargetDefault, CodexTargetSessionExpectation,
    JsonRpcTransport, NativeImportError, NativeThreadExpectation, RawJsonRpc, backup_codex_targets,
    delete_thread_with_app_server_transport, ensure_codex_not_running_from_tasklist,
    fork_rollout_with_target_provider_transport, probe_target_default_transport,
    verify_target_session_transport, verify_thread_listing, write_rollout_atomic_with_operations,
    write_rollout_atomic_with_reader,
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

#[test]
fn atomic_rollout_post_rename_read_failure_removes_committed_destination() {
    let root = tempdir().unwrap();
    let destination = root.path().join("sessions/rollout.jsonl");

    let error = write_rollout_atomic_with_reader(&destination, &[b"fixture\n".to_vec()], |_path| {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "fixture post-rename read failure",
        ))
    })
    .unwrap_err();

    assert!(matches!(error, NativeImportError::Io(_)));
    assert!(!destination.exists());
}

#[test]
fn atomic_rollout_cleanup_failure_requires_manual_intervention() {
    let root = tempdir().unwrap();
    let destination = root.path().join("sessions/rollout.jsonl");

    let error = write_rollout_atomic_with_operations(
        &destination,
        &[b"fixture\n".to_vec()],
        |_path| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "fixture post-rename read failure",
            ))
        },
        |_path| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "fixture cleanup failure",
            ))
        },
    )
    .unwrap_err();

    assert!(matches!(error, NativeImportError::ManualIntervention));
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

#[test]
fn target_default_probe_reads_only_sanitized_effective_config_labels() {
    let token_canary = "sk-proj-target-default-probe-canary-123456789";
    let endpoint_canary = "https://provider-canary.invalid/v1";
    let responses = vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "config": {
                    "model_provider": "openai",
                    "model": "gpt-5",
                    "api_key": token_canary,
                    "base_url": endpoint_canary,
                    "account_id": "provider-account-canary"
                },
                "layers": [{"value": token_canary}],
                "origins": {"model": endpoint_canary}
            }
        }),
    ];
    let (mut transport, sent) = ScriptedTransport::new(responses);

    let target = probe_target_default_transport(&mut transport).unwrap();

    assert_eq!(
        target,
        CodexTargetDefault {
            model_provider: "openai".into(),
            model: "gpt-5".into(),
        }
    );
    let serialized = serde_json::to_string(&target).unwrap();
    assert!(!serialized.contains(token_canary));
    assert!(!serialized.contains(endpoint_canary));
    let methods = sent
        .lock()
        .unwrap()
        .iter()
        .filter_map(|value| value.get("method").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(methods, ["initialize", "initialized", "config/read"]);
}

#[test]
fn target_default_probe_uses_advertised_default_model_when_config_omits_model() {
    let responses = vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 2, "result": {"config": {}}}),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "data": [
                    {"id": "gpt-old", "model": "gpt-old", "isDefault": false},
                    {"id": "gpt-5", "model": "gpt-5", "isDefault": true}
                ],
                "nextCursor": null
            }
        }),
    ];
    let (mut transport, sent) = ScriptedTransport::new(responses);

    let target = probe_target_default_transport(&mut transport).unwrap();

    assert_eq!(target.model_provider, "openai");
    assert_eq!(target.model, "gpt-5");
    let methods = sent
        .lock()
        .unwrap()
        .iter()
        .filter_map(|value| value.get("method").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(
        methods,
        ["initialize", "initialized", "config/read", "model/list"]
    );
}

#[test]
fn existing_target_verifier_checks_id_provider_and_rollout_hash_without_mutation() {
    let codex_home = tempdir().unwrap();
    let sessions = codex_home.path().join("sessions");
    let rollout = sessions.join("existing-target.jsonl");
    fs::create_dir_all(&sessions).unwrap();
    fs::write(&rollout, b"existing verified target").unwrap();
    let target_id = "019existing-target";
    let responses = vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"data": [{
                "id": target_id,
                "path": rollout,
                "modelProvider": "openai"
            }], "nextCursor": null}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"thread": {
                "id": target_id,
                "modelProvider": "openai",
                "turns": [{"id": "turn-1"}]
            }}
        }),
    ];
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let expected = CodexTargetSessionExpectation {
        thread_id: target_id.into(),
        model_provider: "openai".into(),
        rollout_hash: Sha256Digest::from_bytes(b"existing verified target"),
    };

    verify_target_session_transport(&mut transport, codex_home.path(), &expected).unwrap();

    let methods = sent
        .lock()
        .unwrap()
        .iter()
        .filter_map(|value| value.get("method").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(
        methods,
        ["initialize", "initialized", "thread/list", "thread/read"]
    );
}

#[test]
fn existing_target_verifier_rejects_changed_rollout_hash() {
    let codex_home = tempdir().unwrap();
    let sessions = codex_home.path().join("sessions");
    let rollout = sessions.join("changed-target.jsonl");
    fs::create_dir_all(&sessions).unwrap();
    fs::write(&rollout, b"changed target").unwrap();
    let target_id = "019changed-target";
    let responses = vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"data": [{
                "id": target_id,
                "path": rollout,
                "modelProvider": "openai"
            }], "nextCursor": null}
        }),
    ];
    let (mut transport, _) = ScriptedTransport::new(responses);
    let expected = CodexTargetSessionExpectation {
        thread_id: target_id.into(),
        model_provider: "openai".into(),
        rollout_hash: Sha256Digest::from_bytes(b"original target"),
    };

    let error =
        verify_target_session_transport(&mut transport, codex_home.path(), &expected).unwrap_err();

    assert!(matches!(error, NativeImportError::Verification(_)));
}

fn continuation_responses(
    target_thread_id: &str,
    target_rollout: &Path,
    target_cwd: &Path,
) -> (Vec<Value>, Value) {
    let fork_response = json!({
        "jsonrpc": "2.0",
        "id": 2,
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
            fork_response.clone(),
            json!({"jsonrpc": "2.0", "id": 3, "result": {"data": [], "nextCursor": null}}),
            json!({"jsonrpc": "2.0", "id": 4, "result": {"data": [listed_thread], "nextCursor": null}}),
            json!({"jsonrpc": "2.0", "id": 5, "result": {"thread": read_thread}}),
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
    responses[1]["result"]["modelProvider"] = Value::String("unexpected".into());
    responses.truncate(2);
    responses.push(json!({"jsonrpc": "2.0", "id": 3, "result": {}}));
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
    responses[1]["result"]["modelProvider"] = Value::String("unexpected".into());
    responses.truncate(2);
    responses.push(json!({
        "jsonrpc": "2.0",
        "id": 3,
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
fn fork_rollout_missing_target_id_requires_manual_intervention_without_delete() {
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
    responses[1]["result"]["thread"]
        .as_object_mut()
        .unwrap()
        .remove("id");
    responses.truncate(2);
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: None,
        target_model: None,
    };

    let error =
        fork_rollout_with_target_provider_transport(&mut transport, codex_home.path(), &request)
            .unwrap_err();

    assert!(matches!(error, NativeImportError::ManualIntervention));
    assert!(
        sent.lock()
            .unwrap()
            .iter()
            .all(|value| value["method"] != "thread/delete")
    );
}

#[test]
fn fork_rollout_empty_target_id_requires_manual_intervention_without_delete() {
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
    responses[1]["result"]["thread"]["id"] = Value::String("   ".into());
    responses.truncate(2);
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: None,
        target_model: None,
    };

    let error =
        fork_rollout_with_target_provider_transport(&mut transport, codex_home.path(), &request)
            .unwrap_err();

    assert!(matches!(error, NativeImportError::ManualIntervention));
    assert!(
        sent.lock()
            .unwrap()
            .iter()
            .all(|value| value["method"] != "thread/delete")
    );
}

#[test]
fn fork_rollout_reused_source_id_requires_manual_intervention_without_source_delete() {
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
    let (mut responses, _) =
        continuation_responses("019target-thread", &target_rollout, &target_cwd);
    responses[1]["result"]["thread"]["id"] = Value::String(source_thread_id.into());
    responses.truncate(2);
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: source_thread_id.into(),
        target_cwd,
        target_provider: None,
        target_model: None,
    };

    let error =
        fork_rollout_with_target_provider_transport(&mut transport, codex_home.path(), &request)
            .unwrap_err();

    assert!(matches!(error, NativeImportError::ManualIntervention));
    assert!(
        sent.lock()
            .unwrap()
            .iter()
            .all(|value| value["method"] != "thread/delete")
    );
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
    responses[2] = json!({"jsonrpc": "2.0", "id": 3, "result": {}});
    responses.truncate(3);
    responses.push(json!({"jsonrpc": "2.0", "id": 4, "result": {}}));
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
    let mut wrong_cwd_listing = responses[3].clone();
    wrong_cwd_listing["id"] = Value::from(3);
    wrong_cwd_listing["result"]["data"][0]["cwd"] = Value::String("C:/wrong".into());
    responses[2] = wrong_cwd_listing;
    responses.truncate(3);
    responses.push(json!({"jsonrpc": "2.0", "id": 4, "result": {}}));
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
