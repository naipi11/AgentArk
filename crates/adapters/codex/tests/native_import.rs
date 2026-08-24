use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(windows)]
use std::process::Command;

use agentark_adapter_codex::{
    AGENTARK_APP_SERVER_CLIENT_VERSION, CodexContinuationRequest, CodexError, CodexTargetDefault,
    CodexTargetSessionExpectation, CodexVisibleHistoryExpectation, JsonRpcTransport,
    NativeImportError, NativeThreadExpectation, RawJsonRpc, backup_codex_targets,
    delete_thread_with_app_server_transport, delete_thread_with_app_server_transport_guarded,
    ensure_codex_not_running_from_snapshot, ensure_codex_not_running_from_snapshot_excluding,
    fork_rollout_with_target_provider_transport,
    fork_rollout_with_target_provider_transport_guarded, probe_target_default_transport,
    verify_target_session_transport, verify_thread_listing,
    write_rollout_atomic_with_guarded_operations, write_rollout_atomic_with_operations,
    write_rollout_atomic_with_reader,
};
use agentark_canonical::Sha256Digest;
use serde_json::{Value, json};
use tempfile::tempdir;

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

struct ScriptedTransport {
    sent: Arc<Mutex<Vec<Value>>>,
    responses: VecDeque<Value>,
    mutation_events: Option<Arc<Mutex<Vec<String>>>>,
}

enum FaultedResponse {
    Value(Value),
    Timeout,
    EndOfStream,
    Io,
    Malformed,
}

struct FaultingTransport {
    sent: Arc<Mutex<Vec<Value>>>,
    responses: VecDeque<FaultedResponse>,
}

impl FaultingTransport {
    fn new(responses: Vec<FaultedResponse>) -> (Self, Arc<Mutex<Vec<Value>>>) {
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

impl JsonRpcTransport for FaultingTransport {
    fn send_value(&mut self, value: &Value) -> Result<(), CodexError> {
        self.sent.lock().unwrap().push(value.clone());
        Ok(())
    }

    fn receive_value(&mut self) -> Result<RawJsonRpc, CodexError> {
        match self.responses.pop_front().ok_or(CodexError::EndOfStream)? {
            FaultedResponse::Value(value) => Ok(RawJsonRpc {
                bytes: serde_json::to_vec(&value).unwrap(),
                value,
            }),
            FaultedResponse::Timeout => Err(CodexError::AppServerRequestTimeout),
            FaultedResponse::EndOfStream => Err(CodexError::EndOfStream),
            FaultedResponse::Io => Err(CodexError::Io(std::io::Error::other("broken pipe"))),
            FaultedResponse::Malformed => Err(CodexError::MalformedJson),
        }
    }
}

#[test]
fn delete_thread_helper_initializes_and_deletes_exact_target() {
    let responses = vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 2, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 3, "result": {"data": [], "nextCursor": null}}),
        json!({"jsonrpc": "2.0", "id": 4, "result": {"data": [], "nextCursor": null}}),
    ];
    let (mut transport, sent) = ScriptedTransport::new(responses);

    delete_thread_with_app_server_transport(&mut transport, "target-thread").unwrap();

    let sent = sent.lock().unwrap();
    assert_eq!(sent[0]["method"], "initialize");
    assert_eq!(sent[1]["method"], "initialized");
    assert_eq!(sent[2]["method"], "thread/delete");
    assert_eq!(sent[2]["params"], json!({"threadId": "target-thread"}));
    assert_eq!(AGENTARK_APP_SERVER_CLIENT_VERSION, "0.6.1");
    assert_eq!(sent[0]["params"]["clientInfo"]["version"], "0.6.1");
}

#[test]
fn read_only_timeout_is_typed_and_never_retried_or_mutated() {
    let (mut transport, sent) = FaultingTransport::new(vec![
        FaultedResponse::Value(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        FaultedResponse::Timeout,
    ]);

    let error = probe_target_default_transport(&mut transport).unwrap_err();

    assert!(matches!(error, NativeImportError::Timeout));
    let methods = sent
        .lock()
        .unwrap()
        .iter()
        .filter_map(|request| request.get("method").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(methods, ["initialize", "initialized", "config/read"]);
}

#[test]
fn fork_timeout_after_send_is_unknown_and_never_retried() {
    let root = tempdir().unwrap();
    let sessions = root.path().join("sessions");
    let source_rollout = sessions.join("source.jsonl");
    let target_cwd = root.path().join("project");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&target_cwd).unwrap();
    fs::write(&source_rollout, b"source").unwrap();
    let (mut transport, sent) = FaultingTransport::new(vec![
        FaultedResponse::Value(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        FaultedResponse::Timeout,
    ]);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
        title: None,
        visible_history: empty_history(),
    };

    let error = fork_rollout_with_target_provider_transport(&mut transport, root.path(), &request)
        .unwrap_err();

    assert!(matches!(error, NativeImportError::MutationOutcomeUnknown));
    let sent = sent.lock().unwrap();
    assert_eq!(
        sent.iter()
            .filter(|request| request["method"] == "thread/fork")
            .count(),
        1
    );
    assert!(
        sent.iter()
            .all(|request| request["method"] != "thread/delete")
    );
}

#[test]
fn known_target_validation_timeout_is_rolled_back_after_confirmed_delete() {
    let root = tempdir().unwrap();
    let sessions = root.path().join("sessions");
    let source_rollout = sessions.join("source.jsonl");
    let target_rollout = sessions.join("target.jsonl");
    let target_cwd = root.path().join("project");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&target_cwd).unwrap();
    fs::write(&source_rollout, b"source").unwrap();
    fs::write(&target_rollout, b"target").unwrap();
    let target_thread_id = "019target-thread";
    let (_, fork_response) = continuation_responses(target_thread_id, &target_rollout, &target_cwd);
    let (mut transport, sent) = FaultingTransport::new(vec![
        FaultedResponse::Value(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        FaultedResponse::Value(fork_response),
        FaultedResponse::Timeout,
        FaultedResponse::Value(json!({"jsonrpc": "2.0", "id": 4, "result": {}})),
        FaultedResponse::Value(
            json!({"jsonrpc": "2.0", "id": 5, "result": {"data": [], "nextCursor": null}}),
        ),
        FaultedResponse::Value(
            json!({"jsonrpc": "2.0", "id": 6, "result": {"data": [], "nextCursor": null}}),
        ),
    ]);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
        title: None,
        visible_history: empty_history(),
    };

    let error = fork_rollout_with_target_provider_transport(&mut transport, root.path(), &request)
        .unwrap_err();

    assert!(matches!(error, NativeImportError::Timeout));
    let sent = sent.lock().unwrap();
    assert_eq!(
        sent.iter()
            .filter(|request| request["method"] == "thread/delete")
            .count(),
        1
    );
    assert_eq!(
        sent.iter()
            .filter(|request| request["method"] == "thread/fork")
            .count(),
        1
    );
}

#[test]
fn delete_timeout_is_unknown_and_never_retried() {
    let (mut transport, sent) = FaultingTransport::new(vec![
        FaultedResponse::Value(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        FaultedResponse::Timeout,
    ]);

    let error =
        delete_thread_with_app_server_transport(&mut transport, "target-thread").unwrap_err();

    assert!(matches!(error, NativeImportError::MutationOutcomeUnknown));
    let sent = sent.lock().unwrap();
    assert_eq!(
        sent.iter()
            .filter(|request| request["method"] == "thread/delete")
            .count(),
        1
    );
    assert!(
        sent.iter()
            .all(|request| request["method"] != "thread/list")
    );
}

#[test]
fn fork_eof_after_send_is_unknown_and_never_retried() {
    let root = tempdir().unwrap();
    let sessions = root.path().join("sessions");
    let source_rollout = sessions.join("source.jsonl");
    let target_cwd = root.path().join("project");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&target_cwd).unwrap();
    fs::write(&source_rollout, b"source").unwrap();
    let (mut transport, sent) = FaultingTransport::new(vec![
        FaultedResponse::Value(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        FaultedResponse::EndOfStream,
    ]);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
        title: None,
        visible_history: empty_history(),
    };

    let error = fork_rollout_with_target_provider_transport(&mut transport, root.path(), &request)
        .unwrap_err();

    assert!(matches!(error, NativeImportError::MutationOutcomeUnknown));
    let sent = sent.lock().unwrap();
    assert_eq!(
        sent.iter()
            .filter(|request| request["method"] == "thread/fork")
            .count(),
        1
    );
    assert!(
        sent.iter()
            .all(|request| request["method"] != "thread/delete")
    );
}

#[test]
fn delete_io_after_send_is_unknown_and_never_confirmed() {
    let (mut transport, sent) = FaultingTransport::new(vec![
        FaultedResponse::Value(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        FaultedResponse::Io,
    ]);

    let error =
        delete_thread_with_app_server_transport(&mut transport, "target-thread").unwrap_err();

    assert!(matches!(error, NativeImportError::MutationOutcomeUnknown));
    let sent = sent.lock().unwrap();
    assert_eq!(
        sent.iter()
            .filter(|request| request["method"] == "thread/delete")
            .count(),
        1
    );
    assert!(
        sent.iter()
            .all(|request| request["method"] != "thread/list")
    );
}

#[test]
fn fork_malformed_response_after_send_is_unknown() {
    let root = tempdir().unwrap();
    let sessions = root.path().join("sessions");
    let source_rollout = sessions.join("source.jsonl");
    let target_cwd = root.path().join("project");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&target_cwd).unwrap();
    fs::write(&source_rollout, b"source").unwrap();
    let (mut transport, _sent) = FaultingTransport::new(vec![
        FaultedResponse::Value(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        FaultedResponse::Malformed,
    ]);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
        title: None,
        visible_history: empty_history(),
    };

    let error = fork_rollout_with_target_provider_transport(&mut transport, root.path(), &request)
        .unwrap_err();

    assert!(matches!(error, NativeImportError::MutationOutcomeUnknown));
}

#[test]
fn guarded_delete_checks_processes_immediately_before_mutation() {
    let responses = vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 2, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 3, "result": {"data": [], "nextCursor": null}}),
        json!({"jsonrpc": "2.0", "id": 4, "result": {"data": [], "nextCursor": null}}),
    ];
    let mutation_events = Arc::new(Mutex::new(Vec::new()));
    let (mut transport, sent) =
        ScriptedTransport::with_mutation_events(responses, Arc::clone(&mutation_events));
    let checks = AtomicUsize::new(0);

    delete_thread_with_app_server_transport_guarded(
        &mut transport,
        "target-thread",
        &|_excluded| {
            mutation_events.lock().unwrap().push("guard".into());
            checks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        &[],
    )
    .unwrap();

    assert_eq!(checks.load(Ordering::SeqCst), 1);
    assert_eq!(sent.lock().unwrap()[2]["method"], "thread/delete");
    assert_eq!(*mutation_events.lock().unwrap(), ["guard", "thread/delete"]);
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

#[test]
fn guarded_atomic_rollout_checks_immediately_before_rename_and_cleanup() {
    let root = tempdir().unwrap();
    let destination = root.path().join("sessions/rollout.jsonl");
    let events = Mutex::new(Vec::new());

    let error = write_rollout_atomic_with_guarded_operations(
        &destination,
        &[b"fixture\n".to_vec()],
        || {
            events.lock().unwrap().push("guard");
            Ok(())
        },
        |source, target| {
            events.lock().unwrap().push("rename");
            fs::rename(source, target)
        },
        |_path| {
            events.lock().unwrap().push("read");
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "fixture post-rename read failure",
            ))
        },
        |path| {
            events.lock().unwrap().push("remove");
            fs::remove_file(path)
        },
    )
    .unwrap_err();

    assert!(matches!(error, NativeImportError::Io(_)));
    assert_eq!(
        *events.lock().unwrap(),
        ["guard", "guard", "rename", "read", "guard", "remove"]
    );
    assert!(!destination.exists());
}

#[test]
fn post_rename_guard_failure_preserves_target_for_manual_intervention() {
    let root = tempdir().unwrap();
    let destination = root.path().join("sessions/rollout.jsonl");
    let checks = AtomicUsize::new(0);
    let remove_calls = AtomicUsize::new(0);

    let error = write_rollout_atomic_with_guarded_operations(
        &destination,
        &[b"fixture\n".to_vec()],
        || match checks.fetch_add(1, Ordering::SeqCst) {
            0 | 1 => Ok(()),
            _ => Err(NativeImportError::CodexRunning),
        },
        |source, target| fs::rename(source, target),
        |_path| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "fixture post-rename read failure",
            ))
        },
        |path| {
            remove_calls.fetch_add(1, Ordering::SeqCst);
            fs::remove_file(path)
        },
    )
    .unwrap_err();

    assert!(matches!(error, NativeImportError::ManualIntervention));
    assert_eq!(checks.load(Ordering::SeqCst), 3);
    assert_eq!(remove_calls.load(Ordering::SeqCst), 0);
    assert!(destination.is_file());
}

impl ScriptedTransport {
    fn new(responses: Vec<Value>) -> (Self, Arc<Mutex<Vec<Value>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                sent: Arc::clone(&sent),
                responses: responses.into(),
                mutation_events: None,
            },
            sent,
        )
    }

    fn with_mutation_events(
        responses: Vec<Value>,
        mutation_events: Arc<Mutex<Vec<String>>>,
    ) -> (Self, Arc<Mutex<Vec<Value>>>) {
        let (mut transport, sent) = Self::new(responses);
        transport.mutation_events = Some(mutation_events);
        (transport, sent)
    }
}

impl JsonRpcTransport for ScriptedTransport {
    fn send_value(&mut self, value: &Value) -> Result<(), CodexError> {
        if let Some(method) = value.get("method").and_then(Value::as_str)
            && matches!(method, "thread/fork" | "thread/name/set" | "thread/delete")
            && let Some(events) = &self.mutation_events
        {
            events.lock().unwrap().push(method.into());
        }
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

fn empty_history() -> CodexVisibleHistoryExpectation {
    CodexVisibleHistoryExpectation {
        message_count: 0,
        content_hash: Sha256Digest::parse(
            "sha256:9d8b77fbc3e8a7bfa6757b47b9419947b07c1599f91de8aceb4ab2b863635a6b",
        )
        .unwrap(),
    }
}

fn one_fixture_message() -> CodexVisibleHistoryExpectation {
    CodexVisibleHistoryExpectation {
        message_count: 1,
        content_hash: Sha256Digest::parse(
            "sha256:59d55302fadfd18a86ffdf751b4fba88f1384254079bfefef443a739e8278383",
        )
        .unwrap(),
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
                "cwd": "C:/fixture",
                "modelProvider": "openai"
            }], "nextCursor": null}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"thread": {
                "id": target_id,
                "cwd": "C:/fixture",
                "modelProvider": "openai",
                "turns": [{"id": "turn-1", "items": [
                    {"type": "userMessage", "content": [{"type": "input_text", "text": "fixture"}]}
                ]}]
            }}
        }),
    ];
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let expected = CodexTargetSessionExpectation {
        thread_id: target_id.into(),
        cwd: "C:/fixture".into(),
        title: None,
        model_provider: "openai".into(),
        rollout_hash: Sha256Digest::from_bytes(b"existing verified target"),
        visible_history: one_fixture_message(),
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
                "cwd": "C:/fixture",
                "modelProvider": "openai"
            }], "nextCursor": null}
        }),
    ];
    let (mut transport, _) = ScriptedTransport::new(responses);
    let expected = CodexTargetSessionExpectation {
        thread_id: target_id.into(),
        cwd: "C:/fixture".into(),
        title: None,
        model_provider: "openai".into(),
        rollout_hash: Sha256Digest::from_bytes(b"original target"),
        visible_history: one_fixture_message(),
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
        model_provider: "openai".into(),
        rollout_hash: Sha256Digest::from_bytes(b"native rollout"),
        visible_history: one_fixture_message(),
    };
    let result = verify_thread_listing(&json!({"result": {"data": []}}), &expected);
    assert!(matches!(
        result,
        Err(agentark_adapter_codex::NativeImportError::Verification(_))
    ));
}

#[test]
fn process_guard_rejects_direct_and_wrapped_codex_invocations() {
    let cases = [
        ("codex.exe", r#"C:\tools\codex.exe resume"#),
        (
            "CodexDesktop.exe",
            r#"C:\Program Files\Codex\CodexDesktop.exe"#,
        ),
        (
            "cmd.exe",
            r#"cmd.exe /d /s /c "C:\Users\fixture\AppData\Roaming\npm\codex.cmd""#,
        ),
        ("cmd.exe", r#"cmd.exe /c C:\tools\codex.opencodex-real.cmd"#),
        (
            "powershell.exe",
            r#"powershell.exe -File C:\tools\codex.ps1"#,
        ),
        (
            "powershell.exe",
            r#"powershell.exe -File C:\tools\co'dex'.ps1"#,
        ),
        (
            "powershell.exe",
            r#"powershell.exe -File C:\tools\co`dex.ps1"#,
        ),
        ("pwsh.exe", r#"pwsh.exe -File "C:\tools\codex.ps1""#),
        ("cmd.exe", r#"cmd.exe /c C:\tools\co"dex".cmd"#),
        (
            "node.exe",
            r#"node.exe C:\tools\node_modules\@openai\codex\bin\codex.js"#,
        ),
        (
            "node.exe",
            r#"node.exe C:\tools\node_modules\@openai\co"dex"\bin\co"dex".js"#,
        ),
        (
            "node.exe",
            r#"node.exe C:\npm\npm-cli.js exec @openai/codex"#,
        ),
        (
            "node.exe",
            r#"node.exe C:\npm\npm-cli.js exec --package=@openai/codex"#,
        ),
        (
            "powershell.exe",
            r#"powershell.exe npm.cmd exec @openai/co'dex'"#,
        ),
        ("cmd.exe", r#"cmd.exe /c npx.cmd @openai/codex@0.146.0"#),
    ];

    for (index, (name, command_line)) in cases.into_iter().enumerate() {
        let snapshot = serde_json::to_string(&json!([{
            "Name": name,
            "ProcessId": 1000 + index,
            "ParentProcessId": 100,
            "CommandLine": command_line,
        }]))
        .unwrap();
        assert!(
            ensure_codex_not_running_from_snapshot(&snapshot).is_err(),
            "expected {name} invocation to be rejected"
        );
    }
}

#[test]
fn process_guard_accepts_unrelated_hosts_with_codex_in_workspace_names() {
    let snapshot = serde_json::to_string(&json!([
        {
            "Name": "node.exe",
            "ProcessId": 2001,
            "ParentProcessId": 100,
            "CommandLine": r#"node.exe C:\work\codex-native-session-import\scripts\build.js"#,
        },
        {
            "Name": "cmd.exe",
            "ProcessId": 2002,
            "ParentProcessId": 100,
            "CommandLine": r#"cmd.exe /c cargo test --manifest-path C:\work\codex-repository\Cargo.toml"#,
        },
        {
            "Name": "powershell.exe",
            "ProcessId": 2003,
            "ParentProcessId": 100,
            "CommandLine": r#"powershell.exe -File C:\work\codex-tools\cleanup.ps1"#,
        },
        {
            "Name": "powershell.exe",
            "ProcessId": 2004,
            "ParentProcessId": 100,
            "CommandLine": r#"powershell.exe -File "C:\tools\co'dex'.ps1""#,
        },
        {
            "Name": "powershell.exe",
            "ProcessId": 2005,
            "ParentProcessId": 100,
            "CommandLine": r#"powershell.exe -File 'C:\tools\co''dex.ps1'"#,
        }
    ]))
    .unwrap();

    ensure_codex_not_running_from_snapshot(&snapshot).unwrap();
}

#[test]
fn powershell_command_mode_classifies_only_nested_command_positions() {
    let rejected = [
        r#"powershell.exe -f C:\tools\codex.ps1"#,
        r#"pwsh.exe -c "& 'C:\tools\codex.ps1'""#,
        r#"powershell.exe -Command "C:\tools\codex.ps1""#,
        r#"powershell.exe -Command "Start-Process 'C:\tools\codex.ps1'""#,
        r#"powershell.exe -Command "Start-Process -FilePath 'C:\tools\codex.ps1' -Wait""#,
        r#"powershell.exe -Command "Start-Process cmd.exe -ArgumentList '/c', 'C:\tools\codex.cmd'""#,
        r#"powershell.exe -Command "cmd.exe /c C:\tools\codex.cmd""#,
        r#"powershell.exe -Command "node.exe C:\node_modules\@openai\codex\bin\codex.js""#,
        r#"powershell.exe -Command "powershell.exe -File C:\tools\codex.ps1""#,
        r#"powershell.exe -Command "Write-Output safe; & 'C:\tools\codex.ps1'""#,
        r#"pwsh.exe -c "Write-Output safe && cmd.exe /c C:\tools\codex.cmd""#,
        r#"pwsh.exe -c "Write-Output safe & 'C:\tools\codex.ps1'""#,
        r#"powershell.exe -Command "Write-Output safe | & 'C:\tools\codex.ps1'""#,
        "powershell.exe -Command \"Write-Output safe\n& 'C:\\tools\\codex.ps1'\"",
    ];

    for (index, command_line) in rejected.into_iter().enumerate() {
        let snapshot = process_snapshot("powershell.exe", 6000 + index, command_line);
        assert!(
            ensure_codex_not_running_from_snapshot(&snapshot).is_err(),
            "expected nested PowerShell command to be rejected"
        );
    }

    let safe = process_snapshot(
        "powershell.exe",
        6100,
        r#"powershell.exe -Command "Write-Output C:\tools\codex.ps1""#,
    );
    ensure_codex_not_running_from_snapshot(&safe).unwrap();
    let quoted_separator = process_snapshot(
        "powershell.exe",
        6101,
        r#"powershell.exe -Command "Write-Output 'literal; & C:\tools\codex.ps1'""#,
    );
    ensure_codex_not_running_from_snapshot(&quoted_separator).unwrap();
}

#[test]
fn powershell_encoded_command_is_decoded_and_classified_without_leaking_script() {
    const ENCODED_CMD_CODEX: &str =
        "YwBtAGQALgBlAHgAZQAgAC8AYwAgAEMAOgBcAHQAbwBvAGwAcwBcAGMAbwBkAGUAeAAuAGMAbQBkAA==";
    const ENCODED_SAFE_OUTPUT: &str =
        "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABDADoAXAB0AG8AbABzAFwAYwBvAGQAZQB4AC4AcABzADEAMQA=";

    for (index, switch) in ["-EncodedCommand", "-enc", "-e"].into_iter().enumerate() {
        let command_line = format!("powershell.exe {switch} {ENCODED_CMD_CODEX}");
        let snapshot = process_snapshot("powershell.exe", 6200 + index, &command_line);
        assert!(ensure_codex_not_running_from_snapshot(&snapshot).is_err());
    }

    let safe = process_snapshot(
        "powershell.exe",
        6300,
        &format!("powershell.exe -enc {ENCODED_SAFE_OUTPUT}"),
    );
    ensure_codex_not_running_from_snapshot(&safe).unwrap();

    let canary = "encoded-script-canary-do-not-leak";
    for (index, encoded) in [canary, "YQ=="].into_iter().enumerate() {
        let malformed = process_snapshot(
            "powershell.exe",
            6400 + index,
            &format!("powershell.exe -enc {encoded}"),
        );
        let error = ensure_codex_not_running_from_snapshot(&malformed).unwrap_err();
        assert!(!error.to_string().contains(canary));
    }
}

#[test]
fn start_process_dynamic_targets_fail_closed_but_static_data_arguments_are_safe() {
    for (index, command_line) in [
        r#"powershell.exe -Command "Start-Process $target""#,
        r#"powershell.exe -Command "Start-Process -FilePath ${target}""#,
        r#"powershell.exe -Command "Start-Process -FilePath C:\$target\safe.exe""#,
        r#"powershell.exe -Command "Start-Process -FilePath (Get-Command codex)""#,
        r#"powershell.exe -Command "Start-Process (Join-Path C:\tools codex.ps1)""#,
    ]
    .into_iter()
    .enumerate()
    {
        let snapshot = process_snapshot("powershell.exe", 6500 + index, command_line);
        assert!(ensure_codex_not_running_from_snapshot(&snapshot).is_err());
    }

    for (index, command_line) in [
        r#"powershell.exe -Command "Start-Process notepad.exe C:\tools\codex.ps1""#,
        r#"powershell.exe -Command "Start-Process -FilePath C:\tools\safe.exe -ArgumentList C:\tools\codex.ps1""#,
    ]
    .into_iter()
    .enumerate()
    {
        let snapshot = process_snapshot("powershell.exe", 6600 + index, command_line);
        ensure_codex_not_running_from_snapshot(&snapshot).unwrap();
    }
}

#[test]
fn host_parsers_classify_execution_positions_instead_of_data_arguments() {
    let rejected = [
        ("cmd.exe", r#"cmd.exe /d /s /c C:\tools\co^dex.cmd"#),
        (
            "cmd.exe",
            r#"cmd.exe /c echo safe & call C:\tools\codex.cmd"#,
        ),
        (
            "cmd.exe",
            r#"cmd.exe /d /s /c "echo safe & call C:\tools\codex.cmd""#,
        ),
        ("cmd.exe", r#"cmd.exe /c start "" C:\tools\codex.cmd"#),
        (
            "cmd.exe",
            r#"cmd.exe /c start "" cmd.exe /c C:\tools\co^dex.cmd"#,
        ),
        (
            "cmd.exe",
            r#"cmd.exe /c node.exe C:\node_modules\@openai\codex\bin\codex.js"#,
        ),
        (
            "node.exe",
            r#"node.exe C:\node_modules\@openai\codex\bin\codex.js"#,
        ),
        (
            "node.exe",
            r#"node.exe -r C:\node_modules\@openai\codex\bin\codex.js C:\safe.js"#,
        ),
        (
            "node.exe",
            r#"node.exe -e "require('C:\\node_modules\\@openai\\codex\\bin\\codex.js')""#,
        ),
        (
            "node.exe",
            r#"node.exe --require=C:\node_modules\@openai\codex\bin\codex.js C:\safe.js"#,
        ),
        ("node.exe", r#"node.exe -e "require(target)""#),
        ("npm.exe", r#"npm.exe exec @openai/codex"#),
        ("npm.exe", r#"npm.exe x --package=@openai/codex"#),
        ("npx.exe", r#"npx.exe @openai/codex"#),
        ("npm.exe", r#"npm.exe run codex"#),
        (
            "powershell.exe",
            r#"powershell.exe -Command "cmd.exe /c C:\tools\co^dex.cmd""#,
        ),
        (
            "powershell.exe",
            r#"powershell.exe -Command "npm.exe exec @openai/codex""#,
        ),
    ];
    for (index, (name, command_line)) in rejected.into_iter().enumerate() {
        let snapshot = process_snapshot(name, 6700 + index, command_line);
        assert!(ensure_codex_not_running_from_snapshot(&snapshot).is_err());
    }

    let accepted = [
        ("cmd.exe", r#"cmd.exe /c echo C:\tools\codex.cmd"#),
        ("cmd.exe", r#"cmd.exe /c echo safe ^& C:\tools\codex.cmd"#),
        (
            "node.exe",
            r#"node.exe C:\safe.js C:\node_modules\@openai\codex\bin\codex.js"#,
        ),
        (
            "node.exe",
            r#"node.exe -e "console.log('C:\\node_modules\\@openai\\codex\\bin\\codex.js')""#,
        ),
        (
            "node.exe",
            r#"node.exe -e "require('C:\\safe.js'); console.log('C:\\node_modules\\@openai\\codex\\bin\\codex.js')""#,
        ),
        (
            "node.exe",
            r#"node.exe --require=C:\safe.js C:\safe.js C:\node_modules\@openai\codex\bin\codex.js"#,
        ),
        ("npm.exe", r#"npm.exe view @openai/codex"#),
        ("npm.exe", r#"npm.exe install @openai/codex"#),
        ("npm.exe", r#"npm.exe exec echo -- @openai/codex"#),
        (
            "powershell.exe",
            r#"powershell.exe -Command "cmd.exe /c echo C:\tools\codex.cmd""#,
        ),
        (
            "powershell.exe",
            r#"powershell.exe -Command "node.exe C:\safe.js C:\node_modules\@openai\codex\bin\codex.js""#,
        ),
        (
            "powershell.exe",
            r#"powershell.exe -Command "npm.exe view @openai/codex""#,
        ),
    ];
    for (index, (name, command_line)) in accepted.into_iter().enumerate() {
        let snapshot = process_snapshot(name, 6800 + index, command_line);
        ensure_codex_not_running_from_snapshot(&snapshot).unwrap();
    }
}

#[test]
fn cmd_start_preserves_window_title_and_switch_value_metadata() {
    for (index, command_line) in [
        r#"cmd.exe /c start "AgentArk" C:\tools\codex.cmd"#,
        r#"cmd.exe /c start "" /WAIT C:\tools\codex.cmd"#,
        r#"cmd.exe /c start "AgentArk" /D C:\safe C:\tools\codex.cmd"#,
        r#"cmd.exe /c start /D C:\safe "AgentArk" C:\tools\codex.cmd"#,
        r#"cmd.exe /c start /WAIT "AgentArk" cmd.exe /c C:\tools\codex.cmd"#,
    ]
    .into_iter()
    .enumerate()
    {
        let snapshot = process_snapshot("cmd.exe", 6900 + index, command_line);
        assert!(ensure_codex_not_running_from_snapshot(&snapshot).is_err());
    }

    for (index, command_line) in [
        r#"cmd.exe /c start "C:\tools\codex.cmd" notepad.exe"#,
        r#"cmd.exe /c start "C:\tools\codex.cmd" /WAIT notepad.exe"#,
        r#"cmd.exe /c start /D C:\tools\codex.cmd "AgentArk" notepad.exe"#,
    ]
    .into_iter()
    .enumerate()
    {
        let snapshot = process_snapshot("cmd.exe", 7000 + index, command_line);
        ensure_codex_not_running_from_snapshot(&snapshot).unwrap();
    }
}

#[test]
fn node_eval_ignores_comments_and_classifies_static_esm_execution_slots() {
    let codex_js = r#"C:\\node_modules\\@openai\\codex\\bin\\codex.js"#;
    for (index, command_line) in [
        format!(r#"node.exe --input-type module -e "import '{codex_js}'""#),
        format!(r#"node.exe --input-type=module -e "import codex from '{codex_js}'""#),
        format!(r#"node.exe -e "import('{codex_js}')""#),
        format!(r#"node.exe -e "import(target + '{codex_js}')""#),
        format!(r#"node.exe -e "require(getPath('{codex_js}'))""#),
    ]
    .into_iter()
    .enumerate()
    {
        let snapshot = process_snapshot("node.exe", 7100 + index, &command_line);
        assert!(ensure_codex_not_running_from_snapshot(&snapshot).is_err());
    }

    for (index, command_line) in [
        format!(
            "node.exe --input-type module -e \"// require('{codex_js}')\nconsole.log('safe')\""
        ),
        format!(
            r#"node.exe --input-type=module -e "/* require('{codex_js}') */ console.log('safe')""#
        ),
        format!(
            r#"node.exe --input-type module -e "import safe from 'C:\\safe.js'; console.log('{codex_js}')""#
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let snapshot = process_snapshot("node.exe", 7200 + index, &command_line);
        ensure_codex_not_running_from_snapshot(&snapshot).unwrap();
    }
}

#[test]
fn npm_global_options_consume_values_before_locating_subcommands() {
    for (index, (name, command_line)) in [
        ("npm.exe", r#"npm.exe --prefix C:\work exec @openai/codex"#),
        ("npm.exe", r#"npm.exe --prefix=C:\work exec @openai/codex"#),
        ("npm.exe", r#"npm.exe --workspace packages/app run codex"#),
        ("npm.exe", r#"npm.exe -w packages/app run codex"#),
        ("npm.exe", r#"npm.exe --workspace=packages/app run codex"#),
        ("npx.exe", r#"npx.exe --prefix C:\work @openai/codex"#),
        ("npm.exe", r#"npm.exe --mystery value exec @openai/codex"#),
    ]
    .into_iter()
    .enumerate()
    {
        let snapshot = process_snapshot(name, 7300 + index, command_line);
        assert!(ensure_codex_not_running_from_snapshot(&snapshot).is_err());
    }

    for (index, command_line) in [
        r#"npm.exe --prefix C:\work view @openai/codex"#,
        r#"npm.exe --prefix=C:\work install @openai/codex"#,
        r#"npm.exe -w packages/app view @openai/codex"#,
        r#"npm.exe --workspace=packages/app install @openai/codex"#,
    ]
    .into_iter()
    .enumerate()
    {
        let snapshot = process_snapshot("npm.exe", 7400 + index, command_line);
        ensure_codex_not_running_from_snapshot(&snapshot).unwrap();
    }
}

fn process_snapshot(name: &str, process_id: usize, command_line: &str) -> String {
    serde_json::to_string(&json!([{
        "Name": name,
        "ProcessId": process_id,
        "ParentProcessId": 100,
        "CommandLine": command_line,
    }]))
    .unwrap()
}

#[test]
fn process_guard_fails_closed_on_malformed_or_ambiguous_snapshot_without_leaking_commands() {
    let canary = "sk-proj-process-command-line-canary-123456789";
    let malformed = format!(r#"[{{"Name":"node.exe","ProcessId":3001,"CommandLine":"{canary}"}}"#);
    let ambiguous = serde_json::to_string(&json!([{
        "Name": "node.exe",
        "ProcessId": 3002,
        "ParentProcessId": 100,
        "CommandLine": null,
    }]))
    .unwrap();
    let unterminated_quote = serde_json::to_string(&json!([{
        "Name": "powershell.exe",
        "ProcessId": 3003,
        "ParentProcessId": 100,
        "CommandLine": r#"powershell.exe -File "C:\tools\unrelated.ps1"#,
    }]))
    .unwrap();

    for snapshot in [malformed, ambiguous, unterminated_quote] {
        let error = ensure_codex_not_running_from_snapshot(&snapshot).unwrap_err();
        assert!(!error.to_string().contains(canary));
    }
}

#[test]
fn process_guard_accepts_only_the_exact_system_idle_process_sentinel() {
    for sentinel in [
        json!({
            "Name": "System Idle Process",
            "ProcessId": 0,
            "ParentProcessId": 0,
            "CommandLine": null,
        }),
        json!({
            "Name": "system idle process",
            "ProcessId": 0,
            "ParentProcessId": 0,
        }),
    ] {
        ensure_codex_not_running_from_snapshot(&json!([sentinel]).to_string()).unwrap();
    }
}

#[test]
fn process_guard_rejects_system_idle_near_misses_and_other_invalid_rows() {
    let near_misses = [
        json!({
            "Name": "Not System Idle Process",
            "ProcessId": 0,
            "ParentProcessId": 0,
            "CommandLine": null,
        }),
        json!({
            "Name": "System Idle Process",
            "ProcessId": 0,
            "ParentProcessId": 1,
            "CommandLine": null,
        }),
        json!({
            "Name": "System Idle Process",
            "ProcessId": 0,
            "ParentProcessId": 0,
            "CommandLine": "unexpected",
        }),
        json!({
            "Name": "node.exe",
            "ProcessId": 3004,
            "ParentProcessId": 3004,
            "CommandLine": "node.exe safe.js",
        }),
    ];

    for row in near_misses {
        assert!(
            ensure_codex_not_running_from_snapshot(&json!([row]).to_string()).is_err(),
            "near-miss process row must fail closed"
        );
    }
    let duplicate_sentinel = json!([
        {
            "Name": "System Idle Process",
            "ProcessId": 0,
            "ParentProcessId": 0,
            "CommandLine": null,
        },
        {
            "Name": "system idle process",
            "ProcessId": 0,
            "ParentProcessId": 0,
            "CommandLine": null,
        }
    ]);
    assert!(
        ensure_codex_not_running_from_snapshot(&duplicate_sentinel.to_string()).is_err(),
        "duplicate sentinel rows must fail closed"
    );
}

#[test]
fn process_guard_excludes_the_owned_process_tree_transitively() {
    let snapshot = serde_json::to_string(&json!([
        {
            "Name": "cmd.exe",
            "ProcessId": 4100,
            "ParentProcessId": 100,
            "CommandLine": r#"cmd.exe /c C:\owned\codex.cmd app-server"#,
        },
        {
            "Name": "node.exe",
            "ProcessId": 4101,
            "ParentProcessId": 4100,
            "CommandLine": r#"node.exe C:\owned\node_modules\@openai\codex\bin\codex.js app-server"#,
        },
        {
            "Name": "codex.exe",
            "ProcessId": 4102,
            "ParentProcessId": 4101,
            "CommandLine": r#"C:\owned\vendor\codex.exe app-server"#,
        },
        {
            "Name": "node.exe",
            "ProcessId": 4200,
            "ParentProcessId": 100,
            "CommandLine": r#"node.exe C:\work\codex-native-session-import\scripts\build.js"#,
        }
    ]))
    .unwrap();

    ensure_codex_not_running_from_snapshot_excluding(&snapshot, &[4100]).unwrap();
}

#[test]
fn process_guard_does_not_exclude_an_unrelated_user_codex_tree() {
    let snapshot = serde_json::to_string(&json!([
        {
            "Name": "cmd.exe",
            "ProcessId": 4100,
            "ParentProcessId": 100,
            "CommandLine": r#"cmd.exe /c C:\owned\codex.cmd app-server"#,
        },
        {
            "Name": "node.exe",
            "ProcessId": 4101,
            "ParentProcessId": 4100,
            "CommandLine": r#"node.exe C:\owned\node_modules\@openai\codex\bin\codex.js app-server"#,
        },
        {
            "Name": "codex.exe",
            "ProcessId": 5100,
            "ParentProcessId": 5000,
            "CommandLine": r#"C:\user\codex.exe resume"#,
        }
    ]))
    .unwrap();

    assert!(ensure_codex_not_running_from_snapshot_excluding(&snapshot, &[4100]).is_err());
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
fn backup_rejects_linked_source_subtree_without_copying_it() {
    let codex_home = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let sessions = codex_home.path().join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    link_directory(&sessions.join("linked"), outside.path());
    fs::write(outside.path().join("secret.jsonl"), b"outside secret").unwrap();
    let source = sessions.join("linked").join("secret.jsonl");

    let result = backup_codex_targets(
        codex_home.path(),
        &codex_home.path().join("backups"),
        &[source],
    );

    assert!(result.is_err());
}

#[test]
fn backup_rejects_hard_linked_source_file_without_copying_it() {
    let codex_home = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let sessions = codex_home.path().join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    let outside_source = outside.path().join("secret.jsonl");
    fs::write(&outside_source, b"outside secret").unwrap();
    let source = sessions.join("secret.jsonl");
    fs::hard_link(&outside_source, &source).unwrap();

    let result = backup_codex_targets(
        codex_home.path(),
        &codex_home.path().join("backups"),
        &[source],
    );

    assert!(result.is_err());
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
        title: None,
        visible_history: empty_history(),
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
    assert_eq!(report.visible_turns, 0);
    assert!(sent.iter().all(|value| value["method"] != "thread/delete"));
}

#[test]
fn guarded_fork_checks_processes_before_fork_and_name_mutations() {
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
    responses[1]["result"]["thread"]["name"] = Value::String("Imported fixture".into());
    responses[1]["result"]["thread"]["turns"] = Value::Array(Vec::new());
    responses.insert(2, json!({"jsonrpc": "2.0", "id": 3, "result": {}}));
    for (offset, response) in responses.iter_mut().enumerate().skip(3) {
        response["id"] = Value::from((offset + 1) as u64);
        if let Some(data) = response
            .pointer_mut("/result/data")
            .and_then(Value::as_array_mut)
        {
            for thread in data {
                thread["name"] = Value::String("Imported fixture".into());
            }
        }
        if let Some(thread) = response.pointer_mut("/result/thread") {
            thread["name"] = Value::String("Imported fixture".into());
        }
    }
    let mutation_events = Arc::new(Mutex::new(Vec::new()));
    let (mut transport, sent) =
        ScriptedTransport::with_mutation_events(responses, Arc::clone(&mutation_events));
    let checks = AtomicUsize::new(0);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
        title: Some("Imported fixture".into()),
        visible_history: empty_history(),
    };

    fork_rollout_with_target_provider_transport_guarded(
        &mut transport,
        codex_home.path(),
        &request,
        &|_excluded| {
            mutation_events.lock().unwrap().push("guard".into());
            checks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        &[],
    )
    .unwrap();

    assert_eq!(checks.load(Ordering::SeqCst), 2);
    let methods = sent
        .lock()
        .unwrap()
        .iter()
        .filter_map(|value| value.get("method").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(
        methods
            .windows(2)
            .any(|pair| pair == ["thread/fork", "thread/name/set"])
    );
    assert_eq!(
        *mutation_events.lock().unwrap(),
        ["guard", "thread/fork", "guard", "thread/name/set"]
    );
}

#[test]
fn guarded_fork_requires_manual_cleanup_when_process_appears_before_delete() {
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
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let checks = AtomicUsize::new(0);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
        title: None,
        visible_history: empty_history(),
    };

    let error = fork_rollout_with_target_provider_transport_guarded(
        &mut transport,
        codex_home.path(),
        &request,
        &|_excluded| {
            if checks.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(NativeImportError::CodexRunning)
            }
        },
        &[],
    )
    .unwrap_err();

    assert!(matches!(error, NativeImportError::ManualIntervention));
    assert_eq!(checks.load(Ordering::SeqCst), 2);
    assert!(
        sent.lock()
            .unwrap()
            .iter()
            .all(|value| value["method"] != "thread/delete")
    );
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
        title: None,
        visible_history: empty_history(),
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
    responses.push(json!({"jsonrpc": "2.0", "id": 4, "result": {"data": [], "nextCursor": null}}));
    responses.push(json!({"jsonrpc": "2.0", "id": 5, "result": {"data": [], "nextCursor": null}}));
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
        title: None,
        visible_history: empty_history(),
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
        title: None,
        visible_history: empty_history(),
    };

    let error =
        fork_rollout_with_target_provider_transport(&mut transport, codex_home.path(), &request)
            .unwrap_err();

    assert!(matches!(error, NativeImportError::ManualIntervention));
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
        title: None,
        visible_history: empty_history(),
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
        title: None,
        visible_history: empty_history(),
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
        title: None,
        visible_history: empty_history(),
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
    responses.push(json!({"jsonrpc": "2.0", "id": 5, "result": {"data": [], "nextCursor": null}}));
    responses.push(json!({"jsonrpc": "2.0", "id": 6, "result": {"data": [], "nextCursor": null}}));
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
        title: None,
        visible_history: empty_history(),
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
        3
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
    responses.push(json!({"jsonrpc": "2.0", "id": 5, "result": {"data": [], "nextCursor": null}}));
    responses.push(json!({"jsonrpc": "2.0", "id": 6, "result": {"data": [], "nextCursor": null}}));
    let (mut transport, sent) = ScriptedTransport::new(responses);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019source-thread".into(),
        target_cwd,
        target_provider: Some("openai".into()),
        target_model: Some("gpt-5".into()),
        title: None,
        visible_history: empty_history(),
    };

    let error =
        fork_rollout_with_target_provider_transport(&mut transport, codex_home.path(), &request)
            .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("mapped target cwd does not match")
    );
    let sent = sent.lock().unwrap();
    assert_eq!(
        sent.iter()
            .filter(|value| value["method"] == "thread/list")
            .count(),
        3
    );
    assert_eq!(
        sent.iter()
            .filter(|value| value["method"] == "thread/delete")
            .count(),
        1
    );
}
