use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agentark_adapter_codex::{
    CodexContinuationRequest, CodexError, CodexTargetDefault, CodexTargetSessionExpectation,
    CodexVisibleHistoryExpectation, JsonRpcTransport, NativeImportError, NativeThreadExpectation,
    RawJsonRpc, backup_codex_targets, delete_thread_with_app_server_transport,
    delete_thread_with_app_server_transport_guarded, ensure_codex_not_running_from_snapshot,
    ensure_codex_not_running_from_snapshot_excluding, fork_rollout_with_target_provider_transport,
    fork_rollout_with_target_provider_transport_guarded, probe_target_default_transport,
    verify_target_session_transport, verify_thread_listing,
    write_rollout_atomic_with_guarded_operations, write_rollout_atomic_with_operations,
    write_rollout_atomic_with_reader,
};
use agentark_canonical::Sha256Digest;
use serde_json::{Value, json};
use tempfile::tempdir;

struct ScriptedTransport {
    sent: Arc<Mutex<Vec<Value>>>,
    responses: VecDeque<Value>,
    mutation_events: Option<Arc<Mutex<Vec<String>>>>,
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
