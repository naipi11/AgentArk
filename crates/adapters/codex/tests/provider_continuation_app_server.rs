use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use agentark_adapter_codex::{
    CodexContinuationReport, CodexContinuationRequest, JsonRpcTransport, ProcessTransport,
    RawJsonRpc, fork_rollout_with_target_provider, native_thread_expectation,
};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

struct FixtureContext {
    _root: TempDir,
    codex_home: PathBuf,
    executable: PathBuf,
    initial_visible_turns: usize,
}

fn fixture_contexts() -> &'static Mutex<HashMap<String, FixtureContext>> {
    static CONTEXTS: OnceLock<Mutex<HashMap<String, FixtureContext>>> = OnceLock::new();
    CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[test]
#[ignore = "requires compatible Codex, source rollout, and target provider"]
fn fork_rebases_visible_history_to_target_provider() {
    let report = fork_fixture_with_target_provider("openai", None).unwrap();
    assert_ne!(report.source_thread_id, report.target_thread_id);
    assert!(report.visible_turns > 0);
    assert_eq!(report.model_provider, "openai");
    cleanup_fixture(&report.target_thread_id);
}

#[test]
#[ignore = "starts a billed target-provider turn only when explicitly enabled"]
fn forked_thread_accepts_a_target_provider_turn() {
    if std::env::var_os("AGENTARK_RUN_PROVIDER_CONTINUATION").is_none() {
        return;
    }
    let report = fork_fixture_with_target_provider("openai", None).unwrap();
    start_and_wait_for_turn(
        &report.target_thread_id,
        "Reply only: continuation verified.",
    )
    .unwrap();
    assert_target_turn_is_visible(&report.target_thread_id).unwrap();
    cleanup_fixture(&report.target_thread_id);
}

fn fork_fixture_with_target_provider(
    provider: &str,
    model: Option<&str>,
) -> Result<CodexContinuationReport, Box<dyn Error>> {
    let executable = env::var_os("AGENTARK_CODEX_BIN")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "AGENTARK_CODEX_BIN"))?;
    let fixture = env::var_os("AGENTARK_CODEX_ROLLOUT_FIXTURE")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "AGENTARK_CODEX_ROLLOUT_FIXTURE"))?;
    let root = tempdir()?;
    let codex_home = root.path().join("codex");
    let source_rollout = codex_home
        .join("sessions")
        .join("2026")
        .join("08")
        .join("23")
        .join(
            fixture
                .file_name()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "fixture filename"))?,
        );
    fs::create_dir_all(source_rollout.parent().unwrap())?;
    fs::copy(&fixture, &source_rollout)?;
    let source = fs::read(&source_rollout)?;
    let expected = native_thread_expectation(&source)?;
    let target_cwd = env::current_dir()?;
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: expected.thread_id,
        target_cwd,
        target_provider: Some(provider.to_owned()),
        target_model: model.map(str::to_owned),
    };
    let report = fork_rollout_with_target_provider(&executable, &codex_home, &request)?;
    fixture_contexts().lock().unwrap().insert(
        report.target_thread_id.clone(),
        FixtureContext {
            _root: root,
            codex_home,
            executable,
            initial_visible_turns: report.visible_turns,
        },
    );
    Ok(report)
}

fn start_and_wait_for_turn(thread_id: &str, prompt: &str) -> Result<(), Box<dyn Error>> {
    let contexts = fixture_contexts().lock().unwrap();
    let context = contexts
        .get(thread_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "fixture context"))?;
    let mut transport =
        ProcessTransport::spawn_with_codex_home(&context.executable, Some(&context.codex_home))?;
    initialize(&mut transport)?;
    transport.send_value(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "turn/start",
        "params": {
            "threadId": thread_id,
            "input": [{"type": "text", "text": prompt}]
        }
    }))?;
    let mut started = false;
    let mut completed = false;
    while !started || !completed {
        let response = transport.receive_value()?;
        if response.value.get("id") == Some(&Value::from(2)) {
            if let Some(error) = response.value.get("error") {
                return Err(io::Error::other(format!("turn/start failed: {error}")).into());
            }
            started = true;
        }
        if response.value.get("method").and_then(Value::as_str) == Some("turn/completed")
            && response
                .value
                .pointer("/params/threadId")
                .and_then(Value::as_str)
                == Some(thread_id)
        {
            completed = true;
        }
    }
    Ok(())
}

fn assert_target_turn_is_visible(thread_id: &str) -> Result<(), Box<dyn Error>> {
    let contexts = fixture_contexts().lock().unwrap();
    let context = contexts
        .get(thread_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "fixture context"))?;
    let mut transport =
        ProcessTransport::spawn_with_codex_home(&context.executable, Some(&context.codex_home))?;
    initialize(&mut transport)?;
    transport.send_value(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "thread/read",
        "params": {"threadId": thread_id, "includeTurns": true}
    }))?;
    let response = receive_response(&mut transport, 2)?;
    let visible_turns = response
        .value
        .pointer("/result/thread/turns")
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "thread/read turns"))?;
    if visible_turns <= context.initial_visible_turns {
        return Err(io::Error::other("target provider turn is not visible").into());
    }
    Ok(())
}

fn initialize<T: JsonRpcTransport>(transport: &mut T) -> Result<(), Box<dyn Error>> {
    transport.send_value(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "clientInfo": {
                "name": "agentark-provider-continuation-test",
                "title": "AgentArk",
                "version": "0.5.0"
            },
            "capabilities": {"experimentalApi": true}
        }
    }))?;
    receive_response(transport, 1)?;
    transport.send_value(&json!({"method": "initialized", "params": {}}))?;
    Ok(())
}

fn receive_response<T: JsonRpcTransport>(
    transport: &mut T,
    id: u64,
) -> Result<RawJsonRpc, Box<dyn Error>> {
    loop {
        let response = transport.receive_value()?;
        if response.value.get("id") == Some(&Value::from(id)) {
            if let Some(error) = response.value.get("error") {
                return Err(io::Error::other(format!("App Server request failed: {error}")).into());
            }
            return Ok(response);
        }
    }
}

fn cleanup_fixture(thread_id: &str) {
    fixture_contexts().lock().unwrap().remove(thread_id);
}
