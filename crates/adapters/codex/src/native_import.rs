use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use agentark_canonical::Sha256Digest;
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

use crate::{CODEX_VERSION, CodexError, JsonRpcTransport, ProcessTransport, RawJsonRpc};

#[derive(Debug, Error)]
pub enum NativeImportError {
    #[error("native rollout I/O failed")]
    Io(#[from] io::Error),
    #[error("native rollout JSON failed")]
    Json(#[from] serde_json::Error),
    #[error("native rollout is invalid: {0}")]
    Invalid(String),
    #[error("Codex native import is unsupported for this version")]
    UnsupportedVersion,
    #[error("Codex native import verification failed: {0}")]
    Verification(String),
    #[error("Codex is running; native import requires it to be closed")]
    CodexRunning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeCapability {
    Supported,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeThreadExpectation {
    pub thread_id: String,
    pub cwd: String,
    pub title: Option<String>,
    pub visible_text_hash: Sha256Digest,
    pub visible_turns: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexContinuationRequest {
    pub source_rollout: PathBuf,
    pub source_thread_id: String,
    pub target_cwd: PathBuf,
    pub target_provider: Option<String>,
    pub target_model: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexContinuationReport {
    pub source_thread_id: String,
    pub target_thread_id: String,
    pub rollout_path: PathBuf,
    pub model_provider: String,
    pub model: String,
    pub visible_turns: usize,
}

pub fn ensure_codex_not_running_from_tasklist(output: &str) -> Result<(), NativeImportError> {
    let names = ["codex.exe", "codex-desktop.exe", "codexdesktop.exe"];
    if output.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        names
            .iter()
            .any(|name| lower.contains(&format!("\"{name}\"")))
    }) {
        return Err(NativeImportError::CodexRunning);
    }
    Ok(())
}

pub fn ensure_codex_not_running() -> Result<(), NativeImportError> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .output()?;
        ensure_codex_not_running_from_tasklist(&String::from_utf8_lossy(&output.stdout))
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

pub fn backup_codex_targets(
    codex_home: &Path,
    backup_root: &Path,
    files: &[PathBuf],
) -> Result<PathBuf, NativeImportError> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default();
    let backup = backup_root.join(format!("codex-{stamp}-{}", Uuid::new_v4()));
    fs::create_dir_all(&backup)?;
    let mut manifest = Vec::new();
    for source in files {
        let relative = source
            .strip_prefix(codex_home)
            .map_err(|_| NativeImportError::Invalid("backup target escapes CODEX_HOME".into()))?;
        if !source.is_file() {
            manifest.push(json!({
                "path": relative.to_string_lossy().replace('\\', "/"),
                "status": "missing"
            }));
            continue;
        }
        let bytes = fs::read(source)?;
        let destination = backup.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&destination, &bytes)?;
        manifest.push(json!({
            "path": relative.to_string_lossy().replace('\\', "/"),
            "status": "backed-up",
            "size": bytes.len(),
            "sha256": Sha256Digest::from_bytes(&bytes).as_str()
        }));
    }
    fs::write(
        backup.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({"files": manifest}))?,
    )?;
    Ok(backup)
}

pub fn verify_rollout_with_app_server(
    executable: &Path,
    codex_home: &Path,
    rollout: &Path,
    expected: &NativeThreadExpectation,
) -> Result<(), NativeImportError> {
    verify_rollouts_with_app_server(
        executable,
        codex_home,
        &[(rollout.to_path_buf(), expected.clone())],
    )
}

pub fn verify_rollouts_with_app_server(
    executable: &Path,
    codex_home: &Path,
    rollouts: &[(PathBuf, NativeThreadExpectation)],
) -> Result<(), NativeImportError> {
    let mut transport = ProcessTransport::spawn_with_codex_home(executable, Some(codex_home))
        .map_err(map_codex_error)?;
    let mut client = NativeAppServerClient::new(&mut transport);
    client.initialize()?;
    for (rollout, expected) in rollouts {
        let resume_request_id = Uuid::now_v7().to_string();
        let resumed = client.request(
            "thread/resume",
            json!({"threadId": resume_request_id, "path": rollout.to_string_lossy()}),
        )?;
        let thread = resumed.value.pointer("/result/thread").ok_or_else(|| {
            NativeImportError::Verification("thread/resume returned no thread".into())
        })?;
        if thread.get("id").and_then(Value::as_str) != Some(expected.thread_id.as_str()) {
            return Err(NativeImportError::Verification(
                "thread/resume returned a different thread id".into(),
            ));
        }
        let listed = client.request(
            "thread/list",
            json!({
                "archived": false,
                "sourceKinds": ["cli", "vscode", "exec", "appServer", "subAgent", "subAgentReview", "subAgentCompact", "subAgentThreadSpawn", "subAgentOther", "unknown"],
                "limit": 1000
            }),
        )?;
        if verify_thread_listing(&listed.value, expected).is_err() {
            let archived = client.request(
                "thread/list",
                json!({
                    "archived": true,
                    "sourceKinds": ["cli", "vscode", "exec", "appServer", "subAgent", "subAgentReview", "subAgentCompact", "subAgentThreadSpawn", "subAgentOther", "unknown"],
                    "limit": 1000
                }),
            )?;
            verify_thread_listing(&archived.value, expected)?;
        }
        let read = client.request(
            "thread/read",
            json!({"threadId": expected.thread_id, "includeTurns": true}),
        )?;
        verify_thread_read(&read.value, expected)?;
    }
    Ok(())
}

pub fn fork_rollout_with_target_provider(
    executable: &Path,
    codex_home: &Path,
    request: &CodexContinuationRequest,
) -> Result<CodexContinuationReport, NativeImportError> {
    let mut transport = ProcessTransport::spawn_with_codex_home(executable, Some(codex_home))
        .map_err(map_codex_error)?;
    fork_rollout_with_target_provider_transport(&mut transport, codex_home, request)
}

/// Transport-injected form of [`fork_rollout_with_target_provider`].
///
/// This is public so protocol tests can exercise the exact JSON-RPC boundary
/// without launching or contacting a provider.
#[doc(hidden)]
pub fn fork_rollout_with_target_provider_transport<T: JsonRpcTransport>(
    transport: &mut T,
    codex_home: &Path,
    request: &CodexContinuationRequest,
) -> Result<CodexContinuationReport, NativeImportError> {
    let mut client = NativeAppServerClient::new(transport);
    client.initialize()?;
    client.request("modelProvider/capabilities/read", json!({}))?;
    client.request("model/list", json!({}))?;

    let mut params = json!({
        "threadId": request.source_thread_id,
        "path": request.source_rollout.to_string_lossy(),
        "cwd": request.target_cwd.to_string_lossy(),
        "threadSource": "user",
        "ephemeral": false,
    });
    if let Some(provider) = &request.target_provider {
        params["modelProvider"] = Value::String(provider.clone());
    }
    if let Some(model) = &request.target_model {
        params["model"] = Value::String(model.clone());
    }
    let response = client.request("thread/fork", params)?;
    let target_thread_id = required_nonempty_label(
        &response.value,
        "/result/thread/id",
        "thread/fork returned no target thread id",
    )?;
    if target_thread_id == request.source_thread_id {
        return Err(NativeImportError::Verification(
            "thread/fork reused the source thread id".into(),
        ));
    }
    let rollout_path = required_nonempty_label(
        &response.value,
        "/result/thread/path",
        "thread/fork returned no rollout path",
    )?;
    let rollout_path = verified_session_rollout_path(codex_home, Path::new(&rollout_path))?;
    let model_provider = required_nonempty_label(
        &response.value,
        "/result/modelProvider",
        "thread/fork returned no model provider",
    )?;
    let model = required_nonempty_label(
        &response.value,
        "/result/model",
        "thread/fork returned no model",
    )?;
    if let Some(expected) = request.target_provider.as_deref()
        && model_provider != expected
    {
        return Err(NativeImportError::Verification(
            "thread/fork returned a different model provider".into(),
        ));
    }
    if let Some(expected) = request.target_model.as_deref()
        && model != expected
    {
        return Err(NativeImportError::Verification(
            "thread/fork returned a different model".into(),
        ));
    }

    let target_cwd = request.target_cwd.to_string_lossy();
    let listed = client.request("thread/list", continuation_list_params(false))?;
    if verify_continuation_listing(&listed.value, &target_thread_id, &target_cwd).is_err() {
        let archived = client.request("thread/list", continuation_list_params(true))?;
        verify_continuation_listing(&archived.value, &target_thread_id, &target_cwd)?;
    }
    let read = client.request(
        "thread/read",
        json!({"threadId": target_thread_id, "includeTurns": true}),
    )?;
    let visible_turns = verify_continuation_read(&read.value, &target_thread_id, &target_cwd)?;

    Ok(CodexContinuationReport {
        source_thread_id: request.source_thread_id.clone(),
        target_thread_id,
        rollout_path,
        model_provider,
        model,
        visible_turns,
    })
}

fn required_nonempty_label(
    response: &Value,
    pointer: &str,
    error: &str,
) -> Result<String, NativeImportError> {
    response
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| NativeImportError::Verification(error.into()))
}

fn verified_session_rollout_path(
    codex_home: &Path,
    rollout: &Path,
) -> Result<PathBuf, NativeImportError> {
    if !rollout.is_absolute() {
        return Err(NativeImportError::Verification(
            "thread/fork rollout path is not absolute".into(),
        ));
    }
    let sessions = dunce::canonicalize(codex_home.join("sessions")).map_err(|_| {
        NativeImportError::Verification("CODEX_HOME sessions path cannot be resolved".into())
    })?;
    let rollout = dunce::canonicalize(rollout).map_err(|_| {
        NativeImportError::Verification("thread/fork rollout path cannot be resolved".into())
    })?;
    rollout.strip_prefix(&sessions).map_err(|_| {
        NativeImportError::Verification(
            "thread/fork rollout path escapes CODEX_HOME sessions".into(),
        )
    })?;
    Ok(rollout)
}

fn continuation_list_params(archived: bool) -> Value {
    json!({
        "archived": archived,
        "sourceKinds": ["cli", "vscode", "exec", "appServer", "subAgent", "subAgentReview", "subAgentCompact", "subAgentThreadSpawn", "subAgentOther", "unknown"],
        "limit": 1000
    })
}

fn verify_continuation_listing(
    response: &Value,
    target_thread_id: &str,
    target_cwd: &str,
) -> Result<(), NativeImportError> {
    let threads = response
        .pointer("/result/data")
        .and_then(Value::as_array)
        .ok_or_else(|| NativeImportError::Verification("thread/list data is missing".into()))?;
    let thread = threads
        .iter()
        .find(|thread| thread.get("id").and_then(Value::as_str) == Some(target_thread_id))
        .ok_or_else(|| NativeImportError::Verification("forked thread is not listed".into()))?;
    if thread.get("cwd").and_then(Value::as_str) != Some(target_cwd) {
        return Err(NativeImportError::Verification(
            "forked thread cwd does not match".into(),
        ));
    }
    Ok(())
}

fn verify_continuation_read(
    response: &Value,
    target_thread_id: &str,
    target_cwd: &str,
) -> Result<usize, NativeImportError> {
    let thread = response
        .pointer("/result/thread")
        .ok_or_else(|| NativeImportError::Verification("thread/read returned no thread".into()))?;
    if thread.get("id").and_then(Value::as_str) != Some(target_thread_id) {
        return Err(NativeImportError::Verification(
            "thread/read returned a different thread id".into(),
        ));
    }
    if thread.get("cwd").and_then(Value::as_str) != Some(target_cwd) {
        return Err(NativeImportError::Verification(
            "thread/read cwd does not match".into(),
        ));
    }
    let visible_turns = thread
        .get("turns")
        .and_then(Value::as_array)
        .map(Vec::len)
        .filter(|turns| *turns > 0)
        .ok_or_else(|| {
            NativeImportError::Verification("thread/read returned no visible turns".into())
        })?;
    Ok(visible_turns)
}

fn verify_thread_read(
    response: &Value,
    expected: &NativeThreadExpectation,
) -> Result<(), NativeImportError> {
    let thread = response
        .pointer("/result/thread")
        .ok_or_else(|| NativeImportError::Verification("thread/read returned no thread".into()))?;
    if thread.get("cwd").and_then(Value::as_str) != Some(expected.cwd.as_str()) {
        return Err(NativeImportError::Verification(
            "thread/read cwd does not match".into(),
        ));
    }
    let turns = thread
        .get("turns")
        .and_then(Value::as_array)
        .ok_or_else(|| NativeImportError::Verification("thread/read returned no turns".into()))?;
    if turns.len() < expected.visible_turns {
        return Err(NativeImportError::Verification(
            "thread/read returned too few visible turns".into(),
        ));
    }
    Ok(())
}

struct NativeAppServerClient<'a, T: JsonRpcTransport> {
    transport: &'a mut T,
    next_id: u64,
}

impl<'a, T: JsonRpcTransport> NativeAppServerClient<'a, T> {
    fn new(transport: &'a mut T) -> Self {
        Self {
            transport,
            next_id: 1,
        }
    }

    fn initialize(&mut self) -> Result<(), NativeImportError> {
        self.request(
            "initialize",
            json!({
                "clientInfo": {"name": "agentark-native-import", "title": "AgentArk", "version": "0.5.0"},
                "capabilities": {"experimentalApi": true}
            }),
        )?;
        self.transport
            .send_value(&json!({"method":"initialized","params":{}}))
            .map_err(map_codex_error)
    }

    fn request(&mut self, method: &str, params: Value) -> Result<RawJsonRpc, NativeImportError> {
        let id = self.next_id;
        self.next_id += 1;
        self.transport
            .send_value(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .map_err(map_codex_error)?;
        loop {
            let response = self.transport.receive_value().map_err(map_codex_error)?;
            if response.value.get("id") == Some(&Value::from(id)) {
                if let Some(error) = response.value.get("error") {
                    return Err(NativeImportError::Verification(
                        error
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("Codex App Server request failed")
                            .to_owned(),
                    ));
                }
                return Ok(response);
            }
        }
    }
}

fn map_codex_error(error: CodexError) -> NativeImportError {
    NativeImportError::Verification(error.to_string())
}

pub fn native_import_capability_from_outputs(
    version_output: &str,
    help_output: &str,
) -> Result<NativeCapability, NativeImportError> {
    let version = crate::parse_version(version_output)
        .map_err(|_| NativeImportError::Invalid("Codex version output is invalid".into()))?;
    if version != CODEX_VERSION || !help_output.contains("--listen stdio://") {
        return Ok(NativeCapability::Unsupported);
    }
    Ok(NativeCapability::Supported)
}

pub fn verify_thread_listing(
    response: &Value,
    expected: &NativeThreadExpectation,
) -> Result<(), NativeImportError> {
    let threads = response
        .pointer("/result/data")
        .and_then(Value::as_array)
        .ok_or_else(|| NativeImportError::Verification("thread/list data is missing".into()))?;
    let thread = threads
        .iter()
        .find(|thread| {
            thread.get("id").and_then(Value::as_str) == Some(expected.thread_id.as_str())
        })
        .ok_or_else(|| NativeImportError::Verification("imported thread is not listed".into()))?;
    if thread.get("cwd").and_then(Value::as_str) != Some(expected.cwd.as_str()) {
        return Err(NativeImportError::Verification(
            "imported thread cwd does not match".into(),
        ));
    }
    if let Some(title) = &expected.title
        && thread.get("name").and_then(Value::as_str) != Some(title.as_str())
    {
        return Err(NativeImportError::Verification(
            "imported thread title does not match".into(),
        ));
    }
    Ok(())
}

/// Writes a complete rollout using a same-directory temporary file and an
/// atomic rename. The returned digest covers the exact bytes on disk.
pub fn write_rollout_atomic(
    path: &Path,
    lines: &[Vec<u8>],
) -> Result<Sha256Digest, NativeImportError> {
    let parent = path
        .parent()
        .ok_or_else(|| NativeImportError::Invalid("rollout has no parent".into()))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("rollout"),
        Uuid::new_v4()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        for line in lines {
            file.write_all(line)?;
        }
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        let mut committed = File::open(path)?;
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut committed, &mut bytes)?;
        Ok(Sha256Digest::from_bytes(&bytes))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
