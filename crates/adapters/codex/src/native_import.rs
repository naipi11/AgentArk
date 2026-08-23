use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentark_canonical::Sha256Digest;
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

use crate::protocol::{APP_SERVER_REQUEST_TIMEOUT, receive_response_until};
use crate::{
    AGENTARK_APP_SERVER_CLIENT_VERSION, CODEX_VERSION, CodexError, CodexVisibleHistoryExpectation,
    CodexVisibleMessage, CodexVisibleRole, JsonRpcTransport, ProcessTransport, RawJsonRpc,
};

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
    #[error("Codex rollback failed; manual intervention is required")]
    Rollback,
    #[error("Codex recovery requires manual intervention")]
    ManualIntervention,
    #[error("Codex App Server request timed out")]
    Timeout,
    #[error("Codex mutation outcome is unknown; manual intervention is required")]
    MutationOutcomeUnknown,
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
    pub model_provider: String,
    pub rollout_hash: Sha256Digest,
    pub visible_history: CodexVisibleHistoryExpectation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexContinuationRequest {
    pub source_rollout: PathBuf,
    pub source_thread_id: String,
    pub target_cwd: PathBuf,
    pub target_provider: Option<String>,
    pub target_model: Option<String>,
    pub title: Option<String>,
    pub visible_history: CodexVisibleHistoryExpectation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexContinuationReport {
    pub source_thread_id: String,
    pub target_thread_id: String,
    pub rollout_path: PathBuf,
    pub model_provider: String,
    pub model: String,
    pub visible_turns: usize,
    pub rollout_hash: Sha256Digest,
    pub visible_history: CodexVisibleHistoryExpectation,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct CodexTargetDefault {
    pub model_provider: String,
    pub model: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexTargetSessionExpectation {
    pub thread_id: String,
    pub cwd: String,
    pub title: Option<String>,
    pub model_provider: String,
    pub rollout_hash: Sha256Digest,
    pub visible_history: CodexVisibleHistoryExpectation,
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
    for resume in [true, false] {
        let mut transport = ProcessTransport::spawn_with_codex_home(executable, Some(codex_home))
            .map_err(map_codex_error)?;
        let mut client = NativeAppServerClient::new(&mut transport);
        client.initialize()?;
        for (rollout, expected) in rollouts {
            verify_native_rollout_hash(codex_home, rollout, expected)?;
            if resume {
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
            }
            verify_native_list_and_read(&mut client, expected)?;
        }
    }
    Ok(())
}

fn verify_native_rollout_hash(
    codex_home: &Path,
    rollout: &Path,
    expected: &NativeThreadExpectation,
) -> Result<(), NativeImportError> {
    let rollout = verified_session_rollout_path(codex_home, rollout)?;
    let bytes = fs::read(rollout).map_err(|_| {
        NativeImportError::Verification("native target rollout cannot be read".into())
    })?;
    if Sha256Digest::from_bytes(&bytes) != expected.rollout_hash {
        return Err(NativeImportError::Verification(
            "native target rollout hash does not match".into(),
        ));
    }
    Ok(())
}

fn verify_native_list_and_read<T: JsonRpcTransport>(
    client: &mut NativeAppServerClient<'_, T>,
    expected: &NativeThreadExpectation,
) -> Result<(), NativeImportError> {
    let thread = match find_thread_in_listing(client, false, &expected.thread_id)? {
        Some(thread) => thread,
        None => find_thread_in_listing(client, true, &expected.thread_id)?.ok_or_else(|| {
            NativeImportError::Verification("imported thread is not listed".into())
        })?,
    };
    verify_native_thread_listing(&thread, expected)?;
    let read = client.request(
        "thread/read",
        json!({"threadId": expected.thread_id, "includeTurns": true}),
    )?;
    verify_thread_read(&read.value, expected)
}

pub fn probe_target_default(
    executable: &Path,
    codex_home: &Path,
) -> Result<CodexTargetDefault, NativeImportError> {
    let mut transport = ProcessTransport::spawn_with_codex_home(executable, Some(codex_home))
        .map_err(map_codex_error)?;
    probe_target_default_transport(&mut transport)
}

/// Transport-injected form of [`probe_target_default`].
#[doc(hidden)]
pub fn probe_target_default_transport<T: JsonRpcTransport>(
    transport: &mut T,
) -> Result<CodexTargetDefault, NativeImportError> {
    let mut client = NativeAppServerClient::new(transport);
    client.initialize()?;
    let response = client
        .request("config/read", json!({}))
        .map_err(map_target_probe_error)?;
    let config = response
        .value
        .pointer("/result/config")
        .filter(|value| value.is_object())
        .ok_or_else(target_probe_failure)?;
    let model_provider = match config.get("model_provider") {
        Some(value) if !value.is_null() => validated_label(value, "model provider")?,
        _ => "openai".to_owned(),
    };
    let model = match config.get("model") {
        Some(value) if !value.is_null() => validated_label(value, "model")?,
        _ => {
            let models = client
                .request("model/list", json!({}))
                .map_err(map_target_probe_error)?;
            let advertised = models
                .value
                .pointer("/result/data")
                .and_then(Value::as_array)
                .ok_or_else(target_probe_failure)?;
            let defaults = advertised
                .iter()
                .filter(|model| model.get("isDefault").and_then(Value::as_bool) == Some(true))
                .collect::<Vec<_>>();
            if defaults.len() != 1 {
                return Err(target_probe_failure());
            }
            let value = defaults[0]
                .get("model")
                .or_else(|| defaults[0].get("id"))
                .ok_or_else(target_probe_failure)?;
            validated_label(value, "model")?
        }
    };
    Ok(CodexTargetDefault {
        model_provider,
        model,
    })
}

pub fn verify_target_session(
    executable: &Path,
    codex_home: &Path,
    expected: &CodexTargetSessionExpectation,
) -> Result<(), NativeImportError> {
    let mut transport = ProcessTransport::spawn_with_codex_home(executable, Some(codex_home))
        .map_err(map_codex_error)?;
    verify_target_session_transport(&mut transport, codex_home, expected)
}

/// Transport-injected form of [`verify_target_session`].
#[doc(hidden)]
pub fn verify_target_session_transport<T: JsonRpcTransport>(
    transport: &mut T,
    codex_home: &Path,
    expected: &CodexTargetSessionExpectation,
) -> Result<(), NativeImportError> {
    let mut client = NativeAppServerClient::new(transport);
    client.initialize()?;
    let thread =
        match find_thread_in_listing(&mut client, false, &expected.thread_id)? {
            Some(thread) => thread,
            None => find_thread_in_listing(&mut client, true, &expected.thread_id)?.ok_or_else(
                || NativeImportError::Verification("mapped target thread is not listed".into()),
            )?,
        };
    let rollout_path = existing_target_rollout(&thread, codex_home, expected)?;
    let bytes = fs::read(&rollout_path).map_err(|_| {
        NativeImportError::Verification("mapped target rollout cannot be read".into())
    })?;
    if Sha256Digest::from_bytes(&bytes) != expected.rollout_hash {
        return Err(NativeImportError::Verification(
            "mapped target rollout hash does not match".into(),
        ));
    }
    let read = client.request(
        "thread/read",
        json!({"threadId": expected.thread_id, "includeTurns": true}),
    )?;
    let thread = read
        .value
        .pointer("/result/thread")
        .ok_or_else(|| NativeImportError::Verification("mapped target cannot be read".into()))?;
    verify_target_thread_read(thread, expected)
}

pub fn fork_rollout_with_target_provider(
    executable: &Path,
    codex_home: &Path,
    request: &CodexContinuationRequest,
) -> Result<CodexContinuationReport, NativeImportError> {
    fork_rollout_with_target_provider_guarded(
        executable,
        codex_home,
        request,
        &crate::ensure_codex_not_running_excluding,
    )
}

pub fn fork_rollout_with_target_provider_guarded<G>(
    executable: &Path,
    codex_home: &Path,
    request: &CodexContinuationRequest,
    guard: &G,
) -> Result<CodexContinuationReport, NativeImportError>
where
    G: Fn(&[u32]) -> Result<(), NativeImportError> + ?Sized,
{
    let attempt = {
        let mut transport = ProcessTransport::spawn_with_codex_home(executable, Some(codex_home))
            .map_err(map_codex_error)?;
        let excluded_process_ids = [transport.process_id()];
        let mut client = NativeAppServerClient::new(&mut transport);
        client.initialize()?;
        fork_rollout_attempt(
            &mut client,
            codex_home,
            request,
            guard,
            &excluded_process_ids,
        )
    };
    let report = resolve_fork_attempt(attempt, |thread_id| {
        delete_thread_with_app_server_guarded(executable, codex_home, thread_id, guard)
    })?;
    let expected = CodexTargetSessionExpectation {
        thread_id: report.target_thread_id.clone(),
        cwd: request.target_cwd.to_string_lossy().into_owned(),
        title: request.title.clone(),
        model_provider: report.model_provider.clone(),
        rollout_hash: report.rollout_hash.clone(),
        visible_history: report.visible_history.clone(),
    };
    if let Err(error) = verify_target_session(executable, codex_home, &expected) {
        return resolve_fork_attempt(
            Err(ForkAttemptError::known(
                error,
                report.target_thread_id.clone(),
            )),
            |thread_id| {
                delete_thread_with_app_server_guarded(executable, codex_home, thread_id, guard)
            },
        );
    }
    Ok(report)
}

pub fn delete_thread_with_app_server(
    executable: &Path,
    codex_home: &Path,
    thread_id: &str,
) -> Result<(), NativeImportError> {
    delete_thread_with_app_server_guarded(
        executable,
        codex_home,
        thread_id,
        &crate::ensure_codex_not_running_excluding,
    )
}

pub fn delete_thread_with_app_server_guarded<G>(
    executable: &Path,
    codex_home: &Path,
    thread_id: &str,
    guard: &G,
) -> Result<(), NativeImportError>
where
    G: Fn(&[u32]) -> Result<(), NativeImportError> + ?Sized,
{
    let mut transport = ProcessTransport::spawn_with_codex_home(executable, Some(codex_home))
        .map_err(map_codex_error)?;
    let excluded_process_ids = [transport.process_id()];
    delete_thread_with_app_server_transport_guarded(
        &mut transport,
        thread_id,
        guard,
        &excluded_process_ids,
    )
}

/// Transport-injected form of [`delete_thread_with_app_server`].
#[doc(hidden)]
pub fn delete_thread_with_app_server_transport<T: JsonRpcTransport>(
    transport: &mut T,
    thread_id: &str,
) -> Result<(), NativeImportError> {
    delete_thread_with_app_server_transport_guarded(transport, thread_id, &|_| Ok(()), &[])
}

/// Guard-injected form of [`delete_thread_with_app_server_transport`].
#[doc(hidden)]
pub fn delete_thread_with_app_server_transport_guarded<T, G>(
    transport: &mut T,
    thread_id: &str,
    guard: &G,
    excluded_process_ids: &[u32],
) -> Result<(), NativeImportError>
where
    T: JsonRpcTransport,
    G: Fn(&[u32]) -> Result<(), NativeImportError> + ?Sized,
{
    let mut client = NativeAppServerClient::new(transport);
    client.initialize()?;
    match delete_and_confirm_guarded(&mut client, thread_id, guard, excluded_process_ids) {
        Ok(()) => Ok(()),
        Err(NativeImportError::MutationOutcomeUnknown) => {
            Err(NativeImportError::MutationOutcomeUnknown)
        }
        Err(_) => Err(NativeImportError::ManualIntervention),
    }
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
    fork_rollout_with_target_provider_transport_guarded(
        transport,
        codex_home,
        request,
        &|_| Ok(()),
        &[],
    )
}

/// Guard-injected form of [`fork_rollout_with_target_provider_transport`].
#[doc(hidden)]
pub fn fork_rollout_with_target_provider_transport_guarded<T, G>(
    transport: &mut T,
    codex_home: &Path,
    request: &CodexContinuationRequest,
    guard: &G,
    excluded_process_ids: &[u32],
) -> Result<CodexContinuationReport, NativeImportError>
where
    T: JsonRpcTransport,
    G: Fn(&[u32]) -> Result<(), NativeImportError> + ?Sized,
{
    let mut client = NativeAppServerClient::new(transport);
    client.initialize()?;
    let attempt = fork_rollout_attempt(
        &mut client,
        codex_home,
        request,
        guard,
        excluded_process_ids,
    );
    resolve_fork_attempt(attempt, |thread_id| {
        delete_and_confirm_guarded(&mut client, thread_id, guard, excluded_process_ids)
    })
}

fn fork_rollout_attempt<T, G>(
    client: &mut NativeAppServerClient<'_, T>,
    codex_home: &Path,
    request: &CodexContinuationRequest,
    guard: &G,
    excluded_process_ids: &[u32],
) -> Result<CodexContinuationReport, ForkAttemptError>
where
    T: JsonRpcTransport,
    G: Fn(&[u32]) -> Result<(), NativeImportError> + ?Sized,
{
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
    guard(excluded_process_ids).map_err(ForkAttemptError::unknown)?;
    let response = client
        .request("thread/fork", params)
        .map_err(ForkAttemptError::unknown)?;
    let target_thread_id = response
        .value
        .pointer("/result/thread/id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ForkAttemptError::unknown(NativeImportError::ManualIntervention))?;
    if target_thread_id == request.source_thread_id {
        return Err(ForkAttemptError::unknown(
            NativeImportError::ManualIntervention,
        ));
    }
    let outcome = (|| {
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

        if let Some(title) = &request.title {
            guard(excluded_process_ids)?;
            client.request(
                "thread/name/set",
                json!({"threadId": target_thread_id, "name": title}),
            )?;
        }

        let rollout_bytes = fs::read(&rollout_path)
            .map_err(|_| NativeImportError::Verification("forked rollout cannot be read".into()))?;
        let rollout_hash = Sha256Digest::from_bytes(&rollout_bytes);
        let target_cwd = request.target_cwd.to_string_lossy().into_owned();
        let expected = CodexTargetSessionExpectation {
            thread_id: target_thread_id.clone(),
            cwd: target_cwd,
            title: request.title.clone(),
            model_provider: model_provider.clone(),
            rollout_hash: rollout_hash.clone(),
            visible_history: request.visible_history.clone(),
        };

        match find_thread_in_listing(client, false, &target_thread_id)? {
            Some(thread) => {
                let _ = existing_target_rollout(&thread, codex_home, &expected)?;
            }
            None => {
                if let Some(thread) = find_thread_in_listing(client, true, &target_thread_id)? {
                    let _ = existing_target_rollout(&thread, codex_home, &expected)?;
                }
            }
        }
        let read = client.request(
            "thread/read",
            json!({"threadId": target_thread_id, "includeTurns": true}),
        )?;
        let thread = read.value.pointer("/result/thread").ok_or_else(|| {
            NativeImportError::Verification("thread/read returned no thread".into())
        })?;
        verify_target_thread_read(thread, &expected)?;

        Ok(CodexContinuationReport {
            source_thread_id: request.source_thread_id.clone(),
            target_thread_id: target_thread_id.clone(),
            rollout_path,
            model_provider,
            model,
            visible_turns: request.visible_history.message_count,
            rollout_hash,
            visible_history: request.visible_history.clone(),
        })
    })();

    outcome.map_err(|error| ForkAttemptError::known(error, target_thread_id))
}

struct ForkAttemptError {
    error: NativeImportError,
    target_thread_id: Option<String>,
}

impl ForkAttemptError {
    fn unknown(error: NativeImportError) -> Self {
        Self {
            error,
            target_thread_id: None,
        }
    }

    fn known(error: NativeImportError, target_thread_id: String) -> Self {
        Self {
            error,
            target_thread_id: Some(target_thread_id),
        }
    }
}

fn resolve_fork_attempt<F>(
    attempt: Result<CodexContinuationReport, ForkAttemptError>,
    rollback: F,
) -> Result<CodexContinuationReport, NativeImportError>
where
    F: FnOnce(&str) -> Result<(), NativeImportError>,
{
    match attempt {
        Ok(report) => Ok(report),
        Err(ForkAttemptError {
            error,
            target_thread_id: None,
        }) => Err(error),
        Err(ForkAttemptError {
            error,
            target_thread_id: Some(target_thread_id),
        }) => match rollback(&target_thread_id) {
            Ok(()) => Err(error),
            Err(NativeImportError::MutationOutcomeUnknown) => {
                Err(NativeImportError::MutationOutcomeUnknown)
            }
            Err(_) => Err(NativeImportError::ManualIntervention),
        },
    }
}

fn delete_and_confirm_guarded<T, G>(
    client: &mut NativeAppServerClient<'_, T>,
    thread_id: &str,
    guard: &G,
    excluded_process_ids: &[u32],
) -> Result<(), NativeImportError>
where
    T: JsonRpcTransport,
    G: Fn(&[u32]) -> Result<(), NativeImportError> + ?Sized,
{
    guard(excluded_process_ids)?;
    client.request("thread/delete", json!({"threadId": thread_id}))?;
    for archived in [false, true] {
        if find_thread_in_listing(client, archived, thread_id)?.is_some() {
            return Err(NativeImportError::ManualIntervention);
        }
    }
    Ok(())
}

fn target_probe_failure() -> NativeImportError {
    NativeImportError::Verification("Codex target default is unavailable".into())
}

fn map_target_probe_error(error: NativeImportError) -> NativeImportError {
    match error {
        NativeImportError::Timeout | NativeImportError::MutationOutcomeUnknown => error,
        _ => target_probe_failure(),
    }
}

fn validated_label(value: &Value, kind: &str) -> Result<String, NativeImportError> {
    let label = value.as_str().map(str::trim).unwrap_or_default();
    if label.is_empty()
        || label.len() > 128
        || !label.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(NativeImportError::Verification(format!(
            "Codex target {kind} label is invalid"
        )));
    }
    Ok(label.to_owned())
}

fn existing_target_rollout(
    thread: &Value,
    codex_home: &Path,
    expected: &CodexTargetSessionExpectation,
) -> Result<PathBuf, NativeImportError> {
    if thread.get("modelProvider").and_then(Value::as_str) != Some(expected.model_provider.as_str())
    {
        return Err(NativeImportError::Verification(
            "mapped target provider does not match".into(),
        ));
    }
    if thread.get("cwd").and_then(Value::as_str) != Some(expected.cwd.as_str()) {
        return Err(NativeImportError::Verification(
            "mapped target cwd does not match".into(),
        ));
    }
    if let Some(title) = &expected.title
        && thread.get("name").and_then(Value::as_str) != Some(title.as_str())
    {
        return Err(NativeImportError::Verification(
            "mapped target title does not match".into(),
        ));
    }
    let path = thread
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| !path.trim().is_empty())
        .ok_or_else(|| NativeImportError::Verification("mapped target path is missing".into()))?;
    verified_session_rollout_path(codex_home, Path::new(path))
}

fn find_thread_in_listing<T: JsonRpcTransport>(
    client: &mut NativeAppServerClient<'_, T>,
    archived: bool,
    thread_id: &str,
) -> Result<Option<Value>, NativeImportError> {
    const MAX_LIST_PAGES: usize = 10_000;
    let mut cursor = None::<String>;
    let mut seen_cursors = HashSet::new();
    for _ in 0..MAX_LIST_PAGES {
        let listed = client.request(
            "thread/list",
            continuation_list_params(archived, cursor.as_deref()),
        )?;
        let threads = listed
            .value
            .pointer("/result/data")
            .and_then(Value::as_array)
            .ok_or_else(|| NativeImportError::Verification("thread/list data is missing".into()))?;
        if let Some(thread) = threads
            .iter()
            .find(|thread| thread.get("id").and_then(Value::as_str) == Some(thread_id))
        {
            return Ok(Some(thread.clone()));
        }
        let next_cursor = match listed.value.pointer("/result/nextCursor") {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::String(cursor)) if !cursor.trim().is_empty() => cursor.clone(),
            Some(_) => {
                return Err(NativeImportError::Verification(
                    "thread/list cursor is malformed".into(),
                ));
            }
        };
        if !seen_cursors.insert(next_cursor.clone()) {
            return Err(NativeImportError::Verification(
                "thread/list cursor repeated".into(),
            ));
        }
        cursor = Some(next_cursor);
    }
    Err(NativeImportError::Verification(
        "thread/list pagination limit exceeded".into(),
    ))
}

fn verify_target_thread_read(
    thread: &Value,
    expected: &CodexTargetSessionExpectation,
) -> Result<(), NativeImportError> {
    if thread.get("id").and_then(Value::as_str) != Some(expected.thread_id.as_str())
        || thread.get("cwd").and_then(Value::as_str) != Some(expected.cwd.as_str())
        || thread.get("modelProvider").and_then(Value::as_str)
            != Some(expected.model_provider.as_str())
    {
        return Err(NativeImportError::Verification(
            "mapped target identity does not match".into(),
        ));
    }
    if let Some(title) = &expected.title
        && thread.get("name").and_then(Value::as_str) != Some(title.as_str())
    {
        return Err(NativeImportError::Verification(
            "mapped target title does not match".into(),
        ));
    }
    let turns = thread
        .get("turns")
        .and_then(Value::as_array)
        .ok_or_else(|| NativeImportError::Verification("mapped target turns are missing".into()))?;
    let mut messages = Vec::new();
    for turn in turns {
        let items = turn.get("items").and_then(Value::as_array).ok_or_else(|| {
            NativeImportError::Verification("mapped target items are missing".into())
        })?;
        for item in items {
            let role = match item.get("type").and_then(Value::as_str) {
                Some("userMessage") => CodexVisibleRole::User,
                Some("agentMessage") => CodexVisibleRole::Assistant,
                _ => continue,
            };
            let text = app_server_message_text(item, role).ok_or_else(|| {
                NativeImportError::Verification("mapped target visible message is invalid".into())
            })?;
            messages.push(CodexVisibleMessage { role, text });
        }
    }
    let actual = crate::native_payload::visible_history_from_messages(messages)
        .map_err(|_| NativeImportError::Verification("mapped target history is invalid".into()))?;
    if actual.message_count != expected.visible_history.message_count {
        return Err(NativeImportError::Verification(format!(
            "mapped target visible history count does not match (expected {}, actual {})",
            expected.visible_history.message_count, actual.message_count
        )));
    }
    if actual.content_hash != expected.visible_history.content_hash {
        return Err(NativeImportError::Verification(
            "mapped target visible history content does not match".into(),
        ));
    }
    Ok(())
}

fn app_server_message_text(item: &Value, role: CodexVisibleRole) -> Option<String> {
    if let Some(text) = item.get("text").and_then(Value::as_str) {
        return Some(text.to_owned());
    }
    let allowed = match role {
        CodexVisibleRole::User => ["input_text", "text"],
        CodexVisibleRole::Assistant => ["output_text", "text"],
    };
    let parts = item.get("content")?.as_array()?;
    let mut text = String::new();
    for part in parts {
        let part_type = part.get("type").and_then(Value::as_str)?;
        if !allowed.contains(&part_type) {
            continue;
        }
        text.push_str(part.get("text").and_then(Value::as_str)?);
    }
    Some(text)
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

fn continuation_list_params(archived: bool, cursor: Option<&str>) -> Value {
    let mut params = json!({
        "archived": archived,
        "sourceKinds": ["cli", "vscode", "exec", "appServer", "subAgent", "subAgentReview", "subAgentCompact", "subAgentThreadSpawn", "subAgentOther", "unknown"],
        "limit": 1000
    });
    if let Some(cursor) = cursor {
        params["cursor"] = Value::String(cursor.to_owned());
    }
    params
}

fn verify_thread_read(
    response: &Value,
    expected: &NativeThreadExpectation,
) -> Result<(), NativeImportError> {
    let thread = response
        .pointer("/result/thread")
        .ok_or_else(|| NativeImportError::Verification("thread/read returned no thread".into()))?;
    verify_target_thread_read(
        thread,
        &CodexTargetSessionExpectation {
            thread_id: expected.thread_id.clone(),
            cwd: expected.cwd.clone(),
            title: expected.title.clone(),
            model_provider: expected.model_provider.clone(),
            rollout_hash: expected.rollout_hash.clone(),
            visible_history: expected.visible_history.clone(),
        },
    )
}

struct NativeAppServerClient<'a, T: JsonRpcTransport> {
    transport: &'a mut T,
    next_id: u64,
    request_timeout: Duration,
}

impl<'a, T: JsonRpcTransport> NativeAppServerClient<'a, T> {
    fn new(transport: &'a mut T) -> Self {
        Self {
            transport,
            next_id: 1,
            request_timeout: APP_SERVER_REQUEST_TIMEOUT,
        }
    }

    fn initialize(&mut self) -> Result<(), NativeImportError> {
        self.request(
            "initialize",
            json!({
                "clientInfo": {"name": "agentark-native-import", "title": "AgentArk", "version": AGENTARK_APP_SERVER_CLIENT_VERSION},
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
        let deadline = Instant::now() + self.request_timeout;
        self.transport
            .send_value(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .map_err(map_codex_error)?;
        let response = receive_response_until(self.transport, id, deadline)
            .map_err(|error| map_request_error(method, error))?;
        if let Some(error) = response.value.get("error") {
            return Err(NativeImportError::Verification(
                error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("Codex App Server request failed")
                    .to_owned(),
            ));
        }
        Ok(response)
    }
}

fn map_codex_error(error: CodexError) -> NativeImportError {
    match error {
        CodexError::AppServerRequestTimeout => NativeImportError::Timeout,
        error => NativeImportError::Verification(error.to_string()),
    }
}

fn map_request_error(method: &str, error: CodexError) -> NativeImportError {
    if matches!(error, CodexError::AppServerRequestTimeout)
        && matches!(
            method,
            "thread/fork" | "thread/name/set" | "thread/resume" | "thread/delete"
        )
    {
        NativeImportError::MutationOutcomeUnknown
    } else {
        map_codex_error(error)
    }
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
    verify_native_thread_listing(thread, expected)
}

fn verify_native_thread_listing(
    thread: &Value,
    expected: &NativeThreadExpectation,
) -> Result<(), NativeImportError> {
    if thread.get("cwd").and_then(Value::as_str) != Some(expected.cwd.as_str()) {
        return Err(NativeImportError::Verification(
            "imported thread cwd does not match".into(),
        ));
    }
    if thread.get("modelProvider").and_then(Value::as_str) != Some(expected.model_provider.as_str())
    {
        return Err(NativeImportError::Verification(
            "imported thread provider does not match".into(),
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
    write_rollout_atomic_guarded(path, lines, &|| Ok(()))
}

pub fn write_rollout_atomic_guarded<G>(
    path: &Path,
    lines: &[Vec<u8>],
    guard: &G,
) -> Result<Sha256Digest, NativeImportError>
where
    G: Fn() -> Result<(), NativeImportError> + ?Sized,
{
    write_rollout_atomic_with_guarded_operations(
        path,
        lines,
        guard,
        |source, target| fs::rename(source, target),
        |committed| fs::read(committed),
        |cleanup| fs::remove_file(cleanup),
    )
}

/// Reader-injected form of [`write_rollout_atomic`] for post-rename failure tests.
#[doc(hidden)]
pub fn write_rollout_atomic_with_reader<F>(
    path: &Path,
    lines: &[Vec<u8>],
    read_committed: F,
) -> Result<Sha256Digest, NativeImportError>
where
    F: FnOnce(&Path) -> io::Result<Vec<u8>>,
{
    write_rollout_atomic_with_operations(path, lines, read_committed, |cleanup| {
        fs::remove_file(cleanup)
    })
}

/// Operation-injected form of [`write_rollout_atomic`] for cleanup failure tests.
#[doc(hidden)]
pub fn write_rollout_atomic_with_operations<F, R>(
    path: &Path,
    lines: &[Vec<u8>],
    read_committed: F,
    remove: R,
) -> Result<Sha256Digest, NativeImportError>
where
    F: FnOnce(&Path) -> io::Result<Vec<u8>>,
    R: Fn(&Path) -> io::Result<()>,
{
    write_rollout_atomic_with_guarded_operations(
        path,
        lines,
        || Ok(()),
        |source, target| fs::rename(source, target),
        read_committed,
        remove,
    )
}

/// Guard- and operation-injected form of [`write_rollout_atomic`].
#[doc(hidden)]
pub fn write_rollout_atomic_with_guarded_operations<G, N, F, R>(
    path: &Path,
    lines: &[Vec<u8>],
    guard: G,
    rename: N,
    read_committed: F,
    remove: R,
) -> Result<Sha256Digest, NativeImportError>
where
    G: Fn() -> Result<(), NativeImportError>,
    N: FnOnce(&Path, &Path) -> io::Result<()>,
    F: FnOnce(&Path) -> io::Result<Vec<u8>>,
    R: Fn(&Path) -> io::Result<()>,
{
    let parent = path
        .parent()
        .ok_or_else(|| NativeImportError::Invalid("rollout has no parent".into()))?;
    guard()?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("rollout"),
        Uuid::new_v4()
    ));
    let mut temporary_created = false;
    let mut renamed = false;
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        temporary_created = true;
        for line in lines {
            file.write_all(line)?;
        }
        file.sync_all()?;
        drop(file);
        guard()?;
        rename(&temporary, path)?;
        renamed = true;
        let bytes = read_committed(path)?;
        Ok(Sha256Digest::from_bytes(&bytes))
    })();
    if result.is_err() {
        let cleanup_path = if renamed {
            Some(path)
        } else if temporary_created {
            Some(temporary.as_path())
        } else {
            None
        };
        if let Some(cleanup_path) = cleanup_path {
            if guard().is_err() {
                return Err(NativeImportError::ManualIntervention);
            }
            if let Err(error) = remove(cleanup_path)
                && error.kind() != io::ErrorKind::NotFound
            {
                return Err(NativeImportError::ManualIntervention);
            }
        }
    }
    result
}
