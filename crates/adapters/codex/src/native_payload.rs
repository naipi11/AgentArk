use std::fs;
use std::path::{Path, PathBuf};

use agentark_canonical::{CanonicalSession, Sha256Digest};
use agentark_security::SecretScanner;
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum NativePayloadError {
    #[error("native rollout I/O failed")]
    Io(#[from] std::io::Error),
    #[error("native rollout JSON failed")]
    Json(#[from] serde_json::Error),
    #[error("native rollout path is invalid")]
    InvalidPath,
    #[error("native rollout conflicts with an existing target file")]
    Conflict,
    #[error("native rollout import failed")]
    NativeImport(#[from] crate::NativeImportError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeRolloutPayload {
    pub session_id: Uuid,
    pub relative_path: String,
    pub bytes: Vec<u8>,
    pub source_hash: Sha256Digest,
    pub redaction_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeRestoreReport {
    pub imported_count: u64,
    pub skipped_count: u64,
    pub conflict_count: u64,
    pub backup_path: Option<PathBuf>,
    pub mappings: Vec<(String, String)>,
    pub written_paths: Vec<PathBuf>,
    pub restart_required: bool,
}

pub fn collect_native_rollouts(
    codex_home: &Path,
    sessions: &[CanonicalSession],
    scanner: &SecretScanner,
) -> Result<Vec<NativeRolloutPayload>, NativePayloadError> {
    let sessions_root = codex_home.join("sessions");
    if !sessions_root.is_dir() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    collect_files(&sessions_root, &mut files)?;
    let mut payloads = Vec::new();
    for session in sessions {
        let Some((path, bytes)) = files.iter().find_map(|path| {
            let name = path.file_name()?.to_string_lossy();
            if !name.starts_with("rollout-") || !name.ends_with(".jsonl") {
                return None;
            }
            let bytes = fs::read(path).ok()?;
            let matches_id = name.contains(&session.source_session_id)
                || bytes.split(|byte| *byte == b'\n').any(|line| {
                    serde_json::from_slice::<Value>(line)
                        .ok()
                        .and_then(|value| {
                            value
                                .pointer("/payload/session_id")
                                .and_then(Value::as_str)
                                .map(|id| id == session.source_session_id)
                        })
                        .unwrap_or(false)
                });
            matches_id.then_some((path.clone(), bytes))
        }) else {
            continue;
        };
        let relative = path
            .strip_prefix(&sessions_root)
            .map_err(|_| NativePayloadError::InvalidPath)?
            .to_string_lossy()
            .replace('\\', "/");
        let source_hash = Sha256Digest::from_bytes(&bytes);
        let (bytes, redaction_count) = sanitize_rollout_bytes(&bytes, scanner)?;
        payloads.push(NativeRolloutPayload {
            session_id: session.id,
            relative_path: relative,
            bytes,
            source_hash,
            redaction_count,
        });
    }
    Ok(payloads)
}

pub fn sanitize_rollout_bytes(
    bytes: &[u8],
    scanner: &SecretScanner,
) -> Result<(Vec<u8>, u64), NativePayloadError> {
    let mut output = Vec::new();
    let mut redaction_count = 0u64;
    let lines = bytes.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        if line.is_empty() {
            continue;
        }
        let mut value: Value = match serde_json::from_slice(line) {
            Ok(value) => value,
            Err(_) if index + 1 == lines.len() => {
                // Codex can leave a final partial JSONL record while it is
                // writing. Preserve the complete prefix and let the target
                // App Server verify the resulting rollout.
                break;
            }
            Err(error) => return Err(error.into()),
        };
        sanitize_value(&mut value, scanner, &mut redaction_count);
        if value.pointer("/payload/type").and_then(Value::as_str) == Some("reasoning")
            || value.pointer("/payload/type").and_then(Value::as_str) == Some("agent_reasoning")
        {
            continue;
        }
        let mut encoded = serde_json::to_vec(&value)?;
        encoded.push(b'\n');
        output.extend_from_slice(&encoded);
    }
    Ok((output, redaction_count))
}

pub fn rewrite_native_workspace_paths(
    bytes: &[u8],
    mappings: &[(String, String)],
) -> Result<Vec<u8>, NativePayloadError> {
    let mut output = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut value: Value = serde_json::from_slice(line)?;
        rewrite_value(&mut value, mappings);
        let mut encoded = serde_json::to_vec(&value)?;
        encoded.push(b'\n');
        output.extend_from_slice(&encoded);
    }
    Ok(output)
}

pub fn native_thread_expectation(
    bytes: &[u8],
) -> Result<crate::NativeThreadExpectation, NativePayloadError> {
    let mut thread_id = None;
    let mut cwd = None;
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_slice(line)?;
        if value.get("type").and_then(Value::as_str) == Some("session_meta") {
            thread_id = value
                .pointer("/payload/session_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            cwd = value
                .pointer("/payload/cwd")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
        }
    }
    let thread_id = thread_id.ok_or(NativePayloadError::InvalidPath)?;
    let cwd = cwd.ok_or(NativePayloadError::InvalidPath)?;
    Ok(crate::NativeThreadExpectation {
        thread_id,
        cwd,
        title: None,
        visible_text_hash: Sha256Digest::from_bytes(b""),
        visible_turns: 1,
    })
}

pub fn restore_native_rollouts(
    codex_home: &Path,
    payloads: &[NativeRolloutPayload],
    workspace_mappings: &[(String, String)],
    backup_root: &Path,
) -> Result<NativeRestoreReport, NativePayloadError> {
    let mut planned = Vec::new();
    let mut skipped_count = 0u64;
    for payload in payloads {
        validate_relative_path(&payload.relative_path)?;
        let destination = codex_home.join("sessions").join(&payload.relative_path);
        let bytes = rewrite_native_workspace_paths(&payload.bytes, workspace_mappings)?;
        if destination.is_file() {
            if fs::read(&destination)? == bytes {
                skipped_count += 1;
                continue;
            }
            return Err(NativePayloadError::Conflict);
        }
        if let Some((_, _, planned_bytes)) = planned
            .iter()
            .find(|(_, planned_destination, _)| planned_destination == &destination)
        {
            if planned_bytes == &bytes {
                skipped_count += 1;
                continue;
            }
            return Err(NativePayloadError::Conflict);
        }
        planned.push((payload, destination, bytes));
    }
    let planned_paths = planned
        .iter()
        .map(|(_, destination, _)| destination.clone())
        .collect::<Vec<_>>();
    let backup_path = Some(crate::backup_codex_targets(
        codex_home,
        backup_root,
        &planned_paths,
    )?);
    let mut written = Vec::new();
    let mut mappings = Vec::new();
    let result = (|| {
        for (payload, destination, bytes) in planned {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            crate::write_rollout_atomic(&destination, std::slice::from_ref(&bytes))?;
            let thread_id = extract_thread_id(&bytes)?;
            mappings.push((payload.session_id.to_string(), thread_id));
            written.push(destination);
        }
        Ok::<(), NativePayloadError>(())
    })();
    if let Err(error) = result {
        for path in written {
            let _ = fs::remove_file(path);
        }
        return Err(error);
    }
    let imported_count = mappings.len() as u64;
    Ok(NativeRestoreReport {
        imported_count,
        skipped_count,
        conflict_count: 0,
        backup_path,
        mappings,
        written_paths: written,
        restart_required: imported_count > 0,
    })
}

fn collect_files(root: &Path, output: &mut Vec<PathBuf>) -> Result<(), NativePayloadError> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, output)?;
        } else if path.is_file() {
            output.push(path);
        }
    }
    Ok(())
}

fn sanitize_value(value: &mut Value, scanner: &SecretScanner, redaction_count: &mut u64) {
    match value {
        Value::String(text) => {
            let sanitized = scanner.sanitize(text);
            *redaction_count += sanitized.findings.len() as u64;
            *text = sanitized.text;
        }
        Value::Array(values) => {
            for value in values {
                sanitize_value(value, scanner, redaction_count);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                sanitize_value(value, scanner, redaction_count);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn rewrite_value(value: &mut Value, mappings: &[(String, String)]) {
    match value {
        Value::Array(values) => {
            for value in values {
                rewrite_value(value, mappings);
            }
        }
        Value::Object(values) => {
            for (key, value) in values.iter_mut() {
                if key == "cwd" || key == "workspace_roots" {
                    rewrite_path_value(value, mappings);
                } else {
                    rewrite_value(value, mappings);
                }
            }
        }
        Value::String(_) | Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn rewrite_path_value(value: &mut Value, mappings: &[(String, String)]) {
    match value {
        Value::String(text) => replace_path(text, mappings),
        Value::Array(values) => {
            for value in values {
                if let Value::String(text) = value {
                    replace_path(text, mappings);
                }
            }
        }
        _ => {}
    }
}

fn replace_path(text: &mut String, mappings: &[(String, String)]) {
    for (source, target) in mappings {
        if text == source {
            *text = target.clone();
            return;
        }
    }
}

fn extract_thread_id(bytes: &[u8]) -> Result<String, NativePayloadError> {
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_slice(line)?;
        if value.get("type").and_then(Value::as_str) == Some("session_meta")
            && let Some(id) = value.pointer("/payload/session_id").and_then(Value::as_str)
        {
            return Ok(id.to_owned());
        }
    }
    Err(NativePayloadError::InvalidPath)
}

fn validate_relative_path(relative: &str) -> Result<(), NativePayloadError> {
    if relative.is_empty()
        || relative.contains('\\')
        || relative.contains('\0')
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || Path::new(relative).is_absolute()
    {
        return Err(NativePayloadError::InvalidPath);
    }
    Ok(())
}
