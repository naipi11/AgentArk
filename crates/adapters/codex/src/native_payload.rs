use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

use agentark_canonical::{
    CanonicalRole, CanonicalSession, ContentPartKind, Sha256Digest, canonical_hash,
};
use agentark_security::{
    AuthorizedRoot, SecretScanner, open_child_directory_nofollow, open_directory_nofollow,
};
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use serde::Serialize;
use serde_json::{Value, json};
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
    #[error("canonical visible history contains an unsupported message role")]
    UnsupportedVisibleRole,
    #[error("canonical continuation metadata is invalid")]
    InvalidMetadata,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CodexVisibleRole {
    User,
    Assistant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CodexVisibleMessage {
    pub role: CodexVisibleRole,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexVisibleHistory {
    pub messages: Vec<CodexVisibleMessage>,
    pub message_count: usize,
    pub content_hash: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexVisibleHistoryExpectation {
    pub message_count: usize,
    pub content_hash: Sha256Digest,
}

impl CodexVisibleHistory {
    pub fn expectation(&self) -> CodexVisibleHistoryExpectation {
        CodexVisibleHistoryExpectation {
            message_count: self.message_count,
            content_hash: self.content_hash.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalContinuationSource {
    pub thread_id: String,
    pub bytes: Vec<u8>,
    pub title: Option<String>,
    pub visible_history: CodexVisibleHistory,
}

pub fn canonical_visible_history(
    session: &CanonicalSession,
) -> Result<CodexVisibleHistory, NativePayloadError> {
    let mut ordered = session.messages.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|message| message.ordinal);
    let mut messages = Vec::new();
    for message in ordered {
        let text = message
            .content
            .iter()
            .filter(|part| part.kind == ContentPartKind::Text)
            .filter_map(|part| part.text.as_deref())
            .collect::<Vec<_>>()
            .join("");
        if text.is_empty() {
            continue;
        }
        let role = match message.role {
            CanonicalRole::User => CodexVisibleRole::User,
            CanonicalRole::Assistant => CodexVisibleRole::Assistant,
            CanonicalRole::System | CanonicalRole::Tool | CanonicalRole::Unknown => {
                return Err(NativePayloadError::UnsupportedVisibleRole);
            }
        };
        messages.push(CodexVisibleMessage { role, text });
    }
    visible_history_from_messages(messages)
}

pub(crate) fn visible_history_from_messages(
    messages: Vec<CodexVisibleMessage>,
) -> Result<CodexVisibleHistory, NativePayloadError> {
    let content_hash = canonical_hash("codex-visible-history", &messages)
        .map_err(|_| NativePayloadError::InvalidMetadata)?;
    Ok(CodexVisibleHistory {
        message_count: messages.len(),
        messages,
        content_hash,
    })
}

pub fn build_canonical_continuation_source(
    session: &CanonicalSession,
    target_cwd: &Path,
    target_provider: &str,
    target_model: &str,
) -> Result<CanonicalContinuationSource, NativePayloadError> {
    if target_cwd.as_os_str().is_empty()
        || !valid_safe_label(target_provider)
        || !valid_safe_label(target_model)
    {
        return Err(NativePayloadError::InvalidMetadata);
    }
    let visible_history = canonical_visible_history(session)?;
    let source_identity = json!({
        "canonicalSessionId": session.id,
        "cwd": target_cwd.to_string_lossy(),
        "provider": target_provider,
        "model": target_model,
        "visibleHistoryHash": visible_history.content_hash,
    });
    let identity_hash = canonical_hash("codex-continuation-source-id", &source_identity)
        .map_err(|_| NativePayloadError::InvalidMetadata)?;
    let thread_id = Uuid::new_v5(&session.id, identity_hash.as_str().as_bytes()).to_string();
    let timestamp = "1970-01-01T00:00:00.000Z";
    let mut records = Vec::with_capacity(visible_history.message_count * 2 + 1);
    records.push(json!({
        "timestamp": timestamp,
        "type": "session_meta",
        "payload": {
            "id": thread_id,
            "timestamp": timestamp,
            "cwd": target_cwd.to_string_lossy(),
            "originator": "codex_cli_rs",
            "cli_version": crate::CODEX_VERSION,
            "source": "cli",
            "model_provider": target_provider,
            "model": target_model,
            "agentark": {
                "canonical_session_id": session.id,
                "source_agent": "codex",
                "title": session.title,
                "visible_history_hash": visible_history.content_hash,
                "visible_message_count": visible_history.message_count,
            }
        }
    }));
    for message in &visible_history.messages {
        let (role, part_type) = match message.role {
            CodexVisibleRole::User => ("user", "input_text"),
            CodexVisibleRole::Assistant => ("assistant", "output_text"),
        };
        records.push(json!({
            "timestamp": timestamp,
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": role,
                "content": [{"type": part_type, "text": message.text}],
            }
        }));
        let event_payload = match message.role {
            CodexVisibleRole::User => json!({
                "type": "user_message",
                "message": message.text,
                "kind": "plain",
            }),
            CodexVisibleRole::Assistant => json!({
                "type": "agent_message",
                "message": message.text,
                "phase": null,
                "memory_citation": null,
            }),
        };
        records.push(json!({
            "timestamp": timestamp,
            "type": "event_msg",
            "payload": event_payload,
        }));
    }
    let mut bytes = Vec::new();
    for record in records {
        bytes.extend_from_slice(&serde_json::to_vec(&record)?);
        bytes.push(b'\n');
    }
    Ok(CanonicalContinuationSource {
        thread_id,
        bytes,
        title: session.title.clone(),
        visible_history,
    })
}

fn valid_safe_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
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
    let authorized =
        AuthorizedRoot::new(sessions_root.clone()).map_err(|_| NativePayloadError::InvalidPath)?;
    let mut files = Vec::new();
    collect_files(&sessions_root, &mut files)?;
    let mut payloads = Vec::new();
    for session in sessions {
        let mut matched = None;
        for path in &files {
            let Some(name) = path.file_name().map(|name| name.to_string_lossy()) else {
                continue;
            };
            if !name.starts_with("rollout-") || !name.ends_with(".jsonl") {
                continue;
            }
            let relative = path
                .strip_prefix(&sessions_root)
                .map_err(|_| NativePayloadError::InvalidPath)?;
            let bytes = read_authorized_native_file(&authorized, relative)?;
            let matches_id = name.contains(&session.source_session_id)
                || bytes.split(|byte| *byte == b'\n').any(|line| {
                    serde_json::from_slice::<Value>(line)
                        .ok()
                        .and_then(|value| {
                            value
                                .pointer("/payload/id")
                                .or_else(|| value.pointer("/payload/session_id"))
                                .and_then(Value::as_str)
                                .map(|id| id == session.source_session_id)
                        })
                        .unwrap_or(false)
                });
            if matches_id {
                matched = Some((path.clone(), bytes));
                break;
            }
        }
        let Some((path, bytes)) = matched else {
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

fn read_authorized_native_file(
    authorized: &AuthorizedRoot,
    relative: &Path,
) -> Result<Vec<u8>, NativePayloadError> {
    let mut file = authorized
        .open_regular_file(relative)
        .map_err(|_| NativePayloadError::InvalidPath)?;
    if has_multiple_hard_links(&file)? {
        return Err(NativePayloadError::InvalidPath);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
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
    let mut title = None;
    let mut model_provider = None;
    let mut messages = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_slice(line)?;
        if value.get("type").and_then(Value::as_str) == Some("session_meta") {
            thread_id = value
                .pointer("/payload/id")
                .or_else(|| value.pointer("/payload/session_id"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            cwd = value
                .pointer("/payload/cwd")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            title = value
                .pointer("/payload/agentark/title")
                .or_else(|| value.pointer("/payload/title"))
                .and_then(Value::as_str)
                .filter(|title| !title.trim().is_empty())
                .map(ToOwned::to_owned);
            model_provider = value
                .pointer("/payload/model_provider")
                .and_then(Value::as_str)
                .filter(|provider| valid_safe_label(provider))
                .map(ToOwned::to_owned);
        } else if value.get("type").and_then(Value::as_str) == Some("response_item")
            && let Some(message) = native_visible_message(&value)?
        {
            messages.push(message);
        }
    }
    let thread_id = thread_id.ok_or(NativePayloadError::InvalidPath)?;
    let cwd = cwd.ok_or(NativePayloadError::InvalidPath)?;
    let model_provider = model_provider.ok_or(NativePayloadError::InvalidMetadata)?;
    let visible_history = visible_history_from_messages(messages)?.expectation();
    Ok(crate::NativeThreadExpectation {
        thread_id,
        cwd,
        title,
        model_provider,
        rollout_hash: Sha256Digest::from_bytes(bytes),
        visible_history,
    })
}

fn native_visible_message(
    value: &Value,
) -> Result<Option<CodexVisibleMessage>, NativePayloadError> {
    let payload = value
        .get("payload")
        .filter(|payload| payload.get("type").and_then(Value::as_str) == Some("message"));
    let Some(payload) = payload else {
        return Ok(None);
    };
    let role = match payload.get("role").and_then(Value::as_str) {
        Some("user") => CodexVisibleRole::User,
        Some("assistant") => CodexVisibleRole::Assistant,
        _ => return Ok(None),
    };
    let allowed = match role {
        CodexVisibleRole::User => ["input_text", "text"],
        CodexVisibleRole::Assistant => ["output_text", "text"],
    };
    let parts = payload
        .get("content")
        .and_then(Value::as_array)
        .ok_or(NativePayloadError::InvalidMetadata)?;
    let mut text = String::new();
    for part in parts {
        let part_type = part
            .get("type")
            .and_then(Value::as_str)
            .ok_or(NativePayloadError::InvalidMetadata)?;
        if allowed.contains(&part_type) {
            text.push_str(
                part.get("text")
                    .and_then(Value::as_str)
                    .ok_or(NativePayloadError::InvalidMetadata)?,
            );
        }
    }
    Ok(Some(CodexVisibleMessage { role, text }))
}

pub fn restore_native_rollouts(
    codex_home: &Path,
    payloads: &[NativeRolloutPayload],
    workspace_mappings: &[(String, String)],
    backup_root: &Path,
) -> Result<NativeRestoreReport, NativePayloadError> {
    restore_native_rollouts_guarded(
        codex_home,
        payloads,
        workspace_mappings,
        backup_root,
        &|| Ok(()),
    )
}

pub fn restore_native_rollouts_guarded<G>(
    codex_home: &Path,
    payloads: &[NativeRolloutPayload],
    workspace_mappings: &[(String, String)],
    backup_root: &Path,
    guard: &G,
) -> Result<NativeRestoreReport, NativePayloadError>
where
    G: Fn() -> Result<(), crate::NativeImportError> + ?Sized,
{
    let mut planned = Vec::new();
    let mut skipped_count = 0u64;
    for payload in payloads {
        let destination = safe_native_destination(codex_home, &payload.relative_path, false)?;
        let bytes = rewrite_native_workspace_paths(&payload.bytes, workspace_mappings)?;
        if let Ok(metadata) = fs::symlink_metadata(&destination) {
            if is_link_or_reparse_point(&metadata) || !metadata.is_file() {
                return Err(NativePayloadError::InvalidPath);
            }
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
    guard()?;
    let backup_path = Some(crate::backup_codex_targets(
        codex_home,
        backup_root,
        &planned_paths,
    )?);
    let mut written = Vec::new();
    let mut mappings = Vec::new();
    let result = (|| {
        for (payload, destination, bytes) in planned {
            let prepared = safe_native_destination(codex_home, &payload.relative_path, true)?;
            if prepared != destination || prepared.exists() {
                return Err(NativePayloadError::Conflict);
            }
            write_native_rollout_atomic_guarded(codex_home, &payload.relative_path, &bytes, guard)?;
            written.push(destination.clone());
            let thread_id = extract_thread_id(&bytes)?;
            mappings.push((payload.session_id.to_string(), thread_id));
        }
        Ok::<(), NativePayloadError>(())
    })();
    if let Err(error) = result {
        let mut cleanup_failed = false;
        let sessions_root = codex_home.join("sessions");
        for path in &written {
            if guard().is_err() {
                cleanup_failed = true;
                continue;
            }
            let safe_path = path
                .strip_prefix(&sessions_root)
                .ok()
                .and_then(|relative| relative.to_str())
                .and_then(|relative| safe_native_destination(codex_home, relative, false).ok());
            if safe_path.as_deref() != Some(path.as_path()) {
                cleanup_failed = true;
                continue;
            }
            let relative = path
                .strip_prefix(&sessions_root)
                .ok()
                .and_then(|relative| relative.to_str());
            let remove_result = relative
                .ok_or(NativePayloadError::InvalidPath)
                .and_then(|relative| remove_native_rollout(codex_home, relative));
            if let Err(remove_error) = remove_result
                && !matches!(
                    remove_error,
                    NativePayloadError::Io(ref error)
                        if error.kind() == std::io::ErrorKind::NotFound
                )
            {
                cleanup_failed = true;
            }
        }
        if cleanup_failed {
            return Err(NativePayloadError::NativeImport(
                crate::NativeImportError::ManualIntervention,
            ));
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

fn native_sessions_dir(codex_home: &Path) -> Result<Dir, NativePayloadError> {
    let sessions_root = codex_home.join("sessions");
    open_directory_nofollow(&sessions_root).map_err(|_| NativePayloadError::InvalidPath)
}

fn write_native_rollout_atomic_guarded<G>(
    codex_home: &Path,
    relative: &str,
    bytes: &[u8],
    guard: &G,
) -> Result<Sha256Digest, NativePayloadError>
where
    G: Fn() -> Result<(), crate::NativeImportError> + ?Sized,
{
    let dir = native_sessions_dir(codex_home)?;
    let relative_path = Path::new(relative);
    let parent = relative_path.parent().unwrap_or_else(|| Path::new(""));
    let filename = relative_path
        .file_name()
        .ok_or(NativePayloadError::InvalidPath)?;
    guard()?;
    let parent_dir = open_or_create_native_directory(&dir, parent)?;
    let temporary = PathBuf::from(format!(
        ".{}.{}.tmp",
        filename.to_str().ok_or(NativePayloadError::InvalidPath)?,
        Uuid::new_v4()
    ));
    let mut temporary_created = false;
    let mut renamed = false;
    let result = (|| {
        let mut options = CapOpenOptions::new();
        options.create_new(true).write(true);
        let mut file = parent_dir.open_with(&temporary, &options)?;
        temporary_created = true;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        guard()?;
        parent_dir.rename(&temporary, &parent_dir, filename)?;
        renamed = true;
        let mut committed = parent_dir.open(filename)?;
        let mut committed_bytes = Vec::new();
        committed.read_to_end(&mut committed_bytes)?;
        Ok(Sha256Digest::from_bytes(&committed_bytes))
    })();
    if result.is_err() {
        let cleanup_path = if renamed {
            Some(Path::new(filename))
        } else if temporary_created {
            Some(temporary.as_path())
        } else {
            None
        };
        if let Some(cleanup_path) = cleanup_path {
            if guard().is_err() {
                return Err(NativePayloadError::NativeImport(
                    crate::NativeImportError::ManualIntervention,
                ));
            }
            if let Err(error) = parent_dir.remove_file(cleanup_path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(NativePayloadError::NativeImport(
                    crate::NativeImportError::ManualIntervention,
                ));
            }
        }
    }
    result
}

fn remove_native_rollout(codex_home: &Path, relative: &str) -> Result<(), NativePayloadError> {
    let sessions_dir = native_sessions_dir(codex_home)?;
    let relative_path = Path::new(relative);
    let parent = relative_path.parent().unwrap_or_else(|| Path::new(""));
    let filename = relative_path
        .file_name()
        .ok_or(NativePayloadError::InvalidPath)?;
    open_existing_native_directory(&sessions_dir, parent)?
        .remove_file(filename)
        .map_err(NativePayloadError::from)
}

fn open_or_create_native_directory(dir: &Dir, relative: &Path) -> Result<Dir, NativePayloadError> {
    let mut current = dir.try_clone()?;
    for component in relative.components() {
        let std::path::Component::Normal(value) = component else {
            return Err(NativePayloadError::InvalidPath);
        };
        let child = Path::new(value);
        match current.symlink_metadata(child) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(NativePayloadError::InvalidPath),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match current.create_dir(child) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
        current = open_child_directory_nofollow(&current, child)
            .map_err(|_| NativePayloadError::InvalidPath)?;
    }
    Ok(current)
}

fn open_existing_native_directory(dir: &Dir, relative: &Path) -> Result<Dir, NativePayloadError> {
    let mut current = dir.try_clone()?;
    for component in relative.components() {
        let std::path::Component::Normal(value) = component else {
            return Err(NativePayloadError::InvalidPath);
        };
        current = open_child_directory_nofollow(&current, Path::new(value))
            .map_err(|_| NativePayloadError::InvalidPath)?;
    }
    Ok(current)
}

fn collect_files(root: &Path, output: &mut Vec<PathBuf>) -> Result<(), NativePayloadError> {
    let root_metadata = fs::symlink_metadata(root)?;
    if is_link_or_reparse_point(&root_metadata) || !root_metadata.is_dir() {
        return Err(NativePayloadError::InvalidPath);
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if is_link_or_reparse_point(&metadata) {
            return Err(NativePayloadError::InvalidPath);
        }
        if metadata.is_dir() {
            collect_files(&path, output)?;
        } else if metadata.is_file() {
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
            && let Some(id) = value
                .pointer("/payload/id")
                .or_else(|| value.pointer("/payload/session_id"))
                .and_then(Value::as_str)
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

fn safe_native_destination(
    codex_home: &Path,
    relative: &str,
    create_missing_directories: bool,
) -> Result<PathBuf, NativePayloadError> {
    validate_relative_path(relative)?;
    if !ensure_safe_directory(codex_home, create_missing_directories)? {
        return Ok(codex_home.join("sessions").join(relative));
    }

    let mut current = codex_home.to_path_buf();
    let segments = std::iter::once("sessions").chain(
        relative
            .split('/')
            .take(relative.split('/').count().saturating_sub(1)),
    );
    for segment in segments {
        current.push(segment);
        if !ensure_safe_directory(&current, create_missing_directories)? {
            break;
        }
    }

    let destination = codex_home.join("sessions").join(relative);
    if let Ok(metadata) = fs::symlink_metadata(&destination)
        && (is_link_or_reparse_point(&metadata) || !metadata.is_file())
    {
        return Err(NativePayloadError::InvalidPath);
    }
    Ok(destination)
}

fn ensure_safe_directory(path: &Path, create_missing: bool) -> Result<bool, NativePayloadError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if is_link_or_reparse_point(&metadata) || !metadata.is_dir() {
                return Err(NativePayloadError::InvalidPath);
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create_missing => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(NativePayloadError::InvalidPath)?;
            if !ensure_safe_directory(parent, false)? {
                return Err(NativePayloadError::InvalidPath);
            }
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(create_error) if create_error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(create_error) => return Err(create_error.into()),
            }
            ensure_safe_directory(path, false)
        }
        Err(error) => Err(error.into()),
    }
}

fn is_link_or_reparse_point(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        metadata.file_attributes() & 0x0000_0400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn has_multiple_hard_links(file: &cap_std::fs::File) -> Result<bool, NativePayloadError> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        Ok(file.metadata()?.nlink() > 1)
    }
    #[cfg(windows)]
    {
        Ok(winx::winapi_util::file::information(file)?.number_of_links() > 1)
    }
}
