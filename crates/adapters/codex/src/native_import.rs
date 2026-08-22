use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use agentark_canonical::{CanonicalRole, CanonicalSession, Sha256Digest};
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

use crate::CODEX_VERSION;

#[derive(Debug, Error)]
pub enum NativeImportError {
    #[error("native rollout I/O failed")]
    Io(#[from] io::Error),
    #[error("native rollout JSON failed")]
    Json(#[from] serde_json::Error),
    #[error("native rollout is invalid: {0}")]
    Invalid(String),
}

/// Builds the visible Codex rollout records for one canonical session.
///
/// This intentionally emits only user-visible user/assistant messages. Tool
/// internals, hidden reasoning, credentials, and attachments are not copied
/// into the vendor-native file.
pub fn build_rollout_lines(
    session: &CanonicalSession,
    target_thread_id: &str,
    cwd: &Path,
) -> Result<Vec<Vec<u8>>, NativeImportError> {
    if target_thread_id.trim().is_empty() {
        return Err(NativeImportError::Invalid("thread id is empty".into()));
    }
    if !cwd.is_absolute() {
        return Err(NativeImportError::Invalid("cwd must be absolute".into()));
    }
    let timestamp = session
        .created_at_raw
        .as_deref()
        .unwrap_or("1970-01-01T00:00:00.000Z");
    let turn_id = format!("agentark-import-{target_thread_id}");
    let now_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default();
    let cwd_text = cwd.to_string_lossy().into_owned();
    let model = session.model_name.as_deref().unwrap_or("gpt-5.6-sol");
    let mut records = Vec::new();
    push_record(
        &mut records,
        json!({
            "type": "session_meta",
            "payload": {
                "session_id": target_thread_id,
                "id": target_thread_id,
                "timestamp": timestamp,
                "cwd": cwd_text,
                "originator": "Codex Desktop",
                "cli_version": CODEX_VERSION,
                "source": "vscode",
                "thread_source": "user",
                "agent_nickname": null,
                "agent_path": null,
                "model_provider": session.model_provider.as_deref().unwrap_or("openai"),
                "base_instructions": null,
                "history_mode": "legacy",
                "multi_agent_version": "v2",
                "context_window": null,
                "git": null
            }
        }),
    )?;
    push_record(
        &mut records,
        json!({
            "type": "event_msg",
            "payload": {
                "type": "task_started",
                "turn_id": turn_id,
                "started_at": now_seconds,
                "model_context_window": null
            }
        }),
    )?;
    push_record(
        &mut records,
        json!({
            "type": "turn_context",
            "payload": {
                "turn_id": turn_id,
                "cwd": cwd_text,
                "workspace_roots": [cwd_text],
                "current_date": timestamp.get(..10).unwrap_or(timestamp),
                "timezone": "UTC",
                "approval_policy": "on-request",
                "approvals_reviewer": "user",
                "sandbox_policy": {"type": "read-only"},
                "model": model,
                "summary": null
            }
        }),
    )?;

    let mut visible_messages = 0u64;
    for message in &session.messages {
        let text = message.visible_text();
        if text.trim().is_empty() {
            continue;
        }
        let (role, content_type, event_type) = match message.role {
            CanonicalRole::User => ("user", "input_text", "user_message"),
            CanonicalRole::Assistant => ("assistant", "output_text", "agent_message"),
            _ => continue,
        };
        visible_messages += 1;
        let response_id = format!("msg-{target_thread_id}-{visible_messages}");
        push_record(
            &mut records,
            json!({
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "id": response_id,
                    "role": role,
                    "content": [{"type": content_type, "text": text}],
                    "internal_chat_message_metadata_passthrough": {"turn_id": turn_id}
                }
            }),
        )?;
        let event_payload = if event_type == "user_message" {
            json!({
                "type": event_type,
                "client_id": format!("client-{target_thread_id}-{visible_messages}"),
                "message": text,
                "images": [],
                "local_images": [],
                "audio": [],
                "local_audio": [],
                "text_elements": []
            })
        } else {
            json!({"type": event_type, "message": text})
        };
        push_record(
            &mut records,
            json!({"type": "event_msg", "payload": event_payload}),
        )?;
    }
    push_record(
        &mut records,
        json!({
            "type": "event_msg",
            "payload": {
                "type": "task_complete",
                "turn_id": turn_id,
                "last_agent_message": session
                    .messages
                    .iter()
                    .rev()
                    .find(|message| message.role == CanonicalRole::Assistant)
                    .map(|message| message.visible_text()),
                "started_at": now_seconds,
                "completed_at": now_seconds,
                "duration_ms": 0
            }
        }),
    )?;
    Ok(records)
}

fn push_record(records: &mut Vec<Vec<u8>>, value: Value) -> Result<(), NativeImportError> {
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    records.push(bytes);
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
