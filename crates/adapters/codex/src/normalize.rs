use std::collections::BTreeMap;

use agentark_canonical::{
    CanonicalMessage, CanonicalRole, CanonicalSchemaVersion, CanonicalSession, Completeness,
    ContentPart, ContentPartKind, Sha256Digest, ToolEvent, Workspace, message_id, session_id,
    workspace_id,
};
use serde_json::Value;
use uuid::Uuid;

use crate::CodexError;

pub fn normalize_thread_read(text: &str) -> Result<CanonicalSession, CodexError> {
    normalize_thread_read_bytes(text.as_bytes())
}

pub fn normalize_thread_read_bytes(bytes: &[u8]) -> Result<CanonicalSession, CodexError> {
    normalize_thread_read_bytes_for_install(bytes, Uuid::nil())
}

pub fn normalize_thread_read_bytes_for_install(
    bytes: &[u8],
    install_id: Uuid,
) -> Result<CanonicalSession, CodexError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| CodexError::MalformedJson)?;
    let thread = value
        .get("result")
        .and_then(|result| result.get("thread"))
        .or_else(|| value.get("thread"))
        .ok_or(CodexError::InvalidOutput)?;
    let source_session_id = thread
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or(CodexError::InvalidOutput)?
        .to_owned();
    let session = session_id(install_id, &source_session_id);
    let raw_hash = Sha256Digest::from_bytes(bytes);
    let mut messages = Vec::new();
    let mut tool_events = Vec::new();
    let mut ordinal = 0u64;
    let mut partial = false;
    if let Some(turns) = thread.get("turns").and_then(Value::as_array) {
        for turn in turns {
            if let Some(items) = turn.get("items").and_then(Value::as_array) {
                for item in items {
                    let item_type = item.get("type").and_then(Value::as_str).unwrap_or("");
                    match item_type {
                        "userMessage" | "agentMessage" => {
                            let text = item_text(item);
                            if text.is_empty() {
                                partial = true;
                                continue;
                            }
                            ordinal += 1;
                            let role = if item_type == "userMessage" {
                                CanonicalRole::User
                            } else {
                                CanonicalRole::Assistant
                            };
                            messages.push(CanonicalMessage {
                                id: message_id(
                                    session,
                                    Some(&format!("item:{ordinal}")),
                                    ordinal,
                                    &raw_hash,
                                ),
                                source_record_id: Some(format!("item:{ordinal}")),
                                ordinal,
                                role,
                                raw_role: Some(item_type.into()),
                                created_at_raw: item
                                    .get("timestamp")
                                    .and_then(Value::as_str)
                                    .map(ToOwned::to_owned),
                                content: vec![ContentPart {
                                    kind: ContentPartKind::Text,
                                    text: Some(text),
                                    attachment_id: None,
                                    raw_extra: BTreeMap::new(),
                                }],
                                raw_ref: raw_hash.clone(),
                            });
                        }
                        "reasoning" => partial = true,
                        "commandExecution"
                        | "fileChange"
                        | "mcpToolCall"
                        | "dynamicToolCall"
                        | "collabAgentToolCall"
                        | "webSearch" => {
                            ordinal += 1;
                            tool_events
                                .push(tool_event(item, item_type, session, ordinal, &raw_hash));
                        }
                        "imageView" | "imageGeneration" => partial = true,
                        _ => partial = true,
                    }
                }
            }
        }
    } else {
        partial = true;
    }
    let title = thread
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            messages
                .iter()
                .find(|message| message.role == CanonicalRole::User)
                .map(CanonicalMessage::visible_text)
        });
    let workspace = workspace_from_thread(thread);
    Ok(CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id: session,
        install_id,
        source_session_id,
        source_kind: "app-server".into(),
        workspace,
        title,
        archived: false,
        created_at_raw: thread
            .get("createdAt")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        updated_at_raw: thread
            .get("updatedAt")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        model_provider: None,
        model_name: None,
        completeness: if partial {
            Completeness::Partial
        } else {
            Completeness::Complete
        },
        messages,
        tool_events,
        attachments: Vec::new(),
        raw_extra: BTreeMap::new(),
    })
}

fn workspace_from_thread(thread: &Value) -> Option<Workspace> {
    let raw_path = thread
        .get("cwd")
        .and_then(Value::as_str)
        .or_else(|| {
            thread
                .get("workspace")
                .and_then(|workspace| workspace.get("path").or_else(|| workspace.get("cwd")))
                .and_then(Value::as_str)
        })?
        .trim();
    if raw_path.is_empty() {
        return None;
    }
    let path_native = raw_path.strip_prefix("\\\\?\\").unwrap_or(raw_path);
    let canonical_path = std::fs::canonicalize(path_native)
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| path_native.to_owned());
    let canonical_uri = format!("file://{}", canonical_path.replace('\\', "/"));
    let git_commit = thread
        .get("gitInfo")
        .and_then(|git| git.get("sha"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    Some(Workspace {
        id: workspace_id(&canonical_uri),
        path_native: canonical_path,
        canonical_uri,
        git_commit,
    })
}

fn item_text(item: &Value) -> String {
    if let Some(text) = item.get("text").and_then(Value::as_str) {
        return text.to_owned();
    }
    item.get("content")
        .and_then(Value::as_array)
        .map(|parts| {
            parts
                .iter()
                .filter_map(|part| {
                    let kind = part.get("type").and_then(Value::as_str).unwrap_or("");
                    if kind == "input_text" || kind == "output_text" || kind == "text" {
                        part.get("text").and_then(Value::as_str)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default()
}

fn tool_event(
    item: &Value,
    item_type: &str,
    session: Uuid,
    ordinal: u64,
    raw_hash: &Sha256Digest,
) -> ToolEvent {
    let visible_input = if item_type == "collabAgentToolCall" {
        item.get("toolName")
            .or_else(|| item.get("name"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    } else {
        item.get("command")
            .or_else(|| item.get("query"))
            .or_else(|| item.get("name"))
            .or_else(|| item.get("toolName"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    };
    let visible_output = item
        .get("aggregatedOutput")
        .or_else(|| item.get("output"))
        .or_else(|| item.get("result"))
        .and_then(|value| {
            value
                .as_str()
                .or_else(|| value.get("content").and_then(Value::as_str))
        })
        .map(ToOwned::to_owned);
    ToolEvent {
        id: Uuid::new_v5(&session, format!("item:{ordinal}").as_bytes()).to_string(),
        ordinal,
        tool_name: item_type.into(),
        status: item
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .into(),
        visible_input,
        visible_output,
        raw_ref: raw_hash.clone(),
    }
}
