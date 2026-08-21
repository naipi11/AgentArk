use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use agentark_adapter_sdk::{
    AdapterError, CaptureBatch, CaptureIssue, CaptureRequest, CapturedRecord, CapturedSource,
    DetectContext, NormalizeOutcome, ProbeReport, SourceAdapter, SourceCapability,
};
use agentark_canonical::{
    AgentInstall, AgentKind, CanonicalMessage, CanonicalRole, CanonicalSchemaVersion,
    CanonicalSession, Completeness, ContentPart, ContentPartKind, Sha256Digest, ToolEvent,
    Workspace, agent_install_id, message_id, session_id, workspace_id,
};
use agentark_security::AuthorizedRoot;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use walkdir::WalkDir;

const SCHEMA_FINGERPRINT: &str = "sha256:grok-build-session-jsonl-v1";

pub struct GrokBuildAdapter {
    root: PathBuf,
}

impl GrokBuildAdapter {
    pub fn new(root: &Path) -> Result<Self, AdapterError> {
        AuthorizedRoot::new(root.to_path_buf())?;
        Ok(Self {
            root: dunce::canonicalize(root)?,
        })
    }

    pub fn default_home() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("GROK_HOME") {
            return Some(PathBuf::from(path));
        }
        std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .map(|home| home.join(".grok"))
    }

    fn sessions_root(&self) -> PathBuf {
        if self.root.file_name().and_then(|name| name.to_str()) == Some("sessions") {
            self.root.clone()
        } else {
            self.root.join("sessions")
        }
    }

    fn root_uri(&self) -> String {
        format!("file://{}", self.root.to_string_lossy().replace('\\', "/"))
    }

    fn install(&self) -> AgentInstall {
        let root_uri = self.root_uri();
        AgentInstall {
            id: agent_install_id(Uuid::nil(), "grok-build", &root_uri),
            kind: AgentKind::GrokBuild,
            executable_version: "session-jsonl-unknown".into(),
            authorized_root_uri: root_uri,
            adapter_version: "grok-build-adapter-v1".into(),
            schema_fingerprint: SCHEMA_FINGERPRINT.into(),
            capabilities: ["filesystem-raw-archive", "known-semantic-schema"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            quarantine_reason: None,
        }
    }

    fn session_dirs(&self) -> Vec<PathBuf> {
        let root = self.sessions_root();
        if !root.is_dir() {
            return Vec::new();
        }
        let mut paths = WalkDir::new(root)
            .follow_links(false)
            .max_depth(5)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_dir())
            .map(|entry| entry.into_path())
            .filter(|path| path.join("summary.json").is_file())
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }

    fn capture_session(
        &self,
        directory: &Path,
        ordinal: u64,
    ) -> Result<(CapturedRecord, Vec<CaptureIssue>), AdapterError> {
        let summary_bytes = fs::read(directory.join("summary.json"))?;
        let summary: Value = serde_json::from_slice(&summary_bytes).map_err(|error| {
            AdapterError::InvalidData(format!("Grok summary is invalid: {error}"))
        })?;
        let session_id = summary_session_id(&summary)
            .or_else(|| {
                directory
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(ToOwned::to_owned)
            })
            .ok_or_else(|| AdapterError::InvalidData("Grok session id is missing".into()))?;
        let mut issues = Vec::new();
        let (updates, updates_raw) =
            read_jsonl(directory.join("updates.jsonl"), &session_id, &mut issues)?;
        let (chat_history, chat_raw) = read_jsonl(
            directory.join("chat_history.jsonl"),
            &session_id,
            &mut issues,
        )?;
        let payload = json!({
            "summary": summary,
            "updates": updates,
            "updatesRaw": updates_raw,
            "chatHistory": chat_history,
            "chatHistoryRaw": chat_raw,
            "sessionDirectory": directory.strip_prefix(&self.root).unwrap_or(directory).to_string_lossy().replace('\\', "/"),
        });
        let bytes = serde_json::to_vec(&payload)
            .map_err(|error| AdapterError::InvalidData(error.to_string()))?;
        Ok((
            CapturedRecord {
                source: CapturedSource::FilesystemSemantic,
                source_locator: format!("{}#session/{session_id}", directory.to_string_lossy()),
                source_session_id: Some(session_id.clone()),
                source_record_id: Some(session_id),
                ordinal,
                snapshot_id: String::new(),
                bytes,
            },
            issues,
        ))
    }

    fn capture_sessions(&self) -> Result<(Vec<CapturedRecord>, Vec<CaptureIssue>), AdapterError> {
        let mut records = Vec::new();
        let mut issues = Vec::new();
        for (ordinal, directory) in self.session_dirs().into_iter().enumerate() {
            match self.capture_session(&directory, ordinal as u64) {
                Ok((record, mut local_issues)) => {
                    records.push(record);
                    issues.append(&mut local_issues);
                }
                Err(error) => issues.push(CaptureIssue {
                    source_locator: directory.to_string_lossy().into_owned(),
                    source_session_id: None,
                    reason_code: format!("grok-session-read-failed:{error}"),
                    retryable: false,
                }),
            }
        }
        Ok((records, issues))
    }
}

fn read_jsonl(
    path: PathBuf,
    session_id: &str,
    issues: &mut Vec<CaptureIssue>,
) -> Result<(Vec<Value>, Vec<String>), AdapterError> {
    if !path.is_file() {
        return Ok((Vec::new(), Vec::new()));
    }
    let bytes = fs::read(&path)?;
    let mut values = Vec::new();
    let mut raw = Vec::new();
    for (line_number, line) in String::from_utf8_lossy(&bytes).lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(value) => values.push(value),
            Err(_) => {
                raw.push(line.to_owned());
                issues.push(CaptureIssue {
                    source_locator: format!("{}#line/{}", path.to_string_lossy(), line_number + 1),
                    source_session_id: Some(session_id.to_owned()),
                    reason_code: "grok-malformed-jsonl-record".into(),
                    retryable: false,
                });
            }
        }
    }
    Ok((values, raw))
}

fn sql_like_key(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(|character| character.to_lowercase())
        .collect()
}

fn find_value<'a>(value: &'a Value, names: &HashSet<String>) -> Option<&'a Value> {
    match value {
        Value::Object(object) => {
            for (key, candidate) in object {
                if names.contains(&sql_like_key(key)) {
                    return Some(candidate);
                }
            }
            object
                .values()
                .find_map(|candidate| find_value(candidate, names))
        }
        Value::Array(values) => values
            .iter()
            .find_map(|candidate| find_value(candidate, names)),
        _ => None,
    }
}

fn find_text(value: &Value, names: &[&str]) -> Option<String> {
    let names = names
        .iter()
        .map(|name| sql_like_key(name))
        .collect::<HashSet<_>>();
    let candidate = find_value(value, &names)?;
    match candidate {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

fn summary_session_id(summary: &Value) -> Option<String> {
    find_text(summary, &["sessionId", "session_id", "id"])
}

fn event_role(event: &Value) -> String {
    if let Some(role) = find_text(event, &["role", "authorRole", "sender"]) {
        return role;
    }
    let kind = find_text(event, &["sessionUpdate", "update", "type", "kind"]).unwrap_or_default();
    let kind = sql_like_key(&kind);
    if kind.contains("user") || kind.contains("prompt") {
        "user".into()
    } else if kind.contains("tool") {
        "tool".into()
    } else if kind.contains("agent") || kind.contains("assistant") || kind.contains("thought") {
        "assistant".into()
    } else {
        "unknown".into()
    }
}

fn normalize_session(bytes: &[u8], install_id: Uuid) -> Result<CanonicalSession, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "invalid JSON")?;
    let summary = value.get("summary").ok_or("missing summary")?;
    let source_id = summary_session_id(summary).ok_or("missing session id")?;
    let id = session_id(install_id, &source_id);
    let raw_hash = Sha256Digest::from_bytes(bytes);
    let mut events = value
        .get("updates")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if events.is_empty() {
        events = value
            .get("chatHistory")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
    }
    let mut messages = Vec::new();
    let mut tool_events = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let ordinal = index as u64 + 1;
        let role = event_role(event);
        let tool_name = find_text(event, &["toolName", "tool", "name"]);
        let text = find_text(
            event,
            &["text", "content", "message", "output", "result", "delta"],
        )
        .unwrap_or_default();
        if role == "tool" || tool_name.is_some() || sql_like_key(&role).contains("tool") {
            tool_events.push(ToolEvent {
                id: Uuid::new_v5(&id, format!("tool:{ordinal}").as_bytes()).to_string(),
                ordinal,
                tool_name: tool_name.unwrap_or_else(|| "tool".into()),
                status: find_text(event, &["status"]).unwrap_or_else(|| "completed".into()),
                visible_input: find_text(event, &["input", "arguments", "args"]),
                visible_output: (!text.is_empty()).then_some(text),
                raw_ref: raw_hash.clone(),
            });
            continue;
        }
        let canonical_role = match sql_like_key(&role).as_str() {
            "user" => CanonicalRole::User,
            "assistant" => CanonicalRole::Assistant,
            "system" => CanonicalRole::System,
            _ => CanonicalRole::Unknown,
        };
        messages.push(CanonicalMessage {
            id: message_id(id, Some(&format!("event:{ordinal}")), ordinal, &raw_hash),
            source_record_id: Some(format!("event:{ordinal}")),
            ordinal,
            role: canonical_role,
            raw_role: Some(role),
            created_at_raw: find_text(event, &["timestamp", "createdAt", "created_at"]),
            content: vec![ContentPart {
                kind: ContentPartKind::Text,
                text: Some(text),
                attachment_id: None,
                raw_extra: event
                    .as_object()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
            }],
            raw_ref: raw_hash.clone(),
        });
    }
    let cwd = find_text(summary, &["cwd", "workingDirectory", "directory"])
        .or_else(|| find_text(&value, &["cwd"]));
    let workspace = cwd.map(|path| {
        let canonical_uri = format!("file://{}", path.replace('\\', "/"));
        Workspace {
            id: workspace_id(&canonical_uri),
            path_native: path,
            canonical_uri,
            git_commit: None,
        }
    });
    let raw_extra = [
        (
            "parentSessionId",
            find_text(summary, &["parentSessionId", "parent_session_id"])
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        (
            "agentName",
            find_text(summary, &["agentName", "agent_name"])
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        (
            "messageCount",
            find_text(summary, &["numMessages", "num_messages"])
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        (
            "updatesRaw",
            value.get("updatesRaw").cloned().unwrap_or(Value::Null),
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect::<BTreeMap<_, _>>();
    Ok(CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id,
        install_id,
        source_session_id: source_id,
        source_kind: "grok-build".into(),
        workspace,
        title: find_text(
            summary,
            &[
                "generatedTitle",
                "generated_title",
                "sessionSummary",
                "session_summary",
                "title",
            ],
        ),
        archived: false,
        created_at_raw: find_text(summary, &["createdAt", "created_at"]),
        updated_at_raw: find_text(summary, &["updatedAt", "updated_at"]),
        model_provider: Some("xai".into()),
        model_name: find_text(summary, &["currentModelId", "current_model_id", "model"]),
        completeness: if value
            .get("updatesRaw")
            .and_then(Value::as_array)
            .is_some_and(|rows| !rows.is_empty())
        {
            Completeness::Partial
        } else {
            Completeness::Complete
        },
        messages,
        tool_events,
        attachments: Vec::new(),
        raw_extra,
    })
}

impl SourceAdapter for GrokBuildAdapter {
    fn id(&self) -> &'static str {
        "grok-build"
    }

    fn detect(&self, ctx: &DetectContext) -> Result<Vec<AgentInstall>, AdapterError> {
        if !ctx.explicit_roots.is_empty()
            && !ctx
                .explicit_roots
                .iter()
                .any(|root| dunce::canonicalize(root).ok().as_deref() == Some(self.root.as_path()))
        {
            return Ok(Vec::new());
        }
        if self.session_dirs().is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![self.install()])
    }

    fn probe(&self, install: &AgentInstall) -> Result<ProbeReport, AdapterError> {
        if install.id != self.install().id {
            return Err(AdapterError::InvalidData("Grok install mismatch".into()));
        }
        if self.session_dirs().is_empty() {
            return Err(AdapterError::InvalidData(
                "Grok sessions directory is missing".into(),
            ));
        }
        Ok(ProbeReport {
            adapter_id: self.id().into(),
            executable_version: install.executable_version.clone(),
            schema_fingerprint: SCHEMA_FINGERPRINT.into(),
            capabilities: self.capabilities(install),
            quarantine_reason: None,
        })
    }

    fn capture(&self, request: &CaptureRequest) -> Result<CaptureBatch, AdapterError> {
        if request.install.id != self.install().id {
            return Err(AdapterError::InvalidData(
                "Grok capture install mismatch".into(),
            ));
        }
        let (mut records, issues) = self.capture_sessions()?;
        let mut hasher = Sha256::new();
        for record in &records {
            hasher.update(record.source_locator.as_bytes());
            hasher.update([0]);
            hasher.update(&record.bytes);
        }
        let snapshot_id = request
            .snapshot_hint
            .clone()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("sha256:{}", hex::encode(hasher.finalize())));
        for record in &mut records {
            record.snapshot_id = snapshot_id.clone();
        }
        Ok(CaptureBatch {
            snapshot_id,
            records,
            issues,
        })
    }

    fn normalize(&self, record: &CapturedRecord) -> Result<NormalizeOutcome, AdapterError> {
        if !matches!(record.source, CapturedSource::FilesystemSemantic) {
            return Ok(NormalizeOutcome::Quarantined {
                reason_code: "grok-unsupported-source".into(),
                fingerprint: format!("sha256:{}", hex::encode(Sha256::digest(&record.bytes))),
            });
        }
        match normalize_session(&record.bytes, self.install().id) {
            Ok(session) => Ok(NormalizeOutcome::Normalized(Box::new(session))),
            Err(_) => Ok(NormalizeOutcome::Quarantined {
                reason_code: "grok-malformed-session".into(),
                fingerprint: format!("sha256:{}", hex::encode(Sha256::digest(&record.bytes))),
            }),
        }
    }

    fn capabilities(&self, _install: &AgentInstall) -> BTreeSet<SourceCapability> {
        BTreeSet::from([
            SourceCapability::FilesystemRawArchive,
            SourceCapability::KnownSemanticSchema,
        ])
    }
}
