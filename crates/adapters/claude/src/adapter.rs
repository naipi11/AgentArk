use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use agentark_adapter_sdk::{
    AdapterError, CaptureBatch, CaptureRequest, CapturedRecord, CapturedSource, DetectContext,
    NormalizeOutcome, ProbeReport, SourceAdapter, SourceCapability,
};
use agentark_canonical::{
    AgentInstall, AgentKind, CanonicalMessage, CanonicalRole, CanonicalSchemaVersion,
    CanonicalSession, Completeness, ContentPart, ContentPartKind, Sha256Digest, ToolEvent,
    Workspace, agent_install_id, message_id, session_id, workspace_id,
};
use agentark_security::AuthorizedRoot;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use walkdir::WalkDir;

const SCHEMA_FINGERPRINT: &str = "sha256:claude-code-jsonl-v1";

pub struct ClaudeCodeAdapter {
    root: PathBuf,
}

impl ClaudeCodeAdapter {
    pub fn new(root: &Path) -> Result<Self, AdapterError> {
        AuthorizedRoot::new(root.to_path_buf())?;
        Ok(Self {
            root: dunce::canonicalize(root)?,
        })
    }

    pub fn default_home() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("CLAUDE_HOME") {
            return Some(PathBuf::from(path));
        }
        std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .map(|home| home.join(".claude"))
    }

    fn root_uri(&self) -> String {
        format!("file://{}", self.root.to_string_lossy().replace('\\', "/"))
    }

    fn install(&self) -> AgentInstall {
        let root_uri = self.root_uri();
        AgentInstall {
            id: agent_install_id(Uuid::nil(), "claude-code", &root_uri),
            kind: AgentKind::ClaudeCode,
            executable_version: "filesystem-unknown".into(),
            authorized_root_uri: root_uri,
            adapter_version: "claude-code-adapter-v1".into(),
            schema_fingerprint: SCHEMA_FINGERPRINT.into(),
            capabilities: ["filesystem-raw-archive", "archived-threads"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            quarantine_reason: None,
        }
    }

    fn collect_records(&self) -> Result<Vec<CapturedRecord>, AdapterError> {
        let projects = self.root.join("projects");
        if !projects.is_dir() {
            return Ok(Vec::new());
        }
        let authorized = AuthorizedRoot::new(self.root.clone())?;
        let mut paths = Vec::new();
        for entry in WalkDir::new(&projects).follow_links(false) {
            let entry = entry.map_err(|error| AdapterError::InvalidData(error.to_string()))?;
            if entry.file_type().is_symlink() {
                return Err(AdapterError::Security(
                    agentark_security::SecurityError::ForbiddenPathClass("symlink"),
                ));
            }
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|value| value.to_str()) == Some("jsonl")
            {
                paths.push(
                    entry
                        .path()
                        .strip_prefix(&self.root)
                        .map_err(|_| AdapterError::InvalidData("source path escaped root".into()))?
                        .to_path_buf(),
                );
            }
        }
        paths.sort();
        let mut records = Vec::with_capacity(paths.len());
        for (ordinal, relative) in paths.into_iter().enumerate() {
            let mut file = authorized.open_regular_file(&relative)?;
            let before = file.metadata()?;
            let length = before.len();
            let modified = before.modified().ok();
            let mut bytes = Vec::with_capacity(length as usize);
            file.by_ref()
                .take(length.saturating_add(1))
                .read_to_end(&mut bytes)?;
            let after = file.metadata()?;
            if after.len() != length
                || modified != after.modified().ok()
                || bytes.len() != length as usize
            {
                return Err(AdapterError::InvalidData(
                    "Claude source changed during capture".into(),
                ));
            }
            let locator = relative.to_string_lossy().replace('\\', "/");
            let source_session_id = relative
                .file_stem()
                .and_then(|value| value.to_str())
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            records.push(CapturedRecord {
                source: CapturedSource::FilesystemSemantic,
                source_locator: locator.clone(),
                source_session_id,
                source_record_id: Some(locator),
                ordinal: ordinal as u64,
                snapshot_id: String::new(),
                bytes,
            });
        }
        Ok(records)
    }
}

impl SourceAdapter for ClaudeCodeAdapter {
    fn id(&self) -> &'static str {
        "claude-code"
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
        if !self.root.join("projects").is_dir() {
            return Ok(Vec::new());
        }
        Ok(vec![self.install()])
    }

    fn probe(&self, install: &AgentInstall) -> Result<ProbeReport, AdapterError> {
        if install.id != self.install().id {
            return Err(AdapterError::InvalidData(
                "Claude install does not belong to adapter".into(),
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
                "Claude capture install mismatch".into(),
            ));
        }
        let mut records = self.collect_records()?;
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
            issues: Vec::new(),
        })
    }

    fn normalize(&self, record: &CapturedRecord) -> Result<NormalizeOutcome, AdapterError> {
        if !matches!(record.source, CapturedSource::FilesystemSemantic) {
            return Ok(NormalizeOutcome::Quarantined {
                reason_code: "claude-unsupported-source".into(),
                fingerprint: format!("sha256:{}", hex::encode(Sha256::digest(&record.bytes))),
            });
        }
        match normalize_jsonl(
            &record.bytes,
            self.install().id,
            record.source_session_id.as_deref(),
        ) {
            Ok(session) => Ok(NormalizeOutcome::Normalized(Box::new(session))),
            Err(reason) => Ok(NormalizeOutcome::Quarantined {
                reason_code: "claude-malformed-transcript".into(),
                fingerprint: format!(
                    "sha256:{}:{reason}",
                    hex::encode(Sha256::digest(&record.bytes))
                ),
            }),
        }
    }

    fn capabilities(&self, _install: &AgentInstall) -> BTreeSet<SourceCapability> {
        BTreeSet::from([
            SourceCapability::FilesystemRawArchive,
            SourceCapability::ArchivedThreads,
        ])
    }
}

fn normalize_jsonl(
    bytes: &[u8],
    install_id: Uuid,
    fallback_id: Option<&str>,
) -> Result<CanonicalSession, String> {
    let raw_hash = Sha256Digest::from_bytes(bytes);
    let mut messages = Vec::new();
    let mut tool_events = Vec::new();
    let mut workspace = None;
    let mut title = None;
    let mut created_at_raw = None;
    let mut source_id = fallback_id.unwrap_or("claude-session").to_owned();
    let mut ordinal = 0u64;
    let mut partial = false;
    for line in String::from_utf8(bytes.to_vec())
        .map_err(|_| "Claude transcript is not UTF-8".to_owned())?
        .lines()
    {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|_| "Claude transcript contains invalid JSON".to_owned())?;
        if let Some(id) = value
            .get("sessionId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        {
            source_id = id.to_owned();
        }
        if created_at_raw.is_none() {
            created_at_raw = value
                .get("timestamp")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
        }
        if workspace.is_none() {
            workspace = workspace_from_line(&value);
        }
        match value.get("type").and_then(Value::as_str).unwrap_or("") {
            "user" => {
                let text = message_text(value.get("message").unwrap_or(&Value::Null));
                if !text.is_empty() {
                    ordinal += 1;
                    if title.is_none() {
                        title = Some(text.clone());
                    }
                    messages.push(CanonicalMessage {
                        id: message_id(
                            session_id(install_id, &source_id),
                            Some(&format!("user:{ordinal}")),
                            ordinal,
                            &raw_hash,
                        ),
                        source_record_id: Some(format!("user:{ordinal}")),
                        ordinal,
                        role: CanonicalRole::User,
                        raw_role: Some("user".into()),
                        created_at_raw: value
                            .get("timestamp")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        content: vec![ContentPart {
                            kind: ContentPartKind::Text,
                            text: Some(text),
                            attachment_id: None,
                            raw_extra: Default::default(),
                        }],
                        raw_ref: raw_hash.clone(),
                    });
                }
            }
            "assistant" => {
                let (text, tools) = assistant_content(value.get("message").unwrap_or(&Value::Null));
                if !text.is_empty() {
                    ordinal += 1;
                    messages.push(CanonicalMessage {
                        id: message_id(
                            session_id(install_id, &source_id),
                            Some(&format!("assistant:{ordinal}")),
                            ordinal,
                            &raw_hash,
                        ),
                        source_record_id: Some(format!("assistant:{ordinal}")),
                        ordinal,
                        role: CanonicalRole::Assistant,
                        raw_role: Some("assistant".into()),
                        created_at_raw: value
                            .get("timestamp")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        content: vec![ContentPart {
                            kind: ContentPartKind::Text,
                            text: Some(text),
                            attachment_id: None,
                            raw_extra: Default::default(),
                        }],
                        raw_ref: raw_hash.clone(),
                    });
                }
                for (name, input, output) in tools {
                    ordinal += 1;
                    tool_events.push(ToolEvent {
                        id: Uuid::new_v5(
                            &session_id(install_id, &source_id),
                            format!("tool:{ordinal}").as_bytes(),
                        )
                        .to_string(),
                        ordinal,
                        tool_name: name,
                        status: "completed".into(),
                        visible_input: input,
                        visible_output: output,
                        raw_ref: raw_hash.clone(),
                    });
                }
            }
            "summary" | "file-history-snapshot" | "system" | "permission-mode" | "mode" => {}
            _ => partial = true,
        }
    }
    let id = session_id(install_id, &source_id);
    Ok(CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id,
        install_id,
        source_session_id: source_id,
        source_kind: "claude-code".into(),
        workspace,
        title,
        archived: false,
        created_at_raw,
        updated_at_raw: None,
        model_provider: Some("anthropic".into()),
        model_name: None,
        completeness: if partial {
            Completeness::Partial
        } else {
            Completeness::Complete
        },
        messages,
        tool_events,
        attachments: Vec::new(),
        raw_extra: Default::default(),
    })
}

fn message_text(message: &Value) -> String {
    match message.get("content") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|part| {
                if part.get("type").and_then(Value::as_str) == Some("text") {
                    part.get("text").and_then(Value::as_str)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

type ToolContent = (String, Option<String>, Option<String>);

fn assistant_content(message: &Value) -> (String, Vec<ToolContent>) {
    let Some(Value::Array(parts)) = message.get("content") else {
        return (message_text(message), Vec::new());
    };
    let mut text = String::new();
    let mut tools = Vec::new();
    for part in parts {
        match part.get("type").and_then(Value::as_str).unwrap_or("") {
            "text" => text.push_str(part.get("text").and_then(Value::as_str).unwrap_or("")),
            "tool_use" => tools.push((
                part.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("tool")
                    .to_owned(),
                part.get("input").map(Value::to_string),
                None,
            )),
            _ => {}
        }
    }
    (text, tools)
}

fn workspace_from_line(value: &Value) -> Option<Workspace> {
    let path = value
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())?;
    let canonical_path = dunce::canonicalize(path)
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_owned());
    let canonical_uri = format!("file://{}", canonical_path.replace('\\', "/"));
    Some(Workspace {
        id: workspace_id(&canonical_uri),
        path_native: canonical_path,
        canonical_uri,
        git_commit: None,
    })
}
