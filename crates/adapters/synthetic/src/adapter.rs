use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use agentark_adapter_sdk::{
    AdapterError, CaptureBatch, CaptureRequest, CapturedRecord, DetectContext, NormalizeOutcome,
    ProbeReport, SourceAdapter, SourceCapability,
};
use agentark_canonical::{
    AgentInstall, AgentKind, CanonicalMessage, CanonicalRole, CanonicalSchemaVersion,
    CanonicalSession, Completeness, ContentPart, ContentPartKind, Sha256Digest, ToolEvent,
    agent_install_id, message_id, session_id,
};
use agentark_security::AuthorizedRoot;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const FIXTURES: [(&str, &[u8]); 4] = [
    (
        "text.jsonl",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../fixtures/synthetic/text.jsonl"
        )),
    ),
    (
        "tool.jsonl",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../fixtures/synthetic/tool.jsonl"
        )),
    ),
    (
        "truncated.jsonl",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../fixtures/synthetic/truncated.jsonl"
        )),
    ),
    (
        "unknown.jsonl",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../fixtures/synthetic/unknown.jsonl"
        )),
    ),
];

const SYNTHETIC_SCHEMA_FINGERPRINT: &str = "sha256:synthetic-schema-v1";

pub struct SyntheticAdapter {
    root: PathBuf,
}

impl SyntheticAdapter {
    pub fn new(root: &Path) -> Result<Self, AdapterError> {
        AuthorizedRoot::new(root.to_path_buf())?;
        Ok(Self {
            root: dunce::canonicalize(root)?,
        })
    }

    pub fn write_fixture_set(root: &Path) -> Result<(), AdapterError> {
        fs::create_dir_all(root)?;
        for (name, bytes) in FIXTURES {
            let bytes = if name == "truncated.jsonl" {
                bytes.strip_suffix(b"\n").unwrap_or(bytes)
            } else {
                bytes
            };
            fs::write(root.join(name), bytes)?;
        }
        Ok(())
    }

    pub fn tree_digest(root: &Path) -> Result<String, AdapterError> {
        let mut hasher = Sha256::new();
        let mut entries = Vec::new();
        collect_tree(root, root, &mut entries)?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        for (relative, bytes) in entries {
            hasher.update(relative.as_bytes());
            hasher.update([0]);
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    fn root_uri(&self) -> String {
        format!("file://{}", self.root.to_string_lossy().replace('\\', "/"))
    }

    fn install(&self) -> AgentInstall {
        let root_uri = self.root_uri();
        AgentInstall {
            id: agent_install_id(Uuid::nil(), "synthetic", &root_uri),
            kind: AgentKind::Codex,
            executable_version: "synthetic-0.1.0".into(),
            authorized_root_uri: root_uri,
            adapter_version: "synthetic-adapter-v1".into(),
            schema_fingerprint: SYNTHETIC_SCHEMA_FINGERPRINT.into(),
            capabilities: BTreeSet::new(),
            quarantine_reason: None,
        }
    }

    fn fixture_bytes(&self, name: &str) -> Result<Vec<u8>, AdapterError> {
        let root = AuthorizedRoot::new(self.root.clone())?;
        let mut file = root.open_regular_file(Path::new(name))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

impl SourceAdapter for SyntheticAdapter {
    fn id(&self) -> &'static str {
        "synthetic"
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
        Ok(vec![self.install()])
    }

    fn probe(&self, install: &AgentInstall) -> Result<ProbeReport, AdapterError> {
        if install.id != self.install().id {
            return Err(AdapterError::InvalidData(
                "probe install does not belong to this source".into(),
            ));
        }
        Ok(ProbeReport {
            adapter_id: self.id().into(),
            executable_version: install.executable_version.clone(),
            schema_fingerprint: install.schema_fingerprint.clone(),
            capabilities: self.capabilities(install),
            quarantine_reason: None,
        })
    }

    fn capture(&self, request: &CaptureRequest) -> Result<CaptureBatch, AdapterError> {
        if request.install.id != self.install().id {
            return Err(AdapterError::InvalidData(
                "capture install does not belong to this source".into(),
            ));
        }
        let mut hasher = Sha256::new();
        let mut records = Vec::with_capacity(FIXTURES.len());
        for (name, _) in FIXTURES {
            let bytes = self.fixture_bytes(name)?;
            hasher.update(name.as_bytes());
            hasher.update([0]);
            hasher.update(&bytes);
            let source_session_id = Path::new(name)
                .file_stem()
                .and_then(|value| value.to_str())
                .map(|value| format!("synthetic-{value}"));
            records.push(CapturedRecord {
                source_locator: name.into(),
                source_session_id,
                source_record_id: Some(name.into()),
                ordinal: 0,
                snapshot_id: String::new(),
                bytes,
            });
        }
        let snapshot_id = request
            .snapshot_hint
            .clone()
            .filter(|hint| !hint.is_empty())
            .unwrap_or_else(|| format!("sha256:{}", hex::encode(hasher.finalize())));
        for record in &mut records {
            record.snapshot_id = snapshot_id.clone();
        }
        Ok(CaptureBatch {
            snapshot_id,
            records,
        })
    }

    fn normalize(&self, record: &CapturedRecord) -> Result<NormalizeOutcome, AdapterError> {
        let fingerprint = Sha256Digest::from_bytes(&record.bytes).as_str().to_owned();
        if record.source_locator == "truncated.jsonl" || !record.bytes.ends_with(b"\n") {
            return Ok(NormalizeOutcome::Retryable {
                reason_code: "truncated-final-record".into(),
            });
        }
        let text = String::from_utf8(record.bytes.clone()).map_err(|_| {
            AdapterError::InvalidData("synthetic fixture is not valid UTF-8".into())
        })?;
        let record_hash = Sha256Digest::from_bytes(&record.bytes);
        let mut messages = Vec::new();
        let mut tool_events = Vec::new();
        let mut source_session_id = None;
        let mut ordinals = HashSet::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let value: Value = serde_json::from_str(line).map_err(|_| {
                AdapterError::InvalidData("synthetic fixture contains invalid JSON".into())
            })?;
            let session_value =
                value
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        AdapterError::InvalidData(
                            "synthetic fixture record lacks a session id".into(),
                        )
                    })?;
            if let Some(previous) = &source_session_id {
                if previous != session_value {
                    return Ok(NormalizeOutcome::Quarantined {
                        reason_code: "multiple-session-records".into(),
                        fingerprint,
                    });
                }
            } else {
                source_session_id = Some(session_value.to_owned());
            }
            let ordinal = value
                .get("ordinal")
                .and_then(Value::as_u64)
                .ok_or_else(|| AdapterError::InvalidData("synthetic ordinal is invalid".into()))?;
            if !ordinals.insert(ordinal) {
                return Ok(NormalizeOutcome::Quarantined {
                    reason_code: "duplicate-ordinal".into(),
                    fingerprint,
                });
            }
            let raw_hash = Sha256Digest::from_bytes(line.as_bytes());
            let source_record_id = format!("{}:{ordinal}", record.source_locator);
            match value.get("type").and_then(Value::as_str) {
                Some("message") => {
                    let role = match value.get("role").and_then(Value::as_str) {
                        Some("user") => CanonicalRole::User,
                        Some("assistant") => CanonicalRole::Assistant,
                        Some("system") => CanonicalRole::System,
                        Some("tool") => CanonicalRole::Tool,
                        _ => {
                            return Ok(NormalizeOutcome::Quarantined {
                                reason_code: "unknown-role".into(),
                                fingerprint,
                            });
                        }
                    };
                    messages.push(CanonicalMessage {
                        id: message_id(
                            session_id(Uuid::nil(), session_value),
                            Some(&source_record_id),
                            ordinal,
                            &raw_hash,
                        ),
                        source_record_id: Some(source_record_id),
                        ordinal,
                        role,
                        raw_role: value
                            .get("role")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        created_at_raw: value
                            .get("timestamp")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        content: vec![ContentPart {
                            kind: ContentPartKind::Text,
                            text: value
                                .get("text")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned),
                            attachment_id: None,
                            raw_extra: BTreeMap::new(),
                        }],
                        raw_ref: record_hash.clone(),
                    });
                }
                Some("tool") => {
                    tool_events.push(ToolEvent {
                        id: Uuid::new_v5(
                            &session_id(Uuid::nil(), session_value),
                            source_record_id.as_bytes(),
                        )
                        .to_string(),
                        ordinal,
                        tool_name: value
                            .get("toolName")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                            .to_owned(),
                        status: value
                            .get("status")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                            .to_owned(),
                        visible_input: value
                            .get("input")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        visible_output: value
                            .get("output")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        raw_ref: record_hash.clone(),
                    });
                }
                _ => {
                    return Ok(NormalizeOutcome::Quarantined {
                        reason_code: "unknown-record-type".into(),
                        fingerprint,
                    });
                }
            }
        }
        let source_session_id = source_session_id.ok_or_else(|| {
            AdapterError::InvalidData("synthetic fixture contains no records".into())
        })?;
        messages.sort_by_key(|message| message.ordinal);
        tool_events.sort_by_key(|event| event.ordinal);
        let title = messages
            .iter()
            .find(|message| matches!(message.role, CanonicalRole::User))
            .map(CanonicalMessage::visible_text);
        let id = session_id(Uuid::nil(), &source_session_id);
        Ok(NormalizeOutcome::Normalized(Box::new(CanonicalSession {
            schema_version: CanonicalSchemaVersion::V0_1_0,
            id,
            install_id: agent_install_id(Uuid::nil(), "synthetic", &self.root_uri()),
            source_session_id,
            source_kind: "synthetic-jsonl".into(),
            workspace: None,
            title,
            archived: false,
            created_at_raw: None,
            updated_at_raw: None,
            model_provider: Some("synthetic".into()),
            model_name: Some("fixture".into()),
            completeness: Completeness::Complete,
            messages,
            tool_events,
            attachments: Vec::new(),
            raw_extra: BTreeMap::new(),
        })))
    }

    fn capabilities(&self, _install: &AgentInstall) -> BTreeSet<SourceCapability> {
        BTreeSet::from([
            SourceCapability::ArchivedThreads,
            SourceCapability::FilesystemRawArchive,
            SourceCapability::KnownSemanticSchema,
        ])
    }
}

fn collect_tree(
    root: &Path,
    current: &Path,
    entries: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), AdapterError> {
    let mut children = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for entry in children {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| AdapterError::InvalidData("fixture path escaped its root".into()))?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(AdapterError::InvalidData(
                "fixture tree contains a symlink".into(),
            ));
        }
        if metadata.is_dir() {
            collect_tree(root, &path, entries)?;
        } else if metadata.is_file() {
            let bytes = fs::read(&path)?;
            entries.push((relative.to_string_lossy().replace('\\', "/"), bytes));
        }
    }
    Ok(())
}
