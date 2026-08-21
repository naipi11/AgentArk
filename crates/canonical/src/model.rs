use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::Sha256Digest;

pub const CANONICAL_SCHEMA_VERSION: &str = "0.1.0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CanonicalSchemaVersion {
    #[serde(rename = "0.1.0")]
    V0_1_0,
}

impl CanonicalSchemaVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V0_1_0 => CANONICAL_SCHEMA_VERSION,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AgentKind {
    Codex,
    ClaudeCode,
    Hermes,
    OpenClaw,
    OpenCode,
    GrokBuild,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Completeness {
    Complete,
    Partial,
    Quarantined,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CanonicalRole {
    User,
    Assistant,
    System,
    Tool,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ContentPartKind {
    Text,
    Image,
    Audio,
    File,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentInstall {
    #[schemars(with = "String")]
    pub id: Uuid,
    pub kind: AgentKind,
    pub executable_version: String,
    pub authorized_root_uri: String,
    pub adapter_version: String,
    pub schema_fingerprint: String,
    pub capabilities: BTreeSet<String>,
    pub quarantine_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    #[schemars(with = "String")]
    pub id: Uuid,
    pub path_native: String,
    pub canonical_uri: String,
    pub git_commit: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalSession {
    pub schema_version: CanonicalSchemaVersion,
    #[schemars(with = "String")]
    pub id: Uuid,
    #[schemars(with = "String")]
    pub install_id: Uuid,
    pub source_session_id: String,
    pub source_kind: String,
    pub workspace: Option<Workspace>,
    pub title: Option<String>,
    pub archived: bool,
    pub created_at_raw: Option<String>,
    pub updated_at_raw: Option<String>,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub completeness: Completeness,
    pub messages: Vec<CanonicalMessage>,
    pub tool_events: Vec<ToolEvent>,
    pub attachments: Vec<Attachment>,
    pub raw_extra: BTreeMap<String, Value>,
}

impl CanonicalSession {
    #[doc(hidden)]
    pub fn searchable_text(&self) -> String {
        let mut entries = self
            .messages
            .iter()
            .map(|message| (message.ordinal, message.visible_text()))
            .chain(self.tool_events.iter().map(|event| {
                (
                    event.ordinal,
                    [
                        event.visible_input.as_deref(),
                        event.visible_output.as_deref(),
                    ]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" "),
                )
            }))
            .collect::<Vec<_>>();
        entries.sort_by_key(|(ordinal, _)| *ordinal);
        entries
            .into_iter()
            .map(|(_, text)| text)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalMessage {
    #[schemars(with = "String")]
    pub id: Uuid,
    pub source_record_id: Option<String>,
    pub ordinal: u64,
    pub role: CanonicalRole,
    pub raw_role: Option<String>,
    pub created_at_raw: Option<String>,
    pub content: Vec<ContentPart>,
    pub raw_ref: Sha256Digest,
}

impl CanonicalMessage {
    #[doc(hidden)]
    pub fn text_fixture(ordinal: u64, created_at_raw: &str, text: &str) -> Self {
        Self {
            id: Uuid::from_u128(ordinal as u128),
            source_record_id: None,
            ordinal,
            role: CanonicalRole::Assistant,
            raw_role: Some("assistant".into()),
            created_at_raw: Some(created_at_raw.into()),
            content: vec![ContentPart {
                kind: ContentPartKind::Text,
                text: Some(text.into()),
                attachment_id: None,
                raw_extra: BTreeMap::new(),
            }],
            raw_ref: Sha256Digest::from_bytes(text.as_bytes()),
        }
    }

    #[doc(hidden)]
    pub fn visible_text(&self) -> String {
        self.content
            .iter()
            .filter_map(|part| part.text.as_deref())
            .collect::<Vec<_>>()
            .join("")
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContentPart {
    pub kind: ContentPartKind,
    pub text: Option<String>,
    #[schemars(with = "Option<String>")]
    pub attachment_id: Option<Uuid>,
    pub raw_extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ToolEvent {
    pub id: String,
    pub ordinal: u64,
    pub tool_name: String,
    pub status: String,
    pub visible_input: Option<String>,
    pub visible_output: Option<String>,
    pub raw_ref: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    #[schemars(with = "String")]
    pub id: Uuid,
    pub source_locator: String,
    pub media_type: Option<String>,
    pub size: u64,
    pub sha256: Sha256Digest,
    pub raw_ref: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceRecord {
    pub source_locator: String,
    pub source_record_id: Option<String>,
    pub ordinal: u64,
    pub raw_sha256: Sha256Digest,
    pub cas_object_id: String,
    pub adapter_version: String,
    pub snapshot_id: String,
}
