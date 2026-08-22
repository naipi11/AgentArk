#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use agentark_canonical::{AgentKind, CanonicalSession, Sha256Digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum MigrationLevel {
    L0,
    L1,
    L2,
    L3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LossSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LossItem {
    pub field: String,
    pub severity: LossSeverity,
    pub reason: String,
    pub preserved_as: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationPlan {
    pub id: Uuid,
    pub source_agent: String,
    pub target_agent: String,
    pub source_session_id: String,
    pub level: MigrationLevel,
    pub supported_fields: Vec<String>,
    pub loss_report: Vec<LossItem>,
    pub requires_acknowledgement: bool,
    pub plan_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextHandoff {
    pub source_agent: String,
    pub source_session_id: String,
    pub source_workspace: Option<String>,
    pub visible_messages: Vec<HandoffMessage>,
    pub tool_events: Vec<HandoffToolEvent>,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub unsupported_fields: Vec<LossItem>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoffMessage {
    pub ordinal: u64,
    pub role: String,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoffToolEvent {
    pub ordinal: u64,
    pub tool_name: String,
    pub status: String,
    pub visible_input: Option<String>,
    pub visible_output: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub passed: bool,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoffArtifact {
    pub target_agent: String,
    pub json_path: String,
    pub markdown_path: String,
    pub plan_hash: String,
    pub json_sha256: Sha256Digest,
}

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("migration serialization failed")]
    Serialization(#[from] serde_json::Error),
}

pub const SUPPORTED_AGENTS: &[AgentKind] = &[
    AgentKind::Codex,
    AgentKind::ClaudeCode,
    AgentKind::Hermes,
    AgentKind::OpenClaw,
    AgentKind::OpenCode,
    AgentKind::GrokBuild,
];

pub fn build_plan(
    session: &CanonicalSession,
    target: AgentKind,
) -> Result<MigrationPlan, MigrationError> {
    let source_agent = session.source_kind.clone();
    let target_agent: String = agent_label(&target).into();
    let same_agent = source_agent == target_agent;
    let mut loss_report = vec![LossItem {
        field: "native-session-id".into(),
        severity: if same_agent {
            LossSeverity::Info
        } else {
            LossSeverity::Warning
        },
        reason: if same_agent {
            "same-agent native identity can be referenced"
        } else {
            "target native session injection is not a stable public contract"
        }
        .into(),
        preserved_as: Some("source_session_id + provenance".into()),
    }];
    loss_report.push(LossItem {
        field: "vendor-private-fields".into(),
        severity: LossSeverity::Info,
        reason: "vendor-specific fields are preserved in the L0 raw archive, not replayed into the target".into(),
        preserved_as: Some("raw_extra and .ahbundle".into()),
    });
    if !session.attachments.is_empty() {
        loss_report.push(LossItem {
            field: "attachments".into(),
            severity: LossSeverity::Warning,
            reason: "attachment bytes require a target-specific writer; semantic handoff references verified hashes".into(),
            preserved_as: Some("CAS object hash + handoff artifact".into()),
        });
    }
    loss_report.push(LossItem {
        field: "hidden-reasoning".into(),
        severity: LossSeverity::Info,
        reason: "internal reasoning is intentionally excluded from portable semantic context"
            .into(),
        preserved_as: None,
    });
    let supported_fields = [
        "visible_messages",
        "message_order",
        "tool_events",
        "workspace",
        "model_provenance",
        "raw_provenance",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect::<Vec<_>>();
    let mut plan = MigrationPlan {
        id: Uuid::new_v5(&session.id, target_agent.as_bytes()),
        source_agent,
        target_agent,
        source_session_id: session.source_session_id.clone(),
        level: if same_agent {
            MigrationLevel::L2
        } else {
            MigrationLevel::L1
        },
        supported_fields,
        requires_acknowledgement: loss_report
            .iter()
            .any(|item| item.severity == LossSeverity::Error),
        loss_report,
        plan_hash: String::new(),
    };
    let canonical = serde_jcs::to_vec(&plan)?;
    plan.plan_hash = format!("sha256:{}", hex::encode(Sha256::digest(canonical)));
    Ok(plan)
}

pub fn context_handoff(
    session: &CanonicalSession,
    unsupported_fields: Vec<LossItem>,
) -> ContextHandoff {
    ContextHandoff {
        source_agent: session.source_kind.clone(),
        source_session_id: session.source_session_id.clone(),
        source_workspace: session
            .workspace
            .as_ref()
            .map(|workspace| workspace.canonical_uri.clone()),
        visible_messages: session
            .messages
            .iter()
            .map(|message| HandoffMessage {
                ordinal: message.ordinal,
                role: format!("{:?}", message.role).to_lowercase(),
                text: message.visible_text(),
            })
            .collect(),
        tool_events: session
            .tool_events
            .iter()
            .map(|event| HandoffToolEvent {
                ordinal: event.ordinal,
                tool_name: event.tool_name.clone(),
                status: event.status.clone(),
                visible_input: event.visible_input.clone(),
                visible_output: event.visible_output.clone(),
            })
            .collect(),
        model_provider: session.model_provider.clone(),
        model_name: session.model_name.clone(),
        unsupported_fields,
    }
}

pub fn verify(expected: &CanonicalSession, actual: &CanonicalSession) -> VerificationReport {
    let mut issues = Vec::new();
    let expected_messages = expected
        .messages
        .iter()
        .map(|message| {
            (
                message.ordinal,
                format!("{:?}", message.role),
                message.visible_text(),
            )
        })
        .collect::<Vec<_>>();
    let actual_messages = actual
        .messages
        .iter()
        .map(|message| {
            (
                message.ordinal,
                format!("{:?}", message.role),
                message.visible_text(),
            )
        })
        .collect::<Vec<_>>();
    if expected_messages != actual_messages {
        issues.push("visible message order or text differs".into());
    }
    let expected_tools = expected
        .tool_events
        .iter()
        .map(|event| {
            (
                event.ordinal,
                event.tool_name.clone(),
                event.visible_output.clone(),
            )
        })
        .collect::<Vec<_>>();
    let actual_tools = actual
        .tool_events
        .iter()
        .map(|event| {
            (
                event.ordinal,
                event.tool_name.clone(),
                event.visible_output.clone(),
            )
        })
        .collect::<Vec<_>>();
    if expected_tools != actual_tools {
        issues.push("tool event provenance differs".into());
    }
    if expected
        .workspace
        .as_ref()
        .map(|workspace| &workspace.canonical_uri)
        != actual
            .workspace
            .as_ref()
            .map(|workspace| &workspace.canonical_uri)
    {
        issues.push("workspace identity differs".into());
    }
    VerificationReport {
        passed: issues.is_empty(),
        issues,
    }
}

pub fn write_handoff(
    directory: &Path,
    session: &CanonicalSession,
    target: AgentKind,
) -> Result<HandoffArtifact, MigrationError> {
    let plan = build_plan(session, target.clone())?;
    let handoff = context_handoff(session, plan.loss_report.clone());
    fs::create_dir_all(directory).map_err(serde_json::Error::io)?;
    let json_bytes = serde_json::to_vec_pretty(&handoff)?;
    let json_path = directory.join("context-handoff.json");
    let markdown_path = directory.join("context-handoff.md");
    write_atomic(&json_path, &json_bytes).map_err(serde_json::Error::io)?;
    let markdown = render_markdown(&handoff, &plan);
    write_atomic(&markdown_path, markdown.as_bytes()).map_err(serde_json::Error::io)?;
    Ok(HandoffArtifact {
        target_agent: agent_label(&target).into(),
        json_path: json_path.to_string_lossy().into_owned(),
        markdown_path: markdown_path.to_string_lossy().into_owned(),
        plan_hash: plan.plan_hash,
        json_sha256: Sha256Digest::from_bytes(&json_bytes),
    })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temp = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temp, path)
}

fn render_markdown(handoff: &ContextHandoff, plan: &MigrationPlan) -> String {
    let mut output = format!(
        "# AgentArk Context Handoff\n\n- Source agent: `{}`\n- Source session: `{}`\n- Target plan: `{}`\n\n## Visible conversation\n\n",
        handoff.source_agent, handoff.source_session_id, plan.plan_hash
    );
    for message in &handoff.visible_messages {
        output.push_str(&format!(
            "### {} {}\n\n{}\n\n",
            message.ordinal, message.role, message.text
        ));
    }
    if !handoff.tool_events.is_empty() {
        output.push_str("## Tool trace\n\n");
        for event in &handoff.tool_events {
            output.push_str(&format!(
                "- `{}` ({})\n  - input: {}\n  - output: {}\n",
                event.tool_name,
                event.status,
                event.visible_input.as_deref().unwrap_or(""),
                event.visible_output.as_deref().unwrap_or("")
            ));
        }
    }
    output.push_str("\n## Migration notes\n\n");
    for item in &handoff.unsupported_fields {
        output.push_str(&format!(
            "- `{}` [{:?}]: {}\n",
            item.field, item.severity, item.reason
        ));
    }
    output
}

pub fn agent_label(agent: &AgentKind) -> &'static str {
    match agent {
        AgentKind::Codex => "codex",
        AgentKind::ClaudeCode => "claude-code",
        AgentKind::Hermes => "hermes",
        AgentKind::OpenClaw => "openclaw",
        AgentKind::OpenCode => "opencode",
        AgentKind::GrokBuild => "grok-build",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentark_canonical::{CanonicalSchemaVersion, Completeness};
    use tempfile::tempdir;

    fn fixture() -> CanonicalSession {
        CanonicalSession {
            schema_version: CanonicalSchemaVersion::V0_1_0,
            id: Uuid::new_v4(),
            install_id: Uuid::new_v4(),
            source_session_id: "s1".into(),
            source_kind: "codex".into(),
            workspace: None,
            title: Some("title".into()),
            archived: false,
            created_at_raw: None,
            updated_at_raw: None,
            model_provider: None,
            model_name: None,
            completeness: Completeness::Complete,
            messages: vec![agentark_canonical::CanonicalMessage::text_fixture(
                1, "t", "hello",
            )],
            tool_events: vec![],
            attachments: vec![],
            raw_extra: Default::default(),
        }
    }

    #[test]
    fn all_supported_agent_pairs_produce_dry_run_plans() {
        let session = fixture();
        for target in SUPPORTED_AGENTS {
            let plan = build_plan(&session, target.clone()).unwrap();
            assert!(!plan.plan_hash.is_empty());
        }
    }

    #[test]
    fn handoff_verification_is_order_sensitive() {
        let expected = fixture();
        let mut actual = expected.clone();
        actual.messages[0].content[0].text = Some("changed".into());
        assert!(!verify(&expected, &actual).passed);
    }

    #[test]
    fn writes_structured_l1_handoff_artifacts() {
        let directory = tempdir().unwrap();
        let artifact = write_handoff(directory.path(), &fixture(), AgentKind::OpenCode).unwrap();
        assert!(Path::new(&artifact.json_path).is_file());
        assert!(Path::new(&artifact.markdown_path).is_file());
        assert!(artifact.plan_hash.starts_with("sha256:"));
    }
}
