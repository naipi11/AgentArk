use std::fs;
use std::path::{Path, PathBuf};

use agentark_adapter_claude::ClaudeCodeAdapter;
use agentark_adapter_codex::{CodexAdapter, CodexProbe};
use agentark_adapter_grok::GrokBuildAdapter;
use agentark_adapter_hermes::HermesAdapter;
use agentark_adapter_openclaw::OpenClawAdapter;
use agentark_adapter_opencode::OpenCodeAdapter;
use agentark_adapter_sdk::{DetectContext, SourceAdapter};
use agentark_app::{AppError, ScanReport, ScanRequest, ScanService, VerificationService};
use agentark_audit::{AuditEvent, AuditVerification, append_event, verify_chain};
use agentark_bundle::{BundleError, ProjectSelection, read_bundle, write_selected_sessions};
use agentark_canonical::AgentKind;
use agentark_cas::EncryptedCas;
use agentark_index::{IndexDb, SessionQuery};
use agentark_migration::{
    ContextHandoff, HandoffArtifact, MigrationPlan, build_plan, context_handoff, write_handoff,
};
use agentark_security::{DatasetBootstrap, OsMasterKeyStore, SecretScanner};
use agentark_sync::{MergeResult, merge, read_operations};
use directories::ProjectDirs;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("storage is not initialized")]
    NotInitialized,
    #[error("scan requires explicit source authorization")]
    Authorization,
    #[error("Codex probe failed")]
    Probe,
    #[error("application operation failed")]
    App(#[from] AppError),
    #[error("storage operation failed")]
    Storage,
    #[error("invalid command input")]
    InvalidInput,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorData {
    pub dataset_state: &'static str,
    pub bootstrap_present: bool,
    pub index_present: bool,
    pub cas_present: bool,
    pub sqlcipher_ready: bool,
    pub adapters: Vec<DoctorAdapter>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorAdapter {
    pub id: &'static str,
    pub detected: bool,
    pub default_root: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeData {
    pub adapter_id: String,
    pub executable_version: String,
    pub schema_fingerprint: String,
    pub capabilities: Vec<String>,
    pub quarantine_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleData {
    pub format: String,
    pub agent: Option<String>,
    pub session_count: u64,
    pub entry_count: usize,
    pub workspace_count: u64,
    pub file_count: u64,
    pub conflict_count: u64,
    pub redacted: bool,
    pub redaction_count: u64,
    pub restore_scan_id: Option<Uuid>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationData {
    pub plan_count: usize,
    pub plans: Vec<MigrationPlan>,
    pub handoffs: Vec<ContextHandoff>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationExportData {
    pub target_agent: String,
    pub artifacts: Vec<HandoffArtifact>,
}

pub fn data_dir(override_dir: Option<PathBuf>) -> PathBuf {
    override_dir.unwrap_or_else(|| {
        ProjectDirs::from("dev", "AgentArk", "AgentArk")
            .map(|dirs| dirs.data_local_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".agentark-data"))
    })
}

pub fn detected_codex_home() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CODEX_HOME") {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .map(|home| home.join(".codex"))
}

pub fn detected_claude_home() -> Option<PathBuf> {
    ClaudeCodeAdapter::default_home()
}

pub fn detected_hermes_home() -> Option<PathBuf> {
    HermesAdapter::default_home()
}

pub fn detected_openclaw_home() -> Option<PathBuf> {
    OpenClawAdapter::default_home()
}

pub fn detected_opencode_home() -> Option<PathBuf> {
    OpenCodeAdapter::default_home()
}

pub fn detected_grok_build_home() -> Option<PathBuf> {
    GrokBuildAdapter::default_home()
}

pub fn doctor(root: &Path) -> DoctorData {
    let bootstrap_present = root.join("bootstrap.json").is_file();
    let index_present = root.join("index.db").is_file();
    let cas_present = root.join("cas").is_dir();
    let sqlcipher_ready = if bootstrap_present {
        open_storage_existing(root).is_ok()
    } else {
        false
    };
    let adapters = [
        ("codex", detected_codex_home()),
        ("claude-code", detected_claude_home()),
        ("hermes", detected_hermes_home()),
        ("openclaw", detected_openclaw_home()),
        ("opencode", detected_opencode_home()),
        ("grok-build", detected_grok_build_home()),
    ]
    .into_iter()
    .map(|(id, root)| DoctorAdapter {
        id,
        detected: root.as_ref().is_some_and(|path| path.exists()),
        default_root: root.map(|path| path.to_string_lossy().into_owned()),
    })
    .collect();
    DoctorData {
        dataset_state: if bootstrap_present {
            "ready"
        } else {
            "notInitialized"
        },
        bootstrap_present,
        index_present,
        cas_present,
        sqlcipher_ready,
        adapters,
    }
}

pub fn export_bundle(
    root: &Path,
    path: &Path,
    agent: Option<String>,
    workspace_ids: Vec<Uuid>,
    include_files: bool,
) -> Result<BundleData, RuntimeError> {
    let (_cas, index, _store) = open_storage_existing(root)?;
    let agent_kind = agent.as_deref().map(parse_target_agent).transpose()?;
    let sessions = index
        .all_sessions_filtered(agent_kind.clone())
        .map_err(|_| RuntimeError::Storage)?;
    let scanner = SecretScanner::v1().map_err(|_| RuntimeError::Storage)?;
    let selected = workspace_ids
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let selections = sessions
        .iter()
        .filter_map(|session| session.workspace.as_ref())
        .filter(|workspace| selected.is_empty() || selected.contains(&workspace.id))
        .map(|workspace| ProjectSelection {
            workspace_id: workspace.id,
            root: PathBuf::from(&workspace.path_native),
            include_files,
            max_file_bytes: 64 * 1024 * 1024,
        })
        .collect::<Vec<_>>();
    let manifest = write_selected_sessions(
        path,
        agent.as_deref().unwrap_or("all"),
        &sessions,
        &selections,
        &scanner,
    )
    .map_err(bundle_error)?;
    append_audit(root, "bundle.exported", path, None)?;
    Ok(BundleData {
        format: manifest.format,
        agent: manifest.agent,
        session_count: manifest.session_count,
        entry_count: manifest.entries.len() + 1,
        workspace_count: manifest.workspace_count,
        file_count: manifest.file_count,
        conflict_count: 0,
        redacted: manifest.redacted,
        redaction_count: manifest.redaction_count,
        restore_scan_id: None,
    })
}

pub fn verify_bundle(path: &Path) -> Result<BundleData, RuntimeError> {
    let bundle = read_bundle(path).map_err(bundle_error)?;
    Ok(BundleData {
        format: bundle.manifest.format.clone(),
        agent: bundle.manifest.agent.clone(),
        session_count: bundle.manifest.session_count,
        entry_count: bundle.entries.len(),
        workspace_count: bundle.manifest.workspace_count,
        file_count: bundle.manifest.file_count,
        conflict_count: 0,
        redacted: bundle.manifest.redacted,
        redaction_count: bundle.manifest.redaction_count,
        restore_scan_id: None,
    })
}

pub fn restore_bundle(root: &Path, path: &Path) -> Result<BundleData, RuntimeError> {
    let bundle = read_bundle(path).map_err(bundle_error)?;
    let sessions = bundle.session_records().map_err(bundle_error)?;
    let (_cas, mut index, _store) = open_storage_existing(root)?;
    let scan_id = index
        .restore_sessions(&sessions)
        .map_err(|_| RuntimeError::Storage)?;
    append_audit(root, "bundle.restored", path, Some(scan_id))?;
    Ok(BundleData {
        format: bundle.manifest.format.clone(),
        agent: bundle.manifest.agent.clone(),
        session_count: bundle.manifest.session_count,
        entry_count: bundle.entries.len(),
        workspace_count: bundle.manifest.workspace_count,
        file_count: bundle.manifest.file_count,
        conflict_count: 0,
        redacted: bundle.manifest.redacted,
        redaction_count: bundle.manifest.redaction_count,
        restore_scan_id: Some(scan_id),
    })
}

pub fn migration_plan(
    path: &Path,
    target: &str,
    include_handoff: bool,
) -> Result<MigrationData, RuntimeError> {
    let bundle = read_bundle(path).map_err(bundle_error)?;
    let target_kind = parse_target_agent(target)?;
    let sessions = bundle.session_records().map_err(bundle_error)?;
    let mut plans = Vec::with_capacity(sessions.len());
    let mut handoffs = Vec::new();
    for session in sessions {
        let plan = build_plan(&session, target_kind.clone()).map_err(|_| RuntimeError::Storage)?;
        if include_handoff {
            handoffs.push(context_handoff(&session, plan.loss_report.clone()));
        }
        plans.push(plan);
    }
    Ok(MigrationData {
        plan_count: plans.len(),
        plans,
        handoffs,
    })
}

pub fn migration_export(
    path: &Path,
    target: &str,
    output: &Path,
) -> Result<MigrationExportData, RuntimeError> {
    let bundle = read_bundle(path).map_err(bundle_error)?;
    let target_kind = parse_target_agent(target)?;
    let sessions = bundle.session_records().map_err(bundle_error)?;
    let target_label = agentark_migration::agent_label(&target_kind).to_owned();
    let mut artifacts = Vec::with_capacity(sessions.len());
    for session in sessions {
        let directory = output.join(session.id.to_string());
        artifacts.push(
            write_handoff(&directory, &session, target_kind.clone())
                .map_err(|_| RuntimeError::Storage)?,
        );
    }
    Ok(MigrationExportData {
        target_agent: target_label,
        artifacts,
    })
}

fn parse_target_agent(target: &str) -> Result<AgentKind, RuntimeError> {
    match target.to_ascii_lowercase().as_str() {
        "codex" => Ok(AgentKind::Codex),
        "claudecode" | "claude-code" => Ok(AgentKind::ClaudeCode),
        "hermes" => Ok(AgentKind::Hermes),
        "openclaw" => Ok(AgentKind::OpenClaw),
        "opencode" => Ok(AgentKind::OpenCode),
        "grokbuild" | "grok-build" => Ok(AgentKind::GrokBuild),
        _ => Err(RuntimeError::InvalidInput),
    }
}

fn bundle_error(error: BundleError) -> RuntimeError {
    let _ = error;
    RuntimeError::Storage
}

pub fn verify_audit(root: &Path) -> Result<AuditVerification, RuntimeError> {
    verify_chain(&root.join("audit.jsonl")).map_err(|_| RuntimeError::Storage)
}

pub fn sync_merge(local: &Path, remote: &Path) -> Result<MergeResult, RuntimeError> {
    let local = read_operations(local).map_err(|_| RuntimeError::Storage)?;
    let remote = read_operations(remote).map_err(|_| RuntimeError::Storage)?;
    Ok(merge(&local, &remote))
}

fn append_audit(
    root: &Path,
    event_type: &str,
    path: &Path,
    target: Option<Uuid>,
) -> Result<(), RuntimeError> {
    let event = AuditEvent {
        event_id: Uuid::new_v4(),
        event_type: event_type.into(),
        timestamp: "now".into(),
        actor: "agentark".into(),
        source: path
            .file_name()
            .and_then(|name| name.to_str())
            .map(ToOwned::to_owned),
        target: target.map(|value| value.to_string()),
        before_hash: None,
        after_hash: None,
        plan_hash: None,
        result: "success".into(),
        provider_labels: Vec::new(),
        previous_hash: None,
        event_hash: agentark_canonical::Sha256Digest::from_bytes(b"pending"),
    };
    append_event(&root.join("audit.jsonl"), event)
        .map(|_| ())
        .map_err(|_| RuntimeError::Storage)
}

pub fn probe_codex() -> Result<ProbeData, RuntimeError> {
    let executable = resolve_codex_executable();
    let report = CodexProbe::run(&executable).map_err(|_| RuntimeError::Probe)?;
    Ok(ProbeData {
        adapter_id: report.adapter_id,
        executable_version: report.executable_version,
        schema_fingerprint: report.schema_fingerprint,
        capabilities: report
            .capabilities
            .into_iter()
            .map(|capability| format!("{capability:?}"))
            .collect(),
        quarantine_reason: report.quarantine_reason,
    })
}

pub fn probe_claude() -> Result<ProbeData, RuntimeError> {
    let root = detected_claude_home().ok_or(RuntimeError::Authorization)?;
    let adapter = ClaudeCodeAdapter::new(&root).map_err(|_| RuntimeError::Storage)?;
    let install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![root],
            allow_detected_home: false,
        })
        .map_err(|_| RuntimeError::Storage)?
        .pop()
        .ok_or(RuntimeError::Authorization)?;
    let report = adapter.probe(&install).map_err(|_| RuntimeError::Probe)?;
    Ok(ProbeData {
        adapter_id: report.adapter_id,
        executable_version: report.executable_version,
        schema_fingerprint: report.schema_fingerprint,
        capabilities: report
            .capabilities
            .into_iter()
            .map(|capability| format!("{capability:?}"))
            .collect(),
        quarantine_reason: report.quarantine_reason,
    })
}

pub fn probe_hermes() -> Result<ProbeData, RuntimeError> {
    let root = detected_hermes_home().ok_or(RuntimeError::Authorization)?;
    let adapter = HermesAdapter::new(&root).map_err(|_| RuntimeError::Storage)?;
    let install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![root],
            allow_detected_home: false,
        })
        .map_err(|_| RuntimeError::Storage)?
        .pop()
        .ok_or(RuntimeError::Authorization)?;
    let report = adapter.probe(&install).map_err(|_| RuntimeError::Probe)?;
    Ok(ProbeData {
        adapter_id: report.adapter_id,
        executable_version: report.executable_version,
        schema_fingerprint: report.schema_fingerprint,
        capabilities: report
            .capabilities
            .into_iter()
            .map(|capability| format!("{capability:?}"))
            .collect(),
        quarantine_reason: report.quarantine_reason,
    })
}

pub fn probe_openclaw() -> Result<ProbeData, RuntimeError> {
    let root = detected_openclaw_home().ok_or(RuntimeError::Authorization)?;
    let adapter = OpenClawAdapter::new(&root).map_err(|_| RuntimeError::Storage)?;
    let install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![root],
            allow_detected_home: false,
        })
        .map_err(|_| RuntimeError::Storage)?
        .pop()
        .ok_or(RuntimeError::Authorization)?;
    let report = adapter.probe(&install).map_err(|_| RuntimeError::Probe)?;
    Ok(ProbeData {
        adapter_id: report.adapter_id,
        executable_version: report.executable_version,
        schema_fingerprint: report.schema_fingerprint,
        capabilities: report
            .capabilities
            .into_iter()
            .map(|capability| format!("{capability:?}"))
            .collect(),
        quarantine_reason: report.quarantine_reason,
    })
}

pub fn probe_opencode() -> Result<ProbeData, RuntimeError> {
    let root = detected_opencode_home().ok_or(RuntimeError::Authorization)?;
    let adapter = OpenCodeAdapter::new(&root).map_err(|_| RuntimeError::Storage)?;
    let install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![root],
            allow_detected_home: false,
        })
        .map_err(|_| RuntimeError::Storage)?
        .pop()
        .ok_or(RuntimeError::Authorization)?;
    let report = adapter.probe(&install).map_err(|_| RuntimeError::Probe)?;
    Ok(ProbeData {
        adapter_id: report.adapter_id,
        executable_version: report.executable_version,
        schema_fingerprint: report.schema_fingerprint,
        capabilities: report
            .capabilities
            .into_iter()
            .map(|capability| format!("{capability:?}"))
            .collect(),
        quarantine_reason: report.quarantine_reason,
    })
}

pub fn probe_grok_build() -> Result<ProbeData, RuntimeError> {
    let root = detected_grok_build_home().ok_or(RuntimeError::Authorization)?;
    let adapter = GrokBuildAdapter::new(&root).map_err(|_| RuntimeError::Storage)?;
    let install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![root],
            allow_detected_home: false,
        })
        .map_err(|_| RuntimeError::Storage)?
        .pop()
        .ok_or(RuntimeError::Authorization)?;
    let report = adapter.probe(&install).map_err(|_| RuntimeError::Probe)?;
    Ok(ProbeData {
        adapter_id: report.adapter_id,
        executable_version: report.executable_version,
        schema_fingerprint: report.schema_fingerprint,
        capabilities: report
            .capabilities
            .into_iter()
            .map(|capability| format!("{capability:?}"))
            .collect(),
        quarantine_reason: report.quarantine_reason,
    })
}

pub fn scan_codex(root: &Path, data_root: &Path) -> Result<ScanReport, RuntimeError> {
    let executable = resolve_codex_executable();
    let adapter =
        CodexAdapter::with_executable(root, executable).map_err(|_| RuntimeError::Storage)?;
    let mut install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![root.to_path_buf()],
            allow_detected_home: false,
        })
        .map_err(|_| RuntimeError::Storage)?
        .pop()
        .ok_or(RuntimeError::Authorization)?;
    let probe = adapter.probe(&install).map_err(|_| RuntimeError::Probe)?;
    if probe.quarantine_reason.is_some() {
        return Err(RuntimeError::Probe);
    }
    install.executable_version = probe.executable_version;
    install.schema_fingerprint = probe.schema_fingerprint;
    install.capabilities = probe
        .capabilities
        .into_iter()
        .map(|capability| format!("{capability:?}"))
        .collect();
    let (cas, index, keys_store) = open_storage(data_root)?;
    let _ = keys_store;
    let mut service = ScanService::new(
        adapter,
        cas,
        index,
        SecretScanner::v1().map_err(|_| RuntimeError::Storage)?,
    );
    service
        .run(ScanRequest {
            install,
            snapshot_hint: None,
        })
        .map_err(RuntimeError::App)
}

pub fn scan_claude(root: &Path, data_root: &Path) -> Result<ScanReport, RuntimeError> {
    let adapter = ClaudeCodeAdapter::new(root).map_err(|_| RuntimeError::Storage)?;
    let mut install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![root.to_path_buf()],
            allow_detected_home: false,
        })
        .map_err(|_| RuntimeError::Storage)?
        .pop()
        .ok_or(RuntimeError::Authorization)?;
    let probe = adapter.probe(&install).map_err(|_| RuntimeError::Probe)?;
    if probe.quarantine_reason.is_some() {
        return Err(RuntimeError::Probe);
    }
    install.executable_version = probe.executable_version;
    install.schema_fingerprint = probe.schema_fingerprint;
    install.capabilities = probe
        .capabilities
        .into_iter()
        .map(|capability| format!("{capability:?}"))
        .collect();
    let (cas, index, keys_store) = open_storage(data_root)?;
    let _ = keys_store;
    let mut service = ScanService::new(
        adapter,
        cas,
        index,
        SecretScanner::v1().map_err(|_| RuntimeError::Storage)?,
    );
    service
        .run(ScanRequest {
            install,
            snapshot_hint: None,
        })
        .map_err(RuntimeError::App)
}

pub fn scan_hermes(root: &Path, data_root: &Path) -> Result<ScanReport, RuntimeError> {
    let adapter = HermesAdapter::new(root).map_err(|_| RuntimeError::Storage)?;
    let mut install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![root.to_path_buf()],
            allow_detected_home: false,
        })
        .map_err(|_| RuntimeError::Storage)?
        .pop()
        .ok_or(RuntimeError::Authorization)?;
    let probe = adapter.probe(&install).map_err(|_| RuntimeError::Probe)?;
    install.executable_version = probe.executable_version;
    install.schema_fingerprint = probe.schema_fingerprint;
    install.capabilities = probe
        .capabilities
        .into_iter()
        .map(|capability| format!("{capability:?}"))
        .collect();
    let (cas, index, keys_store) = open_storage(data_root)?;
    let _ = keys_store;
    let mut service = ScanService::new(
        adapter,
        cas,
        index,
        SecretScanner::v1().map_err(|_| RuntimeError::Storage)?,
    );
    service
        .run(ScanRequest {
            install,
            snapshot_hint: None,
        })
        .map_err(RuntimeError::App)
}

pub fn scan_openclaw(root: &Path, data_root: &Path) -> Result<ScanReport, RuntimeError> {
    let adapter = OpenClawAdapter::new(root).map_err(|_| RuntimeError::Storage)?;
    let mut install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![root.to_path_buf()],
            allow_detected_home: false,
        })
        .map_err(|_| RuntimeError::Storage)?
        .pop()
        .ok_or(RuntimeError::Authorization)?;
    let probe = adapter.probe(&install).map_err(|_| RuntimeError::Probe)?;
    install.executable_version = probe.executable_version;
    install.schema_fingerprint = probe.schema_fingerprint;
    install.capabilities = probe
        .capabilities
        .into_iter()
        .map(|capability| format!("{capability:?}"))
        .collect();
    let (cas, index, keys_store) = open_storage(data_root)?;
    let _ = keys_store;
    let mut service = ScanService::new(
        adapter,
        cas,
        index,
        SecretScanner::v1().map_err(|_| RuntimeError::Storage)?,
    );
    service
        .run(ScanRequest {
            install,
            snapshot_hint: None,
        })
        .map_err(RuntimeError::App)
}

pub fn scan_opencode(root: &Path, data_root: &Path) -> Result<ScanReport, RuntimeError> {
    let adapter = OpenCodeAdapter::new(root).map_err(|_| RuntimeError::Storage)?;
    let mut install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![root.to_path_buf()],
            allow_detected_home: false,
        })
        .map_err(|_| RuntimeError::Storage)?
        .pop()
        .ok_or(RuntimeError::Authorization)?;
    let probe = adapter.probe(&install).map_err(|_| RuntimeError::Probe)?;
    if probe.quarantine_reason.is_some() {
        return Err(RuntimeError::Probe);
    }
    install.executable_version = probe.executable_version;
    install.schema_fingerprint = probe.schema_fingerprint;
    install.capabilities = probe
        .capabilities
        .into_iter()
        .map(|capability| format!("{capability:?}"))
        .collect();
    let (cas, index, keys_store) = open_storage(data_root)?;
    let _ = keys_store;
    let mut service = ScanService::new(
        adapter,
        cas,
        index,
        SecretScanner::v1().map_err(|_| RuntimeError::Storage)?,
    );
    service
        .run(ScanRequest {
            install,
            snapshot_hint: None,
        })
        .map_err(RuntimeError::App)
}

pub fn scan_grok_build(root: &Path, data_root: &Path) -> Result<ScanReport, RuntimeError> {
    let adapter = GrokBuildAdapter::new(root).map_err(|_| RuntimeError::Storage)?;
    let mut install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![root.to_path_buf()],
            allow_detected_home: false,
        })
        .map_err(|_| RuntimeError::Storage)?
        .pop()
        .ok_or(RuntimeError::Authorization)?;
    let probe = adapter.probe(&install).map_err(|_| RuntimeError::Probe)?;
    install.executable_version = probe.executable_version;
    install.schema_fingerprint = probe.schema_fingerprint;
    install.capabilities = probe
        .capabilities
        .into_iter()
        .map(|capability| format!("{capability:?}"))
        .collect();
    let (cas, index, keys_store) = open_storage(data_root)?;
    let _ = keys_store;
    let mut service = ScanService::new(
        adapter,
        cas,
        index,
        SecretScanner::v1().map_err(|_| RuntimeError::Storage)?,
    );
    service
        .run(ScanRequest {
            install,
            snapshot_hint: None,
        })
        .map_err(RuntimeError::App)
}

pub fn list_sessions(
    root: &Path,
    limit: u32,
    offset: u32,
) -> Result<Vec<agentark_index::SessionSummary>, RuntimeError> {
    let (_cas, index, _store) = open_storage_existing(root)?;
    index
        .list_sessions(limit, offset)
        .map_err(|_| RuntimeError::Storage)
}

pub fn show_session(
    root: &Path,
    id: Uuid,
) -> Result<agentark_app::PublicSessionDetail, RuntimeError> {
    let (_cas, index, _store) = open_storage_existing(root)?;
    let detail = index.show_session(id).map_err(|_| RuntimeError::Storage)?;
    let scanner = SecretScanner::v1().map_err(|_| RuntimeError::Storage)?;
    Ok(agentark_app::PublicSessionDetail {
        id: detail.session.id,
        title: detail
            .session
            .title
            .as_deref()
            .map(|value| scanner.sanitize(value).text),
        archived: detail.session.archived,
        completeness: detail.session.completeness,
        messages: detail
            .session
            .messages
            .into_iter()
            .map(|message| {
                let text = scanner.sanitize(&message.visible_text()).text;
                agentark_app::PublicMessage {
                    ordinal: message.ordinal,
                    role: message.role,
                    text,
                }
            })
            .collect(),
        tool_events: detail
            .session
            .tool_events
            .into_iter()
            .map(|event| agentark_app::PublicToolEvent {
                ordinal: event.ordinal,
                tool_name: event.tool_name,
                status: event.status,
                visible_input: event
                    .visible_input
                    .as_deref()
                    .map(|value| scanner.sanitize(value).text),
                visible_output: event
                    .visible_output
                    .as_deref()
                    .map(|value| scanner.sanitize(value).text),
            })
            .collect(),
    })
}

pub fn search(
    root: &Path,
    query: &str,
    limit: u32,
) -> Result<Vec<agentark_index::SearchHit>, RuntimeError> {
    let (_cas, index, _store) = open_storage_existing(root)?;
    index
        .search(query, limit)
        .map_err(|_| RuntimeError::Storage)
}

pub fn verify(
    root: &Path,
    scan_id: Uuid,
) -> Result<agentark_app::VerificationReport, RuntimeError> {
    let (cas, index, _store) = open_storage_existing(root)?;
    VerificationService::new(cas, index)
        .verify_scan(scan_id)
        .map_err(RuntimeError::App)
}

fn open_storage(root: &Path) -> Result<(EncryptedCas, IndexDb, OsMasterKeyStore), RuntimeError> {
    fs::create_dir_all(root).map_err(|_| RuntimeError::Storage)?;
    let bootstrap_path = root.join("bootstrap.json");
    let machine_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, root.to_string_lossy().as_bytes());
    let store = OsMasterKeyStore::new(machine_id).map_err(|_| RuntimeError::Storage)?;
    let bootstrap = if bootstrap_path.is_file() {
        serde_json::from_slice(&fs::read(&bootstrap_path).map_err(|_| RuntimeError::Storage)?)
            .map_err(|_| RuntimeError::Storage)?
    } else {
        let bootstrap =
            DatasetBootstrap::create(Uuid::new_v4(), &store).map_err(|_| RuntimeError::Storage)?;
        fs::write(
            &bootstrap_path,
            serde_json::to_vec_pretty(&bootstrap).map_err(|_| RuntimeError::Storage)?,
        )
        .map_err(|_| RuntimeError::Storage)?;
        bootstrap
    };
    let keys = bootstrap
        .unlock(&store)
        .map_err(|_| RuntimeError::Storage)?;
    let cas = EncryptedCas::open(root.join("cas"), &keys).map_err(|_| RuntimeError::Storage)?;
    let index = IndexDb::open(&root.join("index.db"), keys.sqlcipher_key())
        .map_err(|_| RuntimeError::Storage)?;
    Ok((cas, index, store))
}

fn open_storage_existing(
    root: &Path,
) -> Result<(EncryptedCas, IndexDb, OsMasterKeyStore), RuntimeError> {
    if !root.join("bootstrap.json").is_file() {
        return Err(RuntimeError::NotInitialized);
    }
    open_storage(root)
}

fn resolve_codex_executable() -> PathBuf {
    if let Some(path) = std::env::var_os("AGENTARK_CODEX_BIN") {
        return PathBuf::from(path);
    }
    if let Some(app_data) = std::env::var_os("APPDATA") {
        let npm_dir = PathBuf::from(app_data).join("npm");
        for candidate in ["codex.opencodex-real.cmd", "codex.cmd"] {
            let path = npm_dir.join(candidate);
            if path.is_file() {
                return path;
            }
        }
    }
    let directories =
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect::<Vec<_>>();
    for candidate in ["codex.cmd", "codex.exe", "codex"] {
        for directory in &directories {
            let path = directory.join(candidate);
            if path.is_file() {
                return path;
            }
        }
    }
    PathBuf::from("codex")
}
