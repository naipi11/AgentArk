use std::fs;
use std::path::{Path, PathBuf};

use agentark_adapter_codex::{CodexAdapter, CodexProbe};
use agentark_adapter_sdk::{DetectContext, SourceAdapter};
use agentark_app::{AppError, ScanReport, ScanRequest, ScanService, VerificationService};
use agentark_cas::EncryptedCas;
use agentark_index::{IndexDb, SessionQuery};
use agentark_security::{DatasetBootstrap, OsMasterKeyStore, SecretScanner};
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

pub fn doctor(root: &Path) -> DoctorData {
    DoctorData {
        dataset_state: if root.join("bootstrap.json").is_file() {
            "ready"
        } else {
            "notInitialized"
        },
    }
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
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        for candidate in ["codex.cmd", "codex.exe", "codex"] {
            let path = directory.join(candidate);
            if path.is_file() {
                return path;
            }
        }
    }
    PathBuf::from("codex")
}
