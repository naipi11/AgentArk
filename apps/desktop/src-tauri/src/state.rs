use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agentark_app::{
    AppError, AppServices, LockedIndexQueryService, QueryUseCase, ScanUseCase, VerifyUseCase,
};
use agentark_index::IndexDb;
use agentark_security::{DatasetBootstrap, OsMasterKeyStore};
use directories::ProjectDirs;

pub struct AppState {
    pub services: Arc<Mutex<AppServices>>,
}

struct EmptyUseCase;
impl ScanUseCase for EmptyUseCase {}
impl VerifyUseCase for EmptyUseCase {}

struct EmptyQuery;
impl QueryUseCase for EmptyQuery {
    fn status(&self) -> Result<agentark_app::StatusDto, AppError> {
        Ok(agentark_app::StatusDto {
            dataset_state: "notInitialized".into(),
            adapter_id: None,
            executable_version: None,
            schema_fingerprint: None,
            capabilities: Vec::new(),
            quarantine_reason: None,
        })
    }

    fn list_sessions(
        &self,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<agentark_index::SessionSummary>, AppError> {
        Ok(Vec::new())
    }

    fn show_session(&self, _id: uuid::Uuid) -> Result<agentark_app::PublicSessionDetail, AppError> {
        Err(AppError::Invariant("session is not available".into()))
    }

    fn search(
        &self,
        _query: &str,
        _limit: u32,
    ) -> Result<Vec<agentark_index::SearchHit>, AppError> {
        Ok(Vec::new())
    }

    fn list_quarantines(&self) -> Result<Vec<agentark_app::QuarantineDto>, AppError> {
        Ok(Vec::new())
    }
}

impl AppState {
    pub fn empty() -> Self {
        Self {
            services: Arc::new(Mutex::new(AppServices {
                scanner: Box::new(EmptyUseCase),
                verifier: Box::new(EmptyUseCase),
                queries: Box::new(EmptyQuery),
            })),
        }
    }

    pub fn open_default() -> Self {
        let Some(index) = open_index(&default_data_dir()) else {
            return Self::empty();
        };
        Self {
            services: Arc::new(Mutex::new(AppServices {
                scanner: Box::new(EmptyUseCase),
                verifier: Box::new(EmptyUseCase),
                queries: Box::new(LockedIndexQueryService::new(index)),
            })),
        }
    }
}

fn default_data_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("AGENTARK_DATA_DIR") {
        return PathBuf::from(path);
    }
    ProjectDirs::from("dev", "AgentArk", "AgentArk")
        .map(|dirs| dirs.data_local_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".agentark-data"))
}

fn open_index(root: &Path) -> Option<IndexDb> {
    let bootstrap_path = root.join("bootstrap.json");
    if !bootstrap_path.is_file() {
        return None;
    }
    let bootstrap: DatasetBootstrap =
        serde_json::from_slice(&std::fs::read(bootstrap_path).ok()?).ok()?;
    let machine_id = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        root.to_string_lossy().as_bytes(),
    );
    let store = OsMasterKeyStore::new(machine_id).ok()?;
    let keys = bootstrap.unlock(&store).ok()?;
    IndexDb::open(&root.join("index.db"), keys.sqlcipher_key()).ok()
}
