use std::sync::{Arc, Mutex};

use agentark_app::{AppError, AppServices, QueryUseCase, ScanUseCase, VerifyUseCase};

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
}
