use agentark_canonical::{CanonicalRole, Completeness};
use agentark_index::{SearchHit, SessionQuery, SessionSummary};
use agentark_security::SecretScanner;
use serde::Serialize;
use std::sync::Mutex;
use uuid::Uuid;

use crate::AppError;

pub struct AppServices {
    pub scanner: Box<dyn ScanUseCase>,
    pub verifier: Box<dyn VerifyUseCase>,
    pub queries: Box<dyn QueryUseCase>,
}

pub trait ScanUseCase: Send + Sync {}
pub trait VerifyUseCase: Send + Sync {}

pub trait QueryUseCase: Send + Sync {
    fn status(&self) -> Result<StatusDto, AppError>;
    fn list_sessions(&self, limit: u32, offset: u32) -> Result<Vec<SessionSummary>, AppError>;
    fn show_session(&self, id: Uuid) -> Result<PublicSessionDetail, AppError>;
    fn search(&self, query: &str, limit: u32) -> Result<Vec<SearchHit>, AppError>;
    fn list_quarantines(&self) -> Result<Vec<QuarantineDto>, AppError>;
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusDto {
    pub dataset_state: String,
    pub adapter_id: Option<String>,
    pub executable_version: Option<String>,
    pub schema_fingerprint: Option<String>,
    pub capabilities: Vec<String>,
    pub quarantine_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicSessionDetail {
    pub id: Uuid,
    pub title: Option<String>,
    pub archived: bool,
    pub completeness: Completeness,
    pub messages: Vec<PublicMessage>,
    pub tool_events: Vec<PublicToolEvent>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicMessage {
    pub ordinal: u64,
    pub role: CanonicalRole,
    pub text: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicToolEvent {
    pub ordinal: u64,
    pub tool_name: String,
    pub status: String,
    pub visible_input: Option<String>,
    pub visible_output: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineDto {
    pub reason_code: String,
    pub fingerprint: String,
    pub sanitized_locator: String,
}

pub struct IndexQueryService<I> {
    index: I,
    scanner: SecretScanner,
}

pub struct LockedIndexQueryService<I> {
    index: Mutex<I>,
    scanner: SecretScanner,
}

impl<I> LockedIndexQueryService<I> {
    pub fn new(index: I) -> Self {
        Self {
            index: Mutex::new(index),
            scanner: SecretScanner::v1().expect("built-in secret rules are valid"),
        }
    }
}

impl<I> IndexQueryService<I> {
    pub fn new(index: I) -> Self {
        Self {
            index,
            scanner: SecretScanner::v1().expect("built-in secret rules are valid"),
        }
    }
}

impl<I: SessionQuery + Send + Sync> QueryUseCase for IndexQueryService<I> {
    fn status(&self) -> Result<StatusDto, AppError> {
        Ok(StatusDto {
            dataset_state: "ready".into(),
            adapter_id: None,
            executable_version: None,
            schema_fingerprint: None,
            capabilities: Vec::new(),
            quarantine_reason: None,
        })
    }

    fn list_sessions(&self, limit: u32, offset: u32) -> Result<Vec<SessionSummary>, AppError> {
        Ok(self.index.list_sessions(limit, offset)?)
    }

    fn show_session(&self, id: Uuid) -> Result<PublicSessionDetail, AppError> {
        public_detail_from_index(&self.index, &self.scanner, id)
    }

    fn search(&self, query: &str, limit: u32) -> Result<Vec<SearchHit>, AppError> {
        Ok(self.index.search(query, limit)?)
    }

    fn list_quarantines(&self) -> Result<Vec<QuarantineDto>, AppError> {
        Ok(self
            .index
            .list_quarantines()?
            .into_iter()
            .map(|item| QuarantineDto {
                reason_code: item.reason_code,
                fingerprint: item.fingerprint,
                sanitized_locator: item.sanitized_locator,
            })
            .collect())
    }
}

impl<I: SessionQuery + Send> QueryUseCase for LockedIndexQueryService<I> {
    fn status(&self) -> Result<StatusDto, AppError> {
        Ok(StatusDto {
            dataset_state: "ready".into(),
            adapter_id: None,
            executable_version: None,
            schema_fingerprint: None,
            capabilities: Vec::new(),
            quarantine_reason: None,
        })
    }

    fn list_sessions(&self, limit: u32, offset: u32) -> Result<Vec<SessionSummary>, AppError> {
        self.index
            .lock()
            .map_err(|_| AppError::Invariant("query state is poisoned".into()))?
            .list_sessions(limit, offset)
            .map_err(AppError::from)
    }

    fn show_session(&self, id: Uuid) -> Result<PublicSessionDetail, AppError> {
        let guard = self
            .index
            .lock()
            .map_err(|_| AppError::Invariant("query state is poisoned".into()))?;
        public_detail_from_index(&*guard, &self.scanner, id)
    }

    fn search(&self, query: &str, limit: u32) -> Result<Vec<SearchHit>, AppError> {
        self.index
            .lock()
            .map_err(|_| AppError::Invariant("query state is poisoned".into()))?
            .search(query, limit)
            .map_err(AppError::from)
    }

    fn list_quarantines(&self) -> Result<Vec<QuarantineDto>, AppError> {
        let rows = self
            .index
            .lock()
            .map_err(|_| AppError::Invariant("query state is poisoned".into()))?
            .list_quarantines()?;
        Ok(rows
            .into_iter()
            .map(|item| QuarantineDto {
                reason_code: item.reason_code,
                fingerprint: item.fingerprint,
                sanitized_locator: item.sanitized_locator,
            })
            .collect())
    }
}

fn public_detail_from_index<I: SessionQuery>(
    index: &I,
    scanner: &SecretScanner,
    id: Uuid,
) -> Result<PublicSessionDetail, AppError> {
    let detail = index.show_session(id)?;
    let title = detail
        .session
        .title
        .as_deref()
        .map(|value| scanner.sanitize(value).text);
    Ok(PublicSessionDetail {
        id: detail.session.id,
        title,
        archived: detail.session.archived,
        completeness: detail.session.completeness,
        messages: detail
            .session
            .messages
            .into_iter()
            .map(|message| {
                let text = scanner.sanitize(&message.visible_text()).text;
                PublicMessage {
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
            .map(|event| PublicToolEvent {
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
