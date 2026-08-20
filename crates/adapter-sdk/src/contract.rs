use std::collections::BTreeSet;

use agentark_canonical::AgentInstall;
use thiserror::Error;

use crate::types::{
    CaptureBatch, CaptureRequest, CapturedRecord, DetectContext, NormalizeOutcome, ProbeReport,
    SourceCapability,
};

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("adapter source I/O failed")]
    Io(#[from] std::io::Error),
    #[error("adapter source security policy rejected the operation")]
    Security(#[from] agentark_security::SecurityError),
    #[error("adapter data is invalid: {0}")]
    InvalidData(String),
    #[error("adapter contract violation: {0}")]
    ContractViolation(String),
}

pub trait SourceAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn detect(&self, ctx: &DetectContext) -> Result<Vec<AgentInstall>, AdapterError>;
    fn probe(&self, install: &AgentInstall) -> Result<ProbeReport, AdapterError>;
    fn capture(&self, request: &CaptureRequest) -> Result<CaptureBatch, AdapterError>;
    fn normalize(&self, record: &CapturedRecord) -> Result<NormalizeOutcome, AdapterError>;
    fn capabilities(&self, install: &AgentInstall) -> BTreeSet<SourceCapability>;
}
