use agentark_adapter_sdk::AdapterError;
use agentark_canonical::CanonicalHashError;
use agentark_cas::CasError;
use agentark_index::IndexError;
use agentark_security::SecurityError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("adapter operation failed")]
    Adapter(#[from] AdapterError),
    #[error("encrypted archive operation failed")]
    Cas(#[from] CasError),
    #[error("index operation failed")]
    Index(#[from] IndexError),
    #[error("security projection operation failed")]
    Security(#[from] SecurityError),
    #[error("canonical hash operation failed")]
    Canonical(#[from] CanonicalHashError),
    #[error("serialization operation failed")]
    Serialization(#[from] serde_json::Error),
    #[error("application invariant violated: {0}")]
    Invariant(String),
}
