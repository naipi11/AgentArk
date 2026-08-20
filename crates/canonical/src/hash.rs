use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error)]
pub enum CanonicalHashError {
    #[error("canonical serialization failed")]
    Serialization(#[from] serde_json::Error),
}

pub fn canonical_hash<T: Serialize>(
    entity_type: &str,
    value: &T,
) -> Result<Sha256Digest, CanonicalHashError> {
    let canonical = serde_jcs::to_vec(value)?;
    let mut input = format!("agentark:v1:{entity_type}:").into_bytes();
    input.extend_from_slice(&canonical);
    Ok(Sha256Digest::from_bytes(&input))
}
