#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("index I/O operation failed")]
    Io(#[from] std::io::Error),
    #[error("index database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("index serialization failed")]
    Serialization(#[from] serde_json::Error),
    #[error("index build lacks required SQLCipher or FTS5 support")]
    UnsupportedStorageBuild,
    #[error("index invariant violation")]
    InvariantViolation,
    #[error("index entity was not found")]
    NotFound,
    #[error("index query is empty")]
    InvalidQuery,
}
