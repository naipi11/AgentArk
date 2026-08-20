#[derive(Debug, thiserror::Error)]
pub enum CasError {
    #[error("CAS I/O operation failed")]
    Io(#[from] std::io::Error),
    #[error("CAS object has an invalid format")]
    InvalidFormat,
    #[error("CAS object authentication failed")]
    AuthenticationFailed,
    #[error("CAS object hash does not match")]
    HashMismatch,
    #[error("CAS object collision")]
    ObjectCollision,
    #[error("CAS object type is unsupported")]
    UnsupportedObjectType,
}
