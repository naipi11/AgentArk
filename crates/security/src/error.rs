#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("source root is not authorized")]
    RootNotAuthorized,
    #[error("path class is forbidden: {0}")]
    ForbiddenPathClass(&'static str),
    #[error("path escapes the authorized root")]
    PathEscape,
    #[error("source is not a regular file")]
    NotRegularFile,
    #[error("path is not valid UTF-8")]
    NonUtf8Path,
    #[error("security I/O operation failed")]
    Io(#[from] std::io::Error),
    #[error("secret rule set is invalid")]
    SecretRuleInvalid,
}
