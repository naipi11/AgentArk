#[derive(Debug, thiserror::Error)]
pub enum CodexError {
    #[error("Codex process I/O failed")]
    Io(#[from] std::io::Error),
    #[error("Codex probe timed out")]
    Timeout,
    #[error("Codex executable output is invalid")]
    InvalidOutput,
    #[error("Codex version is unsupported")]
    UnsupportedVersion,
    #[error("Codex App Server JSON is malformed")]
    MalformedJson,
    #[error("Codex App Server JSON line is oversized")]
    OversizedLine,
    #[error("Codex App Server ended the stream")]
    EndOfStream,
    #[error("Codex App Server protocol error")]
    Protocol,
    #[error("Codex source record is retryable: {0}")]
    Retryable(&'static str),
    #[error("Codex source changed during capture")]
    SourceChanged,
}
