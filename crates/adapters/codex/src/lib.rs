#![forbid(unsafe_code)]

mod error;
mod probe;
mod process;
mod protocol;

pub use error::CodexError;
pub use probe::{CODEX_SCHEMA_SHA256, CODEX_VERSION, CodexProbe, parse_version};
pub use process::ProcessTransport;
pub use protocol::{JsonRpcTransport, MAX_JSON_LINE, RawJsonRpc, ReadOnlyAppServerClient};
