#![forbid(unsafe_code)]

mod adapter;
mod error;
mod filesystem;
mod normalize;
mod probe;
mod process;
mod protocol;

pub use adapter::CodexAdapter;
pub use error::CodexError;
pub use filesystem::{
    capture_jsonl_file, collect_jsonl_paths, split_complete_jsonl_prefix, tree_digest,
};
pub use normalize::{
    normalize_thread_read, normalize_thread_read_bytes, normalize_thread_read_bytes_for_install,
};
pub use probe::{CODEX_SCHEMA_SHA256, CODEX_VERSION, CodexProbe, parse_version};
pub use process::ProcessTransport;
pub use protocol::{JsonRpcTransport, MAX_JSON_LINE, RawJsonRpc, ReadOnlyAppServerClient};
