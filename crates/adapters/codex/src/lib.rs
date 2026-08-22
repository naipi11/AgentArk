#![forbid(unsafe_code)]

mod adapter;
mod error;
mod filesystem;
mod native_import;
mod native_payload;
mod normalize;
mod probe;
mod process;
mod protocol;

pub use adapter::CodexAdapter;
pub use error::CodexError;
pub use filesystem::{
    capture_jsonl_file, collect_jsonl_paths, split_complete_jsonl_prefix, tree_digest,
};
pub use native_import::{
    NativeCapability, NativeImportError, NativeThreadExpectation, backup_codex_targets,
    ensure_codex_not_running, ensure_codex_not_running_from_tasklist,
    native_import_capability_from_outputs, verify_rollout_with_app_server,
    verify_rollouts_with_app_server, verify_thread_listing, write_rollout_atomic,
};
pub use native_payload::{
    NativePayloadError, NativeRestoreReport, NativeRolloutPayload, collect_native_rollouts,
    native_thread_expectation, restore_native_rollouts, rewrite_native_workspace_paths,
    sanitize_rollout_bytes,
};
pub use normalize::{
    normalize_thread_read, normalize_thread_read_bytes, normalize_thread_read_bytes_for_install,
};
pub use probe::{CODEX_SCHEMA_SHA256, CODEX_VERSION, CodexProbe, parse_version};
pub use process::ProcessTransport;
pub use protocol::{JsonRpcTransport, MAX_JSON_LINE, RawJsonRpc, ReadOnlyAppServerClient};
