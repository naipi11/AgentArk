#![forbid(unsafe_code)]

mod adapter;
mod error;
mod filesystem;
mod native_import;
mod native_payload;
mod normalize;
mod probe;
mod process;
mod process_guard;
mod protocol;

pub use adapter::CodexAdapter;
pub use error::CodexError;
pub use filesystem::{
    capture_jsonl_file, collect_jsonl_paths, split_complete_jsonl_prefix, tree_digest,
};
pub use native_import::{
    CodexContinuationReport, CodexContinuationRequest, CodexTargetDefault,
    CodexTargetSessionExpectation, NativeCapability, NativeImportError, NativeThreadExpectation,
    backup_codex_targets, delete_thread_with_app_server, delete_thread_with_app_server_guarded,
    delete_thread_with_app_server_transport, delete_thread_with_app_server_transport_guarded,
    fork_rollout_with_target_provider, fork_rollout_with_target_provider_guarded,
    fork_rollout_with_target_provider_transport,
    fork_rollout_with_target_provider_transport_guarded, native_import_capability_from_outputs,
    probe_target_default, probe_target_default_transport, verify_rollout_with_app_server,
    verify_rollouts_with_app_server, verify_target_session, verify_target_session_transport,
    verify_thread_listing, write_rollout_atomic, write_rollout_atomic_guarded,
    write_rollout_atomic_with_guarded_operations, write_rollout_atomic_with_operations,
    write_rollout_atomic_with_reader,
};
pub use native_payload::{
    CanonicalContinuationSource, CodexVisibleHistory, CodexVisibleHistoryExpectation,
    CodexVisibleMessage, CodexVisibleRole, NativePayloadError, NativeRestoreReport,
    NativeRolloutPayload, build_canonical_continuation_source, canonical_visible_history,
    collect_native_rollouts, native_thread_expectation, restore_native_rollouts,
    restore_native_rollouts_guarded, rewrite_native_workspace_paths, sanitize_rollout_bytes,
};
pub use normalize::{
    normalize_thread_read, normalize_thread_read_bytes, normalize_thread_read_bytes_for_install,
};
pub use probe::{CODEX_SCHEMA_SHA256, CODEX_VERSION, CodexProbe, parse_version};
pub use process::ProcessTransport;
pub use process_guard::{
    ensure_codex_not_running, ensure_codex_not_running_excluding,
    ensure_codex_not_running_from_snapshot, ensure_codex_not_running_from_snapshot_excluding,
};
pub use protocol::{
    AGENTARK_APP_SERVER_CLIENT_VERSION, JsonRpcTransport, MAX_JSON_LINE, RawJsonRpc,
    ReadOnlyAppServerClient,
};
