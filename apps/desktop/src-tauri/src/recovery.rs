use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use agentark_adapter_codex::{
    CodexContinuationReport, CodexContinuationRequest, NativeImportError, NativePayloadError,
    NativeRestoreReport, NativeRolloutPayload, ensure_codex_not_running,
    fork_rollout_with_target_provider, native_thread_expectation, restore_native_rollouts,
    rewrite_native_workspace_paths, verify_rollouts_with_app_server, write_rollout_atomic,
};
use agentark_canonical::{CanonicalSession, Sha256Digest};
use agentark_migration::{
    ProviderIdentity, RestoreOutcome, TargetRecoveryCapabilities, decide_recovery,
};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct RecoveryInput {
    pub session: CanonicalSession,
    pub native_payload: Option<NativeRolloutPayload>,
    pub workspace_mappings: Vec<(String, String)>,
    pub codex_home: PathBuf,
    pub executable: PathBuf,
    pub backup_root: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    MissingProvider,
    Verification,
    Conflict,
    Unavailable,
}

impl RecoveryError {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::MissingProvider => "missing-provider",
            Self::Verification => "verification-failed",
            Self::Conflict => "target-conflict",
            Self::Unavailable => "recovery-unavailable",
        }
    }
}

pub trait CodexRecoveryExecutor {
    fn try_native_identity(
        &self,
        input: &RecoveryInput,
    ) -> Result<NativeRestoreReport, RecoveryError>;

    fn create_continuation(
        &self,
        input: &RecoveryInput,
    ) -> Result<CodexContinuationReport, RecoveryError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutomaticRecoveryReport {
    pub outcome: RestoreOutcome,
    pub source_native_id: Option<String>,
    pub target_native_id: Option<String>,
    pub source_provider: ProviderIdentity,
    pub target_provider: Option<ProviderIdentity>,
    pub source_hash: Sha256Digest,
    pub target_hash: Option<Sha256Digest>,
    pub reason_code: String,
    pub rollback_paths: Vec<PathBuf>,
}

pub fn recover_one_codex_session(
    executor: &dyn CodexRecoveryExecutor,
    input: &RecoveryInput,
) -> AutomaticRecoveryReport {
    let source_provider = ProviderIdentity::new(
        input.session.model_provider.clone(),
        input.session.model_name.clone(),
    );
    let source_hash = input
        .native_payload
        .as_ref()
        .map(|payload| payload.source_hash.clone())
        .unwrap_or_else(|| {
            Sha256Digest::from_bytes(&serde_json::to_vec(&input.session).unwrap_or_default())
        });
    let source_native_id = Some(input.session.source_session_id.clone());

    let Some(payload) = input.native_payload.as_ref() else {
        let decision = decide_recovery(
            source_provider,
            TargetRecoveryCapabilities {
                native_identity_verified: false,
                continuation_writer_verified: false,
                target_default: None,
            },
        );
        return AutomaticRecoveryReport {
            outcome: decision.outcome,
            source_native_id,
            target_native_id: None,
            source_provider: decision.source_provider,
            target_provider: decision.target_provider,
            source_hash,
            target_hash: None,
            reason_code: "native-payload-unavailable".into(),
            rollback_paths: Vec::new(),
        };
    };

    match executor.try_native_identity(input) {
        Ok(native) => {
            let target_native_id = native
                .mappings
                .iter()
                .find(|(canonical_id, _)| canonical_id == &input.session.id.to_string())
                .map(|(_, native_id)| native_id.clone())
                .or_else(|| source_native_id.clone());
            let target_hash =
                rewrite_native_workspace_paths(&payload.bytes, &input.workspace_mappings)
                    .ok()
                    .map(|bytes| Sha256Digest::from_bytes(&bytes));
            let decision = decide_recovery(
                source_provider.clone(),
                TargetRecoveryCapabilities {
                    native_identity_verified: true,
                    continuation_writer_verified: false,
                    target_default: Some(source_provider),
                },
            );
            return AutomaticRecoveryReport {
                outcome: decision.outcome,
                source_native_id,
                target_native_id,
                source_provider: decision.source_provider,
                target_provider: decision.target_provider,
                source_hash,
                target_hash,
                reason_code: decision.reason_code,
                rollback_paths: native.written_paths,
            };
        }
        Err(native_error) => match executor.create_continuation(input) {
            Ok(continuation) => {
                let target_provider = ProviderIdentity::new(
                    Some(continuation.model_provider.clone()),
                    Some(continuation.model.clone()),
                );
                let decision = decide_recovery(
                    source_provider,
                    TargetRecoveryCapabilities {
                        native_identity_verified: false,
                        continuation_writer_verified: true,
                        target_default: Some(target_provider),
                    },
                );
                let target_hash = fs::read(&continuation.rollout_path)
                    .ok()
                    .map(|bytes| Sha256Digest::from_bytes(&bytes));
                AutomaticRecoveryReport {
                    outcome: decision.outcome,
                    source_native_id,
                    target_native_id: Some(continuation.target_thread_id),
                    source_provider: decision.source_provider,
                    target_provider: decision.target_provider,
                    source_hash,
                    target_hash,
                    reason_code: decision.reason_code,
                    rollback_paths: vec![continuation.rollout_path],
                }
            }
            Err(continuation_error) => {
                let decision = decide_recovery(
                    source_provider,
                    TargetRecoveryCapabilities {
                        native_identity_verified: false,
                        continuation_writer_verified: false,
                        target_default: None,
                    },
                );
                AutomaticRecoveryReport {
                    outcome: decision.outcome,
                    source_native_id,
                    target_native_id: None,
                    source_provider: decision.source_provider,
                    target_provider: decision.target_provider,
                    source_hash,
                    target_hash: None,
                    reason_code: format!(
                        "continuation-{}-after-native-{}",
                        continuation_error.reason_code(),
                        native_error.reason_code()
                    ),
                    rollback_paths: Vec::new(),
                }
            }
        },
    }
}

pub struct ProductionCodexRecoveryExecutor {
    write_guard: OnceLock<Result<(), RecoveryError>>,
}

impl ProductionCodexRecoveryExecutor {
    pub fn new() -> Self {
        Self {
            write_guard: OnceLock::new(),
        }
    }

    fn ensure_vendor_write_allowed(&self) -> Result<(), RecoveryError> {
        *self
            .write_guard
            .get_or_init(|| ensure_codex_not_running().map_err(map_native_import_error))
    }
}

impl Default for ProductionCodexRecoveryExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl CodexRecoveryExecutor for ProductionCodexRecoveryExecutor {
    fn try_native_identity(
        &self,
        input: &RecoveryInput,
    ) -> Result<NativeRestoreReport, RecoveryError> {
        if input.codex_home.as_os_str().is_empty() || !input.codex_home.is_dir() {
            return Err(RecoveryError::Unavailable);
        }
        let payload = input
            .native_payload
            .as_ref()
            .ok_or(RecoveryError::Unavailable)?;
        let rewritten = rewrite_native_workspace_paths(&payload.bytes, &input.workspace_mappings)
            .map_err(map_native_payload_error)?;
        let expectation =
            native_thread_expectation(&rewritten).map_err(map_native_payload_error)?;
        self.ensure_vendor_write_allowed()?;
        let report = restore_native_rollouts(
            &input.codex_home,
            std::slice::from_ref(payload),
            &input.workspace_mappings,
            &input.backup_root,
        )
        .map_err(map_native_payload_error)?;
        let destination = input
            .codex_home
            .join("sessions")
            .join(&payload.relative_path);
        if let Err(error) = verify_rollouts_with_app_server(
            &input.executable,
            &input.codex_home,
            &[(destination, expectation)],
        ) {
            for path in &report.written_paths {
                let _ = fs::remove_file(path);
            }
            return Err(map_native_import_error(error));
        }
        Ok(report)
    }

    fn create_continuation(
        &self,
        input: &RecoveryInput,
    ) -> Result<CodexContinuationReport, RecoveryError> {
        if input.codex_home.as_os_str().is_empty() || !input.codex_home.is_dir() {
            return Err(RecoveryError::Unavailable);
        }
        self.ensure_vendor_write_allowed()?;
        create_continuation_with(input, |_staged, request| {
            fork_rollout_with_target_provider(&input.executable, &input.codex_home, request)
                .map_err(map_native_import_error)
        })
    }
}

fn create_continuation_with<F>(
    input: &RecoveryInput,
    fork: F,
) -> Result<CodexContinuationReport, RecoveryError>
where
    F: FnOnce(&Path, &CodexContinuationRequest) -> Result<CodexContinuationReport, RecoveryError>,
{
    let payload = input
        .native_payload
        .as_ref()
        .ok_or(RecoveryError::Unavailable)?;
    let rewritten = rewrite_native_workspace_paths(&payload.bytes, &input.workspace_mappings)
        .map_err(map_native_payload_error)?;
    let expectation = native_thread_expectation(&rewritten).map_err(map_native_payload_error)?;
    let staging_directory = input
        .codex_home
        .join("sessions")
        .join(format!(".agentark-staging-{}", Uuid::new_v4()));
    let staged_source = staging_directory.join("source.jsonl");
    let operation = (|| {
        write_rollout_atomic(&staged_source, std::slice::from_ref(&rewritten))
            .map_err(map_native_import_error)?;
        let target_cwd = input
            .session
            .workspace
            .as_ref()
            .map(|workspace| PathBuf::from(&workspace.path_native))
            .unwrap_or_else(|| PathBuf::from(&expectation.cwd));
        let request = CodexContinuationRequest {
            source_rollout: staged_source.clone(),
            source_thread_id: expectation.thread_id,
            target_cwd,
            target_provider: None,
            target_model: None,
        };
        fork(&staged_source, &request)
    })();
    let cleanup = match fs::remove_file(&staged_source) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RecoveryError::Unavailable),
    };
    let _ = fs::remove_dir(&staging_directory);
    cleanup?;
    operation
}

fn map_native_payload_error(error: NativePayloadError) -> RecoveryError {
    match error {
        NativePayloadError::Conflict => RecoveryError::Conflict,
        NativePayloadError::Json(_) | NativePayloadError::InvalidPath => {
            RecoveryError::Verification
        }
        NativePayloadError::Io(_) => RecoveryError::Unavailable,
        NativePayloadError::NativeImport(error) => map_native_import_error(error),
    }
}

fn map_native_import_error(error: NativeImportError) -> RecoveryError {
    match error {
        NativeImportError::Invalid(_) | NativeImportError::Verification(_) => {
            RecoveryError::Verification
        }
        NativeImportError::Io(_)
        | NativeImportError::Json(_)
        | NativeImportError::UnsupportedVersion
        | NativeImportError::CodexRunning => RecoveryError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Mutex;

    use agentark_canonical::{
        CanonicalMessage, CanonicalSchemaVersion, Completeness, Sha256Digest,
    };
    use uuid::Uuid;

    use super::*;

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("agentark-staging-{}", Uuid::new_v4()));
            fs::create_dir_all(path.join("sessions")).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn input(root: &Path) -> RecoveryInput {
        let session_id = Uuid::from_u128(1);
        let native_id = "source-native-id";
        let bytes = format!(
            "{{\"type\":\"session_meta\",\"payload\":{{\"session_id\":\"{native_id}\",\"cwd\":\"C:/fixture\"}}}}\n"
        )
        .into_bytes();
        RecoveryInput {
            session: CanonicalSession {
                schema_version: CanonicalSchemaVersion::V0_1_0,
                id: session_id,
                install_id: Uuid::from_u128(2),
                source_session_id: native_id.into(),
                source_kind: "codex".into(),
                workspace: None,
                title: None,
                archived: false,
                created_at_raw: None,
                updated_at_raw: None,
                model_provider: Some("source-provider".into()),
                model_name: Some("source-model".into()),
                completeness: Completeness::Complete,
                messages: vec![CanonicalMessage::text_fixture(1, "fixture", "sanitized")],
                tool_events: Vec::new(),
                attachments: Vec::new(),
                raw_extra: Default::default(),
            },
            native_payload: Some(NativeRolloutPayload {
                session_id,
                relative_path: "2026/08/23/rollout-source.jsonl".into(),
                source_hash: Sha256Digest::from_bytes(&bytes),
                bytes,
                redaction_count: 0,
            }),
            workspace_mappings: Vec::new(),
            codex_home: root.to_path_buf(),
            executable: PathBuf::from("fake-codex"),
            backup_root: root.join("backups"),
        }
    }

    #[test]
    fn continuation_staging_source_is_removed_after_fork_success() {
        let root = TempRoot::new();
        let staged = Mutex::new(None::<PathBuf>);
        let result = create_continuation_with(&input(&root.0), |path, request| {
            assert!(path.is_file());
            *staged.lock().unwrap() = Some(path.to_path_buf());
            Ok(CodexContinuationReport {
                source_thread_id: request.source_thread_id.clone(),
                target_thread_id: "target-native-id".into(),
                rollout_path: root.0.join("sessions/target.jsonl"),
                model_provider: "target-provider".into(),
                model: "target-model".into(),
                visible_turns: 1,
            })
        });
        assert!(result.is_ok());
        assert!(!staged.lock().unwrap().as_ref().unwrap().exists());
    }

    #[test]
    fn continuation_staging_source_is_removed_after_fork_error() {
        let root = TempRoot::new();
        let staged = Mutex::new(None::<PathBuf>);
        let result = create_continuation_with(&input(&root.0), |path, _| {
            assert!(path.is_file());
            *staged.lock().unwrap() = Some(path.to_path_buf());
            Err(RecoveryError::Verification)
        });
        assert_eq!(result.unwrap_err(), RecoveryError::Verification);
        assert!(!staged.lock().unwrap().as_ref().unwrap().exists());
    }
}
