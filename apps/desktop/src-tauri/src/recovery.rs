use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use agentark_adapter_codex::{
    CodexContinuationReport, CodexContinuationRequest, CodexProbe, NativeImportError,
    NativePayloadError, NativeRestoreReport, NativeRolloutPayload, delete_thread_with_app_server,
    ensure_codex_not_running, fork_rollout_with_target_provider, native_thread_expectation,
    restore_native_rollouts, rewrite_native_workspace_paths, verify_rollouts_with_app_server,
    write_rollout_atomic,
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
    Rollback,
    ManualIntervention,
}

impl RecoveryError {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::MissingProvider => "missing-provider",
            Self::Verification => "verification-failed",
            Self::Conflict => "target-conflict",
            Self::Unavailable => "recovery-unavailable",
            Self::Rollback => "rollback-required",
            Self::ManualIntervention => "manual-intervention-required",
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

    fn rollback(
        &self,
        input: &RecoveryInput,
        report: &AutomaticRecoveryReport,
    ) -> Result<(), RecoveryError>;

    fn native_attempt_summary(&self) -> NativeAttemptSummary {
        NativeAttemptSummary::default()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NativeAttemptSummary {
    pub skipped_count: u64,
    pub conflict_count: u64,
    pub backup_path: Option<PathBuf>,
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
    pub native_skipped_count: u64,
    pub native_conflict_count: u64,
    pub native_backup_path: Option<PathBuf>,
    pub requires_manual_intervention: bool,
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
            native_skipped_count: 0,
            native_conflict_count: 0,
            native_backup_path: None,
            requires_manual_intervention: false,
        };
    };

    let native_result = executor.try_native_identity(input);
    let native_summary = executor.native_attempt_summary();
    match native_result {
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
                native_skipped_count: native.skipped_count,
                native_conflict_count: native.conflict_count,
                native_backup_path: native.backup_path,
                requires_manual_intervention: false,
            };
        }
        Err(native_error @ (RecoveryError::Rollback | RecoveryError::ManualIntervention)) => {
            let mut report = archive_only_recovery_report(input, native_error.reason_code());
            report.source_provider = source_provider;
            report.native_skipped_count = native_summary.skipped_count;
            report.native_conflict_count = native_summary.conflict_count;
            report.native_backup_path = native_summary.backup_path;
            report.requires_manual_intervention = true;
            report
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
                    native_skipped_count: native_summary.skipped_count,
                    native_conflict_count: native_summary
                        .conflict_count
                        .max(u64::from(native_error == RecoveryError::Conflict)),
                    native_backup_path: native_summary.backup_path,
                    requires_manual_intervention: false,
                }
            }
            Err(
                continuation_error @ (RecoveryError::Rollback | RecoveryError::ManualIntervention),
            ) => {
                let mut report =
                    archive_only_recovery_report(input, continuation_error.reason_code());
                report.source_provider = source_provider;
                report.native_skipped_count = native_summary.skipped_count;
                report.native_conflict_count = native_summary
                    .conflict_count
                    .max(u64::from(native_error == RecoveryError::Conflict));
                report.native_backup_path = native_summary.backup_path;
                report.requires_manual_intervention = true;
                report
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
                    native_skipped_count: native_summary.skipped_count,
                    native_conflict_count: native_summary
                        .conflict_count
                        .max(u64::from(native_error == RecoveryError::Conflict)),
                    native_backup_path: native_summary.backup_path,
                    requires_manual_intervention: false,
                }
            }
        },
    }
}

pub fn archive_only_recovery_report(
    input: &RecoveryInput,
    reason_code: &str,
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
    AutomaticRecoveryReport {
        outcome: RestoreOutcome::ArchiveOnly,
        source_native_id: Some(input.session.source_session_id.clone()),
        target_native_id: None,
        source_provider,
        target_provider: None,
        source_hash,
        target_hash: None,
        reason_code: reason_code.into(),
        rollback_paths: Vec::new(),
        native_skipped_count: 0,
        native_conflict_count: 0,
        native_backup_path: None,
        requires_manual_intervention: false,
    }
}

pub struct ProductionCodexRecoveryExecutor {
    write_guard: OnceLock<Result<(), RecoveryError>>,
    preflight: Arc<dyn CodexRecoveryPreflight>,
    native_summary: Mutex<NativeAttemptSummary>,
}

#[doc(hidden)]
pub trait CodexRecoveryPreflight: Send + Sync {
    fn ensure_not_running(&self) -> Result<(), RecoveryError>;
    fn probe(&self, executable: &Path) -> Result<(), RecoveryError>;
}

struct SystemCodexRecoveryPreflight;

impl CodexRecoveryPreflight for SystemCodexRecoveryPreflight {
    fn ensure_not_running(&self) -> Result<(), RecoveryError> {
        ensure_codex_not_running().map_err(map_native_import_error)
    }

    fn probe(&self, executable: &Path) -> Result<(), RecoveryError> {
        let report = CodexProbe::run(executable).map_err(|_| RecoveryError::Unavailable)?;
        if report.quarantine_reason.is_some() {
            return Err(RecoveryError::Unavailable);
        }
        Ok(())
    }
}

impl ProductionCodexRecoveryExecutor {
    pub fn new() -> Self {
        Self {
            write_guard: OnceLock::new(),
            preflight: Arc::new(SystemCodexRecoveryPreflight),
            native_summary: Mutex::new(NativeAttemptSummary::default()),
        }
    }

    #[doc(hidden)]
    pub fn with_preflight(preflight: Arc<dyn CodexRecoveryPreflight>) -> Self {
        Self {
            write_guard: OnceLock::new(),
            preflight,
            native_summary: Mutex::new(NativeAttemptSummary::default()),
        }
    }

    fn ensure_vendor_write_allowed(&self, executable: &Path) -> Result<(), RecoveryError> {
        *self.write_guard.get_or_init(|| {
            self.preflight.ensure_not_running()?;
            self.preflight.probe(executable)
        })
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
        *self
            .native_summary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = NativeAttemptSummary::default();
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
        self.ensure_vendor_write_allowed(&input.executable)?;
        let report = match restore_native_rollouts(
            &input.codex_home,
            std::slice::from_ref(payload),
            &input.workspace_mappings,
            &input.backup_root,
        ) {
            Ok(report) => report,
            Err(error) => {
                if matches!(error, NativePayloadError::Conflict) {
                    self.native_summary
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .conflict_count = 1;
                }
                return Err(map_native_payload_error(error));
            }
        };
        *self
            .native_summary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = NativeAttemptSummary {
            skipped_count: report.skipped_count,
            conflict_count: report.conflict_count,
            backup_path: report.backup_path.clone(),
        };
        let destination = input
            .codex_home
            .join("sessions")
            .join(&payload.relative_path);
        if let Err(error) = verify_rollouts_with_app_server(
            &input.executable,
            &input.codex_home,
            &[(destination, expectation)],
        ) {
            cleanup_native_paths(&report.written_paths, |path| fs::remove_file(path))?;
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
        self.ensure_vendor_write_allowed(&input.executable)?;
        create_continuation_with_operations(
            input,
            |_staged, request| {
                fork_rollout_with_target_provider(&input.executable, &input.codex_home, request)
                    .map_err(map_native_import_error)
            },
            remove_staged_source,
            |report| {
                delete_thread_with_app_server(
                    &input.executable,
                    &input.codex_home,
                    &report.target_thread_id,
                )
                .map_err(|_| RecoveryError::ManualIntervention)
            },
        )
    }

    fn rollback(
        &self,
        input: &RecoveryInput,
        report: &AutomaticRecoveryReport,
    ) -> Result<(), RecoveryError> {
        match report.outcome {
            RestoreOutcome::NativeIdentity => {
                cleanup_native_paths(&report.rollback_paths, |path| fs::remove_file(path))
            }
            RestoreOutcome::Continuation => {
                let target_thread_id = report
                    .target_native_id
                    .as_deref()
                    .ok_or(RecoveryError::ManualIntervention)?;
                delete_thread_with_app_server(
                    &input.executable,
                    &input.codex_home,
                    target_thread_id,
                )
                .map_err(|_| RecoveryError::ManualIntervention)
            }
            RestoreOutcome::ArchiveOnly => Ok(()),
        }
    }

    fn native_attempt_summary(&self) -> NativeAttemptSummary {
        self.native_summary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
fn create_continuation_with<F>(
    input: &RecoveryInput,
    fork: F,
) -> Result<CodexContinuationReport, RecoveryError>
where
    F: FnOnce(&Path, &CodexContinuationRequest) -> Result<CodexContinuationReport, RecoveryError>,
{
    create_continuation_with_operations(input, fork, remove_staged_source, |_report| Ok(()))
}

fn create_continuation_with_operations<F, C, R>(
    input: &RecoveryInput,
    fork: F,
    cleanup: C,
    rollback: R,
) -> Result<CodexContinuationReport, RecoveryError>
where
    F: FnOnce(&Path, &CodexContinuationRequest) -> Result<CodexContinuationReport, RecoveryError>,
    C: FnOnce(&Path) -> Result<(), RecoveryError>,
    R: FnOnce(&CodexContinuationReport) -> Result<(), RecoveryError>,
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
    let cleanup_result = cleanup(&staged_source);
    match (operation, cleanup_result) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(error), Ok(())) => Err(error),
        (Ok(report), Err(_)) => match rollback(&report) {
            Ok(()) | Err(_) => Err(RecoveryError::ManualIntervention),
        },
        (Err(_), Err(_)) => Err(RecoveryError::ManualIntervention),
    }
}

fn remove_staged_source(path: &Path) -> Result<(), RecoveryError> {
    let parent = path.parent().ok_or(RecoveryError::Rollback)?;
    let file_cleanup = match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RecoveryError::Rollback),
    };
    let directory_cleanup = match fs::remove_dir_all(parent) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RecoveryError::Rollback),
    };
    match (file_cleanup, directory_cleanup) {
        (_, Ok(())) => Ok(()),
        (Ok(()), Err(error)) | (Err(error), Err(_)) => Err(error),
    }
}

fn cleanup_native_paths<F>(paths: &[PathBuf], remove: F) -> Result<(), RecoveryError>
where
    F: Fn(&Path) -> std::io::Result<()>,
{
    let mut cleanup_failed = false;
    for path in paths {
        if let Err(error) = remove(path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            cleanup_failed = true;
        }
    }
    if cleanup_failed {
        Err(RecoveryError::ManualIntervention)
    } else {
        Ok(())
    }
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
        NativeImportError::Rollback => RecoveryError::ManualIntervention,
        NativeImportError::ManualIntervention => RecoveryError::ManualIntervention,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

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

    struct RejectingProbe {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl CodexRecoveryPreflight for RejectingProbe {
        fn ensure_not_running(&self) -> Result<(), RecoveryError> {
            self.events.lock().unwrap().push("process-check");
            Ok(())
        }

        fn probe(&self, _executable: &Path) -> Result<(), RecoveryError> {
            self.events.lock().unwrap().push("version-probe");
            Err(RecoveryError::Unavailable)
        }
    }

    #[test]
    fn unsupported_probe_rejects_before_native_writer() {
        let root = TempRoot::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let executor = ProductionCodexRecoveryExecutor::with_preflight(Arc::new(RejectingProbe {
            events: Arc::clone(&events),
        }));
        let input = input(&root.0);

        assert_eq!(
            executor.try_native_identity(&input).unwrap_err(),
            RecoveryError::Unavailable
        );
        assert_eq!(
            executor.try_native_identity(&input).unwrap_err(),
            RecoveryError::Unavailable
        );
        assert_eq!(*events.lock().unwrap(), ["process-check", "version-probe"]);
        assert!(!input.backup_root.exists());
        assert!(
            !input
                .codex_home
                .join("sessions")
                .join(
                    input
                        .native_payload
                        .as_ref()
                        .unwrap()
                        .relative_path
                        .as_str()
                )
                .exists()
        );
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

    #[test]
    fn staging_cleanup_failure_rolls_back_successful_fork() {
        let root = TempRoot::new();
        let rollback_calls = AtomicUsize::new(0);
        let result = create_continuation_with_operations(
            &input(&root.0),
            |_path, request| {
                Ok(CodexContinuationReport {
                    source_thread_id: request.source_thread_id.clone(),
                    target_thread_id: "target-native-id".into(),
                    rollout_path: root.0.join("sessions/target.jsonl"),
                    model_provider: "target-provider".into(),
                    model: "target-model".into(),
                    visible_turns: 1,
                })
            },
            |_path| Err(RecoveryError::Rollback),
            |_report| {
                rollback_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        assert_eq!(result.unwrap_err(), RecoveryError::ManualIntervention);
        assert_eq!(rollback_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn staging_cleanup_removes_owned_nonempty_directory() {
        let root = TempRoot::new();
        let staging = root.0.join("sessions/.agentark-staging-fixture");
        let source = staging.join("source.jsonl");
        fs::create_dir_all(&staging).unwrap();
        fs::write(&source, b"source").unwrap();
        fs::write(staging.join("extra.tmp"), b"extra").unwrap();

        remove_staged_source(&source).unwrap();

        assert!(!staging.exists());
    }

    #[test]
    fn failed_native_path_cleanup_requires_manual_intervention() {
        let root = TempRoot::new();
        let path = root.0.join("sessions/native.jsonl");
        fs::write(&path, b"fixture").unwrap();

        let result = cleanup_native_paths(std::slice::from_ref(&path), |_path| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "fixture",
            ))
        });

        assert_eq!(result.unwrap_err(), RecoveryError::ManualIntervention);
    }
}
