use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentark_adapter_codex::{CodexContinuationReport, NativeRestoreReport};
use agentark_bundle::{NativeBundleEntry, write_selected_sessions_with_native};
use agentark_canonical::{
    AgentKind, CanonicalMessage, CanonicalSchemaVersion, CanonicalSession, Completeness,
};
use agentark_desktop_lib::recovery::{
    CodexRecoveryExecutor, NativeAttemptSummary, RecoveryError, RecoveryInput,
};
use agentark_desktop_lib::{AppState, RestoreMappingWriter};
use agentark_index::{IndexDb, RestoreMapping};
use agentark_security::SecretScanner;
use uuid::Uuid;

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("agentark-{label}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum NativeScript {
    Success,
    MissingProvider,
    ManualIntervention,
    VerificationWithBackup,
}

#[derive(Clone, Copy)]
enum ContinuationScript {
    Success,
    Unavailable,
    ManualIntervention,
}

struct FakeExecutor {
    native: Mutex<VecDeque<NativeScript>>,
    continuation: Mutex<VecDeque<ContinuationScript>>,
    vendor_writes: AtomicUsize,
    continuation_calls: AtomicUsize,
    rollback_calls: AtomicUsize,
    rollback_fails: bool,
    native_summary: Mutex<NativeAttemptSummary>,
}

impl FakeExecutor {
    fn native_success(self) -> Self {
        self.native.lock().unwrap().push_back(NativeScript::Success);
        self
    }

    fn native_missing_provider(self) -> Self {
        self.native
            .lock()
            .unwrap()
            .push_back(NativeScript::MissingProvider);
        self
    }

    fn native_manual_intervention(self) -> Self {
        self.native
            .lock()
            .unwrap()
            .push_back(NativeScript::ManualIntervention);
        self
    }

    fn native_verification_with_backup(self) -> Self {
        self.native
            .lock()
            .unwrap()
            .push_back(NativeScript::VerificationWithBackup);
        self
    }

    fn continuation_success(self) -> Self {
        self.continuation
            .lock()
            .unwrap()
            .push_back(ContinuationScript::Success);
        self
    }

    fn continuation_unavailable(self) -> Self {
        self.continuation
            .lock()
            .unwrap()
            .push_back(ContinuationScript::Unavailable);
        self
    }

    fn continuation_manual_intervention(self) -> Self {
        self.continuation
            .lock()
            .unwrap()
            .push_back(ContinuationScript::ManualIntervention);
        self
    }

    fn vendor_write_count(&self) -> usize {
        self.vendor_writes.load(Ordering::SeqCst)
    }

    fn continuation_call_count(&self) -> usize {
        self.continuation_calls.load(Ordering::SeqCst)
    }

    fn rollback_failure(mut self) -> Self {
        self.rollback_fails = true;
        self
    }

    fn rollback_call_count(&self) -> usize {
        self.rollback_calls.load(Ordering::SeqCst)
    }
}

impl CodexRecoveryExecutor for FakeExecutor {
    fn try_native_identity(
        &self,
        input: &RecoveryInput,
    ) -> Result<NativeRestoreReport, RecoveryError> {
        match self.native.lock().unwrap().pop_front().unwrap() {
            NativeScript::Success => {
                self.vendor_writes.fetch_add(1, Ordering::SeqCst);
                Ok(NativeRestoreReport {
                    imported_count: 1,
                    skipped_count: 2,
                    conflict_count: 0,
                    backup_path: Some(input.backup_root.join("fake-native")),
                    mappings: vec![(
                        input.session.id.to_string(),
                        input.session.source_session_id.clone(),
                    )],
                    written_paths: vec![input.codex_home.join("sessions/fake-native.jsonl")],
                    restart_required: true,
                })
            }
            NativeScript::MissingProvider => Err(RecoveryError::MissingProvider),
            NativeScript::ManualIntervention => Err(RecoveryError::Rollback),
            NativeScript::VerificationWithBackup => {
                *self.native_summary.lock().unwrap() = NativeAttemptSummary {
                    skipped_count: 0,
                    conflict_count: 1,
                    backup_path: Some(input.backup_root.join("failed-native-backup")),
                };
                Err(RecoveryError::Verification)
            }
        }
    }

    fn create_continuation(
        &self,
        input: &RecoveryInput,
    ) -> Result<CodexContinuationReport, RecoveryError> {
        self.continuation_calls.fetch_add(1, Ordering::SeqCst);
        match self.continuation.lock().unwrap().pop_front().unwrap() {
            ContinuationScript::Success => {
                self.vendor_writes.fetch_add(1, Ordering::SeqCst);
                let target_thread_id = format!("continued-{}", input.session.source_session_id);
                Ok(CodexContinuationReport {
                    source_thread_id: input.session.source_session_id.clone(),
                    target_thread_id,
                    rollout_path: input.codex_home.join("sessions/fake-continuation.jsonl"),
                    model_provider: "target-default-provider".into(),
                    model: "target-default-model".into(),
                    visible_turns: input.session.messages.len(),
                })
            }
            ContinuationScript::Unavailable => Err(RecoveryError::Unavailable),
            ContinuationScript::ManualIntervention => Err(RecoveryError::ManualIntervention),
        }
    }

    fn rollback(
        &self,
        _input: &RecoveryInput,
        _report: &agentark_desktop_lib::recovery::AutomaticRecoveryReport,
    ) -> Result<(), RecoveryError> {
        self.rollback_calls.fetch_add(1, Ordering::SeqCst);
        if self.rollback_fails {
            Err(RecoveryError::ManualIntervention)
        } else {
            Ok(())
        }
    }

    fn native_attempt_summary(&self) -> NativeAttemptSummary {
        self.native_summary.lock().unwrap().clone()
    }
}

fn fake_executor() -> FakeExecutor {
    FakeExecutor {
        native: Mutex::new(VecDeque::new()),
        continuation: Mutex::new(VecDeque::new()),
        vendor_writes: AtomicUsize::new(0),
        continuation_calls: AtomicUsize::new(0),
        rollback_calls: AtomicUsize::new(0),
        rollback_fails: false,
        native_summary: Mutex::new(NativeAttemptSummary::default()),
    }
}

fn session(id: u128, native_id: &str) -> CanonicalSession {
    let session_id = Uuid::from_u128(id);
    let mut message =
        CanonicalMessage::text_fixture(1, &session_id.to_string(), "sanitized fixture");
    message.id = Uuid::new_v5(&session_id, b"fixture-message");
    CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id: session_id,
        install_id: Uuid::from_u128(100),
        source_session_id: native_id.into(),
        source_kind: "app-server".into(),
        workspace: None,
        title: Some(format!("fixture {id}")),
        archived: false,
        created_at_raw: None,
        updated_at_raw: None,
        model_provider: Some("source-provider".into()),
        model_name: Some("source-model".into()),
        completeness: Completeness::Complete,
        messages: vec![message],
        tool_events: Vec::new(),
        attachments: Vec::new(),
        raw_extra: Default::default(),
    }
}

fn payload(session: &CanonicalSession) -> NativeBundleEntry {
    let bytes = format!(
        "{{\"type\":\"session_meta\",\"payload\":{{\"session_id\":\"{}\",\"cwd\":\"C:/fixture\"}}}}\n",
        session.source_session_id
    )
    .into_bytes();
    NativeBundleEntry {
        session_id: session.id,
        relative_path: format!("2026/08/23/rollout-{}.jsonl", session.source_session_id),
        bytes,
        redaction_count: 0,
    }
}

fn restore_with(executor: &FakeExecutor) -> Result<agentark_desktop_lib::BundleReport, String> {
    restore_sessions_with(executor, vec![session(1, "native-one")])
}

fn restore_sessions_with(
    executor: &FakeExecutor,
    sessions: Vec<CanonicalSession>,
) -> Result<agentark_desktop_lib::BundleReport, String> {
    restore_fixture(executor, sessions, "codex", true).map(|fixture| fixture.report)
}

struct RestoredFixture {
    _root: TempRoot,
    state: AppState,
    report: agentark_desktop_lib::BundleReport,
    session_ids: Vec<Uuid>,
}

fn restore_fixture(
    executor: &FakeExecutor,
    sessions: Vec<CanonicalSession>,
    agent: &str,
    include_payloads: bool,
) -> Result<RestoredFixture, String> {
    restore_fixture_with_writer(executor, sessions, agent, include_payloads, None)
}

fn restore_fixture_with_writer(
    executor: &FakeExecutor,
    sessions: Vec<CanonicalSession>,
    agent: &str,
    include_payloads: bool,
    mapping_writer: Option<&dyn RestoreMappingWriter>,
) -> Result<RestoredFixture, String> {
    let root = TempRoot::new("provider-independent-restore");
    let data_root = root.path().join("data");
    let codex_home = root.path().join("codex-home");
    fs::create_dir_all(codex_home.join("sessions")).unwrap();
    let bundle_path = root.path().join("fixture.ahbundle");
    let payloads = if include_payloads {
        sessions.iter().map(payload).collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let scanner = SecretScanner::v1().unwrap();
    write_selected_sessions_with_native(&bundle_path, agent, &sessions, &[], &payloads, &scanner)
        .unwrap();
    let state = AppState::for_data_root(data_root);
    let report = match mapping_writer {
        Some(mapping_writer) => state.bundle_restore_with_executor_and_mapping_writer(
            bundle_path,
            executor,
            mapping_writer,
            codex_home.clone(),
            PathBuf::from("fake-codex"),
            codex_home.join("agentark-backups"),
        )?,
        None => state.bundle_restore_with_executor(
            bundle_path,
            executor,
            codex_home.clone(),
            PathBuf::from("fake-codex"),
            codex_home.join("agentark-backups"),
        )?,
    };
    Ok(RestoredFixture {
        _root: root,
        state,
        report,
        session_ids: sessions.iter().map(|session| session.id).collect(),
    })
}

#[test]
fn compatible_payload_retains_original_id() {
    let executor = fake_executor().native_success();
    let report = restore_with(&executor).unwrap();
    assert_eq!(report.native_identity_count, 1);
    assert_eq!(report.continuation_count, 0);
    assert_eq!(report.archive_only_count, 0);
    assert_eq!(report.manual_intervention_count, 0);
    assert_eq!(report.native_skipped_count, 2);
    assert!(
        report
            .native_backup_path
            .as_deref()
            .unwrap()
            .ends_with("fake-native")
    );
}

#[test]
fn missing_source_provider_falls_back_to_target_default_continuation() {
    let executor = fake_executor()
        .native_missing_provider()
        .continuation_success();
    let report = restore_with(&executor).unwrap();
    assert_eq!(report.native_identity_count, 0);
    assert_eq!(report.continuation_count, 1);
    assert_eq!(report.archive_only_count, 0);
}

#[test]
fn unverified_target_stays_archive_only_without_vendor_write() {
    let executor = fake_executor()
        .native_missing_provider()
        .continuation_unavailable();
    let report = restore_with(&executor).unwrap();
    assert_eq!(report.archive_only_count, 1);
    assert_eq!(executor.vendor_write_count(), 0);
}

#[test]
fn archive_only_session_does_not_skip_later_continuation_or_mapping() {
    let executor = fake_executor()
        .native_missing_provider()
        .native_missing_provider()
        .continuation_unavailable()
        .continuation_success();
    let fixture = restore_fixture(
        &executor,
        vec![session(1, "native-one"), session(2, "native-two")],
        "codex",
        true,
    )
    .unwrap();
    let report = &fixture.report;
    assert_eq!(report.archive_only_count, 1);
    assert_eq!(report.continuation_count, 1);
    assert_eq!(report.restore_mapping_count, 2);
    for session_id in fixture.session_ids {
        assert_eq!(
            fixture
                .state
                .restore_mappings_for(session_id)
                .unwrap()
                .len(),
            1
        );
    }
}

#[test]
fn non_codex_bundle_records_archive_only_mapping_for_every_session() {
    let fixture = restore_fixture(
        &fake_executor(),
        vec![session(1, "claude-one"), session(2, "claude-two")],
        "claude-code",
        false,
    )
    .unwrap();
    assert_eq!(fixture.report.archive_only_count, 2);
    assert_eq!(fixture.report.restore_mapping_count, 2);
    for session_id in fixture.session_ids {
        let mappings = fixture.state.restore_mappings_for(session_id).unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].target_agent, AgentKind::ClaudeCode);
        assert_eq!(mappings[0].reason_code, "target-recovery-unavailable");
    }
}

#[test]
fn all_agent_bundle_uses_safe_source_agent_mapping_and_unavailable_reason() {
    let fixture = restore_fixture(
        &fake_executor(),
        vec![session(1, "native-one")],
        "all",
        false,
    )
    .unwrap();
    let mappings = fixture
        .state
        .restore_mappings_for(fixture.session_ids[0])
        .unwrap();

    assert_eq!(fixture.report.archive_only_count, 1);
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].target_agent, AgentKind::Codex);
    assert_eq!(mappings[0].reason_code, "target-agent-unavailable");
}

#[test]
fn native_rollback_failure_requires_manual_intervention_without_continuation() {
    let executor = fake_executor().native_manual_intervention();
    let fixture =
        restore_fixture(&executor, vec![session(1, "native-one")], "codex", true).unwrap();
    let report = &fixture.report;
    assert_eq!(report.native_identity_count, 0);
    assert_eq!(report.continuation_count, 0);
    assert_eq!(report.archive_only_count, 0);
    assert_eq!(report.manual_intervention_count, 1);
    assert_eq!(report.restore_mapping_count, 0);
    assert_eq!(executor.continuation_call_count(), 0);
    assert_eq!(
        report.recovery_error.as_deref(),
        Some("manual-intervention-required")
    );
    assert!(
        fixture
            .state
            .restore_mappings_for(fixture.session_ids[0])
            .unwrap()
            .is_empty()
    );
}

struct FailingMappingWriter;

impl RestoreMappingWriter for FailingMappingWriter {
    fn record(&self, _index: &mut IndexDb, _mapping: &RestoreMapping) -> Result<(), String> {
        Err("fixture-mapping-failure".into())
    }
}

#[test]
fn mapping_persistence_failure_rolls_back_and_is_not_counted_as_success() {
    let executor = fake_executor().native_success();
    let fixture = restore_fixture_with_writer(
        &executor,
        vec![session(1, "native-one")],
        "codex",
        true,
        Some(&FailingMappingWriter),
    )
    .unwrap();

    assert_eq!(executor.rollback_call_count(), 1);
    assert_eq!(fixture.report.native_identity_count, 0);
    assert_eq!(fixture.report.continuation_count, 0);
    assert_eq!(fixture.report.archive_only_count, 1);
    assert_eq!(fixture.report.restore_mapping_count, 0);
    assert_eq!(
        fixture.report.recovery_error.as_deref(),
        Some("restore-mapping-persistence-failed")
    );
    assert!(
        fixture
            .state
            .restore_mappings_for(fixture.session_ids[0])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn mapping_persistence_and_rollback_failure_requires_manual_intervention() {
    let executor = fake_executor().native_success().rollback_failure();
    let fixture = restore_fixture_with_writer(
        &executor,
        vec![session(1, "native-one")],
        "codex",
        true,
        Some(&FailingMappingWriter),
    )
    .unwrap();

    assert_eq!(fixture.report.native_identity_count, 0);
    assert_eq!(fixture.report.archive_only_count, 0);
    assert_eq!(fixture.report.manual_intervention_count, 1);
    assert_eq!(
        fixture.report.recovery_error.as_deref(),
        Some("manual-intervention-required")
    );
}

#[test]
fn failed_native_attempt_preserves_conflict_and_backup_metrics_after_continuation() {
    let executor = fake_executor()
        .native_verification_with_backup()
        .continuation_success();
    let report = restore_with(&executor).unwrap();

    assert_eq!(report.continuation_count, 1);
    assert_eq!(report.native_conflict_count, 1);
    assert!(
        report
            .native_backup_path
            .as_deref()
            .unwrap()
            .ends_with("failed-native-backup")
    );
}

#[test]
fn failed_continuation_rollback_reports_manual_intervention() {
    let executor = fake_executor()
        .native_missing_provider()
        .continuation_manual_intervention();
    let fixture =
        restore_fixture(&executor, vec![session(1, "native-one")], "codex", true).unwrap();
    let report = &fixture.report;

    assert_eq!(report.continuation_count, 0);
    assert_eq!(report.archive_only_count, 0);
    assert_eq!(report.manual_intervention_count, 1);
    assert_eq!(report.restore_mapping_count, 0);
    assert_eq!(
        report.recovery_error.as_deref(),
        Some("manual-intervention-required")
    );
    assert!(
        fixture
            .state
            .restore_mappings_for(fixture.session_ids[0])
            .unwrap()
            .is_empty()
    );
}
