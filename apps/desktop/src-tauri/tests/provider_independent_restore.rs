use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentark_adapter_codex::{CodexContinuationReport, NativeRestoreReport};
use agentark_bundle::{NativeBundleEntry, write_selected_sessions_with_native};
use agentark_canonical::{
    CanonicalMessage, CanonicalSchemaVersion, CanonicalSession, Completeness,
};
use agentark_desktop_lib::AppState;
use agentark_desktop_lib::recovery::{CodexRecoveryExecutor, RecoveryError, RecoveryInput};
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
}

#[derive(Clone, Copy)]
enum ContinuationScript {
    Success,
    Unavailable,
}

struct FakeExecutor {
    native: Mutex<VecDeque<NativeScript>>,
    continuation: Mutex<VecDeque<ContinuationScript>>,
    vendor_writes: AtomicUsize,
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

    fn vendor_write_count(&self) -> usize {
        self.vendor_writes.load(Ordering::SeqCst)
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
                    skipped_count: 0,
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
        }
    }

    fn create_continuation(
        &self,
        input: &RecoveryInput,
    ) -> Result<CodexContinuationReport, RecoveryError> {
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
        }
    }
}

fn fake_executor() -> FakeExecutor {
    FakeExecutor {
        native: Mutex::new(VecDeque::new()),
        continuation: Mutex::new(VecDeque::new()),
        vendor_writes: AtomicUsize::new(0),
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
        source_kind: "codex".into(),
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
    let root = TempRoot::new("provider-independent-restore");
    let data_root = root.path().join("data");
    let codex_home = root.path().join("codex-home");
    fs::create_dir_all(codex_home.join("sessions")).unwrap();
    let bundle_path = root.path().join("fixture.ahbundle");
    let payloads = sessions.iter().map(payload).collect::<Vec<_>>();
    let scanner = SecretScanner::v1().unwrap();
    write_selected_sessions_with_native(&bundle_path, "codex", &sessions, &[], &payloads, &scanner)
        .unwrap();
    AppState::for_data_root(data_root).bundle_restore_with_executor(
        bundle_path,
        executor,
        codex_home.clone(),
        PathBuf::from("fake-codex"),
        codex_home.join("agentark-backups"),
    )
}

#[test]
fn compatible_payload_retains_original_id() {
    let executor = fake_executor().native_success();
    let report = restore_with(&executor).unwrap();
    assert_eq!(report.native_identity_count, 1);
    assert_eq!(report.continuation_count, 0);
    assert_eq!(report.archive_only_count, 0);
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
    let report = restore_sessions_with(
        &executor,
        vec![session(1, "native-one"), session(2, "native-two")],
    )
    .unwrap();
    assert_eq!(report.archive_only_count, 1);
    assert_eq!(report.continuation_count, 1);
    assert_eq!(report.restore_mapping_count, 2);
}
