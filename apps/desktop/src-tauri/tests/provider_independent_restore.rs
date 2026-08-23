use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agentark_adapter_codex::{
    CodexContinuationReport, CodexContinuationRequest, CodexError, CodexTargetDefault,
    JsonRpcTransport, NativeRestoreReport, RawJsonRpc, fork_rollout_with_target_provider_transport,
    probe_target_default_transport,
};
use agentark_bundle::{NativeBundleEntry, read_bundle, write_selected_sessions_with_native};
use agentark_canonical::{
    AgentKind, CanonicalMessage, CanonicalSchemaVersion, CanonicalSession, Completeness,
};
use agentark_desktop_lib::recovery::{
    CodexRecoveryExecutor, ExistingRestoreTarget, NativeAttemptSummary, RecoveryError,
    RecoveryInput,
};
use agentark_desktop_lib::{AppState, RestoreMappingWriter};
use agentark_index::{IndexDb, RestoreMapping};
use agentark_security::SecretScanner;
use serde_json::{Value, json};
use uuid::Uuid;

const SAFE_PROVIDER_LABEL: &str = "openai";
const PROVIDER_TOKEN_CANARY: &str = "sk-proj-AgentArkProviderCanary1234567890123456";

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
    target_default: Mutex<CodexTargetDefault>,
    existing_verification: Mutex<Result<(), RecoveryError>>,
    vendor_writes: AtomicUsize,
    target_probe_calls: AtomicUsize,
    native_calls: AtomicUsize,
    continuation_calls: AtomicUsize,
    rollback_calls: AtomicUsize,
    rollback_fails: bool,
    native_summary: Mutex<NativeAttemptSummary>,
    restore_lock_probe: Option<AppState>,
    restore_lock_checks: AtomicUsize,
}

impl FakeExecutor {
    fn with_restore_lock_probe(mut self, state: AppState) -> Self {
        self.restore_lock_probe = Some(state);
        self
    }

    fn assert_restore_lock_held(&self) {
        if let Some(state) = &self.restore_lock_probe {
            assert!(!state.try_restore_lock_for_test().unwrap());
            self.restore_lock_checks.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn restore_lock_check_count(&self) -> usize {
        self.restore_lock_checks.load(Ordering::SeqCst)
    }

    fn set_target_default(&self, provider: &str, model: &str) {
        *self.target_default.lock().unwrap() = CodexTargetDefault {
            model_provider: provider.into(),
            model: model.into(),
        };
    }

    fn target_probe_call_count(&self) -> usize {
        self.target_probe_calls.load(Ordering::SeqCst)
    }

    fn existing_target_conflict(self) -> Self {
        *self.existing_verification.lock().unwrap() = Err(RecoveryError::Conflict);
        self
    }

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
    fn probe_target_default(
        &self,
        _input: &RecoveryInput,
    ) -> Result<CodexTargetDefault, RecoveryError> {
        self.target_probe_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.target_default.lock().unwrap().clone())
    }

    fn try_native_identity(
        &self,
        input: &RecoveryInput,
        _target_default: &CodexTargetDefault,
    ) -> Result<NativeRestoreReport, RecoveryError> {
        self.assert_restore_lock_held();
        self.native_calls.fetch_add(1, Ordering::SeqCst);
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
        target_default: &CodexTargetDefault,
    ) -> Result<CodexContinuationReport, RecoveryError> {
        self.assert_restore_lock_held();
        self.continuation_calls.fetch_add(1, Ordering::SeqCst);
        match self.continuation.lock().unwrap().pop_front().unwrap() {
            ContinuationScript::Success => {
                self.vendor_writes.fetch_add(1, Ordering::SeqCst);
                let target_thread_id = format!("continued-{}", input.session.source_session_id);
                let rollout_path = input.codex_home.join("sessions").join(format!(
                    "fake-continuation-{}.jsonl",
                    input.session.source_session_id
                ));
                fs::write(&rollout_path, b"verified fake continuation").unwrap();
                Ok(CodexContinuationReport {
                    source_thread_id: input.session.source_session_id.clone(),
                    target_thread_id,
                    rollout_path,
                    model_provider: target_default.model_provider.clone(),
                    model: target_default.model.clone(),
                    visible_turns: input.session.messages.len(),
                })
            }
            ContinuationScript::Unavailable => Err(RecoveryError::Unavailable),
            ContinuationScript::ManualIntervention => Err(RecoveryError::ManualIntervention),
        }
    }

    fn verify_existing_target(
        &self,
        _input: &RecoveryInput,
        _target: &ExistingRestoreTarget,
    ) -> Result<(), RecoveryError> {
        *self.existing_verification.lock().unwrap()
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
        target_default: Mutex::new(CodexTargetDefault {
            model_provider: "source-provider".into(),
            model: "source-model".into(),
        }),
        existing_verification: Mutex::new(Ok(())),
        vendor_writes: AtomicUsize::new(0),
        target_probe_calls: AtomicUsize::new(0),
        native_calls: AtomicUsize::new(0),
        continuation_calls: AtomicUsize::new(0),
        rollback_calls: AtomicUsize::new(0),
        rollback_fails: false,
        native_summary: Mutex::new(NativeAttemptSummary::default()),
        restore_lock_probe: None,
        restore_lock_checks: AtomicUsize::new(0),
    }
}

struct ReleaseCanaryTransport {
    sent: Arc<Mutex<Vec<Value>>>,
    responses: VecDeque<Value>,
}

impl ReleaseCanaryTransport {
    fn new(responses: Vec<Value>) -> (Self, Arc<Mutex<Vec<Value>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                sent: Arc::clone(&sent),
                responses: responses.into(),
            },
            sent,
        )
    }
}

impl JsonRpcTransport for ReleaseCanaryTransport {
    fn send_value(&mut self, value: &Value) -> Result<(), CodexError> {
        self.sent.lock().unwrap().push(value.clone());
        Ok(())
    }

    fn receive_value(&mut self) -> Result<RawJsonRpc, CodexError> {
        let value = self.responses.pop_front().ok_or(CodexError::EndOfStream)?;
        Ok(RawJsonRpc {
            bytes: serde_json::to_vec(&value).unwrap(),
            value,
        })
    }
}

struct ScriptedProviderRuntimeExecutor {
    sent: Mutex<Vec<Value>>,
    native_calls: AtomicUsize,
    fork_calls: AtomicUsize,
}

impl ScriptedProviderRuntimeExecutor {
    fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            native_calls: AtomicUsize::new(0),
            fork_calls: AtomicUsize::new(0),
        }
    }
}

impl CodexRecoveryExecutor for ScriptedProviderRuntimeExecutor {
    fn probe_target_default(
        &self,
        _input: &RecoveryInput,
    ) -> Result<CodexTargetDefault, RecoveryError> {
        let responses = vec![
            json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "config": {
                        "model_provider": SAFE_PROVIDER_LABEL,
                        "api_key": PROVIDER_TOKEN_CANARY,
                        "base_url": "https://provider-config-canary.invalid/v1"
                    },
                    "layers": [{"value": PROVIDER_TOKEN_CANARY}]
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "result": {
                    "data": [{"id": "gpt-5", "model": "gpt-5", "isDefault": true}],
                    "nextCursor": null
                }
            }),
        ];
        let (mut transport, sent) = ReleaseCanaryTransport::new(responses);
        let target = probe_target_default_transport(&mut transport)
            .map_err(|_| RecoveryError::Unavailable)?;
        self.sent
            .lock()
            .unwrap()
            .extend(sent.lock().unwrap().iter().cloned());
        Ok(target)
    }

    fn try_native_identity(
        &self,
        _input: &RecoveryInput,
        _target_default: &CodexTargetDefault,
    ) -> Result<NativeRestoreReport, RecoveryError> {
        self.native_calls.fetch_add(1, Ordering::SeqCst);
        Err(RecoveryError::Verification)
    }

    fn create_continuation(
        &self,
        input: &RecoveryInput,
        target_default: &CodexTargetDefault,
    ) -> Result<CodexContinuationReport, RecoveryError> {
        self.fork_calls.fetch_add(1, Ordering::SeqCst);
        let sessions = input.codex_home.join("sessions");
        let source_rollout = sessions.join("scripted-source.jsonl");
        let target_rollout = sessions.join("scripted-target.jsonl");
        let target_cwd = input.codex_home.join("scripted-project");
        fs::create_dir_all(&target_cwd).unwrap();
        fs::write(&source_rollout, b"sanitized source").unwrap();
        fs::write(&target_rollout, b"verified target").unwrap();
        let target_thread_id = "019scripted-target";
        let responses = vec![
            json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "modelProvider": SAFE_PROVIDER_LABEL,
                    "model": "gpt-5",
                    "thread": {"id": target_thread_id, "path": target_rollout}
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "result": {
                    "data": [{
                        "id": target_thread_id,
                        "cwd": target_cwd,
                        "path": target_rollout,
                        "modelProvider": SAFE_PROVIDER_LABEL
                    }],
                    "nextCursor": null
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "result": {
                    "thread": {
                        "id": target_thread_id,
                        "cwd": target_cwd,
                        "modelProvider": SAFE_PROVIDER_LABEL,
                        "turns": [{"id": "turn-1"}]
                    }
                }
            }),
        ];
        let (mut transport, sent) = ReleaseCanaryTransport::new(responses);
        let request = CodexContinuationRequest {
            source_rollout,
            source_thread_id: input.session.source_session_id.clone(),
            target_cwd,
            target_provider: Some(target_default.model_provider.clone()),
            target_model: Some(target_default.model.clone()),
        };
        let report = fork_rollout_with_target_provider_transport(
            &mut transport,
            &input.codex_home,
            &request,
        )
        .map_err(|_| RecoveryError::Verification)?;
        self.sent
            .lock()
            .unwrap()
            .extend(sent.lock().unwrap().iter().cloned());
        Ok(report)
    }

    fn verify_existing_target(
        &self,
        _input: &RecoveryInput,
        _target: &ExistingRestoreTarget,
    ) -> Result<(), RecoveryError> {
        Ok(())
    }

    fn rollback(
        &self,
        _input: &RecoveryInput,
        _report: &agentark_desktop_lib::recovery::AutomaticRecoveryReport,
    ) -> Result<(), RecoveryError> {
        Ok(())
    }
}

fn serialized_continuation_request_with_provider_canary(root: &TempRoot) -> String {
    let codex_home = root.path().join("request-codex-home");
    let sessions = codex_home.join("sessions");
    let source_rollout = sessions.join("source.jsonl");
    let target_rollout = sessions.join("target.jsonl");
    let target_cwd = root.path().join("request-project");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&target_cwd).unwrap();
    fs::write(
        &source_rollout,
        format!(r#"{{"provider":"{SAFE_PROVIDER_LABEL}","apiKey":"{PROVIDER_TOKEN_CANARY}"}}"#),
    )
    .unwrap();
    fs::write(&target_rollout, b"target rollout").unwrap();

    let target_thread_id = "019release-canary-target";
    let responses = vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "modelProvider": SAFE_PROVIDER_LABEL,
                "model": "gpt-5",
                "thread": {
                    "id": target_thread_id,
                    "path": target_rollout,
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "data": [{"id": target_thread_id, "cwd": target_cwd}],
                "nextCursor": null
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "result": {
                "thread": {
                    "id": target_thread_id,
                    "cwd": target_cwd,
                    "turns": [{"id": "turn-1"}]
                }
            }
        }),
    ];
    let (mut transport, sent) = ReleaseCanaryTransport::new(responses);
    let request = CodexContinuationRequest {
        source_rollout,
        source_thread_id: "019release-canary-source".into(),
        target_cwd,
        target_provider: Some(SAFE_PROVIDER_LABEL.into()),
        target_model: Some("gpt-5".into()),
    };

    fork_rollout_with_target_provider_transport(&mut transport, &codex_home, &request).unwrap();

    let sent = sent.lock().unwrap();
    serde_json::to_string(
        sent.iter()
            .find(|value| value["method"] == "thread/fork")
            .unwrap(),
    )
    .unwrap()
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
    bundle_path: PathBuf,
    codex_home: PathBuf,
}

fn restore_fixture(
    executor: &dyn CodexRecoveryExecutor,
    sessions: Vec<CanonicalSession>,
    agent: &str,
    include_payloads: bool,
) -> Result<RestoredFixture, String> {
    restore_fixture_with_writer(executor, sessions, agent, include_payloads, None)
}

fn restore_fixture_with_writer(
    executor: &dyn CodexRecoveryExecutor,
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
            bundle_path.clone(),
            executor,
            mapping_writer,
            codex_home.clone(),
            PathBuf::from("fake-codex"),
            codex_home.join("agentark-backups"),
        )?,
        None => state.bundle_restore_with_executor(
            bundle_path.clone(),
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
        bundle_path,
        codex_home,
    })
}

fn restore_again(
    fixture: &RestoredFixture,
    executor: &dyn CodexRecoveryExecutor,
) -> agentark_desktop_lib::BundleReport {
    fixture
        .state
        .bundle_restore_with_executor(
            fixture.bundle_path.clone(),
            executor,
            fixture.codex_home.clone(),
            PathBuf::from("fake-codex"),
            fixture.codex_home.join("agentark-backups"),
        )
        .unwrap()
}

fn restore_again_with_writer(
    fixture: &RestoredFixture,
    executor: &dyn CodexRecoveryExecutor,
    mapping_writer: &dyn RestoreMappingWriter,
) -> agentark_desktop_lib::BundleReport {
    fixture
        .state
        .bundle_restore_with_executor_and_mapping_writer(
            fixture.bundle_path.clone(),
            executor,
            mapping_writer,
            fixture.codex_home.clone(),
            PathBuf::from("fake-codex"),
            fixture.codex_home.join("agentark-backups"),
        )
        .unwrap()
}

struct LockCheckingMappingWriter {
    state: AppState,
    calls: AtomicUsize,
}

impl LockCheckingMappingWriter {
    fn new(state: AppState) -> Self {
        Self {
            state,
            calls: AtomicUsize::new(0),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl RestoreMappingWriter for LockCheckingMappingWriter {
    fn record(&self, index: &mut IndexDb, mapping: &RestoreMapping) -> Result<(), String> {
        assert!(!self.state.try_restore_lock_for_test().unwrap());
        self.calls.fetch_add(1, Ordering::SeqCst);
        index
            .record_restore_mapping(mapping)
            .map_err(|_| "fixture-mapping-failure".into())
    }
}

#[test]
fn restore_lock_spans_vendor_write_mapping_and_repeat_reuse() {
    let root = TempRoot::new("shared-restore-lock");
    let data_root = root.path().join("data");
    let codex_home = root.path().join("codex-home");
    fs::create_dir_all(codex_home.join("sessions")).unwrap();
    let bundle_path = root.path().join("fixture.ahbundle");
    let restored_session = session(30, "native-concurrent");
    write_selected_sessions_with_native(
        &bundle_path,
        "codex",
        std::slice::from_ref(&restored_session),
        &[],
        &[payload(&restored_session)],
        &SecretScanner::v1().unwrap(),
    )
    .unwrap();
    let state = AppState::for_data_root(data_root);
    let executor = fake_executor()
        .native_missing_provider()
        .continuation_success()
        .with_restore_lock_probe(state.clone());
    let mapping_writer = LockCheckingMappingWriter::new(state.clone());

    let first_report = state
        .bundle_restore_with_executor_and_mapping_writer(
            bundle_path.clone(),
            &executor,
            &mapping_writer,
            codex_home.clone(),
            PathBuf::from("fake-codex"),
            codex_home.join("agentark-backups"),
        )
        .unwrap();
    let second_report = state
        .bundle_restore_with_executor_and_mapping_writer(
            bundle_path,
            &executor,
            &mapping_writer,
            codex_home.clone(),
            PathBuf::from("fake-codex"),
            codex_home.join("agentark-backups"),
        )
        .unwrap();
    let mappings = state.restore_mappings_for(restored_session.id).unwrap();

    assert!(state.try_restore_lock_for_test().unwrap());
    assert_eq!(executor.restore_lock_check_count(), 2);
    assert_eq!(mapping_writer.call_count(), 1);
    assert_eq!(executor.continuation_call_count(), 1);
    assert_eq!(executor.vendor_write_count(), 1);
    assert_eq!(mappings.len(), 1);
    assert_eq!(
        mappings[0].target_native_id.as_deref(),
        Some("continued-native-concurrent")
    );
    assert_eq!(first_report.restore_mapping_count, 1);
    assert_eq!(second_report.restore_mapping_count, 1);
    assert_eq!(first_report.continuation_count, 1);
    assert_eq!(second_report.continuation_count, 0);
    assert!(!second_report.native_restart_required);
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
fn production_scripted_target_default_skips_incompatible_native_and_forks_explicitly() {
    let executor = ScriptedProviderRuntimeExecutor::new();
    let mut custom_session = session(8, "native-custom-provider");
    custom_session.model_provider = Some("custom".into());
    custom_session.model_name = Some("claude-custom".into());

    let fixture = restore_fixture(&executor, vec![custom_session], "codex", true).unwrap();

    assert_eq!(executor.native_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.fork_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.report.native_identity_count, 0);
    assert_eq!(fixture.report.continuation_count, 1);
    let sent = executor.sent.lock().unwrap();
    let fork = sent
        .iter()
        .find(|request| request["method"] == "thread/fork")
        .unwrap();
    assert_eq!(fork["params"]["modelProvider"], SAFE_PROVIDER_LABEL);
    assert_eq!(fork["params"]["model"], "gpt-5");
    let mapping = fixture
        .state
        .restore_mappings_for(fixture.session_ids[0])
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(
        mapping.target_provider.as_deref(),
        Some(SAFE_PROVIDER_LABEL)
    );
    let sinks = format!(
        "{}\n{:?}\n{}\n{}",
        serde_json::to_string(&fixture.report).unwrap(),
        mapping,
        fs::read_to_string(fixture._root.path().join("data/audit.jsonl")).unwrap(),
        serde_json::to_string(&*sent).unwrap()
    );
    assert!(!sinks.contains(PROVIDER_TOKEN_CANARY));
    assert!(!sinks.contains("https://provider-config-canary.invalid/v1"));
}

#[test]
fn repeating_verified_continuation_reuses_one_target_and_one_mapping() {
    let executor = fake_executor()
        .native_missing_provider()
        .continuation_success();
    let fixture =
        restore_fixture(&executor, vec![session(9, "native-repeat")], "codex", true).unwrap();
    let original = fixture
        .state
        .restore_mappings_for(fixture.session_ids[0])
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(executor.target_probe_call_count(), 1);
    executor.set_target_default("other-provider", "other-model");

    let second = restore_again(&fixture, &executor);
    let mappings = fixture
        .state
        .restore_mappings_for(fixture.session_ids[0])
        .unwrap();

    assert_eq!(executor.continuation_call_count(), 1);
    assert_eq!(executor.vendor_write_count(), 1);
    assert_eq!(executor.target_probe_call_count(), 1);
    assert_eq!(second.native_identity_count, 0);
    assert_eq!(second.continuation_count, 0);
    assert_eq!(second.native_imported_count, 0);
    assert!(!second.native_restart_required);
    assert_eq!(second.restore_mapping_count, 1);
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].target_native_id, original.target_native_id);
}

#[test]
fn changed_source_hash_conflicts_before_any_repeat_vendor_write() {
    let executor = fake_executor()
        .native_missing_provider()
        .continuation_success();
    let fixture = restore_fixture(
        &executor,
        vec![session(10, "native-changed-source")],
        "codex",
        true,
    )
    .unwrap();
    let changed_session = session(10, "native-changed-source");
    let mut changed_payload = payload(&changed_session);
    changed_payload
        .bytes
        .extend_from_slice(b"{\"type\":\"changed\"}\n");
    write_selected_sessions_with_native(
        &fixture.bundle_path,
        "codex",
        std::slice::from_ref(&changed_session),
        &[],
        &[changed_payload],
        &SecretScanner::v1().unwrap(),
    )
    .unwrap();
    let writes_before = executor.vendor_write_count();

    let second = restore_again(&fixture, &executor);

    assert_eq!(executor.vendor_write_count(), writes_before);
    assert_eq!(executor.continuation_call_count(), 1);
    assert_eq!(second.native_identity_count, 0);
    assert_eq!(second.continuation_count, 0);
    assert_eq!(second.manual_intervention_count, 1);
    assert_eq!(
        second.recovery_error.as_deref(),
        Some("restore-mapping-conflict")
    );
    assert_eq!(
        fixture
            .state
            .restore_mappings_for(fixture.session_ids[0])
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn missing_or_mismatched_mapped_target_conflicts_without_new_vendor_write() {
    let executor = fake_executor()
        .native_missing_provider()
        .continuation_success()
        .existing_target_conflict();
    let fixture = restore_fixture(
        &executor,
        vec![session(11, "native-missing-target")],
        "codex",
        true,
    )
    .unwrap();
    let writes_before = executor.vendor_write_count();

    let second = restore_again(&fixture, &executor);

    assert_eq!(executor.vendor_write_count(), writes_before);
    assert_eq!(executor.continuation_call_count(), 1);
    assert_eq!(second.manual_intervention_count, 1);
    assert_eq!(
        second.recovery_error.as_deref(),
        Some("restore-mapping-conflict")
    );
    assert_eq!(
        fixture
            .state
            .restore_mappings_for(fixture.session_ids[0])
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn repeated_archive_only_restore_does_not_add_another_archive_mapping() {
    let executor = fake_executor()
        .native_missing_provider()
        .native_missing_provider()
        .continuation_unavailable()
        .continuation_unavailable();
    let fixture = restore_fixture(
        &executor,
        vec![session(12, "native-archive-repeat")],
        "codex",
        true,
    )
    .unwrap();

    let second = restore_again(&fixture, &executor);

    assert_eq!(second.archive_only_count, 1);
    assert_eq!(second.restore_mapping_count, 1);
    assert_eq!(
        fixture
            .state
            .restore_mappings_for(fixture.session_ids[0])
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn provider_token_canary_stays_out_of_release_sinks_while_label_survives() {
    let request_root = TempRoot::new("provider-token-request");
    let continuation_request = serialized_continuation_request_with_provider_canary(&request_root);

    let mut canary_session = session(7, "native-provider-canary");
    canary_session.model_provider = Some(SAFE_PROVIDER_LABEL.into());
    canary_session.raw_extra = BTreeMap::from([(
        "providerConfiguration".into(),
        json!({"apiKey": PROVIDER_TOKEN_CANARY}),
    )]);
    let executor = fake_executor()
        .native_missing_provider()
        .continuation_success();
    let fixture = restore_fixture(&executor, vec![canary_session], "codex", true).unwrap();

    let bundle = read_bundle(&fixture._root.path().join("fixture.ahbundle")).unwrap();
    let recovery_manifest = String::from_utf8(
        bundle
            .entries
            .get("recovery/manifest.json")
            .unwrap()
            .clone(),
    )
    .unwrap();
    let mapping = fixture
        .state
        .restore_mappings_for(fixture.session_ids[0])
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let restore_mapping = format!("{mapping:?}");
    let ui_report = serde_json::to_string(&fixture.report).unwrap();
    let audit_event = fs::read_to_string(fixture._root.path().join("data/audit.jsonl")).unwrap();
    assert!(fixture.state.audit_verify().unwrap().valid);

    let sinks = [
        ("native continuation request", continuation_request),
        ("recovery manifest", recovery_manifest),
        ("restore mapping", restore_mapping),
        ("UI report", ui_report),
        ("audit event", audit_event),
    ];
    let leaked_tokens = sinks
        .iter()
        .filter_map(|(name, value)| value.contains(PROVIDER_TOKEN_CANARY).then_some(*name))
        .collect::<Vec<_>>();
    let missing_labels = sinks
        .iter()
        .filter_map(|(name, value)| (!value.contains(SAFE_PROVIDER_LABEL)).then_some(*name))
        .collect::<Vec<_>>();

    assert!(
        leaked_tokens.is_empty(),
        "provider token canary leaked into: {leaked_tokens:?}"
    );
    assert!(
        missing_labels.is_empty(),
        "safe provider label missing from: {missing_labels:?}"
    );
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
fn failed_archive_upgrade_keeps_existing_mapping_count_after_rollback() {
    let initial_executor = fake_executor()
        .native_missing_provider()
        .continuation_unavailable();
    let fixture = restore_fixture(
        &initial_executor,
        vec![session(31, "native-archive-upgrade")],
        "codex",
        true,
    )
    .unwrap();
    let retry_executor = fake_executor()
        .native_missing_provider()
        .continuation_success();

    let report = restore_again_with_writer(&fixture, &retry_executor, &FailingMappingWriter);
    let mappings = fixture
        .state
        .restore_mappings_for(fixture.session_ids[0])
        .unwrap();

    assert_eq!(retry_executor.rollback_call_count(), 1);
    assert_eq!(report.native_identity_count, 0);
    assert_eq!(report.continuation_count, 0);
    assert_eq!(report.archive_only_count, 1);
    assert_eq!(report.restore_mapping_count, 1);
    assert_eq!(
        report.recovery_error.as_deref(),
        Some("restore-mapping-persistence-failed")
    );
    assert_eq!(mappings.len(), 1);
    assert_eq!(
        mappings[0].outcome,
        agentark_migration::RestoreOutcome::ArchiveOnly
    );
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
