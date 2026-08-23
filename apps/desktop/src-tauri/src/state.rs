use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentark_adapter_claude::ClaudeCodeAdapter;
use agentark_adapter_codex::{CodexAdapter, NativeRolloutPayload};
use agentark_adapter_grok::GrokBuildAdapter;
use agentark_adapter_hermes::HermesAdapter;
use agentark_adapter_openclaw::OpenClawAdapter;
use agentark_adapter_opencode::OpenCodeAdapter;
use agentark_adapter_sdk::{DetectContext, SourceAdapter};
use agentark_app::{
    AppError, AppServices, LockedIndexQueryService, QueryUseCase, ScanReport, ScanRequest,
    ScanService, ScanUseCase, VerifyUseCase,
};
use agentark_audit::{AuditEvent, AuditVerification, append_event, verify_chain};
use agentark_bundle::{
    NativeBundleEntry, ProjectSelection, WorkspaceFileEntry, read_bundle,
    write_selected_sessions_with_native,
};
use agentark_canonical::AgentKind;
use agentark_cas::EncryptedCas;
use agentark_index::{IndexDb, RestoreMapping};
use agentark_migration::{RestoreOutcome, agent_label};
use agentark_security::{DatasetBootstrap, OsMasterKeyStore, SecretScanner};
use agentark_watch::{
    ReconcileEvent, ReconciliationQueue, WatchRoot, diff_fingerprints, fingerprint_root,
};
use directories::ProjectDirs;
use serde::Serialize;
use uuid::Uuid;

use crate::recovery::{
    CodexRecoveryExecutor, ExistingRestoreTarget, ProductionCodexRecoveryExecutor, RecoveryInput,
    archive_only_recovery_report, recover_one_codex_session, recovery_source_hash,
};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleReport {
    pub format: String,
    pub agent: Option<String>,
    pub session_count: u64,
    pub entry_count: usize,
    pub workspace_count: u64,
    pub file_count: u64,
    pub conflict_count: u64,
    pub redacted: bool,
    pub redaction_count: u64,
    pub restore_scan_id: Option<Uuid>,
    pub native_payload_count: u64,
    pub native_imported_count: u64,
    pub native_skipped_count: u64,
    pub native_conflict_count: u64,
    pub native_backup_path: Option<String>,
    pub native_restart_required: bool,
    pub native_error: Option<String>,
    pub native_identity_count: u64,
    pub continuation_count: u64,
    pub archive_only_count: u64,
    pub restore_mapping_count: u64,
    pub recovery_error: Option<String>,
    pub manual_intervention_count: u64,
    pub provider_labels: Vec<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub services: Arc<Mutex<AppServices>>,
    data_root: PathBuf,
    scan_lock: Arc<Mutex<()>>,
    restore_lock: Arc<Mutex<()>>,
    restore_lock_attempt_hook: Arc<Mutex<Option<RestoreLockAttemptHook>>>,
    watch_roots: Arc<Mutex<Vec<WatchRoot>>>,
    watcher_started: Arc<AtomicBool>,
}

type RestoreLockAttemptHook = Arc<dyn Fn() + Send + Sync>;

#[doc(hidden)]
pub trait RestoreMappingWriter {
    fn record(&self, index: &mut IndexDb, mapping: &RestoreMapping) -> Result<(), String>;
}

struct IndexRestoreMappingWriter;

impl RestoreMappingWriter for IndexRestoreMappingWriter {
    fn record(&self, index: &mut IndexDb, mapping: &RestoreMapping) -> Result<(), String> {
        index
            .record_restore_mapping(mapping)
            .map_err(|_| "restore-mapping-persistence-failed".into())
    }
}

fn acquire_restore_lock(lock: &Mutex<()>) -> Result<MutexGuard<'_, ()>, String> {
    lock.lock().map_err(|_| "恢复操作锁不可用".to_owned())
}

struct EmptyUseCase;
impl ScanUseCase for EmptyUseCase {}
impl VerifyUseCase for EmptyUseCase {}

struct EmptyQuery;
impl QueryUseCase for EmptyQuery {
    fn status(&self) -> Result<agentark_app::StatusDto, AppError> {
        Ok(agentark_app::StatusDto {
            dataset_state: "notInitialized".into(),
            adapter_id: None,
            executable_version: None,
            schema_fingerprint: None,
            capabilities: Vec::new(),
            quarantine_reason: None,
        })
    }

    fn list_sessions(
        &self,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<agentark_index::SessionSummary>, AppError> {
        Ok(Vec::new())
    }

    fn list_workspaces(
        &self,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<agentark_app::WorkspaceDto>, AppError> {
        Ok(Vec::new())
    }

    fn show_session(&self, _id: uuid::Uuid) -> Result<agentark_app::PublicSessionDetail, AppError> {
        Err(AppError::Invariant("session is not available".into()))
    }

    fn search(
        &self,
        _query: &str,
        _limit: u32,
    ) -> Result<Vec<agentark_index::SearchHit>, AppError> {
        Ok(Vec::new())
    }

    fn list_quarantines(&self) -> Result<Vec<agentark_app::QuarantineDto>, AppError> {
        Ok(Vec::new())
    }
}

impl AppState {
    pub fn empty() -> Self {
        Self {
            services: Arc::new(Mutex::new(AppServices {
                scanner: Box::new(EmptyUseCase),
                verifier: Box::new(EmptyUseCase),
                queries: Box::new(EmptyQuery),
            })),
            data_root: default_data_dir(),
            scan_lock: Arc::new(Mutex::new(())),
            restore_lock: Arc::new(Mutex::new(())),
            restore_lock_attempt_hook: Arc::new(Mutex::new(None)),
            watch_roots: Arc::new(Mutex::new(Vec::new())),
            watcher_started: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn open_default() -> Self {
        let data_root = default_data_dir();
        let Some(index) = open_index(&data_root) else {
            return Self::empty();
        };
        Self {
            services: Arc::new(Mutex::new(AppServices {
                scanner: Box::new(EmptyUseCase),
                verifier: Box::new(EmptyUseCase),
                queries: Box::new(LockedIndexQueryService::new(index)),
            })),
            data_root,
            scan_lock: Arc::new(Mutex::new(())),
            restore_lock: Arc::new(Mutex::new(())),
            restore_lock_attempt_hook: Arc::new(Mutex::new(None)),
            watch_roots: Arc::new(Mutex::new(Vec::new())),
            watcher_started: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Test-only constructor for external integration tests that must isolate
    /// AgentArk storage from the user's configured data root.
    #[doc(hidden)]
    pub fn for_data_root(data_root: PathBuf) -> Self {
        Self {
            services: Arc::new(Mutex::new(AppServices {
                scanner: Box::new(EmptyUseCase),
                verifier: Box::new(EmptyUseCase),
                queries: Box::new(EmptyQuery),
            })),
            data_root,
            scan_lock: Arc::new(Mutex::new(())),
            restore_lock: Arc::new(Mutex::new(())),
            restore_lock_attempt_hook: Arc::new(Mutex::new(None)),
            watch_roots: Arc::new(Mutex::new(Vec::new())),
            watcher_started: Arc::new(AtomicBool::new(false)),
        }
    }

    #[doc(hidden)]
    pub fn set_restore_lock_attempt_hook_for_test(
        &self,
        hook: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), String> {
        *self
            .restore_lock_attempt_hook
            .lock()
            .map_err(|_| "恢复操作锁不可用".to_owned())? = Some(hook);
        Ok(())
    }

    #[doc(hidden)]
    pub fn hold_restore_lock_for_test(&self) -> Result<MutexGuard<'_, ()>, String> {
        acquire_restore_lock(&self.restore_lock)
    }

    #[doc(hidden)]
    pub fn try_restore_lock_for_test(&self) -> Result<bool, String> {
        match self.restore_lock.try_lock() {
            Ok(_guard) => Ok(true),
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Poisoned(_)) => Err("恢复操作锁不可用".to_owned()),
        }
    }

    fn acquire_bundle_restore_lock(&self) -> Result<MutexGuard<'_, ()>, String> {
        let hook = self
            .restore_lock_attempt_hook
            .lock()
            .map_err(|_| "恢复操作锁不可用".to_owned())?
            .take();
        if let Some(hook) = hook {
            hook();
        }
        acquire_restore_lock(&self.restore_lock)
    }

    pub fn scan_codex(&self, source_root: PathBuf) -> Result<ScanReport, String> {
        let _scan_guard = self
            .scan_lock
            .lock()
            .map_err(|_| "扫描状态不可用".to_owned())?;
        let source_root = if source_root.as_os_str().is_empty() {
            detected_codex_home().ok_or_else(|| "找不到默认 Codex 数据目录".to_owned())?
        } else {
            source_root
        };
        if !source_root.is_dir() {
            return Err("Codex 数据目录不存在或不是目录".into());
        }
        self.register_watch("codex", &source_root);

        let executable = resolve_codex_executable();
        let adapter = CodexAdapter::with_executable(&source_root, executable.clone())
            .map_err(|_| "无法打开 Codex 数据目录".to_owned())?;
        let mut install = adapter
            .detect(&DetectContext {
                explicit_roots: vec![source_root],
                allow_detected_home: false,
            })
            .map_err(|_| "无法识别 Codex 数据目录".to_owned())?
            .pop()
            .ok_or_else(|| "未授权的 Codex 数据目录".to_owned())?;
        let probe = adapter.probe(&install).map_err(|error| {
            format!(
                "未找到可用的 Codex（{}）：{error}",
                executable.to_string_lossy()
            )
        })?;
        if probe.quarantine_reason.is_some() {
            return Err("当前 Codex 版本不受支持，扫描已停止".into());
        }
        install.executable_version = probe.executable_version;
        install.schema_fingerprint = probe.schema_fingerprint;
        install.capabilities = probe
            .capabilities
            .into_iter()
            .map(|capability| format!("{capability:?}"))
            .collect();

        self.release_query_index()?;
        let scan_result = (|| {
            let (cas, index) = open_storage(&self.data_root)?;
            let scanner = SecretScanner::v1().map_err(|_| "安全扫描器初始化失败".to_owned())?;
            let mut service = ScanService::new(adapter, cas, index, scanner);
            service
                .run(ScanRequest {
                    install,
                    snapshot_hint: None,
                })
                .map_err(|error| format!("扫描失败：{error}"))
        })();
        match scan_result {
            Ok(report) => {
                self.refresh_query_index()?;
                Ok(report)
            }
            Err(error) => {
                let _ = self.refresh_query_index();
                Err(error)
            }
        }
    }

    pub fn scan_claude(&self, source_root: PathBuf) -> Result<ScanReport, String> {
        let _scan_guard = self
            .scan_lock
            .lock()
            .map_err(|_| "扫描状态不可用".to_owned())?;
        let source_root = if source_root.as_os_str().is_empty() {
            detected_claude_home().ok_or_else(|| "找不到默认 Claude Code 数据目录".to_owned())?
        } else {
            source_root
        };
        if !source_root.is_dir() {
            return Err("Claude Code 数据目录不存在或不是目录".into());
        }
        self.register_watch("claude-code", &source_root);
        let adapter = ClaudeCodeAdapter::new(&source_root)
            .map_err(|_| "无法打开 Claude Code 数据目录".to_owned())?;
        let mut install = adapter
            .detect(&DetectContext {
                explicit_roots: vec![source_root],
                allow_detected_home: false,
            })
            .map_err(|_| "无法识别 Claude Code 数据目录".to_owned())?
            .pop()
            .ok_or_else(|| "未找到 Claude Code projects 目录".to_owned())?;
        let probe = adapter
            .probe(&install)
            .map_err(|error| format!("Claude Code 探测失败：{error}"))?;
        install.executable_version = probe.executable_version;
        install.schema_fingerprint = probe.schema_fingerprint;
        install.capabilities = probe
            .capabilities
            .into_iter()
            .map(|capability| format!("{capability:?}"))
            .collect();

        self.release_query_index()?;
        let scan_result = (|| {
            let (cas, index) = open_storage(&self.data_root)?;
            let scanner = SecretScanner::v1().map_err(|_| "安全扫描器初始化失败".to_owned())?;
            let mut service = ScanService::new(adapter, cas, index, scanner);
            service
                .run(ScanRequest {
                    install,
                    snapshot_hint: None,
                })
                .map_err(|error| format!("扫描失败：{error}"))
        })();
        match scan_result {
            Ok(report) => {
                self.refresh_query_index()?;
                Ok(report)
            }
            Err(error) => {
                let _ = self.refresh_query_index();
                Err(error)
            }
        }
    }

    pub fn scan_hermes(&self, source_root: PathBuf) -> Result<ScanReport, String> {
        let _scan_guard = self
            .scan_lock
            .lock()
            .map_err(|_| "扫描状态不可用".to_owned())?;
        let source_root = if source_root.as_os_str().is_empty() {
            detected_hermes_home().ok_or_else(|| "找不到默认 Hermes 数据目录".to_owned())?
        } else {
            source_root
        };
        if !source_root.is_dir() {
            return Err("Hermes 数据目录不存在或不是目录".into());
        }
        self.register_watch("hermes", &source_root);
        let adapter =
            HermesAdapter::new(&source_root).map_err(|_| "无法打开 Hermes 数据目录".to_owned())?;
        let mut install = adapter
            .detect(&DetectContext {
                explicit_roots: vec![source_root],
                allow_detected_home: false,
            })
            .map_err(|_| "无法识别 Hermes 数据目录".to_owned())?
            .pop()
            .ok_or_else(|| "未找到 Hermes state.db".to_owned())?;
        let probe = adapter
            .probe(&install)
            .map_err(|error| format!("Hermes 探测失败：{error}"))?;
        install.executable_version = probe.executable_version;
        install.schema_fingerprint = probe.schema_fingerprint;
        install.capabilities = probe
            .capabilities
            .into_iter()
            .map(|capability| format!("{capability:?}"))
            .collect();
        self.release_query_index()?;
        let scan_result = (|| {
            let (cas, index) = open_storage(&self.data_root)?;
            let scanner = SecretScanner::v1().map_err(|_| "安全扫描器初始化失败".to_owned())?;
            let mut service = ScanService::new(adapter, cas, index, scanner);
            service
                .run(ScanRequest {
                    install,
                    snapshot_hint: None,
                })
                .map_err(|error| format!("扫描失败：{error}"))
        })();
        match scan_result {
            Ok(report) => {
                self.refresh_query_index()?;
                Ok(report)
            }
            Err(error) => {
                let _ = self.refresh_query_index();
                Err(error)
            }
        }
    }

    pub fn scan_openclaw(&self, source_root: PathBuf) -> Result<ScanReport, String> {
        let _scan_guard = self
            .scan_lock
            .lock()
            .map_err(|_| "扫描状态不可用".to_owned())?;
        let source_root = if source_root.as_os_str().is_empty() {
            detected_openclaw_home().ok_or_else(|| "找不到默认 OpenClaw 数据目录".to_owned())?
        } else {
            source_root
        };
        if !source_root.is_dir() {
            return Err("OpenClaw 数据目录不存在或不是目录".into());
        }
        self.register_watch("openclaw", &source_root);
        let adapter = OpenClawAdapter::new(&source_root)
            .map_err(|_| "无法打开 OpenClaw 数据目录".to_owned())?;
        let mut install = adapter
            .detect(&DetectContext {
                explicit_roots: vec![source_root],
                allow_detected_home: false,
            })
            .map_err(|_| "无法识别 OpenClaw 数据目录".to_owned())?
            .pop()
            .ok_or_else(|| "未找到 OpenClaw SQLite 数据库".to_owned())?;
        let probe = adapter
            .probe(&install)
            .map_err(|error| format!("OpenClaw 探测失败：{error}"))?;
        install.executable_version = probe.executable_version;
        install.schema_fingerprint = probe.schema_fingerprint;
        install.capabilities = probe
            .capabilities
            .into_iter()
            .map(|capability| format!("{capability:?}"))
            .collect();
        self.release_query_index()?;
        let scan_result = (|| {
            let (cas, index) = open_storage(&self.data_root)?;
            let scanner = SecretScanner::v1().map_err(|_| "安全扫描器初始化失败".to_owned())?;
            let mut service = ScanService::new(adapter, cas, index, scanner);
            service
                .run(ScanRequest {
                    install,
                    snapshot_hint: None,
                })
                .map_err(|error| format!("扫描失败：{error}"))
        })();
        match scan_result {
            Ok(report) => {
                self.refresh_query_index()?;
                Ok(report)
            }
            Err(error) => {
                let _ = self.refresh_query_index();
                Err(error)
            }
        }
    }

    pub fn scan_opencode(&self, source_root: PathBuf) -> Result<ScanReport, String> {
        let _scan_guard = self
            .scan_lock
            .lock()
            .map_err(|_| "扫描状态不可用".to_owned())?;
        let source_root = if source_root.as_os_str().is_empty() {
            detected_opencode_home().ok_or_else(|| "找不到默认 OpenCode 数据目录".to_owned())?
        } else {
            source_root
        };
        if !source_root.exists() {
            return Err("OpenCode 数据目录或数据库不存在".into());
        }
        self.register_watch("opencode", &source_root);
        let adapter = OpenCodeAdapter::new(&source_root)
            .map_err(|_| "无法打开 OpenCode 数据目录".to_owned())?;
        let mut install = adapter
            .detect(&DetectContext {
                explicit_roots: vec![source_root],
                allow_detected_home: false,
            })
            .map_err(|_| "无法识别 OpenCode 数据目录".to_owned())?
            .pop()
            .ok_or_else(|| "未找到 OpenCode opencode.db".to_owned())?;
        let probe = adapter
            .probe(&install)
            .map_err(|error| format!("OpenCode 探测失败：{error}"))?;
        if probe.quarantine_reason.is_some() {
            return Err("当前 OpenCode 数据库结构不受支持，扫描已停止".into());
        }
        install.executable_version = probe.executable_version;
        install.schema_fingerprint = probe.schema_fingerprint;
        install.capabilities = probe
            .capabilities
            .into_iter()
            .map(|capability| format!("{capability:?}"))
            .collect();
        self.release_query_index()?;
        let scan_result = (|| {
            let (cas, index) = open_storage(&self.data_root)?;
            let scanner = SecretScanner::v1().map_err(|_| "安全扫描器初始化失败".to_owned())?;
            let mut service = ScanService::new(adapter, cas, index, scanner);
            service
                .run(ScanRequest {
                    install,
                    snapshot_hint: None,
                })
                .map_err(|error| format!("扫描失败：{error}"))
        })();
        match scan_result {
            Ok(report) => {
                self.refresh_query_index()?;
                Ok(report)
            }
            Err(error) => {
                let _ = self.refresh_query_index();
                Err(error)
            }
        }
    }

    pub fn scan_grok_build(&self, source_root: PathBuf) -> Result<ScanReport, String> {
        let _scan_guard = self
            .scan_lock
            .lock()
            .map_err(|_| "扫描状态不可用".to_owned())?;
        let source_root = if source_root.as_os_str().is_empty() {
            detected_grok_build_home().ok_or_else(|| "找不到默认 Grok Build 数据目录".to_owned())?
        } else {
            source_root
        };
        if !source_root.exists() {
            return Err("Grok Build 数据目录不存在".into());
        }
        self.register_watch("grok-build", &source_root);
        let adapter = GrokBuildAdapter::new(&source_root)
            .map_err(|_| "无法打开 Grok Build 数据目录".to_owned())?;
        let mut install = adapter
            .detect(&DetectContext {
                explicit_roots: vec![source_root],
                allow_detected_home: false,
            })
            .map_err(|_| "无法识别 Grok Build 数据目录".to_owned())?
            .pop()
            .ok_or_else(|| "未找到 Grok Build sessions 目录".to_owned())?;
        let probe = adapter
            .probe(&install)
            .map_err(|error| format!("Grok Build 探测失败：{error}"))?;
        install.executable_version = probe.executable_version;
        install.schema_fingerprint = probe.schema_fingerprint;
        install.capabilities = probe
            .capabilities
            .into_iter()
            .map(|capability| format!("{capability:?}"))
            .collect();
        self.release_query_index()?;
        let scan_result = (|| {
            let (cas, index) = open_storage(&self.data_root)?;
            let scanner = SecretScanner::v1().map_err(|_| "安全扫描器初始化失败".to_owned())?;
            let mut service = ScanService::new(adapter, cas, index, scanner);
            service
                .run(ScanRequest {
                    install,
                    snapshot_hint: None,
                })
                .map_err(|error| format!("扫描失败：{error}"))
        })();
        match scan_result {
            Ok(report) => {
                self.refresh_query_index()?;
                Ok(report)
            }
            Err(error) => {
                let _ = self.refresh_query_index();
                Err(error)
            }
        }
    }

    pub fn bundle_export(
        &self,
        path: PathBuf,
        agent_kind: Option<AgentKind>,
        workspace_ids: Vec<Uuid>,
        include_files: bool,
    ) -> Result<BundleReport, String> {
        if path.as_os_str().is_empty() {
            return Err("备份路径不能为空".into());
        }
        self.release_query_index()?;
        let result = (|| {
            let index =
                open_index(&self.data_root).ok_or_else(|| "本地数据集尚未初始化".to_owned())?;
            let sessions = index
                .all_sessions_filtered(agent_kind.clone())
                .map_err(|_| "无法读取本地会话".to_owned())?;
            let scanner = SecretScanner::v1().map_err(|_| "安全扫描器初始化失败".to_owned())?;
            let provider_labels = safe_provider_labels(
                sessions
                    .iter()
                    .filter_map(|session| session.model_provider.as_deref()),
                &scanner,
            );
            let selected = workspace_ids
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            let selections = sessions
                .iter()
                .filter_map(|session| session.workspace.as_ref())
                .filter(|workspace| selected.is_empty() || selected.contains(&workspace.id))
                .map(|workspace| ProjectSelection {
                    workspace_id: workspace.id,
                    root: PathBuf::from(&workspace.path_native),
                    include_files,
                    max_file_bytes: 64 * 1024 * 1024,
                })
                .collect::<Vec<_>>();
            let agent = agent_kind.as_ref().map(agent_label).unwrap_or("all");
            let native_entries = if agent_kind == Some(AgentKind::Codex) {
                detected_codex_home()
                    .filter(|root| root.is_dir())
                    .map(|root| {
                        agentark_adapter_codex::collect_native_rollouts(&root, &sessions, &scanner)
                            .map(|payloads| {
                                payloads
                                    .into_iter()
                                    .map(|payload| NativeBundleEntry {
                                        session_id: payload.session_id,
                                        relative_path: payload.relative_path,
                                        bytes: payload.bytes,
                                        redaction_count: payload.redaction_count,
                                    })
                                    .collect::<Vec<_>>()
                            })
                    })
                    .transpose()
                    .map_err(|_| "无法读取 Codex 原生会话文件".to_owned())?
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let native_payload_count = native_entries.len() as u64;
            let manifest = write_selected_sessions_with_native(
                &path,
                agent,
                &sessions,
                &selections,
                &native_entries,
                &scanner,
            )
            .map_err(|_| "无法写入 .ahbundle 备份".to_owned())?;
            append_audit_event(
                &self.data_root,
                "bundle.exported",
                &path,
                None,
                &provider_labels,
            )?;
            Ok(BundleReport {
                format: manifest.format,
                agent: manifest.agent,
                session_count: manifest.session_count,
                entry_count: manifest.entries.len() + 1,
                workspace_count: manifest.workspace_count,
                file_count: manifest.file_count,
                conflict_count: 0,
                redacted: manifest.redacted,
                redaction_count: manifest.redaction_count,
                restore_scan_id: None,
                native_payload_count,
                native_imported_count: 0,
                native_skipped_count: 0,
                native_conflict_count: 0,
                native_backup_path: None,
                native_restart_required: false,
                native_error: None,
                native_identity_count: 0,
                continuation_count: 0,
                archive_only_count: 0,
                restore_mapping_count: 0,
                recovery_error: None,
                manual_intervention_count: 0,
                provider_labels,
            })
        })();
        let _ = self.refresh_query_index();
        result
    }

    pub fn bundle_verify(&self, path: PathBuf) -> Result<BundleReport, String> {
        let bundle = read_bundle(&path).map_err(|_| "无法验证 .ahbundle 文件".to_owned())?;
        let scanner = SecretScanner::v1().map_err(|_| "安全扫描器初始化失败".to_owned())?;
        let recovery_manifest = bundle
            .recovery_manifest()
            .map_err(|_| "备份中的恢复清单无效".to_owned())?;
        let provider_labels = safe_provider_labels(
            recovery_manifest
                .iter()
                .flat_map(|manifest| manifest.sessions.iter())
                .filter_map(|session| session.source_provider.as_deref()),
            &scanner,
        );
        let mut conflict_count = 0;
        let restore_root = self.data_root.join("restored-workspaces");
        for entry in bundle
            .workspace_file_entries()
            .map_err(|_| "备份中的项目文件清单无效".to_owned())?
        {
            let destination = restore_root
                .join(entry.workspace_id.to_string())
                .join(&entry.relative_path);
            if let Ok(existing) = fs::read(destination)
                && agentark_canonical::Sha256Digest::from_bytes(&existing)
                    != agentark_canonical::Sha256Digest::from_bytes(&entry.bytes)
            {
                conflict_count += 1;
            }
        }
        Ok(BundleReport {
            format: bundle.manifest.format.clone(),
            agent: bundle.manifest.agent.clone(),
            session_count: bundle.manifest.session_count,
            entry_count: bundle.entries.len(),
            workspace_count: bundle.manifest.workspace_count,
            file_count: bundle.manifest.file_count,
            conflict_count,
            redacted: bundle.manifest.redacted,
            redaction_count: bundle.manifest.redaction_count,
            restore_scan_id: None,
            native_payload_count: bundle
                .native_rollout_entries()
                .map_err(|_| "备份中的 Codex 原生清单无效".to_owned())?
                .len() as u64,
            native_imported_count: 0,
            native_skipped_count: 0,
            native_conflict_count: 0,
            native_backup_path: None,
            native_restart_required: false,
            native_error: None,
            native_identity_count: 0,
            continuation_count: 0,
            archive_only_count: 0,
            restore_mapping_count: 0,
            recovery_error: None,
            manual_intervention_count: 0,
            provider_labels,
        })
    }

    pub fn bundle_restore(&self, path: PathBuf) -> Result<BundleReport, String> {
        let codex_home = detected_codex_home().unwrap_or_default();
        let executable = resolve_codex_executable();
        let backup_root = codex_home.join("agentark-backups");
        let executor = ProductionCodexRecoveryExecutor::new();
        self.bundle_restore_with_executor(path, &executor, codex_home, executable, backup_root)
    }

    #[doc(hidden)]
    pub fn bundle_restore_with_executor(
        &self,
        path: PathBuf,
        executor: &dyn CodexRecoveryExecutor,
        codex_home: PathBuf,
        executable: PathBuf,
        backup_root: PathBuf,
    ) -> Result<BundleReport, String> {
        self.bundle_restore_with_executor_and_mapping_writer(
            path,
            executor,
            &IndexRestoreMappingWriter,
            codex_home,
            executable,
            backup_root,
        )
    }

    #[doc(hidden)]
    pub fn bundle_restore_with_executor_and_mapping_writer(
        &self,
        path: PathBuf,
        executor: &dyn CodexRecoveryExecutor,
        mapping_writer: &dyn RestoreMappingWriter,
        codex_home: PathBuf,
        executable: PathBuf,
        backup_root: PathBuf,
    ) -> Result<BundleReport, String> {
        let _restore_guard = self.acquire_bundle_restore_lock()?;
        if path.as_os_str().is_empty() {
            return Err("备份路径不能为空".into());
        }
        let bundle = read_bundle(&path).map_err(|_| "无法读取 .ahbundle 备份".to_owned())?;
        let recovery_manifest = bundle
            .recovery_manifest()
            .map_err(|_| "备份中的恢复清单无效".to_owned())?;
        let mut sessions = bundle
            .session_records()
            .map_err(|_| "备份中的会话数据无效".to_owned())?;
        let scanner = SecretScanner::v1().map_err(|_| "安全扫描器初始化失败".to_owned())?;
        let provider_labels = safe_provider_labels(
            sessions
                .iter()
                .filter_map(|session| session.model_provider.as_deref()),
            &scanner,
        );
        let workspace_ids = bundle
            .workspace_ids()
            .map_err(|_| "备份中的项目清单无效".to_owned())?;
        let file_entries = bundle
            .workspace_file_entries()
            .map_err(|_| "备份中的项目文件清单无效".to_owned())?;
        let native_entries = bundle
            .native_rollout_entries()
            .map_err(|_| "备份中的 Codex 原生清单无效".to_owned())?;
        let native_payload_count = native_entries.len() as u64;
        let mut payloads_by_session = HashMap::<Uuid, Vec<NativeRolloutPayload>>::new();
        for entry in native_entries {
            let payload = NativeRolloutPayload {
                session_id: entry.session_id,
                relative_path: entry.relative_path,
                source_hash: agentark_canonical::Sha256Digest::from_bytes(&entry.bytes),
                bytes: entry.bytes,
                redaction_count: entry.redaction_count,
            };
            payloads_by_session
                .entry(payload.session_id)
                .or_default()
                .push(payload);
        }
        let recovery_sources = recovery_manifest
            .map(|manifest| {
                manifest
                    .sessions
                    .into_iter()
                    .map(|session| (session.canonical_session_id, session))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();
        let restore_root = self.data_root.join("restored-workspaces");
        let workspace_mappings = sessions
            .iter()
            .filter_map(|session| {
                session.workspace.as_ref().map(|workspace| {
                    (
                        workspace.path_native.clone(),
                        restore_root
                            .join(workspace.id.to_string())
                            .to_string_lossy()
                            .into_owned(),
                    )
                })
            })
            .collect::<Vec<_>>();
        restore_project_files(&restore_root, &file_entries)?;
        for session in &mut sessions {
            if let Some(workspace) = session.workspace.as_mut()
                && workspace_ids.contains(&workspace.id)
            {
                let path = restore_root.join(workspace.id.to_string());
                workspace.path_native = path.to_string_lossy().into_owned();
                workspace.canonical_uri =
                    format!("file://{}", workspace.path_native.replace('\\', "/"));
            }
        }
        self.release_query_index()?;
        let result = (|| {
            let (_cas, mut index) = open_storage(&self.data_root)?;
            let scan_id = index
                .restore_sessions(&sessions)
                .map_err(|_| "无法恢复会话到本地索引".to_owned())?;
            append_audit_event(
                &self.data_root,
                "bundle.restored",
                &path,
                Some(scan_id),
                &provider_labels,
            )?;
            let mut native_identity_count = 0u64;
            let mut continuation_count = 0u64;
            let mut archive_only_count = 0u64;
            let mut restore_mapping_count = 0u64;
            let mut recovery_error = None;
            let mut native_skipped_count = 0u64;
            let mut native_conflict_count = 0u64;
            let mut native_backup_path = None;
            let mut manual_intervention_count = 0u64;
            let bundle_target_agent = target_agent_kind(bundle.manifest.agent.as_deref());
            for session in &sessions {
                let mut recovery_session = session.clone();
                if let Some(source) = recovery_sources.get(&session.id) {
                    recovery_session.model_provider = source.source_provider.clone();
                    recovery_session.model_name = source.source_model.clone();
                }
                let native_payload = payloads_by_session
                    .remove(&session.id)
                    .and_then(|payloads| payloads.into_iter().next());
                let input = RecoveryInput {
                    session: recovery_session,
                    native_payload,
                    workspace_mappings: workspace_mappings.clone(),
                    codex_home: codex_home.clone(),
                    executable: executable.clone(),
                    backup_root: backup_root.clone(),
                };
                let target_agent = bundle_target_agent
                    .clone()
                    .or_else(|| source_agent_kind(&session.source_kind));
                let existing_mappings = match index.restore_mappings_for(session.id) {
                    Ok(mappings) => mappings,
                    Err(_) => {
                        manual_intervention_count += 1;
                        recovery_error = Some("restore-mapping-conflict".into());
                        continue;
                    }
                };
                let target_mappings = target_agent
                    .as_ref()
                    .map(|target_agent| {
                        existing_mappings
                            .iter()
                            .filter(|mapping| &mapping.target_agent == target_agent)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let durable_mappings = target_mappings
                    .iter()
                    .copied()
                    .filter(|mapping| {
                        matches!(
                            mapping.outcome,
                            RestoreOutcome::NativeIdentity | RestoreOutcome::Continuation
                        )
                    })
                    .collect::<Vec<_>>();
                if durable_mappings.len() > 1 {
                    manual_intervention_count += 1;
                    recovery_error = Some("restore-mapping-conflict".into());
                    continue;
                }
                if let Some(mapping) = durable_mappings.first() {
                    let current_source_hash = recovery_source_hash(&input);
                    let target = mapping
                        .target_native_id
                        .clone()
                        .zip(mapping.target_provider.clone())
                        .zip(mapping.target_hash.clone())
                        .map(|((target_native_id, model_provider), rollout_hash)| {
                            ExistingRestoreTarget {
                                outcome: mapping.outcome,
                                target_native_id,
                                model_provider,
                                rollout_hash,
                            }
                        });
                    if mapping.source_hash != current_source_hash
                        || target.as_ref().is_none_or(|target| {
                            executor.verify_existing_target(&input, target).is_err()
                        })
                    {
                        manual_intervention_count += 1;
                        recovery_error = Some("restore-mapping-conflict".into());
                        continue;
                    }
                    restore_mapping_count += 1;
                    continue;
                }
                let has_archive_mapping = target_mappings
                    .iter()
                    .any(|mapping| mapping.outcome == RestoreOutcome::ArchiveOnly);
                let recovery = if bundle.manifest.agent.as_deref() == Some("codex") {
                    recover_one_codex_session(executor, &input)
                } else {
                    archive_only_recovery_report(
                        &input,
                        if bundle_target_agent.is_some() {
                            "target-recovery-unavailable"
                        } else {
                            "target-agent-unavailable"
                        },
                    )
                };
                native_skipped_count += recovery.native_skipped_count;
                native_conflict_count += recovery.native_conflict_count;
                if native_backup_path.is_none() {
                    native_backup_path = recovery
                        .native_backup_path
                        .as_ref()
                        .map(|path| path.to_string_lossy().into_owned());
                }
                if recovery.requires_manual_intervention {
                    manual_intervention_count += 1;
                    recovery_error = Some("manual-intervention-required".into());
                    continue;
                }
                if recovery.outcome == RestoreOutcome::ArchiveOnly && has_archive_mapping {
                    archive_only_count += 1;
                    restore_mapping_count += 1;
                    if recovery_error.is_none() {
                        recovery_error = Some(recovery.reason_code.clone());
                    }
                    continue;
                }
                let Some(target_agent) = target_agent else {
                    archive_only_count += 1;
                    if recovery_error.is_none() {
                        recovery_error = Some("target-agent-unavailable".into());
                    }
                    continue;
                };
                let mapping = RestoreMapping {
                    source_session_id: session.id,
                    target_agent,
                    outcome: recovery.outcome,
                    source_native_id: recovery.source_native_id.clone(),
                    target_native_id: recovery.target_native_id.clone(),
                    source_provider: recovery.source_provider.provider.clone(),
                    target_provider: recovery
                        .target_provider
                        .clone()
                        .and_then(|identity| identity.provider),
                    source_hash: recovery.source_hash.clone(),
                    target_hash: recovery.target_hash.clone(),
                    reason_code: recovery.reason_code.clone(),
                    created_at: restore_mapping_timestamp(),
                };
                match mapping_writer.record(&mut index, &mapping) {
                    Ok(()) => {
                        restore_mapping_count += 1;
                        match recovery.outcome {
                            RestoreOutcome::NativeIdentity => native_identity_count += 1,
                            RestoreOutcome::Continuation => continuation_count += 1,
                            RestoreOutcome::ArchiveOnly => {
                                archive_only_count += 1;
                                if recovery_error.is_none() {
                                    recovery_error = Some(recovery.reason_code.clone());
                                }
                            }
                        }
                    }
                    Err(_) => match executor.rollback(&input, &recovery) {
                        Ok(()) => {
                            archive_only_count += 1;
                            if has_archive_mapping {
                                restore_mapping_count += 1;
                            }
                            if recovery_error.is_none() {
                                recovery_error = Some("restore-mapping-persistence-failed".into());
                            }
                        }
                        Err(_) => {
                            manual_intervention_count += 1;
                            recovery_error = Some("manual-intervention-required".into());
                        }
                    },
                }
            }
            let native_imported_count = native_identity_count + continuation_count;
            let native_restart_required = native_imported_count > 0;
            Ok(BundleReport {
                format: bundle.manifest.format.clone(),
                agent: bundle.manifest.agent.clone(),
                session_count: bundle.manifest.session_count,
                entry_count: bundle.entries.len(),
                workspace_count: bundle.manifest.workspace_count,
                file_count: bundle.manifest.file_count,
                conflict_count: 0,
                redacted: bundle.manifest.redacted,
                redaction_count: bundle.manifest.redaction_count,
                restore_scan_id: Some(scan_id),
                native_payload_count,
                native_imported_count,
                native_skipped_count,
                native_conflict_count,
                native_backup_path,
                native_restart_required,
                native_error: recovery_error.clone(),
                native_identity_count,
                continuation_count,
                archive_only_count,
                restore_mapping_count,
                recovery_error,
                manual_intervention_count,
                provider_labels,
            })
        })();
        let _ = self.refresh_query_index();
        result
    }

    #[doc(hidden)]
    pub fn restore_mappings_for(&self, session_id: Uuid) -> Result<Vec<RestoreMapping>, String> {
        self.release_query_index()?;
        let result = open_index(&self.data_root)
            .ok_or_else(|| "无法打开本地加密索引".to_owned())?
            .restore_mappings_for(session_id)
            .map_err(|_| "无法读取恢复映射".to_owned());
        let _ = self.refresh_query_index();
        result
    }

    pub fn audit_verify(&self) -> Result<AuditVerification, String> {
        verify_chain(&self.data_root.join("audit.jsonl")).map_err(|_| "无法验证审计账本".to_owned())
    }

    fn register_watch(&self, agent_id: &str, path: &Path) {
        let root = WatchRoot {
            agent_id: agent_id.to_owned(),
            path: path.to_path_buf(),
        };
        if let Ok(mut roots) = self.watch_roots.lock()
            && !roots.iter().any(|candidate| candidate == &root)
        {
            roots.push(root);
        }
        if !self.watcher_started.swap(true, Ordering::AcqRel) {
            self.start_watcher_thread();
        }
    }

    fn start_watcher_thread(&self) {
        let state = self.clone();
        thread::spawn(move || {
            let mut previous =
                HashMap::<(String, PathBuf), Vec<agentark_watch::FileFingerprint>>::new();
            let mut queue = ReconciliationQueue::new(Duration::from_millis(500));
            loop {
                thread::sleep(Duration::from_secs(2));
                let roots = state
                    .watch_roots
                    .lock()
                    .map(|roots| roots.clone())
                    .unwrap_or_default();
                for root in &roots {
                    let key = (root.agent_id.clone(), root.path.clone());
                    let Ok(current) = fingerprint_root(root) else {
                        continue;
                    };
                    let prior = previous.insert(key, current.clone()).unwrap_or_default();
                    for changed in diff_fingerprints(&prior, &current) {
                        queue.push(ReconcileEvent {
                            agent_id: root.agent_id.clone(),
                            path: changed,
                            changed_at_ns: now_ns(),
                        });
                    }
                }
                queue.flush(now_ns());
                let mut rescanned = BTreeSet::new();
                while let Some(event) = queue.pop_ready() {
                    if !rescanned.insert(event.agent_id.clone()) {
                        continue;
                    }
                    let Some(root) = roots
                        .iter()
                        .find(|root| {
                            root.agent_id == event.agent_id && event.path.starts_with(&root.path)
                        })
                        .map(|root| root.path.clone())
                    else {
                        continue;
                    };
                    match event.agent_id.as_str() {
                        "codex" => {
                            let _ = state.scan_codex(root);
                        }
                        "claude-code" => {
                            let _ = state.scan_claude(root);
                        }
                        "hermes" => {
                            let _ = state.scan_hermes(root);
                        }
                        "openclaw" => {
                            let _ = state.scan_openclaw(root);
                        }
                        "opencode" => {
                            let _ = state.scan_opencode(root);
                        }
                        "grok-build" => {
                            let _ = state.scan_grok_build(root);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    fn release_query_index(&self) -> Result<(), String> {
        let mut services = self
            .services
            .lock()
            .map_err(|_| "桌面端状态不可用".to_owned())?;
        services.queries = Box::new(EmptyQuery);
        Ok(())
    }

    fn refresh_query_index(&self) -> Result<(), String> {
        let index = open_index(&self.data_root)
            .ok_or_else(|| "扫描完成，但无法重新打开本地索引".to_owned())?;
        let mut services = self
            .services
            .lock()
            .map_err(|_| "桌面端状态不可用".to_owned())?;
        services.queries = Box::new(LockedIndexQueryService::new(index));
        Ok(())
    }
}

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn restore_mapping_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| format!("unix:{}", duration.as_secs()))
        .unwrap_or_else(|_| "unix:0".into())
}

fn target_agent_kind(label: Option<&str>) -> Option<AgentKind> {
    match label {
        Some("codex") => Some(AgentKind::Codex),
        Some("claude-code") => Some(AgentKind::ClaudeCode),
        Some("hermes") => Some(AgentKind::Hermes),
        Some("openclaw") => Some(AgentKind::OpenClaw),
        Some("opencode") => Some(AgentKind::OpenCode),
        Some("grok-build") => Some(AgentKind::GrokBuild),
        _ => None,
    }
}

fn source_agent_kind(source_kind: &str) -> Option<AgentKind> {
    match source_kind {
        "app-server" | "codex" => Some(AgentKind::Codex),
        "claude" | "claude-code" => Some(AgentKind::ClaudeCode),
        "hermes" => Some(AgentKind::Hermes),
        "openclaw" => Some(AgentKind::OpenClaw),
        "opencode" => Some(AgentKind::OpenCode),
        "grok" | "grok-build" => Some(AgentKind::GrokBuild),
        _ => None,
    }
}

fn append_audit_event(
    root: &Path,
    event_type: &str,
    path: &Path,
    target: Option<Uuid>,
    provider_labels: &[String],
) -> Result<(), String> {
    let event = AuditEvent {
        event_id: Uuid::new_v4(),
        event_type: event_type.into(),
        timestamp: "now".into(),
        actor: "agentark-desktop".into(),
        source: path
            .file_name()
            .and_then(|name| name.to_str())
            .map(ToOwned::to_owned),
        target: target.map(|value| value.to_string()),
        before_hash: None,
        after_hash: None,
        plan_hash: None,
        result: "success".into(),
        provider_labels: provider_labels.to_vec(),
        previous_hash: None,
        event_hash: agentark_canonical::Sha256Digest::from_bytes(b"pending"),
    };
    append_event(&root.join("audit.jsonl"), event)
        .map(|_| ())
        .map_err(|_| "无法写入审计账本".to_owned())
}

fn safe_provider_labels<'a>(
    values: impl IntoIterator<Item = &'a str>,
    scanner: &SecretScanner,
) -> Vec<String> {
    values
        .into_iter()
        .filter_map(|value| {
            let label = value.trim();
            (!label.is_empty()
                && scanner.sanitize(label).findings.is_empty()
                && label.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
                }))
            .then(|| label.to_owned())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn restore_project_files(root: &Path, entries: &[WorkspaceFileEntry]) -> Result<(), String> {
    for entry in entries {
        let destination = root
            .join(entry.workspace_id.to_string())
            .join(&entry.relative_path);
        if let Ok(existing) = fs::read(&destination) {
            if agentark_canonical::Sha256Digest::from_bytes(&existing)
                != agentark_canonical::Sha256Digest::from_bytes(&entry.bytes)
            {
                return Err(format!("项目文件冲突：{}", entry.relative_path));
            }
            continue;
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|_| "无法创建恢复项目目录".to_owned())?;
        }
        let temporary = destination.with_extension(format!("{}.tmp", Uuid::new_v4()));
        fs::write(&temporary, &entry.bytes).map_err(|_| "无法写入恢复项目文件".to_owned())?;
        fs::rename(&temporary, &destination).map_err(|_| "无法提交恢复项目文件".to_owned())?;
    }
    Ok(())
}

pub fn detected_codex_home() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CODEX_HOME") {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .map(|home| home.join(".codex"))
}

pub fn detected_claude_home() -> Option<PathBuf> {
    ClaudeCodeAdapter::default_home()
}

pub fn detected_hermes_home() -> Option<PathBuf> {
    HermesAdapter::default_home()
}

pub fn detected_openclaw_home() -> Option<PathBuf> {
    OpenClawAdapter::default_home()
}

pub fn detected_opencode_home() -> Option<PathBuf> {
    OpenCodeAdapter::default_home()
}

pub fn detected_grok_build_home() -> Option<PathBuf> {
    GrokBuildAdapter::default_home()
}

fn default_data_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("AGENTARK_DATA_DIR") {
        return PathBuf::from(path);
    }
    ProjectDirs::from("dev", "AgentArk", "AgentArk")
        .map(|dirs| dirs.data_local_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".agentark-data"))
}

fn open_index(root: &Path) -> Option<IndexDb> {
    let bootstrap_path = root.join("bootstrap.json");
    if !bootstrap_path.is_file() {
        return None;
    }
    let bootstrap: DatasetBootstrap =
        serde_json::from_slice(&std::fs::read(bootstrap_path).ok()?).ok()?;
    let machine_id = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        root.to_string_lossy().as_bytes(),
    );
    let store = OsMasterKeyStore::new(machine_id).ok()?;
    let keys = bootstrap.unlock(&store).ok()?;
    IndexDb::open(&root.join("index.db"), keys.sqlcipher_key()).ok()
}

fn open_storage(root: &Path) -> Result<(EncryptedCas, IndexDb), String> {
    fs::create_dir_all(root).map_err(|_| "无法创建 AgentArk 数据目录".to_owned())?;
    let bootstrap_path = root.join("bootstrap.json");
    let machine_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, root.to_string_lossy().as_bytes());
    let store = OsMasterKeyStore::new(machine_id).map_err(|_| "系统密钥存储不可用".to_owned())?;
    let bootstrap = if bootstrap_path.is_file() {
        serde_json::from_slice(
            &fs::read(&bootstrap_path).map_err(|_| "无法读取本地数据密钥".to_owned())?,
        )
        .map_err(|_| "本地数据密钥格式无效".to_owned())?
    } else {
        let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store)
            .map_err(|_| "无法创建本地数据密钥".to_owned())?;
        fs::write(
            &bootstrap_path,
            serde_json::to_vec_pretty(&bootstrap)
                .map_err(|_| "无法序列化本地数据密钥".to_owned())?,
        )
        .map_err(|_| "无法保存本地数据密钥".to_owned())?;
        bootstrap
    };
    let keys = bootstrap
        .unlock(&store)
        .map_err(|_| "无法解锁本地数据密钥".to_owned())?;
    let cas = EncryptedCas::open(root.join("cas"), &keys)
        .map_err(|_| "无法打开本地加密归档".to_owned())?;
    let index = IndexDb::open(&root.join("index.db"), keys.sqlcipher_key())
        .map_err(|_| "无法打开本地加密索引".to_owned())?;
    Ok((cas, index))
}

fn resolve_codex_executable() -> PathBuf {
    if let Some(path) = std::env::var_os("AGENTARK_CODEX_BIN") {
        return PathBuf::from(path);
    }
    if let Some(app_data) = std::env::var_os("APPDATA") {
        let npm_dir = PathBuf::from(app_data).join("npm");
        for candidate in ["codex.opencodex-real.cmd", "codex.cmd"] {
            let path = npm_dir.join(candidate);
            if path.is_file() {
                return path;
            }
        }
    }
    let directories =
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect::<Vec<_>>();
    // Prefer the npm shim when it is present. On Windows, PATH can also expose
    // a packaged WindowsApps `codex.exe` that is not directly executable by a
    // desktop process, even though the corresponding `codex.cmd` works.
    for candidate in ["codex.cmd", "codex.exe", "codex"] {
        for directory in &directories {
            let path = directory.join(candidate);
            if path.is_file() {
                return path;
            }
        }
    }
    PathBuf::from("codex")
}

#[cfg(test)]
mod restore_lock_tests {
    use std::sync::{Arc, Mutex};
    use std::thread;

    use super::acquire_restore_lock;

    #[test]
    fn poisoned_restore_lock_fails_closed() {
        let lock = Arc::new(Mutex::new(()));
        let poisoned = Arc::clone(&lock);
        let _ = thread::spawn(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("poison restore lock fixture");
        })
        .join();

        assert_eq!(
            acquire_restore_lock(&lock).err().as_deref(),
            Some("恢复操作锁不可用")
        );
    }
}
