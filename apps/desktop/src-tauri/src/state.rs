use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentark_adapter_claude::ClaudeCodeAdapter;
use agentark_adapter_codex::CodexAdapter;
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
use agentark_bundle::{read_bundle, write_sessions};
use agentark_cas::EncryptedCas;
use agentark_index::IndexDb;
use agentark_security::{DatasetBootstrap, OsMasterKeyStore, SecretScanner};
use agentark_watch::{
    ReconcileEvent, ReconciliationQueue, WatchRoot, diff_fingerprints, fingerprint_root,
};
use directories::ProjectDirs;
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleReport {
    pub format: String,
    pub session_count: u64,
    pub entry_count: usize,
    pub redacted: bool,
    pub redaction_count: u64,
    pub restore_scan_id: Option<Uuid>,
}

#[derive(Clone)]
pub struct AppState {
    pub services: Arc<Mutex<AppServices>>,
    data_root: PathBuf,
    scan_lock: Arc<Mutex<()>>,
    watch_roots: Arc<Mutex<Vec<WatchRoot>>>,
    watcher_started: Arc<AtomicBool>,
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
            watch_roots: Arc::new(Mutex::new(Vec::new())),
            watcher_started: Arc::new(AtomicBool::new(false)),
        }
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

    pub fn bundle_export(&self, path: PathBuf) -> Result<BundleReport, String> {
        if path.as_os_str().is_empty() {
            return Err("备份路径不能为空".into());
        }
        self.release_query_index()?;
        let result = (|| {
            let index =
                open_index(&self.data_root).ok_or_else(|| "本地数据集尚未初始化".to_owned())?;
            let sessions = index
                .all_sessions()
                .map_err(|_| "无法读取本地会话".to_owned())?;
            let scanner = SecretScanner::v1().map_err(|_| "安全扫描器初始化失败".to_owned())?;
            let manifest = write_sessions(&path, &sessions, &scanner)
                .map_err(|_| "无法写入 .ahbundle 备份".to_owned())?;
            append_audit_event(&self.data_root, "bundle.exported", &path, None)?;
            Ok(BundleReport {
                format: manifest.format,
                session_count: manifest.session_count,
                entry_count: manifest.entries.len() + 1,
                redacted: manifest.redacted,
                redaction_count: manifest.redaction_count,
                restore_scan_id: None,
            })
        })();
        let _ = self.refresh_query_index();
        result
    }

    pub fn bundle_verify(&self, path: PathBuf) -> Result<BundleReport, String> {
        let bundle = read_bundle(&path).map_err(|_| "无法验证 .ahbundle 文件".to_owned())?;
        Ok(BundleReport {
            format: bundle.manifest.format.clone(),
            session_count: bundle.manifest.session_count,
            entry_count: bundle.entries.len(),
            redacted: bundle.manifest.redacted,
            redaction_count: bundle.manifest.redaction_count,
            restore_scan_id: None,
        })
    }

    pub fn bundle_restore(&self, path: PathBuf) -> Result<BundleReport, String> {
        if path.as_os_str().is_empty() {
            return Err("备份路径不能为空".into());
        }
        let bundle = read_bundle(&path).map_err(|_| "无法读取 .ahbundle 备份".to_owned())?;
        let sessions = bundle
            .session_records()
            .map_err(|_| "备份中的会话数据无效".to_owned())?;
        self.release_query_index()?;
        let result = (|| {
            let (_cas, mut index) = open_storage(&self.data_root)?;
            let scan_id = index
                .restore_sessions(&sessions)
                .map_err(|_| "无法恢复会话到本地索引".to_owned())?;
            append_audit_event(&self.data_root, "bundle.restored", &path, Some(scan_id))?;
            Ok(BundleReport {
                format: bundle.manifest.format.clone(),
                session_count: bundle.manifest.session_count,
                entry_count: bundle.entries.len(),
                redacted: bundle.manifest.redacted,
                redaction_count: bundle.manifest.redaction_count,
                restore_scan_id: Some(scan_id),
            })
        })();
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

fn append_audit_event(
    root: &Path,
    event_type: &str,
    path: &Path,
    target: Option<Uuid>,
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
        previous_hash: None,
        event_hash: agentark_canonical::Sha256Digest::from_bytes(b"pending"),
    };
    append_event(&root.join("audit.jsonl"), event)
        .map(|_| ())
        .map_err(|_| "无法写入审计账本".to_owned())
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
