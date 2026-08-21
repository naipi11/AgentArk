use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agentark_adapter_codex::CodexAdapter;
use agentark_adapter_sdk::{DetectContext, SourceAdapter};
use agentark_app::{
    AppError, AppServices, LockedIndexQueryService, QueryUseCase, ScanReport, ScanRequest,
    ScanService, ScanUseCase, VerifyUseCase,
};
use agentark_cas::EncryptedCas;
use agentark_index::IndexDb;
use agentark_security::{DatasetBootstrap, OsMasterKeyStore, SecretScanner};
use directories::ProjectDirs;
use uuid::Uuid;

pub struct AppState {
    pub services: Arc<Mutex<AppServices>>,
    data_root: PathBuf,
    scan_lock: Arc<Mutex<()>>,
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

        let executable = resolve_codex_executable();
        let adapter = CodexAdapter::with_executable(&source_root, executable)
            .map_err(|_| "无法打开 Codex 数据目录".to_owned())?;
        let mut install = adapter
            .detect(&DetectContext {
                explicit_roots: vec![source_root],
                allow_detected_home: false,
            })
            .map_err(|_| "无法识别 Codex 数据目录".to_owned())?
            .pop()
            .ok_or_else(|| "未授权的 Codex 数据目录".to_owned())?;
        let probe = adapter
            .probe(&install)
            .map_err(|_| "未找到可用的 Codex，或 Codex App Server 不兼容".to_owned())?;
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

        let (cas, index) = open_storage(&self.data_root)?;
        let scanner = SecretScanner::v1().map_err(|_| "安全扫描器初始化失败".to_owned())?;
        let mut service = ScanService::new(adapter, cas, index, scanner);
        let report = service
            .run(ScanRequest {
                install,
                snapshot_hint: None,
            })
            .map_err(|error| format!("扫描失败：{error}"))?;
        drop(service);
        self.refresh_query_index()?;
        Ok(report)
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

pub fn detected_codex_home() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CODEX_HOME") {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .map(|home| home.join(".codex"))
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
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        for candidate in ["codex.cmd", "codex.exe", "codex"] {
            let path = directory.join(candidate);
            if path.is_file() {
                return path;
            }
        }
    }
    PathBuf::from("codex")
}
