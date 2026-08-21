use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use agentark_adapter_sdk::{
    AdapterError, CaptureBatch, CaptureRequest, CapturedRecord, CapturedSource, DetectContext,
    NormalizeOutcome, ProbeReport, SourceAdapter, SourceCapability,
};
use agentark_canonical::{
    AgentInstall, AgentKind, CanonicalMessage, CanonicalRole, CanonicalSchemaVersion,
    CanonicalSession, Completeness, ContentPart, ContentPartKind, Sha256Digest, ToolEvent,
    agent_install_id, message_id, session_id, workspace_id, Workspace,
};
use agentark_security::AuthorizedRoot;
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const SCHEMA_FINGERPRINT: &str = "sha256:hermes-state-db-v1";

pub struct HermesAdapter {
    root: PathBuf,
}

impl HermesAdapter {
    pub fn new(root: &Path) -> Result<Self, AdapterError> {
        AuthorizedRoot::new(root.to_path_buf())?;
        Ok(Self { root: dunce::canonicalize(root)? })
    }

    pub fn default_home() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("HERMES_HOME") {
            return Some(PathBuf::from(path));
        }
        std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .map(|home| home.join(".hermes"))
    }

    fn db_path(&self) -> PathBuf { self.root.join("state.db") }

    fn root_uri(&self) -> String {
        format!("file://{}", self.root.to_string_lossy().replace('\\', "/"))
    }

    fn install(&self) -> AgentInstall {
        let root_uri = self.root_uri();
        AgentInstall {
            id: agent_install_id(Uuid::nil(), "hermes", &root_uri),
            kind: AgentKind::Hermes,
            executable_version: "state-db-unknown".into(),
            authorized_root_uri: root_uri,
            adapter_version: "hermes-adapter-v1".into(),
            schema_fingerprint: SCHEMA_FINGERPRINT.into(),
            capabilities: ["filesystem-raw-archive", "known-semantic-schema"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            quarantine_reason: None,
        }
    }

    fn open_read_only(&self) -> Result<Connection, AdapterError> {
        let path = self.db_path();
        if !path.is_file() {
            return Err(AdapterError::InvalidData("Hermes state.db is missing".into()));
        }
        let connection = sql(Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        ))?;
        sql(connection.busy_timeout(std::time::Duration::from_secs(3)))?;
        sql(connection.execute_batch("PRAGMA query_only = ON; PRAGMA foreign_keys = ON;"))?;
        Ok(connection)
    }

    fn table_columns(connection: &Connection, table: &str) -> Result<HashSet<String>, AdapterError> {
        let mut statement = sql(connection.prepare(&format!("PRAGMA table_info({table})")))?;
        let rows = sql(statement.query_map([], |row| row.get::<_, String>(1)))?;
        Ok(sql(rows.collect::<Result<HashSet<_>, _>>())?)
    }

    fn optional_column(columns: &HashSet<String>, name: &str) -> String {
        if columns.contains(name) { format!("\"{name}\"") } else { "NULL".into() }
    }

    fn capture_sessions(&self) -> Result<Vec<CapturedRecord>, AdapterError> {
        let connection = self.open_read_only()?;
        let session_columns = Self::table_columns(&connection, "sessions")?;
        let message_columns = Self::table_columns(&connection, "messages")?;
        if !session_columns.contains("id") || !message_columns.contains("session_id") {
            return Err(AdapterError::InvalidData("Hermes state.db schema lacks sessions/messages".into()));
        }
        let session_sql = format!(
            "SELECT id, {}, {}, {}, {}, {}, {}, {}, {}, {} FROM sessions ORDER BY started_at, id",
            Self::optional_column(&session_columns, "title"),
            Self::optional_column(&session_columns, "display_name"),
            Self::optional_column(&session_columns, "source"),
            Self::optional_column(&session_columns, "model"),
            Self::optional_column(&session_columns, "cwd"),
            Self::optional_column(&session_columns, "git_repo_root"),
            Self::optional_column(&session_columns, "git_branch"),
            Self::optional_column(&session_columns, "started_at"),
            Self::optional_column(&session_columns, "ended_at"),
        );
        let mut sessions = sql(connection.prepare(&session_sql))?;
        let rows = sql(sessions.query_map([], |row| {
            let id: String = row.get(0)?;
            let metadata = json!({
                "id": id,
                "title": row.get::<_, Option<String>>(1)?,
                "displayName": row.get::<_, Option<String>>(2)?,
                "source": row.get::<_, Option<String>>(3)?,
                "model": row.get::<_, Option<String>>(4)?,
                "cwd": row.get::<_, Option<String>>(5)?,
                "gitRepoRoot": row.get::<_, Option<String>>(6)?,
                "gitBranch": row.get::<_, Option<String>>(7)?,
                "startedAt": row.get::<_, Option<f64>>(8)?,
                "endedAt": row.get::<_, Option<f64>>(9)?,
            });
            Ok((id, metadata))
        }))?;
        let session_rows = sql(rows.collect::<Result<Vec<_>, _>>())?;
        let mut records = Vec::with_capacity(session_rows.len());
        for (ordinal, (id, metadata)) in session_rows.into_iter().enumerate() {
            let message_sql = format!(
                "SELECT {}, {}, {}, {}, {}, {} FROM messages WHERE session_id = ?1 ORDER BY {}, id",
                Self::optional_column(&message_columns, "role"),
                Self::optional_column(&message_columns, "content"),
                Self::optional_column(&message_columns, "tool_calls"),
                Self::optional_column(&message_columns, "tool_name"),
                Self::optional_column(&message_columns, "timestamp"),
                Self::optional_column(&message_columns, "id"),
                Self::optional_column(&message_columns, "timestamp"),
            );
            let mut message_statement = sql(connection.prepare(&message_sql))?;
            let message_rows = sql(message_statement.query_map(params![id], |row| {
                    Ok(json!({
                        "role": row.get::<_, Option<String>>(0)?,
                        "content": row.get::<_, Option<String>>(1)?,
                        "toolCalls": row.get::<_, Option<String>>(2)?,
                        "toolName": row.get::<_, Option<String>>(3)?,
                        "timestamp": row.get::<_, Option<f64>>(4)?,
                        "id": row.get::<_, Option<i64>>(5)?,
                    }))
                }))?;
            let messages = sql(message_rows.collect::<Result<Vec<_>, _>>())?;
            let bytes = serde_json::to_vec(&json!({ "session": metadata, "messages": messages }))
                .map_err(|error| AdapterError::InvalidData(error.to_string()))?;
            let locator = format!("state.db#session/{id}");
            records.push(CapturedRecord {
                source: CapturedSource::FilesystemSemantic,
                source_locator: locator.clone(),
                source_session_id: Some(id.clone()),
                source_record_id: Some(id),
                ordinal: ordinal as u64,
                snapshot_id: String::new(),
                bytes,
            });
        }
        Ok(records)
    }
}

fn sql<T>(result: Result<T, rusqlite::Error>) -> Result<T, AdapterError> {
    result.map_err(|error| AdapterError::InvalidData(format!("Hermes SQLite operation failed: {error}")))
}

impl SourceAdapter for HermesAdapter {
    fn id(&self) -> &'static str { "hermes" }

    fn detect(&self, ctx: &DetectContext) -> Result<Vec<AgentInstall>, AdapterError> {
        if !ctx.explicit_roots.is_empty()
            && !ctx.explicit_roots.iter().any(|root| dunce::canonicalize(root).ok().as_deref() == Some(self.root.as_path()))
        { return Ok(Vec::new()); }
        if !self.db_path().is_file() { return Ok(Vec::new()); }
        Ok(vec![self.install()])
    }

    fn probe(&self, install: &AgentInstall) -> Result<ProbeReport, AdapterError> {
        if install.id != self.install().id { return Err(AdapterError::InvalidData("Hermes install mismatch".into())); }
        let _ = self.open_read_only()?;
        Ok(ProbeReport {
            adapter_id: self.id().into(),
            executable_version: install.executable_version.clone(),
            schema_fingerprint: SCHEMA_FINGERPRINT.into(),
            capabilities: self.capabilities(install),
            quarantine_reason: None,
        })
    }

    fn capture(&self, request: &CaptureRequest) -> Result<CaptureBatch, AdapterError> {
        if request.install.id != self.install().id { return Err(AdapterError::InvalidData("Hermes capture install mismatch".into())); }
        let mut records = self.capture_sessions()?;
        let mut hasher = Sha256::new();
        for record in &records { hasher.update(record.source_locator.as_bytes()); hasher.update([0]); hasher.update(&record.bytes); }
        let snapshot_id = request.snapshot_hint.clone().filter(|value| !value.is_empty()).unwrap_or_else(|| format!("sha256:{}", hex::encode(hasher.finalize())));
        for record in &mut records { record.snapshot_id = snapshot_id.clone(); }
        Ok(CaptureBatch { snapshot_id, records, issues: Vec::new() })
    }

    fn normalize(&self, record: &CapturedRecord) -> Result<NormalizeOutcome, AdapterError> {
        if !matches!(record.source, CapturedSource::FilesystemSemantic) {
            return Ok(NormalizeOutcome::Quarantined { reason_code: "hermes-unsupported-source".into(), fingerprint: format!("sha256:{}", hex::encode(Sha256::digest(&record.bytes))) });
        }
        match normalize_session(&record.bytes, self.install().id) {
            Ok(session) => Ok(NormalizeOutcome::Normalized(Box::new(session))),
            Err(_) => Ok(NormalizeOutcome::Quarantined { reason_code: "hermes-malformed-session".into(), fingerprint: format!("sha256:{}", hex::encode(Sha256::digest(&record.bytes))) }),
        }
    }

    fn capabilities(&self, _install: &AgentInstall) -> BTreeSet<SourceCapability> {
        BTreeSet::from([SourceCapability::FilesystemRawArchive, SourceCapability::KnownSemanticSchema])
    }
}

fn normalize_session(bytes: &[u8], install_id: Uuid) -> Result<CanonicalSession, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "invalid JSON")?;
    let metadata = value.get("session").ok_or("missing session")?;
    let source_id = metadata.get("id").and_then(Value::as_str).ok_or("missing id")?;
    let id = session_id(install_id, source_id);
    let raw_hash = Sha256Digest::from_bytes(bytes);
    let mut messages = Vec::new();
    let mut tool_events = Vec::new();
    let rows = value.get("messages").and_then(Value::as_array).ok_or("missing messages")?;
    let mut ordinal = 0u64;
    for row in rows {
        let role = row.get("role").and_then(Value::as_str).unwrap_or("unknown");
        let content = row.get("content").and_then(Value::as_str).unwrap_or("").to_owned();
        let tool_name = row.get("toolName").and_then(Value::as_str).map(ToOwned::to_owned);
        ordinal += 1;
        if role == "tool" || tool_name.is_some() {
            tool_events.push(ToolEvent { id: Uuid::new_v5(&id, format!("tool:{ordinal}").as_bytes()).to_string(), ordinal, tool_name: tool_name.unwrap_or_else(|| "tool".into()), status: "completed".into(), visible_input: None, visible_output: (!content.is_empty()).then_some(content), raw_ref: raw_hash.clone() });
            continue;
        }
        let canonical_role = match role { "user" => CanonicalRole::User, "assistant" => CanonicalRole::Assistant, "system" => CanonicalRole::System, _ => CanonicalRole::Unknown };
        messages.push(CanonicalMessage { id: message_id(id, Some(&format!("message:{ordinal}")), ordinal, &raw_hash), source_record_id: Some(format!("message:{ordinal}")), ordinal, role: canonical_role, raw_role: Some(role.into()), created_at_raw: row.get("timestamp").and_then(Value::as_f64).map(|value| value.to_string()), content: vec![ContentPart { kind: ContentPartKind::Text, text: Some(content), attachment_id: None, raw_extra: Default::default() }], raw_ref: raw_hash.clone() });
    }
    let workspace = metadata.get("cwd").and_then(Value::as_str).map(|path| {
        let path = dunce::canonicalize(path).ok().map(|path| path.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_owned());
        let canonical_uri = format!("file://{}", path.replace('\\', "/"));
        Workspace { id: workspace_id(&canonical_uri), path_native: path, canonical_uri, git_commit: None }
    });
    Ok(CanonicalSession { schema_version: CanonicalSchemaVersion::V0_1_0, id, install_id, source_session_id: source_id.into(), source_kind: "hermes".into(), workspace, title: metadata.get("title").and_then(Value::as_str).or_else(|| metadata.get("displayName").and_then(Value::as_str)).map(ToOwned::to_owned), archived: false, created_at_raw: metadata.get("startedAt").and_then(Value::as_f64).map(|value| value.to_string()), updated_at_raw: metadata.get("endedAt").and_then(Value::as_f64).map(|value| value.to_string()), model_provider: Some("hermes".into()), model_name: metadata.get("model").and_then(Value::as_str).map(ToOwned::to_owned), completeness: Completeness::Complete, messages, tool_events, attachments: Vec::new(), raw_extra: Default::default() })
}
