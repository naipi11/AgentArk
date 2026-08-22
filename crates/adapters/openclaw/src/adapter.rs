use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use agentark_adapter_sdk::{
    AdapterError, CaptureBatch, CaptureRequest, CapturedRecord, CapturedSource, DetectContext,
    NormalizeOutcome, ProbeReport, SourceAdapter, SourceCapability,
};
use agentark_canonical::{
    AgentInstall, AgentKind, CanonicalMessage, CanonicalRole, CanonicalSchemaVersion,
    CanonicalSession, Completeness, ContentPart, ContentPartKind, Sha256Digest, ToolEvent,
    Workspace, agent_install_id, message_id, session_id, workspace_id,
};
use agentark_security::AuthorizedRoot;
use rusqlite::{Connection, OpenFlags, Row, types::ValueRef};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use walkdir::WalkDir;

const SCHEMA_FINGERPRINT: &str = "sha256:openclaw-sqlite-dynamic-v1";

pub struct OpenClawAdapter {
    root: PathBuf,
}

impl OpenClawAdapter {
    pub fn new(root: &Path) -> Result<Self, AdapterError> {
        AuthorizedRoot::new(root.to_path_buf())?;
        Ok(Self {
            root: dunce::canonicalize(root)?,
        })
    }

    pub fn default_home() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("OPENCLAW_HOME") {
            return Some(PathBuf::from(path));
        }
        std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .map(|home| home.join(".openclaw"))
    }

    fn root_uri(&self) -> String {
        format!("file://{}", self.root.to_string_lossy().replace('\\', "/"))
    }

    fn install(&self) -> AgentInstall {
        let root_uri = self.root_uri();
        AgentInstall {
            id: agent_install_id(Uuid::nil(), "openclaw", &root_uri),
            kind: AgentKind::OpenClaw,
            executable_version: "sqlite-unknown".into(),
            authorized_root_uri: root_uri,
            adapter_version: "openclaw-adapter-v1".into(),
            schema_fingerprint: SCHEMA_FINGERPRINT.into(),
            capabilities: ["filesystem-raw-archive", "known-semantic-schema"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            quarantine_reason: None,
        }
    }

    fn database_paths(&self) -> Vec<PathBuf> {
        let mut paths = WalkDir::new(&self.root)
            .follow_links(false)
            .max_depth(7)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.into_path())
            .filter(|path| {
                let name = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default();
                if name.ends_with("-wal") || name.ends_with("-shm") || name.ends_with("-journal") {
                    return false;
                }
                matches!(
                    path.extension().and_then(|value| value.to_str()),
                    Some("sqlite" | "db")
                )
            })
            .collect::<Vec<_>>();
        paths.sort();
        paths.dedup();
        paths
    }

    fn open_read_only(path: &Path) -> Result<Connection, AdapterError> {
        let connection = sql(Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        ))?;
        sql(connection.busy_timeout(std::time::Duration::from_secs(3)))?;
        sql(connection.execute_batch("PRAGMA query_only = ON; PRAGMA foreign_keys = ON;"))?;
        Ok(connection)
    }

    fn capture_database(
        &self,
        path: &Path,
        ordinal_offset: &mut u64,
    ) -> Result<Vec<CapturedRecord>, AdapterError> {
        let connection = Self::open_read_only(path)?;
        let tables = table_names(&connection)?;
        let session_table = tables
            .iter()
            .find(|table| {
                let columns = table_columns(&connection, table).unwrap_or_default();
                let normalized = columns
                    .iter()
                    .map(|c| normalize_key(c))
                    .collect::<HashSet<_>>();
                (normalize_key(table).contains("session") || normalize_key(table) == "state")
                    && (normalized.contains("id")
                        || normalized.contains("sessionid")
                        || normalized.contains("sessionkey")
                        || normalized.contains("key"))
            })
            .cloned();
        let message_table = tables
            .iter()
            .find(|table| {
                let columns = table_columns(&connection, table).unwrap_or_default();
                let normalized = columns
                    .iter()
                    .map(|c| normalize_key(c))
                    .collect::<HashSet<_>>();
                (normalize_key(table).contains("message")
                    || normalize_key(table).contains("transcript")
                    || normalize_key(table).contains("event"))
                    && (normalized.contains("sessionid")
                        || normalized.contains("sessionkey")
                        || normalized.contains("parentid"))
            })
            .cloned();

        let session_rows = if let Some(table) = session_table.as_deref() {
            read_rows(&connection, table)?
        } else {
            Vec::new()
        };
        let message_rows = if let Some(table) = message_table.as_deref() {
            read_rows(&connection, table)?
        } else {
            Vec::new()
        };
        let mut grouped = HashMap::<String, Vec<Map<String, Value>>>::new();
        for row in message_rows {
            if let Some(key) = row_value(
                &row,
                &[
                    "session_id",
                    "sessionId",
                    "session_key",
                    "sessionKey",
                    "key",
                ],
            ) {
                grouped.entry(key).or_default().push(row);
            }
        }
        let mut sessions = session_rows;
        if sessions.is_empty() {
            let mut seen = HashSet::new();
            for key in grouped.keys() {
                if seen.insert(key.clone()) {
                    let mut row = Map::new();
                    row.insert("id".into(), Value::String(key.clone()));
                    row.insert("sessionKey".into(), Value::String(key.clone()));
                    sessions.push(row);
                }
            }
        }
        let db_name = path
            .strip_prefix(&self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let agent_scope = path.strip_prefix(&self.root).ok().and_then(|relative| {
            relative
                .components()
                .collect::<Vec<_>>()
                .windows(2)
                .find_map(|parts| {
                    (parts[0].as_os_str() == "agents")
                        .then(|| parts[1].as_os_str().to_string_lossy().into_owned())
                })
        });
        let mut records = Vec::with_capacity(sessions.len());
        for session in sessions {
            let source_id = row_value(
                &session,
                &[
                    "id",
                    "session_id",
                    "sessionId",
                    "key",
                    "session_key",
                    "sessionKey",
                ],
            )
            .unwrap_or_else(|| format!("row-{}", records.len()));
            let messages = grouped.remove(&source_id).unwrap_or_default();
            let payload = json!({
                "session": session,
                "messages": messages,
                "database": db_name,
                "agentId": agent_scope,
            });
            let bytes = serde_json::to_vec(&payload)
                .map_err(|error| AdapterError::InvalidData(error.to_string()))?;
            let locator = format!("{db_name}#session/{source_id}");
            records.push(CapturedRecord {
                source: CapturedSource::FilesystemSemantic,
                source_locator: locator,
                source_session_id: Some(source_id.clone()),
                source_record_id: Some(source_id),
                ordinal: *ordinal_offset,
                snapshot_id: String::new(),
                bytes,
            });
            *ordinal_offset += 1;
        }
        Ok(records)
    }

    fn capture_sessions(&self) -> Result<Vec<CapturedRecord>, AdapterError> {
        let mut ordinal = 0;
        let mut records = Vec::new();
        for path in self.database_paths() {
            records.extend(self.capture_database(&path, &mut ordinal)?);
        }
        Ok(records)
    }
}

fn sql<T>(result: Result<T, rusqlite::Error>) -> Result<T, AdapterError> {
    result.map_err(|error| {
        AdapterError::InvalidData(format!("OpenClaw SQLite operation failed: {error}"))
    })
}

fn quoted_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn table_names(connection: &Connection) -> Result<Vec<String>, AdapterError> {
    let mut statement = sql(
        connection.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
    )?;
    let rows = sql(statement.query_map([], |row| row.get::<_, String>(0)))?;
    sql(rows.collect::<Result<Vec<_>, _>>())
}

fn table_columns(connection: &Connection, table: &str) -> Result<Vec<String>, AdapterError> {
    let sql_text = format!("PRAGMA table_info({})", quoted_identifier(table));
    let mut statement = sql(connection.prepare(&sql_text))?;
    let rows = sql(statement.query_map([], |row| row.get::<_, String>(1)))?;
    sql(rows.collect::<Result<Vec<_>, _>>())
}

fn read_rows(
    connection: &Connection,
    table: &str,
) -> Result<Vec<Map<String, Value>>, AdapterError> {
    let sql_text = format!("SELECT * FROM {}", quoted_identifier(table));
    let mut statement = sql(connection.prepare(&sql_text))?;
    let columns = statement
        .column_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut rows = sql(statement.query([]))?;
    let mut output = Vec::new();
    while let Some(row) = sql(rows.next())? {
        output.push(row_to_json(row, &columns)?);
    }
    Ok(output)
}

fn row_to_json(row: &Row<'_>, columns: &[String]) -> Result<Map<String, Value>, AdapterError> {
    let mut output = Map::new();
    for (index, column) in columns.iter().enumerate() {
        output.insert(column.clone(), value_ref_to_json(sql(row.get_ref(index))?));
    }
    Ok(output)
}

fn value_ref_to_json(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => Value::Number(value.into()),
        ValueRef::Real(value) => serde_json::Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        ValueRef::Text(value) => Value::String(String::from_utf8_lossy(value).into_owned()),
        ValueRef::Blob(value) => Value::String(format!("hex:{}", hex::encode(value))),
    }
}

fn normalize_key(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn row_value(row: &Map<String, Value>, names: &[&str]) -> Option<String> {
    let wanted = names
        .iter()
        .map(|name| normalize_key(name))
        .collect::<HashSet<_>>();
    row.iter()
        .find_map(|(key, value)| {
            wanted.contains(&normalize_key(key)).then(|| match value {
                Value::String(value) => value.clone(),
                Value::Number(value) => value.to_string(),
                Value::Bool(value) => value.to_string(),
                Value::Null => String::new(),
                other => other.to_string(),
            })
        })
        .filter(|value| !value.is_empty())
}

fn row_value_json<'a>(row: &'a Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    let wanted = names
        .iter()
        .map(|name| normalize_key(name))
        .collect::<HashSet<_>>();
    row.iter()
        .find_map(|(key, value)| wanted.contains(&normalize_key(key)).then_some(value))
}

impl SourceAdapter for OpenClawAdapter {
    fn id(&self) -> &'static str {
        "openclaw"
    }

    fn detect(&self, ctx: &DetectContext) -> Result<Vec<AgentInstall>, AdapterError> {
        if !ctx.explicit_roots.is_empty()
            && !ctx
                .explicit_roots
                .iter()
                .any(|root| dunce::canonicalize(root).ok().as_deref() == Some(self.root.as_path()))
        {
            return Ok(Vec::new());
        }
        if self.database_paths().is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![self.install()])
    }

    fn probe(&self, install: &AgentInstall) -> Result<ProbeReport, AdapterError> {
        if install.id != self.install().id {
            return Err(AdapterError::InvalidData(
                "OpenClaw install mismatch".into(),
            ));
        }
        let databases = self.database_paths();
        if databases.is_empty() {
            return Err(AdapterError::InvalidData(
                "OpenClaw SQLite databases are missing".into(),
            ));
        }
        for database in databases {
            let connection = Self::open_read_only(&database)?;
            let _ =
                sql(connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0)))?;
        }
        Ok(ProbeReport {
            adapter_id: self.id().into(),
            executable_version: install.executable_version.clone(),
            schema_fingerprint: SCHEMA_FINGERPRINT.into(),
            capabilities: self.capabilities(install),
            quarantine_reason: None,
        })
    }

    fn capture(&self, request: &CaptureRequest) -> Result<CaptureBatch, AdapterError> {
        if request.install.id != self.install().id {
            return Err(AdapterError::InvalidData(
                "OpenClaw capture install mismatch".into(),
            ));
        }
        let mut records = self.capture_sessions()?;
        let mut hasher = Sha256::new();
        for record in &records {
            hasher.update(record.source_locator.as_bytes());
            hasher.update([0]);
            hasher.update(&record.bytes);
        }
        let snapshot_id = request
            .snapshot_hint
            .clone()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("sha256:{}", hex::encode(hasher.finalize())));
        for record in &mut records {
            record.snapshot_id = snapshot_id.clone();
        }
        Ok(CaptureBatch {
            snapshot_id,
            records,
            issues: Vec::new(),
        })
    }

    fn normalize(&self, record: &CapturedRecord) -> Result<NormalizeOutcome, AdapterError> {
        if !matches!(record.source, CapturedSource::FilesystemSemantic) {
            return Ok(NormalizeOutcome::Quarantined {
                reason_code: "openclaw-unsupported-source".into(),
                fingerprint: format!("sha256:{}", hex::encode(Sha256::digest(&record.bytes))),
            });
        }
        match normalize_session(&record.bytes, self.install().id) {
            Ok(session) => Ok(NormalizeOutcome::Normalized(Box::new(session))),
            Err(_) => Ok(NormalizeOutcome::Quarantined {
                reason_code: "openclaw-malformed-session".into(),
                fingerprint: format!("sha256:{}", hex::encode(Sha256::digest(&record.bytes))),
            }),
        }
    }

    fn capabilities(&self, _install: &AgentInstall) -> BTreeSet<SourceCapability> {
        BTreeSet::from([
            SourceCapability::FilesystemRawArchive,
            SourceCapability::KnownSemanticSchema,
        ])
    }
}

fn normalize_session(bytes: &[u8], install_id: Uuid) -> Result<CanonicalSession, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "invalid JSON")?;
    let metadata = value
        .get("session")
        .and_then(Value::as_object)
        .ok_or("missing session")?;
    let source_id = row_value(
        metadata,
        &[
            "id",
            "session_id",
            "sessionId",
            "key",
            "session_key",
            "sessionKey",
        ],
    )
    .ok_or("missing id")?;
    let id = session_id(install_id, &source_id);
    let raw_hash = Sha256Digest::from_bytes(bytes);
    let rows = value
        .get("messages")
        .and_then(Value::as_array)
        .ok_or("missing messages")?;
    let mut messages = Vec::new();
    let mut tool_events = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let ordinal = index as u64 + 1;
        let object = row.as_object().ok_or("invalid message row")?;
        let role = row_value(object, &["role", "type", "author_role", "sender"])
            .unwrap_or_else(|| "unknown".into());
        let content_value = row_value_json(
            object,
            &["content", "text", "message", "prompt", "response", "body"],
        );
        let content = content_value
            .map(|value| match value {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default();
        let tool_name = row_value(object, &["tool_name", "toolName", "name", "tool"]);
        if normalize_key(&role) == "tool"
            || tool_name.is_some()
            || normalize_key(&role).contains("toolresult")
        {
            tool_events.push(ToolEvent {
                id: Uuid::new_v5(&id, format!("tool:{ordinal}").as_bytes()).to_string(),
                ordinal,
                tool_name: tool_name.unwrap_or_else(|| "tool".into()),
                status: "completed".into(),
                visible_input: None,
                visible_output: (!content.is_empty()).then_some(content),
                raw_ref: raw_hash.clone(),
            });
            continue;
        }
        let canonical_role = match normalize_key(&role).as_str() {
            "user" => CanonicalRole::User,
            "assistant" => CanonicalRole::Assistant,
            "system" => CanonicalRole::System,
            _ => CanonicalRole::Unknown,
        };
        messages.push(CanonicalMessage {
            id: message_id(id, Some(&format!("message:{ordinal}")), ordinal, &raw_hash),
            source_record_id: Some(format!("message:{ordinal}")),
            ordinal,
            role: canonical_role,
            raw_role: Some(role),
            created_at_raw: row_value(object, &["timestamp", "created_at", "createdAt", "ts"]),
            content: vec![ContentPart {
                kind: ContentPartKind::Text,
                text: Some(content),
                attachment_id: None,
                raw_extra: object.clone().into_iter().collect(),
            }],
            raw_ref: raw_hash.clone(),
        });
    }
    let workspace = row_value(
        metadata,
        &[
            "cwd",
            "workspace",
            "workspace_path",
            "project_path",
            "projectPath",
        ],
    )
    .map(|path| {
        let canonical_uri = format!("file://{}", path.replace('\\', "/"));
        Workspace {
            id: workspace_id(&canonical_uri),
            path_native: path,
            canonical_uri,
            git_commit: None,
        }
    });
    let raw_extra = [
        (
            "database",
            value.get("database").cloned().unwrap_or(Value::Null),
        ),
        (
            "agentId",
            value.get("agentId").cloned().unwrap_or(Value::Null),
        ),
        (
            "sessionKey",
            row_value_json(metadata, &["sessionKey", "session_key"])
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "chatType",
            row_value_json(metadata, &["chatType", "chat_type"])
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "channel",
            row_value_json(metadata, &["channel"])
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "peerId",
            row_value_json(metadata, &["peerId", "peer_id"])
                .cloned()
                .unwrap_or(Value::Null),
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect::<BTreeMap<_, _>>();
    Ok(CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id,
        install_id,
        source_session_id: source_id,
        source_kind: "openclaw".into(),
        workspace,
        title: row_value(
            metadata,
            &["title", "display_name", "displayName", "subject"],
        ),
        archived: row_value_json(metadata, &["archived"])
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || row_value(metadata, &["archived_at", "archivedAt"]).is_some(),
        created_at_raw: row_value(
            metadata,
            &["created_at", "createdAt", "sessionStartedAt", "started_at"],
        ),
        updated_at_raw: row_value(
            metadata,
            &[
                "updated_at",
                "updatedAt",
                "lastActivityAt",
                "last_activity_at",
            ],
        ),
        model_provider: row_value(metadata, &["provider", "providerOverride"]),
        model_name: row_value(metadata, &["model", "model_name", "modelOverride"]),
        completeness: Completeness::Complete,
        messages,
        tool_events,
        attachments: Vec::new(),
        raw_extra,
    })
}
