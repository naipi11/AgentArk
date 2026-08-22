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

const SCHEMA_FINGERPRINT: &str = "sha256:opencode-sqlite-session-v1";

pub struct OpenCodeAdapter {
    root: PathBuf,
}

impl OpenCodeAdapter {
    pub fn new(root: &Path) -> Result<Self, AdapterError> {
        AuthorizedRoot::new(root.to_path_buf())?;
        let canonical = dunce::canonicalize(root)?;
        Ok(Self { root: canonical })
    }

    pub fn default_home() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("OPENCODE_DB") {
            return PathBuf::from(path).parent().map(Path::to_path_buf);
        }
        if let Some(path) = std::env::var_os("OPENCODE_DATA_DIR") {
            return Some(PathBuf::from(path));
        }
        if let Some(path) = std::env::var_os("OPENCODE_HOME") {
            return Some(PathBuf::from(path));
        }
        if cfg!(windows)
            && let Some(path) = std::env::var_os("LOCALAPPDATA")
        {
            return Some(PathBuf::from(path).join("opencode"));
        }
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
            .map(|home| home.join(".local").join("share").join("opencode"))
    }

    fn db_path(&self) -> PathBuf {
        if self.root.is_file() {
            self.root.clone()
        } else {
            self.root.join("opencode.db")
        }
    }

    fn root_uri(&self) -> String {
        format!("file://{}", self.root.to_string_lossy().replace('\\', "/"))
    }

    fn install(&self) -> AgentInstall {
        let root_uri = self.root_uri();
        AgentInstall {
            id: agent_install_id(Uuid::nil(), "opencode", &root_uri),
            kind: AgentKind::OpenCode,
            executable_version: "sqlite-unknown".into(),
            authorized_root_uri: root_uri,
            adapter_version: "opencode-adapter-v1".into(),
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
            return Err(AdapterError::InvalidData(
                "OpenCode opencode.db is missing".into(),
            ));
        }
        let connection = sql(Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        ))?;
        sql(connection.busy_timeout(std::time::Duration::from_secs(3)))?;
        sql(connection.execute_batch("PRAGMA query_only = ON; PRAGMA foreign_keys = ON;"))?;
        Ok(connection)
    }

    fn capture_sessions(&self) -> Result<Vec<CapturedRecord>, AdapterError> {
        let connection = self.open_read_only()?;
        let tables = table_names(&connection)?;
        if !tables.iter().any(|table| table == "session") {
            return Err(AdapterError::InvalidData(
                "OpenCode database lacks the session table".into(),
            ));
        }
        let sessions = read_rows(&connection, "session")?;
        let messages = if tables.iter().any(|table| table == "message") {
            read_rows(&connection, "message")?
        } else {
            Vec::new()
        };
        let parts = if tables.iter().any(|table| table == "part") {
            read_rows(&connection, "part")?
        } else {
            Vec::new()
        };
        let mut parts_by_message = HashMap::<String, Vec<Map<String, Value>>>::new();
        for part in parts {
            if let Some(message_id) = row_value(&part, &["message_id", "messageID"]) {
                parts_by_message.entry(message_id).or_default().push(part);
            }
        }
        let mut messages_by_session = HashMap::<String, Vec<Value>>::new();
        for message in messages {
            let session_id = row_value(&message, &["session_id", "sessionID"]).unwrap_or_default();
            let message_id = row_value(&message, &["id", "message_id", "messageID"]);
            let attached_parts = message_id
                .as_deref()
                .and_then(|id| parts_by_message.get(id))
                .cloned()
                .unwrap_or_default();
            messages_by_session
                .entry(session_id)
                .or_default()
                .push(json!({ "row": message, "parts": attached_parts }));
        }
        let db_path = self.db_path();
        let db_name = db_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("opencode.db");
        let mut records = Vec::with_capacity(sessions.len());
        for (ordinal, session) in sessions.into_iter().enumerate() {
            let source_id = row_value(&session, &["id", "session_id", "sessionID"])
                .unwrap_or_else(|| format!("row-{ordinal}"));
            let payload = json!({
                "session": session,
                "messages": messages_by_session.remove(&source_id).unwrap_or_default(),
                "database": db_name,
            });
            let bytes = serde_json::to_vec(&payload)
                .map_err(|error| AdapterError::InvalidData(error.to_string()))?;
            records.push(CapturedRecord {
                source: CapturedSource::FilesystemSemantic,
                source_locator: format!("{db_name}#session/{source_id}"),
                source_session_id: Some(source_id.clone()),
                source_record_id: Some(source_id),
                ordinal: ordinal as u64,
                snapshot_id: String::new(),
                bytes,
            });
        }
        Ok(records)
    }
}

fn sql<T>(result: Result<T, rusqlite::Error>) -> Result<T, AdapterError> {
    result.map_err(|error| {
        AdapterError::InvalidData(format!("OpenCode SQLite operation failed: {error}"))
    })
}

fn table_names(connection: &Connection) -> Result<Vec<String>, AdapterError> {
    let mut statement = sql(
        connection.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
    )?;
    let rows = sql(statement.query_map([], |row| row.get::<_, String>(0)))?;
    sql(rows.collect::<Result<Vec<_>, _>>())
}

fn quoted_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn read_rows(
    connection: &Connection,
    table: &str,
) -> Result<Vec<Map<String, Value>>, AdapterError> {
    let mut statement =
        sql(connection.prepare(&format!("SELECT * FROM {}", quoted_identifier(table))))?;
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
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(|character| character.to_lowercase())
        .collect()
}

fn row_value(row: &Map<String, Value>, names: &[&str]) -> Option<String> {
    let names = names
        .iter()
        .map(|name| normalize_key(name))
        .collect::<HashSet<_>>();
    row.iter()
        .find_map(|(key, value)| {
            names.contains(&normalize_key(key)).then(|| match value {
                Value::String(value) => value.clone(),
                Value::Number(value) => value.to_string(),
                Value::Bool(value) => value.to_string(),
                Value::Null => String::new(),
                other => other.to_string(),
            })
        })
        .filter(|value| !value.is_empty())
}

fn parse_json_object(value: Option<&Value>) -> Map<String, Value> {
    match value {
        Some(Value::String(text)) => serde_json::from_str(text).unwrap_or_default(),
        Some(Value::Object(object)) => object.clone(),
        _ => Map::new(),
    }
}

impl SourceAdapter for OpenCodeAdapter {
    fn id(&self) -> &'static str {
        "opencode"
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
        if !self.db_path().is_file() {
            return Ok(Vec::new());
        }
        Ok(vec![self.install()])
    }

    fn probe(&self, install: &AgentInstall) -> Result<ProbeReport, AdapterError> {
        if install.id != self.install().id {
            return Err(AdapterError::InvalidData(
                "OpenCode install mismatch".into(),
            ));
        }
        let connection = self.open_read_only()?;
        let tables = table_names(&connection)?;
        if !tables.iter().any(|table| table == "session") {
            return Ok(ProbeReport {
                adapter_id: self.id().into(),
                executable_version: install.executable_version.clone(),
                schema_fingerprint: SCHEMA_FINGERPRINT.into(),
                capabilities: BTreeSet::from([SourceCapability::FilesystemRawArchive]),
                quarantine_reason: Some("opencode-session-schema-unknown".into()),
            });
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
                "OpenCode capture install mismatch".into(),
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
                reason_code: "opencode-unsupported-source".into(),
                fingerprint: format!("sha256:{}", hex::encode(Sha256::digest(&record.bytes))),
            });
        }
        match normalize_session(&record.bytes, self.install().id) {
            Ok(session) => Ok(NormalizeOutcome::Normalized(Box::new(session))),
            Err(_) => Ok(NormalizeOutcome::Quarantined {
                reason_code: "opencode-malformed-session".into(),
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
    let session = value
        .get("session")
        .and_then(Value::as_object)
        .ok_or("missing session")?;
    let source_id = row_value(session, &["id", "session_id", "sessionID"]).ok_or("missing id")?;
    let id = session_id(install_id, &source_id);
    let raw_hash = Sha256Digest::from_bytes(bytes);
    let mut messages = Vec::new();
    let mut tool_events = Vec::new();
    let rows = value
        .get("messages")
        .and_then(Value::as_array)
        .ok_or("missing messages")?;
    for (index, item) in rows.iter().enumerate() {
        let ordinal = index as u64 + 1;
        let item = item.as_object().ok_or("invalid message")?;
        let row = item
            .get("row")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let data = parse_json_object(row.get("data"));
        let role = row_value(&data, &["role"])
            .or_else(|| row_value(&row, &["role"]))
            .unwrap_or_else(|| "unknown".into());
        let mut content = Vec::new();
        let parts = item
            .get("parts")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for part in parts {
            let part = part.as_object().ok_or("invalid part")?;
            let part_row = parse_json_object(part.get("data"));
            let part_type = row_value(&part_row, &["type"])
                .or_else(|| row_value(part, &["type"]))
                .unwrap_or_else(|| "unknown".into());
            let text = row_value(&part_row, &["text", "content", "summary"]);
            let state = part_row.get("state").and_then(Value::as_object);
            let tool_name = row_value(&part_row, &["tool", "tool_name", "name"]);
            if normalize_key(&part_type).contains("tool") || tool_name.is_some() {
                tool_events.push(ToolEvent {
                    id: Uuid::new_v5(
                        &id,
                        format!("tool:{ordinal}:{}", tool_events.len()).as_bytes(),
                    )
                    .to_string(),
                    ordinal,
                    tool_name: tool_name.unwrap_or_else(|| "tool".into()),
                    status: state
                        .and_then(|value| row_value(value, &["status"]))
                        .unwrap_or_else(|| "completed".into()),
                    visible_input: state.and_then(|value| row_value(value, &["input", "args"])),
                    visible_output: state
                        .and_then(|value| row_value(value, &["output", "result", "title"])),
                    raw_ref: raw_hash.clone(),
                });
            } else if let Some(text) = text {
                content.push(ContentPart {
                    kind: if normalize_key(&part_type).contains("image") {
                        ContentPartKind::Image
                    } else {
                        ContentPartKind::Text
                    },
                    text: Some(text),
                    attachment_id: None,
                    raw_extra: part_row.clone().into_iter().collect(),
                });
            }
            if content.is_empty()
                && let Some(text) = row_value(&data, &["text", "content", "prompt", "response"])
            {
                content.push(ContentPart {
                    kind: ContentPartKind::Text,
                    text: Some(text),
                    attachment_id: None,
                    raw_extra: data.clone().into_iter().collect(),
                });
            }
        }
        let canonical_role = match normalize_key(&role).as_str() {
            "user" => CanonicalRole::User,
            "assistant" => CanonicalRole::Assistant,
            "system" => CanonicalRole::System,
            _ => CanonicalRole::Unknown,
        };
        messages.push(CanonicalMessage {
            id: message_id(id, row_value(&row, &["id"]).as_deref(), ordinal, &raw_hash),
            source_record_id: row_value(&row, &["id"]),
            ordinal,
            role: canonical_role,
            raw_role: Some(role),
            created_at_raw: row_value(&data, &["time_created", "createdAt"])
                .or_else(|| row_value(&row, &["time_created", "created_at"])),
            content,
            raw_ref: raw_hash.clone(),
        });
    }
    let directory = row_value(session, &["directory", "path", "cwd"]);
    let workspace = directory.map(|path| {
        let canonical_uri = format!("file://{}", path.replace('\\', "/"));
        Workspace {
            id: workspace_id(&canonical_uri),
            path_native: path,
            canonical_uri,
            git_commit: None,
        }
    });
    let model = parse_json_object(session.get("model"));
    let raw_extra = [
        (
            "projectId",
            row_value_json(session, &["project_id", "projectID"])
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "workspaceId",
            row_value_json(session, &["workspace_id", "workspaceID"])
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "agent",
            row_value_json(session, &["agent"])
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "providerId",
            row_value_json(&model, &["providerID", "provider_id"])
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "variant",
            row_value_json(&model, &["variant"])
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
        source_kind: "opencode".into(),
        workspace,
        title: row_value(session, &["title", "slug"]),
        archived: row_value(session, &["time_archived", "archived_at"]).is_some(),
        created_at_raw: row_value(session, &["time_created", "created_at"]),
        updated_at_raw: row_value(session, &["time_updated", "updated_at"]),
        model_provider: row_value(&model, &["providerID", "provider_id"]),
        model_name: row_value(&model, &["id", "modelID", "model_id"]),
        completeness: Completeness::Complete,
        messages,
        tool_events,
        attachments: Vec::new(),
        raw_extra,
    })
}

fn row_value_json<'a>(row: &'a Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    let names = names
        .iter()
        .map(|name| normalize_key(name))
        .collect::<HashSet<_>>();
    row.iter()
        .find_map(|(key, value)| names.contains(&normalize_key(key)).then_some(value))
}
