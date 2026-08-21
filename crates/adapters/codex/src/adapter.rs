use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use agentark_adapter_sdk::{
    AdapterError, CaptureBatch, CaptureIssue, CaptureRequest, CapturedRecord, CapturedSource,
    DetectContext, NormalizeOutcome, ProbeReport, SourceAdapter, SourceCapability,
};
use agentark_canonical::{AgentInstall, AgentKind, agent_install_id};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    CODEX_SCHEMA_SHA256, CODEX_VERSION, CodexError, CodexProbe, JsonRpcTransport, ProcessTransport,
    ReadOnlyAppServerClient, capture_jsonl_file, collect_jsonl_paths,
    normalize_thread_read_bytes_for_install, tree_digest,
};

pub struct CodexAdapter {
    root: PathBuf,
    executable: Option<PathBuf>,
}

impl CodexAdapter {
    /// Construct a filesystem-only adapter for fixtures and explicitly raw-only callers.
    pub fn new(root: &Path) -> Result<Self, CodexError> {
        Self::from_root(root, None)
    }

    /// Construct an adapter that also obtains semantic sessions from Codex App Server.
    pub fn with_executable(root: &Path, executable: PathBuf) -> Result<Self, CodexError> {
        Self::from_root(root, Some(executable))
    }

    fn from_root(root: &Path, executable: Option<PathBuf>) -> Result<Self, CodexError> {
        agentark_security::AuthorizedRoot::new(root.to_path_buf())
            .map_err(|_| CodexError::InvalidOutput)?;
        Ok(Self {
            root: dunce::canonicalize(root)?,
            executable,
        })
    }

    pub fn tree_digest(root: &Path) -> Result<String, CodexError> {
        tree_digest(root)
    }

    fn root_uri(&self) -> String {
        format!("file://{}", self.root.to_string_lossy().replace('\\', "/"))
    }

    fn install(&self) -> AgentInstall {
        AgentInstall {
            id: agent_install_id(Uuid::nil(), "codex", &self.root_uri()),
            kind: AgentKind::Codex,
            executable_version: CODEX_VERSION.into(),
            authorized_root_uri: self.root_uri(),
            adapter_version: "0.1.0".into(),
            schema_fingerprint: format!("sha256:{CODEX_SCHEMA_SHA256}"),
            capabilities: [
                "app-server-read",
                "filesystem-raw-archive",
                "archived-threads",
                "known-semantic-schema",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            quarantine_reason: None,
        }
    }

    fn capture_app_server(&self, executable: &Path) -> Result<Vec<CapturedRecord>, CodexError> {
        let mut transport = ProcessTransport::spawn(executable)?;
        let mut client = ReadOnlyAppServerClient::new(&mut transport);
        self.capture_app_server_client(&mut client)
    }

    fn capture_app_server_client<T: JsonRpcTransport>(
        &self,
        client: &mut ReadOnlyAppServerClient<'_, T>,
    ) -> Result<Vec<CapturedRecord>, CodexError> {
        client.initialize()?;
        let mut records = Vec::new();
        let mut seen = BTreeSet::new();
        for archived in [false, true] {
            for response in client.list_threads(archived)? {
                let threads = response
                    .value
                    .get("result")
                    .and_then(|result| result.get("data").or_else(|| result.get("threads")))
                    .and_then(Value::as_array)
                    .ok_or(CodexError::InvalidOutput)?;
                for thread in threads {
                    let thread_id = thread
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .ok_or(CodexError::InvalidOutput)?;
                    if !seen.insert(thread_id.to_owned()) {
                        continue;
                    }
                    let response = client.read_thread(thread_id)?;
                    records.push(CapturedRecord {
                        source: CapturedSource::AppServerSemantic,
                        source_locator: format!(
                            "app-server/{}/{}.json",
                            if archived { "archived" } else { "active" },
                            sanitize_thread_id(thread_id)
                        ),
                        source_session_id: Some(thread_id.to_owned()),
                        source_record_id: Some(thread_id.to_owned()),
                        ordinal: records.len() as u64,
                        snapshot_id: String::new(),
                        bytes: response.bytes,
                    });
                }
            }
        }
        Ok(records)
    }
}

impl SourceAdapter for CodexAdapter {
    fn id(&self) -> &'static str {
        "codex"
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
        Ok(vec![self.install()])
    }

    fn probe(&self, install: &AgentInstall) -> Result<ProbeReport, AdapterError> {
        if install.id != self.install().id {
            return Err(AdapterError::InvalidData(
                "Codex install does not belong to this adapter".into(),
            ));
        }
        let report = match self.executable.as_deref() {
            Some(executable) => CodexProbe::run(executable),
            None => CodexProbe::from_outputs(
                &format!("codex-cli {}", install.executable_version),
                "--listen stdio://",
            ),
        }
        .map_err(|error| AdapterError::InvalidData(format!("Codex probe failed: {error}")))?;
        Ok(report)
    }

    fn capture(&self, request: &CaptureRequest) -> Result<CaptureBatch, AdapterError> {
        if request.install.id != self.install().id {
            return Err(AdapterError::InvalidData(
                "Codex capture install does not belong to this adapter".into(),
            ));
        }
        let paths = collect_jsonl_paths(&self.root).map_err(|_| {
            AdapterError::InvalidData("Codex source tree cannot be enumerated".into())
        })?;
        let mut hasher = Sha256::new();
        let mut records = Vec::with_capacity(paths.len());
        let mut issues = Vec::new();
        for relative in paths {
            match capture_jsonl_file(&self.root, &relative) {
                Ok(record) => {
                    hasher.update(record.source_locator.as_bytes());
                    hasher.update([0]);
                    hasher.update(&record.bytes);
                    records.push(record);
                }
                Err(CodexError::Retryable(reason_code)) => issues.push(CaptureIssue {
                    source_locator: relative.to_string_lossy().replace('\\', "/"),
                    source_session_id: source_session_id_for_path(&relative),
                    reason_code: reason_code.into(),
                    retryable: true,
                }),
                Err(CodexError::SourceChanged) => issues.push(CaptureIssue {
                    source_locator: relative.to_string_lossy().replace('\\', "/"),
                    source_session_id: source_session_id_for_path(&relative),
                    reason_code: "source-changed".into(),
                    retryable: true,
                }),
                Err(_) => {
                    return Err(AdapterError::InvalidData(
                        "Codex source record cannot be read".into(),
                    ));
                }
            }
        }

        if let Some(executable) = &self.executable {
            match self.capture_app_server(executable) {
                Ok(semantic_records) => {
                    let semantic_ids = semantic_records
                        .iter()
                        .filter_map(|record| record.source_session_id.as_deref())
                        .collect::<BTreeSet<_>>();
                    for record in &mut records {
                        if record
                            .source_session_id
                            .as_deref()
                            .is_some_and(|id| semantic_ids.contains(id))
                        {
                            record.source = CapturedSource::FilesystemEvidence;
                        }
                    }
                    for record in semantic_records {
                        hasher.update(record.source_locator.as_bytes());
                        hasher.update([0]);
                        hasher.update(&record.bytes);
                        records.push(record);
                    }
                }
                Err(error) => issues.push(CaptureIssue {
                    source_locator: "app-server".into(),
                    source_session_id: None,
                    reason_code: app_server_retry_reason(&error).into(),
                    retryable: true,
                }),
            }
        }

        let snapshot_id = request
            .snapshot_hint
            .clone()
            .filter(|hint| !hint.is_empty())
            .unwrap_or_else(|| format!("sha256:{}", hex::encode(hasher.finalize())));
        for record in &mut records {
            record.snapshot_id = snapshot_id.clone();
        }
        Ok(CaptureBatch {
            snapshot_id,
            records,
            issues,
        })
    }

    fn normalize(&self, record: &CapturedRecord) -> Result<NormalizeOutcome, AdapterError> {
        if !matches!(record.source, CapturedSource::AppServerSemantic) {
            return Ok(NormalizeOutcome::Quarantined {
                reason_code: "filesystem-raw-only".into(),
                fingerprint: format!("sha256:{}", hex::encode(Sha256::digest(&record.bytes))),
            });
        }
        match normalize_thread_read_bytes_for_install(&record.bytes, self.install().id) {
            Ok(mut session) => {
                if record.source_locator.contains("/archived/") {
                    session.archived = true;
                }
                Ok(NormalizeOutcome::Normalized(Box::new(session)))
            }
            Err(CodexError::Retryable(reason_code)) => Ok(NormalizeOutcome::Retryable {
                reason_code: reason_code.into(),
            }),
            Err(CodexError::MalformedJson) => Ok(NormalizeOutcome::Quarantined {
                reason_code: "malformed-app-server-response".into(),
                fingerprint: format!("sha256:{}", hex::encode(Sha256::digest(&record.bytes))),
            }),
            Err(_) => Ok(NormalizeOutcome::Rejected {
                reason_code: "unsupported-app-server-response".into(),
            }),
        }
    }

    fn capabilities(&self, _install: &AgentInstall) -> BTreeSet<SourceCapability> {
        BTreeSet::from([
            SourceCapability::AppServerRead,
            SourceCapability::ArchivedThreads,
            SourceCapability::FilesystemRawArchive,
            SourceCapability::KnownSemanticSchema,
        ])
    }
}

fn source_session_id_for_path(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn app_server_retry_reason(error: &CodexError) -> &'static str {
    match error {
        CodexError::Timeout => "app-server-timeout",
        CodexError::Io(_) => "app-server-unavailable",
        CodexError::Protocol | CodexError::MalformedJson | CodexError::EndOfStream => {
            "app-server-protocol-error"
        }
        _ => "app-server-capture-retryable",
    }
}

fn sanitize_thread_id(value: &str) -> String {
    let mut output = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    output.truncate(128);
    if output.is_empty() {
        "thread".into()
    } else {
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RawJsonRpc;
    use serde_json::json;

    struct ScriptedTransport {
        responses: Vec<RawJsonRpc>,
    }

    impl JsonRpcTransport for ScriptedTransport {
        fn send_value(&mut self, _value: &Value) -> Result<(), CodexError> {
            Ok(())
        }

        fn receive_value(&mut self) -> Result<RawJsonRpc, CodexError> {
            if self.responses.is_empty() {
                return Err(CodexError::EndOfStream);
            }
            Ok(self.responses.remove(0))
        }
    }

    fn response(value: Value) -> RawJsonRpc {
        let bytes = serde_json::to_vec(&value).unwrap();
        RawJsonRpc { bytes, value }
    }

    #[test]
    fn app_server_capture_produces_semantic_records_for_scan() {
        let root = tempfile::tempdir().unwrap();
        let adapter = CodexAdapter::new(root.path()).unwrap();
        let mut transport = ScriptedTransport {
            responses: vec![
                response(json!({"id": 1, "result": {}})),
                response(json!({
                    "id": 2,
                    "result": {"data": [{"id": "thread-a"}], "nextCursor": null}
                })),
                response(json!({
                    "id": 3,
                    "result": {"thread": {"id": "thread-a", "turns": []}}
                })),
                response(json!({
                    "id": 4,
                    "result": {"data": [], "nextCursor": null}
                })),
            ],
        };
        let mut client = ReadOnlyAppServerClient::new(&mut transport);
        let records = adapter.capture_app_server_client(&mut client).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source, CapturedSource::AppServerSemantic);
        assert_eq!(records[0].source_session_id.as_deref(), Some("thread-a"));
        let outcome = adapter.normalize(&records[0]).unwrap();
        assert!(matches!(outcome, NormalizeOutcome::Normalized(_)));
    }

    #[test]
    fn canonical_identity_is_scoped_to_the_authorized_install() {
        let root_a = tempfile::tempdir().unwrap();
        let root_b = tempfile::tempdir().unwrap();
        let adapter_a = CodexAdapter::new(root_a.path()).unwrap();
        let adapter_b = CodexAdapter::new(root_b.path()).unwrap();
        let record = |_adapter: &CodexAdapter| CapturedRecord {
            source: CapturedSource::AppServerSemantic,
            source_locator: "app-server/active/thread-a.json".into(),
            source_session_id: Some("thread-a".into()),
            source_record_id: Some("thread-a".into()),
            ordinal: 0,
            snapshot_id: "snapshot".into(),
            bytes: br#"{"result":{"thread":{"id":"thread-a","turns":[]}}}"#.to_vec(),
        };
        let first = adapter_a.normalize(&record(&adapter_a)).unwrap();
        let second = adapter_b.normalize(&record(&adapter_b)).unwrap();
        let first_id = match first {
            NormalizeOutcome::Normalized(session) => session.id,
            _ => panic!("expected normalized session"),
        };
        let second_id = match second {
            NormalizeOutcome::Normalized(session) => session.id,
            _ => panic!("expected normalized session"),
        };
        assert_ne!(first_id, second_id);
    }
}
