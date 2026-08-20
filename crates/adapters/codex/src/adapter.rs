use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use agentark_adapter_sdk::{
    AdapterError, CaptureBatch, CaptureRequest, CapturedRecord, DetectContext, NormalizeOutcome,
    ProbeReport, SourceAdapter, SourceCapability,
};
use agentark_canonical::{AgentInstall, AgentKind, agent_install_id};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    CODEX_SCHEMA_SHA256, CODEX_VERSION, CodexError, CodexProbe, capture_jsonl_file,
    collect_jsonl_paths, normalize_thread_read_bytes, tree_digest,
};

pub struct CodexAdapter {
    root: PathBuf,
}

impl CodexAdapter {
    pub fn new(root: &Path) -> Result<Self, CodexError> {
        agentark_security::AuthorizedRoot::new(root.to_path_buf())
            .map_err(|_| CodexError::InvalidOutput)?;
        Ok(Self {
            root: dunce::canonicalize(root)?,
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
        CodexProbe::from_outputs(
            &format!("codex-cli {}", install.executable_version),
            "--listen stdio://",
        )
        .map_err(|_| AdapterError::InvalidData("Codex probe failed".into()))
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
        for relative in paths {
            let record =
                capture_jsonl_file(&self.root, &relative).map_err(|error| match error {
                    CodexError::Retryable(_) => {
                        AdapterError::InvalidData("Codex source record is incomplete".into())
                    }
                    CodexError::SourceChanged => {
                        AdapterError::InvalidData("Codex source changed during capture".into())
                    }
                    _ => AdapterError::InvalidData("Codex source record cannot be read".into()),
                })?;
            hasher.update(record.source_locator.as_bytes());
            hasher.update([0]);
            hasher.update(&record.bytes);
            records.push(record);
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
        })
    }

    fn normalize(&self, record: &CapturedRecord) -> Result<NormalizeOutcome, AdapterError> {
        match normalize_thread_read_bytes(&record.bytes) {
            Ok(session) => Ok(NormalizeOutcome::Normalized(Box::new(session))),
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
