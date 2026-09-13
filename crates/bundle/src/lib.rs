#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use agentark_canonical::{CanonicalSession, Sha256Digest, file_uri_for_path};
use agentark_security::{AuthorizedRoot, SecretScanner};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const MAGIC: &[u8; 9] = b"AHBUNDLE1";
const FORMAT_VERSION: &str = "1.2";
const MAX_ENTRY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_ENTRIES: u32 = 100_000;

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("bundle I/O failed")]
    Io(#[from] io::Error),
    #[error("bundle source security policy rejected the operation")]
    Security(#[from] agentark_security::SecurityError),
    #[error("bundle format is invalid: {0}")]
    InvalidFormat(String),
    #[error("bundle path is unsafe: {0}")]
    UnsafePath(String),
    #[error("bundle entry hash mismatch: {0}")]
    HashMismatch(String),
    #[error("bundle JSON failed")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleEntryMeta {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleManifest {
    pub format: String,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub source_root: Option<String>,
    pub created_at: String,
    pub session_count: u64,
    #[serde(default)]
    pub workspace_count: u64,
    #[serde(default)]
    pub file_count: u64,
    #[serde(default)]
    pub skipped_file_count: u64,
    pub redacted: bool,
    pub redaction_count: u64,
    pub entries: Vec<BundleEntryMeta>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleRecoverySession {
    pub canonical_session_id: uuid::Uuid,
    pub source_provider: Option<String>,
    pub source_model: Option<String>,
    pub native_payload_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleRecoveryManifest {
    pub version: String,
    pub sessions: Vec<BundleRecoverySession>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectSelection {
    pub workspace_id: uuid::Uuid,
    pub root: std::path::PathBuf,
    pub include_files: bool,
    pub max_file_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceFileEntry {
    pub workspace_id: uuid::Uuid,
    pub relative_path: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeBundleEntry {
    pub session_id: uuid::Uuid,
    pub relative_path: String,
    pub bytes: Vec<u8>,
    pub redaction_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawProvenanceSummary {
    pub sessions_with_references: u64,
    pub reference_count: u64,
}

struct BundleWriteMeta {
    agent: Option<String>,
    source_root: Option<String>,
    workspace_count: u64,
    file_count: u64,
    skipped_file_count: u64,
}

enum RecoveryLabelKind {
    Provider,
    Model,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleEntry {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Bundle {
    pub manifest: BundleManifest,
    pub entries: BTreeMap<String, Vec<u8>>,
}

impl Bundle {
    pub fn recovery_manifest(&self) -> Result<Option<BundleRecoveryManifest>, BundleError> {
        self.entries
            .get("recovery/manifest.json")
            .map(|bytes| serde_json::from_slice(bytes).map_err(BundleError::from))
            .transpose()
    }

    pub fn session_records(&self) -> Result<Vec<CanonicalSession>, BundleError> {
        let mut sessions = Vec::new();
        for (path, bytes) in &self.entries {
            if !path.starts_with("sessions/") || !path.ends_with(".ndjson") {
                continue;
            }
            let text = String::from_utf8(bytes.clone())
                .map_err(|_| BundleError::InvalidFormat(format!("entry {path} is not UTF-8")))?;
            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                sessions.push(serde_json::from_str(line)?);
            }
        }
        Ok(sessions)
    }

    pub fn raw_provenance_summary(&self) -> Result<RawProvenanceSummary, BundleError> {
        let sessions = self.session_records()?;
        if self.manifest.format == FORMAT_VERSION {
            raw_provenance_summary(&sessions)
        } else {
            // Legacy bundles remain readable even when their historical rawRef
            // value was not normalized as a `sha256:` digest. Such references
            // are reported as unresolved by callers, without exposing bytes.
            Ok(count_raw_references(&sessions))
        }
    }

    pub fn verify(&self) -> Result<(), BundleError> {
        let mut manifest_paths = BTreeSet::new();
        for meta in &self.manifest.entries {
            if meta.path == "manifest.json" {
                return Err(BundleError::InvalidFormat(
                    "manifest.json must not be listed in its own manifest".into(),
                ));
            }
            if !manifest_paths.insert(meta.path.clone()) {
                return Err(BundleError::InvalidFormat(format!(
                    "duplicate manifest entry {}",
                    meta.path
                )));
            }
            let bytes = self.entries.get(&meta.path).ok_or_else(|| {
                BundleError::InvalidFormat(format!("missing entry {}", meta.path))
            })?;
            if bytes.len() as u64 != meta.size {
                return Err(BundleError::HashMismatch(meta.path.clone()));
            }
            let hash = hex::encode(Sha256::digest(bytes));
            if hash != meta.sha256 {
                return Err(BundleError::HashMismatch(meta.path.clone()));
            }
        }

        let actual_paths = self
            .entries
            .keys()
            .filter(|path| path.as_str() != "manifest.json")
            .cloned()
            .collect::<BTreeSet<_>>();
        if let Some(path) = actual_paths.difference(&manifest_paths).next() {
            return Err(BundleError::InvalidFormat(format!(
                "entry {path} is not listed in manifest"
            )));
        }
        if let Some(path) = manifest_paths.difference(&actual_paths).next() {
            return Err(BundleError::InvalidFormat(format!(
                "manifest entry {path} is missing"
            )));
        }

        let strict_semantics = self.manifest.format == FORMAT_VERSION;
        let scanner = SecretScanner::v1().map_err(BundleError::from)?;
        let sessions = self.session_records()?;
        if strict_semantics {
            raw_provenance_summary(&sessions)?;
        }
        let mut session_ids = BTreeSet::new();
        for session in &sessions {
            if !session_ids.insert(session.id) {
                return Err(BundleError::InvalidFormat(
                    "duplicate canonical session ID".into(),
                ));
            }
            if strict_semantics {
                let (_, redaction_count) = redact_value(serde_json::to_value(session)?, &scanner);
                if redaction_count > 0 {
                    return Err(BundleError::InvalidFormat(
                        "bundle contains unsanitized session data".into(),
                    ));
                }
            }
        }
        if self.manifest.session_count != sessions.len() as u64 {
            return Err(BundleError::InvalidFormat(format!(
                "session count is inconsistent: manifest={}, entries={}",
                self.manifest.session_count,
                sessions.len()
            )));
        }

        if strict_semantics {
            let workspace_ids = self.workspace_ids()?;
            if self.manifest.workspace_count != workspace_ids.len() as u64 {
                return Err(BundleError::InvalidFormat(format!(
                    "workspace count is inconsistent: manifest={}, entries={}",
                    self.manifest.workspace_count,
                    workspace_ids.len()
                )));
            }
            let workspace_id_set = workspace_ids.iter().copied().collect::<BTreeSet<_>>();
            let workspace_files = self.workspace_file_entries()?;
            for entry in &workspace_files {
                let text = String::from_utf8(entry.bytes.clone()).map_err(|_| {
                    BundleError::InvalidFormat("bundle contains an unscannable project file".into())
                })?;
                let (_, redaction_count) = redact_value(Value::String(text), &scanner);
                if redaction_count > 0 {
                    return Err(BundleError::InvalidFormat(
                        "bundle contains unsanitized project-file data".into(),
                    ));
                }
            }
            if self.manifest.file_count != workspace_files.len() as u64 {
                return Err(BundleError::InvalidFormat(format!(
                    "file count is inconsistent: manifest={}, entries={}",
                    self.manifest.file_count,
                    workspace_files.len()
                )));
            }
            if workspace_files
                .iter()
                .any(|entry| !workspace_id_set.contains(&entry.workspace_id))
            {
                return Err(BundleError::InvalidFormat(
                    "workspace file entry has no workspace manifest".into(),
                ));
            }
            self.verify_workspace_manifests(&workspace_ids, &workspace_files)?;
        }

        let native_entries = self.native_rollout_entries()?;
        if strict_semantics {
            for entry in &native_entries {
                let text = String::from_utf8(entry.bytes.clone()).map_err(|_| {
                    BundleError::InvalidFormat(
                        "bundle contains an unscannable native payload".into(),
                    )
                })?;
                let (_, redaction_count) = redact_value(Value::String(text), &scanner);
                if redaction_count > 0 {
                    return Err(BundleError::InvalidFormat(
                        "bundle contains unsanitized native payload data".into(),
                    ));
                }
            }
            let mut native_session_ids = BTreeSet::new();
            for entry in &native_entries {
                if !session_ids.contains(&entry.session_id) {
                    return Err(BundleError::InvalidFormat(
                        "native rollout entry has no session record".into(),
                    ));
                }
                if !native_session_ids.insert(entry.session_id) {
                    return Err(BundleError::InvalidFormat(
                        "multiple native rollout entries reference one session".into(),
                    ));
                }
            }
        }
        if let Some(recovery) = self.recovery_manifest()? {
            if recovery.version != "1" {
                return Err(BundleError::InvalidFormat(
                    "unsupported recovery manifest version".into(),
                ));
            }
            let mut recovery_ids = BTreeSet::new();
            for entry in &recovery.sessions {
                if !recovery_ids.insert(entry.canonical_session_id)
                    || !session_ids.contains(&entry.canonical_session_id)
                {
                    return Err(BundleError::InvalidFormat(
                        "recovery manifest does not match session records".into(),
                    ));
                }
                let native_count = native_entries
                    .iter()
                    .filter(|native| native.session_id == entry.canonical_session_id)
                    .count() as u64;
                if entry.native_payload_count != native_count {
                    return Err(BundleError::InvalidFormat(
                        "recovery manifest native payload count is inconsistent".into(),
                    ));
                }
            }
            if strict_semantics && recovery_ids != session_ids {
                return Err(BundleError::InvalidFormat(
                    "recovery manifest does not cover all session records".into(),
                ));
            }
        }
        if strict_semantics && self.manifest.redacted != (self.manifest.redaction_count > 0) {
            return Err(BundleError::InvalidFormat(
                "redaction metadata is inconsistent".into(),
            ));
        }
        Ok(())
    }

    fn verify_workspace_manifests(
        &self,
        workspace_ids: &[uuid::Uuid],
        workspace_files: &[WorkspaceFileEntry],
    ) -> Result<(), BundleError> {
        for workspace_id in workspace_ids {
            let path = format!("workspaces/{workspace_id}/manifest.json");
            let bytes = self
                .entries
                .get(&path)
                .ok_or_else(|| BundleError::InvalidFormat(format!("missing entry {path}")))?;
            let value: Value = serde_json::from_slice(bytes)?;
            let manifest_id = value
                .get("workspaceId")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    BundleError::InvalidFormat(format!("workspace manifest {path} is invalid"))
                })?;
            if manifest_id != workspace_id.to_string() {
                return Err(BundleError::InvalidFormat(format!(
                    "workspace manifest {path} has the wrong workspace ID"
                )));
            }
            let listed = value
                .get("files")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    BundleError::InvalidFormat(format!("workspace manifest {path} is invalid"))
                })?;
            let mut listed_paths = BTreeSet::new();
            for file in listed {
                let relative = file.get("path").and_then(Value::as_str).ok_or_else(|| {
                    BundleError::InvalidFormat(format!("workspace manifest {path} is invalid"))
                })?;
                validate_relative_path(relative)?;
                if !listed_paths.insert(relative.to_owned()) {
                    return Err(BundleError::InvalidFormat(format!(
                        "workspace manifest {path} contains a duplicate file"
                    )));
                }
                let entry = workspace_files.iter().find(|entry| {
                    entry.workspace_id == *workspace_id && entry.relative_path == relative
                });
                let Some(entry) = entry else {
                    return Err(BundleError::InvalidFormat(format!(
                        "workspace manifest {path} references a missing file"
                    )));
                };
                let size = file.get("size").and_then(Value::as_u64).ok_or_else(|| {
                    BundleError::InvalidFormat(format!("workspace manifest {path} is invalid"))
                })?;
                let hash = file.get("sha256").and_then(Value::as_str).ok_or_else(|| {
                    BundleError::InvalidFormat(format!("workspace manifest {path} is invalid"))
                })?;
                if size != entry.bytes.len() as u64
                    || hash != hex::encode(Sha256::digest(&entry.bytes))
                {
                    return Err(BundleError::HashMismatch(format!("{path}::{relative}")));
                }
            }
            let actual_paths = workspace_files
                .iter()
                .filter(|entry| entry.workspace_id == *workspace_id)
                .map(|entry| entry.relative_path.as_str())
                .collect::<BTreeSet<_>>();
            if listed_paths
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != actual_paths
            {
                return Err(BundleError::InvalidFormat(format!(
                    "workspace manifest {path} does not match file entries"
                )));
            }
        }
        Ok(())
    }

    pub fn workspace_manifest(&self, workspace_id: uuid::Uuid) -> Result<Value, BundleError> {
        let path = format!("workspaces/{workspace_id}/manifest.json");
        let bytes = self
            .entries
            .get(&path)
            .ok_or_else(|| BundleError::InvalidFormat(format!("missing entry {path}")))?;
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn workspace_manifest_entries(
        &self,
        restore_root: &Path,
    ) -> Result<Vec<WorkspaceFileEntry>, BundleError> {
        self.workspace_ids()?
            .into_iter()
            .map(|workspace_id| {
                let value = self.workspace_manifest(workspace_id)?;
                let mut value = value;
                let destination = restore_root.join(workspace_id.to_string());
                let object = value.as_object_mut().ok_or_else(|| {
                    BundleError::InvalidFormat("workspace manifest must be an object".into())
                })?;
                object.insert(
                    "pathNative".into(),
                    Value::String(destination.to_string_lossy().into_owned()),
                );
                object.insert(
                    "canonicalUri".into(),
                    Value::String(file_uri_for_path(&destination)),
                );
                Ok(WorkspaceFileEntry {
                    workspace_id,
                    // Keep AgentArk metadata outside the user's project namespace.
                    // A project may legitimately contain its own manifest.json.
                    relative_path: ".agentark/manifest.json".into(),
                    bytes: serde_json::to_vec_pretty(&value)?,
                })
            })
            .collect()
    }

    pub fn workspace_file_entries(&self) -> Result<Vec<WorkspaceFileEntry>, BundleError> {
        let mut files = Vec::new();
        for (path, bytes) in &self.entries {
            let Some(rest) = path.strip_prefix("workspaces/") else {
                continue;
            };
            let Some((workspace, relative)) = rest.split_once("/files/") else {
                continue;
            };
            let workspace_id = uuid::Uuid::parse_str(workspace)
                .map_err(|_| BundleError::UnsafePath(path.clone()))?;
            validate_relative_path(relative)?;
            files.push(WorkspaceFileEntry {
                workspace_id,
                relative_path: relative.to_owned(),
                bytes: bytes.clone(),
            });
        }
        Ok(files)
    }

    pub fn workspace_ids(&self) -> Result<Vec<uuid::Uuid>, BundleError> {
        let mut ids = Vec::new();
        for path in self.entries.keys() {
            let Some(rest) = path.strip_prefix("workspaces/") else {
                continue;
            };
            let Some(id) = rest.strip_suffix("/manifest.json") else {
                continue;
            };
            // Only the workspace metadata entry is an immediate child. A
            // project file named manifest.json lives below `files/` and must
            // not be mistaken for another workspace manifest.
            if id.contains('/') {
                continue;
            }
            ids.push(uuid::Uuid::parse_str(id).map_err(|_| BundleError::UnsafePath(path.clone()))?);
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    pub fn native_rollout_entries(&self) -> Result<Vec<NativeBundleEntry>, BundleError> {
        let mut entries = Vec::new();
        for path in self.entries.keys() {
            let Some(rest) = path.strip_prefix("native/codex/") else {
                continue;
            };
            let Some((session, relative)) = rest.split_once('/') else {
                return Err(BundleError::UnsafePath(path.clone()));
            };
            let session_id = uuid::Uuid::parse_str(session)
                .map_err(|_| BundleError::UnsafePath(path.clone()))?;
            validate_relative_path(relative)?;
            entries.push(NativeBundleEntry {
                session_id,
                relative_path: relative.to_owned(),
                bytes: self
                    .entries
                    .get(path)
                    .cloned()
                    .ok_or_else(|| BundleError::InvalidFormat(path.clone()))?,
                // Redaction totals are intentionally represented by the
                // bundle manifest rather than duplicated in each payload.
                redaction_count: 0,
            });
        }
        Ok(entries)
    }
}

pub fn raw_provenance_summary(
    sessions: &[CanonicalSession],
) -> Result<RawProvenanceSummary, BundleError> {
    let summary = count_raw_references(sessions);
    let references = sessions.iter().flat_map(|session| {
        session
            .messages
            .iter()
            .map(|message| &message.raw_ref)
            .chain(session.tool_events.iter().map(|event| &event.raw_ref))
            .chain(
                session
                    .attachments
                    .iter()
                    .map(|attachment| &attachment.raw_ref),
            )
    });
    for reference in references {
        if Sha256Digest::parse(reference.as_str()).is_none() {
            return Err(BundleError::InvalidFormat(
                "session contains an invalid raw reference".into(),
            ));
        }
    }
    Ok(summary)
}

fn count_raw_references(sessions: &[CanonicalSession]) -> RawProvenanceSummary {
    let mut sessions_with_references = 0u64;
    let mut reference_count = 0u64;
    for session in sessions {
        let session_reference_count = session.messages.len() as u64
            + session.tool_events.len() as u64
            + session.attachments.len() as u64;
        if session_reference_count > 0 {
            sessions_with_references = sessions_with_references.saturating_add(1);
            reference_count = reference_count.saturating_add(session_reference_count);
        }
    }
    RawProvenanceSummary {
        sessions_with_references,
        reference_count,
    }
}

pub fn sanitize_session(
    session: &CanonicalSession,
    scanner: &SecretScanner,
) -> Result<(CanonicalSession, u64), BundleError> {
    let value = serde_json::to_value(session)?;
    let (value, count) = redact_value(value, scanner);
    Ok((serde_json::from_value(value)?, count))
}

pub fn write_sessions(
    path: &Path,
    sessions: &[CanonicalSession],
    scanner: &SecretScanner,
) -> Result<BundleManifest, BundleError> {
    let mut entries = Vec::with_capacity(sessions.len() + 1);
    let mut redaction_count = 0;
    for session in sessions {
        let value = serde_json::to_value(session)?;
        let (value, count) = redact_value(value, scanner);
        redaction_count += count;
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        entries.push(BundleEntry {
            path: format!("sessions/{}.ndjson", session.id),
            bytes,
        });
    }
    write_entries_with_meta(
        path,
        entries,
        sessions.len() as u64,
        redaction_count,
        BundleWriteMeta {
            agent: None,
            source_root: None,
            workspace_count: 0,
            file_count: 0,
            skipped_file_count: 0,
        },
    )
}

pub fn write_selected_sessions(
    path: &Path,
    agent: &str,
    sessions: &[CanonicalSession],
    selections: &[ProjectSelection],
    scanner: &SecretScanner,
) -> Result<BundleManifest, BundleError> {
    write_selected_sessions_with_native(path, agent, sessions, selections, &[], scanner)
}

pub fn write_selected_sessions_with_native(
    path: &Path,
    agent: &str,
    sessions: &[CanonicalSession],
    selections: &[ProjectSelection],
    native_entries: &[NativeBundleEntry],
    scanner: &SecretScanner,
) -> Result<BundleManifest, BundleError> {
    let mut entries = Vec::with_capacity(sessions.len() + selections.len());
    let mut redaction_count = 0;
    for session in sessions {
        let value = serde_json::to_value(session)?;
        let (value, count) = redact_value(value, scanner);
        redaction_count += count;
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        entries.push(BundleEntry {
            path: format!("sessions/{}.ndjson", session.id),
            bytes,
        });
    }
    let mut file_count = 0u64;
    let mut skipped_file_count = 0u64;
    let mut workspace_count = 0u64;
    let mut selected_workspace_ids = BTreeSet::new();
    for selection in selections {
        if !selected_workspace_ids.insert(selection.workspace_id) {
            continue;
        }
        let workspace = sessions.iter().find_map(|session| {
            session
                .workspace
                .as_ref()
                .filter(|workspace| workspace.id == selection.workspace_id)
        });
        let Some(workspace) = workspace else {
            continue;
        };
        let mut workspace_files = Vec::new();
        if selection.include_files {
            let authorized = AuthorizedRoot::new(selection.root.clone())?;
            for entry in walkdir::WalkDir::new(&selection.root)
                .follow_links(false)
                .max_depth(32)
                .into_iter()
                .filter_entry(should_export_project_entry)
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().is_file())
            {
                let relative = entry.path().strip_prefix(&selection.root).map_err(|_| {
                    BundleError::UnsafePath(entry.path().to_string_lossy().into_owned())
                })?;
                let relative_text = relative.to_string_lossy().replace('\\', "/");
                validate_relative_path(&relative_text)?;
                if is_credential_filename(&relative_text) {
                    continue;
                }
                let mut source = authorized.open_regular_file(relative)?;
                let metadata = source.metadata()?;
                if metadata.len() > selection.max_file_bytes {
                    skipped_file_count += 1;
                    continue;
                }
                let mut bytes = Vec::with_capacity(metadata.len() as usize);
                source.read_to_end(&mut bytes)?;
                let Some((bytes, count)) = redact_bytes(bytes, scanner) else {
                    skipped_file_count += 1;
                    continue;
                };
                redaction_count += count;
                file_count += 1;
                entries.push(BundleEntry {
                    path: format!(
                        "workspaces/{}/files/{}",
                        selection.workspace_id, relative_text
                    ),
                    bytes: bytes.clone(),
                });
                workspace_files.push(json!({"path": relative_text, "size": bytes.len(), "sha256": hex::encode(Sha256::digest(&bytes))}));
            }
        }
        let manifest = json!({"workspaceId": workspace.id, "pathNative": workspace.path_native, "canonicalUri": workspace.canonical_uri, "gitCommit": workspace.git_commit, "files": workspace_files});
        entries.push(BundleEntry {
            path: format!("workspaces/{}/manifest.json", selection.workspace_id),
            bytes: serde_json::to_vec_pretty(&manifest)?,
        });
        workspace_count += 1;
    }
    let session_ids = sessions
        .iter()
        .map(|session| session.id)
        .collect::<BTreeSet<_>>();
    let mut native_session_ids = BTreeSet::new();
    for native in native_entries {
        if !session_ids.contains(&native.session_id)
            || !native_session_ids.insert(native.session_id)
        {
            return Err(BundleError::InvalidFormat(
                "native rollout entry does not identify exactly one session".into(),
            ));
        }
        validate_relative_path(&native.relative_path)?;
        redaction_count += native.redaction_count;
        entries.push(BundleEntry {
            path: format!(
                "native/codex/{}/{}",
                native.session_id, native.relative_path
            ),
            bytes: native.bytes.clone(),
        });
    }
    let recovery_manifest = BundleRecoveryManifest {
        version: "1".into(),
        sessions: sessions
            .iter()
            .map(|session| BundleRecoverySession {
                canonical_session_id: session.id,
                source_provider: safe_recovery_label(
                    session.model_provider.as_deref(),
                    scanner,
                    RecoveryLabelKind::Provider,
                ),
                source_model: safe_recovery_label(
                    session.model_name.as_deref(),
                    scanner,
                    RecoveryLabelKind::Model,
                ),
                native_payload_count: native_entries
                    .iter()
                    .filter(|entry| entry.session_id == session.id)
                    .count() as u64,
            })
            .collect(),
    };
    entries.push(BundleEntry {
        path: "recovery/manifest.json".into(),
        bytes: serde_json::to_vec_pretty(&recovery_manifest)?,
    });
    let source_root = selections
        .first()
        .map(|selection| selection.root.to_string_lossy().into_owned());
    write_entries_with_meta(
        path,
        entries,
        sessions.len() as u64,
        redaction_count,
        BundleWriteMeta {
            agent: Some(agent.to_owned()),
            source_root,
            workspace_count,
            file_count,
            skipped_file_count,
        },
    )
}

fn should_export_project_entry(entry: &walkdir::DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return true;
    }

    !matches!(
        entry.file_name().to_str(),
        Some(".git" | ".hg" | ".svn" | ".worktrees" | "build" | "dist" | "node_modules" | "target")
    )
}

pub fn write_entries(
    path: &Path,
    entries: Vec<BundleEntry>,
    session_count: u64,
    redaction_count: u64,
) -> Result<BundleManifest, BundleError> {
    write_entries_with_meta(
        path,
        entries,
        session_count,
        redaction_count,
        BundleWriteMeta {
            agent: None,
            source_root: None,
            workspace_count: 0,
            file_count: 0,
            skipped_file_count: 0,
        },
    )
}

fn write_entries_with_meta(
    path: &Path,
    mut entries: Vec<BundleEntry>,
    session_count: u64,
    redaction_count: u64,
    meta: BundleWriteMeta,
) -> Result<BundleManifest, BundleError> {
    for entry in &entries {
        validate_relative_path(&entry.path)?;
        if entry.path == "manifest.json" {
            return Err(BundleError::InvalidFormat(
                "manifest.json is reserved for the bundle manifest".into(),
            ));
        }
        if entry.bytes.len() as u64 > MAX_ENTRY_BYTES {
            return Err(BundleError::InvalidFormat(format!(
                "entry {} is too large",
                entry.path
            )));
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    if let Some(window) = entries
        .windows(2)
        .find(|window| window[0].path == window[1].path)
    {
        return Err(BundleError::InvalidFormat(format!(
            "duplicate entry {}",
            window[0].path
        )));
    }
    if entries.len().saturating_add(1) > MAX_ENTRIES as usize {
        return Err(BundleError::InvalidFormat("too many bundle entries".into()));
    }
    let metadata = entries
        .iter()
        .map(|entry| BundleEntryMeta {
            path: entry.path.clone(),
            size: entry.bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&entry.bytes)),
        })
        .collect::<Vec<_>>();
    let manifest = BundleManifest {
        format: FORMAT_VERSION.into(),
        agent: meta.agent,
        source_root: meta.source_root,
        created_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default(),
        session_count,
        workspace_count: meta.workspace_count,
        file_count: meta.file_count,
        skipped_file_count: meta.skipped_file_count,
        redacted: redaction_count > 0,
        redaction_count,
        entries: metadata.clone(),
    };
    let manifest_with_self = BundleManifest {
        entries: metadata,
        ..manifest
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest_with_self)?;
    let mut all_entries = vec![BundleEntry {
        path: "manifest.json".into(),
        bytes: manifest_bytes,
    }];
    all_entries.extend(entries);
    let total = all_entries
        .iter()
        .map(|entry| entry.bytes.len() as u64)
        .sum::<u64>();
    if total > MAX_TOTAL_BYTES {
        return Err(BundleError::InvalidFormat("bundle is too large".into()));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("bundle"),
        uuid::Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    file.write_all(MAGIC)?;
    write_u32(&mut file, all_entries.len() as u32)?;
    for entry in all_entries {
        write_entry(&mut file, &entry)?;
    }
    file.sync_all()?;
    drop(file);
    fs::rename(&temp, path)?;
    Ok(manifest_with_self)
}

pub fn read_bundle(path: &Path) -> Result<Bundle, BundleError> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 9];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(BundleError::InvalidFormat("magic header mismatch".into()));
    }
    let count = read_u32(&mut file)?;
    if count == 0 || count > MAX_ENTRIES {
        return Err(BundleError::InvalidFormat("entry count is invalid".into()));
    }
    let mut entries = BTreeMap::new();
    let mut total = 0u64;
    for _ in 0..count {
        let path = read_string(&mut file)?;
        validate_relative_path(&path)?;
        let size = read_u64(&mut file)?;
        if size > MAX_ENTRY_BYTES || total.saturating_add(size) > MAX_TOTAL_BYTES {
            return Err(BundleError::InvalidFormat(
                "bundle size limit exceeded".into(),
            ));
        }
        let mut expected = [0u8; 32];
        file.read_exact(&mut expected)?;
        let mut bytes = vec![
            0u8;
            usize::try_from(size).map_err(|_| BundleError::InvalidFormat(
                "entry size overflow".into()
            ))?
        ];
        file.read_exact(&mut bytes)?;
        let actual = Sha256::digest(&bytes);
        if actual.as_slice() != expected {
            return Err(BundleError::HashMismatch(path));
        }
        total += size;
        if entries.insert(path.clone(), bytes).is_some() {
            return Err(BundleError::InvalidFormat(format!(
                "duplicate entry {path}"
            )));
        }
    }
    let mut trailing = [0u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(BundleError::InvalidFormat(
            "trailing data after bundle entries".into(),
        ));
    }
    let manifest_bytes = entries
        .get("manifest.json")
        .ok_or_else(|| BundleError::InvalidFormat("manifest.json is missing".into()))?;
    let manifest: BundleManifest = serde_json::from_slice(manifest_bytes)?;
    if !matches!(manifest.format.as_str(), "1.0" | "1.1" | FORMAT_VERSION) {
        return Err(BundleError::InvalidFormat(
            "unsupported bundle version".into(),
        ));
    }
    let bundle = Bundle { manifest, entries };
    bundle.verify()?;
    Ok(bundle)
}

pub fn restore_workspace(bundle: &Bundle, root: &Path) -> Result<(), BundleError> {
    let mut entries = bundle.workspace_manifest_entries(root)?;
    entries.extend(bundle.workspace_file_entries()?);
    restore_workspace_files(root, &entries)
}

pub fn restore_workspace_files(
    root: &Path,
    entries: &[WorkspaceFileEntry],
) -> Result<(), BundleError> {
    let root = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    let root_dir = agentark_security::open_or_create_directory_nofollow(&root)?;
    let mut planned = BTreeSet::new();
    for entry in entries {
        validate_relative_path(&entry.relative_path)?;
        let relative_path =
            PathBuf::from(entry.workspace_id.to_string()).join(&entry.relative_path);
        if !planned.insert(relative_path.clone()) {
            return Err(BundleError::InvalidFormat(
                "duplicate workspace restore path".into(),
            ));
        }
        let parent = relative_path.parent().ok_or_else(|| {
            BundleError::InvalidFormat("workspace restore path is invalid".into())
        })?;
        let filename = relative_path.file_name().ok_or_else(|| {
            BundleError::InvalidFormat("workspace restore path is invalid".into())
        })?;
        let parent_dir = open_or_create_relative_directory(&root_dir, parent)?;
        match parent_dir.symlink_metadata(filename) {
            Ok(metadata) => {
                if is_link_or_reparse_point(&metadata) || !metadata.is_file() {
                    return Err(BundleError::UnsafePath(entry.relative_path.clone()));
                }
                let mut existing_file = parent_dir.open(filename)?;
                let mut existing = Vec::new();
                existing_file.read_to_end(&mut existing)?;
                if existing != entry.bytes {
                    return Err(BundleError::InvalidFormat(format!(
                        "workspace file conflict: {}",
                        entry.relative_path
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(BundleError::Io(error)),
        }
    }

    let mut created = Vec::<(cap_std::fs::Dir, PathBuf)>::new();
    for entry in entries {
        let relative_path =
            PathBuf::from(entry.workspace_id.to_string()).join(&entry.relative_path);
        let parent = relative_path.parent().ok_or_else(|| {
            BundleError::InvalidFormat("workspace restore path is invalid".into())
        })?;
        let filename = relative_path.file_name().ok_or_else(|| {
            BundleError::InvalidFormat("workspace restore path is invalid".into())
        })?;
        let parent_dir = open_or_create_relative_directory(&root_dir, parent)?;
        if parent_dir.symlink_metadata(filename).is_ok() {
            continue;
        }
        let committed_parent = parent_dir.try_clone()?;
        let temporary = PathBuf::from(format!(
            ".{}.{}.tmp",
            filename.to_str().ok_or_else(|| {
                BundleError::InvalidFormat("workspace restore path is invalid".into())
            })?,
            uuid::Uuid::new_v4()
        ));
        let write_result = (|| {
            let mut options = cap_std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            let mut temporary_file = parent_dir.open_with(&temporary, &options)?;
            temporary_file.write_all(&entry.bytes)?;
            temporary_file.sync_all()?;
            drop(temporary_file);
            if parent_dir.symlink_metadata(filename).is_ok() {
                return Err(BundleError::InvalidFormat(format!(
                    "workspace file conflict: {}",
                    entry.relative_path
                )));
            }
            parent_dir.rename(&temporary, &parent_dir, filename)?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = parent_dir.remove_file(&temporary);
            for (created_parent, created_name) in created.iter().rev() {
                let _ = created_parent.remove_file(created_name);
            }
        }
        write_result?;
        created.push((committed_parent, PathBuf::from(filename)));
    }
    Ok(())
}

fn open_or_create_relative_directory(
    root: &cap_std::fs::Dir,
    path: &Path,
) -> Result<cap_std::fs::Dir, BundleError> {
    let mut current = root.try_clone()?;
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(BundleError::UnsafePath(path.to_string_lossy().into_owned()));
        };
        let child = Path::new(value);
        match current.symlink_metadata(child) {
            Ok(metadata) if metadata.is_dir() && !is_link_or_reparse_point(&metadata) => {}
            Ok(_) => return Err(BundleError::UnsafePath(path.to_string_lossy().into_owned())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                current.create_dir(child)?;
            }
            Err(error) => return Err(BundleError::Io(error)),
        }
        current = agentark_security::open_child_directory_nofollow(&current, child)?;
    }
    Ok(current)
}

fn is_link_or_reparse_point(metadata: &cap_std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        metadata.file_attributes() & 0x0000_0400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn redact_value(value: Value, scanner: &SecretScanner) -> (Value, u64) {
    match value {
        Value::String(text) => {
            let sanitized = scanner.sanitize(&text);
            (
                Value::String(sanitized.text),
                sanitized.findings.len() as u64,
            )
        }
        Value::Array(values) => {
            let mut count = 0;
            let values = values
                .into_iter()
                .map(|value| {
                    let (value, found) = redact_value(value, scanner);
                    count += found;
                    value
                })
                .collect();
            (Value::Array(values), count)
        }
        Value::Object(values) => {
            let mut count = 0;
            let values = values
                .into_iter()
                .map(|(key, value)| {
                    let (value, found) = redact_value(value, scanner);
                    count += found;
                    (key, value)
                })
                .collect();
            (Value::Object(values), count)
        }
        other => (other, 0),
    }
}

fn safe_recovery_label(
    value: Option<&str>,
    scanner: &SecretScanner,
    kind: RecoveryLabelKind,
) -> Option<String> {
    let label = value?.trim();
    if label.is_empty() {
        return None;
    }
    if !scanner.sanitize(label).findings.is_empty() {
        return None;
    }
    match kind {
        RecoveryLabelKind::Provider => label
            .chars()
            .all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
            })
            .then(|| label.to_owned()),
        RecoveryLabelKind::Model => (!label.contains('/')
            && !label.contains('\\')
            && !label.contains(':')
            && !label.contains("://"))
        .then(|| label.to_owned()),
    }
}

fn redact_bytes(bytes: Vec<u8>, scanner: &SecretScanner) -> Option<(Vec<u8>, u64)> {
    let text = String::from_utf8(bytes).ok()?;
    let sanitized = scanner.sanitize(&text);
    Some((sanitized.text.into_bytes(), sanitized.findings.len() as u64))
}

fn is_credential_filename(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    name.starts_with(".env")
        || matches!(
            name.as_str(),
            "auth.json"
                | "auth.toml"
                | "credentials"
                | "credentials.json"
                | "mcp-auth.json"
                | "token.json"
                | "aws_credentials"
                | "application_default_credentials.json"
        )
        || name.starts_with("service-account")
        || name.starts_with("id_rsa")
        || name.starts_with("id_ed25519")
        || name.ends_with(".pem")
        || name.ends_with(".key")
        || name.ends_with(".p12")
}

fn validate_relative_path(value: &str) -> Result<(), BundleError> {
    if value.is_empty() || value.contains('\0') || value.contains('\\') {
        return Err(BundleError::UnsafePath(value.into()));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(BundleError::UnsafePath(value.into()));
    }
    Ok(())
}

fn write_u32(writer: &mut impl Write, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}
fn write_u64(writer: &mut impl Write, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}
fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}
fn read_u64(reader: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}
fn read_string(reader: &mut impl Read) -> Result<String, BundleError> {
    let len = read_u32(reader)?;
    if len > 4096 {
        return Err(BundleError::InvalidFormat("path is too long".into()));
    }
    let mut bytes = vec![0u8; len as usize];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| BundleError::InvalidFormat("path is not UTF-8".into()))
}
fn write_entry(writer: &mut impl Write, entry: &BundleEntry) -> Result<(), BundleError> {
    let path = entry.path.as_bytes();
    write_u32(writer, path.len() as u32)?;
    writer.write_all(path)?;
    write_u64(writer, entry.bytes.len() as u64)?;
    writer.write_all(Sha256::digest(&entry.bytes).as_slice())?;
    writer.write_all(&entry.bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentark_canonical::CanonicalSession;
    use agentark_security::SecretScanner;
    use tempfile::tempdir;

    #[test]
    fn round_trip_redacts_and_verifies() {
        let root = tempdir().unwrap();
        let path = root.path().join("backup.ahbundle");
        let session = CanonicalSession {
            schema_version: agentark_canonical::CanonicalSchemaVersion::V0_1_0,
            id: uuid::Uuid::new_v4(),
            install_id: uuid::Uuid::new_v4(),
            source_session_id: "s".into(),
            source_kind: "test".into(),
            workspace: None,
            title: Some("{\"token\":\"sk-abcdefghijklmnopqrstuvwxyz\"}".into()),
            archived: false,
            created_at_raw: None,
            updated_at_raw: None,
            model_provider: None,
            model_name: None,
            completeness: agentark_canonical::Completeness::Complete,
            messages: vec![],
            tool_events: vec![],
            attachments: vec![],
            raw_extra: BTreeMap::new(),
        };
        let scanner = SecretScanner::v1().unwrap();
        let manifest = write_sessions(&path, &[session], &scanner).unwrap();
        assert!(manifest.redacted);
        let bundle = read_bundle(&path).unwrap();
        assert_eq!(bundle.session_records().unwrap().len(), 1);
        let session_entry = bundle
            .entries
            .values()
            .find(|bytes| String::from_utf8_lossy(bytes).contains("[REDACTED:"));
        assert!(session_entry.is_some());
    }

    #[test]
    fn raw_provenance_summary_counts_messages_tools_and_attachments() {
        let mut session = CanonicalSession {
            schema_version: agentark_canonical::CanonicalSchemaVersion::V0_1_0,
            id: uuid::Uuid::new_v4(),
            install_id: uuid::Uuid::new_v4(),
            source_session_id: "raw-provenance".into(),
            source_kind: "fixture".into(),
            workspace: None,
            title: None,
            archived: false,
            created_at_raw: None,
            updated_at_raw: None,
            model_provider: None,
            model_name: None,
            completeness: agentark_canonical::Completeness::Complete,
            messages: vec![agentark_canonical::CanonicalMessage::text_fixture(
                1, "now", "message",
            )],
            tool_events: vec![agentark_canonical::ToolEvent {
                id: "tool".into(),
                ordinal: 2,
                tool_name: "fixture".into(),
                status: "ok".into(),
                visible_input: Some("input".into()),
                visible_output: Some("output".into()),
                raw_ref: agentark_canonical::Sha256Digest::from_bytes(b"raw"),
            }],
            attachments: vec![agentark_canonical::Attachment {
                id: uuid::Uuid::new_v4(),
                source_locator: "file.bin".into(),
                media_type: None,
                size: 3,
                sha256: agentark_canonical::Sha256Digest::from_bytes(b"bin"),
                raw_ref: agentark_canonical::Sha256Digest::from_bytes(b"raw"),
            }],
            raw_extra: BTreeMap::new(),
        };
        let raw = agentark_canonical::Sha256Digest::from_bytes(b"raw");
        session.messages[0].raw_ref = raw.clone();
        let summary = raw_provenance_summary(std::slice::from_ref(&session)).unwrap();
        assert_eq!(summary.sessions_with_references, 1);
        assert_eq!(summary.reference_count, 3);
    }

    #[test]
    fn raw_provenance_summary_rejects_malformed_digest() {
        let session = CanonicalSession {
            schema_version: agentark_canonical::CanonicalSchemaVersion::V0_1_0,
            id: uuid::Uuid::new_v4(),
            install_id: uuid::Uuid::new_v4(),
            source_session_id: "raw-provenance-invalid".into(),
            source_kind: "fixture".into(),
            workspace: None,
            title: None,
            archived: false,
            created_at_raw: None,
            updated_at_raw: None,
            model_provider: None,
            model_name: None,
            completeness: agentark_canonical::Completeness::Complete,
            messages: vec![agentark_canonical::CanonicalMessage::text_fixture(
                1, "now", "message",
            )],
            tool_events: Vec::new(),
            attachments: Vec::new(),
            raw_extra: BTreeMap::new(),
        };
        let mut value = serde_json::to_value(session).unwrap();
        value["messages"][0]["rawRef"] = Value::String("sha256:invalid".into());
        let session: CanonicalSession = serde_json::from_value(value).unwrap();
        let error = raw_provenance_summary(std::slice::from_ref(&session)).unwrap_err();
        assert!(
            matches!(error, BundleError::InvalidFormat(message) if message.contains("raw reference"))
        );

        let root = tempdir().unwrap();
        let path = root.path().join("malformed-raw-ref.ahbundle");
        let mut session_bytes =
            serde_json::to_vec(&serde_json::to_value(session).unwrap()).unwrap();
        session_bytes.push(b'\n');
        let manifest = serde_json::json!({
            "format": "1.2",
            "createdAt": "2026-09-13T00:00:00Z",
            "sessionCount": 1,
            "workspaceCount": 0,
            "fileCount": 0,
            "redacted": false,
            "redactionCount": 0,
            "entries": [{
                "path": "sessions/malformed.ndjson",
                "size": session_bytes.len(),
                "sha256": hex::encode(Sha256::digest(&session_bytes))
            }]
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let mut file = File::create(&path).unwrap();
        file.write_all(MAGIC).unwrap();
        write_u32(&mut file, 2).unwrap();
        write_entry(
            &mut file,
            &BundleEntry {
                path: "manifest.json".into(),
                bytes: manifest_bytes,
            },
        )
        .unwrap();
        write_entry(
            &mut file,
            &BundleEntry {
                path: "sessions/malformed.ndjson".into(),
                bytes: session_bytes,
            },
        )
        .unwrap();
        drop(file);
        let error = read_bundle(&path).unwrap_err();
        assert!(
            matches!(error, BundleError::InvalidFormat(message) if message.contains("raw reference"))
        );
    }

    #[test]
    fn legacy_raw_reference_values_remain_readable_and_are_counted() {
        let session = serde_json::json!({
            "schemaVersion": "0.1.0",
            "id": uuid::Uuid::new_v4(),
            "installId": uuid::Uuid::new_v4(),
            "sourceSessionId": "legacy-raw-ref",
            "sourceKind": "fixture",
            "workspace": null,
            "title": null,
            "archived": false,
            "createdAtRaw": null,
            "updatedAtRaw": null,
            "modelProvider": null,
            "modelName": null,
            "completeness": "complete",
            "messages": [{
                "id": uuid::Uuid::new_v4(),
                "sourceRecordId": null,
                "ordinal": 1,
                "role": "assistant",
                "rawRole": "assistant",
                "createdAtRaw": null,
                "content": [{"kind": "text", "text": "legacy", "attachmentId": null, "rawExtra": {}}],
                "rawRef": "legacy-ref"
            }],
            "toolEvents": [],
            "attachments": [],
            "rawExtra": {}
        });
        let session_bytes = format!("{}\n", session).into_bytes();
        let manifest = serde_json::json!({
            "format": "1.1",
            "createdAt": "2026-09-13T00:00:00Z",
            "sessionCount": 1,
            "redacted": false,
            "redactionCount": 0,
            "entries": [{
                "path": "sessions/legacy-raw.ndjson",
                "size": session_bytes.len(),
                "sha256": hex::encode(Sha256::digest(&session_bytes))
            }]
        });
        let root = tempdir().unwrap();
        let path = root.path().join("legacy-raw-ref.ahbundle");
        let mut file = File::create(&path).unwrap();
        file.write_all(MAGIC).unwrap();
        write_u32(&mut file, 2).unwrap();
        write_entry(
            &mut file,
            &BundleEntry {
                path: "manifest.json".into(),
                bytes: serde_json::to_vec(&manifest).unwrap(),
            },
        )
        .unwrap();
        write_entry(
            &mut file,
            &BundleEntry {
                path: "sessions/legacy-raw.ndjson".into(),
                bytes: session_bytes,
            },
        )
        .unwrap();
        drop(file);

        let bundle = read_bundle(&path).unwrap();
        let summary = bundle.raw_provenance_summary().unwrap();
        assert_eq!(summary.sessions_with_references, 1);
        assert_eq!(summary.reference_count, 1);
    }

    #[test]
    fn rejects_duplicate_entries() {
        let root = tempdir().unwrap();
        let error = write_entries(
            root.path().join("duplicate.ahbundle").as_path(),
            vec![
                BundleEntry {
                    path: "notes/session.txt".into(),
                    bytes: b"one".to_vec(),
                },
                BundleEntry {
                    path: "notes/session.txt".into(),
                    bytes: b"two".to_vec(),
                },
            ],
            0,
            0,
        )
        .unwrap_err();
        assert!(
            matches!(error, BundleError::InvalidFormat(message) if message.contains("duplicate entry"))
        );
    }

    #[test]
    fn rejects_a_caller_supplied_manifest_entry() {
        let root = tempdir().unwrap();
        let error = write_entries(
            root.path().join("manifest.ahbundle").as_path(),
            vec![BundleEntry {
                path: "manifest.json".into(),
                bytes: b"not-the-manifest".to_vec(),
            }],
            0,
            0,
        )
        .unwrap_err();
        assert!(
            matches!(error, BundleError::InvalidFormat(message) if message.contains("reserved"))
        );
    }

    #[test]
    fn deduplicates_repeated_workspace_selections() {
        let root = tempdir().unwrap();
        let workspace = agentark_canonical::Workspace {
            id: agentark_canonical::workspace_id("file:///fixture"),
            path_native: root.path().to_string_lossy().into_owned(),
            canonical_uri: "file:///fixture".into(),
            git_commit: None,
        };
        let session = CanonicalSession {
            schema_version: agentark_canonical::CanonicalSchemaVersion::V0_1_0,
            id: uuid::Uuid::new_v4(),
            install_id: uuid::Uuid::new_v4(),
            source_session_id: "workspace-session".into(),
            source_kind: "fixture".into(),
            workspace: Some(workspace.clone()),
            title: None,
            archived: false,
            created_at_raw: None,
            updated_at_raw: None,
            model_provider: None,
            model_name: None,
            completeness: agentark_canonical::Completeness::Complete,
            messages: Vec::new(),
            tool_events: Vec::new(),
            attachments: Vec::new(),
            raw_extra: BTreeMap::new(),
        };
        let path = root.path().join("repeated-workspace.ahbundle");
        let selection = ProjectSelection {
            workspace_id: workspace.id,
            root: root.path().to_path_buf(),
            include_files: false,
            max_file_bytes: 1024,
        };
        let manifest = write_selected_sessions(
            &path,
            "fixture",
            std::slice::from_ref(&session),
            &[selection.clone(), selection],
            &SecretScanner::v1().unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.workspace_count, 1);
        assert!(read_bundle(&path).is_ok());
    }

    #[test]
    fn rejects_multiple_native_entries_for_one_session() {
        let root = tempdir().unwrap();
        let session = CanonicalSession {
            schema_version: agentark_canonical::CanonicalSchemaVersion::V0_1_0,
            id: uuid::Uuid::new_v4(),
            install_id: uuid::Uuid::new_v4(),
            source_session_id: "native-duplicate".into(),
            source_kind: "codex".into(),
            workspace: None,
            title: None,
            archived: false,
            created_at_raw: None,
            updated_at_raw: None,
            model_provider: None,
            model_name: None,
            completeness: agentark_canonical::Completeness::Complete,
            messages: Vec::new(),
            tool_events: Vec::new(),
            attachments: Vec::new(),
            raw_extra: BTreeMap::new(),
        };
        let entries = [
            NativeBundleEntry {
                session_id: session.id,
                relative_path: "one.jsonl".into(),
                bytes: b"one".to_vec(),
                redaction_count: 0,
            },
            NativeBundleEntry {
                session_id: session.id,
                relative_path: "two.jsonl".into(),
                bytes: b"two".to_vec(),
                redaction_count: 0,
            },
        ];
        let error = write_selected_sessions_with_native(
            &root.path().join("duplicate-native.ahbundle"),
            "codex",
            std::slice::from_ref(&session),
            &[],
            &entries,
            &SecretScanner::v1().unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(error, BundleError::InvalidFormat(message) if message.contains("exactly one session"))
        );
    }

    #[test]
    fn rejects_non_utf8_session_entry() {
        let root = tempdir().unwrap();
        let path = root.path().join("non-utf8.ahbundle");
        write_entries(
            &path,
            vec![BundleEntry {
                path: "sessions/non-utf8.ndjson".into(),
                bytes: vec![0xff, b'\n'],
            }],
            1,
            0,
        )
        .unwrap();
        let error = read_bundle(&path).unwrap_err();
        assert!(matches!(error, BundleError::InvalidFormat(message) if message.contains("UTF-8")));
    }

    #[test]
    fn rejects_trailing_bundle_data() {
        let root = tempdir().unwrap();
        let path = root.path().join("trailing.ahbundle");
        write_entries(
            &path,
            vec![BundleEntry {
                path: "notes/session.txt".into(),
                bytes: b"portable history".to_vec(),
            }],
            0,
            0,
        )
        .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(b"trailing-data");
        fs::write(&path, bytes).unwrap();
        let error = read_bundle(&path).unwrap_err();
        assert!(
            matches!(error, BundleError::InvalidFormat(message) if message.contains("trailing"))
        );
    }

    #[test]
    fn rejects_an_entry_not_listed_in_the_manifest() {
        let root = tempdir().unwrap();
        let path = root.path().join("unlisted.ahbundle");
        write_entries(
            &path,
            vec![BundleEntry {
                path: "notes/session.txt".into(),
                bytes: b"portable history".to_vec(),
            }],
            0,
            0,
        )
        .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let count = u32::from_le_bytes(bytes[9..13].try_into().unwrap());
        bytes[9..13].copy_from_slice(&(count + 1).to_le_bytes());
        let mut extra = Vec::new();
        write_entry(
            &mut extra,
            &BundleEntry {
                path: "notes/unlisted.txt".into(),
                bytes: b"unlisted".to_vec(),
            },
        )
        .unwrap();
        bytes.extend_from_slice(&extra);
        fs::write(&path, bytes).unwrap();
        let error = read_bundle(&path).unwrap_err();
        assert!(
            matches!(error, BundleError::InvalidFormat(message) if message.contains("not listed"))
        );
    }

    #[test]
    fn fail_closed_file_policy_skips_binary_and_credential_variants() {
        let scanner = SecretScanner::v1().unwrap();
        assert!(is_credential_filename(".env.production"));
        assert!(is_credential_filename("service-account.json"));
        assert!(is_credential_filename("id_ed25519"));
        assert!(redact_bytes(vec![0xff, b'a'], &scanner).is_none());
        let sanitized =
            redact_bytes(b"AWS_SECRET_ACCESS_KEY=super-secret".to_vec(), &scanner).unwrap();
        assert!(
            !String::from_utf8(sanitized.0)
                .unwrap()
                .contains("super-secret")
        );
    }

    #[test]
    fn rejects_an_orphan_native_payload_in_a_strict_bundle() {
        let root = tempdir().unwrap();
        let path = root.path().join("orphan-native.ahbundle");
        let session = CanonicalSession {
            schema_version: agentark_canonical::CanonicalSchemaVersion::V0_1_0,
            id: uuid::Uuid::new_v4(),
            install_id: uuid::Uuid::new_v4(),
            source_session_id: "native-orphan".into(),
            source_kind: "fixture".into(),
            workspace: None,
            title: None,
            archived: false,
            created_at_raw: None,
            updated_at_raw: None,
            model_provider: None,
            model_name: None,
            completeness: agentark_canonical::Completeness::Complete,
            messages: Vec::new(),
            tool_events: Vec::new(),
            attachments: Vec::new(),
            raw_extra: BTreeMap::new(),
        };
        let orphan = NativeBundleEntry {
            session_id: uuid::Uuid::new_v4(),
            relative_path: "rollout.jsonl".into(),
            bytes: b"{}
"
            .to_vec(),
            redaction_count: 0,
        };
        let error = write_selected_sessions_with_native(
            &path,
            "fixture",
            std::slice::from_ref(&session),
            &[],
            &[orphan],
            &SecretScanner::v1().unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(error, BundleError::InvalidFormat(message) if message.contains("exactly one"))
        );
    }

    #[test]
    fn restores_workspace_manifest_and_files_under_the_destination_root() {
        let source = tempdir().unwrap();
        let destination = tempdir().unwrap();
        let workspace_id = uuid::Uuid::new_v4();
        fs::write(source.path().join("README.md"), b"portable").unwrap();
        let session = CanonicalSession {
            schema_version: agentark_canonical::CanonicalSchemaVersion::V0_1_0,
            id: uuid::Uuid::new_v4(),
            install_id: uuid::Uuid::new_v4(),
            source_session_id: "workspace-restore".into(),
            source_kind: "fixture".into(),
            workspace: Some(agentark_canonical::Workspace {
                id: workspace_id,
                path_native: source.path().to_string_lossy().into_owned(),
                canonical_uri: "file:///source".into(),
                git_commit: None,
            }),
            title: None,
            archived: false,
            created_at_raw: None,
            updated_at_raw: None,
            model_provider: None,
            model_name: None,
            completeness: agentark_canonical::Completeness::Complete,
            messages: Vec::new(),
            tool_events: Vec::new(),
            attachments: Vec::new(),
            raw_extra: BTreeMap::new(),
        };
        let bundle_path = source.path().join("workspace.ahbundle");
        write_selected_sessions(
            &bundle_path,
            "fixture",
            std::slice::from_ref(&session),
            &[ProjectSelection {
                workspace_id,
                root: source.path().to_path_buf(),
                include_files: true,
                max_file_bytes: 1024,
            }],
            &SecretScanner::v1().unwrap(),
        )
        .unwrap();
        let bundle = read_bundle(&bundle_path).unwrap();
        restore_workspace(&bundle, destination.path()).unwrap();
        assert_eq!(
            fs::read(
                destination
                    .path()
                    .join(workspace_id.to_string())
                    .join("README.md")
            )
            .unwrap(),
            b"portable"
        );
        restore_workspace(&bundle, destination.path()).unwrap();
    }

    #[test]
    fn workspace_metadata_does_not_collide_with_a_project_manifest_file() {
        let source = tempdir().unwrap();
        let destination = tempdir().unwrap();
        let workspace_id = uuid::Uuid::new_v4();
        fs::write(source.path().join("manifest.json"), b"project manifest").unwrap();
        let session = CanonicalSession {
            schema_version: agentark_canonical::CanonicalSchemaVersion::V0_1_0,
            id: uuid::Uuid::new_v4(),
            install_id: uuid::Uuid::new_v4(),
            source_session_id: "manifest-collision".into(),
            source_kind: "fixture".into(),
            workspace: Some(agentark_canonical::Workspace {
                id: workspace_id,
                path_native: source.path().to_string_lossy().into_owned(),
                canonical_uri: "file:///source".into(),
                git_commit: None,
            }),
            title: None,
            archived: false,
            created_at_raw: None,
            updated_at_raw: None,
            model_provider: None,
            model_name: None,
            completeness: agentark_canonical::Completeness::Complete,
            messages: Vec::new(),
            tool_events: Vec::new(),
            attachments: Vec::new(),
            raw_extra: BTreeMap::new(),
        };
        let bundle_path = source.path().join("collision.ahbundle");
        write_selected_sessions(
            &bundle_path,
            "fixture",
            std::slice::from_ref(&session),
            &[ProjectSelection {
                workspace_id,
                root: source.path().to_path_buf(),
                include_files: true,
                max_file_bytes: 1024,
            }],
            &SecretScanner::v1().unwrap(),
        )
        .unwrap();
        let bundle = read_bundle(&bundle_path).unwrap();
        restore_workspace(&bundle, destination.path()).unwrap();
        let workspace_root = destination.path().join(workspace_id.to_string());
        assert_eq!(
            fs::read(workspace_root.join("manifest.json")).unwrap(),
            b"project manifest"
        );
        assert!(workspace_root.join(".agentark/manifest.json").is_file());
    }

    #[test]
    fn legacy_bundle_without_new_semantic_sections_remains_readable() {
        let root = tempdir().unwrap();
        let path = root.path().join("legacy.ahbundle");
        let session = serde_json::json!({
            "schemaVersion": "0.1.0",
            "id": uuid::Uuid::new_v4(),
            "installId": uuid::Uuid::new_v4(),
            "sourceSessionId": "legacy",
            "sourceKind": "fixture",
            "workspace": null,
            "title": "legacy",
            "archived": false,
            "createdAtRaw": null,
            "updatedAtRaw": null,
            "modelProvider": null,
            "modelName": null,
            "completeness": "complete",
            "messages": [],
            "toolEvents": [],
            "attachments": [],
            "rawExtra": {}
        });
        let session_bytes = format!("{}\n", session).into_bytes();
        let manifest = serde_json::json!({
            "format": "1.1",
            "createdAt": "2026-08-23T00:00:00Z",
            "sessionCount": 1,
            "redacted": false,
            "redactionCount": 0,
            "entries": [{"path": "sessions/legacy.ndjson", "size": session_bytes.len(), "sha256": hex::encode(Sha256::digest(&session_bytes))}]
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let mut file = File::create(&path).unwrap();
        file.write_all(MAGIC).unwrap();
        write_u32(&mut file, 2).unwrap();
        write_entry(
            &mut file,
            &BundleEntry {
                path: "manifest.json".into(),
                bytes: manifest_bytes,
            },
        )
        .unwrap();
        write_entry(
            &mut file,
            &BundleEntry {
                path: "sessions/legacy.ndjson".into(),
                bytes: session_bytes,
            },
        )
        .unwrap();
        drop(file);
        assert!(read_bundle(&path).is_ok());
    }

    #[test]
    fn rejects_traversal_entry() {
        let root = tempdir().unwrap();
        let error = write_entries(
            root.path().join("x.ahbundle").as_path(),
            vec![BundleEntry {
                path: "../evil".into(),
                bytes: b"x".to_vec(),
            }],
            0,
            0,
        )
        .unwrap_err();
        assert!(matches!(error, BundleError::UnsafePath(_)));
    }
}
