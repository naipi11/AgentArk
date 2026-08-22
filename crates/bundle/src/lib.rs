#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path};

use agentark_canonical::CanonicalSession;
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

struct BundleWriteMeta {
    agent: Option<String>,
    source_root: Option<String>,
    workspace_count: u64,
    file_count: u64,
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
            for line in String::from_utf8_lossy(bytes).lines() {
                if line.trim().is_empty() {
                    continue;
                }
                sessions.push(serde_json::from_str(line)?);
            }
        }
        Ok(sessions)
    }

    pub fn verify(&self) -> Result<(), BundleError> {
        for meta in &self.manifest.entries {
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
        Ok(())
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
    let mut workspace_count = 0u64;
    for selection in selections {
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
                    return Err(BundleError::InvalidFormat(format!(
                        "project file {} exceeds the selected size limit",
                        relative_text
                    )));
                }
                let mut bytes = Vec::with_capacity(metadata.len() as usize);
                source.read_to_end(&mut bytes)?;
                let (bytes, count) = redact_bytes(bytes, scanner);
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
    for native in native_entries {
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
                source_provider: safe_recovery_label(session.model_provider.as_deref(), scanner),
                source_model: safe_recovery_label(session.model_name.as_deref(), scanner),
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
        },
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
        if entry.bytes.len() as u64 > MAX_ENTRY_BYTES {
            return Err(BundleError::InvalidFormat(format!(
                "entry {} is too large",
                entry.path
            )));
        }
    }
    if entries.len() as u32 >= MAX_ENTRIES {
        return Err(BundleError::InvalidFormat("too many bundle entries".into()));
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
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

fn safe_recovery_label(value: Option<&str>, scanner: &SecretScanner) -> Option<String> {
    let label = value?.trim();
    if label.contains("://") || !scanner.sanitize(label).findings.is_empty() {
        None
    } else {
        Some(label.to_owned())
    }
}

fn redact_bytes(bytes: Vec<u8>, scanner: &SecretScanner) -> (Vec<u8>, u64) {
    match String::from_utf8(bytes) {
        Ok(text) => {
            let sanitized = scanner.sanitize(&text);
            (sanitized.text.into_bytes(), sanitized.findings.len() as u64)
        }
        Err(error) => (error.into_bytes(), 0),
    }
}

fn is_credential_filename(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    matches!(
        name.as_str(),
        ".env"
            | ".env.local"
            | "auth.json"
            | "auth.toml"
            | "credentials.json"
            | "mcp-auth.json"
            | "token.json"
    ) || name.ends_with(".pem")
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
