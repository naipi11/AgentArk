#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use agentark_canonical::Sha256Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit I/O failed")]
    Io(#[from] std::io::Error),
    #[error("audit serialization failed")]
    Json(#[from] serde_json::Error),
    #[error("audit chain is invalid: {0}")]
    InvalidChain(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub event_id: Uuid,
    pub event_type: String,
    pub timestamp: String,
    pub actor: String,
    pub source: Option<String>,
    pub target: Option<String>,
    pub before_hash: Option<Sha256Digest>,
    pub after_hash: Option<Sha256Digest>,
    pub plan_hash: Option<Sha256Digest>,
    pub result: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_labels: Vec<String>,
    pub previous_hash: Option<Sha256Digest>,
    pub event_hash: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditVerification {
    pub valid: bool,
    pub event_count: u64,
    pub last_hash: Option<Sha256Digest>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    pub id: Uuid,
    pub created_at: String,
    pub root: String,
    pub files: Vec<CheckpointFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointFile {
    pub relative_path: String,
    pub size: u64,
    pub sha256: Sha256Digest,
}

pub fn append_event(path: &Path, mut event: AuditEvent) -> Result<AuditEvent, AuditError> {
    let previous = last_event(path)?;
    event.previous_hash = previous.as_ref().map(|value| value.event_hash.clone());
    event.event_hash = hash_event(&event)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, &event)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(event)
}

pub fn verify_chain(path: &Path) -> Result<AuditVerification, AuditError> {
    if !path.is_file() {
        return Ok(AuditVerification {
            valid: true,
            event_count: 0,
            last_hash: None,
            error: None,
        });
    }
    let file = fs::File::open(path)?;
    let mut previous: Option<Sha256Digest> = None;
    let mut count = 0;
    for (line_number, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let event: AuditEvent = serde_json::from_str(&line)?;
        if event.previous_hash != previous {
            return Ok(AuditVerification {
                valid: false,
                event_count: count,
                last_hash: previous,
                error: Some(format!(
                    "previous hash mismatch at line {}",
                    line_number + 1
                )),
            });
        }
        let expected = hash_event(&event)?;
        if expected != event.event_hash {
            return Ok(AuditVerification {
                valid: false,
                event_count: count,
                last_hash: previous,
                error: Some(format!("event hash mismatch at line {}", line_number + 1)),
            });
        }
        previous = Some(event.event_hash);
        count += 1;
    }
    Ok(AuditVerification {
        valid: true,
        event_count: count,
        last_hash: previous,
        error: None,
    })
}

pub fn create_checkpoint(root: &Path, paths: &[PathBuf]) -> Result<Checkpoint, AuditError> {
    let mut files = Vec::new();
    for path in paths {
        let bytes = fs::read(path)?;
        let relative_path = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        files.push(CheckpointFile {
            relative_path,
            size: bytes.len() as u64,
            sha256: Sha256Digest::from_bytes(&bytes),
        });
    }
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(Checkpoint {
        id: Uuid::new_v4(),
        created_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default(),
        root: root.to_string_lossy().into_owned(),
        files,
    })
}

pub fn verify_checkpoint(checkpoint: &Checkpoint) -> Result<bool, AuditError> {
    let root = Path::new(&checkpoint.root);
    for file in &checkpoint.files {
        let path = root.join(&file.relative_path);
        let bytes = fs::read(path)?;
        if bytes.len() as u64 != file.size || Sha256Digest::from_bytes(&bytes) != file.sha256 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn last_event(path: &Path) -> Result<Option<AuditEvent>, AuditError> {
    if !path.is_file() {
        return Ok(None);
    }
    let file = fs::File::open(path)?;
    let mut last = None;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if !line.trim().is_empty() {
            last = Some(serde_json::from_str(&line)?);
        }
    }
    Ok(last)
}

fn hash_event(event: &AuditEvent) -> Result<Sha256Digest, AuditError> {
    let mut value = serde_json::to_value(event)?;
    if let Some(object) = value.as_object_mut() {
        object.insert("eventHash".into(), serde_json::Value::Null);
    }
    Ok(Sha256Digest::from_bytes(&Sha256::digest(
        serde_jcs::to_vec(&value)?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn event(kind: &str) -> AuditEvent {
        AuditEvent {
            event_id: Uuid::new_v4(),
            event_type: kind.into(),
            timestamp: "now".into(),
            actor: "test".into(),
            source: None,
            target: None,
            before_hash: None,
            after_hash: None,
            plan_hash: None,
            result: "success".into(),
            provider_labels: Vec::new(),
            previous_hash: None,
            event_hash: Sha256Digest::from_bytes(b"pending"),
        }
    }

    #[test]
    fn hash_chain_detects_tampering() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        append_event(&path, event("plan.accepted")).unwrap();
        append_event(&path, event("migration.completed")).unwrap();
        assert!(verify_chain(&path).unwrap().valid);
        let mut text = fs::read_to_string(&path).unwrap();
        text = text.replacen("migration.completed", "migration.tampered", 1);
        fs::write(&path, text).unwrap();
        assert!(!verify_chain(&path).unwrap().valid);
    }

    #[test]
    fn checkpoint_detects_changed_file() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("index.db");
        fs::write(&file, b"one").unwrap();
        let checkpoint = create_checkpoint(dir.path(), std::slice::from_ref(&file)).unwrap();
        assert!(verify_checkpoint(&checkpoint).unwrap());
        fs::write(&file, b"two").unwrap();
        assert!(!verify_checkpoint(&checkpoint).unwrap());
    }
}
