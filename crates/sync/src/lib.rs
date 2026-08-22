#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use agentark_canonical::Sha256Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncOperation {
    pub op_id: Uuid,
    pub device_id: Uuid,
    pub hlc: String,
    pub entity_type: String,
    pub entity_id: String,
    pub operation: String,
    pub content_hash: Sha256Digest,
    pub base_hash: Option<Sha256Digest>,
    pub tombstone: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncConflict {
    pub entity_type: String,
    pub entity_id: String,
    pub local: SyncOperation,
    pub remote: SyncOperation,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeResult {
    pub operations: Vec<SyncOperation>,
    pub conflicts: Vec<SyncConflict>,
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("sync log I/O failed")]
    Io(#[from] std::io::Error),
    #[error("sync log serialization failed")]
    Json(#[from] serde_json::Error),
    #[error("sync operation is invalid: {0}")]
    Invalid(String),
}

pub fn append_operation(path: &Path, operation: &SyncOperation) -> Result<(), SyncError> {
    if operation.op_id.is_nil() || operation.device_id.is_nil() {
        return Err(SyncError::Invalid("nil sync identity".into()));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, operation)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub fn read_operations(path: &Path) -> Result<Vec<SyncOperation>, SyncError> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(path)?;
    let mut operations = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        operations.push(serde_json::from_str(&line)?);
    }
    Ok(operations)
}

pub fn merge(local: &[SyncOperation], remote: &[SyncOperation]) -> MergeResult {
    let mut by_key = BTreeMap::<(String, String), SyncOperation>::new();
    let mut conflicts = Vec::new();
    for operation in local.iter().chain(remote.iter()) {
        let key = (operation.entity_type.clone(), operation.entity_id.clone());
        match by_key.get(&key) {
            None => {
                by_key.insert(key, operation.clone());
            }
            Some(existing)
                if existing.content_hash == operation.content_hash
                    && existing.tombstone == operation.tombstone => {}
            Some(existing)
                if operation.entity_type == "message" || operation.entity_type == "tool_event" =>
            {
                conflicts.push(SyncConflict {
                    entity_type: operation.entity_type.clone(),
                    entity_id: operation.entity_id.clone(),
                    local: existing.clone(),
                    remote: operation.clone(),
                    reason: "immutable content differs; union cannot choose silently".into(),
                });
            }
            Some(existing) => {
                let winner = if operation.hlc > existing.hlc {
                    operation.clone()
                } else {
                    existing.clone()
                };
                by_key.insert(key, winner);
            }
        }
    }
    let mut operations = by_key.into_values().collect::<Vec<_>>();
    for conflict in &conflicts {
        if !operations
            .iter()
            .any(|operation| operation.op_id == conflict.remote.op_id)
        {
            operations.push(conflict.remote.clone());
        }
    }
    MergeResult {
        operations,
        conflicts,
    }
}

pub fn new_operation(
    device_id: Uuid,
    entity_type: &str,
    entity_id: &str,
    operation: &str,
    content: &[u8],
    base_hash: Option<Sha256Digest>,
    tombstone: bool,
) -> SyncOperation {
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    SyncOperation {
        op_id: Uuid::new_v4(),
        device_id,
        hlc: timestamp,
        entity_type: entity_type.into(),
        entity_id: entity_id.into(),
        operation: operation.into(),
        content_hash: Sha256Digest::from_bytes(content),
        base_hash,
        tombstone,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn message_conflict_is_never_lww_overwritten() {
        let device_a = Uuid::new_v4();
        let device_b = Uuid::new_v4();
        let local = new_operation(device_a, "message", "m1", "upsert", b"one", None, false);
        let remote = new_operation(device_b, "message", "m1", "upsert", b"two", None, false);
        let merged = merge(&[local], &[remote]);
        assert_eq!(merged.conflicts.len(), 1);
        assert_eq!(merged.operations.len(), 2);
    }

    #[test]
    fn metadata_uses_hlc_winner_and_log_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ops.jsonl");
        let operation = new_operation(
            Uuid::new_v4(),
            "title",
            "s1",
            "upsert",
            b"title",
            None,
            false,
        );
        append_operation(&path, &operation).unwrap();
        assert_eq!(read_operations(&path).unwrap(), vec![operation.clone()]);
        let older = operation.clone();
        let mut newer = operation.clone();
        newer.hlc = "9999-01-01T00:00:00Z".into();
        newer.content_hash = Sha256Digest::from_bytes(b"new");
        let merged = merge(&[older], &[newer.clone()]);
        assert_eq!(merged.operations, vec![newer]);
    }
}
