use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use agentark_adapter_sdk::{CapturedRecord, CapturedSource};
use agentark_canonical::Sha256Digest;
use agentark_security::AuthorizedRoot;
use sha2::{Digest, Sha256};

use crate::CodexError;

pub fn split_complete_jsonl_prefix(bytes: &[u8]) -> Result<Vec<u8>, CodexError> {
    if bytes.is_empty() {
        return Err(CodexError::Retryable("incomplete-final-record"));
    }
    if !bytes.ends_with(b"\n") {
        return Err(CodexError::Retryable("incomplete-final-record"));
    }
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        serde_json::from_slice::<serde_json::Value>(line)
            .map_err(|_| CodexError::Retryable("incomplete-final-record"))?;
    }
    Ok(bytes.to_vec())
}

pub fn capture_jsonl_file(root: &Path, relative: &Path) -> Result<CapturedRecord, CodexError> {
    let authorized =
        AuthorizedRoot::new(root.to_path_buf()).map_err(|_| CodexError::InvalidOutput)?;
    let mut file = authorized
        .open_regular_file(relative)
        .map_err(|_| CodexError::InvalidOutput)?;
    let before = file.metadata()?;
    let length = before.len();
    let modified = before.modified().ok();
    let mut bytes = Vec::with_capacity(length as usize);
    file.by_ref()
        .take(length.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if after.len() != length || modified != after.modified().ok() || bytes.len() != length as usize
    {
        return Err(CodexError::SourceChanged);
    }
    let bytes = split_complete_jsonl_prefix(&bytes)?;
    let locator = relative.to_string_lossy().replace('\\', "/");
    let source_session_id = relative
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    Ok(CapturedRecord {
        source: CapturedSource::FilesystemRawOnly,
        source_locator: locator.clone(),
        source_session_id,
        source_record_id: Some(locator),
        ordinal: 0,
        snapshot_id: Sha256Digest::from_bytes(&bytes).as_str().to_owned(),
        bytes,
    })
}

pub fn collect_jsonl_paths(root: &Path) -> Result<Vec<PathBuf>, CodexError> {
    let mut paths = Vec::new();
    for directory in ["sessions", "archived_sessions"] {
        let path = root.join(directory);
        if path.exists() {
            collect_jsonl_paths_inner(root, &path, &mut paths)?;
        }
    }
    paths.sort();
    Ok(paths)
}

pub fn tree_digest(root: &Path) -> Result<String, CodexError> {
    let mut entries = Vec::new();
    collect_tree(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    for (path, bytes) in entries {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn collect_jsonl_paths_inner(
    root: &Path,
    current: &Path,
    paths: &mut Vec<PathBuf>,
) -> Result<(), CodexError> {
    let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(CodexError::InvalidOutput);
        }
        if metadata.is_dir() {
            collect_jsonl_paths_inner(root, &path, paths)?;
        } else if metadata.is_file()
            && path.extension().and_then(|value| value.to_str()) == Some("jsonl")
        {
            paths.push(
                path.strip_prefix(root)
                    .map_err(|_| CodexError::InvalidOutput)?
                    .to_path_buf(),
            );
        }
    }
    Ok(())
}

fn collect_tree(
    root: &Path,
    current: &Path,
    entries: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), CodexError> {
    let mut children = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for entry in children {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(CodexError::InvalidOutput);
        }
        if metadata.is_dir() {
            collect_tree(root, &path, entries)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| CodexError::InvalidOutput)?
                .to_string_lossy()
                .replace('\\', "/");
            entries.push((relative, fs::read(&path)?));
        }
    }
    Ok(())
}
