#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use agentark_security::AuthorizedRoot;
use sha2::{Digest, Sha256};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Error)]
pub enum WatchError {
    #[error("watch root is not authorized")]
    Unauthorized(#[from] agentark_security::SecurityError),
    #[error("watch root I/O failed")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchRoot {
    pub agent_id: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileFingerprint {
    pub path: PathBuf,
    pub size: u64,
    pub modified_ns: u128,
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileEvent {
    pub agent_id: String,
    pub path: PathBuf,
    pub changed_at_ns: u128,
}

#[derive(Clone, Debug)]
pub struct ReconciliationQueue {
    debounce: Duration,
    pending: HashMap<(String, PathBuf), (u128, ReconcileEvent)>,
    ready: VecDeque<ReconcileEvent>,
}

impl ReconciliationQueue {
    pub fn new(debounce: Duration) -> Self {
        Self {
            debounce,
            pending: HashMap::new(),
            ready: VecDeque::new(),
        }
    }

    pub fn push(&mut self, event: ReconcileEvent) {
        let key = (event.agent_id.clone(), event.path.clone());
        self.pending.insert(key, (event.changed_at_ns, event));
    }

    pub fn flush(&mut self, now_ns: u128) {
        let debounce_ns = self.debounce.as_nanos();
        let keys = self
            .pending
            .iter()
            .filter_map(|(key, (changed, _))| {
                (now_ns.saturating_sub(*changed) >= debounce_ns).then_some(key.clone())
            })
            .collect::<Vec<_>>();
        for key in keys {
            if let Some((_, event)) = self.pending.remove(&key) {
                self.ready.push_back(event);
            }
        }
    }

    pub fn pop_ready(&mut self) -> Option<ReconcileEvent> {
        self.ready.pop_front()
    }
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
    pub fn ready_len(&self) -> usize {
        self.ready.len()
    }
}

pub fn fingerprint_root(root: &WatchRoot) -> Result<Vec<FileFingerprint>, WatchError> {
    let _authorized = AuthorizedRoot::new(root.path.clone())?;
    let mut files = WalkDir::new(&root.path)
        .follow_links(false)
        .max_depth(8)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .collect::<Vec<_>>();
    files.sort();
    files.into_iter().map(fingerprint_file).collect()
}

pub fn fingerprint_file(path: PathBuf) -> Result<FileFingerprint, WatchError> {
    let metadata = fs::metadata(&path)?;
    let bytes = fs::read(&path)?;
    let modified_ns = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    Ok(FileFingerprint {
        path,
        size: metadata.len(),
        modified_ns,
        digest: hex::encode(Sha256::digest(&bytes)),
    })
}

pub fn diff_fingerprints(
    previous: &[FileFingerprint],
    current: &[FileFingerprint],
) -> Vec<PathBuf> {
    let old = previous
        .iter()
        .map(|item| (&item.path, (&item.size, &item.modified_ns, &item.digest)))
        .collect::<HashMap<_, _>>();
    current
        .iter()
        .filter_map(|item| {
            (old.get(&item.path) != Some(&(&item.size, &item.modified_ns, &item.digest)))
                .then_some(item.path.clone())
        })
        .chain(
            previous
                .iter()
                .filter(|item| !current.iter().any(|candidate| candidate.path == item.path))
                .map(|item| item.path.clone()),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use tempfile::tempdir;

    #[test]
    fn debounce_deduplicates_bursty_events() {
        let mut queue = ReconciliationQueue::new(Duration::from_millis(10));
        queue.push(ReconcileEvent {
            agent_id: "codex".into(),
            path: PathBuf::from("a"),
            changed_at_ns: 100_000_000,
        });
        queue.push(ReconcileEvent {
            agent_id: "codex".into(),
            path: PathBuf::from("a"),
            changed_at_ns: 105_000_000,
        });
        queue.flush(110_000_000);
        assert_eq!(queue.ready_len(), 0);
        queue.flush(120_000_000);
        assert_eq!(queue.ready_len(), 1);
    }

    #[test]
    fn root_fingerprint_detects_content_changes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("session.jsonl");
        fs::write(&path, "one").unwrap();
        let root = WatchRoot {
            agent_id: "test".into(),
            path: dir.path().into(),
        };
        let before = fingerprint_root(&root).unwrap();
        sleep(Duration::from_millis(2));
        fs::write(&path, "two").unwrap();
        let after = fingerprint_root(&root).unwrap();
        assert_eq!(diff_fingerprints(&before, &after), vec![path]);
    }
}
