use std::sync::Arc;

use agentark_canonical::{CanonicalSession, Sha256Digest, canonical_hash};
use agentark_cas::{ArtifactStore, ObjectType, StoredObject};
use agentark_index::{IndexDb, IndexError, VerificationSnapshot};
use agentark_security::SecretScanner;
use serde::Serialize;
use uuid::Uuid;

use crate::AppError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationFailure {
    pub code: String,
    pub object_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub scan_id: Uuid,
    pub passed: bool,
    pub failures: Vec<VerificationFailure>,
}

#[derive(Clone, Default)]
pub struct VerificationJournal {
    objects:
        Arc<std::sync::Mutex<std::collections::BTreeMap<Uuid, Vec<VerificationEvidenceRecord>>>>,
}

#[derive(Clone)]
pub struct VerificationEvidenceRecord {
    pub object: StoredObject,
    pub session: Option<CanonicalSession>,
    pub canonical_hash: Option<Sha256Digest>,
    pub sanitized_title: Option<String>,
    pub sanitized_body: Option<String>,
}

pub trait VerificationEvidence {
    fn snapshot(&self, scan_id: Uuid) -> Result<VerificationEvidenceSnapshot, AppError>;
}

#[derive(Clone, Default)]
pub struct VerificationEvidenceSnapshot {
    pub status: Option<String>,
    pub indexed_count: u64,
    pub quarantined_count: u64,
    pub retryable_count: u64,
    pub rejected_count: u64,
    pub records: Vec<VerificationEvidenceRecord>,
    pub sessions: Vec<IndexedSessionEvidence>,
}

#[derive(Clone)]
pub struct IndexedSessionEvidence {
    pub id: Uuid,
    pub canonical_json: String,
    pub canonical_hash: Sha256Digest,
    pub search_title: String,
    pub search_body: String,
    pub fts_title: Option<String>,
    pub fts_body: Option<String>,
    pub message_ordinals: Vec<u64>,
    pub tool_event_ordinals: Vec<u64>,
}

impl VerificationJournal {
    pub fn record(&self, scan_id: Uuid, object: StoredObject) {
        if let Ok(mut guard) = self.objects.lock() {
            guard
                .entry(scan_id)
                .or_default()
                .push(VerificationEvidenceRecord {
                    object,
                    session: None,
                    canonical_hash: None,
                    sanitized_title: None,
                    sanitized_body: None,
                });
        }
    }

    pub fn record_session(
        &self,
        scan_id: Uuid,
        object_id: &str,
        session: CanonicalSession,
        canonical_hash: Sha256Digest,
        sanitized_title: String,
        sanitized_body: String,
    ) {
        if let Ok(mut guard) = self.objects.lock()
            && let Some(entry) = guard
                .entry(scan_id)
                .or_default()
                .iter_mut()
                .rev()
                .find(|entry| entry.object.object_id == object_id)
        {
            entry.session = Some(session);
            entry.canonical_hash = Some(canonical_hash);
            entry.sanitized_title = Some(sanitized_title);
            entry.sanitized_body = Some(sanitized_body);
        }
    }

    fn objects(&self, scan_id: Uuid) -> Vec<VerificationEvidenceRecord> {
        self.objects
            .lock()
            .ok()
            .and_then(|guard| guard.get(&scan_id).cloned())
            .unwrap_or_default()
    }
}

impl VerificationEvidence for VerificationJournal {
    fn snapshot(&self, scan_id: Uuid) -> Result<VerificationEvidenceSnapshot, AppError> {
        let records = self.objects(scan_id);
        Ok(VerificationEvidenceSnapshot {
            status: if records.is_empty() {
                Some("missing".into())
            } else {
                None
            },
            indexed_count: records
                .iter()
                .filter(|record| record.session.is_some())
                .count() as u64,
            records,
            ..VerificationEvidenceSnapshot::default()
        })
    }
}

impl<T: VerificationEvidence + ?Sized> VerificationEvidence for &T {
    fn snapshot(&self, scan_id: Uuid) -> Result<VerificationEvidenceSnapshot, AppError> {
        (*self).snapshot(scan_id)
    }
}

impl VerificationEvidence for IndexDb {
    fn snapshot(&self, scan_id: Uuid) -> Result<VerificationEvidenceSnapshot, AppError> {
        let snapshot = match self.verification_snapshot(scan_id) {
            Ok(snapshot) => snapshot,
            Err(IndexError::NotFound) => {
                return Ok(VerificationEvidenceSnapshot {
                    status: Some("missing".into()),
                    ..VerificationEvidenceSnapshot::default()
                });
            }
            Err(error) => return Err(error.into()),
        };
        convert_index_snapshot(snapshot)
    }
}

fn convert_index_snapshot(
    snapshot: VerificationSnapshot,
) -> Result<VerificationEvidenceSnapshot, AppError> {
    let records = snapshot
        .records
        .into_iter()
        .map(convert_index_record)
        .collect::<Result<Vec<_>, _>>()?;
    let sessions = snapshot
        .sessions
        .into_iter()
        .map(|session| IndexedSessionEvidence {
            id: session.id,
            canonical_json: session.canonical_json,
            canonical_hash: session.canonical_hash,
            search_title: session.search_title,
            search_body: session.search_body,
            fts_title: session.fts_title,
            fts_body: session.fts_body,
            message_ordinals: session.message_ordinals,
            tool_event_ordinals: session.tool_event_ordinals,
        })
        .collect();
    Ok(VerificationEvidenceSnapshot {
        status: Some(snapshot.status),
        indexed_count: snapshot.indexed_count,
        quarantined_count: snapshot.quarantined_count,
        retryable_count: snapshot.retryable_count,
        rejected_count: snapshot.rejected_count,
        records,
        sessions,
    })
}

fn convert_index_record(
    record: agentark_index::VerificationRecord,
) -> Result<VerificationEvidenceRecord, AppError> {
    let object_type = ObjectType::from_byte(record.object_type)?;
    let session = record
        .session_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?;
    Ok(VerificationEvidenceRecord {
        object: StoredObject {
            object_id: record.object_id,
            object_type,
            plaintext_hash: record.plaintext_hash,
            size: record.size,
        },
        session,
        canonical_hash: record.canonical_hash,
        sanitized_title: record.sanitized_title,
        sanitized_body: record.sanitized_body,
    })
}

pub struct VerificationService<C, E = VerificationJournal> {
    cas: C,
    evidence: E,
    scanner: SecretScanner,
}

impl<C: ArtifactStore, E: VerificationEvidence> VerificationService<C, E> {
    pub fn new(cas: C, evidence: E) -> Self {
        Self {
            cas,
            evidence,
            scanner: SecretScanner::v1().expect("built-in secret rules are valid"),
        }
    }

    pub fn verify_scan(&self, scan_id: Uuid) -> Result<VerificationReport, AppError> {
        let mut failures = Vec::new();
        let snapshot = self.evidence.snapshot(scan_id)?;
        if snapshot.status.as_deref() == Some("missing") {
            failures.push(VerificationFailure {
                code: "scan-not-found".into(),
                object_id: None,
            });
        }
        if matches!(snapshot.status.as_deref(), Some("running" | "failed")) {
            failures.push(VerificationFailure {
                code: "scan-not-complete".into(),
                object_id: None,
            });
        }
        if snapshot.status.is_some() {
            let expected_records = snapshot.indexed_count
                + snapshot.quarantined_count
                + snapshot.retryable_count
                + snapshot.rejected_count;
            if expected_records != snapshot.records.len() as u64
                || snapshot.sessions.len() as u64 != snapshot.indexed_count
            {
                failures.push(VerificationFailure {
                    code: "scan-count-mismatch".into(),
                    object_id: None,
                });
            }
        }
        for entry in &snapshot.records {
            let plaintext = match self.cas.get(&entry.object) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    failures.push(VerificationFailure {
                        code: "cas-authentication-failed".into(),
                        object_id: Some(entry.object.object_id.clone()),
                    });
                    continue;
                }
            };
            if plaintext.len() as u64 != entry.object.size
                || Sha256Digest::from_bytes(&plaintext) != entry.object.plaintext_hash
            {
                failures.push(VerificationFailure {
                    code: "cas-plaintext-hash-mismatch".into(),
                    object_id: Some(entry.object.object_id.clone()),
                });
            }
            if let (Some(session), Some(expected_hash)) =
                (entry.session.as_ref(), entry.canonical_hash.as_ref())
            {
                match canonical_hash("session", session) {
                    Ok(actual_hash) if &actual_hash == expected_hash => {}
                    _ => failures.push(VerificationFailure {
                        code: "canonical-hash-mismatch".into(),
                        object_id: Some(entry.object.object_id.clone()),
                    }),
                }
                if !strictly_increasing_messages(session) || !strictly_increasing_tools(session) {
                    failures.push(VerificationFailure {
                        code: "message-ordinal-order".into(),
                        object_id: Some(entry.object.object_id.clone()),
                    });
                }
                let expected_title = self
                    .scanner
                    .sanitize(session.title.as_deref().unwrap_or(""))
                    .text;
                let expected_body = self.scanner.sanitize(&session.searchable_text()).text;
                if entry.sanitized_title.as_deref() != Some(expected_title.as_str())
                    || entry.sanitized_body.as_deref() != Some(expected_body.as_str())
                {
                    failures.push(VerificationFailure {
                        code: "fts-sanitized-projection-mismatch".into(),
                        object_id: Some(entry.object.object_id.clone()),
                    });
                }
            }
        }
        for session in &snapshot.sessions {
            match serde_json::from_str::<CanonicalSession>(&session.canonical_json) {
                Ok(canonical) => {
                    if canonical.id != session.id
                        || canonical_hash("session", &canonical).ok().as_ref()
                            != Some(&session.canonical_hash)
                        || canonical.messages.len() != session.message_ordinals.len()
                        || canonical.tool_events.len() != session.tool_event_ordinals.len()
                        || !strictly_increasing(&session.message_ordinals)
                        || !strictly_increasing(&session.tool_event_ordinals)
                        || !merged_ordinals_unique(
                            &session.message_ordinals,
                            &session.tool_event_ordinals,
                        )
                    {
                        failures.push(VerificationFailure {
                            code: "indexed-session-mismatch".into(),
                            object_id: None,
                        });
                        continue;
                    }
                    let expected_title = self
                        .scanner
                        .sanitize(&canonical.title.clone().unwrap_or_default())
                        .text;
                    let expected_body = self.scanner.sanitize(&canonical.searchable_text()).text;
                    if session.fts_title.as_deref() != Some(session.search_title.as_str())
                        || session.fts_body.as_deref() != Some(session.search_body.as_str())
                        || session.search_title != expected_title
                        || session.search_body != expected_body
                    {
                        failures.push(VerificationFailure {
                            code: "fts-sanitized-projection-mismatch".into(),
                            object_id: None,
                        });
                    }
                }
                Err(_) => failures.push(VerificationFailure {
                    code: "indexed-session-json-invalid".into(),
                    object_id: None,
                }),
            }
        }
        Ok(VerificationReport {
            scan_id,
            passed: failures.is_empty(),
            failures,
        })
    }
}

fn strictly_increasing_messages(session: &CanonicalSession) -> bool {
    session
        .messages
        .windows(2)
        .all(|window| window[0].ordinal < window[1].ordinal)
}

fn strictly_increasing_tools(session: &CanonicalSession) -> bool {
    session
        .tool_events
        .windows(2)
        .all(|window| window[0].ordinal < window[1].ordinal)
}

fn strictly_increasing(values: &[u64]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn merged_ordinals_unique(messages: &[u64], tools: &[u64]) -> bool {
    let mut values = messages
        .iter()
        .chain(tools.iter())
        .copied()
        .collect::<Vec<_>>();
    values.sort_unstable();
    strictly_increasing(&values)
}
