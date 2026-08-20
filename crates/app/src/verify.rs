use std::sync::Arc;

use agentark_canonical::{CanonicalSession, Sha256Digest, canonical_hash};
use agentark_cas::{ArtifactStore, ObjectType, StoredObject};
use agentark_index::IndexDb;
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
    fn records(&self, scan_id: Uuid) -> Result<Vec<VerificationEvidenceRecord>, AppError>;
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
    fn records(&self, scan_id: Uuid) -> Result<Vec<VerificationEvidenceRecord>, AppError> {
        Ok(self.objects(scan_id))
    }
}

impl<T: VerificationEvidence + ?Sized> VerificationEvidence for &T {
    fn records(&self, scan_id: Uuid) -> Result<Vec<VerificationEvidenceRecord>, AppError> {
        (*self).records(scan_id)
    }
}

impl VerificationEvidence for IndexDb {
    fn records(&self, scan_id: Uuid) -> Result<Vec<VerificationEvidenceRecord>, AppError> {
        self.verification_records(scan_id)?
            .into_iter()
            .map(|record| {
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
            })
            .collect()
    }
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
        for entry in self.evidence.records(scan_id)? {
            let plaintext = match self.cas.get(&entry.object) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    failures.push(VerificationFailure {
                        code: "cas-authentication-failed".into(),
                        object_id: Some(entry.object.object_id),
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
