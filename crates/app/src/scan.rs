use agentark_adapter_sdk::{CaptureRequest, CapturedSource, NormalizeOutcome, SourceAdapter};
use agentark_canonical::{
    AgentInstall, CanonicalSession, Sha256Digest, SourceRecord, canonical_hash, session_id,
};
use agentark_cas::{ArtifactStore, ObjectType};
use agentark_index::{
    QuarantineRecord, ScanManifest, ScanManifestStatus, SessionIndex, SessionIngest,
    VerificationRecord,
};
use agentark_security::{SecretFinding, SecretScanner};
use serde::Serialize;
use std::collections::HashMap;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{AppError, VerificationJournal, VerificationService};

#[derive(Clone, Debug)]
pub struct ScanRequest {
    pub install: AgentInstall,
    pub snapshot_hint: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanStatus {
    Complete,
    Partial,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub scan_id: Uuid,
    pub status: ScanStatus,
    pub indexed: u64,
    pub quarantined: u64,
    pub retryable: u64,
    pub rejected: u64,
}

pub struct ScanService<A, C, I> {
    adapter: A,
    cas: C,
    index: I,
    scanner: SecretScanner,
    journal: VerificationJournal,
    pending_session_ids: Vec<Uuid>,
    pending_source_session_ids: Vec<String>,
    pending_install_id: Option<Uuid>,
}

impl<A, C, I> ScanService<A, C, I>
where
    A: SourceAdapter,
    C: ArtifactStore,
    I: SessionIndex,
{
    pub fn new(adapter: A, cas: C, index: I, scanner: SecretScanner) -> Self {
        Self {
            adapter,
            cas,
            index,
            scanner,
            journal: VerificationJournal::default(),
            pending_session_ids: Vec::new(),
            pending_source_session_ids: Vec::new(),
            pending_install_id: None,
        }
    }

    pub fn index(&self) -> &I {
        &self.index
    }

    pub fn index_mut(&mut self) -> &mut I {
        &mut self.index
    }

    pub fn verification_journal(&self) -> VerificationJournal {
        self.journal.clone()
    }

    pub fn into_parts(self) -> (A, C, I, VerificationJournal) {
        (self.adapter, self.cas, self.index, self.journal)
    }

    pub fn run(&mut self, request: ScanRequest) -> Result<ScanReport, AppError> {
        self.pending_session_ids.clear();
        self.pending_source_session_ids.clear();
        self.pending_install_id = Some(request.install.id);
        let scan_id = Uuid::new_v4();
        let initial_snapshot = request
            .snapshot_hint
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("pending");
        self.index
            .begin_scan(scan_id, self.adapter.id(), initial_snapshot)?;

        let result = self.run_started(scan_id, request);
        match result {
            Ok(report) => Ok(report),
            Err(error) => {
                let _ = self.index.mark_sessions_stale(&self.pending_session_ids);
                if let Some(install_id) = self.pending_install_id {
                    let _ = self
                        .index
                        .mark_source_sessions_stale(install_id, &self.pending_source_session_ids);
                }
                let _ = self.index.fail_scan(scan_id);
                self.pending_session_ids.clear();
                self.pending_source_session_ids.clear();
                self.pending_install_id = None;
                Err(error)
            }
        }
    }

    fn run_started(&mut self, scan_id: Uuid, request: ScanRequest) -> Result<ScanReport, AppError> {
        let batch = self.adapter.capture(&CaptureRequest {
            install: request.install.clone(),
            snapshot_hint: request.snapshot_hint.clone(),
        })?;
        let mut indexed = 0;
        let mut quarantined = 0;
        let mut retryable = 0;
        let mut rejected = 0;

        for issue in &batch.issues {
            if let Some(source_session_id) = issue.source_session_id.as_deref() {
                let id = session_id(request.install.id, source_session_id);
                if !self.pending_session_ids.contains(&id) {
                    self.pending_session_ids.push(id);
                }
                if !self
                    .pending_source_session_ids
                    .iter()
                    .any(|value| value == source_session_id)
                {
                    self.pending_source_session_ids
                        .push(source_session_id.to_owned());
                }
            }
            if issue.retryable {
                retryable += 1;
            } else {
                rejected += 1;
            }
        }

        let mut archived_records = Vec::with_capacity(batch.records.len());
        for record in batch.records {
            if let Some(source_session_id) = record.source_session_id.as_deref() {
                let id = session_id(request.install.id, source_session_id);
                if !self.pending_session_ids.contains(&id) {
                    self.pending_session_ids.push(id);
                }
                if !self
                    .pending_source_session_ids
                    .iter()
                    .any(|value| value == source_session_id)
                {
                    self.pending_source_session_ids
                        .push(source_session_id.to_owned());
                }
            }
            let stored = self.cas.put(ObjectType::AgentRawRecord, &record.bytes)?;
            self.journal.record(scan_id, stored.clone());
            self.index.record_verification(VerificationRecord {
                scan_id,
                object_id: stored.object_id.clone(),
                object_type: stored.object_type.as_byte(),
                plaintext_hash: stored.plaintext_hash.clone(),
                size: stored.size,
                session_json: None,
                canonical_hash: None,
                sanitized_title: None,
                sanitized_body: None,
            })?;
            archived_records.push((record, stored));
        }

        let mut evidence_by_source: HashMap<String, Vec<SourceRecord>> = HashMap::new();
        for (record, stored) in archived_records {
            if matches!(record.source, CapturedSource::FilesystemEvidence) {
                if let Some(source_session_id) = record.source_session_id.as_deref() {
                    evidence_by_source
                        .entry(source_session_id.to_owned())
                        .or_default()
                        .push(SourceRecord {
                            source_locator: sanitize_locator(&record.source_locator),
                            source_record_id: record.source_record_id.clone(),
                            ordinal: record.ordinal,
                            raw_sha256: stored.plaintext_hash.clone(),
                            cas_object_id: stored.object_id.clone(),
                            adapter_version: request.install.adapter_version.clone(),
                            snapshot_id: batch.snapshot_id.clone(),
                        });
                }
                continue;
            }
            if matches!(record.source, CapturedSource::FilesystemRawOnly) {
                self.index.record_quarantine(QuarantineRecord {
                    id: Uuid::new_v5(
                        &scan_id,
                        format!("{}:{}", record.source_locator, record.ordinal).as_bytes(),
                    ),
                    scan_id,
                    source_locator: sanitize_locator(&record.source_locator),
                    fingerprint: format!("sha256:{}", stored.plaintext_hash.as_str()),
                    reason_code: "filesystem-raw-only".into(),
                    raw_sha256: stored.plaintext_hash,
                    cas_object_id: stored.object_id,
                })?;
                quarantined += 1;
                continue;
            }

            let outcome = self.adapter.normalize(&record)?;
            match outcome {
                NormalizeOutcome::Normalized(session) => {
                    let session = *session;
                    if !self.pending_session_ids.contains(&session.id) {
                        self.pending_session_ids.push(session.id);
                    }
                    verify_raw_references(&session, &stored.plaintext_hash)?;
                    let (sanitized_title, sanitized_body, findings) =
                        sanitize_session(&self.scanner, &session);
                    let canonical_hash = canonical_hash("session", &session)?;
                    let source_record = SourceRecord {
                        source_locator: sanitize_locator(&record.source_locator),
                        source_record_id: record.source_record_id.clone(),
                        ordinal: record.ordinal,
                        raw_sha256: stored.plaintext_hash.clone(),
                        cas_object_id: stored.object_id.clone(),
                        adapter_version: request.install.adapter_version.clone(),
                        snapshot_id: batch.snapshot_id.clone(),
                    };
                    let mut source_records = vec![source_record];
                    if let Some(source_session_id) = record.source_session_id.as_deref()
                        && let Some(mut evidence) = evidence_by_source.remove(source_session_id)
                    {
                        source_records.append(&mut evidence);
                    }
                    self.journal.record_session(
                        scan_id,
                        &stored.object_id,
                        session.clone(),
                        canonical_hash.clone(),
                        sanitized_title.clone(),
                        sanitized_body.clone(),
                    );
                    self.index.record_verification(VerificationRecord {
                        scan_id,
                        object_id: stored.object_id.clone(),
                        object_type: stored.object_type.as_byte(),
                        plaintext_hash: stored.plaintext_hash.clone(),
                        size: stored.size,
                        session_json: Some(serde_json::to_string(&session)?),
                        canonical_hash: Some(canonical_hash.clone()),
                        sanitized_title: Some(sanitized_title.clone()),
                        sanitized_body: Some(sanitized_body.clone()),
                    })?;
                    self.index.ingest_session(SessionIngest {
                        install: &request.install,
                        session: &session,
                        source_records: &source_records,
                        sanitized_title: &sanitized_title,
                        sanitized_body: &sanitized_body,
                        findings: &findings,
                        canonical_hash: &canonical_hash,
                    })?;
                    indexed += 1;
                }
                NormalizeOutcome::Quarantined {
                    reason_code,
                    fingerprint,
                } => {
                    self.index.record_quarantine(QuarantineRecord {
                        id: Uuid::new_v5(
                            &scan_id,
                            format!("{}:{}", record.source_locator, record.ordinal).as_bytes(),
                        ),
                        scan_id,
                        source_locator: sanitize_locator(&record.source_locator),
                        fingerprint: sanitize_fingerprint(&fingerprint),
                        reason_code: sanitize_reason(&reason_code),
                        raw_sha256: stored.plaintext_hash,
                        cas_object_id: stored.object_id,
                    })?;
                    quarantined += 1;
                }
                NormalizeOutcome::Retryable { .. } => retryable += 1,
                NormalizeOutcome::Rejected { .. } => rejected += 1,
            }
        }

        let status = if quarantined == 0 && retryable == 0 && rejected == 0 {
            ScanStatus::Complete
        } else {
            ScanStatus::Partial
        };
        let verification = VerificationService::new(&self.cas, self.journal.clone())
            .verify_scan_before_publish(scan_id)?;
        if !verification.passed {
            return Err(AppError::Invariant(
                "scan verification failed before manifest publication".into(),
            ));
        }
        if let Some(snapshot) = self.index.verification_snapshot(scan_id)? {
            let verification = VerificationService::new(&self.cas, snapshot)
                .verify_scan_before_publish(scan_id)?;
            if !verification.passed {
                return Err(AppError::Invariant(format!(
                    "durable scan verification failed before manifest publication: {}",
                    verification
                        .failures
                        .iter()
                        .map(|failure| failure.code.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                )));
            }
        }
        self.index.finish_scan(&ScanManifest {
            id: scan_id,
            status: match status {
                ScanStatus::Complete => ScanManifestStatus::Complete,
                ScanStatus::Partial => ScanManifestStatus::Partial,
                ScanStatus::Failed => ScanManifestStatus::Failed,
            },
            completed_at: now_string(),
            indexed_count: indexed,
            quarantined_count: quarantined,
            retryable_count: retryable,
            rejected_count: rejected,
        })?;
        self.pending_session_ids.clear();
        self.pending_source_session_ids.clear();
        self.pending_install_id = None;
        Ok(ScanReport {
            scan_id,
            status,
            indexed,
            quarantined,
            retryable,
            rejected,
        })
    }
}

fn verify_raw_references(
    session: &CanonicalSession,
    raw_hash: &Sha256Digest,
) -> Result<(), AppError> {
    let invalid_message = session
        .messages
        .iter()
        .any(|message| &message.raw_ref != raw_hash);
    let invalid_tool = session
        .tool_events
        .iter()
        .any(|event| &event.raw_ref != raw_hash);
    if invalid_message || invalid_tool {
        return Err(AppError::Invariant(
            "normalized raw reference is not the archived object hash".into(),
        ));
    }
    Ok(())
}

fn sanitize_session(
    scanner: &SecretScanner,
    session: &CanonicalSession,
) -> (String, String, Vec<SecretFinding>) {
    let title = scanner.sanitize(session.title.as_deref().unwrap_or(""));
    let body = scanner.sanitize(&session.searchable_text());
    let mut findings = title.findings.clone();
    let body_offset = title.text.len() + 1;
    findings.extend(body.findings.into_iter().map(|mut finding| {
        finding.start += body_offset;
        finding.end += body_offset;
        finding
    }));
    (title.text, body.text, findings)
}

fn sanitize_locator(value: &str) -> String {
    let basename = value
        .split(['/', '\\'])
        .rfind(|part| !part.is_empty())
        .unwrap_or("source");
    let mut output = basename
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
        "source".into()
    } else {
        output
    }
}

fn sanitize_reason(value: &str) -> String {
    sanitize_locator(value).replace('.', "-")
}

fn sanitize_fingerprint(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_hexdigit() || *character == ':')
        .take(80)
        .collect()
}

fn now_string() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}
