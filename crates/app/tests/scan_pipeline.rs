use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use agentark_adapter_sdk::{
    AdapterError, CaptureBatch, CaptureRequest, CapturedRecord, CapturedSource, DetectContext,
    NormalizeOutcome, ProbeReport, SourceAdapter, SourceCapability,
};
use agentark_app::{AppError, ScanRequest, ScanService, ScanStatus};
use agentark_canonical::{
    AgentInstall, AgentKind, CanonicalSchemaVersion, CanonicalSession, Completeness, Sha256Digest,
};
use agentark_cas::{ArtifactStore, CasError, ObjectType, StoredObject};
use agentark_index::{IndexError, QuarantineRecord, ScanManifest, SessionIndex, SessionIngest};
use agentark_security::SecretScanner;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
enum FixtureOutcome {
    Normalized,
    Quarantined,
}

#[derive(Clone)]
struct FixtureAdapter {
    events: Arc<Mutex<Vec<&'static str>>>,
    outcome: FixtureOutcome,
    install: AgentInstall,
}

impl SourceAdapter for FixtureAdapter {
    fn id(&self) -> &'static str {
        "fixture"
    }
    fn detect(&self, _ctx: &DetectContext) -> Result<Vec<AgentInstall>, AdapterError> {
        Ok(vec![self.install.clone()])
    }
    fn probe(&self, _install: &AgentInstall) -> Result<ProbeReport, AdapterError> {
        Ok(ProbeReport {
            adapter_id: self.id().into(),
            executable_version: "fixture".into(),
            schema_fingerprint: "fixture".into(),
            capabilities: self.capabilities(&self.install),
            quarantine_reason: None,
        })
    }
    fn capture(&self, _request: &CaptureRequest) -> Result<CaptureBatch, AdapterError> {
        self.events.lock().unwrap().push("capture");
        Ok(CaptureBatch {
            snapshot_id: "snapshot".into(),
            records: vec![CapturedRecord {
                source: CapturedSource::AppServerSemantic,
                source_locator: "fixture.jsonl".into(),
                source_session_id: Some("fixture-session".into()),
                source_record_id: Some("record-1".into()),
                ordinal: 0,
                snapshot_id: "snapshot".into(),
                bytes: b"raw".to_vec(),
            }],
            issues: Vec::new(),
        })
    }
    fn normalize(&self, record: &CapturedRecord) -> Result<NormalizeOutcome, AdapterError> {
        self.events.lock().unwrap().push("normalize");
        Ok(match self.outcome {
            FixtureOutcome::Normalized => {
                NormalizeOutcome::Normalized(Box::new(CanonicalSession {
                    schema_version: CanonicalSchemaVersion::V0_1_0,
                    id: Uuid::new_v4(),
                    install_id: self.install.id,
                    source_session_id: "fixture-session".into(),
                    source_kind: "fixture".into(),
                    workspace: None,
                    title: Some("fixture".into()),
                    archived: false,
                    created_at_raw: None,
                    updated_at_raw: None,
                    model_provider: None,
                    model_name: None,
                    completeness: Completeness::Complete,
                    messages: Vec::new(),
                    tool_events: Vec::new(),
                    attachments: Vec::new(),
                    raw_extra: Default::default(),
                }))
            }
            FixtureOutcome::Quarantined => NormalizeOutcome::Quarantined {
                reason_code: "fixture-quarantine".into(),
                fingerprint: Sha256Digest::from_bytes(&record.bytes).as_str().into(),
            },
        })
    }
    fn capabilities(&self, _install: &AgentInstall) -> BTreeSet<SourceCapability> {
        BTreeSet::from([SourceCapability::FilesystemRawArchive])
    }
}

#[derive(Clone)]
struct FixtureCas {
    events: Arc<Mutex<Vec<&'static str>>>,
}
impl ArtifactStore for FixtureCas {
    fn put(&self, object_type: ObjectType, plaintext: &[u8]) -> Result<StoredObject, CasError> {
        self.events.lock().unwrap().push("cas.put");
        Ok(StoredObject {
            object_id: "object-1".into(),
            object_type,
            plaintext_hash: Sha256Digest::from_bytes(plaintext),
            size: plaintext.len() as u64,
        })
    }
    fn get(&self, _object: &StoredObject) -> Result<Zeroizing<Vec<u8>>, CasError> {
        Ok(Zeroizing::new(b"raw".to_vec()))
    }
}

#[derive(Clone, Default)]
struct FixtureIndex {
    events: Arc<Mutex<Vec<&'static str>>>,
    status: Arc<Mutex<Option<String>>>,
    stale_sources: Arc<Mutex<Vec<String>>>,
    fail_ingest: bool,
}
impl FixtureIndex {
    fn last_scan_status(&self) -> Option<String> {
        self.status.lock().unwrap().clone()
    }
    fn stale_sources(&self) -> Vec<String> {
        self.stale_sources.lock().unwrap().clone()
    }
}
impl SessionIndex for FixtureIndex {
    fn begin_scan(
        &mut self,
        _scan_id: Uuid,
        _adapter_id: &str,
        _snapshot_id: &str,
    ) -> Result<(), IndexError> {
        Ok(())
    }
    fn ingest_session(&mut self, _input: SessionIngest<'_>) -> Result<(), IndexError> {
        if self.fail_ingest {
            return Err(IndexError::NotFound);
        }
        self.events.lock().unwrap().push("index.ingest");
        Ok(())
    }
    fn record_quarantine(&mut self, _record: QuarantineRecord) -> Result<(), IndexError> {
        self.events.lock().unwrap().push("index.quarantine");
        Ok(())
    }
    fn finish_scan(&mut self, manifest: &ScanManifest) -> Result<(), IndexError> {
        *self.status.lock().unwrap() = Some(
            match manifest.status {
                agentark_index::ScanManifestStatus::Complete => "complete",
                agentark_index::ScanManifestStatus::Partial => "partial",
                agentark_index::ScanManifestStatus::Failed => "failed",
            }
            .into(),
        );
        Ok(())
    }
    fn fail_scan(&mut self, _scan_id: Uuid) -> Result<(), IndexError> {
        *self.status.lock().unwrap() = Some("failed".into());
        Ok(())
    }

    fn mark_source_sessions_stale(
        &mut self,
        _install_id: Uuid,
        source_session_ids: &[String],
    ) -> Result<(), IndexError> {
        self.stale_sources
            .lock()
            .unwrap()
            .extend(source_session_ids.iter().cloned());
        Ok(())
    }
}

fn install() -> AgentInstall {
    AgentInstall {
        id: Uuid::new_v4(),
        kind: AgentKind::Codex,
        executable_version: "fixture".into(),
        authorized_root_uri: "file:///fixture".into(),
        adapter_version: "fixture".into(),
        schema_fingerprint: "fixture".into(),
        capabilities: BTreeSet::new(),
        quarantine_reason: None,
    }
}

fn fixture_service(
    events: Arc<Mutex<Vec<&'static str>>>,
    outcome: FixtureOutcome,
) -> ScanService<FixtureAdapter, FixtureCas, FixtureIndex> {
    let install = install();
    ScanService::new(
        FixtureAdapter {
            events: events.clone(),
            outcome,
            install,
        },
        FixtureCas {
            events: events.clone(),
        },
        FixtureIndex {
            events,
            status: Arc::new(Mutex::new(None)),
            stale_sources: Arc::new(Mutex::new(Vec::new())),
            fail_ingest: false,
        },
        SecretScanner::v1().unwrap(),
    )
}

fn fixture_service_with_failing_index(
    events: Arc<Mutex<Vec<&'static str>>>,
) -> ScanService<FixtureAdapter, FixtureCas, FixtureIndex> {
    let install = install();
    ScanService::new(
        FixtureAdapter {
            events: events.clone(),
            outcome: FixtureOutcome::Normalized,
            install,
        },
        FixtureCas {
            events: events.clone(),
        },
        FixtureIndex {
            events,
            status: Arc::new(Mutex::new(None)),
            stale_sources: Arc::new(Mutex::new(Vec::new())),
            fail_ingest: true,
        },
        SecretScanner::v1().unwrap(),
    )
}

fn fixture_request() -> ScanRequest {
    ScanRequest {
        install: install(),
        snapshot_hint: None,
    }
}

#[test]
fn archives_raw_bytes_before_normalizing_or_indexing() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut service = fixture_service(events.clone(), FixtureOutcome::Normalized);
    let report = service.run(fixture_request()).unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        ["capture", "cas.put", "normalize", "index.ingest"]
    );
    assert_eq!(report.status, ScanStatus::Complete);
    assert_eq!(report.indexed, 1);
}

#[test]
fn quarantine_is_archived_but_never_indexed_and_marks_scan_partial() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut service = fixture_service(events.clone(), FixtureOutcome::Quarantined);
    let report = service.run(fixture_request()).unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        ["capture", "cas.put", "normalize", "index.quarantine"]
    );
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.quarantined, 1);
}

#[test]
fn index_failure_does_not_publish_a_complete_manifest() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut service = fixture_service_with_failing_index(events);
    let error = service.run(fixture_request()).unwrap_err();
    assert!(matches!(error, AppError::Index(_)));
    assert_eq!(service.index().last_scan_status(), Some("failed".into()));
    assert_eq!(service.index().stale_sources(), vec!["fixture-session"]);
}
