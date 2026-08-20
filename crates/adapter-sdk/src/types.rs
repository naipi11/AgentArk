use std::collections::BTreeSet;
use std::path::PathBuf;

use agentark_canonical::{AgentInstall, CanonicalSession};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectContext {
    pub explicit_roots: Vec<PathBuf>,
    pub allow_detected_home: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceCapability {
    AppServerRead,
    FilesystemRawArchive,
    ArchivedThreads,
    Attachments,
    KnownSemanticSchema,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeReport {
    pub adapter_id: String,
    pub executable_version: String,
    pub schema_fingerprint: String,
    pub capabilities: BTreeSet<SourceCapability>,
    pub quarantine_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CaptureRequest {
    pub install: AgentInstall,
    pub snapshot_hint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedRecord {
    pub source_locator: String,
    pub source_session_id: Option<String>,
    pub source_record_id: Option<String>,
    pub ordinal: u64,
    pub snapshot_id: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureBatch {
    pub snapshot_id: String,
    pub records: Vec<CapturedRecord>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum NormalizeOutcome {
    Normalized(Box<CanonicalSession>),
    Quarantined {
        reason_code: String,
        fingerprint: String,
    },
    Retryable {
        reason_code: String,
    },
    Rejected {
        reason_code: String,
    },
}
