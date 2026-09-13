#![forbid(unsafe_code)]

mod database;
mod error;
mod provenance;
mod query;
mod recovery;
mod verification;
mod write;

pub use database::IndexDb;
pub use error::IndexError;
pub use provenance::{
    RawProvenanceStatus, session_has_raw_references, session_raw_provenance_status,
};
pub use query::{
    QuarantineSummary, SearchHit, SessionDetail, SessionQuery, SessionSummary, WorkspaceSummary,
};
pub use recovery::RestoreMapping;
pub use verification::{IndexedSession, VerificationSnapshot};
pub use write::{
    QuarantineRecord, ScanManifest, ScanManifestStatus, SessionIndex, SessionIngest,
    VerificationRecord,
};
