#![forbid(unsafe_code)]

mod database;
mod error;
mod query;
mod write;

pub use database::IndexDb;
pub use error::IndexError;
pub use query::{QuarantineSummary, SearchHit, SessionDetail, SessionQuery, SessionSummary};
pub use write::{
    QuarantineRecord, ScanManifest, ScanManifestStatus, SessionIndex, SessionIngest,
    VerificationRecord,
};
