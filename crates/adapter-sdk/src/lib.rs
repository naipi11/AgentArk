#![forbid(unsafe_code)]

mod conformance;
mod contract;
mod types;

pub use conformance::{ContractReport, assert_source_adapter_contract};
pub use contract::{AdapterError, SourceAdapter};
pub use types::{
    CaptureBatch, CaptureRequest, CapturedRecord, DetectContext, NormalizeOutcome, ProbeReport,
    SourceCapability,
};
