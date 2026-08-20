use std::collections::BTreeSet;

use crate::{
    AdapterError, CaptureRequest, DetectContext, NormalizeOutcome, ProbeReport, SourceAdapter,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContractReport {
    pub normalized: u64,
    pub quarantined: u64,
    pub retryable: u64,
    pub rejected: u64,
}

pub fn assert_source_adapter_contract<A: SourceAdapter>(
    adapter: &A,
) -> Result<ContractReport, AdapterError> {
    if adapter.id().is_empty() {
        return Err(AdapterError::ContractViolation(
            "adapter id must not be empty".into(),
        ));
    }
    let installs = adapter.detect(&DetectContext {
        explicit_roots: Vec::new(),
        allow_detected_home: false,
    })?;
    if installs.len() != 1 {
        return Err(AdapterError::ContractViolation(
            "contract fixture must expose exactly one install".into(),
        ));
    }
    let install = &installs[0];
    let probe = adapter.probe(install)?;
    validate_probe(adapter.id(), &probe, &adapter.capabilities(install))?;

    let request = CaptureRequest {
        install: install.clone(),
        snapshot_hint: None,
    };
    let first = adapter.capture(&request)?;
    let second = adapter.capture(&request)?;
    if first != second {
        return Err(AdapterError::ContractViolation(
            "repeated capture must be byte- and order-deterministic".into(),
        ));
    }
    if first.snapshot_id.is_empty() {
        return Err(AdapterError::ContractViolation(
            "capture snapshot id must not be empty".into(),
        ));
    }
    let mut previous = None;
    for record in &first.records {
        if record.snapshot_id != first.snapshot_id {
            return Err(AdapterError::ContractViolation(
                "records must use the batch snapshot id".into(),
            ));
        }
        let key = (&record.source_locator, record.ordinal);
        if let Some(previous_key) = previous
            && previous_key > key
        {
            return Err(AdapterError::ContractViolation(
                "records must be in deterministic source order".into(),
            ));
        }
        previous = Some(key);
    }

    let mut report = ContractReport::default();
    for record in first.records {
        match adapter.normalize(&record)? {
            NormalizeOutcome::Normalized(_) => report.normalized += 1,
            NormalizeOutcome::Quarantined { .. } => report.quarantined += 1,
            NormalizeOutcome::Retryable { .. } => report.retryable += 1,
            NormalizeOutcome::Rejected { .. } => report.rejected += 1,
        }
    }
    Ok(report)
}

fn validate_probe(
    adapter_id: &str,
    probe: &ProbeReport,
    capabilities: &BTreeSet<crate::SourceCapability>,
) -> Result<(), AdapterError> {
    if probe.adapter_id != adapter_id {
        return Err(AdapterError::ContractViolation(
            "probe adapter id does not match SourceAdapter::id".into(),
        ));
    }
    if probe.executable_version.is_empty() || probe.schema_fingerprint.is_empty() {
        return Err(AdapterError::ContractViolation(
            "probe version and schema fingerprint must not be empty".into(),
        ));
    }
    if &probe.capabilities != capabilities {
        return Err(AdapterError::ContractViolation(
            "probe capabilities differ from the adapter capability set".into(),
        ));
    }
    Ok(())
}
