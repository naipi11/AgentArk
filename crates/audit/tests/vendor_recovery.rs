use std::fs;

use agentark_audit::{
    AuditEvent, VendorRecoveryAudit, VendorRecoveryStatus, append_event, verify_chain,
};
use agentark_canonical::Sha256Digest;
use tempfile::tempdir;
use uuid::Uuid;

fn event(vendor_recovery: Option<VendorRecoveryAudit>) -> AuditEvent {
    AuditEvent {
        event_id: Uuid::from_u128(1),
        event_type: "vendor.recovery.completed".into(),
        timestamp: "2026-08-24T00:00:00Z".into(),
        actor: "test".into(),
        source: None,
        target: None,
        before_hash: None,
        after_hash: None,
        plan_hash: None,
        result: "complete".into(),
        provider_labels: vec!["openai".into()],
        vendor_recovery,
        previous_hash: None,
        event_hash: Sha256Digest::from_bytes(b"pending"),
    }
}

#[test]
fn aggregate_hashes_are_exact_and_independent_of_input_order() {
    let source_a = Sha256Digest::from_bytes(b"source-a");
    let source_b = Sha256Digest::from_bytes(b"source-b");
    let target_a = Sha256Digest::from_bytes(b"target-a");

    let first = VendorRecoveryAudit::from_hashes(
        1,
        1,
        0,
        0,
        [source_b.clone(), source_a.clone()],
        [target_a.clone()],
    );
    let reordered = VendorRecoveryAudit::from_hashes(1, 1, 0, 0, [source_a, source_b], [target_a]);

    assert_eq!(first, reordered);
    assert_eq!(
        first.source_hashes_digest.as_str(),
        "sha256:a1d11530e0ebb28cc901ce0bd1fb72270865ab03cc98a8b3ecb2a1b4dd3cdbd9"
    );
    assert_eq!(
        first.target_hashes_digest.as_str(),
        "sha256:a80758f0001da5b96cedd691652294600b18387494361598ffa928ae60bfddea"
    );
    assert_eq!(first.status, VendorRecoveryStatus::Complete);
}

#[test]
fn status_is_closed_and_derived_from_outcome_counts() {
    let partial =
        VendorRecoveryAudit::from_hashes(0, 0, 1, 0, std::iter::empty(), std::iter::empty());
    let manual =
        VendorRecoveryAudit::from_hashes(1, 0, 1, 1, std::iter::empty(), std::iter::empty());

    assert_eq!(partial.status, VendorRecoveryStatus::Partial);
    assert_eq!(manual.status, VendorRecoveryStatus::ManualIntervention);
    assert_eq!(
        serde_json::to_value(manual).unwrap()["status"],
        "manualIntervention"
    );
}

#[test]
fn absent_vendor_recovery_keeps_legacy_event_shape_and_chain_valid() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let appended = append_event(&path, event(None)).unwrap();
    let line = fs::read_to_string(&path).unwrap();

    assert!(!line.contains("vendorRecovery"));
    let legacy: AuditEvent = serde_json::from_str(&line).unwrap();
    assert_eq!(legacy.vendor_recovery, None);
    assert_eq!(legacy.event_hash, appended.event_hash);
    assert!(verify_chain(&path).unwrap().valid);
}

#[test]
fn vendor_recovery_serialization_contains_only_the_allowlisted_summary_fields() {
    let summary = VendorRecoveryAudit::from_hashes(
        1,
        2,
        3,
        4,
        [Sha256Digest::from_bytes(b"source")],
        [Sha256Digest::from_bytes(b"target")],
    );
    let value = serde_json::to_value(summary).unwrap();
    let mut keys = value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();

    assert_eq!(
        keys,
        vec![
            "archiveOnlyCount",
            "continuationCount",
            "manualInterventionCount",
            "nativeIdentityCount",
            "sourceHashesDigest",
            "status",
            "targetHashesDigest",
        ]
    );
}
