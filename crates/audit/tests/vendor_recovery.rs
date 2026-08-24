use std::fs;

use agentark_audit::{AuditEvent, VendorRecoveryAudit, VendorRecoveryStatus, verify_chain};
use agentark_canonical::Sha256Digest;
use tempfile::tempdir;

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
fn fixed_pre_vendor_recovery_chain_rehashes_and_verifies_unchanged() {
    const LEGACY_CHAIN: &str = concat!(
        r#"{"eventId":"00000000-0000-0000-0000-000000000001","eventType":"bundle.restored","timestamp":"2026-08-23T00:00:00Z","actor":"agentark-desktop","source":"legacy.ahbundle","target":null,"beforeHash":null,"afterHash":null,"planHash":null,"result":"success","providerLabels":["openai"],"previousHash":null,"eventHash":"sha256:77b250aa0ead12edb04fb70558f5920eecc7f32e46312b1e90e8247ddb3f727c"}"#,
        "\n",
        r#"{"eventId":"00000000-0000-0000-0000-000000000002","eventType":"migration.completed","timestamp":"2026-08-23T00:00:01Z","actor":"agentark-desktop","source":null,"target":"00000000-0000-0000-0000-000000000003","beforeHash":null,"afterHash":null,"planHash":null,"result":"partial","previousHash":"sha256:77b250aa0ead12edb04fb70558f5920eecc7f32e46312b1e90e8247ddb3f727c","eventHash":"sha256:d6dd1e4d441813db0828daef20937d8e4d4a42004799f5c1c48236992287aa9d"}"#,
        "\n",
    );
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    fs::write(&path, LEGACY_CHAIN).unwrap();

    let events = LEGACY_CHAIN
        .lines()
        .map(|line| serde_json::from_str::<AuditEvent>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(events.iter().all(|event| event.vendor_recovery.is_none()));
    let verification = verify_chain(&path).unwrap();
    assert!(verification.valid, "{:?}", verification.error);
    assert_eq!(verification.event_count, 2);
    assert_eq!(
        verification.last_hash.unwrap().as_str(),
        "sha256:d6dd1e4d441813db0828daef20937d8e4d4a42004799f5c1c48236992287aa9d"
    );
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
