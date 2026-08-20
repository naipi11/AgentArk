use agentark_adapter_sdk::assert_source_adapter_contract;
use agentark_adapter_synthetic::SyntheticAdapter;
use tempfile::tempdir;

#[test]
fn synthetic_adapter_meets_read_only_contract() {
    let root = tempdir().unwrap();
    SyntheticAdapter::write_fixture_set(root.path()).unwrap();
    let before = SyntheticAdapter::tree_digest(root.path()).unwrap();
    let report =
        assert_source_adapter_contract(&SyntheticAdapter::new(root.path()).unwrap()).unwrap();
    let after = SyntheticAdapter::tree_digest(root.path()).unwrap();
    assert_eq!(before, after);
    assert_eq!(report.normalized, 2);
    assert_eq!(report.quarantined, 1);
    assert_eq!(report.retryable, 1);
}
