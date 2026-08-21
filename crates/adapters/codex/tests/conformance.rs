use std::fs;

use agentark_adapter_codex::CodexAdapter;
use agentark_adapter_sdk::assert_source_adapter_contract;
use tempfile::tempdir;

#[test]
fn codex_filesystem_adapter_meets_read_only_contract() {
    let root = tempdir().unwrap();
    fs::create_dir_all(root.path().join("sessions")).unwrap();
    fs::write(
        root.path().join("sessions/thread_fixture.jsonl"),
        include_bytes!("../../../../fixtures/codex/app-server/thread-read-visible.json"),
    )
    .unwrap();
    let before = CodexAdapter::tree_digest(root.path()).unwrap();
    let report = assert_source_adapter_contract(&CodexAdapter::new(root.path()).unwrap()).unwrap();
    let after = CodexAdapter::tree_digest(root.path()).unwrap();
    assert_eq!(before, after);
    assert_eq!(report.normalized, 0);
    assert_eq!(report.quarantined, 1);
}
