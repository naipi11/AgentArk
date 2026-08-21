use std::fs;

use agentark_adapter_claude::ClaudeCodeAdapter;
use agentark_adapter_sdk::assert_source_adapter_contract;
use tempfile::tempdir;

#[test]
fn claude_adapter_satisfies_source_contract() {
    let root = tempdir().unwrap();
    let projects = root.path().join("projects").join("C--Users-test-project");
    fs::create_dir_all(&projects).unwrap();
    fs::write(
        projects.join("session-1.jsonl"),
        concat!(
            "{\"type\":\"user\",\"sessionId\":\"session-1\",\"cwd\":\"C:\\\\project\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n",
            "{\"type\":\"assistant\",\"sessionId\":\"session-1\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"world\"}]}}\n"
        ),
    )
    .unwrap();
    let adapter = ClaudeCodeAdapter::new(root.path()).unwrap();
    let report = assert_source_adapter_contract(&adapter).unwrap();
    assert_eq!(report.normalized, 1);
}
