use agentark_adapter_grok::GrokBuildAdapter;
use agentark_adapter_sdk::assert_source_adapter_contract;
use serde_json::json;
use tempfile::tempdir;

fn fixture() -> tempfile::TempDir {
    let root = tempdir().unwrap();
    let session = root.path().join("sessions/cwd/session-1");
    std::fs::create_dir_all(&session).unwrap();
    std::fs::write(session.join("summary.json"), serde_json::to_vec(&json!({"info":{"sessionId":"session-1","cwd":"C:/project"},"generated_title":"title","created_at":"1","updated_at":"2"})).unwrap()).unwrap();
    std::fs::write(session.join("updates.jsonl"), r#"{"sessionUpdate":"user_message_chunk","content":{"text":"hello"}}\n{"sessionUpdate":"agent_message_chunk","content":{"text":"world"}}\n"#).unwrap();
    root
}

#[test]
fn grok_adapter_satisfies_source_contract() {
    let root = fixture();
    let adapter = GrokBuildAdapter::new(root.path()).unwrap();
    let report = assert_source_adapter_contract(&adapter).unwrap();
    assert_eq!(report.normalized, 1);
}
