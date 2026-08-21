use agentark_adapter_openclaw::OpenClawAdapter;
use agentark_adapter_sdk::assert_source_adapter_contract;
use rusqlite::Connection;
use tempfile::tempdir;

fn fixture() -> tempfile::TempDir {
    let root = tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("agents/main/agent")).unwrap();
    let connection =
        Connection::open(root.path().join("agents/main/agent/openclaw-agent.sqlite")).unwrap();
    connection.execute_batch("CREATE TABLE sessions(id TEXT PRIMARY KEY, session_key TEXT, title TEXT, agent_id TEXT, chat_type TEXT, updated_at INTEGER); CREATE TABLE messages(id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT, tool_name TEXT, timestamp INTEGER); INSERT INTO sessions VALUES ('s1','agent:main:main','title','main','direct',2); INSERT INTO messages VALUES (1,'s1','user','ask',NULL,1);").unwrap();
    root
}

#[test]
fn openclaw_adapter_satisfies_source_contract() {
    let root = fixture();
    let adapter = OpenClawAdapter::new(root.path()).unwrap();
    let report = assert_source_adapter_contract(&adapter).unwrap();
    assert_eq!(report.normalized, 1);
}
