use agentark_adapter_sdk::assert_source_adapter_contract;
use agentark_adapter_hermes::HermesAdapter;
use rusqlite::Connection;
use tempfile::tempdir;

fn fixture() -> tempfile::TempDir {
    let root = tempdir().unwrap();
    let connection = Connection::open(root.path().join("state.db")).unwrap();
    connection.execute_batch("CREATE TABLE sessions(id TEXT PRIMARY KEY, source TEXT NOT NULL, title TEXT, display_name TEXT, model TEXT, cwd TEXT, git_repo_root TEXT, git_branch TEXT, started_at REAL, ended_at REAL); CREATE TABLE messages(id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, role TEXT, content TEXT, tool_calls TEXT, tool_name TEXT, timestamp REAL); INSERT INTO sessions VALUES ('s1','cli','title',NULL,'m','C:/project',NULL,NULL,1,2); INSERT INTO messages VALUES (1,'s1','user','ask',NULL,NULL,1);").unwrap();
    root
}

#[test]
fn hermes_adapter_satisfies_source_contract() {
    let root = fixture();
    let adapter = HermesAdapter::new(root.path()).unwrap();
    let report = assert_source_adapter_contract(&adapter).unwrap();
    assert_eq!(report.normalized, 1);
}
