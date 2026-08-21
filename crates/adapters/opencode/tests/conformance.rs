use agentark_adapter_opencode::OpenCodeAdapter;
use agentark_adapter_sdk::assert_source_adapter_contract;
use rusqlite::Connection;
use tempfile::tempdir;

fn fixture() -> tempfile::TempDir {
    let root = tempdir().unwrap();
    let connection = Connection::open(root.path().join("opencode.db")).unwrap();
    connection.execute_batch("CREATE TABLE session(id TEXT PRIMARY KEY, project_id TEXT, directory TEXT, title TEXT, version TEXT, time_created INTEGER, time_updated INTEGER, model TEXT); CREATE TABLE message(id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER, data TEXT NOT NULL); CREATE TABLE part(id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, data TEXT NOT NULL); INSERT INTO session VALUES ('ses_1','proj_1','C:/project','title','1.0',1,2,'{\"providerID\":\"openai\",\"id\":\"gpt\"}'); INSERT INTO message VALUES ('msg_1','ses_1',1,'{\"role\":\"user\",\"agent\":\"build\"}'); INSERT INTO part VALUES ('prt_1','msg_1','ses_1','{\"type\":\"text\",\"text\":\"hello\"}');").unwrap();
    root
}

#[test]
fn opencode_adapter_satisfies_source_contract() {
    let root = fixture();
    let adapter = OpenCodeAdapter::new(root.path()).unwrap();
    let report = assert_source_adapter_contract(&adapter).unwrap();
    assert_eq!(report.normalized, 1);
}
