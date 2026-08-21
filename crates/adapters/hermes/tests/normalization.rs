use agentark_adapter_hermes::HermesAdapter;
use agentark_adapter_sdk::{CaptureRequest, DetectContext, NormalizeOutcome, SourceAdapter};
use rusqlite::Connection;
use tempfile::tempdir;

#[test]
fn normalizes_hermes_messages_and_tool_rows() {
    let root = tempdir().unwrap();
    let connection = Connection::open(root.path().join("state.db")).unwrap();
    connection.execute_batch("CREATE TABLE sessions(id TEXT PRIMARY KEY, source TEXT NOT NULL, title TEXT, display_name TEXT, model TEXT, cwd TEXT, git_repo_root TEXT, git_branch TEXT, started_at REAL, ended_at REAL); CREATE TABLE messages(id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, role TEXT, content TEXT, tool_calls TEXT, tool_name TEXT, timestamp REAL); INSERT INTO sessions VALUES ('s1','cli','title',NULL,'m','C:/project',NULL,NULL,1,2); INSERT INTO messages VALUES (1,'s1','user','ask',NULL,NULL,1),(2,'s1','assistant','answer',NULL,NULL,2),(3,'s1','tool','result',NULL,'shell',3);").unwrap();
    let adapter = HermesAdapter::new(root.path()).unwrap();
    let install = adapter
        .detect(&DetectContext {
            explicit_roots: Vec::new(),
            allow_detected_home: false,
        })
        .unwrap()
        .pop()
        .unwrap();
    let batch = adapter
        .capture(&CaptureRequest {
            install,
            snapshot_hint: None,
        })
        .unwrap();
    let session = match adapter.normalize(&batch.records[0]).unwrap() {
        NormalizeOutcome::Normalized(session) => session,
        other => panic!("unexpected outcome: {other:?}"),
    };
    assert_eq!(session.messages.len(), 2);
    assert_eq!(session.tool_events.len(), 1);
    assert_eq!(session.title.as_deref(), Some("title"));
}
