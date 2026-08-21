use agentark_adapter_openclaw::OpenClawAdapter;
use agentark_adapter_sdk::{CaptureRequest, DetectContext, NormalizeOutcome, SourceAdapter};
use rusqlite::Connection;
use tempfile::tempdir;

#[test]
fn normalizes_openclaw_session_scope_and_tool_events() {
    let root = tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("agents/work/agent")).unwrap();
    let connection =
        Connection::open(root.path().join("agents/work/agent/openclaw-agent.sqlite")).unwrap();
    connection.execute_batch("CREATE TABLE sessions(id TEXT PRIMARY KEY, session_key TEXT, title TEXT, agent_id TEXT, chat_type TEXT, updated_at INTEGER); CREATE TABLE messages(id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT, tool_name TEXT, timestamp INTEGER); INSERT INTO sessions VALUES ('s1','agent:work:main','title','work','group',2); INSERT INTO messages VALUES (1,'s1','user','ask',NULL,1),(2,'s1','assistant','answer',NULL,2),(3,'s1','tool','done','shell',3);").unwrap();
    let adapter = OpenClawAdapter::new(root.path()).unwrap();
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
    assert_eq!(
        session.raw_extra.get("chatType").and_then(|v| v.as_str()),
        Some("group")
    );
}
