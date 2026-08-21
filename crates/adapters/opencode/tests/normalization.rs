use agentark_adapter_opencode::OpenCodeAdapter;
use agentark_adapter_sdk::{CaptureRequest, DetectContext, NormalizeOutcome, SourceAdapter};
use rusqlite::Connection;
use tempfile::tempdir;

#[test]
fn normalizes_opencode_json_data_and_tool_parts() {
    let root = tempdir().unwrap();
    let connection = Connection::open(root.path().join("opencode.db")).unwrap();
    connection.execute_batch("CREATE TABLE session(id TEXT PRIMARY KEY, project_id TEXT, directory TEXT, title TEXT, version TEXT, time_created INTEGER, time_updated INTEGER, model TEXT); CREATE TABLE message(id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER, data TEXT NOT NULL); CREATE TABLE part(id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, data TEXT NOT NULL); INSERT INTO session VALUES ('ses_1','proj_1','C:/project','title','1.0',1,4,'{\"providerID\":\"openai\",\"id\":\"gpt\"}'); INSERT INTO message VALUES ('msg_1','ses_1',1,'{\"role\":\"user\"}'),('msg_2','ses_1',2,'{\"role\":\"assistant\"}'); INSERT INTO part VALUES ('prt_1','msg_1','ses_1','{\"type\":\"text\",\"text\":\"hello\"}'),('prt_2','msg_2','ses_1','{\"type\":\"tool\",\"tool\":\"shell\",\"state\":{\"status\":\"completed\",\"output\":\"ok\"}}');").unwrap();
    let adapter = OpenCodeAdapter::new(root.path()).unwrap();
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
    assert_eq!(session.messages[0].visible_text(), "hello");
    assert_eq!(session.tool_events.len(), 1);
    assert_eq!(session.model_provider.as_deref(), Some("openai"));
}
