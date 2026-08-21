use agentark_adapter_grok::GrokBuildAdapter;
use agentark_adapter_sdk::{CaptureRequest, DetectContext, NormalizeOutcome, SourceAdapter};
use serde_json::json;
use tempfile::tempdir;

#[test]
fn normalizes_grok_updates_and_quarantines_malformed_lines() {
    let root = tempdir().unwrap();
    let session = root.path().join("sessions/cwd/session-1");
    std::fs::create_dir_all(&session).unwrap();
    std::fs::write(session.join("summary.json"), serde_json::to_vec(&json!({"info":{"sessionId":"session-1","cwd":"C:/project"},"generated_title":"title","current_model_id":"grok-build","created_at":"1","updated_at":"2"})).unwrap()).unwrap();
    std::fs::write(session.join("updates.jsonl"), "{\"sessionUpdate\":\"user_message_chunk\",\"content\":{\"text\":\"hello\"}}\nnot-json\n{\"sessionUpdate\":\"tool_call\",\"toolName\":\"shell\",\"output\":\"ok\"}\n").unwrap();
    let adapter = GrokBuildAdapter::new(root.path()).unwrap();
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
    assert_eq!(batch.issues.len(), 1);
    let session = match adapter.normalize(&batch.records[0]).unwrap() {
        NormalizeOutcome::Normalized(session) => session,
        other => panic!("unexpected outcome: {other:?}"),
    };
    assert_eq!(session.messages.len(), 1);
    assert_eq!(session.tool_events.len(), 1);
    assert_eq!(session.title.as_deref(), Some("title"));
}
