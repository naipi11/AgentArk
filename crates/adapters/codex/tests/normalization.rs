use agentark_adapter_codex::{normalize_thread_read, normalize_thread_read_bytes};
use agentark_canonical::{CanonicalRole, Completeness};
use serde_json::json;

#[test]
fn maps_visible_messages_and_command_execution() {
    let visible = normalize_thread_read(include_str!(
        "../../../../fixtures/codex/app-server/thread-read-visible.json"
    ))
    .unwrap();
    assert_eq!(visible.messages[0].role, CanonicalRole::User);
    assert_eq!(visible.messages[1].role, CanonicalRole::Assistant);
    assert!(
        visible
            .tool_events
            .iter()
            .any(|event| event.tool_name == "commandExecution")
    );
}

#[test]
fn excludes_reasoning_text_and_marks_the_session_partial() {
    let reasoning = normalize_thread_read(include_str!(
        "../../../../fixtures/codex/app-server/thread-read-reasoning.json"
    ))
    .unwrap();
    assert!(
        !reasoning
            .messages
            .iter()
            .any(|message| message.visible_text().contains("HiddenReasoningCanary"))
    );
    assert!(
        !reasoning
            .searchable_text()
            .contains("HiddenReasoningCanary")
    );
    assert_eq!(reasoning.completeness, Completeness::Partial);
}

#[test]
fn malformed_json_is_rejected_without_panicking() {
    assert!(normalize_thread_read_bytes(b"not-json\n").is_err());
}

#[test]
fn extracts_workspace_from_thread_metadata() {
    let value = json!({
        "result": {"thread": {
            "id": "thread-project",
            "name": "AgentArk",
            "cwd": "C:\\Users\\test\\AgentArk",
            "gitInfo": {"sha": "abc123"},
            "turns": []
        }}
    });
    let session = normalize_thread_read(&value.to_string()).unwrap();
    let workspace = session.workspace.expect("workspace metadata");
    assert_eq!(workspace.path_native, "C:\\Users\\test\\AgentArk");
    assert_eq!(workspace.git_commit.as_deref(), Some("abc123"));
    assert_eq!(session.title.as_deref(), Some("AgentArk"));
}
