use std::fs;

use agentark_adapter_claude::ClaudeCodeAdapter;
use agentark_adapter_sdk::{CaptureRequest, DetectContext, NormalizeOutcome, SourceAdapter};
use tempfile::tempdir;

#[test]
fn normalizes_claude_user_assistant_and_tool_content() {
    let root = tempdir().unwrap();
    let projects = root.path().join("projects").join("C--Users-test-project");
    fs::create_dir_all(&projects).unwrap();
    fs::write(
        projects.join("session-1.jsonl"),
        concat!(
            "{\"type\":\"user\",\"sessionId\":\"session-1\",\"cwd\":\"C:\\\\project\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n",
            "{\"type\":\"assistant\",\"sessionId\":\"session-1\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"world\"},{\"type\":\"tool_use\",\"name\":\"Bash\",\"input\":{\"command\":\"pwd\"}}]}}\n"
        ),
    )
    .unwrap();
    let adapter = ClaudeCodeAdapter::new(root.path()).unwrap();
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
    let outcome = adapter.normalize(&batch.records[0]).unwrap();
    let session = match outcome {
        NormalizeOutcome::Normalized(session) => session,
        other => panic!("unexpected outcome: {other:?}"),
    };
    assert_eq!(session.messages.len(), 2);
    assert_eq!(session.tool_events.len(), 1);
    assert_eq!(
        session.workspace.as_ref().unwrap().path_native,
        "C:\\project"
    );
}
