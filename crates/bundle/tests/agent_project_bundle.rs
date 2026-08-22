use std::collections::BTreeMap;

use agentark_bundle::{
    NativeBundleEntry, ProjectSelection, read_bundle, write_selected_sessions,
    write_selected_sessions_with_native,
};
use agentark_canonical::{
    CanonicalSchemaVersion, CanonicalSession, Completeness, Workspace, workspace_id,
};
use agentark_security::SecretScanner;
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn exports_selected_agent_project_files_without_credentials() {
    let root = tempdir().unwrap();
    std::fs::write(root.path().join("README.md"), "hello project").unwrap();
    std::fs::write(
        root.path().join("auth.json"),
        "{\"token\":\"should-not-export\"}",
    )
    .unwrap();
    let workspace = Workspace {
        id: workspace_id("file:///C:/project"),
        path_native: root.path().to_string_lossy().into_owned(),
        canonical_uri: "file:///C:/project".into(),
        git_commit: None,
    };
    let session = CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id: Uuid::new_v4(),
        install_id: Uuid::new_v4(),
        source_session_id: "s1".into(),
        source_kind: "codex".into(),
        workspace: Some(workspace.clone()),
        title: Some("title".into()),
        archived: false,
        created_at_raw: None,
        updated_at_raw: None,
        model_provider: None,
        model_name: None,
        completeness: Completeness::Complete,
        messages: vec![],
        tool_events: vec![],
        attachments: vec![],
        raw_extra: BTreeMap::new(),
    };
    let bundle_path = root.path().join("export.ahbundle");
    let manifest = write_selected_sessions(
        &bundle_path,
        "codex",
        &[session],
        &[ProjectSelection {
            workspace_id: workspace.id,
            root: root.path().to_path_buf(),
            include_files: true,
            max_file_bytes: 1024 * 1024,
        }],
        &SecretScanner::v1().unwrap(),
    )
    .unwrap();
    assert_eq!(manifest.agent.as_deref(), Some("codex"));
    assert_eq!(manifest.workspace_count, 1);
    let bundle = read_bundle(&bundle_path).unwrap();
    assert!(
        bundle
            .entries
            .keys()
            .any(|path| path.ends_with("/files/README.md"))
    );
    assert!(
        !bundle
            .entries
            .values()
            .any(|bytes| String::from_utf8_lossy(bytes).contains("should-not-export"))
    );
    let files = bundle.workspace_file_entries().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].relative_path, "README.md");
}

#[test]
fn exports_and_reads_native_codex_rollout_payloads() {
    let root = tempdir().unwrap();
    let session = CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id: Uuid::new_v4(),
        install_id: Uuid::new_v4(),
        source_session_id: "s-native".into(),
        source_kind: "codex".into(),
        workspace: None,
        title: Some("native".into()),
        archived: false,
        created_at_raw: None,
        updated_at_raw: None,
        model_provider: None,
        model_name: None,
        completeness: Completeness::Complete,
        messages: vec![],
        tool_events: vec![],
        attachments: vec![],
        raw_extra: BTreeMap::new(),
    };
    let bundle_path = root.path().join("native.ahbundle");
    write_selected_sessions_with_native(
        &bundle_path,
        "codex",
        std::slice::from_ref(&session),
        &[],
        &[NativeBundleEntry {
            session_id: session.id,
            relative_path: "2026/08/23/rollout-native.jsonl".into(),
            bytes: b"{\"type\":\"session_meta\"}\n".to_vec(),
            redaction_count: 0,
        }],
        &SecretScanner::v1().unwrap(),
    )
    .unwrap();
    let bundle = read_bundle(&bundle_path).unwrap();
    let entries = bundle.native_rollout_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].session_id, session.id);
    assert_eq!(entries[0].relative_path, "2026/08/23/rollout-native.jsonl");
}
