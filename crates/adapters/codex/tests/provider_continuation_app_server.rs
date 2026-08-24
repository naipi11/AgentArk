use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

use agentark_adapter_codex::{
    CodexContinuationRequest, build_canonical_continuation_source,
    delete_thread_with_app_server_guarded, fork_rollout_with_target_provider_guarded,
    probe_target_default,
};
use agentark_canonical::{
    CanonicalMessage, CanonicalRole, CanonicalSchemaVersion, CanonicalSession, Completeness,
    ContentPart, ContentPartKind, Sha256Digest, Workspace,
};
use tempfile::tempdir;
use uuid::Uuid;

#[test]
#[ignore = "non-billed; requires compatible Codex and uses only generated data in a temporary CODEX_HOME"]
fn generated_canonical_history_forks_survives_restart_and_deletes_exact_target() {
    let executable = env::var_os("AGENTARK_CODEX_BIN")
        .map(PathBuf::from)
        .expect("AGENTARK_CODEX_BIN");
    let root = tempdir().unwrap();
    let codex_home = root.path().join("codex");
    let sessions = codex_home.join("sessions").join("2026/08/23");
    let target_cwd = root.path().join("project");
    fs::create_dir_all(&sessions).unwrap();
    fs::create_dir_all(&target_cwd).unwrap();
    let target_default = probe_target_default(&executable, &codex_home).unwrap();
    let session = canonical_fixture(&target_cwd);
    let source = build_canonical_continuation_source(
        &session,
        &target_cwd,
        &target_default.model_provider,
        &target_default.model,
    )
    .unwrap();
    let source_rollout = sessions.join(format!("rollout-{}.jsonl", source.thread_id));
    fs::write(&source_rollout, &source.bytes).unwrap();
    let request = CodexContinuationRequest {
        source_rollout: source_rollout.clone(),
        source_thread_id: source.thread_id,
        target_cwd: target_cwd.clone(),
        target_provider: Some(target_default.model_provider.clone()),
        target_model: Some(target_default.model.clone()),
        title: source.title.clone(),
        visible_history: source.visible_history.expectation(),
    };

    // This generated-data gate isolates the App Server protocol, deadline,
    // restart, and deletion proof. Production process guarding is exercised
    // separately by the Task 11A process-guard suite.
    let allow_test_owned_app_server = |_excluded_process_ids: &[u32]| Ok(());
    let report = fork_rollout_with_target_provider_guarded(
        &executable,
        &codex_home,
        &request,
        &allow_test_owned_app_server,
    )
    .unwrap();

    assert_ne!(report.source_thread_id, report.target_thread_id);
    assert_eq!(report.model_provider, target_default.model_provider);
    assert_eq!(report.model, target_default.model);
    assert_eq!(report.visible_history, request.visible_history);
    assert_eq!(
        report.rollout_hash,
        Sha256Digest::from_bytes(&fs::read(&report.rollout_path).unwrap())
    );
    assert!(source_rollout.is_file());

    delete_thread_with_app_server_guarded(
        &executable,
        &codex_home,
        &report.target_thread_id,
        &allow_test_owned_app_server,
    )
    .unwrap();

    assert!(source_rollout.is_file());
    assert!(!report.rollout_path.exists());
}

#[test]
fn continuation_target_cwd_is_scoped_to_fixture_tempdir() {
    let root = tempdir().unwrap();
    let target_cwd = root.path().join("project");
    fs::create_dir(&target_cwd).unwrap();
    assert!(target_cwd.starts_with(root.path()));
    assert!(target_cwd.is_dir());
}

fn canonical_fixture(target_cwd: &std::path::Path) -> CanonicalSession {
    let session_id = Uuid::from_u128(0x9001);
    CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id: session_id,
        install_id: Uuid::from_u128(0x9002),
        source_session_id: "synthetic-source".into(),
        source_kind: "codex".into(),
        workspace: Some(Workspace {
            id: Uuid::from_u128(0x9003),
            path_native: target_cwd.to_string_lossy().into_owned(),
            canonical_uri: format!("file://{}", target_cwd.to_string_lossy().replace('\\', "/")),
            git_commit: None,
        }),
        title: Some("Synthetic canonical continuation".into()),
        archived: false,
        created_at_raw: None,
        updated_at_raw: None,
        model_provider: Some("legacy-provider".into()),
        model_name: Some("legacy-model".into()),
        completeness: Completeness::Complete,
        messages: vec![
            visible_message(session_id, 1, CanonicalRole::User, "synthetic user message"),
            visible_message(
                session_id,
                2,
                CanonicalRole::Assistant,
                "synthetic assistant message",
            ),
        ],
        tool_events: Vec::new(),
        attachments: Vec::new(),
        raw_extra: BTreeMap::new(),
    }
}

fn visible_message(
    session_id: Uuid,
    ordinal: u64,
    role: CanonicalRole,
    text: &str,
) -> CanonicalMessage {
    CanonicalMessage {
        id: Uuid::new_v5(&session_id, format!("message-{ordinal}").as_bytes()),
        source_record_id: Some(format!("synthetic-{ordinal}")),
        ordinal,
        role,
        raw_role: None,
        created_at_raw: None,
        content: vec![ContentPart {
            kind: ContentPartKind::Text,
            text: Some(text.into()),
            attachment_id: None,
            raw_extra: BTreeMap::new(),
        }],
        raw_ref: Sha256Digest::from_bytes(text.as_bytes()),
    }
}
