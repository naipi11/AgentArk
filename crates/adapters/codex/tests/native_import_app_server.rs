use std::env;
use std::fs;
use std::path::Path;

use agentark_adapter_codex::{
    native_thread_expectation, sanitize_rollout_bytes, verify_rollout_with_app_server,
};
use agentark_security::SecretScanner;
use tempfile::tempdir;

#[test]
#[ignore = "requires a locally installed compatible Codex executable and rollout fixture"]
fn copied_native_rollout_is_visible_after_app_server_restart() {
    let executable = env::var_os("AGENTARK_CODEX_BIN").expect("AGENTARK_CODEX_BIN");
    let fixture =
        env::var_os("AGENTARK_CODEX_ROLLOUT_FIXTURE").expect("AGENTARK_CODEX_ROLLOUT_FIXTURE");
    let fixture = Path::new(&fixture);
    let root = tempdir().unwrap();
    let target_home = root.path().join("codex");
    let rollout = target_home
        .join("sessions")
        .join("2026")
        .join("08")
        .join("23")
        .join(fixture.file_name().unwrap());
    fs::create_dir_all(rollout.parent().unwrap()).unwrap();
    fs::copy(fixture, &rollout).unwrap();
    let bytes = fs::read(&rollout).unwrap();
    let expected = native_thread_expectation(&bytes).unwrap();
    verify_rollout_with_app_server(Path::new(&executable), &target_home, &rollout, &expected)
        .unwrap();
}

#[test]
#[ignore = "requires a locally installed compatible Codex executable and rollout fixture"]
fn sanitized_native_rollout_is_visible_after_app_server_restart() {
    let executable = env::var_os("AGENTARK_CODEX_BIN").expect("AGENTARK_CODEX_BIN");
    let fixture =
        env::var_os("AGENTARK_CODEX_ROLLOUT_FIXTURE").expect("AGENTARK_CODEX_ROLLOUT_FIXTURE");
    let fixture = Path::new(&fixture);
    let source = fs::read(fixture).unwrap();
    let scanner = SecretScanner::v1().unwrap();
    let (sanitized, _) = sanitize_rollout_bytes(&source, &scanner).unwrap();
    let root = tempdir().unwrap();
    let target_home = root.path().join("codex");
    let rollout = target_home
        .join("sessions")
        .join("2026")
        .join("08")
        .join("23")
        .join(fixture.file_name().unwrap());
    fs::create_dir_all(rollout.parent().unwrap()).unwrap();
    fs::write(&rollout, sanitized).unwrap();
    let bytes = fs::read(&rollout).unwrap();
    let expected = native_thread_expectation(&bytes).unwrap();
    verify_rollout_with_app_server(Path::new(&executable), &target_home, &rollout, &expected)
        .unwrap();
}
