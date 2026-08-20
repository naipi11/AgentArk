use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn probe_codex_is_read_only_and_json_sanitized() {
    let dir = tempdir().unwrap();
    Command::cargo_bin("agentark")
        .unwrap()
        .args(["--json", "--data-dir"])
        .arg(dir.path())
        .args(["probe", "codex"])
        .assert()
        .success()
        .stdout(predicate::str::contains("codex"))
        .stdout(predicate::str::contains("schemaVersion"))
        .stdout(predicate::str::contains("thread/start").not());
}
