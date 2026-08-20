use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn help_lists_only_approved_read_only_commands() {
    Command::cargo_bin("agentark")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("probe"))
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("sessions"))
        .stdout(predicate::str::contains("search"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("delete").not())
        .stdout(predicate::str::contains("import").not());
}

#[test]
fn doctor_json_is_versioned_and_does_not_initialize_storage() {
    let dir = tempdir().unwrap();
    let output = Command::cargo_bin("agentark")
        .unwrap()
        .args(["--json", "--data-dir"])
        .arg(dir.path())
        .arg("doctor")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["ok"], true);
    assert_eq!(value["command"], "doctor");
    assert_eq!(value["data"]["datasetState"], "notInitialized");
    assert!(value["warnings"].as_array().unwrap().is_empty());
    assert!(!dir.path().join("index.db").exists());
}

#[test]
fn scan_requires_explicit_authorization() {
    let dir = tempdir().unwrap();
    Command::cargo_bin("agentark")
        .unwrap()
        .args(["--json", "--data-dir"])
        .arg(dir.path())
        .args(["scan", "codex"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("authorization"));
}
