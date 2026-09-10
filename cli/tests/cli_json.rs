use std::fs;

use agentark_bundle::{BundleEntry, write_entries};
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

fn bundle_error(path: &std::path::Path, expected_code: &str, expected_exit: i32) {
    let output = Command::cargo_bin("agentark")
        .unwrap()
        .args(["--json", "bundle", "verify"])
        .arg(path)
        .assert()
        .code(expected_exit)
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["ok"], false);
    assert_eq!(value["command"], "bundle.verify");
    assert_eq!(value["error"]["code"], expected_code);
    assert!(value["error"]["message"].as_str().is_some());
}

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

#[test]
fn bundle_verify_reports_a_stable_code_for_an_unreadable_file() {
    let dir = tempdir().unwrap();
    bundle_error(
        &dir.path().join("missing.ahbundle"),
        "bundle-file-unreadable",
        5,
    );
}

#[test]
fn bundle_verify_reports_a_stable_code_for_integrity_failure() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("corrupted.ahbundle");
    write_entries(
        &path,
        vec![BundleEntry {
            path: "notes/session.txt".into(),
            bytes: b"portable history".to_vec(),
        }],
        0,
        0,
    )
    .unwrap();
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 0x01;
    fs::write(&path, bytes).unwrap();

    bundle_error(&path, "bundle-integrity-check-failed", 4);
}

#[test]
fn bundle_verify_reports_a_stable_code_for_an_invalid_format() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("invalid.ahbundle");
    fs::write(&path, b"not-an-agentark-bundle").unwrap();

    bundle_error(&path, "bundle-invalid-format", 2);
}

#[test]
fn bundle_verify_reports_a_stable_code_for_malformed_session_records() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("malformed-session.ahbundle");
    write_entries(
        &path,
        vec![BundleEntry {
            path: "sessions/session.ndjson".into(),
            bytes: b"not-json\n".to_vec(),
        }],
        1,
        0,
    )
    .unwrap();

    bundle_error(&path, "bundle-invalid-format", 2);
}

#[test]
fn bundle_restore_reports_bundle_errors_before_opening_the_dataset() {
    let dir = tempdir().unwrap();
    let output = Command::cargo_bin("agentark")
        .unwrap()
        .args(["--json", "--data-dir"])
        .arg(dir.path().join("dataset"))
        .args(["bundle", "restore"])
        .arg(dir.path().join("missing.ahbundle"))
        .assert()
        .code(5)
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["error"]["code"], "bundle-file-unreadable");
    assert!(!dir.path().join("dataset").exists());
}
