#![cfg(windows)]

use std::fs;
use std::time::{Duration, Instant};

use agentark_adapter_codex::{CodexError, ProcessTransport, ReadOnlyAppServerClient};
use tempfile::tempdir;

fn pipe_holding_cmd() -> (tempfile::TempDir, std::path::PathBuf) {
    let root = tempdir().unwrap();
    let shim = root.path().join("silent-app-server.cmd");
    fs::write(
        &shim,
        b"@echo off\r\npowershell.exe -NoLogo -NoProfile -NonInteractive -Command \"Start-Sleep -Seconds 30\"\r\n",
    )
    .unwrap();
    (root, shim)
}

#[test]
fn silent_process_times_out_and_closes_owned_reader_within_bound() {
    let (_root, shim) = pipe_holding_cmd();
    let mut transport = ProcessTransport::spawn(&shim).unwrap();
    let started = Instant::now();
    let mut client =
        ReadOnlyAppServerClient::with_request_timeout(&mut transport, Duration::from_millis(150));

    let error = client.initialize().unwrap_err();

    assert!(matches!(error, CodexError::AppServerRequestTimeout));
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn drop_terminates_cmd_descendant_that_holds_stdout_before_joining_reader() {
    let (_root, shim) = pipe_holding_cmd();
    let transport = ProcessTransport::spawn(&shim).unwrap();
    let started = Instant::now();

    drop(transport);

    assert!(started.elapsed() < Duration::from_secs(5));
}
