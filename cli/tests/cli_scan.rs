use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn codex_probe_fixture(root: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let path = root.join("codex-probe-fixture.cmd");
        fs::write(
            &path,
            concat!(
                "@echo off\r\n",
                "echo %*>>\"%AGENTARK_PROBE_LOG%\"\r\n",
                "if \"%1\"==\"--version\" (\r\n",
                "  echo codex-cli 0.146.0\r\n",
                "  exit /b 0\r\n",
                ")\r\n",
                "if \"%1\"==\"app-server\" (\r\n",
                "  echo --listen stdio://\r\n",
                "  exit /b 0\r\n",
                ")\r\n",
                "exit /b 1\r\n"
            ),
        )
        .unwrap();
        path
    }

    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;

        let path = root.join("codex-probe-fixture");
        fs::write(
            &path,
            concat!(
                "#!/bin/sh\n",
                "printf '%s\\n' \"$*\" >> \"$AGENTARK_PROBE_LOG\"\n",
                "if [ \"$1\" = \"--version\" ]; then\n",
                "  echo 'codex-cli 0.146.0'\n",
                "  exit 0\n",
                "fi\n",
                "if [ \"$1\" = \"app-server\" ] && [ \"$2\" = \"--help\" ]; then\n",
                "  echo '--listen stdio://'\n",
                "  exit 0\n",
                "fi\n",
                "exit 1\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

#[test]
fn probe_codex_is_read_only_and_json_sanitized() {
    let dir = tempdir().unwrap();
    let probe_log = dir.path().join("probe.log");
    let fixture = codex_probe_fixture(dir.path());
    Command::cargo_bin("agentark")
        .unwrap()
        .env("AGENTARK_CODEX_BIN", fixture)
        .env("AGENTARK_PROBE_LOG", &probe_log)
        .args(["--json", "--data-dir"])
        .arg(dir.path())
        .args(["probe", "codex"])
        .assert()
        .success()
        .stdout(predicate::str::contains("codex"))
        .stdout(predicate::str::contains("schemaVersion"))
        .stdout(predicate::str::contains("thread/start").not());
    assert_eq!(
        fs::read_to_string(probe_log)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        ["--version", "app-server --help"]
    );
}
