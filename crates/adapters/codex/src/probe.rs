use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::{collections::BTreeSet, thread};

use agentark_adapter_sdk::{ProbeReport, SourceCapability};

use crate::CodexError;

pub const CODEX_VERSION: &str = "0.146.0";
pub const CODEX_SCHEMA_SHA256: &str =
    "fcb6b8b329c3436b4af8c5b180b7cb06f05cbcefdf31462aeefa579b0ca99cd";

pub struct CodexProbe;

impl CodexProbe {
    pub fn from_outputs(
        version_output: &str,
        help_output: &str,
    ) -> Result<ProbeReport, CodexError> {
        let executable_version = parse_version(version_output)?;
        let app_server_read = help_output.contains("--listen stdio://");
        let mut capabilities = BTreeSet::new();
        if app_server_read {
            capabilities.insert(SourceCapability::AppServerRead);
        }
        capabilities.insert(SourceCapability::FilesystemRawArchive);
        capabilities.insert(SourceCapability::ArchivedThreads);
        let quarantine_reason = if executable_version == CODEX_VERSION && app_server_read {
            capabilities.insert(SourceCapability::KnownSemanticSchema);
            None
        } else if executable_version != CODEX_VERSION {
            Some("unsupported-codex-version".into())
        } else {
            Some("app-server-stdio-unsupported".into())
        };
        Ok(ProbeReport {
            adapter_id: "codex".into(),
            executable_version,
            schema_fingerprint: format!("sha256:{CODEX_SCHEMA_SHA256}"),
            capabilities,
            quarantine_reason,
        })
    }

    pub fn run(executable: &Path) -> Result<ProbeReport, CodexError> {
        let version = run_bounded(executable, &["--version"])?;
        let help = run_bounded(executable, &["app-server", "--help"])?;
        Self::from_outputs(&version, &help)
    }
}

pub fn parse_version(output: &str) -> Result<String, CodexError> {
    let mut parts = output.split_whitespace();
    if parts.next() != Some("codex-cli") {
        return Err(CodexError::InvalidOutput);
    }
    let version = parts.next().ok_or(CodexError::InvalidOutput)?;
    if !version.split('.').all(|component| {
        !component.is_empty()
            && component
                .chars()
                .all(|character| character.is_ascii_digit())
    }) {
        return Err(CodexError::InvalidOutput);
    }
    Ok(version.to_owned())
}

fn run_bounded(executable: &Path, args: &[&str]) -> Result<String, CodexError> {
    let mut child = Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            let output = child.wait_with_output()?;
            if output.stdout.len() + output.stderr.len() > 64 * 1024 {
                return Err(CodexError::InvalidOutput);
            }
            let mut combined = output.stdout;
            combined.extend_from_slice(&output.stderr);
            return String::from_utf8(combined).map_err(|_| CodexError::InvalidOutput);
        }
        if started.elapsed() >= Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CodexError::Timeout);
        }
        thread::sleep(Duration::from_millis(10));
    }
}
