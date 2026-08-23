use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::Value;

use crate::{CodexError, JsonRpcTransport, MAX_JSON_LINE, RawJsonRpc};

pub struct ProcessTransport {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl ProcessTransport {
    pub(crate) fn process_id(&self) -> u32 {
        self.child.id()
    }

    pub fn spawn(executable: &Path) -> Result<Self, CodexError> {
        Self::spawn_with_codex_home(executable, None)
    }

    pub fn spawn_with_codex_home(
        executable: &Path,
        codex_home: Option<&Path>,
    ) -> Result<Self, CodexError> {
        let mut command = Command::new(executable);
        command
            .args([
                "app-server",
                "-c",
                "analytics.enabled=false",
                "--listen",
                "stdio://",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(codex_home) = codex_home {
            command.env("CODEX_HOME", codex_home);
        }
        let mut child = command.spawn()?;
        let stdin = child.stdin.take().ok_or(CodexError::InvalidOutput)?;
        let stdout = child.stdout.take().ok_or(CodexError::InvalidOutput)?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }
}

impl JsonRpcTransport for ProcessTransport {
    fn send_value(&mut self, value: &Value) -> Result<(), CodexError> {
        let mut bytes = serde_json::to_vec(value).map_err(|_| CodexError::MalformedJson)?;
        if bytes.len() > MAX_JSON_LINE {
            return Err(CodexError::OversizedLine);
        }
        bytes.push(b'\n');
        self.stdin.write_all(&bytes)?;
        self.stdin.flush()?;
        Ok(())
    }

    fn receive_value(&mut self) -> Result<RawJsonRpc, CodexError> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            let read = self.stdout.read(&mut byte)?;
            if read == 0 {
                if bytes.is_empty() {
                    return Err(CodexError::EndOfStream);
                }
                break;
            }
            if byte[0] == b'\n' {
                break;
            }
            bytes.push(byte[0]);
            if bytes.len() > MAX_JSON_LINE {
                return Err(CodexError::OversizedLine);
            }
        }
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        let value = serde_json::from_slice(&bytes).map_err(|_| CodexError::MalformedJson)?;
        Ok(RawJsonRpc { bytes, value })
    }
}

impl Drop for ProcessTransport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
