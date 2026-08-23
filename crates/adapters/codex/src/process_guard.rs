use std::collections::{HashMap, HashSet, VecDeque};

use serde::Deserialize;

use crate::NativeImportError;

const PROCESS_SNAPSHOT_UNAVAILABLE: &str = "Codex process snapshot is unavailable";

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct ProcessSnapshotRow {
    name: String,
    process_id: u32,
    parent_process_id: u32,
    command_line: Option<String>,
}

pub fn ensure_codex_not_running_from_snapshot(output: &str) -> Result<(), NativeImportError> {
    ensure_codex_not_running_from_snapshot_excluding(output, &[])
}

#[doc(hidden)]
pub fn ensure_codex_not_running_from_snapshot_excluding(
    output: &str,
    excluded_process_ids: &[u32],
) -> Result<(), NativeImportError> {
    classify_process_snapshot(output, excluded_process_ids)
}

fn classify_process_snapshot(
    output: &str,
    excluded_process_ids: &[u32],
) -> Result<(), NativeImportError> {
    let rows: Vec<ProcessSnapshotRow> =
        serde_json::from_str(output).map_err(|_| snapshot_unavailable())?;
    if rows.is_empty() {
        return Err(snapshot_unavailable());
    }
    if excluded_process_ids.contains(&0) {
        return Err(snapshot_unavailable());
    }
    let mut seen = HashSet::new();
    for row in &rows {
        if row.process_id == 0
            || row.process_id == row.parent_process_id
            || row.name.trim().is_empty()
            || !seen.insert(row.process_id)
        {
            return Err(snapshot_unavailable());
        }
    }
    let mut children = HashMap::<u32, Vec<u32>>::new();
    for row in &rows {
        children
            .entry(row.parent_process_id)
            .or_default()
            .push(row.process_id);
    }
    let mut excluded = excluded_process_ids.iter().copied().collect::<HashSet<_>>();
    let mut pending = excluded_process_ids
        .iter()
        .copied()
        .collect::<VecDeque<_>>();
    while let Some(parent) = pending.pop_front() {
        for child in children.get(&parent).into_iter().flatten() {
            if excluded.insert(*child) {
                pending.push_back(*child);
            }
        }
    }
    for row in rows {
        if excluded.contains(&row.process_id) {
            continue;
        }
        let name = row.name.trim().to_ascii_lowercase();
        if is_direct_codex_executable(&name) {
            return Err(NativeImportError::CodexRunning);
        }
        if !is_command_host(&name) {
            continue;
        }
        let command_line = row
            .command_line
            .as_deref()
            .ok_or_else(snapshot_unavailable)?;
        if command_line.trim().is_empty() {
            return Err(snapshot_unavailable());
        }
        if command_line_runs_codex(&name, command_line)? {
            return Err(NativeImportError::CodexRunning);
        }
    }
    Ok(())
}

fn is_direct_codex_executable(name: &str) -> bool {
    matches!(
        name,
        "codex.exe" | "codex-cli.exe" | "codex-desktop.exe" | "codexdesktop.exe"
    )
}

fn is_command_host(name: &str) -> bool {
    matches!(
        name,
        "cmd.exe" | "powershell.exe" | "pwsh.exe" | "node.exe" | "npm.exe" | "npx.exe"
    )
}

fn command_line_runs_codex(host: &str, command_line: &str) -> Result<bool, NativeImportError> {
    let tokens = command_line_tokens(command_line, matches!(host, "powershell.exe" | "pwsh.exe"))
        .ok_or_else(snapshot_unavailable)?;
    if matches!(host, "cmd.exe")
        && tokens.iter().any(|token| {
            matches!(
                token_basename(token).as_str(),
                "codex.cmd" | "codex.opencodex-real.cmd"
            )
        })
    {
        return Ok(true);
    }
    if matches!(host, "powershell.exe" | "pwsh.exe")
        && tokens
            .iter()
            .any(|token| token_basename(token) == "codex.ps1")
    {
        return Ok(true);
    }
    if matches!(host, "node.exe") && tokens.iter().any(|token| is_codex_node_entrypoint(token)) {
        return Ok(true);
    }
    Ok(tokens.iter().any(|token| is_npm_launcher(token))
        && tokens.iter().any(|token| is_codex_package(token)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QuoteMode {
    Unquoted,
    Double,
    PowerShellSingle,
}

fn command_line_tokens(command_line: &str, powershell_quotes: bool) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote_mode = QuoteMode::Unquoted;
    let mut characters = command_line.chars().peekable();
    while let Some(character) = characters.next() {
        match (quote_mode, character) {
            (QuoteMode::Unquoted | QuoteMode::Double, '`') if powershell_quotes => {
                match characters.next()? {
                    '\r' => {
                        if characters.peek() == Some(&'\n') {
                            characters.next();
                        }
                    }
                    '\n' => {}
                    escaped => token.push(escaped),
                }
            }
            (QuoteMode::Unquoted, '"') => quote_mode = QuoteMode::Double,
            (QuoteMode::Double, '"') => quote_mode = QuoteMode::Unquoted,
            (QuoteMode::Unquoted, '\'') if powershell_quotes => {
                quote_mode = QuoteMode::PowerShellSingle;
            }
            (QuoteMode::PowerShellSingle, '\'') if characters.peek() == Some(&'\'') => {
                characters.next();
                token.push('\'');
            }
            (QuoteMode::PowerShellSingle, '\'') => quote_mode = QuoteMode::Unquoted,
            (QuoteMode::Unquoted, character) if character.is_whitespace() => {
                if !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            }
            _ => token.push(character),
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    (quote_mode == QuoteMode::Unquoted).then_some(tokens)
}

fn token_basename(token: &str) -> String {
    token
        .trim_matches(|character: char| matches!(character, '"' | '&' | '(' | ')'))
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn is_codex_node_entrypoint(token: &str) -> bool {
    let components = token
        .trim_matches('"')
        .split(['\\', '/'])
        .filter(|component| !component.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    components.ends_with(&[
        "@openai".into(),
        "codex".into(),
        "bin".into(),
        "codex.js".into(),
    ])
}

fn is_npm_launcher(token: &str) -> bool {
    matches!(
        token_basename(token).as_str(),
        "npm" | "npm.cmd" | "npm.exe" | "npm-cli.js" | "npx" | "npx.cmd" | "npx.exe" | "npx-cli.js"
    )
}

fn is_codex_package(token: &str) -> bool {
    let token = token.trim_matches('"').to_ascii_lowercase();
    let token = token.strip_prefix("--package=").unwrap_or(&token);
    token == "@openai/codex" || token.starts_with("@openai/codex@")
}

fn snapshot_unavailable() -> NativeImportError {
    NativeImportError::Verification(PROCESS_SNAPSHOT_UNAVAILABLE.into())
}

fn ensure_snapshot_execution_succeeded(
    timed_out: bool,
    succeeded: bool,
    stdout_overflowed: bool,
    stderr_overflowed: bool,
) -> Result<(), NativeImportError> {
    if timed_out || !succeeded || stdout_overflowed || stderr_overflowed {
        Err(snapshot_unavailable())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
mod windows {
    use std::io::{self, Read};
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{
        classify_process_snapshot, ensure_snapshot_execution_succeeded, snapshot_unavailable,
    };
    use crate::NativeImportError;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const SNAPSHOT_DEADLINE: Duration = Duration::from_secs(3);
    const MAX_STDOUT_BYTES: usize = 1024 * 1024;
    const MAX_STDERR_BYTES: usize = 64 * 1024;
    const PROCESS_SNAPSHOT_SCRIPT: &str = "$selfPid=$PID; $rows=@(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.ProcessId -ne $selfPid } | Select-Object Name,ProcessId,ParentProcessId,CommandLine); ConvertTo-Json -InputObject @($rows) -Compress -Depth 2";

    pub(super) fn ensure_codex_not_running_excluding(
        excluded_process_ids: &[u32],
    ) -> Result<(), NativeImportError> {
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                PROCESS_SNAPSHOT_SCRIPT,
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| snapshot_unavailable())?;
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(snapshot_unavailable());
        };
        let Some(stderr) = child.stderr.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(snapshot_unavailable());
        };
        let stdout_reader = thread::spawn(move || read_bounded(stdout, MAX_STDOUT_BYTES));
        let stderr_reader = thread::spawn(move || read_bounded(stderr, MAX_STDERR_BYTES));

        let deadline = Instant::now() + SNAPSHOT_DEADLINE;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    drop(stdout_reader);
                    drop(stderr_reader);
                    return ensure_snapshot_execution_succeeded(true, false, false, false);
                }
            }
        };
        let stdout = stdout_reader
            .join()
            .map_err(|_| snapshot_unavailable())?
            .map_err(|_| snapshot_unavailable())?;
        let stderr = stderr_reader
            .join()
            .map_err(|_| snapshot_unavailable())?
            .map_err(|_| snapshot_unavailable())?;
        ensure_snapshot_execution_succeeded(
            false,
            status.success(),
            stdout.overflowed,
            stderr.overflowed,
        )?;
        let output = String::from_utf8(stdout.bytes).map_err(|_| snapshot_unavailable())?;
        classify_process_snapshot(&output, excluded_process_ids)
    }

    struct BoundedOutput {
        bytes: Vec<u8>,
        overflowed: bool,
    }

    fn read_bounded(mut reader: impl Read, limit: usize) -> io::Result<BoundedOutput> {
        let mut bytes = Vec::new();
        let mut overflowed = false;
        let mut chunk = [0u8; 8192];
        loop {
            let read = reader.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            let available = limit.saturating_sub(bytes.len());
            let retained = available.min(read);
            bytes.extend_from_slice(&chunk[..retained]);
            overflowed |= retained != read;
        }
        Ok(BoundedOutput { bytes, overflowed })
    }
}

pub fn ensure_codex_not_running_excluding(
    excluded_process_ids: &[u32],
) -> Result<(), NativeImportError> {
    #[cfg(windows)]
    {
        windows::ensure_codex_not_running_excluding(excluded_process_ids)
    }
    #[cfg(not(windows))]
    {
        let _ = excluded_process_ids;
        Ok(())
    }
}

pub fn ensure_codex_not_running() -> Result<(), NativeImportError> {
    ensure_codex_not_running_excluding(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_nonzero_and_bounded_output_overflow_fail_closed() {
        for (timed_out, succeeded, stdout_overflowed, stderr_overflowed) in [
            (true, false, false, false),
            (false, false, false, false),
            (false, true, true, false),
            (false, true, false, true),
        ] {
            let error = ensure_snapshot_execution_succeeded(
                timed_out,
                succeeded,
                stdout_overflowed,
                stderr_overflowed,
            )
            .unwrap_err();
            assert!(matches!(error, NativeImportError::Verification(_)));
        }
    }
}
