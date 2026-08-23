use std::collections::{HashMap, HashSet, VecDeque};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;

use crate::NativeImportError;

const PROCESS_SNAPSHOT_UNAVAILABLE: &str = "Codex process snapshot is unavailable";
const MAX_ENCODED_COMMAND_BYTES: usize = 128 * 1024;
const MAX_DECODED_COMMAND_BYTES: usize = 64 * 1024;
const MAX_POWERSHELL_NESTING: usize = 4;

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
    if matches!(host, "powershell.exe" | "pwsh.exe") {
        let tokens = command_line_tokens(command_line, true).ok_or_else(snapshot_unavailable)?;
        return powershell_argv_runs_codex(&tokens, 0);
    }
    let tokens = command_line_tokens(command_line, false).ok_or_else(snapshot_unavailable)?;
    if matches!(host, "cmd.exe") && cmd_tokens_run_codex(&tokens) {
        return Ok(true);
    }
    if matches!(host, "node.exe") && tokens.iter().any(|token| is_codex_node_entrypoint(token)) {
        return Ok(true);
    }
    Ok(tokens.iter().any(|token| is_npm_launcher(token))
        && tokens.iter().any(|token| is_codex_package(token)))
}

fn powershell_argv_runs_codex(
    tokens: &[String],
    nesting: usize,
) -> Result<bool, NativeImportError> {
    if tokens.is_empty() || nesting > MAX_POWERSHELL_NESTING {
        return Err(snapshot_unavailable());
    }
    let mut index = 1usize;
    while index < tokens.len() {
        let argument = tokens[index].to_ascii_lowercase();
        match argument.as_str() {
            "-file" | "-f" => {
                let script = tokens.get(index + 1).ok_or_else(snapshot_unavailable)?;
                if script == "-" {
                    return Err(snapshot_unavailable());
                }
                return Ok(is_codex_powershell_script(script));
            }
            "-command" | "-c" => {
                let script = tokens.get(index + 1..).ok_or_else(snapshot_unavailable)?;
                if script.is_empty() || script == ["-"] {
                    return Err(snapshot_unavailable());
                }
                return powershell_script_runs_codex(&script.join(" "), nesting);
            }
            "-encodedcommand" | "-enc" | "-e" => {
                if index + 2 != tokens.len() {
                    return Err(snapshot_unavailable());
                }
                let encoded = tokens.get(index + 1).ok_or_else(snapshot_unavailable)?;
                let script = decode_powershell_command(encoded)?;
                return powershell_script_runs_codex(&script, nesting);
            }
            "-nologo" | "-noprofile" | "-noninteractive" | "-noexit" | "-sta" | "-mta" => {
                index += 1;
            }
            "-executionpolicy" | "-ep" | "-inputformat" | "-outputformat" | "-windowstyle"
            | "-workingdirectory" | "-configurationname" => {
                if tokens.get(index + 1).is_none() {
                    return Err(snapshot_unavailable());
                }
                index += 2;
            }
            _ if argument.starts_with('-') => return Err(snapshot_unavailable()),
            _ => return powershell_script_runs_codex(&tokens[index..].join(" "), nesting),
        }
    }
    Ok(false)
}

fn powershell_script_runs_codex(script: &str, nesting: usize) -> Result<bool, NativeImportError> {
    if script.len() > MAX_DECODED_COMMAND_BYTES || nesting > MAX_POWERSHELL_NESTING {
        return Err(snapshot_unavailable());
    }
    for statement in powershell_statements(script).ok_or_else(snapshot_unavailable)? {
        let tokens = command_line_tokens(&statement, true).ok_or_else(snapshot_unavailable)?;
        if powershell_statement_runs_codex(&tokens, nesting)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn powershell_statement_runs_codex(
    tokens: &[String],
    nesting: usize,
) -> Result<bool, NativeImportError> {
    if tokens.is_empty() {
        return Ok(false);
    }
    let mut command_index = 0usize;
    if matches!(tokens[0].as_str(), "&" | ".") {
        command_index = 1;
        if tokens.get(command_index).is_none() {
            return Err(snapshot_unavailable());
        }
    }
    let command = &tokens[command_index];
    if command.starts_with(['$', '(', '{']) {
        return Err(snapshot_unavailable());
    }
    if is_codex_powershell_script(command)
        || is_codex_cmd_script(command)
        || is_codex_node_entrypoint(command)
        || is_direct_codex_executable(&token_basename(command))
    {
        return Ok(true);
    }
    let basename = token_basename(command);
    let arguments = &tokens[command_index + 1..];
    if matches!(basename.as_str(), "start-process" | "start" | "saps") {
        return start_process_runs_codex(arguments, nesting);
    }
    nested_launcher_runs_codex(&basename, arguments, nesting)
}

fn nested_launcher_runs_codex(
    launcher: &str,
    arguments: &[String],
    nesting: usize,
) -> Result<bool, NativeImportError> {
    let mut invocation = Vec::with_capacity(arguments.len() + 1);
    invocation.push(launcher.to_owned());
    invocation.extend(arguments.iter().map(|argument| {
        argument
            .trim_matches(|character| character == ',' || character == ';')
            .to_owned()
    }));
    match launcher {
        "cmd" | "cmd.exe" => Ok(cmd_tokens_run_codex(&invocation)),
        "node" | "node.exe" => Ok(invocation
            .iter()
            .any(|token| is_codex_node_entrypoint(token))
            || (invocation.iter().any(|token| is_npm_launcher(token))
                && invocation.iter().any(|token| is_codex_package(token)))),
        "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" => {
            powershell_argv_runs_codex(&invocation, nesting + 1)
        }
        "npm" | "npm.cmd" | "npm.exe" | "npx" | "npx.cmd" | "npx.exe" => {
            Ok(invocation.iter().any(|token| is_codex_package(token)))
        }
        _ => Ok(false),
    }
}

fn start_process_runs_codex(
    arguments: &[String],
    nesting: usize,
) -> Result<bool, NativeImportError> {
    if arguments.is_empty() {
        return Err(snapshot_unavailable());
    }
    let file_path_index = arguments
        .iter()
        .position(|argument| matches!(argument.to_ascii_lowercase().as_str(), "-filepath" | "-fp"));
    let target_index = match file_path_index {
        Some(index) => index + 1,
        None if !arguments[0].starts_with('-') => 0,
        None => return Err(snapshot_unavailable()),
    };
    let target = arguments
        .get(target_index)
        .ok_or_else(snapshot_unavailable)?;
    if is_codex_powershell_script(target)
        || is_codex_cmd_script(target)
        || is_codex_node_entrypoint(target)
        || is_direct_codex_executable(&token_basename(target))
    {
        return Ok(true);
    }
    let launcher = token_basename(target);
    let mut nested_arguments = Vec::new();
    if let Some(argument_list) = arguments.iter().position(|argument| {
        matches!(
            argument.to_ascii_lowercase().as_str(),
            "-argumentlist" | "-args"
        )
    }) {
        nested_arguments.extend_from_slice(&arguments[argument_list + 1..]);
    } else {
        nested_arguments.extend_from_slice(&arguments[target_index + 1..]);
    }
    nested_launcher_runs_codex(&launcher, &nested_arguments, nesting)
}

fn cmd_tokens_run_codex(tokens: &[String]) -> bool {
    tokens.iter().any(|token| is_codex_cmd_script(token))
}

fn is_codex_cmd_script(token: &str) -> bool {
    matches!(
        token_basename(token).as_str(),
        "codex.cmd" | "codex.opencodex-real.cmd"
    )
}

fn is_codex_powershell_script(token: &str) -> bool {
    token_basename(token) == "codex.ps1"
}

fn powershell_statements(script: &str) -> Option<Vec<String>> {
    let mut statements = Vec::new();
    let mut statement = String::new();
    let mut quote_mode = QuoteMode::Unquoted;
    let mut characters = script.chars().peekable();
    while let Some(character) = characters.next() {
        match (quote_mode, character) {
            (QuoteMode::Unquoted | QuoteMode::Double, '`') => {
                statement.push(character);
                statement.push(characters.next()?);
            }
            (QuoteMode::Unquoted, '"') => {
                quote_mode = QuoteMode::Double;
                statement.push(character);
            }
            (QuoteMode::Double, '"') => {
                quote_mode = QuoteMode::Unquoted;
                statement.push(character);
            }
            (QuoteMode::Unquoted, '\'') => {
                quote_mode = QuoteMode::PowerShellSingle;
                statement.push(character);
            }
            (QuoteMode::PowerShellSingle, '\'') if characters.peek() == Some(&'\'') => {
                statement.push(character);
                statement.push(characters.next()?);
            }
            (QuoteMode::PowerShellSingle, '\'') => {
                quote_mode = QuoteMode::Unquoted;
                statement.push(character);
            }
            (QuoteMode::Unquoted, '#') => {
                for next in characters.by_ref() {
                    if matches!(next, '\r' | '\n') {
                        break;
                    }
                }
                push_powershell_statement(&mut statements, &mut statement);
            }
            (QuoteMode::Unquoted, ';' | '\r' | '\n' | '|') => {
                if matches!(character, '|' | '\r') && characters.peek() == Some(&character) {
                    characters.next();
                }
                push_powershell_statement(&mut statements, &mut statement);
            }
            (QuoteMode::Unquoted, '&') if characters.peek() == Some(&'&') => {
                characters.next();
                push_powershell_statement(&mut statements, &mut statement);
            }
            (QuoteMode::Unquoted, '&') if !statement.trim().is_empty() => {
                push_powershell_statement(&mut statements, &mut statement);
            }
            _ => statement.push(character),
        }
    }
    if quote_mode != QuoteMode::Unquoted {
        return None;
    }
    push_powershell_statement(&mut statements, &mut statement);
    Some(statements)
}

fn push_powershell_statement(statements: &mut Vec<String>, statement: &mut String) {
    let trimmed = statement.trim();
    if !trimmed.is_empty() {
        statements.push(trimmed.to_owned());
    }
    statement.clear();
}

fn decode_powershell_command(encoded: &str) -> Result<String, NativeImportError> {
    if encoded.is_empty() || encoded.len() > MAX_ENCODED_COMMAND_BYTES {
        return Err(snapshot_unavailable());
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| snapshot_unavailable())?;
    if bytes.is_empty() || bytes.len() > MAX_DECODED_COMMAND_BYTES || bytes.len() % 2 != 0 {
        return Err(snapshot_unavailable());
    }
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let script = String::from_utf16(&units).map_err(|_| snapshot_unavailable())?;
    if script.trim().is_empty() || script.contains('\0') {
        return Err(snapshot_unavailable());
    }
    Ok(script)
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

#[cfg(windows)]
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
        let mut command = Command::new("powershell.exe");
        command.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            PROCESS_SNAPSHOT_SCRIPT,
        ]);
        let output = run_bounded_command(
            command,
            SNAPSHOT_DEADLINE,
            MAX_STDOUT_BYTES,
            MAX_STDERR_BYTES,
        )?;
        let output = String::from_utf8(output.stdout).map_err(|_| snapshot_unavailable())?;
        classify_process_snapshot(&output, excluded_process_ids)
    }

    #[derive(Debug)]
    struct BoundedCommandOutput {
        stdout: Vec<u8>,
    }

    fn run_bounded_command(
        mut command: Command,
        deadline: Duration,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<BoundedCommandOutput, NativeImportError> {
        let mut child = command
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
        let stdout_reader = thread::spawn(move || read_bounded(stdout, max_stdout_bytes));
        let stderr_reader = thread::spawn(move || read_bounded(stderr, max_stderr_bytes));

        let deadline = Instant::now() + deadline;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    drop(stdout_reader);
                    drop(stderr_reader);
                    ensure_snapshot_execution_succeeded(true, false, false, false)?;
                    unreachable!("a timed out process snapshot cannot succeed");
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
        Ok(BoundedCommandOutput {
            stdout: stdout.bytes,
        })
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

    #[cfg(test)]
    mod tests {
        use std::thread;

        use tempfile::tempdir;

        use super::*;

        #[test]
        fn bounded_runner_times_out_and_kills_owned_sleeping_powershell() {
            let root = tempdir().unwrap();
            let marker = root.path().join("owned-child-survived.txt");
            let script = format!(
                "Start-Sleep -Milliseconds 600; Set-Content -LiteralPath '{}' -Value survived",
                marker.to_string_lossy().replace('\'', "''")
            );
            let started = Instant::now();

            let error = run_bounded_command(
                powershell_command(&script),
                Duration::from_millis(100),
                64 * 1024,
                64 * 1024,
            )
            .unwrap_err();

            assert!(matches!(error, NativeImportError::Verification(_)));
            assert!(started.elapsed() < Duration::from_secs(5));
            thread::sleep(Duration::from_millis(800));
            assert!(!marker.exists());
        }

        #[test]
        fn bounded_runner_propagates_owned_child_nonzero_exit() {
            let error = run_bounded_command(
                powershell_command("exit 23"),
                Duration::from_secs(5),
                64 * 1024,
                64 * 1024,
            )
            .unwrap_err();

            assert!(matches!(error, NativeImportError::Verification(_)));
        }

        #[test]
        fn bounded_runner_detects_actual_stdout_and_stderr_overflow() {
            for script in [
                "[Console]::Out.Write(('x' * 4096))",
                "[Console]::Error.Write(('x' * 4096))",
            ] {
                let error =
                    run_bounded_command(powershell_command(script), Duration::from_secs(5), 64, 64)
                        .unwrap_err();

                assert!(matches!(error, NativeImportError::Verification(_)));
            }
        }

        fn powershell_command(script: &str) -> Command {
            let mut command = Command::new("powershell.exe");
            command.args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ]);
            command
        }
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
