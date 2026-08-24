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
        if row.name.trim().is_empty() || !seen.insert(row.process_id) {
            return Err(snapshot_unavailable());
        }
        if is_system_idle_process(row) {
            continue;
        }
        if row.process_id == 0 || row.process_id == row.parent_process_id {
            return Err(snapshot_unavailable());
        }
    }
    let mut children = HashMap::<u32, Vec<u32>>::new();
    for row in &rows {
        if is_system_idle_process(row) {
            continue;
        }
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
        if is_system_idle_process(&row) {
            continue;
        }
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

fn is_system_idle_process(row: &ProcessSnapshotRow) -> bool {
    row.name.eq_ignore_ascii_case("System Idle Process")
        && row.process_id == 0
        && row.parent_process_id == 0
        && row.command_line.is_none()
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
    if host == "cmd.exe" {
        return cmd_command_line_runs_codex(command_line, 0);
    }
    let tokens = command_line_tokens(command_line, false).ok_or_else(snapshot_unavailable)?;
    if host == "node.exe" {
        return node_argv_runs_codex(&tokens, 0);
    }
    npm_argv_runs_codex(&tokens)
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
        "cmd" | "cmd.exe" => cmd_argv_runs_codex(&invocation, nesting + 1),
        "node" | "node.exe" => node_argv_runs_codex(&invocation, nesting + 1),
        "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" => {
            powershell_argv_runs_codex(&invocation, nesting + 1)
        }
        "npm" | "npm.cmd" | "npm.exe" | "npm-cli.js" | "npx" | "npx.cmd" | "npx.exe"
        | "npx-cli.js" => npm_argv_runs_codex(&invocation),
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
    if target.trim_start().starts_with(['(', '{', '[', '@']) || target.contains('$') {
        return Err(snapshot_unavailable());
    }
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

fn cmd_command_line_runs_codex(
    command_line: &str,
    nesting: usize,
) -> Result<bool, NativeImportError> {
    let words = cmd_words(command_line).ok_or_else(snapshot_unavailable)?;
    let Some(command_switch) = words
        .iter()
        .position(|word| matches!(word.value.to_ascii_lowercase().as_str(), "/c" | "/k"))
    else {
        return Ok(false);
    };
    let script = strip_cmd_outer_quotes(command_line[words[command_switch].end..].trim_start());
    if script.is_empty() {
        return Err(snapshot_unavailable());
    }
    cmd_script_runs_codex(script, nesting)
}

fn strip_cmd_outer_quotes(script: &str) -> &str {
    script
        .strip_prefix('"')
        .and_then(|script| script.strip_suffix('"'))
        .unwrap_or(script)
}

fn cmd_argv_runs_codex(tokens: &[String], nesting: usize) -> Result<bool, NativeImportError> {
    let Some(command_switch) = tokens
        .iter()
        .position(|token| matches!(token.to_ascii_lowercase().as_str(), "/c" | "/k"))
    else {
        return Ok(false);
    };
    let script = tokens
        .get(command_switch + 1..)
        .ok_or_else(snapshot_unavailable)?;
    if script.is_empty() {
        return Err(snapshot_unavailable());
    }
    cmd_script_runs_codex(&script.join(" "), nesting)
}

fn cmd_script_runs_codex(script: &str, nesting: usize) -> Result<bool, NativeImportError> {
    if nesting > MAX_POWERSHELL_NESTING {
        return Err(snapshot_unavailable());
    }
    for statement in cmd_statements(script).ok_or_else(snapshot_unavailable)? {
        let words = cmd_words(&statement).ok_or_else(snapshot_unavailable)?;
        if cmd_statement_runs_codex(&words, nesting)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn cmd_statement_runs_codex(words: &[CmdWord], nesting: usize) -> Result<bool, NativeImportError> {
    if words.is_empty() {
        return Ok(false);
    }
    let mut command_index = 0usize;
    let mut command = words[command_index].value.trim_start_matches('@');
    if command.eq_ignore_ascii_case("call") {
        command_index += 1;
        command = words
            .get(command_index)
            .map(|word| word.value.trim_start_matches('@'))
            .ok_or_else(snapshot_unavailable)?;
    }
    if command.starts_with(['%', '!', '(']) {
        return Err(snapshot_unavailable());
    }
    let basename = token_basename(command);
    let arguments = &words[command_index + 1..];
    if basename == "start" {
        return cmd_start_runs_codex(arguments, nesting);
    }
    let arguments = arguments
        .iter()
        .map(|word| word.value.clone())
        .collect::<Vec<_>>();
    command_target_runs_codex(command, &arguments, nesting)
}

fn cmd_start_runs_codex(arguments: &[CmdWord], nesting: usize) -> Result<bool, NativeImportError> {
    let mut index = 0usize;
    let mut title_consumed = false;
    while let Some(word) = arguments.get(index) {
        if word.quoted && !title_consumed {
            title_consumed = true;
            index += 1;
            continue;
        }
        let option = word.value.to_ascii_lowercase();
        if !option.starts_with('/') {
            break;
        }
        match option.as_str() {
            "/d" | "/node" | "/affinity" | "/machine" => {
                if arguments.get(index + 1).is_none() {
                    return Err(snapshot_unavailable());
                }
                index += 2;
            }
            "/b" | "/wait" | "/i" | "/min" | "/max" | "/low" | "/normal" | "/high"
            | "/realtime" | "/abovenormal" | "/belownormal" | "/separate" | "/shared" => {
                index += 1;
            }
            _ => return Err(snapshot_unavailable()),
        }
    }
    let target = arguments.get(index).ok_or_else(snapshot_unavailable)?;
    if target.value.starts_with(['%', '!', '(']) {
        return Err(snapshot_unavailable());
    }
    let remaining = arguments[index + 1..]
        .iter()
        .map(|word| word.value.clone())
        .collect::<Vec<_>>();
    command_target_runs_codex(&target.value, &remaining, nesting)
}

fn command_target_runs_codex(
    command: &str,
    arguments: &[String],
    nesting: usize,
) -> Result<bool, NativeImportError> {
    if is_codex_cmd_script(command)
        || is_codex_powershell_script(command)
        || is_codex_node_entrypoint(command)
        || is_direct_codex_executable(&token_basename(command))
    {
        return Ok(true);
    }
    nested_launcher_runs_codex(&token_basename(command), arguments, nesting)
}

struct CmdWord {
    value: String,
    end: usize,
    quoted: bool,
}

fn cmd_words(command_line: &str) -> Option<Vec<CmdWord>> {
    let mut words = Vec::new();
    let mut value = String::new();
    let mut started = false;
    let mut quoted = false;
    let mut word_quoted = false;
    let mut end = 0usize;
    let mut characters = command_line.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        end = index + character.len_utf8();
        match character {
            '^' => {
                let (escaped_index, escaped) = characters.next()?;
                end = escaped_index + escaped.len_utf8();
                started = true;
                if escaped == '\r' {
                    if characters.peek().is_some_and(|(_, next)| *next == '\n') {
                        let (line_feed_index, line_feed) = characters.next()?;
                        end = line_feed_index + line_feed.len_utf8();
                    }
                } else if escaped != '\n' {
                    value.push(escaped);
                }
            }
            '"' => {
                started = true;
                word_quoted = true;
                quoted = !quoted;
            }
            character if character.is_whitespace() && !quoted => {
                if started {
                    words.push(CmdWord {
                        value: std::mem::take(&mut value),
                        end: index,
                        quoted: word_quoted,
                    });
                    started = false;
                    word_quoted = false;
                }
            }
            _ => {
                started = true;
                value.push(character);
            }
        }
    }
    if quoted {
        return None;
    }
    if started {
        words.push(CmdWord {
            value,
            end,
            quoted: word_quoted,
        });
    }
    Some(words)
}

fn cmd_statements(script: &str) -> Option<Vec<String>> {
    let mut statements = Vec::new();
    let mut statement = String::new();
    let mut quoted = false;
    let mut characters = script.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '^' => {
                let escaped = characters.next()?;
                statement.push('^');
                statement.push(escaped);
                if escaped == '\r' && characters.peek() == Some(&'\n') {
                    statement.push(characters.next()?);
                }
            }
            '"' => {
                quoted = !quoted;
                statement.push(character);
            }
            '&' | '|' if !quoted => {
                if characters.peek() == Some(&character) {
                    characters.next();
                }
                push_powershell_statement(&mut statements, &mut statement);
            }
            '\r' | '\n' if !quoted => {
                push_powershell_statement(&mut statements, &mut statement);
            }
            _ => statement.push(character),
        }
    }
    if quoted {
        return None;
    }
    push_powershell_statement(&mut statements, &mut statement);
    Some(statements)
}

fn node_argv_runs_codex(tokens: &[String], nesting: usize) -> Result<bool, NativeImportError> {
    if tokens.is_empty() || nesting > MAX_POWERSHELL_NESTING {
        return Err(snapshot_unavailable());
    }
    let mut index = 1usize;
    while index < tokens.len() {
        let argument = tokens[index].to_ascii_lowercase();
        match argument.as_str() {
            "--" => {
                index += 1;
                break;
            }
            "-r" | "--require" | "--import" => {
                let module = tokens.get(index + 1).ok_or_else(snapshot_unavailable)?;
                if is_codex_node_entrypoint(module) || is_codex_package(module) {
                    return Ok(true);
                }
                index += 2;
            }
            "-e" | "--eval" | "-p" | "--print" => {
                let source = tokens.get(index + 1).ok_or_else(snapshot_unavailable)?;
                return node_eval_runs_codex(source);
            }
            "--input-type" => {
                if tokens.get(index + 1).is_none() {
                    return Err(snapshot_unavailable());
                }
                index += 2;
            }
            _ if argument.starts_with("--input-type=") => {
                if tokens[index]
                    .split_once('=')
                    .is_none_or(|(_, value)| value.is_empty())
                {
                    return Err(snapshot_unavailable());
                }
                index += 1;
            }
            _ if argument.starts_with("--require=") || argument.starts_with("--import=") => {
                let module = tokens[index]
                    .split_once('=')
                    .map(|(_, value)| value)
                    .unwrap_or("");
                if module.is_empty() {
                    return Err(snapshot_unavailable());
                }
                if is_codex_node_entrypoint(module) || is_codex_package(module) {
                    return Ok(true);
                }
                index += 1;
            }
            _ if argument.starts_with("--eval=") || argument.starts_with("--print=") => {
                let source = tokens[index]
                    .split_once('=')
                    .map(|(_, value)| value)
                    .unwrap_or("");
                if source.is_empty() {
                    return Err(snapshot_unavailable());
                }
                return node_eval_runs_codex(source);
            }
            _ if argument.starts_with('-') => index += 1,
            _ => break,
        }
    }
    let Some(script) = tokens.get(index) else {
        return Ok(false);
    };
    if is_codex_node_entrypoint(script) || is_codex_package(script) {
        return Ok(true);
    }
    if is_npm_launcher(script) {
        let mut npm = vec![token_basename(script)];
        npm.extend_from_slice(&tokens[index + 1..]);
        return npm_argv_runs_codex(&npm);
    }
    Ok(false)
}

fn node_eval_runs_codex(source: &str) -> Result<bool, NativeImportError> {
    let characters = source.chars().collect::<Vec<_>>();
    let mut index = 0usize;
    let mut quote = None::<char>;
    while index < characters.len() {
        let character = characters[index];
        if let Some(delimiter) = quote {
            if character == '\\' {
                index = (index + 2).min(characters.len());
                continue;
            }
            if character == delimiter {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(character, '\'' | '"' | '`') {
            quote = Some(character);
            index += 1;
            continue;
        }
        if character == '/' && characters.get(index + 1) == Some(&'/') {
            index += 2;
            while characters
                .get(index)
                .is_some_and(|character| *character != '\n')
            {
                index += 1;
            }
            continue;
        }
        if character == '/' && characters.get(index + 1) == Some(&'*') {
            index += 2;
            let mut closed = false;
            while index + 1 < characters.len() {
                if characters[index] == '*' && characters[index + 1] == '/' {
                    index += 2;
                    closed = true;
                    break;
                }
                index += 1;
            }
            if !closed {
                return Err(snapshot_unavailable());
            }
            continue;
        }
        if character.is_ascii_alphabetic() || character == '_' {
            let start = index;
            while index < characters.len()
                && (characters[index].is_ascii_alphanumeric() || characters[index] == '_')
            {
                index += 1;
            }
            let identifier = characters[start..index].iter().collect::<String>();
            let module = match identifier.as_str() {
                "require" => parse_js_module_call(&characters, &mut index)?,
                "import" => parse_js_import(&characters, &mut index)?,
                _ => None,
            };
            if let Some(module) = module
                && (is_codex_node_entrypoint(&module) || is_codex_package(&module))
            {
                return Ok(true);
            }
            continue;
        }
        index += 1;
    }
    if quote.is_some() {
        return Err(snapshot_unavailable());
    }
    Ok(false)
}

fn parse_js_module_call(
    characters: &[char],
    index: &mut usize,
) -> Result<Option<String>, NativeImportError> {
    skip_js_whitespace(characters, index);
    if characters.get(*index) != Some(&'(') {
        return Ok(None);
    }
    *index += 1;
    skip_js_whitespace(characters, index);
    let module = parse_js_string_literal(characters, index)?;
    skip_js_whitespace(characters, index);
    if characters.get(*index) != Some(&')') {
        return Err(snapshot_unavailable());
    }
    *index += 1;
    Ok(Some(module))
}

fn parse_js_import(
    characters: &[char],
    index: &mut usize,
) -> Result<Option<String>, NativeImportError> {
    skip_js_whitespace(characters, index);
    if characters.get(*index) == Some(&'(') {
        return parse_js_module_call(characters, index);
    }
    if characters
        .get(*index)
        .is_some_and(|character| matches!(character, '\'' | '"'))
    {
        return parse_js_string_literal(characters, index).map(Some);
    }
    while *index < characters.len() {
        if matches!(characters[*index], ';' | '\r' | '\n') {
            return Err(snapshot_unavailable());
        }
        if characters[*index].is_ascii_alphabetic() || characters[*index] == '_' {
            let start = *index;
            while *index < characters.len()
                && (characters[*index].is_ascii_alphanumeric() || characters[*index] == '_')
            {
                *index += 1;
            }
            let identifier = characters[start..*index].iter().collect::<String>();
            if identifier == "from" {
                skip_js_whitespace(characters, index);
                return parse_js_string_literal(characters, index).map(Some);
            }
        } else {
            *index += 1;
        }
    }
    Err(snapshot_unavailable())
}

fn parse_js_string_literal(
    characters: &[char],
    index: &mut usize,
) -> Result<String, NativeImportError> {
    let delimiter = *characters.get(*index).ok_or_else(snapshot_unavailable)?;
    if !matches!(delimiter, '\'' | '"') {
        return Err(snapshot_unavailable());
    }
    *index += 1;
    let mut value = String::new();
    while let Some(character) = characters.get(*index).copied() {
        if character == '\\' {
            let escaped = *characters
                .get(*index + 1)
                .ok_or_else(snapshot_unavailable)?;
            value.push(escaped);
            *index += 2;
        } else if character == delimiter {
            *index += 1;
            return Ok(value);
        } else {
            value.push(character);
            *index += 1;
        }
    }
    Err(snapshot_unavailable())
}

fn skip_js_whitespace(characters: &[char], index: &mut usize) {
    while characters
        .get(*index)
        .is_some_and(|character| character.is_whitespace())
    {
        *index += 1;
    }
}

fn npm_argv_runs_codex(tokens: &[String]) -> Result<bool, NativeImportError> {
    if tokens.is_empty() {
        return Err(snapshot_unavailable());
    }
    let launcher = token_basename(&tokens[0]);
    let is_npx = matches!(
        launcher.as_str(),
        "npx" | "npx.cmd" | "npx.exe" | "npx-cli.js"
    );
    let mut index = 1usize;
    let mut package_option_runs_codex = false;
    while index < tokens.len() && tokens[index].starts_with('-') {
        let option = tokens[index].to_ascii_lowercase();
        match option.as_str() {
            "--" => {
                index += 1;
                break;
            }
            "--package" | "-p" => {
                let package = tokens.get(index + 1).ok_or_else(snapshot_unavailable)?;
                package_option_runs_codex |= is_codex_package(package);
                index += 2;
            }
            "--prefix" | "--workspace" | "-w" | "--registry" | "--userconfig" | "--cache"
            | "--scope" | "--tag" | "--loglevel" => {
                if tokens.get(index + 1).is_none() {
                    return Err(snapshot_unavailable());
                }
                index += 2;
            }
            "--silent"
            | "-s"
            | "--yes"
            | "-y"
            | "--global"
            | "-g"
            | "--workspaces"
            | "--include-workspace-root"
            | "--if-present"
            | "--ignore-scripts"
            | "--foreground-scripts"
            | "--json"
            | "--dry-run"
            | "--force"
            | "--verbose"
            | "-q"
            | "-d"
            | "-dd"
            | "-ddd" => index += 1,
            _ if option.starts_with("--package=") => {
                let package = option
                    .strip_prefix("--package=")
                    .filter(|package| !package.is_empty())
                    .ok_or_else(snapshot_unavailable)?;
                package_option_runs_codex |= is_codex_package(package);
                index += 1;
            }
            _ if npm_value_option_with_equals(&option) => index += 1,
            _ => return Err(snapshot_unavailable()),
        }
    }
    if is_npx {
        let command = tokens.get(index);
        return Ok(package_option_runs_codex
            || command.is_some_and(|command| {
                is_codex_package(command)
                    || matches!(token_basename(command).as_str(), "codex" | "codex.cmd")
            }));
    }
    let Some(subcommand) = tokens
        .get(index)
        .map(|command| command.to_ascii_lowercase())
    else {
        return Ok(false);
    };
    let arguments = &tokens[index + 1..];
    match subcommand.as_str() {
        "exec" | "x" => npm_exec_runs_codex(arguments, package_option_runs_codex),
        "run" | "run-script" => Ok(arguments
            .iter()
            .find(|argument| !argument.starts_with('-'))
            .is_some_and(|script| {
                let script = script.to_ascii_lowercase();
                script == "codex" || script.starts_with("codex:") || is_codex_package(&script)
            })),
        _ => Ok(false),
    }
}

fn npm_value_option_with_equals(option: &str) -> bool {
    [
        "--prefix=",
        "--workspace=",
        "-w=",
        "--registry=",
        "--userconfig=",
        "--cache=",
        "--scope=",
        "--tag=",
        "--loglevel=",
    ]
    .iter()
    .any(|prefix| {
        option
            .strip_prefix(prefix)
            .is_some_and(|value| !value.is_empty())
    })
}

fn npm_exec_runs_codex(
    arguments: &[String],
    mut package_option_runs_codex: bool,
) -> Result<bool, NativeImportError> {
    let mut index = 0usize;
    while index < arguments.len() {
        let argument = arguments[index].to_ascii_lowercase();
        match argument.as_str() {
            "--" => {
                index += 1;
                break;
            }
            "--package" | "-p" => {
                let package = arguments.get(index + 1).ok_or_else(snapshot_unavailable)?;
                package_option_runs_codex |= is_codex_package(package);
                index += 2;
            }
            _ if argument.starts_with("--package=") => {
                package_option_runs_codex |= argument
                    .strip_prefix("--package=")
                    .is_some_and(is_codex_package);
                index += 1;
            }
            "--yes" | "-y" | "--if-present" | "--ignore-scripts" => index += 1,
            _ if argument.starts_with('-') => return Err(snapshot_unavailable()),
            _ => break,
        }
    }
    let command_runs_codex = arguments.get(index).is_some_and(|command| {
        is_codex_package(command)
            || matches!(token_basename(command).as_str(), "codex" | "codex.cmd")
    });
    Ok(package_option_runs_codex || command_runs_codex)
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
mod windows {
    use std::io::{self, Read};
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{classify_process_snapshot, snapshot_unavailable};
    use crate::NativeImportError;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const SNAPSHOT_DEADLINE: Duration = Duration::from_secs(3);
    const MAX_STDOUT_BYTES: usize = 1024 * 1024;
    const MAX_STDERR_BYTES: usize = 64 * 1024;
    const PROCESS_SNAPSHOT_SCRIPT: &str = "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $selfPid=$PID; $rows=@(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.ProcessId -ne $selfPid } | Select-Object Name,ProcessId,ParentProcessId,CommandLine); ConvertTo-Json -InputObject @($rows) -Compress -Depth 2";

    fn decode_process_snapshot(bytes: Vec<u8>) -> Result<String, NativeImportError> {
        String::from_utf8(bytes).map_err(|_| snapshot_unavailable())
    }

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
        let output = decode_process_snapshot(output.stdout)?;
        classify_process_snapshot(&output, excluded_process_ids)
    }

    #[derive(Debug)]
    struct BoundedCommandOutput {
        stdout: Vec<u8>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum BoundedCommandFailure {
        Spawn,
        MissingStdout,
        MissingStderr,
        Poll,
        Kill,
        Wait,
        Timeout,
        StdoutReaderPanic,
        StderrReaderPanic,
        StdoutRead,
        StderrRead,
        NonZero(i32),
        UnknownExit,
        StdoutOverflow,
        StderrOverflow,
    }

    fn run_bounded_command(
        command: Command,
        deadline: Duration,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<BoundedCommandOutput, NativeImportError> {
        run_bounded_command_typed(command, deadline, max_stdout_bytes, max_stderr_bytes)
            .map_err(map_bounded_command_failure)
    }

    fn run_bounded_command_typed(
        mut command: Command,
        deadline: Duration,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<BoundedCommandOutput, BoundedCommandFailure> {
        let mut child = command
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| BoundedCommandFailure::Spawn)?;
        let Some(stdout) = child.stdout.take() else {
            stop_owned_child(&mut child)?;
            return Err(BoundedCommandFailure::MissingStdout);
        };
        let Some(stderr) = child.stderr.take() else {
            stop_owned_child(&mut child)?;
            return Err(BoundedCommandFailure::MissingStderr);
        };
        let stdout_reader = thread::spawn(move || read_bounded(stdout, max_stdout_bytes));
        let stderr_reader = thread::spawn(move || read_bounded(stderr, max_stderr_bytes));

        let deadline = Instant::now() + deadline;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(None) => {
                    stop_owned_child(&mut child)?;
                    drop(stdout_reader);
                    drop(stderr_reader);
                    return Err(BoundedCommandFailure::Timeout);
                }
                Err(_) => {
                    stop_owned_child(&mut child)?;
                    drop(stdout_reader);
                    drop(stderr_reader);
                    return Err(BoundedCommandFailure::Poll);
                }
            }
        };
        let stdout = stdout_reader
            .join()
            .map_err(|_| BoundedCommandFailure::StdoutReaderPanic)?
            .map_err(|_| BoundedCommandFailure::StdoutRead)?;
        let stderr = stderr_reader
            .join()
            .map_err(|_| BoundedCommandFailure::StderrReaderPanic)?
            .map_err(|_| BoundedCommandFailure::StderrRead)?;
        if stdout.overflowed {
            return Err(BoundedCommandFailure::StdoutOverflow);
        }
        if stderr.overflowed {
            return Err(BoundedCommandFailure::StderrOverflow);
        }
        if !status.success() {
            return Err(match status.code() {
                Some(code) => BoundedCommandFailure::NonZero(code),
                None => BoundedCommandFailure::UnknownExit,
            });
        }
        Ok(BoundedCommandOutput {
            stdout: stdout.bytes,
        })
    }

    fn stop_owned_child(child: &mut std::process::Child) -> Result<(), BoundedCommandFailure> {
        child.kill().map_err(|_| BoundedCommandFailure::Kill)?;
        child.wait().map_err(|_| BoundedCommandFailure::Wait)?;
        Ok(())
    }

    fn map_bounded_command_failure(_failure: BoundedCommandFailure) -> NativeImportError {
        snapshot_unavailable()
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
        use std::sync::{Mutex, MutexGuard, OnceLock, mpsc};
        use std::thread;

        use tempfile::tempdir;

        use super::*;

        struct OwnedTestChild(Option<std::process::Child>);

        impl OwnedTestChild {
            fn spawn(command: &mut Command) -> Self {
                Self(Some(command.spawn().unwrap()))
            }

            fn id(&self) -> u32 {
                self.0.as_ref().unwrap().id()
            }
        }

        impl Drop for OwnedTestChild {
            fn drop(&mut self) {
                if let Some(child) = self.0.as_mut() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        fn powershell_test_lock() -> MutexGuard<'static, ()> {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
        }

        fn wait_for_file(path: &std::path::Path, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            loop {
                if path.is_file() {
                    return true;
                }
                if Instant::now() >= deadline {
                    return false;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }

        #[test]
        fn snapshot_runner_emits_bomless_utf8_for_non_ascii_owned_process_metadata() {
            let _powershell_test_lock = powershell_test_lock();
            let command_line_canary = "AgentArk-快照-元数据";
            let script = format!("$metadata = '{command_line_canary}'; Start-Sleep -Seconds 30");
            let mut owned_command = powershell_command(&script);
            owned_command
                .creation_flags(CREATE_NO_WINDOW)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let owned = OwnedTestChild::spawn(&mut owned_command);
            thread::sleep(Duration::from_millis(200));

            let output = run_bounded_command_typed(
                powershell_command(PROCESS_SNAPSHOT_SCRIPT),
                SNAPSHOT_DEADLINE,
                MAX_STDOUT_BYTES,
                MAX_STDERR_BYTES,
            )
            .unwrap();
            let output = match String::from_utf8(output.stdout) {
                Ok(output) => output,
                Err(_) => panic!("snapshot must be UTF-8"),
            };
            assert!(!output.starts_with('\u{feff}'));
            let rows = serde_json::from_str::<Vec<super::super::ProcessSnapshotRow>>(&output)
                .expect("snapshot must be valid JSON");
            let owned_row = rows
                .iter()
                .find(|row| row.process_id == owned.id())
                .expect("owned child must appear in snapshot");
            assert!(
                owned_row
                    .command_line
                    .as_deref()
                    .unwrap()
                    .contains(command_line_canary)
            );
            let controlled = serde_json::json!([{
                "Name": owned_row.name,
                "ProcessId": owned_row.process_id,
                "ParentProcessId": owned_row.parent_process_id,
                "CommandLine": owned_row.command_line,
            }]);
            super::super::classify_process_snapshot(&controlled.to_string(), &[owned.id()])
                .unwrap();
        }

        #[test]
        fn invalid_snapshot_bytes_fail_closed_without_leaking_raw_metadata() {
            let command_line_canary = "agentark-sensitive-command-line-canary";
            let mut bytes = command_line_canary.as_bytes().to_vec();
            bytes.push(0xff);

            let error = decode_process_snapshot(bytes).unwrap_err();

            assert!(matches!(error, NativeImportError::Verification(_)));
            assert!(!error.to_string().contains(command_line_canary));
        }

        #[test]
        fn bounded_runner_times_out_and_kills_owned_sleeping_powershell() {
            let _powershell_test_lock = powershell_test_lock();
            let root = tempdir().unwrap();
            let started_marker = root.path().join("owned-child-started.txt");
            let release_marker = root.path().join("owned-child-release.txt");
            let delayed_marker = root.path().join("owned-child-survived.txt");
            let script = format!(
                "Set-Content -LiteralPath '{}' -Value started; while (-not (Test-Path -LiteralPath '{}')) {{ Start-Sleep -Milliseconds 25 }}; Set-Content -LiteralPath '{}' -Value survived",
                started_marker.to_string_lossy().replace('\'', "''"),
                release_marker.to_string_lossy().replace('\'', "''"),
                delayed_marker.to_string_lossy().replace('\'', "''")
            );
            let started = Instant::now();
            let (outcome_tx, outcome_rx) = mpsc::sync_channel(1);
            let runner = thread::spawn(move || {
                let outcome = run_bounded_command_typed(
                    powershell_command(&script),
                    Duration::from_secs(6),
                    64 * 1024,
                    64 * 1024,
                );
                outcome_tx.send(outcome).unwrap();
            });

            assert!(
                wait_for_file(&started_marker, Duration::from_secs(4)),
                "PowerShell command must start before its bounded deadline"
            );
            let outcome = outcome_rx
                .recv_timeout(Duration::from_secs(7))
                .expect("bounded command must finish after its deadline");
            runner
                .join()
                .expect("bounded runner test thread must not panic");
            std::fs::write(&release_marker, "release").unwrap();

            let outcome = outcome.unwrap_err();
            let elapsed = started.elapsed();
            assert_eq!(outcome, BoundedCommandFailure::Timeout);
            assert!(elapsed < Duration::from_secs(9));
            assert!(
                !wait_for_file(&delayed_marker, Duration::from_secs(1)),
                "timed-out child must not observe the release signal"
            );
        }

        #[test]
        fn bounded_runner_propagates_owned_child_nonzero_exit() {
            let _powershell_test_lock = powershell_test_lock();
            let outcome = run_bounded_command_typed(
                powershell_command("exit 23"),
                Duration::from_secs(5),
                64 * 1024,
                64 * 1024,
            )
            .unwrap_err();

            assert_eq!(outcome, BoundedCommandFailure::NonZero(23));
        }

        #[test]
        fn bounded_runner_detects_actual_stdout_and_stderr_overflow() {
            let _powershell_test_lock = powershell_test_lock();
            let root = tempdir().unwrap();
            for (index, (write, expected)) in [
                (
                    "[Console]::Out.Write(('x' * 4096))",
                    BoundedCommandFailure::StdoutOverflow,
                ),
                (
                    "[Console]::Error.Write(('x' * 4096))",
                    BoundedCommandFailure::StderrOverflow,
                ),
            ]
            .into_iter()
            .enumerate()
            {
                let marker = root.path().join(format!("overflow-{index}-started.txt"));
                let script = format!(
                    "Set-Content -LiteralPath '{}' -Value started; {write}",
                    marker.to_string_lossy().replace('\'', "''")
                );
                let outcome = run_bounded_command_typed(
                    powershell_command(&script),
                    Duration::from_secs(5),
                    64,
                    64,
                )
                .unwrap_err();

                assert_eq!(outcome, expected);
                assert!(marker.is_file());
            }
        }

        #[test]
        fn bounded_runner_reports_spawn_and_maps_every_failure_to_sanitized_error() {
            let missing = "agentark-owned-missing-process-fixture.exe";
            let outcome =
                run_bounded_command_typed(Command::new(missing), Duration::from_secs(1), 64, 64)
                    .unwrap_err();
            assert_eq!(outcome, BoundedCommandFailure::Spawn);

            for failure in [
                BoundedCommandFailure::Spawn,
                BoundedCommandFailure::MissingStdout,
                BoundedCommandFailure::MissingStderr,
                BoundedCommandFailure::Poll,
                BoundedCommandFailure::Kill,
                BoundedCommandFailure::Wait,
                BoundedCommandFailure::Timeout,
                BoundedCommandFailure::StdoutReaderPanic,
                BoundedCommandFailure::StderrReaderPanic,
                BoundedCommandFailure::StdoutRead,
                BoundedCommandFailure::StderrRead,
                BoundedCommandFailure::NonZero(23),
                BoundedCommandFailure::UnknownExit,
                BoundedCommandFailure::StdoutOverflow,
                BoundedCommandFailure::StderrOverflow,
            ] {
                let error = map_bounded_command_failure(failure);
                assert!(matches!(error, NativeImportError::Verification(_)));
                assert!(!error.to_string().contains(missing));
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
