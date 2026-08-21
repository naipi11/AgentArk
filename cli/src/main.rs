#![forbid(unsafe_code)]

mod args;
mod output;
mod runtime;

use std::process::ExitCode;

use agentark_app::{ScanReport, ScanStatus};
use args::{Cli, Command, ProbeAgent, SessionsCommand};
use clap::Parser;
use output::{failure, success};
use runtime::RuntimeError;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let data_root = runtime::data_dir(cli.data_dir.clone());
    match cli.command {
        Command::Doctor => print_result(cli.json, "doctor", Ok(runtime::doctor(&data_root))),
        Command::Probe { agent } => match agent {
            ProbeAgent::Codex => print_result(cli.json, "probe", runtime::probe_codex()),
            ProbeAgent::Claude => print_result(cli.json, "probe", runtime::probe_claude()),
            ProbeAgent::Hermes => print_result(cli.json, "probe", runtime::probe_hermes()),
        },
        Command::Scan(scan) => {
            let agent = scan.agent;
            let source_root = match scan.source_root {
                Some(root) => root,
                None if scan.allow_detected_codex_home
                    || scan.allow_detected_claude_home
                    || scan.allow_detected_hermes_home =>
                {
                    let root = match agent {
                        args::AgentArg::Codex => runtime::detected_codex_home(),
                        args::AgentArg::Claude => runtime::detected_claude_home(),
                        args::AgentArg::Hermes => runtime::detected_hermes_home(),
                    };
                    let Some(root) = root else {
                        return print_error(cli.json, "scan", RuntimeError::Authorization);
                    };
                    root
                }
                None => return print_error(cli.json, "scan", RuntimeError::Authorization),
            };
            print_scan_result(
                cli.json,
                "scan",
                match agent {
                    args::AgentArg::Codex => runtime::scan_codex(&source_root, &data_root),
                    args::AgentArg::Claude => runtime::scan_claude(&source_root, &data_root),
                    args::AgentArg::Hermes => runtime::scan_hermes(&source_root, &data_root),
                },
            )
        }
        Command::Sessions { command } => match command {
            SessionsCommand::List { limit, offset } => print_result(
                cli.json,
                "sessions.list",
                runtime::list_sessions(&data_root, limit, offset),
            ),
            SessionsCommand::Show { session_id } => print_result(
                cli.json,
                "sessions.show",
                runtime::show_session(&data_root, session_id),
            ),
        },
        Command::Search { query, limit } => print_result(
            cli.json,
            "search",
            runtime::search(&data_root, &query, limit),
        ),
        Command::Verify { scan_id } => {
            let Some(scan_id) = scan_id else {
                return print_error(cli.json, "verify", RuntimeError::InvalidInput);
            };
            print_result(cli.json, "verify", runtime::verify(&data_root, scan_id))
        }
    }
}

fn print_scan_result(
    json_mode: bool,
    command: &'static str,
    result: Result<ScanReport, RuntimeError>,
) -> ExitCode {
    match result {
        Ok(data) => {
            if json_mode {
                println!(
                    "{}",
                    serde_json::to_string(&success(command, &data)).unwrap_or_else(|_| "{}".into())
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".into())
                );
            }
            if data.status == ScanStatus::Partial {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => print_error(json_mode, command, error),
    }
}

fn print_result<T: serde::Serialize>(
    json_mode: bool,
    command: &'static str,
    result: Result<T, RuntimeError>,
) -> ExitCode {
    match result {
        Ok(data) => {
            if json_mode {
                println!(
                    "{}",
                    serde_json::to_string(&success(command, data)).unwrap_or_else(|_| "{}".into())
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".into())
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => print_error(json_mode, command, error),
    }
}

fn print_error(json_mode: bool, command: &'static str, error: RuntimeError) -> ExitCode {
    let (code, message, exit) = match error {
        RuntimeError::Authorization => (
            "authorization-required",
            "scan requires explicit source authorization",
            2,
        ),
        RuntimeError::NotInitialized => ("not-initialized", "dataset is not initialized", 5),
        RuntimeError::Probe => ("probe-failed", "Codex probe failed", 3),
        RuntimeError::InvalidInput => ("invalid-arguments", "invalid command arguments", 2),
        RuntimeError::Storage => ("storage-failed", "local storage operation failed", 5),
        RuntimeError::App(_) => ("application-failed", "application operation failed", 5),
    };
    if json_mode {
        println!(
            "{}",
            serde_json::to_string(&failure::<serde_json::Value>(command, code, message))
                .unwrap_or_else(|_| "{}".into())
        );
    } else {
        eprintln!("{message}");
    }
    ExitCode::from(exit)
}
