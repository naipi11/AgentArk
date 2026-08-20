use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(
    name = "agentark",
    version,
    about = "Local read-only agent history archive"
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub json: bool,
    #[arg(long, global = true, env = "AGENTARK_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Doctor,
    Probe {
        #[command(subcommand)]
        agent: ProbeAgent,
    },
    Scan(ScanArgs),
    Sessions {
        #[command(subcommand)]
        command: SessionsCommand,
    },
    Search {
        query: String,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    Verify {
        #[arg(long)]
        scan_id: Option<Uuid>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ProbeAgent {
    Codex,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AgentArg {
    Codex,
}

#[derive(Subcommand, Debug)]
pub enum SessionsCommand {
    List {
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long, default_value_t = 0)]
        offset: u32,
    },
    Show {
        session_id: Uuid,
    },
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    #[arg(value_enum)]
    pub agent: AgentArg,
    #[arg(long, conflicts_with = "allow_detected_codex_home")]
    pub source_root: Option<PathBuf>,
    #[arg(long)]
    pub allow_detected_codex_home: bool,
}
