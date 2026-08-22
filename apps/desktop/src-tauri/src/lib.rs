#![forbid(unsafe_code)]

mod commands;
mod state;

pub mod recovery;
pub use state::{AppState, BundleReport};

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(state::AppState::open_default())
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::sessions_list,
            commands::sessions_show,
            commands::search,
            commands::quarantines_list,
            commands::scan_codex,
            commands::codex_default_root,
            commands::workspaces_list,
            commands::scan_claude,
            commands::claude_default_root,
            commands::scan_hermes,
            commands::hermes_default_root,
            commands::scan_openclaw,
            commands::openclaw_default_root,
            commands::scan_opencode,
            commands::opencode_default_root,
            commands::scan_grok_build,
            commands::grok_build_default_root,
            commands::bundle_export,
            commands::bundle_verify,
            commands::bundle_restore,
            commands::audit_verify,
        ])
        .run(tauri::generate_context!())
        .expect("error while running AgentArk desktop");
}

#[cfg(test)]
mod tests {
    use super::commands::REGISTERED_COMMANDS;

    #[test]
    fn registered_commands_include_queries_and_codex_scan() {
        assert_eq!(
            REGISTERED_COMMANDS,
            [
                "status",
                "sessions_list",
                "sessions_show",
                "search",
                "quarantines_list",
                "scan_codex",
                "codex_default_root",
                "workspaces_list",
                "scan_claude",
                "claude_default_root",
                "scan_hermes",
                "hermes_default_root",
                "scan_openclaw",
                "openclaw_default_root",
                "scan_opencode",
                "opencode_default_root",
                "scan_grok_build",
                "grok_build_default_root",
                "bundle_export",
                "bundle_verify",
                "bundle_restore",
                "audit_verify"
            ]
        );
    }
}
