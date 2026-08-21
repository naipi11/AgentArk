#![forbid(unsafe_code)]

mod commands;
mod state;

pub fn run() {
    tauri::Builder::default()
        .manage(state::AppState::open_default())
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::sessions_list,
            commands::sessions_show,
            commands::search,
            commands::quarantines_list,
        ])
        .run(tauri::generate_context!())
        .expect("error while running AgentArk desktop");
}

#[cfg(test)]
mod tests {
    use super::commands::REGISTERED_COMMANDS;

    #[test]
    fn no_mutating_command_is_registered() {
        assert_eq!(
            REGISTERED_COMMANDS,
            [
                "status",
                "sessions_list",
                "sessions_show",
                "search",
                "quarantines_list"
            ]
        );
    }
}
