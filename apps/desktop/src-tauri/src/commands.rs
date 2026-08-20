use std::sync::{Arc, Mutex};

use agentark_app::{AppError, PublicSessionDetail, QuarantineDto, QueryUseCase, StatusDto};
use agentark_index::{SearchHit, SessionSummary};
use tauri::State;
use uuid::Uuid;

use crate::state::AppState;

#[allow(dead_code)]
pub const REGISTERED_COMMANDS: [&str; 5] = [
    "status",
    "sessions_list",
    "sessions_show",
    "search",
    "quarantines_list",
];

#[tauri::command]
pub fn status(state: State<'_, AppState>) -> Result<StatusDto, String> {
    status_inner(&state.services)
}

pub fn status_inner(services: &Arc<Mutex<agentark_app::AppServices>>) -> Result<StatusDto, String> {
    with_query(services, |query| query.status())
}

#[tauri::command]
pub fn sessions_list(
    state: State<'_, AppState>,
    limit: u32,
    offset: u32,
) -> Result<Vec<SessionSummary>, String> {
    sessions_list_inner(&state.services, limit, offset)
}

pub fn sessions_list_inner(
    services: &Arc<Mutex<agentark_app::AppServices>>,
    limit: u32,
    offset: u32,
) -> Result<Vec<SessionSummary>, String> {
    with_query(services, |query| query.list_sessions(limit, offset))
}

#[tauri::command]
pub fn sessions_show(
    state: State<'_, AppState>,
    session_id: Uuid,
) -> Result<PublicSessionDetail, String> {
    with_query(&state.services, |query| query.show_session(session_id))
}

#[tauri::command]
pub fn search(
    state: State<'_, AppState>,
    query: String,
    limit: u32,
) -> Result<Vec<SearchHit>, String> {
    with_query(&state.services, |service| service.search(&query, limit))
}

#[tauri::command]
pub fn quarantines_list(state: State<'_, AppState>) -> Result<Vec<QuarantineDto>, String> {
    with_query(&state.services, |query| query.list_quarantines())
}

fn with_query<T>(
    services: &Arc<Mutex<agentark_app::AppServices>>,
    operation: impl FnOnce(&dyn QueryUseCase) -> Result<T, AppError>,
) -> Result<T, String> {
    let guard = services
        .lock()
        .map_err(|_| "desktop state unavailable".to_owned())?;
    operation(guard.queries.as_ref()).map_err(|_| "query operation failed".to_owned())
}
