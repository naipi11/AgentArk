use std::sync::{Arc, Mutex};

use agentark_app::{
    AppError, PublicSessionDetail, QuarantineDto, QueryUseCase, ScanReport, StatusDto, WorkspaceDto,
};
use agentark_index::{SearchHit, SessionSummary};
use tauri::State;
use uuid::Uuid;

use crate::state::AppState;

#[allow(dead_code)]
pub const REGISTERED_COMMANDS: [&str; 18] = [
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
    workspace_id: Option<Uuid>,
) -> Result<Vec<SessionSummary>, String> {
    sessions_list_inner(&state.services, limit, offset, workspace_id)
}

pub fn sessions_list_inner(
    services: &Arc<Mutex<agentark_app::AppServices>>,
    limit: u32,
    offset: u32,
    workspace_id: Option<Uuid>,
) -> Result<Vec<SessionSummary>, String> {
    with_query(services, |query| match workspace_id {
        Some(workspace_id) => query.list_sessions_for_workspace(workspace_id, limit, offset),
        None => query.list_sessions(limit, offset),
    })
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

#[tauri::command]
pub fn workspaces_list(
    state: State<'_, AppState>,
    limit: u32,
    offset: u32,
) -> Result<Vec<WorkspaceDto>, String> {
    with_query(&state.services, |query| {
        query.list_workspaces(limit, offset)
    })
}

#[tauri::command]
pub fn scan_codex(state: State<'_, AppState>, source_root: String) -> Result<ScanReport, String> {
    state.scan_codex(std::path::PathBuf::from(source_root.trim()))
}

#[tauri::command]
pub fn codex_default_root() -> Option<String> {
    crate::state::detected_codex_home().map(|path| path.to_string_lossy().into_owned())
}

#[tauri::command]
pub fn scan_claude(state: State<'_, AppState>, source_root: String) -> Result<ScanReport, String> {
    state.scan_claude(std::path::PathBuf::from(source_root.trim()))
}

#[tauri::command]
pub fn claude_default_root() -> Option<String> {
    crate::state::detected_claude_home().map(|path| path.to_string_lossy().into_owned())
}

#[tauri::command]
pub fn scan_hermes(state: State<'_, AppState>, source_root: String) -> Result<ScanReport, String> {
    state.scan_hermes(std::path::PathBuf::from(source_root.trim()))
}

#[tauri::command]
pub fn hermes_default_root() -> Option<String> {
    crate::state::detected_hermes_home().map(|path| path.to_string_lossy().into_owned())
}

#[tauri::command]
pub fn scan_openclaw(
    state: State<'_, AppState>,
    source_root: String,
) -> Result<ScanReport, String> {
    state.scan_openclaw(std::path::PathBuf::from(source_root.trim()))
}

#[tauri::command]
pub fn openclaw_default_root() -> Option<String> {
    crate::state::detected_openclaw_home().map(|path| path.to_string_lossy().into_owned())
}

#[tauri::command]
pub fn scan_opencode(
    state: State<'_, AppState>,
    source_root: String,
) -> Result<ScanReport, String> {
    state.scan_opencode(std::path::PathBuf::from(source_root.trim()))
}

#[tauri::command]
pub fn opencode_default_root() -> Option<String> {
    crate::state::detected_opencode_home().map(|path| path.to_string_lossy().into_owned())
}

#[tauri::command]
pub fn scan_grok_build(
    state: State<'_, AppState>,
    source_root: String,
) -> Result<ScanReport, String> {
    state.scan_grok_build(std::path::PathBuf::from(source_root.trim()))
}

#[tauri::command]
pub fn grok_build_default_root() -> Option<String> {
    crate::state::detected_grok_build_home().map(|path| path.to_string_lossy().into_owned())
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
