use agentark_canonical::{AgentKind, CanonicalSession, Completeness};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::{IndexDb, IndexError};

pub trait SessionQuery {
    fn list_sessions(&self, limit: u32, offset: u32) -> Result<Vec<SessionSummary>, IndexError>;
    fn list_sessions_filtered(
        &self,
        agent_kind: Option<AgentKind>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SessionSummary>, IndexError> {
        if agent_kind.is_some() {
            return Err(IndexError::InvalidQuery);
        }
        self.list_sessions(limit, offset)
    }
    fn list_sessions_for_workspace(
        &self,
        workspace_id: Uuid,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SessionSummary>, IndexError> {
        let _ = workspace_id;
        self.list_sessions(limit, offset)
    }
    fn list_sessions_for_workspace_filtered(
        &self,
        workspace_id: Uuid,
        agent_kind: Option<AgentKind>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SessionSummary>, IndexError> {
        if agent_kind.is_some() {
            return Err(IndexError::InvalidQuery);
        }
        self.list_sessions_for_workspace(workspace_id, limit, offset)
    }
    fn list_workspaces(&self, limit: u32, offset: u32)
    -> Result<Vec<WorkspaceSummary>, IndexError>;
    fn list_workspaces_filtered(
        &self,
        agent_kind: Option<AgentKind>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<WorkspaceSummary>, IndexError> {
        if agent_kind.is_some() {
            return Err(IndexError::InvalidQuery);
        }
        self.list_workspaces(limit, offset)
    }
    fn show_session(&self, id: Uuid) -> Result<SessionDetail, IndexError>;
    fn search(&self, query: &str, limit: u32) -> Result<Vec<SearchHit>, IndexError>;
    fn list_quarantines(&self) -> Result<Vec<QuarantineSummary>, IndexError>;
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub id: Uuid,
    pub title: Option<String>,
    pub source_kind: String,
    pub archived: bool,
    pub completeness: Completeness,
    pub stale: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSummary {
    pub id: Uuid,
    pub path_native: String,
    pub canonical_uri: String,
    pub git_commit: Option<String>,
    pub session_count: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDetail {
    pub session: CanonicalSession,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    pub session_id: Uuid,
    pub title: Option<String>,
    pub snippet: String,
    pub score: f64,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineSummary {
    pub id: Uuid,
    pub reason_code: String,
    pub fingerprint: String,
    pub sanitized_locator: String,
}

impl SessionQuery for IndexDb {
    fn list_sessions(&self, limit: u32, offset: u32) -> Result<Vec<SessionSummary>, IndexError> {
        self.list_sessions_filtered(None, limit, offset)
    }

    fn list_sessions_filtered(
        &self,
        agent_kind: Option<AgentKind>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SessionSummary>, IndexError> {
        let agent_kind = agent_kind_storage_label(agent_kind.as_ref())?;
        let mut statement = self.connection().prepare(
            "SELECT s.id, s.search_title, s.source_kind, s.archived, s.completeness, s.stale
             FROM sessions s JOIN agent_installs ai ON ai.id = s.install_id
             WHERE (?1 IS NULL OR ai.kind = ?1)
             ORDER BY s.rowid DESC LIMIT ?2 OFFSET ?3",
        )?;
        let rows = statement.query_map(params![agent_kind, limit.min(100), offset], |row| {
            Ok(SessionSummary {
                id: parse_uuid(row.get::<_, String>(0)?)?,
                title: row.get(1)?,
                source_kind: row.get(2)?,
                archived: row.get::<_, i64>(3)? != 0,
                completeness: parse_completeness(&row.get::<_, String>(4)?)?,
                stale: row.get::<_, i64>(5)? != 0,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    fn list_sessions_for_workspace(
        &self,
        workspace_id: Uuid,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SessionSummary>, IndexError> {
        self.list_sessions_for_workspace_filtered(workspace_id, None, limit, offset)
    }

    fn list_sessions_for_workspace_filtered(
        &self,
        workspace_id: Uuid,
        agent_kind: Option<AgentKind>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SessionSummary>, IndexError> {
        let agent_kind = agent_kind_storage_label(agent_kind.as_ref())?;
        let mut statement = self.connection().prepare(
            "SELECT s.id, s.search_title, s.source_kind, s.archived, s.completeness, s.stale
             FROM sessions s JOIN agent_installs ai ON ai.id = s.install_id
             WHERE s.workspace_id = ?1 AND (?2 IS NULL OR ai.kind = ?2)
             ORDER BY s.rowid DESC LIMIT ?3 OFFSET ?4",
        )?;
        let rows = statement.query_map(
            params![workspace_id.to_string(), agent_kind, limit.min(100), offset],
            |row| {
                Ok(SessionSummary {
                    id: parse_uuid(row.get::<_, String>(0)?)?,
                    title: row.get(1)?,
                    source_kind: row.get(2)?,
                    archived: row.get::<_, i64>(3)? != 0,
                    completeness: parse_completeness(&row.get::<_, String>(4)?)?,
                    stale: row.get::<_, i64>(5)? != 0,
                })
            },
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    fn list_workspaces(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<WorkspaceSummary>, IndexError> {
        self.list_workspaces_filtered(None, limit, offset)
    }

    fn list_workspaces_filtered(
        &self,
        agent_kind: Option<AgentKind>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<WorkspaceSummary>, IndexError> {
        let agent_kind = agent_kind_storage_label(agent_kind.as_ref())?;
        let mut statement = self.connection().prepare(
            "SELECT w.id, w.path_native, w.canonical_uri, w.git_commit, COUNT(s.id)
             FROM workspaces w
             JOIN sessions s ON s.workspace_id = w.id
             JOIN agent_installs ai ON ai.id = s.install_id
             WHERE (?1 IS NULL OR ai.kind = ?1)
             GROUP BY w.id, w.path_native, w.canonical_uri, w.git_commit
             HAVING COUNT(s.id) > 0
             ORDER BY MAX(s.rowid) DESC, w.rowid DESC
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = statement.query_map(params![agent_kind, limit.min(100), offset], |row| {
            Ok(WorkspaceSummary {
                id: parse_uuid(row.get::<_, String>(0)?)?,
                path_native: row.get(1)?,
                canonical_uri: row.get(2)?,
                git_commit: row.get(3)?,
                session_count: row
                    .get::<_, i64>(4)?
                    .try_into()
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(4, i64::MAX))?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    fn show_session(&self, id: Uuid) -> Result<SessionDetail, IndexError> {
        let json: String = self
            .connection()
            .query_row(
                "SELECT canonical_json FROM sessions WHERE id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(IndexError::NotFound)?;
        Ok(SessionDetail {
            session: serde_json::from_str(&json)?,
        })
    }

    fn search(&self, query: &str, limit: u32) -> Result<Vec<SearchHit>, IndexError> {
        let query = query.trim();
        if query.is_empty() {
            return Err(IndexError::InvalidQuery);
        }
        let escaped = query
            .split_whitespace()
            .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" ");
        let mut statement = self.connection().prepare(
            "WITH matched AS (
                 SELECT rowid, rank
                 FROM session_fts
                 WHERE session_fts MATCH ?1
                 ORDER BY rank
                 LIMIT ?2
             )
             SELECT s.id, s.search_title,
                    snippet(session_fts, 2, '[', ']', ' … ', 16), matched.rank
             FROM matched
             JOIN session_fts f ON f.rowid = matched.rowid
             JOIN sessions s ON s.id = f.session_id
             ORDER BY matched.rank",
        )?;
        let rows = statement.query_map(params![escaped, limit.min(100)], |row| {
            Ok(SearchHit {
                session_id: parse_uuid(row.get::<_, String>(0)?)?,
                title: row.get(1)?,
                snippet: row.get(2)?,
                score: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    fn list_quarantines(&self) -> Result<Vec<QuarantineSummary>, IndexError> {
        let mut statement = self.connection().prepare(
            "SELECT id, reason_code, fingerprint, source_locator
             FROM quarantines ORDER BY rowid DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(QuarantineSummary {
                id: parse_uuid(row.get::<_, String>(0)?)?,
                reason_code: row.get(1)?,
                fingerprint: row.get(2)?,
                sanitized_locator: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

impl IndexDb {
    /// Returns every canonical session for portable backup/export.
    pub fn all_sessions(&self) -> Result<Vec<CanonicalSession>, IndexError> {
        self.all_sessions_filtered(None)
    }

    pub fn all_sessions_filtered(
        &self,
        agent_kind: Option<AgentKind>,
    ) -> Result<Vec<CanonicalSession>, IndexError> {
        let agent_kind = agent_kind_storage_label(agent_kind.as_ref())?;
        let mut statement = self
            .connection()
            .prepare("SELECT s.canonical_json FROM sessions s JOIN agent_installs ai ON ai.id = s.install_id WHERE (?1 IS NULL OR ai.kind = ?1) ORDER BY s.rowid ASC")?;
        let rows = statement.query_map(params![agent_kind], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let json = row?;
            Ok(serde_json::from_str(&json)?)
        })
        .collect()
    }
}

fn agent_kind_storage_label(agent_kind: Option<&AgentKind>) -> Result<Option<String>, IndexError> {
    agent_kind
        .map(serde_json::to_string)
        .transpose()
        .map_err(IndexError::from)
}

fn parse_uuid(value: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn parse_completeness(value: &str) -> rusqlite::Result<Completeness> {
    match value {
        "complete" => Ok(Completeness::Complete),
        "partial" => Ok(Completeness::Partial),
        "quarantined" => Ok(Completeness::Quarantined),
        _ => Err(rusqlite::Error::InvalidColumnType(
            0,
            "completeness".into(),
            rusqlite::types::Type::Text,
        )),
    }
}
