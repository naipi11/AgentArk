use agentark_canonical::{AgentKind, Sha256Digest};
use agentark_migration::RestoreOutcome;
use rusqlite::{params, types::Type};
use uuid::Uuid;

use crate::{IndexDb, IndexError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreMapping {
    pub source_session_id: Uuid,
    pub target_agent: AgentKind,
    pub outcome: RestoreOutcome,
    pub source_native_id: Option<String>,
    pub target_native_id: Option<String>,
    pub source_provider: Option<String>,
    pub target_provider: Option<String>,
    pub source_hash: Sha256Digest,
    pub target_hash: Option<Sha256Digest>,
    pub reason_code: String,
    pub created_at: String,
}

impl IndexDb {
    pub fn record_restore_mapping(&mut self, mapping: &RestoreMapping) -> Result<(), IndexError> {
        let target_agent = enum_label(&mapping.target_agent)?;
        let outcome = enum_label(&mapping.outcome)?;
        self.connection_mut().execute(
            "INSERT INTO session_restore_mappings(
               id, source_session_id, target_agent, outcome, source_native_id, target_native_id,
               source_provider, target_provider, source_hash, target_hash, reason_code, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                Uuid::new_v4().to_string(),
                mapping.source_session_id.to_string(),
                target_agent,
                outcome,
                mapping.source_native_id,
                mapping.target_native_id,
                mapping.source_provider,
                mapping.target_provider,
                mapping.source_hash.as_str(),
                mapping.target_hash.as_ref().map(Sha256Digest::as_str),
                mapping.reason_code,
                mapping.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn restore_mappings_for(
        &self,
        source_session_id: Uuid,
    ) -> Result<Vec<RestoreMapping>, IndexError> {
        let mut statement = self.connection().prepare(
            "SELECT source_session_id, target_agent, outcome, source_native_id, target_native_id,
                    source_provider, target_provider, source_hash, target_hash, reason_code, created_at
             FROM session_restore_mappings
             WHERE source_session_id = ?1
             ORDER BY created_at DESC",
        )?;
        let rows = statement.query_map(params![source_session_id.to_string()], |row| {
            let source_session_id = parse_uuid(row.get(0)?, 0, "source_session_id")?;
            let target_agent = parse_json(row.get(1)?, 1, "target_agent")?;
            let outcome = parse_json(row.get(2)?, 2, "outcome")?;
            let source_hash = parse_hash(row.get(7)?, 7, "source_hash")?;
            let target_hash = row
                .get::<_, Option<String>>(8)?
                .map(|value| parse_hash(value, 8, "target_hash"))
                .transpose()?;
            Ok(RestoreMapping {
                source_session_id,
                target_agent,
                outcome,
                source_native_id: row.get(3)?,
                target_native_id: row.get(4)?,
                source_provider: row.get(5)?,
                target_provider: row.get(6)?,
                source_hash,
                target_hash,
                reason_code: row.get(9)?,
                created_at: row.get(10)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

fn parse_uuid(value: String, index: usize, column: &str) -> Result<Uuid, rusqlite::Error> {
    Uuid::parse_str(&value).map_err(|_| invalid_value(index, column))
}

fn parse_hash(value: String, index: usize, column: &str) -> Result<Sha256Digest, rusqlite::Error> {
    Sha256Digest::parse(&value).ok_or_else(|| invalid_value(index, column))
}

fn parse_json<T>(value: String, index: usize, column: &str) -> Result<T, rusqlite::Error>
where
    T: serde::de::DeserializeOwned,
{
    let json = serde_json::to_string(&value).map_err(|_| invalid_value(index, column))?;
    serde_json::from_str(&json).map_err(|_| invalid_value(index, column))
}

fn enum_label<T>(value: &T) -> Result<String, IndexError>
where
    T: serde::Serialize,
{
    Ok(serde_json::from_str(&serde_json::to_string(value)?)?)
}

fn invalid_value(index: usize, column: &str) -> rusqlite::Error {
    rusqlite::Error::InvalidColumnType(index, column.into(), Type::Text)
}
