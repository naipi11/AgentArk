use agentark_canonical::Sha256Digest;
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::{IndexDb, IndexError, VerificationRecord};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedSession {
    pub id: Uuid,
    pub canonical_json: String,
    pub canonical_hash: Sha256Digest,
    pub search_title: String,
    pub search_body: String,
    pub fts_title: Option<String>,
    pub fts_body: Option<String>,
    pub message_ordinals: Vec<u64>,
    pub tool_event_ordinals: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationSnapshot {
    pub status: String,
    pub indexed_count: u64,
    pub quarantined_count: u64,
    pub retryable_count: u64,
    pub rejected_count: u64,
    pub records: Vec<VerificationRecord>,
    pub sessions: Vec<IndexedSession>,
}

impl IndexDb {
    pub fn verification_snapshot(&self, scan_id: Uuid) -> Result<VerificationSnapshot, IndexError> {
        let scan = self
            .connection()
            .query_row(
                "SELECT status, indexed_count, quarantined_count, retryable_count,
                        rejected_count
                 FROM scan_runs WHERE id = ?1",
                params![scan_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(IndexError::NotFound)?;
        let mut statement = self.connection().prepare(
            "SELECT id, canonical_json, canonical_hash, search_title, search_body
             FROM sessions WHERE last_scan_id = ?1 ORDER BY id ASC",
        )?;
        let mut sessions = Vec::new();
        let rows = statement.query_map(params![scan_id.to_string()], |row| {
            let id_text = row.get::<_, String>(0)?;
            let id = Uuid::parse_str(&id_text).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            let canonical_hash = row.get::<_, String>(2)?;
            let canonical_hash = Sha256Digest::parse(&canonical_hash).ok_or_else(|| {
                rusqlite::Error::InvalidColumnType(
                    2,
                    "canonical_hash".into(),
                    rusqlite::types::Type::Text,
                )
            })?;
            let fts = self
                .connection()
                .query_row(
                    "SELECT title, body FROM session_fts WHERE session_id = ?1",
                    params![id_text.clone()],
                    |fts_row| Ok((fts_row.get::<_, String>(0)?, fts_row.get::<_, String>(1)?)),
                )
                .optional()?;
            let mut message_statement = self.connection().prepare(
                "SELECT ordinal FROM messages WHERE session_id = ?1 ORDER BY ordinal ASC",
            )?;
            let message_ordinals = message_statement
                .query_map(params![id_text.clone()], |message_row| {
                    Ok(message_row.get::<_, i64>(0)? as u64)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let mut tool_statement = self.connection().prepare(
                "SELECT ordinal FROM tool_events WHERE session_id = ?1 ORDER BY ordinal ASC",
            )?;
            let tool_event_ordinals = tool_statement
                .query_map(params![id_text], |tool_row| {
                    Ok(tool_row.get::<_, i64>(0)? as u64)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(IndexedSession {
                id,
                canonical_json: row.get(1)?,
                canonical_hash,
                search_title: row.get(3)?,
                search_body: row.get(4)?,
                fts_title: fts.as_ref().map(|value| value.0.clone()),
                fts_body: fts.map(|value| value.1),
                message_ordinals,
                tool_event_ordinals,
            })
        })?;
        for row in rows {
            sessions.push(row?);
        }
        Ok(VerificationSnapshot {
            status: scan.0,
            indexed_count: u64::try_from(scan.1).map_err(|_| IndexError::InvariantViolation)?,
            quarantined_count: u64::try_from(scan.2).map_err(|_| IndexError::InvariantViolation)?,
            retryable_count: u64::try_from(scan.3).map_err(|_| IndexError::InvariantViolation)?,
            rejected_count: u64::try_from(scan.4).map_err(|_| IndexError::InvariantViolation)?,
            records: self.verification_records(scan_id)?,
            sessions,
        })
    }
}
