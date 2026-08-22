use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::IndexError;

pub struct IndexDb {
    connection: Connection,
    active_scan_id: Option<uuid::Uuid>,
}

impl IndexDb {
    pub fn open(path: &Path, sqlcipher_key: &[u8; 32]) -> Result<Self, IndexError> {
        let connection = Connection::open(path)?;
        let key_sql = format!("PRAGMA key = \"x'{}'\";", hex::encode(sqlcipher_key));
        connection.execute_batch(&key_sql)?;
        let cipher_version: Option<String> = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .optional()?;
        if cipher_version.as_deref().is_none_or(str::is_empty) {
            return Err(IndexError::UnsupportedStorageBuild);
        }
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA secure_delete = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;",
        )?;
        let fts5: i64 = connection.query_row(
            "SELECT sqlite_compileoption_used('ENABLE_FTS5')",
            [],
            |row| row.get(0),
        )?;
        if fts5 != 1 {
            return Err(IndexError::UnsupportedStorageBuild);
        }
        let has_schema_meta: bool = connection.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta'
             )",
            [],
            |row| row.get(0),
        )?;
        if has_schema_meta {
            let schema_version: Option<String> = connection
                .query_row(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            match schema_version
                .as_deref()
                .and_then(|value| value.parse::<u32>().ok())
            {
                Some(1) => connection
                    .execute_batch(include_str!("../migrations/0002_restore_mappings.sql"))?,
                Some(2) => {}
                _ => return Err(IndexError::UnsupportedStorageBuild),
            }
        } else {
            connection.execute_batch(include_str!("../migrations/0001_init.sql"))?;
            connection.execute_batch(include_str!("../migrations/0002_restore_mappings.sql"))?;
        }
        Ok(Self {
            connection,
            active_scan_id: None,
        })
    }

    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }

    pub(crate) fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    pub(crate) fn active_scan_id(&self) -> Option<uuid::Uuid> {
        self.active_scan_id
    }

    pub(crate) fn set_active_scan_id(&mut self, scan_id: Option<uuid::Uuid>) {
        self.active_scan_id = scan_id;
    }

    pub fn cipher_version(&self) -> Result<String, IndexError> {
        Ok(self
            .connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))?)
    }

    pub fn fts5_enabled(&self) -> Result<bool, IndexError> {
        Ok(self.connection.query_row(
            "SELECT sqlite_compileoption_used('ENABLE_FTS5')",
            [],
            |row| row.get::<_, i64>(0),
        )? == 1)
    }

    pub fn verification_records(
        &self,
        scan_id: Uuid,
    ) -> Result<Vec<crate::VerificationRecord>, IndexError> {
        let mut statement = self.connection.prepare(
            "SELECT object_id, object_type, plaintext_hash, size, session_json,
                    canonical_hash, sanitized_title, sanitized_body
             FROM verification_records WHERE scan_id = ?1 ORDER BY object_id ASC",
        )?;
        let rows = statement.query_map(params![scan_id.to_string()], |row| {
            let object_type = row.get::<_, i64>(1)?;
            let plaintext_hash = row.get::<_, String>(2)?;
            let size = row.get::<_, i64>(3)?;
            let canonical_hash = match row.get::<_, Option<String>>(5)? {
                Some(value) => Some(agentark_canonical::Sha256Digest::parse(&value).ok_or_else(
                    || {
                        rusqlite::Error::InvalidColumnType(
                            5,
                            "canonical_hash".into(),
                            rusqlite::types::Type::Text,
                        )
                    },
                )?),
                None => None,
            };
            Ok(crate::VerificationRecord {
                scan_id,
                object_id: row.get(0)?,
                object_type: u8::try_from(object_type)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, object_type))?,
                plaintext_hash: agentark_canonical::Sha256Digest::parse(&plaintext_hash)
                    .ok_or_else(|| {
                        rusqlite::Error::InvalidColumnType(
                            2,
                            "plaintext_hash".into(),
                            rusqlite::types::Type::Text,
                        )
                    })?,
                size: u64::try_from(size)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, size))?,
                session_json: row.get(4)?,
                canonical_hash,
                sanitized_title: row.get(6)?,
                sanitized_body: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}
