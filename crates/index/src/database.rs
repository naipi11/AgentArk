use std::path::Path;

use rusqlite::{Connection, OptionalExtension};

use crate::IndexError;

pub struct IndexDb {
    connection: Connection,
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
        connection.execute_batch(include_str!("../migrations/0001_init.sql"))?;
        Ok(Self { connection })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub(crate) fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
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
}
