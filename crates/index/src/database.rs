use std::path::Path;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use uuid::Uuid;

use crate::IndexError;

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum MigrationFault {
    AfterV1,
    BeforeCommit,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_FAULT: std::cell::Cell<Option<MigrationFault>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn fail_migration_at(point: MigrationFault) -> Result<(), IndexError> {
    let should_fail = MIGRATION_FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            true
        } else {
            false
        }
    });
    if should_fail {
        Err(IndexError::InvariantViolation)
    } else {
        Ok(())
    }
}

pub struct IndexDb {
    connection: Connection,
    active_scan_id: Option<uuid::Uuid>,
}

impl IndexDb {
    pub fn open(path: &Path, sqlcipher_key: &[u8; 32]) -> Result<Self, IndexError> {
        let mut connection = Connection::open(path)?;
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
                Some(1) => {
                    let transaction =
                        connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    transaction
                        .execute_batch(include_str!("../migrations/0002_restore_mappings.sql"))?;
                    #[cfg(test)]
                    fail_migration_at(MigrationFault::BeforeCommit)?;
                    transaction.commit()?;
                }
                Some(2) => {}
                _ => return Err(IndexError::UnsupportedStorageBuild),
            }
        } else {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(include_str!("../migrations/0001_init.sql"))?;
            #[cfg(test)]
            fail_migration_at(MigrationFault::AfterV1)?;
            transaction.execute_batch(include_str!("../migrations/0002_restore_mappings.sql"))?;
            #[cfg(test)]
            fail_migration_at(MigrationFault::BeforeCommit)?;
            transaction.commit()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use tempfile::TempDir;

    struct TempIndex {
        directory: TempDir,
        key: [u8; 32],
    }

    impl TempIndex {
        fn new() -> Self {
            Self {
                directory: tempfile::tempdir().unwrap(),
                key: [7; 32],
            }
        }

        fn path(&self) -> std::path::PathBuf {
            self.directory.path().join("agentark.db")
        }

        fn raw_connection(&self) -> Connection {
            let connection = Connection::open(self.path()).unwrap();
            let key_sql = format!("PRAGMA key = \"x'{}'\";", hex::encode(self.key));
            connection.execute_batch(&key_sql).unwrap();
            connection
        }

        fn open_with_fault(&self, fault: MigrationFault) -> Result<IndexDb, IndexError> {
            struct ResetFault;

            impl Drop for ResetFault {
                fn drop(&mut self) {
                    MIGRATION_FAULT.with(|current| current.set(None));
                }
            }

            MIGRATION_FAULT.with(|current| {
                assert!(current.replace(Some(fault)).is_none());
            });
            let reset = ResetFault;
            let result = IndexDb::open(&self.path(), &self.key);
            drop(reset);
            result
        }
    }

    fn table_exists(connection: &Connection, table: &str) -> bool {
        connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1
                 )",
                [table],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn failed_v1_to_v2_migration_rolls_back_before_normal_reopen() {
        let fixture = TempIndex::new();
        let connection = fixture.raw_connection();
        connection
            .execute_batch(include_str!("../migrations/0001_init.sql"))
            .unwrap();
        let install_id = Uuid::from_u128(8).to_string();
        let session_id = Uuid::from_u128(9).to_string();
        connection
            .execute(
                "INSERT INTO agent_installs(id, kind, executable_version, authorized_root_uri,
                 adapter_version, schema_fingerprint, capabilities_json, quarantine_reason)
                 VALUES (?1, 'codex', '0.146.0', 'file:///fixture', '0.1.0',
                         'sha256:fixture', '[]', NULL)",
                [&install_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sessions(id, install_id, workspace_id, source_session_id, source_kind,
                 title, archived, completeness, canonical_hash, canonical_json, search_title,
                 search_body, model_provider, model_name, revision, stale, last_scan_id)
                 VALUES (?1, ?2, NULL, 'pre-existing', 'codex', NULL, 0, 'complete',
                         'sha256:version-one', '{}', '', '', NULL, NULL, 1, 0, NULL)",
                params![session_id, install_id],
            )
            .unwrap();
        drop(connection);

        assert!(
            fixture
                .open_with_fault(MigrationFault::BeforeCommit)
                .is_err()
        );

        let connection = fixture.raw_connection();
        assert_eq!(
            connection
                .query_row(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "1"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT source_session_id FROM sessions WHERE id = ?1",
                    [&session_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "pre-existing"
        );
        assert!(!table_exists(&connection, "session_restore_mappings"));
        drop(connection);

        drop(IndexDb::open(&fixture.path(), &fixture.key).unwrap());
        let connection = fixture.raw_connection();
        assert_eq!(
            connection
                .query_row(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "2"
        );
        assert!(table_exists(&connection, "session_restore_mappings"));
    }

    #[test]
    fn failed_fresh_initialization_rolls_back_before_clean_reopen() {
        let fixture = TempIndex::new();

        assert!(fixture.open_with_fault(MigrationFault::AfterV1).is_err());

        let connection = fixture.raw_connection();
        assert!(!table_exists(&connection, "schema_meta"));
        assert!(!table_exists(&connection, "sessions"));
        assert!(!table_exists(&connection, "session_restore_mappings"));
        drop(connection);

        drop(IndexDb::open(&fixture.path(), &fixture.key).unwrap());
        let connection = fixture.raw_connection();
        assert_eq!(
            connection
                .query_row(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "2"
        );
        assert!(table_exists(&connection, "sessions"));
        assert!(table_exists(&connection, "session_restore_mappings"));
        drop(connection);

        drop(IndexDb::open(&fixture.path(), &fixture.key).unwrap());
    }
}
