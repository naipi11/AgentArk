use std::collections::HashSet;

use agentark_canonical::{
    AgentInstall, CanonicalSession, Completeness, Sha256Digest, SourceRecord, ToolEvent,
};
use agentark_security::SecretFinding;
use rusqlite::{OptionalExtension, params};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{IndexDb, IndexError};

pub struct SessionIngest<'a> {
    pub install: &'a AgentInstall,
    pub session: &'a CanonicalSession,
    pub source_records: &'a [SourceRecord],
    pub sanitized_title: &'a str,
    pub sanitized_body: &'a str,
    pub findings: &'a [SecretFinding],
    pub canonical_hash: &'a Sha256Digest,
}

pub struct QuarantineRecord {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub source_locator: String,
    pub fingerprint: String,
    pub reason_code: String,
    pub raw_sha256: Sha256Digest,
    pub cas_object_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanManifestStatus {
    Complete,
    Partial,
    Failed,
}

pub struct ScanManifest {
    pub id: Uuid,
    pub status: ScanManifestStatus,
    pub completed_at: String,
    pub indexed_count: u64,
    pub quarantined_count: u64,
    pub retryable_count: u64,
    pub rejected_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationRecord {
    pub scan_id: Uuid,
    pub object_id: String,
    pub object_type: u8,
    pub plaintext_hash: Sha256Digest,
    pub size: u64,
    pub session_json: Option<String>,
    pub canonical_hash: Option<Sha256Digest>,
    pub sanitized_title: Option<String>,
    pub sanitized_body: Option<String>,
}

pub trait SessionIndex {
    fn begin_scan(
        &mut self,
        scan_id: Uuid,
        adapter_id: &str,
        snapshot_id: &str,
    ) -> Result<(), IndexError>;
    fn ingest_session(&mut self, input: SessionIngest<'_>) -> Result<(), IndexError>;
    fn record_quarantine(&mut self, record: QuarantineRecord) -> Result<(), IndexError>;
    fn finish_scan(&mut self, manifest: &ScanManifest) -> Result<(), IndexError>;
    fn fail_scan(&mut self, scan_id: Uuid) -> Result<(), IndexError>;
    fn mark_sessions_stale(&mut self, _session_ids: &[Uuid]) -> Result<(), IndexError> {
        Ok(())
    }
    fn mark_source_sessions_stale(
        &mut self,
        _install_id: Uuid,
        _source_session_ids: &[String],
    ) -> Result<(), IndexError> {
        Ok(())
    }
    fn verification_snapshot(
        &self,
        _scan_id: Uuid,
    ) -> Result<Option<crate::VerificationSnapshot>, IndexError> {
        Ok(None)
    }
    fn record_verification(&mut self, _record: VerificationRecord) -> Result<(), IndexError> {
        Ok(())
    }
}

impl SessionIndex for IndexDb {
    fn begin_scan(
        &mut self,
        scan_id: Uuid,
        adapter_id: &str,
        snapshot_id: &str,
    ) -> Result<(), IndexError> {
        self.connection_mut().execute(
            "INSERT INTO scan_runs(id, adapter_id, snapshot_id, status, started_at)
             VALUES (?1, ?2, ?3, 'running', ?4)",
            params![scan_id.to_string(), adapter_id, snapshot_id, now_string(),],
        )?;
        self.set_active_scan_id(Some(scan_id));
        Ok(())
    }

    fn ingest_session(&mut self, input: SessionIngest<'_>) -> Result<(), IndexError> {
        let mut ordinals = HashSet::new();
        for message in &input.session.messages {
            if !ordinals.insert(message.ordinal) {
                return Err(IndexError::InvariantViolation);
            }
        }
        for event in &input.session.tool_events {
            if !ordinals.insert(event.ordinal) {
                return Err(IndexError::InvariantViolation);
            }
        }
        let messages_ordered = input
            .session
            .messages
            .windows(2)
            .all(|window| window[0].ordinal < window[1].ordinal);
        let tools_ordered = input
            .session
            .tool_events
            .windows(2)
            .all(|window| window[0].ordinal < window[1].ordinal);
        let mut merged_ordinals = input
            .session
            .messages
            .iter()
            .map(|message| message.ordinal)
            .chain(input.session.tool_events.iter().map(|event| event.ordinal))
            .collect::<Vec<_>>();
        merged_ordinals.sort_unstable();
        let merged_unique = merged_ordinals
            .windows(2)
            .all(|window| window[0] < window[1]);
        if !messages_ordered || !tools_ordered || !merged_unique {
            return Err(IndexError::InvariantViolation);
        }
        let canonical_json = serde_json::to_string(input.session)?;
        let capabilities_json = serde_json::to_string(&input.install.capabilities)?;
        let install_json = serde_json::to_string(&input.install.kind)?;
        let active_scan_id = self.active_scan_id().map(|scan_id| scan_id.to_string());
        let tx = self.connection_mut().transaction()?;
        let workspace_id = if let Some(workspace) = input.session.workspace.as_ref() {
            tx.execute(
                "INSERT INTO workspaces(id, path_native, canonical_uri, git_commit)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET path_native=excluded.path_native,
                   canonical_uri=excluded.canonical_uri, git_commit=excluded.git_commit",
                params![
                    workspace.id.to_string(),
                    workspace.path_native,
                    workspace.canonical_uri,
                    workspace.git_commit,
                ],
            )?;
            Some(workspace.id.to_string())
        } else {
            None
        };
        tx.execute(
            "INSERT INTO agent_installs(id, kind, executable_version, authorized_root_uri,
             adapter_version, schema_fingerprint, capabilities_json, quarantine_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET executable_version=excluded.executable_version,
               authorized_root_uri=excluded.authorized_root_uri,
               adapter_version=excluded.adapter_version,
               schema_fingerprint=excluded.schema_fingerprint,
               capabilities_json=excluded.capabilities_json,
               quarantine_reason=excluded.quarantine_reason",
            params![
                input.install.id.to_string(),
                install_json,
                input.install.executable_version,
                input.install.authorized_root_uri,
                input.install.adapter_version,
                input.install.schema_fingerprint,
                capabilities_json,
                input.install.quarantine_reason,
            ],
        )?;
        let prior_revision: Option<i64> = tx
            .query_row(
                "SELECT revision FROM sessions WHERE id = ?1",
                params![input.session.id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        tx.execute(
            "DELETE FROM session_fts WHERE session_id = ?1",
            params![input.session.id.to_string()],
        )?;
        for table in ["messages", "tool_events", "attachments", "secret_findings"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE session_id = ?1"),
                params![input.session.id.to_string()],
            )?;
        }
        tx.execute(
            "INSERT INTO sessions(id, install_id, workspace_id, source_session_id, source_kind,
             title, archived, completeness, canonical_hash, canonical_json, search_title,
             search_body, model_provider, model_name, revision, stale, last_scan_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 0, ?16)
             ON CONFLICT(id) DO UPDATE SET title=excluded.title, archived=excluded.archived,
               completeness=excluded.completeness, canonical_hash=excluded.canonical_hash,
               canonical_json=excluded.canonical_json, search_title=excluded.search_title,
               search_body=excluded.search_body, model_provider=excluded.model_provider,
               model_name=excluded.model_name, revision=excluded.revision, stale=0,
               last_scan_id=excluded.last_scan_id",
            params![
                input.session.id.to_string(),
                input.install.id.to_string(),
                workspace_id,
                input.session.source_session_id,
                input.session.source_kind,
                input.session.title,
                input.session.archived,
                completeness_label(&input.session.completeness),
                input.canonical_hash.as_str(),
                canonical_json,
                input.sanitized_title,
                input.sanitized_body,
                input.session.model_provider,
                input.session.model_name,
                prior_revision.unwrap_or(0) + 1,
                active_scan_id,
            ],
        )?;
        for message in &input.session.messages {
            tx.execute(
                "INSERT INTO messages(id, session_id, ordinal, role, raw_role, visible_text,
                 raw_ref, message_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    message.id.to_string(),
                    input.session.id.to_string(),
                    message.ordinal as i64,
                    serde_json::to_string(&message.role)?,
                    message.raw_role,
                    message.visible_text(),
                    message.raw_ref.as_str(),
                    serde_json::to_string(message)?,
                ],
            )?;
        }
        for event in &input.session.tool_events {
            insert_tool_event(&tx, input.session.id, event)?;
        }
        for attachment in &input.session.attachments {
            tx.execute(
                "INSERT INTO attachments(id, session_id, source_locator, media_type, size,
                 sha256, raw_ref) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    attachment.id.to_string(),
                    input.session.id.to_string(),
                    attachment.source_locator,
                    attachment.media_type,
                    attachment.size as i64,
                    attachment.sha256.as_str(),
                    attachment.raw_ref.as_str(),
                ],
            )?;
        }
        for record in input.source_records {
            let record_id = Uuid::new_v5(
                &input.session.id,
                format!("{}:{}", record.source_locator, record.snapshot_id).as_bytes(),
            );
            tx.execute(
                "INSERT OR REPLACE INTO source_records(id, raw_sha256, session_id, source_locator,
                 source_record_id, ordinal, cas_object_id, adapter_version, snapshot_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    record_id.to_string(),
                    record.raw_sha256.as_str(),
                    input.session.id.to_string(),
                    record.source_locator,
                    record.source_record_id,
                    record.ordinal as i64,
                    record.cas_object_id,
                    record.adapter_version,
                    record.snapshot_id,
                ],
            )?;
        }
        for finding in input.findings {
            tx.execute(
                "INSERT INTO secret_findings(session_id, class, rule_version, start_offset,
                 end_offset) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    input.session.id.to_string(),
                    finding.class.label(),
                    finding.rule_version,
                    finding.start as i64,
                    finding.end as i64,
                ],
            )?;
        }
        tx.execute(
            "INSERT INTO session_fts(session_id, title, body) VALUES (?1, ?2, ?3)",
            params![
                input.session.id.to_string(),
                input.sanitized_title,
                input.sanitized_body
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn record_quarantine(&mut self, record: QuarantineRecord) -> Result<(), IndexError> {
        self.connection_mut().execute(
            "INSERT INTO quarantines(id, scan_id, source_locator, fingerprint, reason_code,
             raw_sha256, cas_object_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.id.to_string(),
                record.scan_id.to_string(),
                record.source_locator,
                record.fingerprint,
                record.reason_code,
                record.raw_sha256.as_str(),
                record.cas_object_id,
            ],
        )?;
        Ok(())
    }

    fn finish_scan(&mut self, manifest: &ScanManifest) -> Result<(), IndexError> {
        self.connection_mut().execute(
            "UPDATE scan_runs SET status = ?1, completed_at = ?2, indexed_count = ?3,
             quarantined_count = ?4, retryable_count = ?5, rejected_count = ?6 WHERE id = ?7",
            params![
                scan_status_label(manifest.status),
                manifest.completed_at,
                manifest.indexed_count as i64,
                manifest.quarantined_count as i64,
                manifest.retryable_count as i64,
                manifest.rejected_count as i64,
                manifest.id.to_string(),
            ],
        )?;
        self.set_active_scan_id(None);
        Ok(())
    }

    fn fail_scan(&mut self, scan_id: Uuid) -> Result<(), IndexError> {
        let tx = self.connection_mut().transaction()?;
        tx.execute(
            "UPDATE scan_runs SET status = 'failed', completed_at = ?1 WHERE id = ?2",
            params![now_string(), scan_id.to_string()],
        )?;
        tx.commit()?;
        self.set_active_scan_id(None);
        Ok(())
    }

    fn mark_sessions_stale(&mut self, session_ids: &[Uuid]) -> Result<(), IndexError> {
        let tx = self.connection_mut().transaction()?;
        for session_id in session_ids {
            tx.execute(
                "UPDATE sessions SET stale = 1 WHERE id = ?1",
                params![session_id.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn mark_source_sessions_stale(
        &mut self,
        install_id: Uuid,
        source_session_ids: &[String],
    ) -> Result<(), IndexError> {
        let tx = self.connection_mut().transaction()?;
        for source_session_id in source_session_ids {
            tx.execute(
                "UPDATE sessions SET stale = 1
                 WHERE install_id = ?1 AND source_session_id = ?2",
                params![install_id.to_string(), source_session_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn verification_snapshot(
        &self,
        scan_id: Uuid,
    ) -> Result<Option<crate::VerificationSnapshot>, IndexError> {
        Ok(Some(IndexDb::verification_snapshot(self, scan_id)?))
    }

    fn record_verification(&mut self, record: VerificationRecord) -> Result<(), IndexError> {
        self.connection_mut().execute(
            "INSERT INTO verification_records(
               scan_id, object_id, object_type, plaintext_hash, size,
               session_json, canonical_hash, sanitized_title, sanitized_body
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(scan_id, object_id) DO UPDATE SET
               object_type=excluded.object_type,
               plaintext_hash=excluded.plaintext_hash,
               size=excluded.size,
               session_json=COALESCE(excluded.session_json, verification_records.session_json),
               canonical_hash=COALESCE(excluded.canonical_hash, verification_records.canonical_hash),
               sanitized_title=COALESCE(excluded.sanitized_title, verification_records.sanitized_title),
               sanitized_body=COALESCE(excluded.sanitized_body, verification_records.sanitized_body)",
            params![
                record.scan_id.to_string(),
                record.object_id,
                i64::from(record.object_type),
                record.plaintext_hash.as_str(),
                record.size as i64,
                record.session_json,
                record.canonical_hash.map(|hash| hash.as_str().to_owned()),
                record.sanitized_title,
                record.sanitized_body,
            ],
        )?;
        Ok(())
    }
}

fn insert_tool_event(
    tx: &rusqlite::Transaction<'_>,
    session_id: Uuid,
    event: &ToolEvent,
) -> Result<(), IndexError> {
    tx.execute(
        "INSERT INTO tool_events(id, session_id, ordinal, tool_name, status, visible_input,
         visible_output, raw_ref) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            event.id,
            session_id.to_string(),
            event.ordinal as i64,
            event.tool_name,
            event.status,
            event.visible_input,
            event.visible_output,
            event.raw_ref.as_str(),
        ],
    )?;
    Ok(())
}

fn completeness_label(value: &Completeness) -> &'static str {
    match value {
        Completeness::Complete => "complete",
        Completeness::Partial => "partial",
        Completeness::Quarantined => "quarantined",
    }
}

fn scan_status_label(value: ScanManifestStatus) -> &'static str {
    match value {
        ScanManifestStatus::Complete => "complete",
        ScanManifestStatus::Partial => "partial",
        ScanManifestStatus::Failed => "failed",
    }
}

fn now_string() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}
