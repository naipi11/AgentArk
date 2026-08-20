use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use agentark_app::{VerificationJournal, VerificationService};
use agentark_canonical::{
    CanonicalMessage, CanonicalSchemaVersion, CanonicalSession, Completeness, Sha256Digest,
    canonical_hash,
};
use agentark_cas::{ArtifactStore, CasError, ObjectType, StoredObject};
use agentark_index::{IndexedSession, VerificationRecord, VerificationSnapshot};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone)]
struct TamperingCas {
    tampered: Arc<AtomicBool>,
}

impl ArtifactStore for TamperingCas {
    fn put(&self, object_type: ObjectType, plaintext: &[u8]) -> Result<StoredObject, CasError> {
        Ok(StoredObject {
            object_id: "object-1".into(),
            object_type,
            plaintext_hash: Sha256Digest::from_bytes(plaintext),
            size: plaintext.len() as u64,
        })
    }

    fn get(&self, _object: &StoredObject) -> Result<Zeroizing<Vec<u8>>, CasError> {
        if self.tampered.load(Ordering::Relaxed) {
            Err(CasError::AuthenticationFailed)
        } else {
            Ok(Zeroizing::new(b"raw".to_vec()))
        }
    }
}

#[test]
fn verification_reports_cas_authentication_failure_without_plaintext() {
    let scan_id = Uuid::new_v4();
    let object = StoredObject {
        object_id: "object-1".into(),
        object_type: ObjectType::AgentRawRecord,
        plaintext_hash: Sha256Digest::from_bytes(b"raw"),
        size: 3,
    };
    let journal = VerificationJournal::default();
    journal.record(scan_id, object);
    let tampered = Arc::new(AtomicBool::new(true));
    let verifier = VerificationService::new(
        TamperingCas {
            tampered: tampered.clone(),
        },
        journal,
    );
    let report = verifier.verify_scan(scan_id).unwrap();
    assert!(!report.passed);
    assert_eq!(report.failures[0].code, "cas-authentication-failed");
    assert!(!serde_json::to_string(&report).unwrap().contains("raw"));
}

#[test]
fn verification_rejects_an_unknown_scan_id() {
    let verifier = VerificationService::new(
        TamperingCas {
            tampered: Arc::new(AtomicBool::new(false)),
        },
        VerificationJournal::default(),
    );
    let report = verifier.verify_scan(Uuid::new_v4()).unwrap();
    assert!(!report.passed);
    assert_eq!(report.failures[0].code, "scan-not-found");
}

#[test]
fn verification_rejects_persisted_ordinals_that_differ_from_canonical() {
    let scan_id = Uuid::new_v4();
    let canonical = CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id: Uuid::new_v4(),
        install_id: Uuid::new_v4(),
        source_session_id: "ordinal-fixture".into(),
        source_kind: "fixture".into(),
        workspace: None,
        title: None,
        archived: false,
        created_at_raw: None,
        updated_at_raw: None,
        model_provider: None,
        model_name: None,
        completeness: Completeness::Complete,
        messages: vec![
            CanonicalMessage::text_fixture(1, "same", "first"),
            CanonicalMessage::text_fixture(2, "same", "second"),
        ],
        tool_events: Vec::new(),
        attachments: Vec::new(),
        raw_extra: Default::default(),
    };
    let canonical_json = serde_json::to_string(&canonical).unwrap();
    let canonical_hash = canonical_hash("session", &canonical).unwrap();
    let object = StoredObject {
        object_id: "object-ordinal".into(),
        object_type: ObjectType::AgentRawRecord,
        plaintext_hash: Sha256Digest::from_bytes(b"raw"),
        size: 3,
    };
    let snapshot = VerificationSnapshot {
        status: "complete".into(),
        indexed_count: 1,
        quarantined_count: 0,
        retryable_count: 0,
        rejected_count: 0,
        records: vec![VerificationRecord {
            scan_id,
            object_id: object.object_id.clone(),
            object_type: object.object_type.as_byte(),
            plaintext_hash: object.plaintext_hash.clone(),
            size: object.size,
            session_json: Some(canonical_json.clone()),
            canonical_hash: Some(canonical_hash.clone()),
            sanitized_title: Some(String::new()),
            sanitized_body: Some("first\nsecond".into()),
        }],
        sessions: vec![IndexedSession {
            id: canonical.id,
            canonical_json,
            canonical_hash,
            search_title: String::new(),
            search_body: "first\nsecond".into(),
            fts_title: Some(String::new()),
            fts_body: Some("first\nsecond".into()),
            message_ordinals: vec![1, 3],
            tool_event_ordinals: Vec::new(),
        }],
    };
    let report = VerificationService::new(
        TamperingCas {
            tampered: Arc::new(AtomicBool::new(false)),
        },
        snapshot,
    )
    .verify_scan(scan_id)
    .unwrap();
    assert!(!report.passed);
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.code == "indexed-session-mismatch")
    );
}
