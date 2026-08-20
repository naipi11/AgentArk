use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use agentark_app::{VerificationJournal, VerificationService};
use agentark_canonical::Sha256Digest;
use agentark_cas::{ArtifactStore, CasError, ObjectType, StoredObject};
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
