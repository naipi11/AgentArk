use std::fs;

use agentark_adapter_sdk::{DetectContext, SourceAdapter};
use agentark_adapter_synthetic::SyntheticAdapter;
use agentark_app::{ScanRequest, ScanService, ScanStatus, VerificationService};
use agentark_cas::EncryptedCas;
use agentark_index::{IndexDb, SessionQuery};
use agentark_security::{DatasetBootstrap, MemoryMasterKeyStore, SecretScanner};
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn local_read_only_vertical_is_idempotent_and_detects_cas_tamper() {
    let source = tempdir().unwrap();
    SyntheticAdapter::write_fixture_set(source.path()).unwrap();
    let before = SyntheticAdapter::tree_digest(source.path()).unwrap();
    let dataset = tempdir().unwrap();
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
    let keys = bootstrap.unlock(&store).unwrap();
    let cas_root = dataset.path().join("cas");
    let db_path = dataset.path().join("dataset.db");
    let adapter = SyntheticAdapter::new(source.path()).unwrap();
    let install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![source.path().to_path_buf()],
            allow_detected_home: false,
        })
        .unwrap()
        .pop()
        .unwrap();
    let cas = EncryptedCas::open(cas_root, &keys).unwrap();
    let index = IndexDb::open(&db_path, keys.sqlcipher_key()).unwrap();
    let mut first = ScanService::new(adapter, cas, index, SecretScanner::v1().unwrap());
    let report1 = first
        .run(ScanRequest {
            install: install.clone(),
            snapshot_hint: None,
        })
        .unwrap();
    assert_eq!(report1.status, ScanStatus::Partial);
    let (_adapter, cas, index, _journal) = first.into_parts();
    let adapter = SyntheticAdapter::new(source.path()).unwrap();
    let mut second = ScanService::new(adapter, cas, index, SecretScanner::v1().unwrap());
    let report2 = second
        .run(ScanRequest {
            install,
            snapshot_hint: None,
        })
        .unwrap();
    assert_eq!(second.index().list_sessions(50, 0).unwrap().len(), 2);
    let (_adapter, cas, index, _journal) = second.into_parts();
    assert!(
        VerificationService::new(&cas, &index)
            .verify_scan(report2.scan_id)
            .unwrap()
            .passed
    );
    let object = index
        .verification_records(report2.scan_id)
        .unwrap()
        .remove(0);
    let path = cas.object_path(&object.object_id);
    let mut ciphertext = fs::read(&path).unwrap();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 1;
    fs::write(path, ciphertext).unwrap();
    let tampered = VerificationService::new(&cas, &index)
        .verify_scan(report2.scan_id)
        .unwrap();
    assert!(!tampered.passed);
    assert_eq!(tampered.failures[0].code, "cas-authentication-failed");
    assert_eq!(
        SyntheticAdapter::tree_digest(source.path()).unwrap(),
        before
    );
}
