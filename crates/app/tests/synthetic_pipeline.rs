use agentark_adapter_sdk::{DetectContext, SourceAdapter};
use agentark_adapter_synthetic::SyntheticAdapter;
use agentark_app::{ScanRequest, ScanService, ScanStatus, VerificationService};
use agentark_cas::EncryptedCas;
use agentark_index::{IndexDb, SessionQuery};
use agentark_security::{DatasetBootstrap, MemoryMasterKeyStore, SecretScanner};
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn synthetic_scan_publishes_only_normalized_sessions() {
    let root = tempdir().unwrap();
    SyntheticAdapter::write_fixture_set(root.path()).unwrap();
    let adapter = SyntheticAdapter::new(root.path()).unwrap();
    let install = adapter
        .detect(&DetectContext {
            explicit_roots: vec![root.path().to_path_buf()],
            allow_detected_home: false,
        })
        .unwrap()
        .pop()
        .unwrap();
    let store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
    let keys = bootstrap.unlock(&store).unwrap();
    let cas = EncryptedCas::open(root.path().join("cas"), &keys).unwrap();
    let db_path = root.path().join("index.db");
    let index = IndexDb::open(&db_path, keys.sqlcipher_key()).unwrap();
    let mut service = ScanService::new(adapter, cas, index, SecretScanner::v1().unwrap());
    let report = service
        .run(ScanRequest {
            install,
            snapshot_hint: None,
        })
        .unwrap();
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.indexed, 2);
    assert_eq!(report.quarantined, 1);
    assert_eq!(report.retryable, 1);
    assert_eq!(service.index().list_sessions(10, 0).unwrap().len(), 2);
    assert_eq!(service.index().search("world", 10).unwrap().len(), 2);
    let scan_id = report.scan_id;
    let (_adapter, cas, index, _journal) = service.into_parts();
    let durable_report = VerificationService::new(cas, index)
        .verify_scan(scan_id)
        .unwrap();
    assert!(durable_report.passed);
}
