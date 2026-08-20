use agentark_security::{DatasetBootstrap, MasterKeyStore, MemoryMasterKeyStore, SecurityError};
use uuid::Uuid;

struct UnavailableStore;

impl MasterKeyStore for UnavailableStore {
    fn load(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, SecurityError> {
        Err(SecurityError::MasterKeyStoreUnavailable)
    }

    fn store(&self, _key: &[u8; 32]) -> Result<(), SecurityError> {
        panic!("must not replace an unavailable key store");
    }
}

#[test]
fn creates_and_unlocks_wrapped_dataset_keys_without_plaintext_metadata() {
    let store = MemoryMasterKeyStore::empty();
    let dataset_id = Uuid::parse_str("018f8e42-89e0-7d35-b52a-1c8f7e98c010").unwrap();
    let bootstrap = DatasetBootstrap::create(dataset_id, &store).unwrap();
    let json = serde_json::to_string(&bootstrap).unwrap();
    assert!(!json.contains("source-root"));
    assert!(!json.contains("session-title"));
    let first = bootstrap.unlock(&store).unwrap();
    let second = bootstrap.unlock(&store).unwrap();
    assert_eq!(first.sqlcipher_key(), second.sqlcipher_key());
    assert_ne!(first.sqlcipher_key(), first.cas_aead_key());
    assert_eq!(first.dataset_id(), dataset_id);
}

#[test]
fn missing_master_key_never_falls_back_to_plaintext() {
    let creator = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &creator).unwrap();
    let missing = MemoryMasterKeyStore::empty();
    assert!(matches!(
        bootstrap.unlock(&missing),
        Err(SecurityError::MasterKeyUnavailable)
    ));
}

#[test]
fn unavailable_master_key_store_never_creates_a_replacement() {
    assert!(matches!(
        DatasetBootstrap::create(Uuid::new_v4(), &UnavailableStore),
        Err(SecurityError::MasterKeyStoreUnavailable)
    ));
}

#[test]
fn rejects_unknown_bootstrap_format_version() {
    let store = MemoryMasterKeyStore::empty();
    let mut bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &store).unwrap();
    bootstrap.format_version = 2;
    assert!(matches!(
        bootstrap.unlock(&store),
        Err(SecurityError::KeyOperationFailed)
    ));
}
