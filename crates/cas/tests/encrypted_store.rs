use std::fs;

use agentark_cas::{ArtifactStore, EncryptedCas, ObjectType};
use agentark_security::{DatasetBootstrap, MemoryMasterKeyStore};
use tempfile::tempdir;
use uuid::Uuid;

fn store() -> (tempfile::TempDir, EncryptedCas) {
    let dir = tempdir().unwrap();
    let key_store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &key_store).unwrap();
    let keys = bootstrap.unlock(&key_store).unwrap();
    let cas = EncryptedCas::open(dir.path().join("objects"), &keys).unwrap();
    (dir, cas)
}

#[test]
fn encrypts_round_trips_and_deduplicates() {
    let (_dir, cas) = store();
    let first = cas
        .put(ObjectType::AgentRawRecord, b"canary plaintext")
        .unwrap();
    let second = cas
        .put(ObjectType::AgentRawRecord, b"canary plaintext")
        .unwrap();
    assert_eq!(first.object_id, second.object_id);
    assert_eq!(&*cas.get(&first).unwrap(), b"canary plaintext");
    let bytes = fs::read(cas.object_path(&first.object_id)).unwrap();
    assert!(
        !bytes
            .windows(b"canary plaintext".len())
            .any(|window| window == b"canary plaintext")
    );
}

#[test]
fn rejects_tampered_ciphertext() {
    let (_dir, cas) = store();
    let object = cas.put(ObjectType::AgentRawRecord, b"record").unwrap();
    let path = cas.object_path(&object.object_id);
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(path, bytes).unwrap();
    assert!(cas.get(&object).is_err());
}
