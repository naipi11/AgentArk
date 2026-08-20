use std::sync::{Arc, Mutex};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::SecurityError;

pub trait MasterKeyStore: Send + Sync {
    fn load(&self) -> Result<Zeroizing<[u8; 32]>, SecurityError>;
    fn store(&self, key: &[u8; 32]) -> Result<(), SecurityError>;
}

#[derive(Clone, Default)]
pub struct MemoryMasterKeyStore {
    key: Arc<Mutex<Option<[u8; 32]>>>,
}

impl MemoryMasterKeyStore {
    pub fn empty() -> Self {
        Self::default()
    }
}

impl MasterKeyStore for MemoryMasterKeyStore {
    fn load(&self) -> Result<Zeroizing<[u8; 32]>, SecurityError> {
        let guard = self
            .key
            .lock()
            .map_err(|_| SecurityError::KeyOperationFailed)?;
        guard
            .as_ref()
            .copied()
            .map(Zeroizing::new)
            .ok_or(SecurityError::MasterKeyUnavailable)
    }

    fn store(&self, key: &[u8; 32]) -> Result<(), SecurityError> {
        let mut guard = self
            .key
            .lock()
            .map_err(|_| SecurityError::KeyOperationFailed)?;
        *guard = Some(*key);
        Ok(())
    }
}

pub struct OsMasterKeyStore {
    entry: keyring::Entry,
}

impl OsMasterKeyStore {
    pub fn new(machine_id: Uuid) -> Result<Self, SecurityError> {
        let entry = keyring::Entry::new("dev.agentark.master-key", &machine_id.to_string())
            .map_err(|_| SecurityError::KeyOperationFailed)?;
        Ok(Self { entry })
    }
}

impl MasterKeyStore for OsMasterKeyStore {
    fn load(&self) -> Result<Zeroizing<[u8; 32]>, SecurityError> {
        let bytes = self
            .entry
            .get_secret()
            .map_err(|_| SecurityError::MasterKeyUnavailable)?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SecurityError::InvalidMasterKeyLength)?;
        Ok(Zeroizing::new(key))
    }

    fn store(&self, key: &[u8; 32]) -> Result<(), SecurityError> {
        self.entry
            .set_secret(key)
            .map_err(|_| SecurityError::KeyOperationFailed)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatasetBootstrap {
    pub format_version: u32,
    pub dataset_id: Uuid,
    pub wrap_nonce_hex: String,
    pub wrapped_dataset_key_hex: String,
}

pub struct DatasetKeys {
    dataset_id: Uuid,
    sqlcipher_key: Zeroizing<[u8; 32]>,
    cas_aead_key: Zeroizing<[u8; 32]>,
    object_id_key: Zeroizing<[u8; 32]>,
}

impl DatasetKeys {
    pub fn dataset_id(&self) -> Uuid {
        self.dataset_id
    }

    pub fn sqlcipher_key(&self) -> &[u8; 32] {
        &self.sqlcipher_key
    }

    pub fn cas_aead_key(&self) -> &[u8; 32] {
        &self.cas_aead_key
    }

    pub fn object_id_key(&self) -> &[u8; 32] {
        &self.object_id_key
    }
}

impl DatasetBootstrap {
    pub fn create(dataset_id: Uuid, store: &dyn MasterKeyStore) -> Result<Self, SecurityError> {
        let master = match store.load() {
            Ok(key) => key,
            Err(SecurityError::MasterKeyUnavailable) => {
                let key = random_key()?;
                store.store(&key)?;
                Zeroizing::new(key)
            }
            Err(error) => return Err(error),
        };
        let dataset_key = random_key()?;
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| SecurityError::KeyOperationFailed)?;
        let cipher = XChaCha20Poly1305::new((&*master).into());
        let aad = format!("agentark:v1:dataset-key:{dataset_id}");
        let nonce =
            XNonce::try_from(nonce.as_slice()).map_err(|_| SecurityError::KeyOperationFailed)?;
        let encrypted = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &dataset_key,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| SecurityError::KeyOperationFailed)?;
        Ok(Self {
            format_version: 1,
            dataset_id,
            wrap_nonce_hex: hex::encode(nonce),
            wrapped_dataset_key_hex: hex::encode(encrypted),
        })
    }

    pub fn unlock(&self, store: &dyn MasterKeyStore) -> Result<DatasetKeys, SecurityError> {
        let master = store.load()?;
        let nonce = decode_fixed::<24>(&self.wrap_nonce_hex)?;
        let ciphertext = hex::decode(&self.wrapped_dataset_key_hex)
            .map_err(|_| SecurityError::KeyOperationFailed)?;
        let cipher = XChaCha20Poly1305::new((&*master).into());
        let aad = format!("agentark:v1:dataset-key:{}", self.dataset_id);
        let nonce =
            XNonce::try_from(nonce.as_slice()).map_err(|_| SecurityError::KeyOperationFailed)?;
        let dataset_key = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| SecurityError::KeyOperationFailed)?;
        let dataset_key: [u8; 32] = dataset_key
            .try_into()
            .map_err(|_| SecurityError::KeyOperationFailed)?;
        Ok(DatasetKeys {
            dataset_id: self.dataset_id,
            sqlcipher_key: derive_key(&dataset_key, self.dataset_id, b"agentark-v1-sqlcipher")?,
            cas_aead_key: derive_key(&dataset_key, self.dataset_id, b"agentark-v1-cas-aead")?,
            object_id_key: derive_key(&dataset_key, self.dataset_id, b"agentark-v1-object-id")?,
        })
    }
}

fn random_key() -> Result<[u8; 32], SecurityError> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|_| SecurityError::KeyOperationFailed)?;
    Ok(key)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], SecurityError> {
    let bytes = hex::decode(value).map_err(|_| SecurityError::KeyOperationFailed)?;
    bytes
        .try_into()
        .map_err(|_| SecurityError::KeyOperationFailed)
}

fn derive_key(
    dataset_key: &[u8; 32],
    dataset_id: Uuid,
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, SecurityError> {
    let hkdf = Hkdf::<Sha256>::new(Some(dataset_id.as_bytes()), dataset_key);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, &mut *output)
        .map_err(|_| SecurityError::KeyOperationFailed)?;
    Ok(output)
}
