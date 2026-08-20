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
    fn load(&self) -> Result<Zeroizing<Vec<u8>>, SecurityError>;
    fn store(&self, key: &[u8; 32]) -> Result<(), SecurityError>;
}

#[derive(Clone, Default)]
pub struct MemoryMasterKeyStore {
    key: Arc<Mutex<Option<Zeroizing<[u8; 32]>>>>,
}

impl MemoryMasterKeyStore {
    pub fn empty() -> Self {
        Self::default()
    }
}

impl MasterKeyStore for MemoryMasterKeyStore {
    fn load(&self) -> Result<Zeroizing<Vec<u8>>, SecurityError> {
        let guard = self
            .key
            .lock()
            .map_err(|_| SecurityError::KeyOperationFailed)?;
        guard
            .as_ref()
            .map(|key| Zeroizing::new(key.to_vec()))
            .ok_or(SecurityError::MasterKeyUnavailable)
    }

    fn store(&self, key: &[u8; 32]) -> Result<(), SecurityError> {
        let mut guard = self
            .key
            .lock()
            .map_err(|_| SecurityError::KeyOperationFailed)?;
        *guard = Some(Zeroizing::new(*key));
        Ok(())
    }
}

pub struct OsMasterKeyStore {
    entry: keyring::Entry,
}

impl OsMasterKeyStore {
    pub fn new(machine_id: Uuid) -> Result<Self, SecurityError> {
        let entry = keyring::Entry::new("dev.agentark.master-key", &machine_id.to_string())
            .map_err(|_| SecurityError::MasterKeyStoreUnavailable)?;
        Ok(Self { entry })
    }
}

impl MasterKeyStore for OsMasterKeyStore {
    fn load(&self) -> Result<Zeroizing<Vec<u8>>, SecurityError> {
        let bytes = self.entry.get_secret().map_err(|error| match error {
            keyring::Error::NoEntry => SecurityError::MasterKeyUnavailable,
            _ => SecurityError::MasterKeyStoreUnavailable,
        })?;
        if bytes.len() != 32 {
            return Err(SecurityError::InvalidMasterKeyLength);
        }
        Ok(Zeroizing::new(bytes))
    }

    fn store(&self, key: &[u8; 32]) -> Result<(), SecurityError> {
        self.entry
            .set_secret(key)
            .map_err(|_| SecurityError::MasterKeyStoreUnavailable)
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
        let master = match load_master_key(store) {
            Ok(key) => key,
            Err(SecurityError::MasterKeyUnavailable) => {
                let key = random_key()?;
                store.store(&key)?;
                key
            }
            Err(error) => return Err(error),
        };
        let dataset_key = random_key()?;
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).map_err(|_| SecurityError::KeyOperationFailed)?;
        let cipher = XChaCha20Poly1305::new((&*master).into());
        let aad = format!("agentark:v1:dataset-key:{dataset_id}");
        let nonce = XNonce::try_from(nonce_bytes.as_slice())
            .map_err(|_| SecurityError::KeyOperationFailed)?;
        let encrypted = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &*dataset_key,
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
        let master = load_master_key(store)?;
        if self.format_version != 1 {
            return Err(SecurityError::KeyOperationFailed);
        }
        let nonce_bytes = decode_fixed::<24>(&self.wrap_nonce_hex)?;
        let ciphertext = Zeroizing::new(
            hex::decode(&self.wrapped_dataset_key_hex)
                .map_err(|_| SecurityError::KeyOperationFailed)?,
        );
        let cipher = XChaCha20Poly1305::new((&*master).into());
        let aad = format!("agentark:v1:dataset-key:{}", self.dataset_id);
        let nonce = XNonce::try_from(nonce_bytes.as_slice())
            .map_err(|_| SecurityError::KeyOperationFailed)?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| SecurityError::KeyOperationFailed)?;
        let mut dataset_key = Zeroizing::new([0u8; 32]);
        if plaintext.len() != dataset_key.len() {
            return Err(SecurityError::KeyOperationFailed);
        }
        dataset_key.copy_from_slice(&plaintext);
        Ok(DatasetKeys {
            dataset_id: self.dataset_id,
            sqlcipher_key: derive_key(&dataset_key, self.dataset_id, b"agentark-v1-sqlcipher")?,
            cas_aead_key: derive_key(&dataset_key, self.dataset_id, b"agentark-v1-cas-aead")?,
            object_id_key: derive_key(&dataset_key, self.dataset_id, b"agentark-v1-object-id")?,
        })
    }
}

fn random_key() -> Result<Zeroizing<[u8; 32]>, SecurityError> {
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *key).map_err(|_| SecurityError::KeyOperationFailed)?;
    Ok(key)
}

fn load_master_key(store: &dyn MasterKeyStore) -> Result<Zeroizing<[u8; 32]>, SecurityError> {
    let bytes = store.load()?;
    if bytes.len() != 32 {
        return Err(SecurityError::InvalidMasterKeyLength);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
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
