use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

use agentark_canonical::Sha256Digest;
use agentark_security::DatasetKeys;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{CasError, MAGIC, ObjectType};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredObject {
    pub object_id: String,
    pub object_type: ObjectType,
    pub plaintext_hash: Sha256Digest,
    pub size: u64,
}

pub trait ArtifactStore {
    fn put(&self, object_type: ObjectType, plaintext: &[u8]) -> Result<StoredObject, CasError>;
    fn get(&self, object: &StoredObject) -> Result<Zeroizing<Vec<u8>>, CasError>;
}

pub struct EncryptedCas {
    root: PathBuf,
    dataset_id: Uuid,
    aead_key: Zeroizing<[u8; 32]>,
    object_id_key: Zeroizing<[u8; 32]>,
}

impl EncryptedCas {
    pub fn open(root: PathBuf, keys: &DatasetKeys) -> Result<Self, CasError> {
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            dataset_id: keys.dataset_id(),
            aead_key: Zeroizing::new(*keys.cas_aead_key()),
            object_id_key: Zeroizing::new(*keys.object_id_key()),
        })
    }

    pub fn object_path(&self, object_id: &str) -> PathBuf {
        self.root
            .join("v1")
            .join(&object_id[..2.min(object_id.len())])
            .join(object_id)
    }

    fn object_id(&self, digest: &[u8; 32]) -> Result<String, CasError> {
        let mut mac =
            HmacSha256::new_from_slice(&*self.object_id_key).map_err(|_| CasError::HashMismatch)?;
        mac.update(digest);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn associated_data(&self, object_type: ObjectType, object_id: &str) -> Vec<u8> {
        format!(
            "agentark:v1:cas:{}:{}:{}",
            self.dataset_id,
            object_type.as_byte(),
            object_id
        )
        .into_bytes()
    }

    fn read_verified(&self, object: &StoredObject) -> Result<Zeroizing<Vec<u8>>, CasError> {
        let bytes = Zeroizing::new(fs::read(self.object_path(&object.object_id))?);
        if bytes.len() < MAGIC.len() + 1 + 24 + 16 || &bytes[..MAGIC.len()] != MAGIC {
            return Err(CasError::InvalidFormat);
        }
        let object_type = ObjectType::from_byte(bytes[MAGIC.len()])?;
        if object_type != object.object_type {
            return Err(CasError::HashMismatch);
        }
        let nonce_start = MAGIC.len() + 1;
        let nonce_end = nonce_start + 24;
        let nonce = XNonce::try_from(&bytes[nonce_start..nonce_end])
            .map_err(|_| CasError::InvalidFormat)?;
        let cipher = XChaCha20Poly1305::new((&*self.aead_key).into());
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &bytes[nonce_end..],
                    aad: &self.associated_data(object.object_type, &object.object_id),
                },
            )
            .map_err(|_| CasError::AuthenticationFailed)?;
        let plaintext = Zeroizing::new(plaintext);
        if plaintext.len() as u64 != object.size {
            return Err(CasError::HashMismatch);
        }
        let digest = Sha256::digest(&*plaintext);
        let digest_slice: &[u8] = digest.as_ref();
        let digest_bytes: [u8; 32] = digest_slice
            .try_into()
            .map_err(|_| CasError::HashMismatch)?;
        if Sha256Digest::from_bytes(&plaintext) != object.plaintext_hash
            || self.object_id(&digest_bytes)? != object.object_id
        {
            return Err(CasError::HashMismatch);
        }
        Ok(plaintext)
    }
}

impl ArtifactStore for EncryptedCas {
    fn put(&self, object_type: ObjectType, plaintext: &[u8]) -> Result<StoredObject, CasError> {
        let digest = Sha256::digest(plaintext);
        let digest_slice: &[u8] = digest.as_ref();
        let digest_bytes: [u8; 32] = digest_slice
            .try_into()
            .map_err(|_| CasError::HashMismatch)?;
        let plaintext_hash = Sha256Digest::from_bytes(plaintext);
        let object_id = self.object_id(&digest_bytes)?;
        let object = StoredObject {
            object_id: object_id.clone(),
            object_type,
            plaintext_hash,
            size: plaintext.len() as u64,
        };
        let final_path = self.object_path(&object_id);
        if final_path.exists() {
            let existing = self.read_verified(&object)?;
            if existing.as_slice() != plaintext {
                return Err(CasError::ObjectCollision);
            }
            return Ok(object);
        }
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).map_err(|_| CasError::AuthenticationFailed)?;
        let nonce =
            XNonce::try_from(nonce_bytes.as_slice()).map_err(|_| CasError::InvalidFormat)?;
        let cipher = XChaCha20Poly1305::new((&*self.aead_key).into());
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &self.associated_data(object_type, &object_id),
                },
            )
            .map_err(|_| CasError::AuthenticationFailed)?;
        let temp_path = self.root.join(format!(".tmp-{}", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(MAGIC)?;
        file.write_all(&[object_type.as_byte()])?;
        file.write_all(&nonce_bytes)?;
        file.write_all(&ciphertext)?;
        file.sync_all()?;
        drop(file);
        match fs::rename(&temp_path, &final_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temp_path)?;
                let existing = self.read_verified(&object)?;
                if existing.as_slice() != plaintext {
                    return Err(CasError::ObjectCollision);
                }
            }
            Err(error) => {
                let _ = fs::remove_file(&temp_path);
                return Err(CasError::Io(error));
            }
        }
        Ok(object)
    }

    fn get(&self, object: &StoredObject) -> Result<Zeroizing<Vec<u8>>, CasError> {
        self.read_verified(object)
    }
}
