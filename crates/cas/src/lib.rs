#![forbid(unsafe_code)]

mod error;
mod format;
mod store;

pub use error::CasError;
pub use format::{MAGIC, ObjectType};
pub use store::{ArtifactStore, EncryptedCas, StoredObject};
