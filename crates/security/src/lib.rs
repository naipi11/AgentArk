#![forbid(unsafe_code)]

mod error;
mod path;
mod secrets;

pub use error::SecurityError;
pub use path::{
    AuthorizedRoot, PathClass, classify_windows_path, is_windows_reparse_point,
    validate_relative_lexical,
};
pub use secrets::{SanitizedText, SecretClass, SecretFinding, SecretScanner};
