#![forbid(unsafe_code)]

mod hash;
mod ids;
mod model;

pub use hash::{CanonicalHashError, Sha256Digest, canonical_hash};
pub use ids::{agent_install_id, message_id, session_id};
pub use model::{
    AgentInstall, AgentKind, Attachment, CANONICAL_SCHEMA_VERSION, CanonicalMessage, CanonicalRole,
    CanonicalSchemaVersion, CanonicalSession, Completeness, ContentPart, ContentPartKind,
    SourceRecord, ToolEvent, Workspace,
};
