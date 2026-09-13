use agentark_canonical::{CanonicalSession, Sha256Digest, SourceRecord};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RawProvenanceStatus {
    None,
    Available,
    Unresolved,
    Unknown,
}

impl RawProvenanceStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Available => "available",
            Self::Unresolved => "unresolved",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse_storage(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "available" => Some(Self::Available),
            "unresolved" => Some(Self::Unresolved),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

pub fn session_has_raw_references(session: &CanonicalSession) -> bool {
    !session.messages.is_empty()
        || !session.tool_events.is_empty()
        || !session.attachments.is_empty()
}

pub fn session_raw_provenance_status(
    session: &CanonicalSession,
    source_records: &[SourceRecord],
) -> RawProvenanceStatus {
    if !session_has_raw_references(session) {
        return RawProvenanceStatus::None;
    }

    let raw_hashes = source_records
        .iter()
        .map(|record| record.raw_sha256.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut references = session
        .messages
        .iter()
        .map(|message| &message.raw_ref)
        .chain(session.tool_events.iter().map(|event| &event.raw_ref))
        .chain(
            session
                .attachments
                .iter()
                .map(|attachment| &attachment.raw_ref),
        );
    if references.all(|reference| {
        Sha256Digest::parse(reference.as_str()).is_some() && raw_hashes.contains(reference.as_str())
    }) {
        RawProvenanceStatus::Available
    } else {
        RawProvenanceStatus::Unresolved
    }
}
