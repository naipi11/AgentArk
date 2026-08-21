use uuid::Uuid;

use crate::Sha256Digest;

const AGENTARK_NAMESPACE: Uuid = Uuid::from_u128(0xd6ba6862_673d_5f83_9df7_64c15b5138e6);

pub fn agent_install_id(machine_id: Uuid, agent_kind: &str, canonical_root: &str) -> Uuid {
    Uuid::new_v5(
        &AGENTARK_NAMESPACE,
        format!("install\0{machine_id}\0{agent_kind}\0{canonical_root}").as_bytes(),
    )
}

pub fn session_id(install_id: Uuid, source_session_id: &str) -> Uuid {
    Uuid::new_v5(
        &AGENTARK_NAMESPACE,
        format!("session\0{install_id}\0{source_session_id}").as_bytes(),
    )
}

pub fn workspace_id(canonical_uri: &str) -> Uuid {
    Uuid::new_v5(
        &AGENTARK_NAMESPACE,
        format!("workspace\0{canonical_uri}").as_bytes(),
    )
}

pub fn message_id(
    session_id: Uuid,
    source_record_id: Option<&str>,
    ordinal: u64,
    raw_hash: &Sha256Digest,
) -> Uuid {
    let source_key = source_record_id
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{ordinal}\0{}", raw_hash.as_str()));
    Uuid::new_v5(
        &AGENTARK_NAMESPACE,
        format!("message\0{session_id}\0{source_key}").as_bytes(),
    )
}
