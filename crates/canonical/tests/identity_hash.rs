use agentark_canonical::{Sha256Digest, agent_install_id, canonical_hash, message_id, session_id};
use serde::Serialize;
use uuid::Uuid;

#[test]
fn identities_are_stable_and_message_ordinals_are_distinct() {
    let machine = Uuid::parse_str("018f8e42-89e0-7d35-b52a-1c8f7e98c001").unwrap();
    let install = agent_install_id(machine, "codex", "file:///C:/Users/test/.codex");
    assert_eq!(
        install,
        agent_install_id(machine, "codex", "file:///C:/Users/test/.codex")
    );

    let session = session_id(install, "thr_123");
    let raw = Sha256Digest::from_bytes(b"{\"type\":\"message\"}");
    assert_ne!(
        message_id(session, None, 1, &raw),
        message_id(session, None, 2, &raw)
    );
    assert_eq!(
        message_id(session, Some("item_1"), 1, &raw),
        message_id(session, Some("item_1"), 99, &raw)
    );
}

#[derive(Serialize)]
struct HashFixture {
    b: u64,
    a: &'static str,
}

#[test]
fn canonical_hash_is_key_order_independent_and_domain_separated() {
    let value = HashFixture { b: 7, a: "x" };
    let session_hash = canonical_hash("session", &value).unwrap();
    let message_hash = canonical_hash("message", &value).unwrap();
    assert_ne!(session_hash, message_hash);
    assert!(session_hash.as_str().starts_with("sha256:"));
    assert_eq!(session_hash.as_str().len(), 71);
}
