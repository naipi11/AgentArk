use agentark_canonical::{Sha256Digest, agent_install_id, canonical_hash, message_id, session_id};
use serde::Serialize;
use serde_json::{Map, Value};
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
    assert_eq!(install.to_string(), "6cbb4aa8-a0ec-5855-8f90-cc73a3ecb980");
    assert_eq!(session.to_string(), "74488c15-b9ac-5572-b6cd-94eca4eaa7a9");
    assert_eq!(
        message_id(session, Some("item_1"), 1, &raw).to_string(),
        "a9c86930-ddd6-538c-949b-82762e81709c"
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

#[test]
fn canonical_hash_uses_jcs_key_order_and_known_answer() {
    let mut first = Map::new();
    first.insert("b".into(), Value::from(7));
    first.insert("a".into(), Value::from("x"));
    let mut second = Map::new();
    second.insert("a".into(), Value::from("x"));
    second.insert("b".into(), Value::from(7));
    let first_hash = canonical_hash("session", &first).unwrap();
    let second_hash = canonical_hash("session", &second).unwrap();
    assert_eq!(first_hash, second_hash);
    assert_eq!(
        first_hash.as_str(),
        "sha256:507bd3957d5890938190600e935dc1b7c4d6b319a6f8735eb53fd99038dc16e1"
    );
}
