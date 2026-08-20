use std::collections::BTreeMap;

use agentark_canonical::{
    CanonicalMessage, CanonicalRole, ContentPart, ContentPartKind, Sha256Digest,
};
use serde_json::json;
use uuid::Uuid;

#[test]
fn raw_role_and_unknown_fields_survive_round_trip() {
    let mut raw_extra = BTreeMap::new();
    raw_extra.insert("futureField".into(), json!({"nested": true}));
    let message = CanonicalMessage {
        id: Uuid::nil(),
        source_record_id: None,
        ordinal: 4,
        role: CanonicalRole::Unknown,
        raw_role: Some("critic".into()),
        created_at_raw: Some("not-a-time".into()),
        content: vec![ContentPart {
            kind: ContentPartKind::Text,
            text: Some("visible".into()),
            attachment_id: None,
            raw_extra,
        }],
        raw_ref: Sha256Digest::from_bytes(b"raw"),
    };
    let encoded = serde_json::to_vec(&message).unwrap();
    let decoded: CanonicalMessage = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, message);
}

#[test]
fn ordinal_is_not_derived_from_timestamp() {
    let mut messages = [
        CanonicalMessage::text_fixture(2, "same", "second"),
        CanonicalMessage::text_fixture(1, "same", "first"),
    ];
    messages.sort_by_key(|message| message.ordinal);
    assert_eq!(messages[0].visible_text(), "first");
    assert_eq!(messages[1].visible_text(), "second");
}
