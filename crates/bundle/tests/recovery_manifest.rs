use std::collections::BTreeMap;
use std::io::Write;

use agentark_bundle::{NativeBundleEntry, read_bundle, write_selected_sessions_with_native};
use agentark_canonical::{CanonicalSchemaVersion, CanonicalSession, Completeness};
use agentark_security::SecretScanner;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn writes_recovery_metadata_without_provider_secrets() {
    let bundle = write_codex_bundle_with(
        "custom",
        "claude",
        "api_key=fixture-secret-value",
        one_native_payload(),
    );
    let manifest = bundle.recovery_manifest().unwrap().unwrap();
    assert_eq!(manifest.version, "1");
    assert_eq!(
        manifest.sessions[0].source_provider.as_deref(),
        Some("custom")
    );
    assert_eq!(manifest.sessions[0].source_model.as_deref(), Some("claude"));
    assert_eq!(manifest.sessions[0].native_payload_count, 1);
    let entry = bundle.entries.get("recovery/manifest.json").unwrap();
    assert!(!String::from_utf8_lossy(entry).contains("fixture-secret-value"));
}

#[test]
fn omits_secret_and_endpoint_shaped_model_labels() {
    let provider_secret = "api_key=provider-label-secret-value";
    let model_endpoint = "https://private-model-endpoint.example/v1";
    let bundle = write_codex_bundle_with(
        provider_secret,
        model_endpoint,
        "api_key=fixture-secret-value",
        one_native_payload(),
    );
    let manifest = bundle.recovery_manifest().unwrap().unwrap();
    assert_eq!(manifest.sessions[0].source_provider, None);
    assert_eq!(manifest.sessions[0].source_model, None);
    let entry = bundle.entries.get("recovery/manifest.json").unwrap();
    let entry = String::from_utf8_lossy(entry);
    assert!(!entry.contains(provider_secret));
    assert!(!entry.contains(model_endpoint));
    assert!(!entry.contains("[REDACTED:"));
}

#[test]
fn omits_endpoint_shaped_labels_without_schemes() {
    let bundle = write_codex_bundle_with(
        "localhost:8080",
        "private-model-endpoint.example/v1",
        "api_key=fixture-secret-value",
        one_native_payload(),
    );
    let manifest = bundle.recovery_manifest().unwrap().unwrap();
    assert_eq!(manifest.sessions[0].source_provider, None);
    assert_eq!(manifest.sessions[0].source_model, None);
}

#[test]
fn retains_ordinary_dotted_provider_and_model_labels() {
    let bundle = write_codex_bundle_with(
        "gpt-5.1",
        "claude-3.5",
        "api_key=fixture-secret-value",
        one_native_payload(),
    );
    let manifest = bundle.recovery_manifest().unwrap().unwrap();
    assert_eq!(
        manifest.sessions[0].source_provider.as_deref(),
        Some("gpt-5.1")
    );
    assert_eq!(
        manifest.sessions[0].source_model.as_deref(),
        Some("claude-3.5")
    );
}

#[test]
fn old_bundle_has_no_recovery_manifest() {
    let bundle = read_fixture_with_format("1.1");
    assert_eq!(bundle.recovery_manifest().unwrap(), None);
}

fn one_native_payload() -> Vec<u8> {
    b"{\"type\":\"session_meta\"}\n".to_vec()
}

fn write_codex_bundle_with(
    source_provider: &str,
    source_model: &str,
    provider_configuration: &str,
    native_payload: Vec<u8>,
) -> agentark_bundle::Bundle {
    let root = tempdir().unwrap();
    let bundle_path = root.path().join("recovery.ahbundle");
    let session = CanonicalSession {
        schema_version: CanonicalSchemaVersion::V0_1_0,
        id: Uuid::new_v4(),
        install_id: Uuid::new_v4(),
        source_session_id: "recovery-session".into(),
        source_kind: "codex".into(),
        workspace: None,
        title: None,
        archived: false,
        created_at_raw: None,
        updated_at_raw: None,
        model_provider: Some(source_provider.into()),
        model_name: Some(source_model.into()),
        completeness: Completeness::Complete,
        messages: vec![],
        tool_events: vec![],
        attachments: vec![],
        raw_extra: BTreeMap::from([(
            "providerConfiguration".into(),
            json!({"apiKey": provider_configuration, "endpoint": "https://private.example"}),
        )]),
    };
    write_selected_sessions_with_native(
        &bundle_path,
        "codex",
        std::slice::from_ref(&session),
        &[],
        &[NativeBundleEntry {
            session_id: session.id,
            relative_path: "2026/08/23/rollout-native.jsonl".into(),
            bytes: native_payload,
            redaction_count: 0,
        }],
        &SecretScanner::v1().unwrap(),
    )
    .unwrap();
    read_bundle(&bundle_path).unwrap()
}

fn read_fixture_with_format(format: &str) -> agentark_bundle::Bundle {
    let root = tempdir().unwrap();
    let bundle_path = root.path().join("old.ahbundle");
    let manifest = json!({
        "format": format,
        "createdAt": "2026-08-23T00:00:00Z",
        "sessionCount": 0,
        "redacted": false,
        "redactionCount": 0,
        "entries": []
    });
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let mut file = std::fs::File::create(&bundle_path).unwrap();
    file.write_all(b"AHBUNDLE1").unwrap();
    file.write_all(&1u32.to_le_bytes()).unwrap();
    file.write_all(&("manifest.json".len() as u32).to_le_bytes())
        .unwrap();
    file.write_all(b"manifest.json").unwrap();
    file.write_all(&(bytes.len() as u64).to_le_bytes()).unwrap();
    file.write_all(Sha256::digest(&bytes).as_slice()).unwrap();
    file.write_all(&bytes).unwrap();
    drop(file);
    read_bundle(&bundle_path).unwrap()
}
