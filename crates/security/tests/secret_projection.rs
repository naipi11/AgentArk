use agentark_security::{SecretClass, SecretScanner};

#[test]
fn removes_secret_values_but_keeps_classes() {
    let input = concat!(
        "Authorization: Bearer canary_authorization_value\n",
        "api_key = \"sk-proj-CanaryValue123456789012345\"\n",
        "https://canary-user:canary-password@example.invalid/path\n",
        "-----BEGIN PRIVATE KEY-----\ncanary\n-----END PRIVATE KEY-----",
    );
    let sanitized = SecretScanner::v1().unwrap().sanitize(input);
    for secret in [
        "canary_authorization_value",
        "sk-proj-CanaryValue123456789012345",
        "canary-password",
        "-----BEGIN PRIVATE KEY-----",
    ] {
        assert!(!sanitized.text.contains(secret));
    }
    assert!(sanitized.text.contains("[REDACTED:authorization]"));
    assert!(
        sanitized
            .findings
            .iter()
            .any(|f| f.class == SecretClass::PrivateKey)
    );
}

#[test]
fn does_not_redact_high_entropy_text_without_a_rule_match() {
    let visible = "a8f9d4c3b2e190887766554433221100";
    let sanitized = SecretScanner::v1().unwrap().sanitize(visible);
    assert_eq!(sanitized.text, visible);
    assert!(sanitized.findings.is_empty());
}

#[test]
fn canary_fixture_values_are_redacted() {
    let values: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../fixtures/security/vendor-token-canaries.json"
    ))
    .unwrap();
    let scanner = SecretScanner::v1().unwrap();
    for entry in values {
        let value = entry["value"].as_str().unwrap();
        assert!(!scanner.sanitize(value).text.contains(value));
    }
}

#[test]
fn serialized_diagnostic_contains_no_original_secret_value() {
    let input = "Authorization: Bearer AgentArkDiagnosticCanary";
    let sanitized = SecretScanner::v1().unwrap().sanitize(input);
    let diagnostic = serde_json::to_string(&sanitized).unwrap();
    assert!(!diagnostic.contains("AgentArkDiagnosticCanary"));
    assert!(diagnostic.contains("authorization"));
}

#[test]
fn quoted_structured_secrets_with_spaces_and_escaped_quotes_are_fully_redacted() {
    let input = r#"password = "horse battery staple"
token: "alpha\" beta"
{"api_key":"first second"}"#;
    let sanitized = SecretScanner::v1().unwrap().sanitize(input);
    assert!(!sanitized.text.contains("horse battery staple"));
    assert!(!sanitized.text.contains("alpha\\\" beta"));
    assert!(!sanitized.text.contains("first second"));
}
