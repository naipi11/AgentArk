use std::collections::BTreeSet;

use agentark_adapter_codex::CodexProbe;
use agentark_adapter_sdk::SourceCapability;

#[test]
fn supported_version_reports_read_and_known_schema_capabilities() {
    let report = CodexProbe::from_outputs(
        "codex-cli 0.146.0\n",
        "Usage: codex app-server --listen stdio://\n",
    )
    .unwrap();
    assert_eq!(report.adapter_id, "codex");
    assert_eq!(report.executable_version, "0.146.0");
    assert!(
        report
            .capabilities
            .contains(&SourceCapability::AppServerRead)
    );
    assert!(
        report
            .capabilities
            .contains(&SourceCapability::KnownSemanticSchema)
    );
    assert_eq!(report.quarantine_reason, None);
}

#[test]
fn unsupported_version_is_quarantined_and_has_no_known_schema_capability() {
    let report = CodexProbe::from_outputs(
        "codex-cli 0.147.0\n",
        "Usage: codex app-server --listen stdio://\n",
    )
    .unwrap();
    assert_eq!(
        report.quarantine_reason.as_deref(),
        Some("unsupported-codex-version")
    );
    assert!(
        !report
            .capabilities
            .contains(&SourceCapability::KnownSemanticSchema)
    );
}

#[test]
fn probe_capabilities_are_stable_and_deterministic() {
    let first = CodexProbe::from_outputs(
        "codex-cli 0.146.0\n",
        "Usage: codex app-server --listen stdio://\n",
    )
    .unwrap();
    let second = CodexProbe::from_outputs(
        "codex-cli 0.146.0\n",
        "Usage: codex app-server --listen stdio://\n",
    )
    .unwrap();
    assert_eq!(first.capabilities, second.capabilities);
    assert_eq!(
        first.capabilities,
        BTreeSet::from([
            SourceCapability::AppServerRead,
            SourceCapability::ArchivedThreads,
            SourceCapability::FilesystemRawArchive,
            SourceCapability::KnownSemanticSchema,
        ])
    );
}
