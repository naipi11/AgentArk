use agentark_migration::{
    ProviderIdentity, RestoreOutcome, TargetRecoveryCapabilities, decide_recovery,
};

#[test]
fn provider_identity_constructor_normalizes_blank_labels() {
    assert_eq!(
        ProviderIdentity::new(Some("  openai  ".into()), Some("\t".into())),
        ProviderIdentity {
            provider: Some("openai".into()),
            model: None,
        }
    );
}

#[test]
fn recovery_decision_normalizes_blank_source_and_target_labels() {
    let decision = decide_recovery(
        ProviderIdentity {
            provider: Some("  ".into()),
            model: Some("\t".into()),
        },
        TargetRecoveryCapabilities {
            native_identity_verified: true,
            continuation_writer_verified: true,
            target_default: Some(ProviderIdentity {
                provider: Some("  ".into()),
                model: Some("\n".into()),
            }),
        },
    );

    assert_eq!(decision.source_provider.provider, None);
    assert_eq!(decision.source_provider.model, None);
    let target_provider = decision.target_provider.unwrap();
    assert_eq!(target_provider.provider, None);
    assert_eq!(target_provider.model, None);
}

#[test]
fn same_provider_with_verified_identity_keeps_native_id() {
    let decision = decide_recovery(
        ProviderIdentity {
            provider: Some("openai".into()),
            model: Some("gpt-5".into()),
        },
        TargetRecoveryCapabilities {
            native_identity_verified: true,
            continuation_writer_verified: true,
            target_default: Some(ProviderIdentity {
                provider: Some("openai".into()),
                model: Some("gpt-5".into()),
            }),
        },
    );
    assert_eq!(decision.outcome, RestoreOutcome::NativeIdentity);
    assert_eq!(decision.reason_code, "native-identity-verified");
}

#[test]
fn unavailable_source_provider_uses_target_default_continuation() {
    let decision = decide_recovery(
        ProviderIdentity {
            provider: Some("custom".into()),
            model: Some("claude".into()),
        },
        TargetRecoveryCapabilities {
            native_identity_verified: false,
            continuation_writer_verified: true,
            target_default: Some(ProviderIdentity {
                provider: Some("openai".into()),
                model: Some("gpt-5".into()),
            }),
        },
    );
    assert_eq!(decision.outcome, RestoreOutcome::Continuation);
    assert_eq!(
        decision.target_provider.unwrap().provider.as_deref(),
        Some("openai")
    );
    assert_eq!(decision.reason_code, "target-default-continuation");
}

#[test]
fn unavailable_writer_stays_archive_only() {
    let decision = decide_recovery(
        ProviderIdentity {
            provider: None,
            model: None,
        },
        TargetRecoveryCapabilities {
            native_identity_verified: false,
            continuation_writer_verified: false,
            target_default: None,
        },
    );
    assert_eq!(decision.outcome, RestoreOutcome::ArchiveOnly);
    assert_eq!(decision.reason_code, "continuation-writer-unavailable");
}
