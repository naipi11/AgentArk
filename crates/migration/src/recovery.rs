use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderIdentity {
    pub provider: Option<String>,
    pub model: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RestoreOutcome {
    NativeIdentity,
    Continuation,
    ArchiveOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetRecoveryCapabilities {
    pub native_identity_verified: bool,
    pub continuation_writer_verified: bool,
    pub target_default: Option<ProviderIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryDecision {
    pub outcome: RestoreOutcome,
    pub source_provider: ProviderIdentity,
    pub target_provider: Option<ProviderIdentity>,
    pub reason_code: String,
}

pub fn decide_recovery(
    source: ProviderIdentity,
    capabilities: TargetRecoveryCapabilities,
) -> RecoveryDecision {
    if capabilities.native_identity_verified {
        return RecoveryDecision {
            outcome: RestoreOutcome::NativeIdentity,
            source_provider: source,
            target_provider: capabilities.target_default,
            reason_code: "native-identity-verified".into(),
        };
    }
    if capabilities.continuation_writer_verified {
        if let Some(target_provider) = capabilities.target_default {
            return RecoveryDecision {
                outcome: RestoreOutcome::Continuation,
                source_provider: source,
                target_provider: Some(target_provider),
                reason_code: "target-default-continuation".into(),
            };
        }
    }
    RecoveryDecision {
        outcome: RestoreOutcome::ArchiveOnly,
        source_provider: source,
        target_provider: None,
        reason_code: "continuation-writer-unavailable".into(),
    }
}
