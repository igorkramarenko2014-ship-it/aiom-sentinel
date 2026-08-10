use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditPolicyV1 {
    pub policy_id: String,
    pub policy_version: String,
    pub enabled: bool,
    pub effect: AuditEffectV1,
    pub allowed_root: String,
    pub engine_id: String,
    pub ruleset_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuditEffectV1 {
    AuditOnly,
    QuarantineDisabled,
    Quarantine,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ResponseActionV1 {
    Audit,
    Notify,
    Quarantine,
    NoAction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PolicyReasonCodeV1 {
    PolicyDisabled,
    AuditOnly,
    EffectDisabled,
    ExplicitQuarantine,
    InvalidScope,
    IncompatibleEngine,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactIdentityV1 {
    pub normalized_path: String,
    pub content_digest: String,
    pub size: u64,
    pub platform_file_id: Option<String>,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationIdentityV1 {
    pub event_id: u64,
    pub generation: u64,
    pub source: String,
    pub observed_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResponseArtifactIdentityV1 {
    pub normalized_path: String,
    pub content_digest: String,
    pub size: u64,
    pub platform_file_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResponsePlanV1 {
    pub transaction_id: String,
    pub action: ResponseActionV1,
    pub effect_enabled: bool,
    pub reason: PolicyReasonCodeV1,
    pub detail: Option<String>,
}

pub fn plan_for_artifact(
    identity: &ArtifactIdentityV1,
    policy: &AuditPolicyV1,
) -> Result<ResponsePlanV1, String> {
    let policy_bytes =
        serde_json::to_vec(policy).map_err(|e| format!("policy serialization: {e}"))?;
    let policy_digest = Sha256::digest(policy_bytes);
    let action = if !policy.enabled {
        ResponseActionV1::NoAction
    } else {
        match policy.effect {
            AuditEffectV1::AuditOnly => ResponseActionV1::Audit,
            AuditEffectV1::QuarantineDisabled => ResponseActionV1::NoAction,
            AuditEffectV1::Quarantine => ResponseActionV1::Quarantine,
        }
    };
    let canonical = serde_json::to_vec(&(
        identity.normalized_path.as_bytes(),
        identity.content_digest.as_bytes(),
        identity.size,
        &identity.platform_file_id,
        &policy.policy_id,
        &policy.policy_version,
        policy_digest.as_slice(),
        &policy.engine_id,
        &policy.ruleset_id,
        &action,
    ))
    .map_err(|e| format!("idempotency serialization: {e}"))?;
    let transaction_id = hex::encode(Sha256::digest(canonical));
    Ok(if !policy.enabled {
        ResponsePlanV1 {
            transaction_id,
            action,
            effect_enabled: false,
            reason: PolicyReasonCodeV1::PolicyDisabled,
            detail: None,
        }
    } else {
        match policy.effect {
            AuditEffectV1::AuditOnly => ResponsePlanV1 {
                transaction_id,
                action,
                effect_enabled: false,
                reason: PolicyReasonCodeV1::AuditOnly,
                detail: None,
            },
            AuditEffectV1::QuarantineDisabled => ResponsePlanV1 {
                transaction_id,
                action,
                effect_enabled: false,
                reason: PolicyReasonCodeV1::EffectDisabled,
                detail: None,
            },
            AuditEffectV1::Quarantine => ResponsePlanV1 {
                transaction_id,
                action,
                effect_enabled: false,
                reason: PolicyReasonCodeV1::ExplicitQuarantine,
                detail: Some("effect gate remains disabled until RUN 3 prerequisites close".into()),
            },
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn idempotency_key_is_deterministic_and_effect_disabled() {
        let policy = AuditPolicyV1 {
            policy_id: "p".into(),
            policy_version: "v1".into(),
            enabled: true,
            effect: AuditEffectV1::AuditOnly,
            allowed_root: "/tmp".into(),
            engine_id: "yara-x".into(),
            ruleset_id: "r".into(),
        };
        let identity = ArtifactIdentityV1 {
            normalized_path: "/tmp/a".into(),
            content_digest: "d".into(),
            size: 1,
            platform_file_id: None,
            generation: 7,
        };
        let a = plan_for_artifact(&identity, &policy).unwrap();
        let b = plan_for_artifact(&identity, &policy).unwrap();
        assert_eq!(a.transaction_id, b.transaction_id);
        assert!(!a.effect_enabled);
        assert_eq!(a.action, ResponseActionV1::Audit);
    }
}
