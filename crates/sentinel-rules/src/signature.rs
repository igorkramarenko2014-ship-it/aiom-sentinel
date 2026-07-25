//! Fail-closed Ed25519 verification for canonical rule-bundle signature contexts.
//! Production code contains verification keys only; signing keys exist only in tests.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use std::collections::BTreeMap;
use thiserror::Error;

pub const SIGNATURE_DOMAIN_SEPARATOR: &[u8] = b"AIOM_SENTINEL_RULE_BUNDLE_SIGNATURE_V1\0";
pub const SIGNATURE_ALGORITHM: &str = "ED25519";

const PINNED_PRODUCTION_REGISTRY: &str =
    include_str!("../../../config/rule-bundle-public-keys.json");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryScope {
    Production,
    #[cfg(test)]
    Test,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug)]
struct RegistryKey {
    verifying_key: VerifyingKey,
    status: KeyStatus,
}

#[derive(Clone, Debug, Default)]
pub struct PublicKeyRegistry {
    keys: BTreeMap<String, RegistryKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSignature {
    pub key_id: String,
    pub algorithm: &'static str,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SignatureVerificationError {
    #[error("public-key registry JSON is malformed: {0}")]
    RegistryMalformed(String),
    #[error("public-key registry schema version is unsupported")]
    RegistrySchemaUnsupported,
    #[error("public-key registry contains duplicate key_id: {0}")]
    DuplicateKeyId(String),
    #[error("public-key key_id must not be empty")]
    EmptyKeyId,
    #[error("public-key algorithm must be exactly ED25519")]
    WrongAlgorithm,
    #[error("public key must be exactly 32 bytes encoded as strict lowercase hex")]
    MalformedPublicKey,
    #[error("public key is not a valid Ed25519 verifying key")]
    InvalidPublicKey,
    #[error("test-only key is rejected by the production registry path")]
    TestOnlyKeyRejected,
    #[error("unknown key_id: {0}")]
    UnknownKey(String),
    #[error("key_id is revoked: {0}")]
    RevokedKey(String),
    #[error("canonical signature-context bytes must not be empty")]
    EmptySignatureContext,
    #[error("signature must be exactly 64 bytes encoded as strict lowercase hex")]
    MalformedSignature,
    #[error("Ed25519 signature verification failed")]
    InvalidSignature,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryDocument {
    schema_version: u32,
    keys: Vec<RegistryEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryEntry {
    key_id: String,
    algorithm: String,
    public_key_hex: String,
    status: String,
    scope: String,
}

impl PublicKeyRegistry {
    /// Load the repository-pinned production registry embedded into the binary.
    pub fn production() -> Result<Self, SignatureVerificationError> {
        Self::parse(PINNED_PRODUCTION_REGISTRY, RegistryScope::Production)
    }

    #[cfg(test)]
    fn from_test_json(json: &str) -> Result<Self, SignatureVerificationError> {
        Self::parse(json, RegistryScope::Test)
    }

    fn parse(json: &str, scope: RegistryScope) -> Result<Self, SignatureVerificationError> {
        let document: RegistryDocument = serde_json::from_str(json)
            .map_err(|error| SignatureVerificationError::RegistryMalformed(error.to_string()))?;
        if document.schema_version != 1 {
            return Err(SignatureVerificationError::RegistrySchemaUnsupported);
        }

        let mut keys = BTreeMap::new();
        for entry in document.keys {
            if entry.key_id.is_empty() {
                return Err(SignatureVerificationError::EmptyKeyId);
            }
            if entry.algorithm != SIGNATURE_ALGORITHM {
                return Err(SignatureVerificationError::WrongAlgorithm);
            }
            if entry.scope != "PRODUCTION" && entry.scope != "TEST_ONLY" {
                return Err(SignatureVerificationError::RegistryMalformed(
                    "scope must be PRODUCTION or TEST_ONLY".to_owned(),
                ));
            }
            if entry.scope == "TEST_ONLY" && scope == RegistryScope::Production {
                return Err(SignatureVerificationError::TestOnlyKeyRejected);
            }

            let status = match entry.status.as_str() {
                "ACTIVE" => KeyStatus::Active,
                "REVOKED" => KeyStatus::Revoked,
                _ => {
                    return Err(SignatureVerificationError::RegistryMalformed(
                        "status must be ACTIVE or REVOKED".to_owned(),
                    ));
                }
            };
            let public_key_bytes = decode_strict_hex::<32>(
                &entry.public_key_hex,
                SignatureVerificationError::MalformedPublicKey,
            )?;
            let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
                .map_err(|_| SignatureVerificationError::InvalidPublicKey)?;
            let key_id = entry.key_id;
            if keys
                .insert(
                    key_id.clone(),
                    RegistryKey {
                        verifying_key,
                        status,
                    },
                )
                .is_some()
            {
                return Err(SignatureVerificationError::DuplicateKeyId(key_id));
            }
        }
        Ok(Self { keys })
    }

    pub fn verify_strict(
        &self,
        key_id: &str,
        canonical_signature_context: &[u8],
        signature_hex: &str,
    ) -> Result<VerifiedSignature, SignatureVerificationError> {
        if canonical_signature_context.is_empty() {
            return Err(SignatureVerificationError::EmptySignatureContext);
        }
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| SignatureVerificationError::UnknownKey(key_id.to_owned()))?;
        if key.status == KeyStatus::Revoked {
            return Err(SignatureVerificationError::RevokedKey(key_id.to_owned()));
        }

        let signature_bytes = decode_strict_hex::<64>(
            signature_hex,
            SignatureVerificationError::MalformedSignature,
        )?;
        let signature = Signature::from_bytes(&signature_bytes);
        let message = signed_message(canonical_signature_context);
        key.verifying_key
            .verify_strict(&message, &signature)
            .map_err(|_| SignatureVerificationError::InvalidSignature)?;
        Ok(VerifiedSignature {
            key_id: key_id.to_owned(),
            algorithm: SIGNATURE_ALGORITHM,
        })
    }
}

pub fn signed_message(canonical_signature_context: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(SIGNATURE_DOMAIN_SEPARATOR.len() + canonical_signature_context.len());
    message.extend_from_slice(SIGNATURE_DOMAIN_SEPARATOR);
    message.extend_from_slice(canonical_signature_context);
    message
}

fn decode_strict_hex<const N: usize>(
    value: &str,
    error: SignatureVerificationError,
) -> Result<[u8; N], SignatureVerificationError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error);
    }
    let decoded = hex::decode(value).map_err(|_| error.clone())?;
    decoded.try_into().map_err(|_| error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const CONTEXT: &[u8] =
        br#"{"bundle_content_id":"aaaaaaaa","key_id":"test-key","version":"1.0.0"}"#;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn registry_json(
        key_id: &str,
        signing_key: &SigningKey,
        status: &str,
        scope: &str,
        algorithm: &str,
    ) -> String {
        format!(
            r#"{{"schema_version":1,"keys":[{{"key_id":"{key_id}","algorithm":"{algorithm}","public_key_hex":"{}","status":"{status}","scope":"{scope}"}}]}}"#,
            hex::encode(signing_key.verifying_key().to_bytes())
        )
    }

    fn signature_hex(signing_key: &SigningKey, context: &[u8]) -> String {
        hex::encode(signing_key.sign(&signed_message(context)).to_bytes())
    }

    #[test]
    fn valid_signature_verifies_strictly() {
        let key = signing_key(7);
        let registry = PublicKeyRegistry::from_test_json(&registry_json(
            "test-key",
            &key,
            "ACTIVE",
            "TEST_ONLY",
            "ED25519",
        ))
        .unwrap();
        let verified = registry
            .verify_strict("test-key", CONTEXT, &signature_hex(&key, CONTEXT))
            .unwrap();
        assert_eq!(verified.key_id, "test-key");
        assert_eq!(verified.algorithm, "ED25519");
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let key = signing_key(7);
        let registry = PublicKeyRegistry::from_test_json(&registry_json(
            "test-key",
            &key,
            "ACTIVE",
            "TEST_ONLY",
            "ED25519",
        ))
        .unwrap();
        let signature = signature_hex(&key, CONTEXT);
        assert_eq!(
            registry
                .verify_strict("test-key", b"{\"tampered\":true}", &signature)
                .unwrap_err(),
            SignatureVerificationError::InvalidSignature
        );
    }

    #[test]
    fn wrong_signature_context_is_rejected() {
        let key = signing_key(7);
        let registry = PublicKeyRegistry::from_test_json(&registry_json(
            "test-key",
            &key,
            "ACTIVE",
            "TEST_ONLY",
            "ED25519",
        ))
        .unwrap();
        let wrong_domain_message = [b"WRONG_CONTEXT\0".as_slice(), CONTEXT].concat();
        let signature = hex::encode(key.sign(&wrong_domain_message).to_bytes());
        assert_eq!(
            registry
                .verify_strict("test-key", CONTEXT, &signature)
                .unwrap_err(),
            SignatureVerificationError::InvalidSignature
        );
    }

    #[test]
    fn unknown_key_is_rejected() {
        let key = signing_key(7);
        let registry = PublicKeyRegistry::from_test_json(&registry_json(
            "test-key",
            &key,
            "ACTIVE",
            "TEST_ONLY",
            "ED25519",
        ))
        .unwrap();
        assert_eq!(
            registry
                .verify_strict("unknown", CONTEXT, &signature_hex(&key, CONTEXT))
                .unwrap_err(),
            SignatureVerificationError::UnknownKey("unknown".to_owned())
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let trusted = signing_key(7);
        let attacker = signing_key(9);
        let registry = PublicKeyRegistry::from_test_json(&registry_json(
            "trusted",
            &trusted,
            "ACTIVE",
            "TEST_ONLY",
            "ED25519",
        ))
        .unwrap();
        assert_eq!(
            registry
                .verify_strict("trusted", CONTEXT, &signature_hex(&attacker, CONTEXT))
                .unwrap_err(),
            SignatureVerificationError::InvalidSignature
        );
    }

    #[test]
    fn revoked_key_is_rejected_before_signature_verification() {
        let key = signing_key(7);
        let registry = PublicKeyRegistry::from_test_json(&registry_json(
            "revoked",
            &key,
            "REVOKED",
            "TEST_ONLY",
            "ED25519",
        ))
        .unwrap();
        assert_eq!(
            registry
                .verify_strict("revoked", CONTEXT, &signature_hex(&key, CONTEXT))
                .unwrap_err(),
            SignatureVerificationError::RevokedKey("revoked".to_owned())
        );
    }

    #[test]
    fn malformed_key_algorithm_and_signature_are_rejected() {
        let key = signing_key(7);
        let uppercase_key = hex::encode_upper(key.verifying_key().to_bytes());
        let malformed_key = format!(
            r#"{{"schema_version":1,"keys":[{{"key_id":"bad","algorithm":"ED25519","public_key_hex":"{uppercase_key}","status":"ACTIVE","scope":"TEST_ONLY"}}]}}"#
        );
        assert_eq!(
            PublicKeyRegistry::from_test_json(&malformed_key).unwrap_err(),
            SignatureVerificationError::MalformedPublicKey
        );
        assert_eq!(
            PublicKeyRegistry::from_test_json(&registry_json(
                "bad",
                &key,
                "ACTIVE",
                "TEST_ONLY",
                "RSA"
            ))
            .unwrap_err(),
            SignatureVerificationError::WrongAlgorithm
        );

        let registry = PublicKeyRegistry::from_test_json(&registry_json(
            "test-key",
            &key,
            "ACTIVE",
            "TEST_ONLY",
            "ED25519",
        ))
        .unwrap();
        assert_eq!(
            registry
                .verify_strict("test-key", CONTEXT, "ABC")
                .unwrap_err(),
            SignatureVerificationError::MalformedSignature
        );
    }

    #[test]
    fn test_only_key_is_rejected_by_production_registry_path() {
        let key = signing_key(7);
        assert_eq!(
            PublicKeyRegistry::parse(
                &registry_json("test-key", &key, "ACTIVE", "TEST_ONLY", "ED25519"),
                RegistryScope::Production,
            )
            .unwrap_err(),
            SignatureVerificationError::TestOnlyKeyRejected
        );
        assert!(PublicKeyRegistry::production().unwrap().keys.is_empty());
    }
}
