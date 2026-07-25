#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Harmless local literal-rule adapter behind a stable rule-engine abstraction.

pub mod signature;

use sentinel_core::{RuleMatch, Severity};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const ENGINE_VERSION: &str = "sentinel-literal-rules/1";

#[derive(Clone, Debug)]
pub struct Rule {
    identifier: String,
    namespace: String,
    literal: Vec<u8>,
    severity: Severity,
    confidence: u8,
    source_hash: String,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RuleError {
    #[error("rule must contain exactly five pipe-delimited fields")]
    InvalidFieldCount,
    #[error("rule identifier, namespace, and literal must be non-empty")]
    EmptyField,
    #[error("confidence must be an integer from 0 through 100")]
    InvalidConfidence,
    #[error("unknown severity: {0}")]
    InvalidSeverity(String),
}

pub trait RuleEngine: Send + Sync {
    fn evaluate(&self, bytes: &[u8]) -> Vec<RuleMatch>;
    fn version(&self) -> &'static str;
}

#[derive(Clone, Debug, Default)]
pub struct LocalRuleEngine {
    rules: Vec<Rule>,
}

impl LocalRuleEngine {
    pub fn parse(source: &str) -> Result<Self, RuleError> {
        let source_hash = hex::encode(Sha256::digest(source.as_bytes()));
        let mut rules = Vec::new();
        for line in source
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let fields: Vec<&str> = line.split('|').collect();
            if fields.len() != 5 {
                return Err(RuleError::InvalidFieldCount);
            }
            if fields[0].is_empty() || fields[1].is_empty() || fields[2].is_empty() {
                return Err(RuleError::EmptyField);
            }
            let confidence = fields[4]
                .parse::<u8>()
                .ok()
                .filter(|value| *value <= 100)
                .ok_or(RuleError::InvalidConfidence)?;
            let severity = match fields[3].to_ascii_uppercase().as_str() {
                "INFORMATIONAL" => Severity::Informational,
                "LOW" => Severity::Low,
                "MEDIUM" => Severity::Medium,
                "HIGH" => Severity::High,
                "CRITICAL" => Severity::Critical,
                other => return Err(RuleError::InvalidSeverity(other.to_owned())),
            };
            rules.push(Rule {
                identifier: fields[0].to_owned(),
                namespace: fields[1].to_owned(),
                literal: fields[2].as_bytes().to_vec(),
                severity,
                confidence,
                source_hash: source_hash.clone(),
            });
        }
        Ok(Self { rules })
    }
}

impl RuleEngine for LocalRuleEngine {
    fn evaluate(&self, bytes: &[u8]) -> Vec<RuleMatch> {
        self.rules
            .iter()
            .filter(|rule| {
                bytes
                    .windows(rule.literal.len())
                    .any(|window| window == rule.literal)
            })
            .map(|rule| RuleMatch {
                identifier: rule.identifier.clone(),
                namespace: rule.namespace.clone(),
                source_hash_sha256: rule.source_hash.clone(),
                matched_condition: "literal-present".to_owned(),
                severity: rule.severity.clone(),
                confidence_contribution: rule.confidence,
                evidence_reference: format!("rule:{}:{}", rule.namespace, rule.identifier),
            })
            .collect()
    }
    fn version(&self) -> &'static str {
        ENGINE_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_harmless_literal() {
        let engine = LocalRuleEngine::parse("marker|synthetic|HARMLESS_MARKER|LOW|20").unwrap();
        let matches = engine.evaluate(b"prefix HARMLESS_MARKER suffix");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].identifier, "marker");
    }
    #[test]
    fn rejects_bad_confidence() {
        assert_eq!(
            LocalRuleEngine::parse("a|b|c|LOW|101").unwrap_err(),
            RuleError::InvalidConfidence
        );
    }
}
