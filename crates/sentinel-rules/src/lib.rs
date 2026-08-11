#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Harmless local literal-rule adapter behind a stable rule-engine abstraction.

pub mod signature;

use sentinel_core::{
    DetectionEngineIdentityV1, EngineCoverageStateV1, EngineCoverageV1, EngineScanBudgetV1,
    EngineScanResultV1, MatchSpan, RuleMatch, RuleMetadataEntry, RuleSetIdentityV1, Severity,
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use thiserror::Error;

pub const ENGINE_VERSION: &str = "sentinel-literal-rules/1";
pub const YARA_X_ENGINE_ID: &str = "yara-x";
pub const ENGINE_RESULT_SCHEMA_VERSION: &str = "sentinel-engine-result/v1";

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
    #[error("YARA-X compilation failed: {0}")]
    YaraCompile(String),
    #[error("ruleset must contain at least one source")]
    EmptyRuleSet,
    #[error("YARA pattern is too weak: {0}")]
    WeakYaraPattern(String),
}

pub trait RuleEngine: Send + Sync {
    fn evaluate(&self, bytes: &[u8], budget: &EngineScanBudgetV1) -> EngineScanResultV1;
    fn identity(&self) -> DetectionEngineIdentityV1;
    fn ruleset_identity(&self) -> RuleSetIdentityV1;
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
    fn evaluate(&self, bytes: &[u8], budget: &EngineScanBudgetV1) -> EngineScanResultV1 {
        let identity = self.identity();
        let ruleset = self.ruleset_identity();
        if budget.cancelled {
            return engine_result(
                identity,
                ruleset,
                EngineCoverageStateV1::Cancelled,
                0,
                Vec::new(),
                Some("scan cancelled before engine execution".to_owned()),
            );
        }
        if bytes.len() > budget.max_scan_bytes {
            return engine_result(
                identity,
                ruleset,
                EngineCoverageStateV1::Partial,
                0,
                Vec::new(),
                Some(format!(
                    "input exceeds {} byte engine limit",
                    budget.max_scan_bytes
                )),
            );
        }
        let mut matches: Vec<_> = self
            .rules
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
                tags: Vec::new(),
                metadata: Vec::new(),
                spans: Vec::new(),
            })
            .collect();
        matches.sort_by(|left, right| {
            (&left.namespace, &left.identifier).cmp(&(&right.namespace, &right.identifier))
        });
        if matches.len() > budget.max_matches {
            matches.truncate(budget.max_matches);
            return engine_result(
                identity,
                ruleset,
                EngineCoverageStateV1::Partial,
                bytes.len(),
                matches,
                Some("match limit reached".to_owned()),
            );
        }
        engine_result(
            identity,
            ruleset,
            EngineCoverageStateV1::Complete,
            bytes.len(),
            matches,
            None,
        )
    }
    fn identity(&self) -> DetectionEngineIdentityV1 {
        DetectionEngineIdentityV1 {
            engine_id: "sentinel-literal".to_owned(),
            engine_version: ENGINE_VERSION.to_owned(),
        }
    }
    fn ruleset_identity(&self) -> RuleSetIdentityV1 {
        let content_sha256 = self.rules.first().map_or_else(
            || hex::encode(Sha256::digest([])),
            |rule| rule.source_hash.clone(),
        );
        RuleSetIdentityV1 {
            pack_id: "local-literal".to_owned(),
            content_sha256,
        }
    }
}

pub struct YaraXRuleSource<'a> {
    pub namespace: &'a str,
    pub source: &'a str,
}

pub struct YaraXEngine {
    rules: yara_x::Rules,
    identity: DetectionEngineIdentityV1,
    ruleset: RuleSetIdentityV1,
}

impl YaraXEngine {
    pub fn compile(pack_id: &str, sources: &[YaraXRuleSource<'_>]) -> Result<Self, RuleError> {
        if sources.is_empty() {
            return Err(RuleError::EmptyRuleSet);
        }
        let mut compiler = yara_x::Compiler::new();
        let mut digest = Sha256::new();
        for source in sources {
            validate_yara_source_quality(source.source)?;
            digest.update((source.namespace.len() as u64).to_le_bytes());
            digest.update(source.namespace.as_bytes());
            digest.update((source.source.len() as u64).to_le_bytes());
            digest.update(source.source.as_bytes());
            compiler.new_namespace(source.namespace);
            compiler
                .add_source(source.source)
                .map_err(|error| RuleError::YaraCompile(error.to_string()))?;
        }
        Ok(Self {
            rules: compiler.build(),
            identity: DetectionEngineIdentityV1 {
                engine_id: YARA_X_ENGINE_ID.to_owned(),
                engine_version: yara_x::VERSION.to_owned(),
            },
            ruleset: RuleSetIdentityV1 {
                pack_id: pack_id.to_owned(),
                content_sha256: hex::encode(digest.finalize()),
            },
        })
    }
}

fn validate_yara_source_quality(source: &str) -> Result<(), RuleError> {
    let Some((_, after_strings)) = source.split_once("strings:") else {
        return Ok(());
    };
    let strings = after_strings
        .split_once("condition:")
        .map_or(after_strings, |(section, _)| section);
    let mut remaining = strings;
    while let Some((left, after_equals)) = remaining.split_once('=') {
        let value = after_equals.trim_start();
        if let Some(quoted) = value.strip_prefix('"') {
            let mut escaped = false;
            let mut units = 0usize;
            let mut end = None;
            for (index, character) in quoted.char_indices() {
                if escaped {
                    escaped = false;
                    units += 1;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    end = Some(index + character.len_utf8());
                    break;
                } else {
                    units += 1;
                }
            }
            if units <= 1 {
                let identifier = left.split_whitespace().last().unwrap_or("unknown-pattern");
                return Err(RuleError::WeakYaraPattern(identifier.to_owned()));
            }
            remaining = end.map_or("", |index| &quoted[index..]);
        } else {
            remaining = after_equals;
        }
    }
    Ok(())
}

impl RuleEngine for YaraXEngine {
    fn evaluate(&self, bytes: &[u8], budget: &EngineScanBudgetV1) -> EngineScanResultV1 {
        let identity = self.identity();
        let ruleset = self.ruleset_identity();
        if budget.cancelled {
            return engine_result(
                identity,
                ruleset,
                EngineCoverageStateV1::Cancelled,
                0,
                Vec::new(),
                Some("scan cancelled before YARA-X execution".to_owned()),
            );
        }
        if budget.timeout_ms == 0 {
            return engine_result(
                identity,
                ruleset,
                EngineCoverageStateV1::Failed,
                0,
                Vec::new(),
                Some("scan deadline expired before YARA-X execution".to_owned()),
            );
        }
        if bytes.len() > budget.max_scan_bytes {
            return engine_result(
                identity,
                ruleset,
                EngineCoverageStateV1::Partial,
                0,
                Vec::new(),
                Some(format!(
                    "input exceeds {} byte YARA-X limit",
                    budget.max_scan_bytes
                )),
            );
        }
        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner
            .set_timeout(Duration::from_millis(budget.timeout_ms.max(1)))
            .max_matches_per_pattern(budget.max_matches.saturating_add(1).max(1));
        let results = match scanner.scan(bytes) {
            Ok(results) => results,
            Err(error) => {
                return engine_result(
                    identity,
                    ruleset,
                    EngineCoverageStateV1::Failed,
                    0,
                    Vec::new(),
                    Some(error.to_string()),
                );
            }
        };
        let mut matches = Vec::new();
        let mut observed_matches = 0usize;
        for rule in results.matching_rules() {
            let mut spans = Vec::new();
            for pattern in rule.patterns() {
                for matched in pattern.matches() {
                    observed_matches = observed_matches.saturating_add(1);
                    if observed_matches > budget.max_matches {
                        matches.sort_by(|left: &RuleMatch, right| {
                            (&left.namespace, &left.identifier)
                                .cmp(&(&right.namespace, &right.identifier))
                        });
                        return engine_result(
                            identity,
                            ruleset,
                            EngineCoverageStateV1::Partial,
                            bytes.len(),
                            matches,
                            Some("match limit reached".to_owned()),
                        );
                    }
                    let range = matched.range();
                    spans.push(MatchSpan {
                        pattern: pattern.identifier().to_owned(),
                        start: range.start as u64,
                        end: range.end as u64,
                    });
                }
            }
            spans.sort_by(|left, right| {
                (&left.pattern, left.start, left.end).cmp(&(&right.pattern, right.start, right.end))
            });
            let mut tags: Vec<_> = rule.tags().map(|tag| tag.identifier().to_owned()).collect();
            tags.sort();
            let mut metadata: Vec<_> = rule
                .metadata()
                .map(|(key, value)| RuleMetadataEntry {
                    key: key.to_owned(),
                    value: match value {
                        yara_x::MetaValue::Integer(value) => value.to_string(),
                        yara_x::MetaValue::Float(value) => value.to_string(),
                        yara_x::MetaValue::Bool(value) => value.to_string(),
                        yara_x::MetaValue::String(value) => value.to_owned(),
                        yara_x::MetaValue::Bytes(value) => format!("{value:?}"),
                    },
                })
                .collect();
            metadata.sort_by(|left, right| left.key.cmp(&right.key));
            matches.push(RuleMatch {
                identifier: rule.identifier().to_owned(),
                namespace: rule.namespace().to_owned(),
                source_hash_sha256: self.ruleset.content_sha256.clone(),
                matched_condition: "yara-x-condition-true".to_owned(),
                severity: severity_from_metadata(&metadata),
                confidence_contribution: 50,
                evidence_reference: format!("yara-x:{}:{}", rule.namespace(), rule.identifier()),
                tags,
                metadata,
                spans,
            });
        }
        matches.sort_by(|left, right| {
            (&left.namespace, &left.identifier).cmp(&(&right.namespace, &right.identifier))
        });
        engine_result(
            identity,
            ruleset,
            EngineCoverageStateV1::Complete,
            bytes.len(),
            matches,
            None,
        )
    }

    fn identity(&self) -> DetectionEngineIdentityV1 {
        self.identity.clone()
    }
    fn ruleset_identity(&self) -> RuleSetIdentityV1 {
        self.ruleset.clone()
    }
}

fn severity_from_metadata(metadata: &[RuleMetadataEntry]) -> Severity {
    let value = metadata
        .iter()
        .find(|entry| entry.key.eq_ignore_ascii_case("severity"))
        .map(|entry| entry.value.to_ascii_uppercase());
    match value.as_deref() {
        Some("CRITICAL") => Severity::Critical,
        Some("HIGH") => Severity::High,
        Some("MEDIUM") => Severity::Medium,
        Some("LOW") => Severity::Low,
        _ => Severity::Informational,
    }
}

fn engine_result(
    engine: DetectionEngineIdentityV1,
    ruleset: RuleSetIdentityV1,
    state: EngineCoverageStateV1,
    scanned_bytes: usize,
    matches: Vec<RuleMatch>,
    reason: Option<String>,
) -> EngineScanResultV1 {
    EngineScanResultV1 {
        schema_version: ENGINE_RESULT_SCHEMA_VERSION.to_owned(),
        coverage: EngineCoverageV1 {
            engine,
            ruleset,
            state,
            scanned_bytes: scanned_bytes as u64,
            match_count: matches.len() as u64,
            reason,
        },
        matches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_harmless_literal() {
        let engine = LocalRuleEngine::parse("marker|synthetic|HARMLESS_MARKER|LOW|20").unwrap();
        let result = engine.evaluate(b"prefix HARMLESS_MARKER suffix", &budget());
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].identifier, "marker");
    }

    fn budget() -> EngineScanBudgetV1 {
        EngineScanBudgetV1 {
            max_scan_bytes: 1024,
            max_matches: 100,
            timeout_ms: 1_000,
            cancelled: false,
        }
    }

    #[test]
    fn yara_x_compiles_matches_and_preserves_typed_evidence() {
        let engine = YaraXEngine::compile("fixture-pack", &[YaraXRuleSource { namespace: "fixture", source: r#"rule BenignMarker : synthetic { meta: severity = "LOW" author = "AIOM" strings: $marker = "HARMLESS_YARA_X_MARKER" condition: $marker }"# }]).unwrap();
        let result = engine.evaluate(b"prefix HARMLESS_YARA_X_MARKER suffix", &budget());
        assert_eq!(result.coverage.state, EngineCoverageStateV1::Complete);
        assert_eq!(result.matches[0].namespace, "fixture");
        assert_eq!(result.matches[0].tags, vec!["synthetic"]);
        assert_eq!(result.matches[0].spans[0].start, 7);
        assert_eq!(result.matches[0].severity, Severity::Low);
    }

    #[test]
    fn yara_x_rejects_malformed_source_without_snapshot() {
        let error = YaraXEngine::compile(
            "broken",
            &[YaraXRuleSource {
                namespace: "fixture",
                source: "rule broken { condition:",
            }],
        )
        .err()
        .unwrap();
        assert!(matches!(error, RuleError::YaraCompile(_)));
    }

    #[test]
    fn yara_x_no_match_is_complete_and_limits_are_not_clean() {
        let engine = YaraXEngine::compile(
            "fixture-pack",
            &[YaraXRuleSource {
                namespace: "fixture",
                source: r#"rule marker { strings: $a = "MARKER" condition: $a }"#,
            }],
        )
        .unwrap();
        let no_match = engine.evaluate(b"other", &budget());
        assert!(no_match.matches.is_empty());
        assert_eq!(no_match.coverage.state, EngineCoverageStateV1::Complete);
        let partial = engine.evaluate(
            b"too large",
            &EngineScanBudgetV1 {
                max_scan_bytes: 2,
                ..budget()
            },
        );
        assert_eq!(partial.coverage.state, EngineCoverageStateV1::Partial);
    }

    #[test]
    fn yara_x_namespaces_are_deterministic_and_duplicate_rules_are_rejected() {
        let engine = YaraXEngine::compile(
            "namespaces",
            &[
                YaraXRuleSource {
                    namespace: "zeta",
                    source: r#"rule marker { strings: $a = "MARKER" condition: $a }"#,
                },
                YaraXRuleSource {
                    namespace: "alpha",
                    source: r#"rule marker { strings: $a = "MARKER" condition: $a }"#,
                },
            ],
        )
        .unwrap();
        let result = engine.evaluate(b"MARKER", &budget());
        assert_eq!(
            result
                .matches
                .iter()
                .map(|item| item.namespace.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );
        assert!(
            YaraXEngine::compile(
                "duplicate",
                &[YaraXRuleSource {
                    namespace: "same",
                    source: "rule duplicate { condition: true } rule duplicate { condition: true }"
                }]
            )
            .is_err()
        );
    }

    #[test]
    fn yara_x_rejects_obvious_single_byte_literal_and_accepts_normal_literal() {
        // Arrange
        let weak = YaraXRuleSource {
            namespace: "quality",
            source: r#"rule weak { strings: $a = "x" condition: $a }"#,
        };
        let normal = YaraXRuleSource {
            namespace: "quality",
            source: r#"rule normal { strings: $a = "HARMLESS_MARKER" condition: $a }"#,
        };

        // Act
        let weak_result = YaraXEngine::compile("weak", &[weak]);
        let normal_result = YaraXEngine::compile("normal", &[normal]);

        // Assert
        assert!(matches!(weak_result, Err(RuleError::WeakYaraPattern(_))));
        assert!(normal_result.is_ok());
    }

    #[test]
    fn yara_x_cancellation_and_match_limit_are_explicit_non_complete_states() {
        let engine = YaraXEngine::compile(
            "limits",
            &[YaraXRuleSource {
                namespace: "default",
                source: r#"rule marker { strings: $a = "MARKER" condition: $a }"#,
            }],
        )
        .unwrap();
        let cancelled = engine.evaluate(
            b"MARKER",
            &EngineScanBudgetV1 {
                cancelled: true,
                ..budget()
            },
        );
        assert_eq!(cancelled.coverage.state, EngineCoverageStateV1::Cancelled);
        let limited = engine.evaluate(
            b"MARKER MARKER",
            &EngineScanBudgetV1 {
                max_matches: 1,
                ..budget()
            },
        );
        assert_eq!(limited.coverage.state, EngineCoverageStateV1::Partial);
        let timed_out = engine.evaluate(
            b"MARKER",
            &EngineScanBudgetV1 {
                timeout_ms: 0,
                ..budget()
            },
        );
        assert_eq!(timed_out.coverage.state, EngineCoverageStateV1::Failed);
        assert!(
            timed_out
                .coverage
                .reason
                .as_deref()
                .unwrap()
                .contains("deadline")
        );
    }

    #[test]
    fn yara_x_truncated_input_is_bounded_and_does_not_panic() {
        let engine = YaraXEngine::compile(
            "truncated",
            &[YaraXRuleSource {
                namespace: "default",
                source: r#"rule pe_marker { strings: $mz = { 4D 5A 90 00 } condition: $mz at 0 }"#,
            }],
        )
        .unwrap();
        let result = engine.evaluate(b"MZ\0", &budget());
        assert_eq!(result.coverage.state, EngineCoverageStateV1::Complete);
        assert!(result.matches.is_empty());
    }
    #[test]
    fn rejects_bad_confidence() {
        assert_eq!(
            LocalRuleEngine::parse("a|b|c|LOW|101").unwrap_err(),
            RuleError::InvalidConfidence
        );
    }
}
