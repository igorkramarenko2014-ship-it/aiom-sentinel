#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use sentinel_core::{ScanLimits, ScanRequest, ScanTarget, Verdict};
use sentinel_evidence::EvidenceBundle;
use sentinel_rules::LocalRuleEngine;
use sentinel_scanner::scan;
use std::{path::PathBuf, process::ExitCode, sync::Arc};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "sentinel",
    version,
    about = "Read-only static evidence scanner"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Scan {
        path: PathBuf,
        #[arg(long)]
        recursive: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        rules: Option<PathBuf>,
        #[arg(long, default_value_t = 256)]
        max_file_mib: u64,
    },
    Version,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => ExitCode::from(code),
        Err((code, message)) => {
            eprintln!("sentinel: {message}");
            ExitCode::from(code)
        }
    }
}

async fn run(cli: Cli) -> Result<u8, (u8, String)> {
    match cli.command {
        Command::Version => {
            println!("sentinel {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        Command::Scan {
            path,
            recursive,
            json,
            output,
            rules,
            max_file_mib,
        } => {
            if max_file_mib == 0 {
                return Err((3, "--max-file-mib must be greater than zero".to_owned()));
            }
            if !path.exists() {
                return Err((
                    3,
                    format!("target does not exist: {}", path.to_string_lossy()),
                ));
            }
            if path.is_dir() && !recursive {
                return Err((
                    3,
                    "directory scans require the explicit --recursive flag".to_owned(),
                ));
            }
            let rule_engine = match rules {
                Some(rule_path) => {
                    let source = std::fs::read_to_string(&rule_path).map_err(|error| {
                        (
                            3,
                            format!(
                                "failed to read rules {}: {error}",
                                rule_path.to_string_lossy()
                            ),
                        )
                    })?;
                    Some(Arc::new(
                        LocalRuleEngine::parse(&source).map_err(|error| (3, error.to_string()))?,
                    ) as Arc<dyn sentinel_rules::RuleEngine>)
                }
                None => None,
            };
            let request = ScanRequest {
                scan_id: Uuid::new_v4(),
                target: ScanTarget(path),
                recursive,
                limits: ScanLimits {
                    max_file_size: max_file_mib.saturating_mul(1024 * 1024),
                    ..ScanLimits::default()
                },
            };
            let result = scan(&request, rule_engine)
                .await
                .map_err(|error| (2, error.to_string()))?;
            let has_match = result
                .records
                .iter()
                .any(|record| matches!(record.verdict, Verdict::Match | Verdict::Suspicious));
            let has_error = !result.traversal_errors.is_empty()
                || result
                    .records
                    .iter()
                    .any(|record| record.verdict == Verdict::ScanError);
            let bundle = EvidenceBundle::from(result);
            let encoded = bundle.to_json().map_err(|error| (2, error.to_string()))?;
            if let Some(destination) = output {
                bundle
                    .write(&destination)
                    .map_err(|error| (2, error.to_string()))?;
            }
            if json {
                println!("{encoded}");
            } else {
                println!(
                    "scan_id={} records={} matches={} errors={}",
                    bundle.scan_id,
                    bundle.records.len(),
                    has_match,
                    has_error
                );
            }
            Ok(if has_error {
                2
            } else if has_match {
                1
            } else {
                0
            })
        }
    }
}
