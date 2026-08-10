#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use sentinel_core::{ScanLimits, ScanRequest, ScanTarget, Verdict};
use sentinel_evidence::EvidenceBundle;
use sentinel_rules::{LocalRuleEngine, YaraXEngine, YaraXRuleSource};
use sentinel_scanner::scan;
use std::time::Duration;
use std::{collections::HashMap, path::PathBuf, process::ExitCode, sync::Arc};
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
        /// Compile and scan with the Rust-native YARA-X engine.
        #[arg(long, conflicts_with = "rules")]
        yara_rules: Option<PathBuf>,
        #[arg(long, default_value = "default")]
        yara_namespace: String,
        #[arg(long, default_value_t = 256)]
        max_file_mib: u64,
    },
    Watch {
        directory: PathBuf,
        #[arg(long)]
        yara_rules: PathBuf,
        #[arg(long, default_value = "default")]
        yara_namespace: String,
        #[arg(long)]
        json: bool,
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
        Command::Watch {
            directory,
            yara_rules,
            yara_namespace,
            json,
        } => {
            if !directory.is_dir() {
                return Err((
                    3,
                    format!("watch directory does not exist: {}", directory.display()),
                ));
            }
            let source = std::fs::read_to_string(&yara_rules)
                .map_err(|e| (3, format!("failed to read YARA rules: {e}")))?;
            let engine = Arc::new(
                YaraXEngine::compile(
                    &yara_rules.to_string_lossy(),
                    &[YaraXRuleSource {
                        namespace: &yara_namespace,
                        source: &source,
                    }],
                )
                .map_err(|e| (3, e.to_string()))?,
            ) as Arc<dyn sentinel_rules::RuleEngine>;
            let watcher =
                sentinel_product_service::watcher::FileWatcher::start_root(directory.clone())
                    .map_err(|e| (3, e.to_string()))?;
            let (intake, rx, counters) =
                sentinel_product_service::watcher::BoundedIntake::new_with_root(
                    128,
                    Duration::from_millis(300),
                    directory.clone(),
                );
            println!(
                "{{\"schema_version\":\"sentinel-watch/v1\",\"state\":\"READY\",\"root\":{}}}",
                serde_json::to_string(&directory.to_string_lossy()).unwrap()
            );
            let stop = tokio::signal::ctrl_c();
            tokio::pin!(stop);
            let mut generation = 0u64;
            let mut snapshot: HashMap<PathBuf, (u64, Option<std::time::SystemTime>)> =
                HashMap::new();
            loop {
                tokio::select! {
                    _ = &mut stop => break,
                    _ = tokio::time::sleep(Duration::from_millis(25)) => {
                        while let Some(event) = watcher.try_next() { match event { Ok(event) => { eprintln!("watch source_event kind={:?} paths={:?}", event.kind, event.paths); if sentinel_product_service::watcher::event_kind(&event.kind) { for path in event.paths { generation += 1; let _ = intake.submit(path, event.kind, generation); } } }, Err(error) => eprintln!("watch source_error={error}"), } }
                        if let Ok(entries) = std::fs::read_dir(&directory) {
                            for entry in entries.flatten() {
                                let path = entry.path();
                                if path.is_symlink() || !path.is_file() { continue; }
                                if let Ok(meta) = std::fs::symlink_metadata(&path) {
                                    let identity = (meta.len(), meta.modified().ok());
                                    if snapshot.get(&path) != Some(&identity) {
                                        snapshot.insert(path.clone(), identity);
                                        generation += 1;
                                        let _ = intake.submit(path, notify::EventKind::Create(notify::event::CreateKind::File), generation);
                                    }
                                }
                            }
                        }
                        while let Ok(item) = rx.try_recv() {
                            let started = std::time::Instant::now();
                            let result = sentinel_product_service::watcher::stable_file(&item.path, started + Duration::from_millis(500)).and_then(|_| std::fs::read(&item.path));
                            let (state, matched, failure) = match result { Ok(_bytes) => { let request = sentinel_core::ScanRequest { scan_id: Uuid::new_v4(), target: sentinel_core::ScanTarget(item.path.clone()), recursive: false, limits: ScanLimits::default() }; match scan(&request, Some(engine.clone())).await { Ok(bundle) => { let matched = bundle.records.iter().any(|r| matches!(r.verdict, Verdict::Match | Verdict::Suspicious)); (if matched { "MATCH" } else { "NO_MATCH" }, matched, None) }, Err(e) => ("FAILED", false, Some(e.to_string())) } }, Err(e) => ("FAILED", false, Some(e.to_string())) };
                            if matched { counters.lock().unwrap().matched += 1; } counters.lock().unwrap().scanned += 1;
                            let line = serde_json::json!({"schema_version":"sentinel-watch/v1","event_id":item.id,"event_type":format!("{:?}", item.kind),"path":item.path,"state":state,"failure":failure,"latency_ms":started.elapsed().as_millis()});
                            if json { println!("{}", line); } else { println!("watch state={} path={}", state, item.path.display()); }
                        }
                    }
                }
            }
            let c = counters.lock().unwrap().clone();
            eprintln!(
                "watch summary accepted={} coalesced={} dropped={} rejected={} scanned={} matched={} failed={} cancelled={}",
                c.accepted,
                c.coalesced,
                c.dropped,
                c.rejected,
                c.scanned,
                c.matched,
                c.failed,
                c.cancelled
            );
            Ok(0)
        }
        Command::Scan {
            path,
            recursive,
            json,
            output,
            rules,
            yara_rules,
            yara_namespace,
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
            let rule_engine = match (rules, yara_rules) {
                (Some(rule_path), None) => {
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
                (None, Some(rule_path)) => {
                    let source = std::fs::read_to_string(&rule_path).map_err(|error| {
                        (
                            3,
                            format!(
                                "failed to read YARA-X rules {}: {error}",
                                rule_path.to_string_lossy()
                            ),
                        )
                    })?;
                    Some(Arc::new(
                        YaraXEngine::compile(
                            &rule_path.to_string_lossy(),
                            &[YaraXRuleSource {
                                namespace: &yara_namespace,
                                source: &source,
                            }],
                        )
                        .map_err(|error| (3, error.to_string()))?,
                    ) as Arc<dyn sentinel_rules::RuleEngine>)
                }
                (None, None) => None,
                (Some(_), Some(_)) => {
                    return Err((
                        3,
                        "--rules and --yara-rules are mutually exclusive".to_owned(),
                    ));
                }
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
