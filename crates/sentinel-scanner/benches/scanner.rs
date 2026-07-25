#![allow(clippy::expect_used, clippy::unwrap_used)]
use criterion::{Criterion, criterion_group, criterion_main};
use sentinel_core::{ScanLimits, ScanRequest, ScanTarget};
use sentinel_scanner::scan;
use uuid::Uuid;

fn scanner_benchmark(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("benchmark runtime");
    let directory = tempfile::tempdir().expect("benchmark tempdir");
    let target = directory.path().join("sample.bin");
    std::fs::write(&target, vec![42_u8; 1024 * 1024]).expect("benchmark fixture");
    criterion.bench_function("scan_1_mib", |bench| {
        bench.iter(|| {
            runtime.block_on(scan(
                &ScanRequest {
                    scan_id: Uuid::nil(),
                    target: ScanTarget(target.clone()),
                    recursive: false,
                    limits: ScanLimits::default(),
                },
                None,
            ))
        })
    });
}
criterion_group!(benches, scanner_benchmark);
criterion_main!(benches);
