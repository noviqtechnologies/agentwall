use criterion::{black_box, criterion_group, criterion_main, Criterion};
use agentwall::policy::safe_mode::SafeModeScanner;
use serde_json::json;

fn bench_safe_mode(c: &mut Criterion) {
    let scanner = SafeModeScanner::new().expect("Failed to create scanner");

    let mut group = c.benchmark_group("Safe Mode Scanner");

    // Bench 1: A completely safe string that doesn't trigger any rules
    let safe_params = json!({
        "path": "/workspace/docs/readme.md",
        "command": "npm install",
        "nested": {
            "key": "value"
        }
    });

    group.bench_function("Scan Safe Params", |b| {
        b.iter(|| scanner.scan(black_box(&safe_params)))
    });

    // Bench 2: A string that triggers a rule near the end of the evaluation (worst case)
    // We'll trigger SSRF which is towards the end of the list.
    let malicious_params = json!({
        "url": "http://169.254.169.254/latest/meta-data/"
    });

    group.bench_function("Scan Malicious Params (SSRF)", |b| {
        b.iter(|| scanner.scan(black_box(&malicious_params)))
    });

    group.finish();
}

criterion_group!(benches, bench_safe_mode);
criterion_main!(benches);
