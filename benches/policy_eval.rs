//! Benchmark: policy evaluation with 1000-rule policy (FR-102, NFR-102)
//!
//! Acceptance criterion: `evaluate()` < 1ms p99 with a 1000-rule policy.
//!
//! Run: `cargo bench --bench policy_eval`
//! Results committed to: `bench/results/policy_eval_baseline.md`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jsonschema::JSONSchema;
use regex::Regex;
use serde_json::json;
use std::sync::Arc;

use agentwall::policy::engine::{CompiledParam, CompiledPolicy, CompiledTool};
use agentwall::policy::schema::ParamType;

// ---------------------------------------------------------------------------
// Policy construction helpers
// ---------------------------------------------------------------------------

/// Build a compiled policy with `n` allow-rules plus one deny sentinel.
///
/// Every tool gets two parameters to make evaluation non-trivial:
/// - `path` (string, anchored regex)
/// - `limit` (number)
///
/// Tool names follow the pattern `tool_NNN` so the lookup is realistic.
fn make_policy(n: usize) -> CompiledPolicy {
    let pattern = Regex::new(r"^(?:/workspace/.*)$").unwrap();

    let tools: Vec<CompiledTool> = (0..n)
        .map(|i| CompiledTool {
            name: format!("tool_{:04}", i),
            action: "allow".to_string(),
            risk: None,
            identity: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
            parameters: vec![
                CompiledParam {
                    name: "path".to_string(),
                    param_type: ParamType::String,
                    pattern: Some(pattern.clone()),
                    schema: None,
                    max_length: Some(512),
                    required: true,
                    validators: vec![],
                },
                CompiledParam {
                    name: "limit".to_string(),
                    param_type: ParamType::Number,
                    pattern: None,
                    schema: None,
                    max_length: None,
                    required: false,
                    validators: vec![],
                },
            ],
        })
        .collect();

    CompiledPolicy {
        tools,
        max_calls_per_second: 0,
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
    }
}

/// Build a policy where one tool has an inline JSON Schema on an object param.
fn make_policy_with_schema() -> CompiledPolicy {
    let schema_json = json!({
        "type": "object",
        "properties": {
            "limit": { "type": "integer", "minimum": 0, "maximum": 100 },
            "tag":   { "type": "string" }
        },
        "required": ["limit"],
        "additionalProperties": false
    });
    let compiled_schema = Arc::new(JSONSchema::compile(&schema_json).unwrap());

    CompiledPolicy {
        tools: vec![CompiledTool {
            name: "query_db".to_string(),
            action: "allow".to_string(),
            risk: None,
            identity: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
            parameters: vec![CompiledParam {
                name: "options".to_string(),
                param_type: ParamType::Object,
                pattern: None,
                schema: Some(compiled_schema),
                max_length: None,
                required: true,
                validators: vec![],
            }],
        }],
        max_calls_per_second: 0,
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
    }
}

// ---------------------------------------------------------------------------
// Benchmark groups
// ---------------------------------------------------------------------------

/// Hot path: evaluate a known-allowed tool against a 1000-rule policy.
/// This is the acceptance-criterion benchmark (< 1ms p99).
fn bench_eval_allowed_1000_rules(c: &mut Criterion) {
    let policy = make_policy(1000);
    // Target: last tool in the list — worst case linear scan
    let params = json!({
        "path": "/workspace/src/main.rs",
        "limit": 50
    });

    c.bench_function("eval_allowed_worst_case_1000_rules", |b| {
        b.iter(|| {
            black_box(policy.evaluate(black_box("tool_0999"), black_box(&params), None))
        })
    });
}

/// Denial path: tool not in the policy at all.
fn bench_eval_denied_not_in_policy(c: &mut Criterion) {
    let policy = make_policy(1000);
    let params = json!({ "path": "/workspace/src/main.rs" });

    c.bench_function("eval_denied_not_in_policy_1000_rules", |b| {
        b.iter(|| {
            black_box(policy.evaluate(black_box("unknown_tool"), black_box(&params), None))
        })
    });
}

/// JSON Schema validation path: object param against inline schema.
fn bench_eval_schema_validation(c: &mut Criterion) {
    let policy = make_policy_with_schema();
    let valid_params = json!({ "options": { "limit": 42, "tag": "prod" } });

    c.bench_function("eval_schema_validation_allowed", |b| {
        b.iter(|| {
            black_box(policy.evaluate(black_box("query_db"), black_box(&valid_params), None))
        })
    });
}

/// Denial by schema violation: object param that fails the inline schema.
fn bench_eval_schema_denial(c: &mut Criterion) {
    let policy = make_policy_with_schema();
    // limit exceeds maximum of 100
    let bad_params = json!({ "options": { "limit": 999 } });

    c.bench_function("eval_schema_validation_denied", |b| {
        b.iter(|| {
            black_box(policy.evaluate(black_box("query_db"), black_box(&bad_params), None))
        })
    });
}

/// Regex denial: string parameter that doesn't match the anchored pattern.
fn bench_eval_regex_denial(c: &mut Criterion) {
    let policy = make_policy(1000);
    // Path outside /workspace → regex mismatch
    let bad_params = json!({
        "path": "/etc/passwd",
        "limit": 10
    });

    c.bench_function("eval_regex_denial_1000_rules", |b| {
        b.iter(|| {
            black_box(policy.evaluate(black_box("tool_0999"), black_box(&bad_params), None))
        })
    });
}

criterion_group!(
    benches,
    bench_eval_allowed_1000_rules,
    bench_eval_denied_not_in_policy,
    bench_eval_schema_validation,
    bench_eval_schema_denial,
    bench_eval_regex_denial,
);
criterion_main!(benches);
