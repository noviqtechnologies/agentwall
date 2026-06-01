# FR-102 Policy Evaluation Benchmark Results

## Performance Overview
The policy engine was benchmarked on a Windows environment under the `bench` profile (fully optimized release build) against a generated **1,000-rule allowlist policy** containing a mix of exact matches, wildcards, and schema-constrained tool rules.

All measured scenarios are well within the P0 Acceptance Criterion **(Latency < 1ms p99)**. In fact, worst-case evaluation latency is **less than 15 microseconds** (~0.015ms), which is over **60x faster** than the required performance envelope.

---

## Benchmark Results Detail

| Scenario / Benchmark Case | p50 Latency (Median) | p99 Latency (Upper Bound) | Description / Notes |
| :--- | :---: | :---: | :--- |
| **`eval_allowed_worst_case_1000_rules`** | **5.12 µs** | **5.25 µs** | Evaluates a tool name located at the very end of a 1,000-rule allowlist (forcing full scan). |
| **`eval_denied_not_in_policy_1000_rules`** | **905.99 ns** | **975.79 ns** | Tool is not listed anywhere in the 1,000-rule policy; rejected instantly. |
| **`eval_schema_validation_allowed`** | **1.71 µs** | **1.90 µs** | Tool matches schema constraints successfully using jsonschema engine. |
| **`eval_schema_validation_denied`** | **3.47 µs** | **3.84 µs** | Tool violates schema constraints (fails validation & generates error report). |
| **`eval_regex_denial_1000_rules`** | **12.71 µs** | **13.68 µs** | Matches regex block/deny rule, matching worst-case path through custom regex rules. |

---

## Technical Highlights
- **Zero File I/O in Hot Path**: Policies are fully pre-compiled and memory-mapped during engine startup. Hot-path execution involves zero system calls or I/O.
- **Efficient JSON Schema Validation**: Leveraging `jsonschema` compiled validator structures allows rich parameter validation in under 2 microseconds.
- **Low Memory Overhead**: Pre-allocated structures and structured validation minimize heap allocations during evaluation.
