# Benchmark and Reliability Reporting

This document defines the reproducible commands for policy performance and reliability checks.

## 1) Policy Evaluation Benchmarks

Run policy engine benchmarks with memory metrics:

```bash
go test ./internal/core/policy -run '^$' -bench 'BenchmarkEngineEvaluate' -benchmem -count=3
```

Benchmarks currently included:

- `BenchmarkEngineEvaluateSimplePermit`
- `BenchmarkEngineEvaluateConditionalMatch`

## 2) Reliability Validation

Run adversarial and replay/backtest reliability suites:

```bash
go test ./tests/adversarial -count=1
go test ./cmd/faramesh -run 'TestRunPolicyReplayWAL|TestRunPolicyBacktestFixtures' -count=1
```

## 3) One-Command Report Generation

Generate a timestamped artifact bundle and markdown report:

```bash
./scripts/generate_policy_reliability_report.sh
```

Optional custom output directory:

```bash
./scripts/generate_policy_reliability_report.sh ./reports/policy-reliability/manual-run
```

Generated artifacts:

- `benchmarks.txt`
- `adversarial.txt`
- `replay_backtest.txt`
- `report.md`

Default output location:

- `reports/policy-reliability/<UTC timestamp>/`
