#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${1:-${ROOT_DIR}/reports/policy-reliability/${STAMP}}"

mkdir -p "${OUT_DIR}"

pushd "${ROOT_DIR}" >/dev/null

echo "[1/3] Running policy benchmarks..."
go test ./internal/core/policy -run '^$' -bench 'BenchmarkEngineEvaluate' -benchmem -count=3 >"${OUT_DIR}/benchmarks.txt"

echo "[2/3] Running adversarial reliability tests..."
go test ./tests/adversarial -count=1 >"${OUT_DIR}/adversarial.txt"

echo "[3/3] Running replay/backtest reliability tests..."
go test ./cmd/faramesh -run 'TestRunPolicyReplayWAL|TestRunPolicyBacktestFixtures' -count=1 >"${OUT_DIR}/replay_backtest.txt"

REPORT_PATH="${OUT_DIR}/report.md"
{
  echo "# Policy Reliability Report"
  echo
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "## Benchmarks"
  echo '```text'
  cat "${OUT_DIR}/benchmarks.txt"
  echo '```'
  echo
  echo "## Adversarial"
  echo '```text'
  cat "${OUT_DIR}/adversarial.txt"
  echo '```'
  echo
  echo "## Replay and Backtest"
  echo '```text'
  cat "${OUT_DIR}/replay_backtest.txt"
  echo '```'
} >"${REPORT_PATH}"

popd >/dev/null

echo "Policy reliability artifacts written to ${OUT_DIR}"
echo "Report: ${REPORT_PATH}"
