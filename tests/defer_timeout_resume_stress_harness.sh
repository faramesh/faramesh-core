#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run_cmd() {
  echo "+ $*"
  "$@"
}

# G3 core workflow stress lane: timeout finalization + high-contention resolve races.
run_cmd go test ./internal/core/defer -run 'TestLateResolveAfterTimeoutKeepsExpiredTerminalState|TestResolveStressOnlyOneWinnerMaintainsStableFinalState' -count=1

# G3 daemon wait-for-approval stress lane: timeout with late approve/deny resumes.
run_cmd go test ./internal/adapter/daemon -run 'TestWaitForApprovalTimeoutAllowsLateApprovalResolution|TestWaitForApprovalTimeoutAllowsLateDenialResolution' -count=1

# G3 escalation lane: triage SLA breach escalation ordering and single-fire behavior.
run_cmd go test ./internal/core/defer -run 'TestTriageClassifyAndEscalateOnce|TestTriagePendingSortedOrdersByPriority' -count=1

echo "defer timeout/resume stress harness passed"
