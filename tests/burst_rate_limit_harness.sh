#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run_cmd() {
  echo "+ $*"
  "$@"
}

# SDK socket adapter burst lane (rate-limited by agent id).
run_cmd go test ./internal/adapter/sdk -run 'TestGovernBurstRateLimitedByAgentID|TestGovernRateLimitIsolatedByAgentID' -count=1

# Proxy adapter burst lane (rate-limited by source IP identity).
run_cmd go test ./internal/adapter/proxy -run 'TestServerAuthorizeBurstRateLimitedBySourceIP|TestServerAuthorizeRateLimitIsolatedBySourceIP' -count=1

echo "burst rate-limit harness passed"
