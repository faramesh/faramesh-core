#!/usr/bin/env sh
set -eu

# Thin wrapper for onboarding preflight checks.
# This is not a full installer; use scripts/faramesh_setup.sh for end-to-end setup.

POLICY_PATH="${FARAMESH_POLICY_PATH:-}"
STRICT_MODE="${FARAMESH_ONBOARD_STRICT:-true}"

if [ "${1:-}" = "--policy" ] && [ -n "${2:-}" ]; then
  POLICY_PATH="$2"
  shift 2
fi

if [ -n "$POLICY_PATH" ]; then
  exec faramesh onboard --strict="$STRICT_MODE" --policy "$POLICY_PATH" "$@"
fi

exec faramesh onboard --strict="$STRICT_MODE" "$@"
