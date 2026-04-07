#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Compatibility wrapper. Canonical lifecycle entrypoint is faramesh_setup.sh.
exec bash "$CORE_DIR/scripts/faramesh_setup.sh" onboard "$@"
