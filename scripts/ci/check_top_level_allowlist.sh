#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
allowlist_file="$repo_root/scripts/ci/top_level_allowlist.txt"

if [[ ! -f "$allowlist_file" ]]; then
  echo "missing allowlist file: $allowlist_file" >&2
  exit 1
fi

mapfile -t allowed_entries < <(grep -vE '^\s*#|^\s*$' "$allowlist_file" | sort -u)
mapfile -t root_entries < <(git -C "$repo_root" ls-tree --name-only --full-tree HEAD | sort -u)

declare -A allowed_map=()
for entry in "${allowed_entries[@]}"; do
  allowed_map["$entry"]=1
done

unexpected=()
for entry in "${root_entries[@]}"; do
  if [[ -z "${allowed_map[$entry]:-}" ]]; then
    unexpected+=("$entry")
  fi
done

if (( ${#unexpected[@]} > 0 )); then
  echo "Top-level allowlist check failed." >&2
  echo "Unexpected root entries in git tree:" >&2
  for entry in "${unexpected[@]}"; do
    echo "  - $entry" >&2
  done
  echo "" >&2
  echo "Allowed entries are listed in: scripts/ci/top_level_allowlist.txt" >&2
  exit 1
fi

echo "Top-level allowlist check passed."
