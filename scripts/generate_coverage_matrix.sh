#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS_DIR="${1:-$CORE_DIR/tests/corpus}"

python3 - "$CORE_DIR" "$CORPUS_DIR" <<'PY'
import json
import os
import sys

core_dir = os.path.abspath(sys.argv[1])
corpus_dir = os.path.abspath(sys.argv[2])
json_out = os.path.join(corpus_dir, "coverage-matrix.json")
md_out = os.path.join(corpus_dir, "coverage-matrix.md")

try:
    corpus_label = os.path.relpath(corpus_dir, core_dir)
except ValueError:
    corpus_label = corpus_dir

entries = []
for root, _, files in os.walk(corpus_dir):
    if "expected.json" not in files:
        continue
    expected_path = os.path.join(root, "expected.json")
    with open(expected_path, "r", encoding="utf-8") as f:
        expected = json.load(f)
    rel = os.path.relpath(root, corpus_dir)
    surfaces = expected.get("enforcement_surfaces", {})
    replay = expected.get("replay_parity", {})
    hook = expected.get("hook_truth", {})
    entry = {
        "entry": rel,
        "status": expected.get("status", "unknown"),
        "framework": expected.get("framework", ""),
        "pattern": expected.get("pattern", ""),
        "coverage_tier": expected.get("coverage_tier", ""),
        "harness": expected.get("harness", ""),
        "attachable": bool(surfaces.get("attachable", False)),
        "governable": bool(surfaces.get("governable", False)),
        "policy_visible": bool(surfaces.get("policy_visible", False)),
        "credential_brokered": bool(surfaces.get("credential_brokered", False)),
        "shell_governed": bool(surfaces.get("shell_governed", False)),
        "network_governed": bool(surfaces.get("network_governed", False)),
        "mcp_governed": bool(surfaces.get("mcp_governed", False)),
        "audit_complete": bool(surfaces.get("audit_complete", False)),
        "replay_parity": bool(replay.get("asserted", False)),
        "replay_strict_reason": bool(replay.get("strict_reason", False)),
        "replay_source": replay.get("source", ""),
        "hook_interception_layer": hook.get("interception_layer", ""),
        "hook_pre_execution_gate": bool(hook.get("pre_execution_gate", False)),
        "known_gaps": expected.get("known_gaps", []),
        "expected_tools": expected.get("expected_tools", []),
    }
    entries.append(entry)

entries.sort(key=lambda item: item["entry"])

summary = {
    "entries": len(entries),
    "passing": sum(1 for e in entries if e["status"] == "passing"),
    "wip": sum(1 for e in entries if e["status"] == "wip"),
    "replay_parity": sum(1 for e in entries if e["replay_parity"]),
    "tiers": {},
}
for entry in entries:
    tier = entry["coverage_tier"] or "unknown"
    summary["tiers"][tier] = summary["tiers"].get(tier, 0) + 1

with open(json_out, "w", encoding="utf-8") as f:
    json.dump({"summary": summary, "entries": entries}, f, indent=2)
    f.write("\n")

lines = [
    "# Coverage Matrix",
    "",
    f"- Corpus root: `{corpus_label}`",
    f"- Entries: {summary['entries']}",
    f"- Passing: {summary['passing']}",
    f"- WIP: {summary['wip']}",
    "",
    f"- Replay parity asserted: {summary['replay_parity']}",
    "",
    "| Entry | Status | Tier | Framework | Attachable | Governable | Policy Visible | Credential Brokered | Shell | Network | MCP | Audit | Replay | Hook | Pre-exec | Known Gaps |",
    "|-------|--------|------|-----------|------------|------------|----------------|---------------------|-------|---------|-----|-------|--------|------|----------|------------|",
]

def yn(value):
    return "yes" if value else "no"

for entry in entries:
    gaps = "; ".join(entry["known_gaps"]) if entry["known_gaps"] else "-"
    hook_layer = entry.get("hook_interception_layer") or "-"
    hook_pe = yn(entry.get("hook_pre_execution_gate", False))
    lines.append(
        f"| `{entry['entry']}` | {entry['status']} | {entry['coverage_tier']} | {entry['framework']} | "
        f"{yn(entry['attachable'])} | {yn(entry['governable'])} | {yn(entry['policy_visible'])} | "
        f"{yn(entry['credential_brokered'])} | {yn(entry['shell_governed'])} | {yn(entry['network_governed'])} | "
        f"{yn(entry['mcp_governed'])} | {yn(entry['audit_complete'])} | {yn(entry['replay_parity'])} | "
        f"{hook_layer} | {hook_pe} | {gaps} |"
    )

with open(md_out, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
PY
