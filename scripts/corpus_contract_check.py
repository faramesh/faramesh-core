#!/usr/bin/env python3
"""Validate corpus expected.json files against the agent corpus / runtime-truth contract."""

from __future__ import annotations

import json
import os
import sys

REQUIRED_TOP_LEVEL = (
    "status",
    "framework",
    "pattern",
    "coverage_tier",
    "harness",
    "expected_tools",
    "enforcement_surfaces",
    "detection",
)

REPLAY_REQUIRED_TIERS = frozenset({"A", "B"})


def err(msg: str) -> None:
    print(f"corpus contract: {msg}", file=sys.stderr)


def validate_expected(path: str, data: dict) -> list[str]:
    problems: list[str] = []
    for key in REQUIRED_TOP_LEVEL:
        if key not in data:
            problems.append(f"{path}: missing required key {key!r}")

    st = data.get("status", "")
    tier = (data.get("coverage_tier") or "").strip().upper()

    tools = data.get("expected_tools")
    if not isinstance(tools, list) or len(tools) < 1:
        problems.append(f"{path}: expected_tools must be a non-empty array")

    surf = data.get("enforcement_surfaces")
    if not isinstance(surf, dict):
        problems.append(f"{path}: enforcement_surfaces must be an object")
    else:
        for k in (
            "framework_hook",
            "attachable",
            "governable",
            "policy_visible",
            "credential_brokered",
            "shell_governed",
            "network_governed",
            "mcp_governed",
            "audit_complete",
        ):
            if k not in surf:
                problems.append(f"{path}: enforcement_surfaces missing {k!r}")

    det = data.get("detection")
    if not isinstance(det, dict):
        problems.append(f"{path}: detection must be an object")
    else:
        for k in ("framework_detected", "framework_name", "trust_level"):
            if k not in det:
                problems.append(f"{path}: detection missing {k!r}")

    if st == "passing":
        harness = (data.get("harness") or "").strip()
        if not harness:
            problems.append(f"{path}: passing entry requires non-empty harness")

        if not isinstance(surf, dict) or not surf.get("audit_complete"):
            problems.append(f"{path}: passing entry requires enforcement_surfaces.audit_complete")

        rp = data.get("replay_parity")
        if tier in REPLAY_REQUIRED_TIERS:
            if not isinstance(rp, dict):
                problems.append(f"{path}: tier {tier} requires replay_parity object")
            else:
                if not rp.get("asserted"):
                    problems.append(
                        f"{path}: tier {tier} requires replay_parity.asserted true"
                    )
                if not rp.get("strict_reason"):
                    problems.append(
                        f"{path}: tier {tier} requires replay_parity.strict_reason true"
                    )
                src = (rp.get("source") or "").strip().lower()
                if src != "wal":
                    problems.append(f"{path}: tier {tier} requires replay_parity.source 'wal'")

        ht = data.get("hook_truth")
        if not isinstance(ht, dict):
            problems.append(f"{path}: passing entry requires hook_truth object")
        else:
            layer = (ht.get("interception_layer") or "").strip()
            if layer not in (
                "framework_autopatch",
                "mcp_gateway",
                "mixed",
            ):
                problems.append(
                    f"{path}: hook_truth.interception_layer must be "
                    f"framework_autopatch|mcp_gateway|mixed, got {layer!r}"
                )
            if not ht.get("pre_execution_gate"):
                problems.append(
                    f"{path}: hook_truth.pre_execution_gate must be true for passing entries"
                )
            if not ht.get("dpr_evidence_expected"):
                problems.append(
                    f"{path}: hook_truth.dpr_evidence_expected must be true for passing entries"
                )

    elif st == "wip":
        pass
    else:
        problems.append(f"{path}: unknown status {st!r} (expected passing or wip)")

    return problems


def main() -> int:
    corpus_dir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "tests/corpus")
    if not os.path.isdir(corpus_dir):
        err(f"corpus dir not found: {corpus_dir}")
        return 1

    all_problems: list[str] = []
    for root, _, files in os.walk(corpus_dir):
        if "expected.json" not in files:
            continue
        path = os.path.join(root, "expected.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            all_problems.append(f"{path}: invalid JSON: {e}")
            continue
        if not isinstance(data, dict):
            all_problems.append(f"{path}: expected top-level object")
            continue
        all_problems.extend(validate_expected(path, data))

    if all_problems:
        for p in all_problems:
            err(p)
        err(f"failed with {len(all_problems)} issue(s)")
        return 1

    print(f"corpus contract: OK ({corpus_dir})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
