"""Unit tests for faramesh.govern (no HTTP)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from faramesh import DeferredError, DenyError, govern
from faramesh.gate import GateDecision


def _dec(**kwargs) -> GateDecision:
    base = {
        "outcome": "EXECUTE",
        "reason_code": "RULE_PERMIT",
        "reason": None,
        "request_hash": "abc",
        "policy_version": "1",
        "policy_hash": "ph",
        "profile_id": None,
        "profile_version": None,
        "profile_hash": None,
        "runtime_version": None,
        "provenance_id": None,
    }
    base.update(kwargs)
    return GateDecision.from_dict(base)


@patch("faramesh.govern.gate_decide")
def test_govern_execute(mock_gd):
    mock_gd.return_value = _dec(outcome="EXECUTE")
    d = govern("a", "http", "get", {})
    assert d.outcome == "EXECUTE"


@patch("faramesh.govern.gate_decide")
def test_govern_permit(mock_gd):
    mock_gd.return_value = _dec(outcome="PERMIT")
    d = govern("a", "http", "get", {})
    assert d.outcome == "PERMIT"


@patch("faramesh.govern.gate_decide")
def test_govern_halt_raises_deny(mock_gd):
    mock_gd.return_value = _dec(outcome="HALT", reason_code="RULE_DENY")
    with pytest.raises(DenyError) as ei:
        govern("a", "shell", "run", {})
    assert ei.value.reason_code == "RULE_DENY"
    assert ei.value.decision is not None


@patch("faramesh.govern.gate_decide")
def test_govern_abstain_raises_deferred(mock_gd):
    mock_gd.return_value = _dec(outcome="ABSTAIN", reason_code="DEFER_APPROVAL")
    with pytest.raises(DeferredError) as ei:
        govern("a", "pay", "refund", {})
    assert ei.value.reason_code == "DEFER_APPROVAL"
