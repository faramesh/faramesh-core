"""Tests for risk scoring functionality."""

import tempfile
from pathlib import Path

import yaml

from faramesh.server.policy_engine import PolicyEngine


def test_risk_scoring_basic():
    """Test basic risk scoring from risk rules."""
    policy_data = {
        "rules": [
            {
                "match": {"tool": "*", "op": "*"},
                "allow": True,
            }
        ],
        "risk": {
            "rules": [
                {
                    "name": "dangerous_shell",
                    "when": {
                        "tool": "shell",
                        "operation": "run",
                        "pattern": "rm -rf",
                    },
                    "risk_level": "high",
                }
            ]
        },
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(policy_data, f)
        policy_path = f.name
    
    try:
        engine = PolicyEngine(policy_path)
        
        # Test high risk
        decision, reason, risk = engine.evaluate(
            tool="shell",
            operation="run",
            params={"cmd": "rm -rf /tmp"},
            context={},
        )
        assert risk == "high"
        
        # Test default low risk
        decision, reason, risk = engine.evaluate(
            tool="http",
            operation="get",
            params={"url": "https://example.com"},
            context={},
        )
        assert risk == "low"
    finally:
        Path(policy_path).unlink()


def test_risk_scoring_with_rule_risk():
    """Test that rule-level risk overrides computed risk."""
    policy_data = {
        "rules": [
            {
                "match": {"tool": "shell", "op": "*"},
                "require_approval": True,
                "risk": "medium",  # Rule-level risk
            }
        ],
        "risk": {
            "rules": [
                {
                    "name": "dangerous_shell",
                    "when": {
                        "tool": "shell",
                        "operation": "run",
                        "pattern": "rm -rf",
                    },
                    "risk_level": "high",
                }
            ]
        },
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(policy_data, f)
        policy_path = f.name
    
    try:
        engine = PolicyEngine(policy_path)
        
        # Rule-level risk should take precedence
        decision, reason, risk = engine.evaluate(
            tool="shell",
            operation="run",
            params={"cmd": "rm -rf /tmp"},
            context={},
        )
        assert risk == "medium"  # From rule, not risk rule
    finally:
        Path(policy_path).unlink()
