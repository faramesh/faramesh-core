"""Tests for typed policy objects."""

import pytest
from faracore.sdk.policy import (
    Policy,
    PolicyRule,
    MatchCondition,
    RiskRule,
    RiskLevel,
    create_policy,
)


def test_match_condition_to_dict():
    """Test MatchCondition.to_dict()."""
    match = MatchCondition(
        tool="http",
        op="get",
        pattern="example.com",
    )
    
    result = match.to_dict()
    assert result["tool"] == "http"
    assert result["op"] == "get"
    assert result["pattern"] == "example.com"


def test_policy_rule_validation():
    """Test PolicyRule validation."""
    # Valid rule with allow
    rule1 = PolicyRule(
        match=MatchCondition(tool="http", op="get"),
        description="Allow HTTP GET",
        allow=True,
    )
    assert rule1.allow is True
    
    # Valid rule with deny
    rule2 = PolicyRule(
        match=MatchCondition(tool="shell", op="*"),
        description="Deny shell",
        deny=True,
    )
    assert rule2.deny is True
    
    # Invalid: no effect
    with pytest.raises(ValueError):
        PolicyRule(
            match=MatchCondition(tool="http"),
            description="No effect",
        )
    
    # Invalid: multiple effects
    with pytest.raises(ValueError):
        PolicyRule(
            match=MatchCondition(tool="http"),
            description="Multiple effects",
            allow=True,
            deny=True,
        )


def test_policy_rule_to_dict():
    """Test PolicyRule.to_dict()."""
    rule = PolicyRule(
        match=MatchCondition(tool="http", op="get"),
        description="Allow HTTP GET",
        allow=True,
        risk=RiskLevel.LOW,
    )
    
    result = rule.to_dict()
    assert result["description"] == "Allow HTTP GET"
    assert result["allow"] is True
    assert result["risk"] == "low"
    assert "match" in result


def test_risk_rule_to_dict():
    """Test RiskRule.to_dict()."""
    risk_rule = RiskRule(
        name="dangerous_shell",
        when=MatchCondition(tool="shell", pattern="rm -rf"),
        risk_level=RiskLevel.HIGH,
    )
    
    result = risk_rule.to_dict()
    assert result["name"] == "dangerous_shell"
    assert result["risk_level"] == "high"
    assert "when" in result


def test_policy_to_dict():
    """Test Policy.to_dict()."""
    policy = Policy(
        rules=[
            PolicyRule(
                match=MatchCondition(tool="http", op="get"),
                description="Allow HTTP GET",
                allow=True,
            ),
            PolicyRule(
                match=MatchCondition(tool="*", op="*"),
                description="Default deny",
                deny=True,
            ),
        ],
        risk={
            "rules": [
                RiskRule(
                    name="test_risk",
                    when=MatchCondition(tool="shell"),
                    risk_level=RiskLevel.MEDIUM,
                ),
            ],
        },
    )
    
    result = policy.to_dict()
    assert len(result["rules"]) == 2
    assert "risk" in result
    assert len(result["risk"]["rules"]) == 1


def test_policy_to_yaml():
    """Test Policy.to_yaml()."""
    policy = Policy(
        rules=[
            PolicyRule(
                match=MatchCondition(tool="http", op="get"),
                description="Allow HTTP GET",
                allow=True,
            ),
        ],
    )
    
    try:
        yaml_str = policy.to_yaml()
        assert "rules:" in yaml_str
        assert "Allow HTTP GET" in yaml_str
    except ImportError:
        pytest.skip("pyyaml not installed")


def test_policy_validate():
    """Test Policy.validate()."""
    # Valid policy
    policy1 = Policy(
        rules=[
            PolicyRule(
                match=MatchCondition(tool="http"),
                description="Test rule",
                allow=True,
            ),
        ],
    )
    errors = policy1.validate()
    assert len(errors) == 0
    
    # Invalid: no rules
    policy2 = Policy(rules=[])
    errors = policy2.validate()
    assert len(errors) > 0
    assert "at least one rule" in errors[0].lower()
    
    # Invalid: rule without description
    policy3 = Policy(
        rules=[
            PolicyRule(
                match=MatchCondition(tool="http"),
                description="",  # Empty description
                allow=True,
            ),
        ],
    )
    errors = policy3.validate()
    assert len(errors) > 0


def test_create_policy():
    """Test create_policy() convenience function."""
    rules = [
        PolicyRule(
            match=MatchCondition(tool="http", op="get"),
            description="Allow HTTP GET",
            allow=True,
        ),
    ]
    
    risk_rules = [
        RiskRule(
            name="test_risk",
            when=MatchCondition(tool="shell"),
            risk_level=RiskLevel.HIGH,
        ),
    ]
    
    policy = create_policy(rules, risk_rules)
    assert len(policy.rules) == 1
    assert policy.risk is not None
    assert len(policy.risk["rules"]) == 1


def test_match_condition_operation_alias():
    """Test that operation is an alias for op."""
    match1 = MatchCondition(tool="http", op="get")
    match2 = MatchCondition(tool="http", operation="get")
    
    dict1 = match1.to_dict()
    dict2 = match2.to_dict()
    
    assert dict1["op"] == "get"
    assert dict2["op"] == "get"
