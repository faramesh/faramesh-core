#!/usr/bin/env python3
"""Example: Build policy in code using typed objects."""

from faracore.sdk.policy import (
    create_policy,
    PolicyRule,
    MatchCondition,
    RiskRule,
    RiskLevel,
)

# Build a policy programmatically
policy = create_policy(
    rules=[
        PolicyRule(
            match=MatchCondition(tool="http", op="get"),
            description="Allow HTTP GET requests",
            allow=True,
            risk=RiskLevel.LOW,
        ),
        PolicyRule(
            match=MatchCondition(tool="shell", op="*"),
            description="Shell commands require approval",
            require_approval=True,
            risk=RiskLevel.MEDIUM,
        ),
        PolicyRule(
            match=MatchCondition(tool="*", op="*"),
            description="Default deny",
            deny=True,
            risk=RiskLevel.HIGH,
        ),
    ],
    risk_rules=[
        RiskRule(
            name="dangerous_shell",
            when=MatchCondition(tool="shell", pattern="rm -rf|shutdown"),
            risk_level=RiskLevel.HIGH,
        ),
    ],
)

# Validate it
errors = policy.validate()
if errors:
    print("Policy validation errors:")
    for error in errors:
        print(f"  - {error}")
    exit(1)

# Convert to YAML
try:
    yaml_str = policy.to_yaml()
    print("Generated policy YAML:")
    print(yaml_str)
except ImportError:
    print("YAML support requires pyyaml. Install with: pip install pyyaml")
    print("\nPolicy dict:")
    import json
    print(json.dumps(policy.to_dict(), indent=2))
