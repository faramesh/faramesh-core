"""Typed policy objects for client-side policy building and validation.

These models allow you to build and test policies in code without needing
to write YAML files. The server-side DSL, evaluators, and policy packs
remain in Horizon/Nexus.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Literal
from enum import Enum


class RiskLevel(str, Enum):
    """Risk level enumeration."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class MatchCondition:
    """Match condition for policy rules.
    
    All specified conditions must match for the rule to apply.
    """
    tool: Optional[str] = None  # Tool name or "*" for any
    op: Optional[str] = None  # Operation name or "*" for any
    operation: Optional[str] = None  # Alias for op
    pattern: Optional[str] = None  # Regex pattern to match in params
    contains: Optional[str] = None  # Substring match in params JSON
    amount_gt: Optional[float] = None  # Numeric comparison: amount > value
    amount_lt: Optional[float] = None  # Numeric comparison: amount < value
    amount_gte: Optional[float] = None  # Numeric comparison: amount >= value
    amount_lte: Optional[float] = None  # Numeric comparison: amount <= value
    path_contains: Optional[str] = None  # Path contains substring
    path_starts_with: Optional[str] = None  # Path starts with
    path_ends_with: Optional[str] = None  # Path ends with
    method: Optional[str] = None  # HTTP method
    branch: Optional[str] = None  # Git branch name
    agent_id: Optional[str] = None  # Agent identifier
    field: Optional[str] = None  # Custom field name
    value: Optional[Any] = None  # Custom field value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        result = {}
        if self.tool is not None:
            result["tool"] = self.tool
        if self.op is not None:
            result["op"] = self.op
        elif self.operation is not None:
            result["op"] = self.operation
        if self.pattern is not None:
            result["pattern"] = self.pattern
        if self.contains is not None:
            result["contains"] = self.contains
        if self.amount_gt is not None:
            result["amount_gt"] = self.amount_gt
        if self.amount_lt is not None:
            result["amount_lt"] = self.amount_lt
        if self.amount_gte is not None:
            result["amount_gte"] = self.amount_gte
        if self.amount_lte is not None:
            result["amount_lte"] = self.amount_lte
        if self.path_contains is not None:
            result["path_contains"] = self.path_contains
        if self.path_starts_with is not None:
            result["path_starts_with"] = self.path_starts_with
        if self.path_ends_with is not None:
            result["path_ends_with"] = self.path_ends_with
        if self.method is not None:
            result["method"] = self.method
        if self.branch is not None:
            result["branch"] = self.branch
        if self.agent_id is not None:
            result["agent_id"] = self.agent_id
        if self.field is not None:
            result["field"] = self.field
        if self.value is not None:
            result["value"] = self.value
        return result


@dataclass
class PolicyRule:
    """A single policy rule.
    
    Each rule must have exactly one effect: allow, deny, or require_approval.
    """
    match: MatchCondition
    description: str
    allow: Optional[bool] = None
    deny: Optional[bool] = None
    require_approval: Optional[bool] = None
    risk: Optional[RiskLevel] = None
    
    def __post_init__(self):
        """Validate that exactly one effect is specified."""
        effects = sum([
            self.allow is not None and self.allow,
            self.deny is not None and self.deny,
            self.require_approval is not None and self.require_approval,
        ])
        if effects != 1:
            raise ValueError(
                "PolicyRule must have exactly one effect: allow, deny, or require_approval"
            )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        result = {
            "match": self.match.to_dict(),
            "description": self.description,
        }
        if self.allow is not None:
            result["allow"] = self.allow
        if self.deny is not None:
            result["deny"] = self.deny
        if self.require_approval is not None:
            result["require_approval"] = self.require_approval
        if self.risk is not None:
            result["risk"] = self.risk.value if isinstance(self.risk, RiskLevel) else self.risk
        return result


@dataclass
class RiskRule:
    """A risk scoring rule."""
    name: str
    when: MatchCondition
    risk_level: RiskLevel
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        return {
            "name": self.name,
            "when": self.when.to_dict(),
            "risk_level": self.risk_level.value if isinstance(self.risk_level, RiskLevel) else self.risk_level,
        }


@dataclass
class Policy:
    """Complete policy definition.
    
    This represents a full policy file with rules and optional risk scoring.
    """
    rules: List[PolicyRule]
    risk: Optional[Dict[str, List[RiskRule]]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        result = {
            "rules": [rule.to_dict() for rule in self.rules],
        }
        if self.risk and self.risk.get("rules"):
            result["risk"] = {
                "rules": [rule.to_dict() for rule in self.risk["rules"]],
            }
        return result
    
    def to_yaml(self) -> str:
        """Convert to YAML string."""
        try:
            import yaml
            return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)
        except ImportError:
            raise ImportError("YAML support requires pyyaml. Install with: pip install pyyaml")
    
    def validate(self) -> List[str]:
        """Validate the policy and return list of errors (empty if valid)."""
        errors = []
        
        if not self.rules:
            errors.append("Policy must have at least one rule")
        
        for i, rule in enumerate(self.rules):
            if not rule.description:
                errors.append(f"Rule {i+1}: description is required")
            
            if not rule.match.to_dict():
                errors.append(f"Rule {i+1}: match conditions cannot be empty")
        
        return errors


def create_policy(
    rules: List[PolicyRule],
    risk_rules: Optional[List[RiskRule]] = None,
) -> Policy:
    """Convenience function to create a Policy.
    
    Args:
        rules: List of policy rules
        risk_rules: Optional list of risk scoring rules
    
    Returns:
        Policy object
    
    Example:
        >>> from faramesh.sdk.policy import create_policy, PolicyRule, MatchCondition, RiskLevel
        >>> 
        >>> policy = create_policy([
        ...     PolicyRule(
        ...         match=MatchCondition(tool="http", op="get"),
        ...         description="Allow HTTP GET",
        ...         allow=True,
        ...         risk=RiskLevel.LOW,
        ...     ),
        ...     PolicyRule(
        ...         match=MatchCondition(tool="*", op="*"),
        ...         description="Default deny",
        ...         deny=True,
        ...     ),
        ... ])
        >>> print(policy.to_yaml())
    """
    risk = None
    if risk_rules:
        risk = {"rules": risk_rules}
    
    return Policy(rules=rules, risk=risk)
