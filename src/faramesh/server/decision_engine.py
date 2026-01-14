# src/faramesh/server/decision_engine.py
"""Centralized decision engine for execution gate."""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, Optional, Tuple

from .canonicalization import (
    compute_policy_hash,
    compute_profile_hash,
    compute_request_hash,
)
from .models import (
    Decision,
    DecisionOutcome,
    REASON_CODE_DEFAULT_DENY_NO_MATCH,
    REASON_CODE_INTERNAL_ERROR,
    REASON_CODE_MISSING_POLICY,
    REASON_CODE_POLICY_ALLOW,
    REASON_CODE_POLICY_DENY,
    REASON_CODE_POLICY_REQUIRE_APPROVAL,
    REASON_CODE_PROFILE_DISALLOWS_TOOL,
    REASON_CODE_PROFILE_LOAD_ERROR,
    REASON_CODE_PROFILE_MISSING_REQUIRED_CONTROL,
    REASON_CODE_PROFILE_RULE_DENY,
    REASON_CODE_RISK_UPGRADE,
)
from .policy_engine import PolicyEngine


class DecisionResult:
    """Result of a decision evaluation."""
    
    def __init__(
        self,
        outcome: DecisionOutcome,
        reason_code: str,
        reason: Optional[str] = None,
        reason_details: Optional[Dict[str, Any]] = None,
        request_hash: Optional[str] = None,
        policy_version: Optional[str] = None,
        policy_hash: Optional[str] = None,
        profile_id: Optional[str] = None,
        profile_version: Optional[str] = None,
        profile_hash: Optional[str] = None,
        runtime_version: Optional[str] = None,
        provenance_id: Optional[str] = None,
    ):
        self.outcome = outcome
        self.reason_code = reason_code
        self.reason = reason
        self.reason_details = reason_details
        self.request_hash = request_hash
        self.policy_version = policy_version
        self.policy_hash = policy_hash
        self.profile_id = profile_id
        self.profile_version = profile_version
        self.profile_hash = profile_hash
        self.runtime_version = runtime_version
        self.provenance_id = provenance_id


def evaluate_decision(
    agent_id: str,
    tool: str,
    operation: str,
    params: Dict[str, Any],
    context: Optional[Dict[str, Any]],
    policy_engine: PolicyEngine,
    profile: Optional[Any] = None,  # ExecutionProfile type
    runtime_version: Optional[str] = None,
) -> DecisionResult:
    """
    Centralized decision evaluation with fail-closed semantics.
    
    Args:
        agent_id: Agent identifier
        tool: Tool name
        operation: Operation name
        params: Action parameters
        context: Action context
        policy_engine: PolicyEngine instance
        profile: Optional ExecutionProfile instance
        runtime_version: Runtime version string
        
    Returns:
        DecisionResult with outcome, reason_code, and version-bound fields
    """
    context = context or {}
    
    # Step 1: Canonicalize and compute request_hash
    payload = {
        "agent_id": agent_id,
        "tool": tool,
        "operation": operation,
        "params": params,
        "context": context,
    }
    request_hash = compute_request_hash(payload)
    
    # Step 2: Get policy version and hash
    policy_version = None
    policy_hash = None
    try:
        policy_version = policy_engine.policy_version()
        if hasattr(policy_engine, "policy_hash"):
            policy_hash = policy_engine.policy_hash()
        else:
            # Compute hash from cached policy
            cached_policy = getattr(policy_engine, "cached_policy", {})
            if cached_policy:
                policy_hash = compute_policy_hash(cached_policy)
    except Exception as e:
        logging.error(f"Failed to get policy version/hash: {e}")
        return DecisionResult(
            outcome=DecisionOutcome.HALT,
            reason_code=REASON_CODE_MISSING_POLICY,
            reason=f"Policy evaluation error: {str(e)}",
            request_hash=request_hash,
            runtime_version=runtime_version,
        )
    
    # Step 3: Profile evaluation (if profile exists)
    profile_id = None
    profile_version = None
    profile_hash = None
    
    if profile:
        try:
            profile_id = getattr(profile, "id", None)
            profile_version = getattr(profile, "version", None)
            if hasattr(profile, "profile_hash"):
                profile_hash = profile.profile_hash
            else:
                # Compute hash from profile dict
                profile_dict = {
                    "id": profile_id,
                    "version": profile_version,
                    "allowed_tools": getattr(profile, "allowed_tools", []),
                    "rules": [rule.__dict__ if hasattr(rule, "__dict__") else rule for rule in getattr(profile, "rules", [])],
                    "required_controls": getattr(profile, "required_controls", {}),
                }
                profile_hash = compute_profile_hash(profile_dict)
            
            # Check if tool is allowed
            allowed_tools = getattr(profile, "allowed_tools", [])
            if tool not in allowed_tools:
                provenance_id = _compute_provenance_id(
                    request_hash, policy_hash, profile_hash, runtime_version
                )
                return DecisionResult(
                    outcome=DecisionOutcome.HALT,
                    reason_code=REASON_CODE_PROFILE_DISALLOWS_TOOL,
                    reason=f"Tool '{tool}' is not in profile allowed_tools",
                    request_hash=request_hash,
                    policy_version=policy_version,
                    policy_hash=policy_hash,
                    profile_id=profile_id,
                    profile_version=profile_version,
                    profile_hash=profile_hash,
                    runtime_version=runtime_version,
                    provenance_id=provenance_id,
                )
            
            # Evaluate profile rules
            profile_rules = getattr(profile, "rules", [])
            for rule in profile_rules:
                if _profile_rule_matches(rule, tool, operation, params, context):
                    rule_outcome = getattr(rule, "outcome", "HALT")
                    rule_reason_code = getattr(rule, "reason_code", REASON_CODE_PROFILE_RULE_DENY)
                    
                    # Map rule outcome to DecisionOutcome
                    if rule_outcome == "HALT":
                        outcome = DecisionOutcome.HALT
                    elif rule_outcome == "ABSTAIN":
                        outcome = DecisionOutcome.ABSTAIN
                    else:
                        outcome = DecisionOutcome.EXECUTE
                    
                    provenance_id = _compute_provenance_id(
                        request_hash, policy_hash, profile_hash, runtime_version
                    )
                    return DecisionResult(
                        outcome=outcome,
                        reason_code=rule_reason_code,
                        reason=getattr(rule, "name", "Profile rule matched"),
                        request_hash=request_hash,
                        policy_version=policy_version,
                        policy_hash=policy_hash,
                        profile_id=profile_id,
                        profile_version=profile_version,
                        profile_hash=profile_hash,
                        runtime_version=runtime_version,
                        provenance_id=provenance_id,
                    )
            
            # Check required controls
            required_controls = getattr(profile, "required_controls", {})
            # Handle both dict and RequiredControls instance
            if hasattr(required_controls, "approval_token"):
                approval_token_required = required_controls.approval_token
            elif isinstance(required_controls, dict):
                approval_token_required = required_controls.get("approval_token", False)
            else:
                approval_token_required = False
            
            if approval_token_required:
                if not context.get("approval_token") and not params.get("approval_token"):
                    provenance_id = _compute_provenance_id(
                        request_hash, policy_hash, profile_hash, runtime_version
                    )
                    return DecisionResult(
                        outcome=DecisionOutcome.HALT,
                        reason_code=REASON_CODE_PROFILE_MISSING_REQUIRED_CONTROL,
                        reason="Profile requires approval_token but none provided",
                        request_hash=request_hash,
                        policy_version=policy_version,
                        policy_hash=policy_hash,
                        profile_id=profile_id,
                        profile_version=profile_version,
                        profile_hash=profile_hash,
                        runtime_version=runtime_version,
                        provenance_id=provenance_id,
                    )
        except Exception as e:
            logging.error(f"Profile evaluation error: {e}", exc_info=True)
            provenance_id = _compute_provenance_id(
                request_hash, policy_hash, None, runtime_version
            )
            return DecisionResult(
                outcome=DecisionOutcome.HALT,
                reason_code=REASON_CODE_PROFILE_LOAD_ERROR,
                reason=f"Profile evaluation error: {str(e)}",
                request_hash=request_hash,
                policy_version=policy_version,
                policy_hash=policy_hash,
                runtime_version=runtime_version,
                provenance_id=provenance_id,
            )
    
    # Step 4: Policy evaluation
    try:
        decision, reason, risk = policy_engine.evaluate(
            tool=tool,
            operation=operation,
            params=params,
            context=context,
        )
    except Exception as e:
        logging.error(f"Policy evaluation error: {e}", exc_info=True)
        provenance_id = _compute_provenance_id(
            request_hash, policy_hash, profile_hash, runtime_version
        )
        return DecisionResult(
            outcome=DecisionOutcome.HALT,
            reason_code=REASON_CODE_INTERNAL_ERROR,
            reason=f"Policy evaluation error: {str(e)}",
            request_hash=request_hash,
            policy_version=policy_version,
            policy_hash=policy_hash,
            profile_id=profile_id,
            profile_version=profile_version,
            profile_hash=profile_hash,
            runtime_version=runtime_version,
            provenance_id=provenance_id,
        )
    
    # Step 5: Map policy decision to outcome and reason_code
    if decision == Decision.ALLOW:
        outcome = DecisionOutcome.EXECUTE
        reason_code = REASON_CODE_POLICY_ALLOW
    elif decision == Decision.DENY:
        outcome = DecisionOutcome.HALT
        reason_code = REASON_CODE_POLICY_DENY if reason != "No rule matched (deny by default)" else REASON_CODE_DEFAULT_DENY_NO_MATCH
    elif decision == Decision.REQUIRE_APPROVAL:
        outcome = DecisionOutcome.ABSTAIN
        reason_code = REASON_CODE_POLICY_REQUIRE_APPROVAL
    else:
        # Fallback for unknown decision
        outcome = DecisionOutcome.HALT
        reason_code = REASON_CODE_INTERNAL_ERROR
        reason = f"Unknown decision: {decision}"
        risk = "high"
    
    # Step 6: Compute provenance_id
    provenance_id = _compute_provenance_id(
        request_hash, policy_hash, profile_hash, runtime_version
    )
    
    return DecisionResult(
        outcome=outcome,
        reason_code=reason_code,
        reason=reason,
        reason_details={"risk_level": risk} if risk else None,
        request_hash=request_hash,
        policy_version=policy_version,
        policy_hash=policy_hash,
        profile_id=profile_id,
        profile_version=profile_version,
        profile_hash=profile_hash,
        runtime_version=runtime_version,
        provenance_id=provenance_id,
    )


def _profile_rule_matches(
    rule: Any,
    tool: str,
    operation: str,
    params: Dict[str, Any],
    context: Dict[str, Any],
) -> bool:
    """Check if a profile rule matches."""
    when = getattr(rule, "when", {})
    if not when:
        return False
    
    # Check tool match
    if "tool" in when:
        rule_tool = when["tool"]
        if rule_tool not in ("*", tool):
            return False
    
    # Check operation match (when may use "op" or "operation")
    rule_op = when.get("operation") or when.get("op")
    if rule_op and rule_op not in ("*", operation):
        return False
    
    # Check pattern match if present
    pattern = getattr(rule, "pattern", None)
    if pattern:
        import re
        import json
        # Search in params JSON representation
        try:
            params_str = json.dumps(params, default=str)
            if not re.search(pattern, params_str):
                return False
        except (re.error, TypeError):
            return False
    
    return True


def _compute_provenance_id(
    request_hash: Optional[str],
    policy_hash: Optional[str],
    profile_hash: Optional[str],
    runtime_version: Optional[str],
) -> str:
    """Compute provenance_id from hashes and runtime version."""
    parts = [
        request_hash or "",
        policy_hash or "",
        profile_hash or "",
        runtime_version or "",
    ]
    combined = "|".join(parts)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()
