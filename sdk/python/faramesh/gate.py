"""
Execution gate helpers for deterministic decision verification.

This module provides functions to interact with the Faramesh gate endpoint
and verify/replay decisions deterministically.

Usage:
    >>> from faramesh import configure
    >>> from faramesh.gate import gate_decide, replay_decision
    >>> 
    >>> configure(base_url="http://localhost:8000")
    >>> 
    >>> # Get decision without creating action
    >>> decision = gate_decide("agent", "http", "get", {"url": "https://example.com"})
    >>> if decision["outcome"] == "EXECUTE":
    ...     # Safe to proceed
    ...     pass
    >>> 
    >>> # Replay existing decision
    >>> result = replay_decision(action_id="abc123")
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from .client import (
    _make_request,
    _get_config,
    get_action,
    FarameshError,
)
from .canonicalization import compute_request_hash


@dataclass
class GateDecision:
    """Result from the gate/decide endpoint."""
    outcome: str  # EXECUTE, ABSTAIN, HALT
    reason_code: str
    reason: Optional[str]
    request_hash: str
    policy_version: Optional[str]
    policy_hash: Optional[str]
    profile_id: Optional[str]
    profile_version: Optional[str]
    profile_hash: Optional[str]
    runtime_version: Optional[str]
    provenance_id: Optional[str]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GateDecision":
        return cls(
            outcome=data.get("outcome", ""),
            reason_code=data.get("reason_code", ""),
            reason=data.get("reason"),
            request_hash=data.get("request_hash", ""),
            policy_version=data.get("policy_version"),
            policy_hash=data.get("policy_hash"),
            profile_id=data.get("profile_id"),
            profile_version=data.get("profile_version"),
            profile_hash=data.get("profile_hash"),
            runtime_version=data.get("runtime_version"),
            provenance_id=data.get("provenance_id"),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "request_hash": self.request_hash,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "profile_hash": self.profile_hash,
            "runtime_version": self.runtime_version,
            "provenance_id": self.provenance_id,
        }


@dataclass
class ReplayResult:
    """Result of a decision replay verification."""
    success: bool
    original_outcome: str
    replayed_outcome: str
    original_reason_code: str
    replayed_reason_code: str
    request_hash_match: bool
    policy_hash_match: bool
    profile_hash_match: bool
    runtime_version_match: bool
    mismatches: list
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "original_outcome": self.original_outcome,
            "replayed_outcome": self.replayed_outcome,
            "original_reason_code": self.original_reason_code,
            "replayed_reason_code": self.replayed_reason_code,
            "request_hash_match": self.request_hash_match,
            "policy_hash_match": self.policy_hash_match,
            "profile_hash_match": self.profile_hash_match,
            "runtime_version_match": self.runtime_version_match,
            "mismatches": self.mismatches,
        }


def gate_decide(
    agent_id: str,
    tool: str,
    operation: str,
    params: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> GateDecision:
    """
    Call the gate/decide endpoint to get a decision without creating an action.
    
    This is useful for:
    - Pre-checking if an action would be allowed before committing
    - Getting deterministic decision data (hashes, versions) for verification
    - Implementing non-bypassable execution gates
    
    Args:
        agent_id: Agent identifier
        tool: Tool name (e.g., "http", "shell")
        operation: Operation name (e.g., "get", "run")
        params: Action parameters (default: {})
        context: Additional context (default: {})
        
    Returns:
        GateDecision with outcome, reason_code, and version-bound fields
        
    Raises:
        FarameshError: On API errors
        
    Example:
        >>> decision = gate_decide("agent", "http", "get", {"url": "https://example.com"})
        >>> if decision.outcome == "EXECUTE":
        ...     print("Action would be allowed")
        >>> elif decision.outcome == "HALT":
        ...     print(f"Action would be denied: {decision.reason_code}")
    """
    payload = {
        "agent_id": agent_id,
        "tool": tool,
        "operation": operation,
        "params": params or {},
        "context": context or {},
    }
    
    response = _make_request("POST", "/v1/gate/decide", json_data=payload)
    return GateDecision.from_dict(response)


def gate_decide_dict(
    agent_id: str,
    tool: str,
    operation: str,
    params: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Call the gate/decide endpoint and return raw dict response.
    
    Same as gate_decide() but returns the raw API response dict.
    
    Args:
        agent_id: Agent identifier
        tool: Tool name
        operation: Operation name
        params: Action parameters (default: {})
        context: Additional context (default: {})
        
    Returns:
        Raw API response dict
    """
    payload = {
        "agent_id": agent_id,
        "tool": tool,
        "operation": operation,
        "params": params or {},
        "context": context or {},
    }
    
    return _make_request("POST", "/v1/gate/decide", json_data=payload)


def replay_decision(
    action_id: Optional[str] = None,
    provenance_id: Optional[str] = None,
) -> ReplayResult:
    """
    Replay a decision to verify determinism.
    
    Given an existing action (by ID or provenance_id), re-runs the gate/decide
    endpoint and compares the results. This verifies that:
    - The decision outcome matches
    - Policy/profile/runtime versions match
    - Hashes are consistent
    
    Args:
        action_id: Action ID to replay (provide this OR provenance_id)
        provenance_id: Provenance ID to find and replay
        
    Returns:
        ReplayResult with comparison results
        
    Raises:
        FarameshError: If action not found or API error
        ValueError: If neither action_id nor provenance_id provided
        
    Example:
        >>> # Replay by action ID
        >>> result = replay_decision(action_id="abc123")
        >>> if result.success:
        ...     print("Decision replay passed!")
        >>> else:
        ...     print(f"Mismatches: {result.mismatches}")
    """
    if not action_id and not provenance_id:
        raise ValueError("Must provide either action_id or provenance_id")
    
    # Find the action
    if provenance_id:
        # Search for action by provenance_id
        from .client import list_actions
        actions = list_actions(limit=1000)
        matches = [a for a in actions if a.get("provenance_id") == provenance_id]
        if not matches:
            raise FarameshError(f"No action found with provenance_id '{provenance_id}'")
        original = matches[0]
        action_id = original["id"]
    else:
        original = get_action(action_id)
    
    # Extract payload for replay
    payload = {
        "agent_id": original["agent_id"],
        "tool": original["tool"],
        "operation": original["operation"],
        "params": original.get("params", {}),
        "context": original.get("context", {}),
    }
    
    # Call gate/decide
    replayed = gate_decide_dict(**payload)
    
    # Compare results
    mismatches = []
    
    original_outcome = original.get("outcome", "")
    replayed_outcome = replayed.get("outcome", "")
    if original_outcome != replayed_outcome:
        mismatches.append(f"outcome: {original_outcome} != {replayed_outcome}")
    
    original_reason_code = original.get("reason_code", "")
    replayed_reason_code = replayed.get("reason_code", "")
    if original_reason_code != replayed_reason_code:
        mismatches.append(f"reason_code: {original_reason_code} != {replayed_reason_code}")
    
    request_hash_match = original.get("request_hash") == replayed.get("request_hash")
    if not request_hash_match:
        mismatches.append("request_hash mismatch")
    
    policy_hash_match = original.get("policy_hash") == replayed.get("policy_hash")
    if not policy_hash_match:
        mismatches.append("policy_hash mismatch (policy may have changed)")
    
    profile_hash_match = original.get("profile_hash") == replayed.get("profile_hash")
    if not profile_hash_match:
        mismatches.append("profile_hash mismatch (profile may have changed)")
    
    runtime_version_match = original.get("runtime_version") == replayed.get("runtime_version")
    if not runtime_version_match:
        mismatches.append(f"runtime_version: {original.get('runtime_version')} != {replayed.get('runtime_version')}")
    
    return ReplayResult(
        success=len(mismatches) == 0,
        original_outcome=original_outcome,
        replayed_outcome=replayed_outcome,
        original_reason_code=original_reason_code,
        replayed_reason_code=replayed_reason_code,
        request_hash_match=request_hash_match,
        policy_hash_match=policy_hash_match,
        profile_hash_match=profile_hash_match,
        runtime_version_match=runtime_version_match,
        mismatches=mismatches,
    )


def verify_request_hash(payload: Dict[str, Any], expected_hash: str) -> bool:
    """
    Verify that a payload produces the expected request_hash.
    
    This can be used to verify that the server's request_hash matches
    the client's locally computed hash.
    
    Args:
        payload: Action payload dict
        expected_hash: Expected SHA-256 hash
        
    Returns:
        True if hashes match, False otherwise
        
    Example:
        >>> action = submit_action("agent", "http", "get", {"url": "..."})
        >>> payload = {"agent_id": "agent", "tool": "http", ...}
        >>> assert verify_request_hash(payload, action["request_hash"])
    """
    computed = compute_request_hash(payload)
    return computed == expected_hash


def execute_if_allowed(
    agent_id: str,
    tool: str,
    operation: str,
    params: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    executor: Optional[callable] = None,
) -> Dict[str, Any]:
    """
    Execute an action only if the gate decision is EXECUTE.
    
    This implements a non-bypassable execution gate pattern:
    1. Call gate/decide to get decision
    2. If outcome is EXECUTE, optionally run the executor
    3. Return the decision with execution result
    
    Args:
        agent_id: Agent identifier
        tool: Tool name
        operation: Operation name
        params: Action parameters
        context: Additional context
        executor: Optional callable to run if decision is EXECUTE.
                  Receives (tool, operation, params, context) as arguments.
        
    Returns:
        Dict with decision and optional execution result
        
    Example:
        >>> def my_executor(tool, op, params, ctx):
        ...     # Actually perform the action
        ...     return {"status": "done"}
        >>> 
        >>> result = execute_if_allowed(
        ...     "agent", "http", "get", {"url": "..."},
        ...     executor=my_executor
        ... )
        >>> if result["executed"]:
        ...     print("Action executed:", result["execution_result"])
    """
    decision = gate_decide(agent_id, tool, operation, params, context)
    
    result = {
        "decision": decision.to_dict(),
        "outcome": decision.outcome,
        "reason_code": decision.reason_code,
        "executed": False,
        "execution_result": None,
    }
    
    if decision.outcome == "EXECUTE" and executor:
        try:
            execution_result = executor(tool, operation, params or {}, context or {})
            result["executed"] = True
            result["execution_result"] = execution_result
        except Exception as e:
            result["execution_error"] = str(e)
    
    return result
