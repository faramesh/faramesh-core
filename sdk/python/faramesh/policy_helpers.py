"""Policy validation and testing helpers.

This module provides helpers for validating policy files locally.
Note: Full policy validation may require server endpoints if available.
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from .client import FarameshError, FarameshPolicyError, _make_request, _get_config


def validate_policy_file(path: str) -> None:
    """Validate a policy YAML/JSON file.
    
    This function loads and validates the structure of a policy file.
    If the server exposes /v1/policy/validate, it will use that endpoint.
    Otherwise, it performs basic local structure validation.
    
    Args:
        path: Path to policy file (YAML or JSON)
    
    Raises:
        FarameshPolicyError: If policy is invalid
        FarameshError: On other errors
    
    Example:
        >>> validate_policy_file("policies/default.yaml")
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FarameshError(f"Policy file not found: {path}")
    
    # Try to use server endpoint if available
    config = _get_config()
    try:
        with open(file_path, "r") as f:
            content = f.read()
        
        # Try POST to /v1/policy/validate if it exists
        try:
            payload = {"policy": content}
            _make_request("POST", "/v1/policy/validate", json_data=payload)
            return  # Server validated successfully
        except FarameshError:
            # Endpoint doesn't exist, fall back to local validation
            pass
    except Exception as e:
        raise FarameshError(f"Failed to read policy file: {e}")
    
    # Local validation: parse and check structure
    try:
        if yaml is None:
            raise FarameshError("PyYAML required for local policy validation. Install with: pip install pyyaml")
        
        with open(file_path, "r") as f:
            data = yaml.safe_load(f)
        
        if not isinstance(data, dict):
            raise FarameshPolicyError("Policy must be a YAML/JSON object")
        
        # Check for basic structure
        if "rules" not in data:
            raise FarameshPolicyError("Policy must have 'rules' field")
        
        if not isinstance(data["rules"], list):
            raise FarameshPolicyError("Policy 'rules' must be a list")
        
        # Validate each rule has required fields
        errors = []
        for i, rule in enumerate(data["rules"]):
            if not isinstance(rule, dict):
                errors.append(f"Rule {i} must be an object")
                continue
            
            if "match" not in rule:
                errors.append(f"Rule {i} missing 'match' field")
            
            if "allow" not in rule and "deny" not in rule:
                errors.append(f"Rule {i} must have 'allow' or 'deny' field")
        
        if errors:
            raise FarameshPolicyError(f"Policy validation errors: {'; '.join(errors)}")
    
    except FarameshPolicyError:
        raise
    except Exception as e:
        raise FarameshPolicyError(f"Failed to validate policy: {e}")


def test_policy_against_action(policy_path: str, action: Dict[str, Any]) -> Dict[str, Any]:
    """Test a policy against an action (if server endpoint exists).
    
    This function attempts to use a server endpoint for policy testing.
    If the endpoint doesn't exist, it raises an error.
    
    Args:
        policy_path: Path to policy file
        action: Action dict to test
    
    Returns:
        Test result dict from server
    
    Raises:
        FarameshError: If endpoint doesn't exist or on other errors
    
    Example:
        >>> action = {"agent_id": "agent", "tool": "http", "operation": "get", "params": {}}
        >>> result = test_policy_against_action("policies/default.yaml", action)
    """
    file_path = Path(policy_path)
    if not file_path.exists():
        raise FarameshError(f"Policy file not found: {policy_path}")
    
    try:
        with open(file_path, "r") as f:
            policy_content = f.read()
    except Exception as e:
        raise FarameshError(f"Failed to read policy file: {e}")
    
    # Try POST to /v1/policy/test if it exists
    try:
        payload = {
            "policy": policy_content,
            "action": action,
        }
        return _make_request("POST", "/v1/policy/test", json_data=payload)
    except FarameshError as e:
        raise FarameshError(
            f"Policy testing endpoint not available. Server may not support /v1/policy/test. "
            f"Error: {e}"
        )
