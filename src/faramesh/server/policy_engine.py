# src/faramesh/server/policy_engine.py
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .models import Decision


class PolicyEngine:
    """Core policy engine - YAML-only, no DB policy store."""
    
    def __init__(self, yaml_path: str):
        self.yaml_path = yaml_path
        self.cached_policy = None
        self.refresh()

    def _validate_policy(self, policy_data: Any, file_path: Optional[Path] = None) -> List[str]:
        """Validate policy data and return list of error messages with file/line context."""
        errors: List[str] = []
        file_info = f" in {file_path}" if file_path else ""
        
        if not isinstance(policy_data, dict):
            return [f"Policy file must be a mapping with a 'rules' list{file_info}"]

        rules = policy_data.get("rules")
        if rules is None:
            return [f"Policy missing 'rules' field{file_info}"]
        if not isinstance(rules, list):
            return [f"'rules' must be a list{file_info}"]
        
        # Validate risk rules if present
        risk = policy_data.get("risk")
        if risk is not None:
            if not isinstance(risk, dict):
                errors.append("'risk' must be a mapping")
            else:
                risk_rules = risk.get("rules", [])
                if not isinstance(risk_rules, list):
                    errors.append("'risk.rules' must be a list")
                else:
                    for idx, risk_rule in enumerate(risk_rules):
                        if not isinstance(risk_rule, dict):
                            errors.append(f"Risk rule {idx} must be a mapping")
                            continue
                        if "name" not in risk_rule:
                            errors.append(f"Risk rule {idx} missing 'name'")
                        if "when" not in risk_rule:
                            errors.append(f"Risk rule {idx} missing 'when'")
                        if "risk_level" not in risk_rule:
                            errors.append(f"Risk rule {idx} missing 'risk_level'")
                        risk_level = risk_rule.get("risk_level")
                        if risk_level and risk_level not in ("low", "medium", "high"):
                            errors.append(f"Risk rule {idx}: risk_level must be low/medium/high")

        allowed_match_keys = {
            "tool",
            "op",
            "contains",
            "amount_gt",
            "amount_lt",
            "amount_gte",
            "amount_lte",
            "path_contains",
            "path_starts_with",
            "path_ends_with",
            "method",
            "branch",
            "agent_id",
            "pattern",
            "field",
            "value",
        }
        allowed_effect_keys = {"allow", "deny", "require_approval"}

        for idx, rule in enumerate(rules):
            rule_num = idx + 1  # 1-indexed for user-friendly messages
            if not isinstance(rule, dict):
                errors.append(f"Rule #{rule_num}{file_info}: must be a mapping (object)")
                continue

            match = rule.get("match", {}) or {}
            if not isinstance(match, dict):
                errors.append(f"Rule #{rule_num}{file_info}: 'match' must be a mapping (object)")
                continue

            # Check for missing required match fields
            if not match:
                errors.append(f"Rule #{rule_num}{file_info}: 'match' is empty - at least one match condition required")

            unknown_match = set(match.keys()) - allowed_match_keys
            if unknown_match:
                errors.append(f"Rule #{rule_num}{file_info}: unknown match keys: {sorted(unknown_match)}")

            effects_set = [k for k in allowed_effect_keys if rule.get(k)]
            if not effects_set:
                errors.append(f"Rule #{rule_num}{file_info}: must set one of allow/deny/require_approval")
            if len(effects_set) > 1:
                errors.append(f"Rule #{rule_num}{file_info}: multiple effects set: {effects_set}")

        return errors

    def refresh(self):
        """Load policy from YAML file with comprehensive error handling."""
        import logging
        
        p = Path(self.yaml_path)
        # If relative path, try relative to current working directory first, then relative to package
        if not p.is_absolute():
            if not p.exists():
                # Try relative to package root
                package_root = Path(__file__).resolve().parents[2]
                p = package_root / self.yaml_path
        
        if p.exists():
            try:
                # Read file with error handling
                try:
                    policy_text = p.read_text(encoding='utf-8')
                except (IOError, PermissionError, UnicodeDecodeError) as e:
                    logging.error(f"Failed to read policy file '{p}': {e}")
                    # Use empty policy as fallback
                    self.cached_policy = {
                        "version": "error",
                        "rules": [],
                        "risk_rules": [],
                        "policy_hash": None,
                    }
                    return
                
                # Parse YAML with error handling
                try:
                    y = yaml.safe_load(policy_text) or {}
                except yaml.YAMLError as e:
                    logging.error(f"Failed to parse YAML in policy file '{p}': {e}")
                    # Use empty policy as fallback
                    self.cached_policy = {
                        "version": "error",
                        "rules": [],
                        "risk_rules": [],
                        "policy_hash": None,
                    }
                    return
                
                # Validate policy
                errors = self._validate_policy(y, file_path=p)
                if errors:
                    # Format errors with helpful guidance
                    error_summary = "\n".join(f"  - {err}" for err in errors)
                    error_msg = f"Invalid policy file '{p}':\n{error_summary}"
                    logging.error(error_msg)
                    # Raise ValueError on initialization to fail fast
                    raise ValueError(error_msg)
                
                rules = y.get("rules", []) if isinstance(y, dict) else []
                risk = y.get("risk", {}) if isinstance(y, dict) else {}
                risk_rules = risk.get("rules", []) if isinstance(risk, dict) else []
                
                # Compute policy version (prefer env var, else file-based)
                import os
                policy_version_env = os.getenv("FARAMESH_POLICY_VERSION")
                if policy_version_env:
                    policy_version = policy_version_env
                else:
                    # Use filename and mtime
                    import time
                    mtime = p.stat().st_mtime if p.exists() else 0
                    mtime_iso = datetime.fromtimestamp(mtime).isoformat() if mtime else "unknown"
                    policy_version = f"{p.name}@{mtime_iso}"
                
                # Compute policy hash
                from .canonicalization import compute_policy_hash
                policy_dict = {
                    "version": policy_version,
                    "rules": rules,
                    "risk_rules": risk_rules,
                }
                policy_hash = compute_policy_hash(policy_dict)
                
                self.cached_policy = {
                    "version": policy_version,
                    "rules": rules,
                    "risk_rules": risk_rules,
                    "policy_hash": policy_hash,
                }
            except ValueError:
                # Re-raise validation errors - these should fail initialization
                raise
            except Exception as e:
                logging.error(f"Unexpected error loading policy file '{p}': {e}", exc_info=True)
                # Use empty policy as fallback for unexpected errors only
                self.cached_policy = {
                    "version": "error",
                    "rules": [],
                    "risk_rules": [],
                    "policy_hash": None,
                }
        else:
            logging.warning(f"Policy file not found: {p}, using empty policy (deny all)")
            self.cached_policy = {
                "version": "none",
                "rules": [],
                "risk_rules": [],
                "policy_hash": None,
            }

    def _get_param_value(self, params: Dict, context: Dict, key: str, default=None):
        """Get value from params or context, supporting nested keys (e.g., 'user.id')."""
        # Try params first
        if key in params:
            return params[key]
        
        # Try context
        if key in context:
            return context[key]
        
        # Try nested access (e.g., "user.id")
        if "." in key:
            parts = key.split(".")
            value = params
            try:
                for part in parts:
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        return default
                return value
            except (AttributeError, TypeError, KeyError):
                pass
        
        return default

    def _match_condition(self, match: Dict, tool: str, operation: str, params: Dict, context: Dict) -> bool:
        """Check if a match condition is satisfied."""
        # Tool matching
        mt = match.get("tool")
        if mt is not None and mt not in ("*", tool):
            return False

        # Operation matching
        mo = match.get("op")
        if mo is not None and mo not in ("*", operation):
            return False

        # Contains substring in params
        if "contains" in match:
            try:
                probe = json.dumps(params, default=str) if isinstance(params, dict) else str(params)
            except (TypeError, ValueError):
                probe = str(params) if params is not None else ""
            match_contains = str(match["contains"]) if match["contains"] is not None else ""
            if match_contains not in probe:
                return False

        # Numeric comparisons
        if "amount_gt" in match:
            amount = self._get_param_value(params, context, "amount", 0)
            try:
                if float(amount) <= float(match["amount_gt"]):
                    return False
            except (ValueError, TypeError):
                return False

        if "amount_lt" in match:
            amount = self._get_param_value(params, context, "amount", 0)
            try:
                if float(amount) >= float(match["amount_lt"]):
                    return False
            except (ValueError, TypeError):
                return False

        if "amount_gte" in match:
            amount = self._get_param_value(params, context, "amount", 0)
            try:
                if float(amount) < float(match["amount_gte"]):
                    return False
            except (ValueError, TypeError):
                return False

        if "amount_lte" in match:
            amount = self._get_param_value(params, context, "amount", 0)
            try:
                if float(amount) > float(match["amount_lte"]):
                    return False
            except (ValueError, TypeError):
                return False

        # String/path matching
        if "path_contains" in match:
            path = self._get_param_value(params, context, "path", "")
            path_str = str(path) if path is not None else ""
            match_path = str(match["path_contains"]) if match["path_contains"] is not None else ""
            if match_path not in path_str:
                return False

        if "path_starts_with" in match:
            path = self._get_param_value(params, context, "path", "")
            path_str = str(path) if path is not None else ""
            match_path = str(match["path_starts_with"]) if match["path_starts_with"] is not None else ""
            if not path_str.startswith(match_path):
                return False

        if "path_ends_with" in match:
            path = self._get_param_value(params, context, "path", "")
            path_str = str(path) if path is not None else ""
            match_path = str(match["path_ends_with"]) if match["path_ends_with"] is not None else ""
            if not path_str.endswith(match_path):
                return False

        # HTTP method matching
        if "method" in match:
            method = self._get_param_value(params, context, "method", "")
            # Defensive check - ensure method is a string before calling upper()
            if not isinstance(method, str):
                method = str(method) if method is not None else ""
            method_upper = method.upper()
            match_method = match.get("method", "")
            match_method_upper = str(match_method).upper() if match_method is not None else ""
            if method_upper != match_method_upper:
                return False

        # Branch matching (for Git operations)
        if "branch" in match:
            branch = self._get_param_value(params, context, "branch", "")
            if branch != match["branch"]:
                return False

        # Agent ID matching
        if "agent_id" in match:
            agent_id = self._get_param_value(params, context, "agent_id", "")
            if match["agent_id"] not in ("*", agent_id):
                return False

        # Regex pattern matching
        if "pattern" in match:
            pattern = match["pattern"]
            if not isinstance(pattern, str):
                return False
            try:
                probe = json.dumps(params, default=str) if isinstance(params, dict) else str(params)
            except (TypeError, ValueError):
                probe = str(params) if params is not None else ""
            try:
                if not re.search(pattern, probe):
                    return False
            except re.error as e:
                import logging
                logging.warning(f"Invalid regex pattern in policy rule: {pattern}, error: {e}")
                return False  # Invalid pattern doesn't match

        # Custom field matching
        if "field" in match and "value" in match:
            field_name = match["field"]
            expected_value = match["value"]
            actual_value = self._get_param_value(params, context, field_name)
            if actual_value != expected_value:
                return False

        return True

    def _evaluate_risk(self, tool: str, operation: str, params: Dict, context: Dict) -> str:
        """Evaluate risk rules to determine risk_level. Returns 'low', 'medium', or 'high'."""
        risk_rules = self.cached_policy.get("risk_rules", [])
        
        for risk_rule in risk_rules:
            if not isinstance(risk_rule, dict):
                continue
            
            when = risk_rule.get("when", {})
            if not isinstance(when, dict):
                continue
            
            # Check if risk rule matches
            if self._match_condition(when, tool, operation, params, context):
                risk_level = risk_rule.get("risk_level", "low")
                if risk_level in ("low", "medium", "high"):
                    return risk_level
        
        # Default risk level
        return "low"

    def evaluate(
        self,
        tool: str,
        operation: str,
        params: Dict,
        context: Dict,
    ) -> Tuple[Decision, str, str]:
        """
        First-match-wins policy evaluation.
        
        Evaluation order:
        1. Rules are evaluated in the order they appear in the policy
        2. First matching rule wins (decision is returned immediately)
        3. If no rules match, returns DENY (deny-by-default)
        4. Risk level is computed from risk rules (default: low)
        
        Effects (in order of precedence):
        - deny: returns DENY
        - require_approval: returns REQUIRE_APPROVAL
        - allow: returns ALLOW
        
        Risk rules can also trigger require_approval if risk_level == high
        """
        rules = self.cached_policy.get("rules", [])
        
        # First, evaluate risk rules to get risk level
        risk_level = self._evaluate_risk(tool, operation, params, context)

        for r in rules:
            if not isinstance(r, dict):
                continue

            match = r.get("match", {}) or {}

            # Check match conditions
            if not self._match_condition(match, tool, operation, params, context):
                continue

            # -------------------------------------------
            # EFFECTS
            # -------------------------------------------
            if r.get("deny"):
                reason = r.get("description") or "Denied by policy rule"
                # Use risk from rule if specified, otherwise use computed risk
                final_risk = r.get("risk") or risk_level
                return Decision.DENY, reason, final_risk

            if r.get("require_approval"):
                reason = r.get("description") or "Requires approval by policy rule"
                final_risk = r.get("risk") or risk_level
                return (
                    Decision.REQUIRE_APPROVAL,
                    reason,
                    final_risk,
                )

            if r.get("allow"):
                reason = r.get("description") or "Allowed by policy rule"
                final_risk = r.get("risk") or risk_level
                # If risk is high and rule allows, require approval instead
                if final_risk == "high" and not r.get("risk"):
                    return (
                        Decision.REQUIRE_APPROVAL,
                        f"{reason} (high risk requires approval)",
                        final_risk,
                    )
                return Decision.ALLOW, reason, final_risk

        # Default deny with computed risk
        return Decision.DENY, "No rule matched (deny by default)", risk_level

    def policy_version(self) -> str:
        return str(self.cached_policy.get("version", "none"))
    
    def policy_hash(self) -> Optional[str]:
        """Get the policy hash."""
        return self.cached_policy.get("policy_hash")
