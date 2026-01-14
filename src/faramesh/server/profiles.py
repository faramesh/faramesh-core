# src/faramesh/server/profiles.py
"""Execution profiles for allowlists and constraints."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field, model_validator

from .canonicalization import compute_profile_hash


class ProfileRule(BaseModel):
    """A profile rule that can match and override decisions."""
    
    name: str
    when: Dict[str, Any] = Field(default_factory=dict)
    pattern: Optional[str] = None
    outcome: str = "HALT"  # HALT, ABSTAIN, or EXECUTE
    reason_code: str = "PROFILE_RULE_DENY"


class RequiredControls(BaseModel):
    """Required controls for profile execution."""
    
    approval_token: bool = False


class ExecutionProfile(BaseModel):
    """Execution profile with allowlists and constraints."""
    
    id: str
    version: str
    allowed_tools: List[str] = Field(default_factory=list)
    rules: List[ProfileRule] = Field(default_factory=list)
    required_controls: Union[RequiredControls, Dict[str, Any]] = Field(default_factory=dict)
    profile_hash: Optional[str] = None
    
    @model_validator(mode="after")
    def compute_hash(self) -> "ExecutionProfile":
        """Compute profile_hash after initialization."""
        profile_dict = {
            "id": self.id,
            "version": self.version,
            "allowed_tools": self.allowed_tools,
            "rules": [rule.model_dump() if hasattr(rule, "model_dump") else rule for rule in self.rules],
            "required_controls": self.required_controls.model_dump() if isinstance(self.required_controls, RequiredControls) else self.required_controls,
        }
        self.profile_hash = compute_profile_hash(profile_dict)
        return self


def load_profile_from_env() -> Optional[ExecutionProfile]:
    """
    Load execution profile from environment variable.
    
    Reads FARAMESH_PROFILE_FILE (default: profiles/default.yaml).
    Returns None if profile file doesn't exist or can't be loaded.
    """
    profile_file = os.getenv("FARAMESH_PROFILE_FILE", "profiles/default.yaml")
    profile_path = Path(profile_file)
    
    # Try relative to CWD first, then package root
    if not profile_path.is_absolute():
        if not profile_path.exists():
            package_root = Path(__file__).resolve().parents[2]
            profile_path = package_root / profile_file
    
    if not profile_path.exists():
        logging.debug(f"Profile file not found: {profile_path}")
        return None
    
    try:
        with open(profile_path, "r", encoding="utf-8") as f:
            profile_data = yaml.safe_load(f) or {}
        
        # Parse required_controls
        required_controls_data = profile_data.get("required_controls", {})
        if isinstance(required_controls_data, dict) and required_controls_data:
            required_controls = RequiredControls(**required_controls_data)
        else:
            required_controls = RequiredControls()
        
        # Parse rules
        rules_data = profile_data.get("rules", [])
        rules = []
        for rule_data in rules_data:
            if isinstance(rule_data, dict):
                rules.append(ProfileRule(**rule_data))
            else:
                rules.append(rule_data)
        
        profile = ExecutionProfile(
            id=profile_data.get("id", "default"),
            version=profile_data.get("version", "1"),
            allowed_tools=profile_data.get("allowed_tools", []),
            rules=rules,
            required_controls=required_controls,
        )
        
        return profile
    except Exception as e:
        logging.error(f"Failed to load profile from {profile_path}: {e}", exc_info=True)
        return None
