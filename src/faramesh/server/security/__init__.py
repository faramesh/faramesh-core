# security/__init__.py
# SPDX-License-Identifier: Elastic-2.0
"""Security and validation module for Faramesh."""

from .guard import (
    SecurityError,
    enforce_no_side_effects,
    sanitize_shell_command,
    validate_action_params,
    validate_external_string,
    validate_policy_decision,
)

__all__ = [
    "validate_action_params",
    "sanitize_shell_command",
    "validate_policy_decision",
    "enforce_no_side_effects",
    "validate_external_string",
    "SecurityError",
]
