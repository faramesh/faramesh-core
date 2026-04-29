"""
Deterministic canonicalization for Faramesh client-side hashing.

This module mirrors the canonicalization logic in faramesh-core to enable
clients to compute request_hash locally before submitting actions.

Usage:
    >>> from faramesh.canonicalization import compute_request_hash
    >>> payload = {"agent_id": "test", "tool": "http", "operation": "get", "params": {}}
    >>> hash_value = compute_request_hash(payload)
"""

from __future__ import annotations

import copy
import hashlib
import math
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Union


class CanonicalizeError(Exception):
    """
    Raised when canonicalization fails.
    
    This is a fail-closed error: if canonicalization cannot complete,
    the action should not proceed.
    """
    pass


# Fields to exclude from action payloads (ephemeral/internal)
_ACTION_EXCLUDE_FIELDS = frozenset({
    "id",
    "approval_token",
    "created_at",
    "updated_at",
    "tenant_id",
    "project_id",
    "version",
    "decision",
    "status",
    "reason",
    "risk_level",
    "policy_version",
    "policy_hash",
    "runtime_version",
    "profile_id",
    "profile_version",
    "profile_hash",
    "provenance_id",
    "outcome",
    "reason_code",
    "reason_details",
    "request_hash",
})


def _normalize_float(value: float) -> str:
    """
    Normalize a float to canonical string representation.
    
    Rules:
    - No exponent notation (1e3 → 1000)
    - No trailing zeros (1.50 → 1.5)
    - Whole numbers have no decimal point (1.0 → 1)
    - NaN, Infinity, -Infinity → CanonicalizeError
    """
    # FAIL CLOSED on non-finite values
    if math.isnan(value):
        raise CanonicalizeError("NaN is not allowed in canonical JSON")
    if math.isinf(value):
        raise CanonicalizeError("Infinity is not allowed in canonical JSON")
    
    # Handle zero explicitly
    if value == 0.0:
        return "0"
    
    try:
        dec = Decimal(repr(value))
        dec = dec.normalize()
        sign, digits, exponent = dec.as_tuple()
        digit_str = ''.join(str(d) for d in digits)
        
        if exponent >= 0:
            result = digit_str + ('0' * exponent)
        elif -exponent >= len(digit_str):
            result = '0.' + ('0' * (-exponent - len(digit_str))) + digit_str
        else:
            decimal_pos = len(digit_str) + exponent
            result = digit_str[:decimal_pos] + '.' + digit_str[decimal_pos:]
        
        if sign:
            result = '-' + result
            
        return result
        
    except (InvalidOperation, ValueError) as e:
        raise CanonicalizeError(f"Failed to normalize float {value!r}: {e}")


def _serialize_string(value: str) -> str:
    """Serialize a string to canonical JSON representation."""
    result = ['"']
    
    for char in value:
        code = ord(char)
        
        if char == '"':
            result.append('\\"')
        elif char == '\\':
            result.append('\\\\')
        elif char == '\b':
            result.append('\\b')
        elif char == '\f':
            result.append('\\f')
        elif char == '\n':
            result.append('\\n')
        elif char == '\r':
            result.append('\\r')
        elif char == '\t':
            result.append('\\t')
        elif code < 0x20:
            result.append(f'\\u{code:04x}')
        else:
            result.append(char)
    
    result.append('"')
    return ''.join(result)


def _serialize_dict(value: dict) -> str:
    """Serialize a dict to canonical JSON with sorted keys."""
    for key in value:
        if not isinstance(key, str):
            raise CanonicalizeError(
                f"Dict keys must be strings, got {type(key).__name__}: {key!r}"
            )
    
    sorted_keys = sorted(value.keys())
    parts = []
    for key in sorted_keys:
        key_str = _serialize_string(key)
        val_str = _serialize_value(value[key])
        parts.append(f"{key_str}:{val_str}")
    
    return "{" + ",".join(parts) + "}"


def _serialize_list(value: Union[list, tuple]) -> str:
    """Serialize a list/tuple to canonical JSON (order preserved)."""
    parts = [_serialize_value(item) for item in value]
    return "[" + ",".join(parts) + "]"


def _serialize_value(value: Any) -> str:
    """Serialize a value to canonical JSON string."""
    if value is None:
        return "null"
    
    if isinstance(value, bool):
        return "true" if value else "false"
    
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    
    if isinstance(value, float):
        return _normalize_float(value)
    
    if isinstance(value, str):
        return _serialize_string(value)
    
    if isinstance(value, dict):
        return _serialize_dict(value)
    
    if isinstance(value, (list, tuple)):
        return _serialize_list(value)
    
    raise CanonicalizeError(
        f"Cannot canonicalize value of type {type(value).__name__}: {value!r}"
    )


def canonicalize(obj: Any) -> str:
    """
    Canonicalize an object to a deterministic JSON string.
    
    Guarantees:
    - Dict keys sorted lexicographically
    - Lists preserve order
    - UTF-8 compatible (ensure_ascii=False)
    - No NaN, Infinity, -Infinity
    - Floats normalized: no exponent, no trailing zeros
    - Input is never mutated
    
    Args:
        obj: Any JSON-serializable Python object
        
    Returns:
        Canonical JSON string
        
    Raises:
        CanonicalizeError: If canonicalization fails
    """
    obj_copy = copy.deepcopy(obj)
    return _serialize_value(obj_copy)


def canonicalize_action_payload(payload: dict) -> bytes:
    """
    Canonicalize an action payload for hashing.
    
    Drops ephemeral/internal fields (id, approval_token, timestamps, etc.)
    and produces canonical bytes.
    
    Args:
        payload: Action payload dict with agent_id, tool, operation, params, context
        
    Returns:
        Canonical bytes representation
        
    Raises:
        CanonicalizeError: If canonicalization fails
    """
    clean_payload: Dict[str, Any] = {}
    
    for key, value in payload.items():
        if key in _ACTION_EXCLUDE_FIELDS or key.startswith("_"):
            continue
        clean_payload[key] = value
    
    return canonicalize(clean_payload).encode("utf-8")


def compute_request_hash(payload: dict) -> str:
    """
    Compute SHA-256 hash of canonicalized action payload.
    
    This produces the same hash as the Faramesh server, enabling
    clients to verify request_hash matches before/after submission.
    
    Args:
        payload: Action payload dict (agent_id, tool, operation, params, context)
        
    Returns:
        SHA-256 hex digest (64 characters)
        
    Raises:
        CanonicalizeError: If canonicalization fails
        
    Example:
        >>> payload = {
        ...     "agent_id": "test",
        ...     "tool": "http", 
        ...     "operation": "get",
        ...     "params": {"url": "https://example.com"},
        ...     "context": {}
        ... }
        >>> hash_value = compute_request_hash(payload)
        >>> print(hash_value)  # 64-char hex string
    """
    canonical_bytes = canonicalize_action_payload(payload)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_hash(obj: Any) -> str:
    """
    Compute SHA-256 hash of the canonical JSON representation.
    
    Args:
        obj: Any JSON-serializable Python object
        
    Returns:
        SHA-256 hex digest (64 characters)
        
    Raises:
        CanonicalizeError: If canonicalization fails
    """
    canonical_str = canonicalize(obj)
    canonical_bytes = canonical_str.encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()
