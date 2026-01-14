# src/faramesh/server/canonicalization.py
"""
Deterministic canonicalization for Faramesh execution-control-layer semantics.

NON-NEGOTIABLE INVARIANTS:
- Canonicalization produces identical bytes across runs
- Dict keys sorted lexicographically
- Lists preserve order
- UTF-8 encoding, ensure_ascii=False
- No NaN, Infinity, -Infinity → FAIL CLOSED
- Floats normalized: no exponent, no trailing zeros (1.0 → 1, 1e3 → 1000)
- Input is never mutated
- Failure returns fail-closed outcome (raises CanonicalizeError)
"""

from __future__ import annotations

import copy
import hashlib
import math
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Union


class CanonicalizeError(Exception):
    """
    Raised when canonicalization fails.
    
    This is a fail-closed error: if canonicalization cannot complete,
    the caller MUST deny the action.
    """
    pass


# JSON primitive types that are directly serializable
JsonPrimitive = Union[str, int, bool, None]
JsonValue = Union[JsonPrimitive, float, Dict[str, Any], List[Any]]


def _normalize_float(value: float) -> str:
    """
    Normalize a float to canonical string representation.
    
    Rules:
    - No exponent notation (1e3 → 1000)
    - No trailing zeros (1.50 → 1.5)
    - Whole numbers have no decimal point (1.0 → 1)
    - NaN, Infinity, -Infinity → CanonicalizeError
    
    Args:
        value: Float value to normalize
        
    Returns:
        Canonical string representation
        
    Raises:
        CanonicalizeError: If value is NaN or Infinity
    """
    # FAIL CLOSED on non-finite values
    if math.isnan(value):
        raise CanonicalizeError("NaN is not allowed in canonical JSON")
    if math.isinf(value):
        raise CanonicalizeError("Infinity is not allowed in canonical JSON")
    
    # Handle zero explicitly
    if value == 0.0:
        # Normalize -0.0 to 0
        return "0"
    
    # Use Decimal for precise representation without floating point artifacts
    try:
        # Convert to Decimal for precise string conversion
        # Use string representation to avoid float precision issues
        dec = Decimal(repr(value))
        
        # Normalize to remove trailing zeros and adjust exponent
        dec = dec.normalize()
        
        # Convert to tuple to inspect components
        sign, digits, exponent = dec.as_tuple()
        
        # Build the canonical string without exponent notation
        digit_str = ''.join(str(d) for d in digits)
        
        if exponent >= 0:
            # No decimal point needed - result is an integer
            result = digit_str + ('0' * exponent)
        elif -exponent >= len(digit_str):
            # Need leading zeros after decimal point
            result = '0.' + ('0' * (-exponent - len(digit_str))) + digit_str
        else:
            # Insert decimal point within digits
            decimal_pos = len(digit_str) + exponent
            result = digit_str[:decimal_pos] + '.' + digit_str[decimal_pos:]
        
        if sign:
            result = '-' + result
            
        return result
        
    except (InvalidOperation, ValueError) as e:
        raise CanonicalizeError(f"Failed to normalize float {value!r}: {e}")


def _serialize_value(value: Any) -> str:
    """
    Serialize a single value to its canonical JSON string representation.
    
    Args:
        value: Value to serialize
        
    Returns:
        Canonical JSON string
        
    Raises:
        CanonicalizeError: If value cannot be canonicalized
    """
    if value is None:
        return "null"
    
    if isinstance(value, bool):
        # Must check bool before int since bool is subclass of int
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
    
    # Unknown type - fail closed
    raise CanonicalizeError(
        f"Cannot canonicalize value of type {type(value).__name__}: {value!r}"
    )


def _serialize_string(value: str) -> str:
    """
    Serialize a string to canonical JSON representation.
    
    Uses UTF-8 encoding with ensure_ascii=False semantics:
    - Control characters are escaped
    - Unicode characters are preserved as-is
    - Quotes and backslashes are escaped
    
    Args:
        value: String to serialize
        
    Returns:
        JSON string with quotes
    """
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
            # Other control characters - use \uXXXX
            result.append(f'\\u{code:04x}')
        else:
            # All other characters including unicode - preserve as-is
            result.append(char)
    
    result.append('"')
    return ''.join(result)


def _serialize_dict(value: dict) -> str:
    """
    Serialize a dict to canonical JSON representation.
    
    Keys are sorted lexicographically.
    
    Args:
        value: Dict to serialize
        
    Returns:
        Canonical JSON object string
        
    Raises:
        CanonicalizeError: If any key is not a string
    """
    # Validate all keys are strings
    for key in value:
        if not isinstance(key, str):
            raise CanonicalizeError(
                f"Dict keys must be strings, got {type(key).__name__}: {key!r}"
            )
    
    # Sort keys lexicographically
    sorted_keys = sorted(value.keys())
    
    parts = []
    for key in sorted_keys:
        key_str = _serialize_string(key)
        val_str = _serialize_value(value[key])
        parts.append(f"{key_str}:{val_str}")
    
    return "{" + ",".join(parts) + "}"


def _serialize_list(value: Union[list, tuple]) -> str:
    """
    Serialize a list/tuple to canonical JSON representation.
    
    Order is preserved.
    
    Args:
        value: List or tuple to serialize
        
    Returns:
        Canonical JSON array string
    """
    parts = [_serialize_value(item) for item in value]
    return "[" + ",".join(parts) + "]"


def canonicalize(obj: Any) -> str:
    """
    Canonicalize an object to a deterministic JSON string.
    
    This function produces identical output across runs for equivalent input.
    
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
        CanonicalizeError: If canonicalization fails (fail-closed)
    """
    # Deep copy to ensure we never mutate input
    obj_copy = copy.deepcopy(obj)
    return _serialize_value(obj_copy)


def compute_hash(obj: Any) -> str:
    """
    Compute SHA-256 hash of the canonical JSON representation.
    
    Args:
        obj: Any JSON-serializable Python object
        
    Returns:
        SHA-256 hex digest (64 characters)
        
    Raises:
        CanonicalizeError: If canonicalization fails (fail-closed)
    """
    canonical_str = canonicalize(obj)
    canonical_bytes = canonical_str.encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


# =============================================================================
# Domain-specific canonicalization functions (backward compatibility)
# =============================================================================

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


def canonicalize_action_payload(payload: dict) -> bytes:
    """
    Canonicalize an action payload for hashing.
    
    Drops ephemeral/internal fields and produces canonical bytes.
    
    Args:
        payload: Action payload dict
        
    Returns:
        Canonical bytes representation
        
    Raises:
        CanonicalizeError: If canonicalization fails
    """
    # Build clean payload with only logical fields
    clean_payload: Dict[str, Any] = {}
    
    for key, value in payload.items():
        # Skip excluded fields and fields starting with _
        if key in _ACTION_EXCLUDE_FIELDS or key.startswith("_"):
            continue
        clean_payload[key] = value
    
    return canonicalize(clean_payload).encode("utf-8")


def canonicalize_event_payload(event: dict) -> bytes:
    """
    Canonicalize an event payload for hashing.
    
    Includes only immutable fields: id, action_id, event_type, created_at, meta.
    
    Args:
        event: Event dict
        
    Returns:
        Canonical bytes representation
        
    Raises:
        CanonicalizeError: If canonicalization fails
    """
    clean_event: Dict[str, Any] = {
        "id": event.get("id"),
        "action_id": event.get("action_id"),
        "event_type": event.get("event_type"),
        "created_at": event.get("created_at"),
        "meta": event.get("meta", {}),
    }
    
    return canonicalize(clean_event).encode("utf-8")


def canonicalize_profile(profile: dict) -> bytes:
    """
    Canonicalize a profile for hashing.
    
    Args:
        profile: Profile dict
        
    Returns:
        Canonical bytes representation
        
    Raises:
        CanonicalizeError: If canonicalization fails
    """
    return canonicalize(profile).encode("utf-8")


def canonicalize_policy(policy: dict) -> bytes:
    """
    Canonicalize a policy for hashing.
    
    Args:
        policy: Policy dict
        
    Returns:
        Canonical bytes representation
        
    Raises:
        CanonicalizeError: If canonicalization fails
    """
    return canonicalize(policy).encode("utf-8")


def compute_request_hash(payload: dict) -> str:
    """
    Compute SHA256 hash of canonicalized action payload.
    
    Args:
        payload: Action payload dict
        
    Returns:
        Hex digest of SHA256 hash
        
    Raises:
        CanonicalizeError: If canonicalization fails
    """
    canonical_bytes = canonicalize_action_payload(payload)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_profile_hash(profile: dict) -> str:
    """
    Compute SHA256 hash of canonicalized profile.
    
    Args:
        profile: Profile dict
        
    Returns:
        Hex digest of SHA256 hash
        
    Raises:
        CanonicalizeError: If canonicalization fails
    """
    canonical_bytes = canonicalize_profile(profile)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_policy_hash(policy: dict) -> str:
    """
    Compute SHA256 hash of canonicalized policy.
    
    Args:
        policy: Policy dict
        
    Returns:
        Hex digest of SHA256 hash
        
    Raises:
        CanonicalizeError: If canonicalization fails
    """
    canonical_bytes = canonicalize_policy(policy)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_event_hash(event: dict, prev_hash: Optional[str] = None) -> str:
    """
    Compute SHA256 hash of canonicalized event with previous hash chaining.
    
    Args:
        event: Event dict
        prev_hash: Previous event's record_hash (for chaining)
        
    Returns:
        Hex digest of SHA256 hash
        
    Raises:
        CanonicalizeError: If canonicalization fails
    """
    canonical_bytes = canonicalize_event_payload(event)
    if prev_hash:
        canonical_bytes += prev_hash.encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()
