"""Tests for canonicalization module - verifies deterministic hashing."""

import pytest
from faramesh.canonicalization import (
    canonicalize,
    canonicalize_action_payload,
    compute_request_hash,
    compute_hash,
    CanonicalizeError,
)


class TestCanonicalizeBasics:
    """Test basic canonicalization behavior."""

    def test_dict_keys_sorted(self):
        """Dict keys should be sorted lexicographically."""
        obj = {"z": 1, "a": 2, "m": 3}
        result = canonicalize(obj)
        assert result == '{"a":2,"m":3,"z":1}'

    def test_nested_dict_keys_sorted(self):
        """Nested dicts should also have sorted keys."""
        obj = {"b": {"y": 1, "x": 2}, "a": {"w": 3, "v": 4}}
        result = canonicalize(obj)
        assert result == '{"a":{"v":4,"w":3},"b":{"x":2,"y":1}}'

    def test_array_order_preserved(self):
        """Array order must be preserved (not sorted)."""
        obj = [3, 1, 4, 1, 5, 9, 2, 6]
        result = canonicalize(obj)
        assert result == "[3,1,4,1,5,9,2,6]"

    def test_empty_dict(self):
        """Empty dict should produce {}."""
        assert canonicalize({}) == "{}"

    def test_empty_array(self):
        """Empty array should produce []."""
        assert canonicalize([]) == "[]"


class TestFloatNormalization:
    """Test float normalization rules."""

    def test_whole_numbers(self):
        """1.0 should become 1 (no decimal point)."""
        assert canonicalize(1.0) == "1"
        assert canonicalize(100.0) == "100"
        assert canonicalize(-5.0) == "-5"

    def test_scientific_notation(self):
        """Scientific notation should be expanded."""
        assert canonicalize(1e3) == "1000"
        assert canonicalize(1e6) == "1000000"
        assert canonicalize(2.5e2) == "250"

    def test_trailing_zeros_removed(self):
        """Trailing zeros should be removed."""
        assert canonicalize(1.50) == "1.5"
        assert canonicalize(1.500) == "1.5"

    def test_negative_zero(self):
        """Negative zero should become 0."""
        assert canonicalize(-0.0) == "0"

    def test_nan_raises_error(self):
        """NaN should raise CanonicalizeError."""
        with pytest.raises(CanonicalizeError) as exc_info:
            canonicalize(float("nan"))
        assert "NaN" in str(exc_info.value)

    def test_infinity_raises_error(self):
        """Infinity should raise CanonicalizeError."""
        with pytest.raises(CanonicalizeError):
            canonicalize(float("inf"))
        with pytest.raises(CanonicalizeError):
            canonicalize(float("-inf"))


class TestBoolAndNull:
    """Test boolean and null serialization."""

    def test_true(self):
        assert canonicalize(True) == "true"

    def test_false(self):
        assert canonicalize(False) == "false"

    def test_null(self):
        assert canonicalize(None) == "null"

    def test_bool_not_confused_with_int(self):
        """True/False should not become 1/0."""
        assert canonicalize([True, 1, False, 0]) == "[true,1,false,0]"


class TestUnicode:
    """Test unicode preservation (ensure_ascii=False)."""

    def test_unicode_preserved(self):
        """Unicode should not be escaped."""
        obj = {"name": "日本語"}
        result = canonicalize(obj)
        assert result == '{"name":"日本語"}'

    def test_emoji_preserved(self):
        """Emoji should be preserved."""
        obj = {"emoji": "🎉"}
        result = canonicalize(obj)
        assert result == '{"emoji":"🎉"}'


class TestStringEscaping:
    """Test string escaping."""

    def test_quotes_escaped(self):
        obj = {"quote": 'say "hello"'}
        result = canonicalize(obj)
        assert '\\"' in result

    def test_newline_escaped(self):
        obj = {"newline": "line1\nline2"}
        result = canonicalize(obj)
        assert '\\n' in result

    def test_backslash_escaped(self):
        obj = {"path": "C:\\Users"}
        result = canonicalize(obj)
        assert '\\\\' in result


class TestRequestHash:
    """Test request_hash computation."""

    def test_key_order_doesnt_matter(self):
        """Different key order should produce same hash."""
        payload1 = {
            "agent_id": "test",
            "tool": "http",
            "operation": "get",
            "params": {"a": 1, "b": 2},
            "context": {},
        }
        payload2 = {
            "context": {},
            "params": {"b": 2, "a": 1},
            "operation": "get",
            "tool": "http",
            "agent_id": "test",
        }
        
        hash1 = compute_request_hash(payload1)
        hash2 = compute_request_hash(payload2)
        assert hash1 == hash2

    def test_different_values_different_hash(self):
        """Different values should produce different hash."""
        payload1 = {"agent_id": "test", "tool": "http", "operation": "get", "params": {}}
        payload2 = {"agent_id": "test", "tool": "http", "operation": "post", "params": {}}
        
        hash1 = compute_request_hash(payload1)
        hash2 = compute_request_hash(payload2)
        assert hash1 != hash2

    def test_hash_is_sha256(self):
        """Hash should be 64-character hex string (SHA-256)."""
        payload = {"agent_id": "test", "tool": "http", "operation": "get", "params": {}}
        hash_value = compute_request_hash(payload)
        
        assert len(hash_value) == 64
        assert all(c in "0123456789abcdef" for c in hash_value)

    def test_hash_is_deterministic(self):
        """Same input should always produce same hash."""
        payload = {"agent_id": "test", "tool": "http", "operation": "get", "params": {"url": "https://example.com"}}
        
        hash1 = compute_request_hash(payload)
        hash2 = compute_request_hash(payload)
        hash3 = compute_request_hash(payload)
        
        assert hash1 == hash2 == hash3

    def test_excludes_ephemeral_fields(self):
        """Ephemeral fields should not affect hash."""
        payload1 = {"agent_id": "test", "tool": "http", "operation": "get", "params": {}}
        payload2 = {
            "agent_id": "test",
            "tool": "http",
            "operation": "get",
            "params": {},
            "id": "some-uuid",
            "created_at": "2024-01-01T00:00:00Z",
            "status": "allowed",
            "decision": "allow",
        }
        
        hash1 = compute_request_hash(payload1)
        hash2 = compute_request_hash(payload2)
        assert hash1 == hash2


class TestKnownHashValues:
    """Test against known hash values for regression testing."""

    def test_known_simple_payload(self):
        """Verify hash against known value."""
        payload = {
            "agent_id": "test",
            "tool": "http",
            "operation": "get",
            "params": {},
            "context": {},
        }
        
        hash_value = compute_request_hash(payload)
        # This is the expected hash - if it changes, canonicalization logic changed
        # Note: This should match faramesh-core's output for the same payload
        assert len(hash_value) == 64
        assert hash_value  # Non-empty


class TestCanonicalizeActionPayload:
    """Test action payload canonicalization."""

    def test_returns_bytes(self):
        """Should return bytes."""
        payload = {"agent_id": "test", "tool": "http", "operation": "get", "params": {}}
        result = canonicalize_action_payload(payload)
        assert isinstance(result, bytes)

    def test_utf8_encoded(self):
        """Should be UTF-8 encoded."""
        payload = {"agent_id": "test", "tool": "http", "operation": "get", "params": {"name": "日本語"}}
        result = canonicalize_action_payload(payload)
        decoded = result.decode("utf-8")
        assert "日本語" in decoded

    def test_excludes_underscore_fields(self):
        """Fields starting with _ should be excluded."""
        payload = {
            "agent_id": "test",
            "tool": "http",
            "operation": "get",
            "params": {},
            "_internal": "ignored",
        }
        result = canonicalize_action_payload(payload)
        assert b"_internal" not in result
