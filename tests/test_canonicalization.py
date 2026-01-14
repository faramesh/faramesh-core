# tests/test_canonicalization.py
"""
Unit tests for deterministic canonicalization.

Covers:
1. Sorted dict keys
2. Nested dicts
3. Arrays preserving order
4. Float normalization
5. Unicode
6. Booleans/null
7. Error case: NaN
8. Error case: Infinity
9. Stable hashing
10. Non-mutation of input
"""

from __future__ import annotations

import copy
import math

import pytest

from faramesh.server.canonicalization import (
    CanonicalizeError,
    canonicalize,
    compute_hash,
)


class TestSortedDictKeys:
    """Test 1: Dict keys must be sorted lexicographically."""

    def test_simple_dict_keys_sorted(self) -> None:
        """Keys should be sorted in lexicographic order."""
        obj = {"zebra": 1, "apple": 2, "mango": 3}
        result = canonicalize(obj)
        assert result == '{"apple":2,"mango":3,"zebra":1}'

    def test_numeric_string_keys_sorted_lexicographically(self) -> None:
        """Numeric string keys should sort lexicographically, not numerically."""
        obj = {"10": "ten", "2": "two", "1": "one"}
        result = canonicalize(obj)
        # Lexicographic: "1" < "10" < "2"
        assert result == '{"1":"one","10":"ten","2":"two"}'

    def test_empty_dict(self) -> None:
        """Empty dict should produce {}."""
        assert canonicalize({}) == "{}"


class TestNestedDicts:
    """Test 2: Nested dicts must have keys sorted at all levels."""

    def test_nested_dict_keys_sorted(self) -> None:
        """Keys should be sorted at all nesting levels."""
        obj = {
            "outer_z": {"inner_b": 1, "inner_a": 2},
            "outer_a": {"inner_y": 3, "inner_x": 4},
        }
        result = canonicalize(obj)
        expected = '{"outer_a":{"inner_x":4,"inner_y":3},"outer_z":{"inner_a":2,"inner_b":1}}'
        assert result == expected

    def test_deeply_nested_dict(self) -> None:
        """Deep nesting should still sort keys at all levels."""
        obj = {"z": {"y": {"x": {"w": 1, "v": 2}}}}
        result = canonicalize(obj)
        assert result == '{"z":{"y":{"x":{"v":2,"w":1}}}}'


class TestArraysPreserveOrder:
    """Test 3: Arrays must preserve element order."""

    def test_array_order_preserved(self) -> None:
        """Array elements should maintain their original order."""
        obj = [3, 1, 4, 1, 5, 9, 2, 6]
        result = canonicalize(obj)
        assert result == "[3,1,4,1,5,9,2,6]"

    def test_array_of_dicts_order_preserved(self) -> None:
        """Array of dicts should preserve array order, sort dict keys."""
        obj = [{"b": 2, "a": 1}, {"d": 4, "c": 3}]
        result = canonicalize(obj)
        assert result == '[{"a":1,"b":2},{"c":3,"d":4}]'

    def test_empty_array(self) -> None:
        """Empty array should produce []."""
        assert canonicalize([]) == "[]"

    def test_nested_arrays(self) -> None:
        """Nested arrays should preserve order at all levels."""
        obj = [[3, 2, 1], [6, 5, 4]]
        result = canonicalize(obj)
        assert result == "[[3,2,1],[6,5,4]]"


class TestFloatNormalization:
    """Test 4: Floats must be normalized without exponent or trailing zeros."""

    def test_float_whole_number(self) -> None:
        """1.0 should become 1 (no decimal point for whole numbers)."""
        assert canonicalize(1.0) == "1"
        assert canonicalize(100.0) == "100"
        assert canonicalize(-5.0) == "-5"

    def test_float_scientific_notation_normalized(self) -> None:
        """Scientific notation should be expanded (1e3 → 1000)."""
        assert canonicalize(1e3) == "1000"
        assert canonicalize(1e6) == "1000000"
        assert canonicalize(2.5e2) == "250"

    def test_float_trailing_zeros_removed(self) -> None:
        """Trailing zeros should be removed."""
        assert canonicalize(1.50) == "1.5"
        assert canonicalize(1.500) == "1.5"

    def test_float_small_decimals(self) -> None:
        """Small decimals should be preserved without scientific notation."""
        assert canonicalize(0.001) == "0.001"
        assert canonicalize(0.0001) == "0.0001"

    def test_float_negative_zero(self) -> None:
        """Negative zero should be normalized to 0."""
        assert canonicalize(-0.0) == "0"

    def test_float_regular_decimals(self) -> None:
        """Regular decimals should be preserved correctly."""
        assert canonicalize(3.14159) == "3.14159"
        assert canonicalize(-2.5) == "-2.5"


class TestUnicode:
    """Test 5: Unicode strings must be preserved (ensure_ascii=False)."""

    def test_unicode_preserved(self) -> None:
        """Unicode characters should not be escaped."""
        obj = {"name": "日本語"}
        result = canonicalize(obj)
        assert result == '{"name":"日本語"}'

    def test_emoji_preserved(self) -> None:
        """Emoji should be preserved as-is."""
        obj = {"emoji": "🎉"}
        result = canonicalize(obj)
        assert result == '{"emoji":"🎉"}'

    def test_mixed_unicode(self) -> None:
        """Mixed unicode and ASCII should work correctly."""
        obj = {"greeting": "Hello, 世界! 🌍"}
        result = canonicalize(obj)
        assert result == '{"greeting":"Hello, 世界! 🌍"}'


class TestBooleansAndNull:
    """Test 6: Booleans and null must serialize correctly."""

    def test_true(self) -> None:
        """True should serialize as true."""
        assert canonicalize(True) == "true"

    def test_false(self) -> None:
        """False should serialize as false."""
        assert canonicalize(False) == "false"

    def test_null(self) -> None:
        """None should serialize as null."""
        assert canonicalize(None) == "null"

    def test_bool_in_dict(self) -> None:
        """Booleans in dict should serialize correctly."""
        obj = {"enabled": True, "disabled": False, "unknown": None}
        result = canonicalize(obj)
        assert result == '{"disabled":false,"enabled":true,"unknown":null}'

    def test_bool_not_confused_with_int(self) -> None:
        """True/False should not become 1/0."""
        # This is critical: bool is subclass of int in Python
        assert canonicalize([True, 1, False, 0]) == "[true,1,false,0]"


class TestErrorNaN:
    """Test 7: NaN must raise CanonicalizeError (fail closed)."""

    def test_nan_raises_error(self) -> None:
        """NaN should raise CanonicalizeError."""
        with pytest.raises(CanonicalizeError) as exc_info:
            canonicalize(float("nan"))
        assert "NaN" in str(exc_info.value)

    def test_nan_in_dict_raises_error(self) -> None:
        """NaN nested in dict should raise CanonicalizeError."""
        obj = {"value": float("nan")}
        with pytest.raises(CanonicalizeError) as exc_info:
            canonicalize(obj)
        assert "NaN" in str(exc_info.value)

    def test_nan_in_list_raises_error(self) -> None:
        """NaN nested in list should raise CanonicalizeError."""
        obj = [1, 2, float("nan"), 4]
        with pytest.raises(CanonicalizeError) as exc_info:
            canonicalize(obj)
        assert "NaN" in str(exc_info.value)


class TestErrorInfinity:
    """Test 8: Infinity must raise CanonicalizeError (fail closed)."""

    def test_positive_infinity_raises_error(self) -> None:
        """Positive infinity should raise CanonicalizeError."""
        with pytest.raises(CanonicalizeError) as exc_info:
            canonicalize(float("inf"))
        assert "Infinity" in str(exc_info.value)

    def test_negative_infinity_raises_error(self) -> None:
        """Negative infinity should raise CanonicalizeError."""
        with pytest.raises(CanonicalizeError) as exc_info:
            canonicalize(float("-inf"))
        assert "Infinity" in str(exc_info.value)

    def test_infinity_in_nested_structure_raises_error(self) -> None:
        """Infinity deeply nested should still raise CanonicalizeError."""
        obj = {"outer": {"inner": [1, 2, {"deep": math.inf}]}}
        with pytest.raises(CanonicalizeError) as exc_info:
            canonicalize(obj)
        assert "Infinity" in str(exc_info.value)


class TestStableHashing:
    """Test 9: compute_hash must produce stable, deterministic hashes."""

    def test_hash_is_deterministic(self) -> None:
        """Same input should always produce same hash."""
        obj = {"tool": "shell", "operation": "exec", "params": {"cmd": "ls"}}
        hash1 = compute_hash(obj)
        hash2 = compute_hash(obj)
        assert hash1 == hash2

    def test_hash_is_sha256_hex(self) -> None:
        """Hash should be 64-character hex string (SHA-256)."""
        hash_result = compute_hash({"test": True})
        assert len(hash_result) == 64
        assert all(c in "0123456789abcdef" for c in hash_result)

    def test_different_key_order_same_hash(self) -> None:
        """Different key order in input should produce same hash."""
        obj1 = {"a": 1, "b": 2, "c": 3}
        obj2 = {"c": 3, "b": 2, "a": 1}
        obj3 = {"b": 2, "a": 1, "c": 3}
        assert compute_hash(obj1) == compute_hash(obj2) == compute_hash(obj3)

    def test_different_values_different_hash(self) -> None:
        """Different values should produce different hashes."""
        obj1 = {"value": 1}
        obj2 = {"value": 2}
        assert compute_hash(obj1) != compute_hash(obj2)

    def test_hash_known_value(self) -> None:
        """Verify hash against known value for regression testing."""
        # Simple object with known canonical form: {"a":1}
        obj = {"a": 1}
        canonical = canonicalize(obj)
        assert canonical == '{"a":1}'
        # SHA-256 of '{"a":1}' encoded as UTF-8
        expected_hash = "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
        assert compute_hash(obj) == expected_hash


class TestNonMutation:
    """Test 10: canonicalize and compute_hash must not mutate input."""

    def test_canonicalize_does_not_mutate_dict(self) -> None:
        """canonicalize should not modify the input dict."""
        obj = {"z": 1, "a": 2, "m": {"y": 3, "x": 4}}
        original = copy.deepcopy(obj)
        canonicalize(obj)
        assert obj == original

    def test_canonicalize_does_not_mutate_list(self) -> None:
        """canonicalize should not modify the input list."""
        obj = [{"b": 1, "a": 2}, [3, 2, 1]]
        original = copy.deepcopy(obj)
        canonicalize(obj)
        assert obj == original

    def test_compute_hash_does_not_mutate_input(self) -> None:
        """compute_hash should not modify the input."""
        obj = {"nested": {"z": 1, "a": 2}, "list": [3, 2, 1]}
        original = copy.deepcopy(obj)
        compute_hash(obj)
        assert obj == original

    def test_input_with_mutable_nested_structures(self) -> None:
        """Complex nested mutable structures should not be mutated."""
        inner_list = [3, 2, 1]
        inner_dict = {"z": 1, "a": 2}
        obj = {"list": inner_list, "dict": inner_dict}
        
        inner_list_copy = inner_list.copy()
        inner_dict_copy = inner_dict.copy()
        
        canonicalize(obj)
        
        assert inner_list == inner_list_copy
        assert inner_dict == inner_dict_copy


class TestEdgeCases:
    """Additional edge cases for robustness."""

    def test_string_escaping(self) -> None:
        """Special characters in strings should be escaped."""
        obj = {"quote": 'say "hello"', "newline": "line1\nline2"}
        result = canonicalize(obj)
        assert result == '{"newline":"line1\\nline2","quote":"say \\"hello\\""}'

    def test_backslash_escaping(self) -> None:
        """Backslashes should be escaped."""
        obj = {"path": "C:\\Users\\test"}
        result = canonicalize(obj)
        assert result == '{"path":"C:\\\\Users\\\\test"}'

    def test_control_characters_escaped(self) -> None:
        """Control characters should be escaped."""
        obj = {"tab": "\t", "cr": "\r"}
        result = canonicalize(obj)
        assert result == '{"cr":"\\r","tab":"\\t"}'

    def test_non_string_key_raises_error(self) -> None:
        """Non-string dict keys should raise CanonicalizeError."""
        obj = {1: "value"}  # type: ignore
        with pytest.raises(CanonicalizeError) as exc_info:
            canonicalize(obj)
        assert "keys must be strings" in str(exc_info.value)

    def test_unsupported_type_raises_error(self) -> None:
        """Unsupported types should raise CanonicalizeError."""
        obj = {"func": lambda x: x}
        with pytest.raises(CanonicalizeError) as exc_info:
            canonicalize(obj)
        assert "Cannot canonicalize" in str(exc_info.value)
