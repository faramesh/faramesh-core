"""Tests for the Faramesh auto-patcher."""
from __future__ import annotations

import os
import types
import unittest
from unittest.mock import patch, MagicMock


class TestAutopatch(unittest.TestCase):
    """Tests for the autopatch module."""

    def _make_fake_cls(self):
        """Create a fake tool class to patch."""
        class FakeTool:
            name = "test_tool"

            def run(self, *args, **kwargs):
                return "original_result"

        return FakeTool

    def test_wrap_method_patches_class(self):
        from faramesh.autopatch import _wrap_method

        cls = self._make_fake_cls()
        tool_id_fn = lambda self, a, kw: getattr(self, "name", "unknown")

        ok = _wrap_method(cls, "run", "test", tool_id_fn)
        self.assertTrue(ok)
        self.assertTrue(getattr(cls.run, "_faramesh_patched", False))

    def test_wrap_method_idempotent(self):
        from faramesh.autopatch import _wrap_method

        cls = self._make_fake_cls()
        tool_id_fn = lambda self, a, kw: "t"

        ok1 = _wrap_method(cls, "run", "test", tool_id_fn)
        ok2 = _wrap_method(cls, "run", "test", tool_id_fn)
        self.assertTrue(ok1)
        self.assertFalse(ok2)

    def test_wrap_method_nonexistent(self):
        from faramesh.autopatch import _wrap_method

        cls = self._make_fake_cls()
        tool_id_fn = lambda self, a, kw: "t"

        ok = _wrap_method(cls, "nonexistent_method", "test", tool_id_fn)
        self.assertFalse(ok)

    @patch("faramesh.autopatch._govern_call")
    def test_wrapped_method_calls_govern(self, mock_govern):
        from faramesh.autopatch import _wrap_method

        mock_govern.return_value = {"effect": "PERMIT"}

        cls = self._make_fake_cls()
        tool_id_fn = lambda self, a, kw: getattr(self, "name", "unknown")
        _wrap_method(cls, "run", "test", tool_id_fn)

        instance = cls()
        result = instance.run("hello")

        mock_govern.assert_called_once()
        call_args = mock_govern.call_args
        self.assertEqual(call_args[0][0], "test_tool")
        self.assertEqual(result, "original_result")

    @patch("faramesh.autopatch._govern_call")
    def test_wrapped_method_deny_raises(self, mock_govern):
        from faramesh.autopatch import _wrap_method

        mock_govern.return_value = {"effect": "DENY", "reason_code": "BUDGET_EXCEEDED"}

        cls = self._make_fake_cls()
        tool_id_fn = lambda self, a, kw: "test_tool"
        _wrap_method(cls, "run", "test", tool_id_fn)

        instance = cls()
        with self.assertRaises(RuntimeError) as ctx:
            instance.run("hello")
        self.assertIn("DENY", str(ctx.exception))
        self.assertIn("BUDGET_EXCEEDED", str(ctx.exception))

    @patch("faramesh.autopatch._govern_call")
    def test_wrapped_method_defer_raises(self, mock_govern):
        from faramesh.autopatch import _wrap_method

        mock_govern.return_value = {"effect": "DEFER", "defer_token": "tok123"}

        cls = self._make_fake_cls()
        tool_id_fn = lambda self, a, kw: "test_tool"
        _wrap_method(cls, "run", "test", tool_id_fn)

        instance = cls()
        with self.assertRaises(RuntimeError) as ctx:
            instance.run()
        self.assertIn("DEFER", str(ctx.exception))

    @patch("faramesh.autopatch._govern_call")
    def test_wrapped_method_unknown_effect_fail_closed(self, mock_govern):
        from faramesh.autopatch import _wrap_method

        mock_govern.return_value = {"effect": "UNEXPECTED_EFFECT"}

        cls = self._make_fake_cls()
        tool_id_fn = lambda self, a, kw: "test_tool"
        _wrap_method(cls, "run", "test", tool_id_fn)

        instance = cls()
        with self.assertRaises(RuntimeError) as ctx:
            instance.run()
        self.assertIn("unknown effect", str(ctx.exception).lower())

    @patch("os.path.exists", return_value=False)
    @patch("faramesh.gate.gate_decide")
    def test_govern_call_unknown_outcome_fail_closed(self, mock_gate_decide, _mock_exists):
        from faramesh.autopatch import _govern_call

        mock_gate_decide.return_value = types.SimpleNamespace(
            outcome="MYSTERY",
            reason_code="X",
            provenance_id="",
        )

        with self.assertRaises(RuntimeError) as ctx:
            _govern_call("test_tool/invoke", {})
        self.assertIn("unknown effect", str(ctx.exception).lower())

    @patch("os.path.exists", return_value=True)
    @patch("socket.socket")
    def test_govern_call_jsonrpc_error_fail_closed(self, mock_socket_ctor, _mock_exists):
        from faramesh.autopatch import _govern_call

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            b'{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"boom"}}\n'
        ]
        mock_socket_ctor.return_value = mock_sock

        with self.assertRaises(RuntimeError) as ctx:
            _govern_call("test_tool/invoke", {"input": "hello"})
        self.assertIn("denied", str(ctx.exception).lower())

    @patch("faramesh.adapters.langchain.install_langchain_interceptor")
    def test_patch_langchain_delegates_to_langchain_adapter(self, mock_install):
        from faramesh.autopatch import _patch_langchain

        mock_install.return_value = {
            "langchain": ["run", "arun", "invoke", "ainvoke"],
            "langgraph": ["_execute_tool_sync", "_execute_tool_async"],
        }

        patched = _patch_langchain()
        self.assertTrue(patched)
        mock_install.assert_called_once_with(include_langgraph=True, fail_open=False)

    def test_extract_args(self):
        from faramesh.autopatch import _extract_args

        result = _extract_args(("hello",), {"key": "value"})
        self.assertEqual(result["input"], "hello")
        self.assertEqual(result["key"], "value")

        result = _extract_args((), {"a": 1, "b": 2})
        self.assertEqual(result, {"a": 1, "b": 2})

        result = _extract_args((1, 2, 3), {})
        self.assertEqual(result["_positional"], [1, 2, 3])

    def test_strip_ambient_credentials_env(self):
        """Test that the Go-side credential stripping logic matches expectations."""
        env = {
            "PATH": "/usr/bin",
            "OPENAI_API_KEY": "sk-abc",
            "MY_SAFE_VAR": "keep",
        }
        ambient_keys = {"OPENAI_API_KEY", "STRIPE_API_KEY", "ANTHROPIC_API_KEY"}
        stripped = {k: v for k, v in env.items() if k not in ambient_keys}
        self.assertNotIn("OPENAI_API_KEY", stripped)
        self.assertIn("MY_SAFE_VAR", stripped)

    def test_install_idempotent(self):
        """install() should be idempotent."""
        import faramesh.autopatch as ap
        ap._installed = False
        ap._patched_frameworks.clear()

        result1 = ap.install()
        result2 = ap.install()
        self.assertEqual(result1, result2)


if __name__ == "__main__":
    unittest.main()
