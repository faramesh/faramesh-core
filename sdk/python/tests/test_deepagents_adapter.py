"""Tests for the Faramesh DeepAgents adapter."""
from __future__ import annotations

import importlib
import sys
import types
import unittest
from unittest.mock import patch


class TestDeepAgentsAdapter(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_modules: dict[str, object | None] = {}
        for name in (
            "deepagents",
            "deepagents.graph",
            "faramesh.adapters.deepagents",
        ):
            self._saved_modules[name] = sys.modules.get(name)

        def fake_create_deep_agent(*args, **kwargs):
            return {
                "args": args,
                "kwargs": kwargs,
            }

        graph_mod = types.ModuleType("deepagents.graph")
        graph_mod.create_deep_agent = fake_create_deep_agent

        top_mod = types.ModuleType("deepagents")
        top_mod.create_deep_agent = fake_create_deep_agent

        sys.modules["deepagents"] = top_mod
        sys.modules["deepagents.graph"] = graph_mod
        sys.modules.pop("faramesh.adapters.deepagents", None)

        self.adapter = importlib.import_module("faramesh.adapters.deepagents")

    def tearDown(self) -> None:
        for name, module in self._saved_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module

    @patch("faramesh.adapters.deepagents.install_langchain_interceptor")
    def test_install_patches_deepagents_entrypoint(self, mock_install):
        mock_install.return_value = {
            "langchain": ["run"],
            "langgraph": ["_execute_tool_sync"],
        }

        patched = self.adapter.install_deepagents_interceptor(
            include_langgraph=True,
            fail_open=False,
        )

        self.assertIn("deepagents", patched)
        self.assertIn("create_deep_agent", patched["deepagents"])
        self.assertIn("langchain", patched)
        self.assertIn("langgraph", patched)

        deepagents_mod = importlib.import_module("deepagents")
        result = deepagents_mod.create_deep_agent(name="demo")

        self.assertEqual(result["kwargs"]["name"], "demo")
        # One call during install, plus one call when invoking wrapped create_deep_agent.
        self.assertGreaterEqual(mock_install.call_count, 2)

    @patch("faramesh.adapters.deepagents.install_langchain_interceptor")
    def test_install_is_idempotent_for_deepagents_patch(self, mock_install):
        mock_install.return_value = {}

        first = self.adapter.install_deepagents_interceptor()
        second = self.adapter.install_deepagents_interceptor()

        self.assertIn("deepagents", first)
        self.assertIn("create_deep_agent", first["deepagents"])
        self.assertNotIn("deepagents", second)

    @patch("faramesh.adapters.deepagents.install_langchain_interceptor")
    def test_install_without_deepagents_module(self, mock_install):
        mock_install.return_value = {"langchain": ["invoke"]}

        real_import = importlib.import_module

        def side_effect(name, *args, **kwargs):
            if name == "deepagents.graph":
                raise ImportError("deepagents missing")
            return real_import(name, *args, **kwargs)

        with patch("faramesh.adapters.deepagents.importlib.import_module", side_effect=side_effect):
            patched = self.adapter.install_deepagents_interceptor()

        self.assertIn("langchain", patched)
        self.assertNotIn("deepagents", patched)


if __name__ == "__main__":
    unittest.main()
