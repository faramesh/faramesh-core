"""Tests for the Faramesh LangChain/LangGraph drop-in adapter."""
from __future__ import annotations

import asyncio
import importlib
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class TestLangChainAdapter(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_modules: dict[str, object | None] = {}
        for name in (
            "langchain_core",
            "langchain_core.tools",
            "langgraph",
            "langgraph.prebuilt",
            "langgraph.prebuilt.tool_node",
            "faramesh.adapters.langchain",
        ):
            self._saved_modules[name] = sys.modules.get(name)

        class FakeBaseTool:
            name = "fake_tool"

            def __init__(self) -> None:
                self.run_calls = 0
                self.arun_calls = 0

            def run(self, tool_input, **kwargs):
                self.run_calls += 1
                return {"ok": tool_input, "kwargs": kwargs}

            async def arun(self, tool_input, **kwargs):
                self.arun_calls += 1
                return {"ok": tool_input, "kwargs": kwargs}

            def invoke(self, input, config=None, **kwargs):
                return self.run(input, **kwargs)

            async def ainvoke(self, input, config=None, **kwargs):
                return await self.arun(input, **kwargs)

        class FakeToolNode:
            def _run_one(self, call, input_type, tool_runtime):
                return {"tool": call["name"], "input_type": input_type}

            async def _arun_one(self, call, input_type, tool_runtime):
                return {"tool": call["name"], "input_type": input_type}

        class FakeToolNodeExecute:
            def __init__(self):
                self._wrap_tool_call = None
                self._awrap_tool_call = None

            def _execute_tool_sync(self, request, input_type, config):
                call = request.tool_call
                return {
                    "tool": call["name"],
                    "args": call.get("args", {}),
                    "input_type": input_type,
                }

            async def _execute_tool_async(self, request, input_type, config):
                call = request.tool_call
                return {
                    "tool": call["name"],
                    "args": call.get("args", {}),
                    "input_type": input_type,
                }

            def _run_one(self, call, input_type, tool_runtime):
                request = SimpleNamespace(tool_call=call)
                if self._wrap_tool_call is None:
                    return self._execute_tool_sync(request, input_type, {})

                def execute(req):
                    return self._execute_tool_sync(req, input_type, {})

                return self._wrap_tool_call(request, execute)

            async def _arun_one(self, call, input_type, tool_runtime):
                request = SimpleNamespace(tool_call=call)
                if self._awrap_tool_call is not None:
                    async def execute(req):
                        return await self._execute_tool_async(req, input_type, {})

                    return await self._awrap_tool_call(request, execute)

                if self._wrap_tool_call is not None:
                    def execute_sync(req):
                        return self._execute_tool_sync(req, input_type, {})

                    return self._wrap_tool_call(request, execute_sync)

                return await self._execute_tool_async(request, input_type, {})

        self._FakeBaseTool = FakeBaseTool
        self._FakeToolNode = FakeToolNode
        self._FakeToolNodeExecute = FakeToolNodeExecute

        langchain_core_mod = types.ModuleType("langchain_core")
        langchain_tools_mod = types.ModuleType("langchain_core.tools")
        langchain_tools_mod.BaseTool = FakeBaseTool
        langchain_core_mod.tools = langchain_tools_mod

        langgraph_mod = types.ModuleType("langgraph")
        prebuilt_mod = types.ModuleType("langgraph.prebuilt")
        tool_node_mod = types.ModuleType("langgraph.prebuilt.tool_node")
        tool_node_mod.ToolNode = FakeToolNodeExecute
        prebuilt_mod.tool_node = tool_node_mod
        langgraph_mod.prebuilt = prebuilt_mod

        sys.modules["langchain_core"] = langchain_core_mod
        sys.modules["langchain_core.tools"] = langchain_tools_mod
        sys.modules["langgraph"] = langgraph_mod
        sys.modules["langgraph.prebuilt"] = prebuilt_mod
        sys.modules["langgraph.prebuilt.tool_node"] = tool_node_mod

        sys.modules.pop("faramesh.adapters.langchain", None)
        self.adapter = importlib.import_module("faramesh.adapters.langchain")

    def tearDown(self) -> None:
        for name, module in self._saved_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module

    @patch("faramesh.autopatch._govern_call")
    def test_install_patches_langchain_and_langgraph(self, mock_govern):
        mock_govern.return_value = {"effect": "PERMIT"}

        patched = self.adapter.install_langchain_interceptor(include_langgraph=True)

        self.assertIn("langchain", patched)
        self.assertIn("run", patched["langchain"])
        self.assertIn("invoke", patched["langchain"])
        self.assertIn("langgraph", patched)
        self.assertIn("_execute_tool_sync", patched["langgraph"])

    @patch("faramesh.autopatch._govern_call")
    def test_install_is_idempotent_with_execute_layer_toolnode(self, mock_govern):
        mock_govern.return_value = {"effect": "PERMIT"}

        first = self.adapter.install_langchain_interceptor(include_langgraph=True)
        second = self.adapter.install_langchain_interceptor(include_langgraph=True)

        self.assertIn("langgraph", first)
        self.assertIn("_execute_tool_sync", first["langgraph"])
        self.assertEqual(second, {})

        node = self._FakeToolNodeExecute()
        result = node._run_one(
            {"name": "idempotent_tool", "args": {"q": "x"}, "id": "idem-1"},
            "tool_calls",
            None,
        )

        self.assertEqual(result["tool"], "idempotent_tool")
        ids = [c[0][0] for c in mock_govern.call_args_list]
        self.assertIn("idempotent_tool/_execute_tool_sync", ids)
        self.assertNotIn("idempotent_tool/_run_one", ids)

    @patch("faramesh.autopatch._govern_call")
    def test_install_fallback_for_old_toolnode_shape(self, mock_govern):
        mock_govern.return_value = {"effect": "PERMIT"}

        class FallbackOnlyToolNode:
            def _run_one(self, call, input_type, tool_runtime):
                return {"tool": call["name"]}

            async def _arun_one(self, call, input_type, tool_runtime):
                return {"tool": call["name"]}

        tool_node_mod = types.ModuleType("langgraph.prebuilt.tool_node")
        tool_node_mod.ToolNode = FallbackOnlyToolNode
        sys.modules["langgraph.prebuilt.tool_node"] = tool_node_mod
        self.adapter = importlib.reload(self.adapter)

        patched = self.adapter.install_langchain_interceptor(include_langgraph=True)
        self.assertIn("langgraph", patched)
        self.assertIn("_run_one", patched["langgraph"])

        node = FallbackOnlyToolNode()
        result = node._run_one(
            {"name": "fallback_tool", "args": {"q": "x"}, "id": "fb1"},
            "tool_calls",
            None,
        )

        self.assertEqual(result["tool"], "fallback_tool")
        self.assertGreaterEqual(mock_govern.call_count, 1)
        self.assertEqual(mock_govern.call_args_list[-1][0][0], "fallback_tool/_run_one")

    @patch("faramesh.autopatch._govern_call")
    def test_invoke_governed_once(self, mock_govern):
        mock_govern.return_value = {"effect": "PERMIT"}

        self.adapter.install_langchain_interceptor(include_langgraph=False)
        tool = self._FakeBaseTool()

        result = tool.invoke(
            {"name": "fake_tool", "args": {"city": "SF"}, "id": "call-1", "type": "tool_call"}
        )

        self.assertEqual(result["ok"]["args"]["city"], "SF")
        self.assertEqual(mock_govern.call_count, 1)
        self.assertEqual(mock_govern.call_args[0][0], "fake_tool/invoke")

    @patch("faramesh.autopatch._govern_call")
    def test_ainvoke_governed_once(self, mock_govern):
        mock_govern.return_value = {"effect": "PERMIT"}

        self.adapter.install_langchain_interceptor(include_langgraph=False)
        tool = self._FakeBaseTool()

        out = asyncio.run(tool.ainvoke({"name": "fake_tool", "args": {"x": 1}, "id": "acall-1"}))

        self.assertEqual(out["ok"]["args"]["x"], 1)
        self.assertEqual(mock_govern.call_count, 1)
        self.assertEqual(mock_govern.call_args[0][0], "fake_tool/ainvoke")

    @patch("faramesh.autopatch._govern_call")
    def test_deny_blocks_before_tool_execution(self, mock_govern):
        mock_govern.return_value = {"effect": "DENY", "reason_code": "BLOCKED"}

        self.adapter.install_langchain_interceptor(include_langgraph=False)
        tool = self._FakeBaseTool()

        with self.assertRaises(RuntimeError) as ctx:
            tool.run({"action": "dangerous"})

        self.assertIn("DENY", str(ctx.exception))
        self.assertEqual(tool.run_calls, 0)

    @patch("faramesh.autopatch._govern_call")
    def test_fail_open_allows_execution_when_governance_transport_fails(self, mock_govern):
        mock_govern.side_effect = RuntimeError("socket down")

        self.adapter.install_langchain_interceptor(fail_open=True, include_langgraph=False)
        tool = self._FakeBaseTool()

        result = tool.run({"safe": True})

        self.assertEqual(result["ok"]["safe"], True)
        self.assertEqual(tool.run_calls, 1)

    @patch("faramesh.autopatch._govern_call")
    def test_toolnode_sync_dispatch_governed(self, mock_govern):
        mock_govern.return_value = {"effect": "PERMIT"}

        self.adapter.install_langchain_interceptor(include_langgraph=True)
        node = self._FakeToolNodeExecute()

        out = node._run_one({"name": "graph_tool", "args": {"q": "ping"}, "id": "t1"}, "tool_calls", None)

        self.assertEqual(out["tool"], "graph_tool")
        self.assertEqual(mock_govern.call_count, 1)
        self.assertEqual(mock_govern.call_args[0][0], "graph_tool/_execute_tool_sync")

    @patch("faramesh.autopatch._govern_call")
    def test_toolnode_async_dispatch_governed(self, mock_govern):
        mock_govern.return_value = {"effect": "PERMIT"}

        self.adapter.install_langchain_interceptor(include_langgraph=True)
        node = self._FakeToolNodeExecute()

        out = asyncio.run(
            node._arun_one({"name": "graph_tool", "args": {"q": "ping"}, "id": "t2"}, "tool_calls", None)
        )

        self.assertEqual(out["tool"], "graph_tool")
        self.assertEqual(mock_govern.call_count, 1)
        self.assertEqual(mock_govern.call_args[0][0], "graph_tool/_execute_tool_async")

    @patch("faramesh.autopatch._govern_call")
    def test_toolnode_execute_layer_retry_sync_governed_each_attempt(self, mock_govern):
        mock_govern.return_value = {"effect": "PERMIT"}

        self.adapter.install_langchain_interceptor(include_langgraph=True)
        node = self._FakeToolNodeExecute()

        def wrap_tool_call(request, execute):
            first = SimpleNamespace(
                tool_call={
                    "name": request.tool_call["name"],
                    "args": {"attempt": 1},
                    "id": request.tool_call["id"],
                }
            )
            second = SimpleNamespace(
                tool_call={
                    "name": request.tool_call["name"],
                    "args": {"attempt": 2},
                    "id": request.tool_call["id"],
                }
            )
            execute(first)
            return execute(second)

        node._wrap_tool_call = wrap_tool_call
        result = node._run_one(
            {"name": "graph_tool", "args": {"attempt": 0}, "id": "retry-sync"},
            "tool_calls",
            None,
        )

        self.assertEqual(result["args"]["attempt"], 2)
        self.assertEqual(mock_govern.call_count, 2)
        self.assertEqual(mock_govern.call_args_list[0][0][0], "graph_tool/_execute_tool_sync")
        self.assertEqual(mock_govern.call_args_list[1][0][0], "graph_tool/_execute_tool_sync")

    @patch("faramesh.autopatch._govern_call")
    def test_toolnode_execute_layer_retry_async_governed_each_attempt(self, mock_govern):
        mock_govern.return_value = {"effect": "PERMIT"}

        self.adapter.install_langchain_interceptor(include_langgraph=True)
        node = self._FakeToolNodeExecute()

        async def awrap_tool_call(request, execute):
            first = SimpleNamespace(
                tool_call={
                    "name": request.tool_call["name"],
                    "args": {"attempt": 1},
                    "id": request.tool_call["id"],
                }
            )
            second = SimpleNamespace(
                tool_call={
                    "name": request.tool_call["name"],
                    "args": {"attempt": 2},
                    "id": request.tool_call["id"],
                }
            )
            await execute(first)
            return await execute(second)

        node._awrap_tool_call = awrap_tool_call

        result = asyncio.run(
            node._arun_one(
                {"name": "graph_tool", "args": {"attempt": 0}, "id": "retry-async"},
                "tool_calls",
                None,
            )
        )

        self.assertEqual(result["args"]["attempt"], 2)
        self.assertEqual(mock_govern.call_count, 2)
        self.assertEqual(mock_govern.call_args_list[0][0][0], "graph_tool/_execute_tool_async")
        self.assertEqual(mock_govern.call_args_list[1][0][0], "graph_tool/_execute_tool_async")

    @patch("faramesh.autopatch._govern_call")
    def test_unknown_effect_is_fail_closed(self, mock_govern):
        mock_govern.return_value = {"effect": "MYSTERY"}

        self.adapter.install_langchain_interceptor(include_langgraph=False)
        tool = self._FakeBaseTool()

        with self.assertRaises(RuntimeError) as ctx:
            tool.run({"x": 1})
        self.assertIn("unknown effect", str(ctx.exception).lower())

    @patch("faramesh.autopatch._govern_call")
    def test_fail_open_handles_non_runtime_errors(self, mock_govern):
        mock_govern.side_effect = ValueError("unexpected serialization failure")

        self.adapter.install_langchain_interceptor(fail_open=True, include_langgraph=False)
        tool = self._FakeBaseTool()
        result = tool.run({"safe": True})

        self.assertEqual(result["ok"]["safe"], True)


if __name__ == "__main__":
    unittest.main()
