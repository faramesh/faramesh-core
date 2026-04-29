"""Live integration tests for Faramesh LangChain/LangGraph interception.

These tests run against real langchain-core/langgraph packages when available.
They are skipped automatically if dependencies are not installed.
"""
from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from faramesh.adapters.langchain import install_langchain_interceptor

try:
    from langchain_core.tools import tool
    from langgraph.prebuilt.tool_node import ToolNode

    HAS_LIVE_DEPS = True
except Exception:  # pragma: no cover - dependency presence gate
    HAS_LIVE_DEPS = False


@unittest.skipUnless(HAS_LIVE_DEPS, "requires langchain-core and langgraph")
class TestLangChainLangGraphLiveIntegration(unittest.TestCase):
    def _runtime(self, tool_call_id: str) -> SimpleNamespace:
        return SimpleNamespace(
            state={"messages": []},
            config={},
            context=None,
            store=None,
            stream_writer=None,
            execution_info=None,
            server_info=None,
            tool_call_id=tool_call_id,
        )

    @patch("faramesh.autopatch._govern_call")
    def test_sync_permit_deny_defer_paths(self, mock_govern):
        execution_count = {"safe_math": 0, "deny_tool": 0, "defer_tool": 0}

        @tool
        def safe_math(x: int, y: int) -> int:
            """Safe math operation."""
            execution_count["safe_math"] += 1
            return x + y

        @tool
        def deny_tool(x: int) -> int:
            """Tool that policy denies."""
            execution_count["deny_tool"] += 1
            return x

        @tool
        def defer_tool(x: int) -> int:
            """Tool that policy defers."""
            execution_count["defer_tool"] += 1
            return x

        def govern_side_effect(tool_id, payload):
            if tool_id.startswith("deny_tool/"):
                return {"effect": "DENY", "reason_code": "TEST_DENY"}
            if tool_id.startswith("defer_tool/"):
                return {"effect": "DEFER", "defer_token": "tok-123"}
            return {"effect": "PERMIT"}

        mock_govern.side_effect = govern_side_effect

        install_langchain_interceptor(include_langgraph=True, fail_open=False)
        node = ToolNode([safe_math, deny_tool, defer_tool])

        permit_call = {
            "name": "safe_math",
            "args": {"x": 2, "y": 3},
            "id": "permit-1",
            "type": "tool_call",
        }
        out = node._run_one(permit_call, "tool_calls", self._runtime("permit-1"))
        self.assertEqual(str(out.content), "5")
        self.assertEqual(execution_count["safe_math"], 1)

        deny_call = {
            "name": "deny_tool",
            "args": {"x": 7},
            "id": "deny-1",
            "type": "tool_call",
        }
        with self.assertRaises(RuntimeError) as deny_ctx:
            node._run_one(deny_call, "tool_calls", self._runtime("deny-1"))
        self.assertIn("DENY", str(deny_ctx.exception))
        self.assertEqual(execution_count["deny_tool"], 0)

        defer_call = {
            "name": "defer_tool",
            "args": {"x": 9},
            "id": "defer-1",
            "type": "tool_call",
        }
        with self.assertRaises(RuntimeError) as defer_ctx:
            node._run_one(defer_call, "tool_calls", self._runtime("defer-1"))
        self.assertIn("DEFER", str(defer_ctx.exception))
        self.assertEqual(execution_count["defer_tool"], 0)

    @patch("faramesh.autopatch._govern_call")
    def test_sync_retry_wrapper_governs_each_execution(self, mock_govern):
        attempts: list[int] = []

        @tool
        def retryable_tool(attempt: int) -> int:
            """Records each retry attempt."""
            attempts.append(attempt)
            return attempt

        mock_govern.return_value = {"effect": "PERMIT"}

        def wrap_tool_call(request, execute):
            first = request.override(
                tool_call={
                    **request.tool_call,
                    "args": {"attempt": 1},
                }
            )
            second = request.override(
                tool_call={
                    **request.tool_call,
                    "args": {"attempt": 2},
                }
            )
            execute(first)
            return execute(second)

        install_langchain_interceptor(include_langgraph=True, fail_open=False)
        node = ToolNode([retryable_tool], wrap_tool_call=wrap_tool_call)

        call = {
            "name": "retryable_tool",
            "args": {"attempt": 0},
            "id": "retry-sync",
            "type": "tool_call",
        }
        out = node._run_one(call, "tool_calls", self._runtime("retry-sync"))

        self.assertEqual(str(out.content), "2")
        self.assertEqual(attempts, [1, 2])
        tool_ids = [c.args[0] for c in mock_govern.call_args_list]
        execute_layer = [tid for tid in tool_ids if tid.endswith("/_execute_tool_sync")]
        self.assertEqual(len(execute_layer), 2)

    @patch("faramesh.autopatch._govern_call")
    def test_async_retry_wrapper_governs_each_execution(self, mock_govern):
        attempts: list[int] = []

        @tool
        def retryable_tool(attempt: int) -> int:
            """Records each retry attempt."""
            attempts.append(attempt)
            return attempt

        mock_govern.return_value = {"effect": "PERMIT"}

        async def awrap_tool_call(request, execute):
            first = request.override(
                tool_call={
                    **request.tool_call,
                    "args": {"attempt": 1},
                }
            )
            second = request.override(
                tool_call={
                    **request.tool_call,
                    "args": {"attempt": 2},
                }
            )
            await execute(first)
            return await execute(second)

        install_langchain_interceptor(include_langgraph=True, fail_open=False)
        node = ToolNode([retryable_tool], awrap_tool_call=awrap_tool_call)

        async def run_test():
            call = {
                "name": "retryable_tool",
                "args": {"attempt": 0},
                "id": "retry-async",
                "type": "tool_call",
            }
            return await node._arun_one(call, "tool_calls", self._runtime("retry-async"))

        out = asyncio.run(run_test())

        self.assertEqual(str(out.content), "2")
        self.assertEqual(attempts, [1, 2])
        tool_ids = [c.args[0] for c in mock_govern.call_args_list]
        execute_layer = [tid for tid in tool_ids if tid.endswith("/_execute_tool_async")]
        self.assertEqual(len(execute_layer), 2)

    @patch("faramesh.autopatch._govern_call")
    def test_repeated_install_keeps_execute_layer_only(self, mock_govern):
        @tool
        def idempotent_tool(x: int) -> int:
            """Simple test tool for repeated install path checks."""
            return x

        mock_govern.return_value = {"effect": "PERMIT"}

        install_langchain_interceptor(include_langgraph=True, fail_open=False)
        install_langchain_interceptor(include_langgraph=True, fail_open=False)

        node = ToolNode([idempotent_tool])
        call = {
            "name": "idempotent_tool",
            "args": {"x": 11},
            "id": "idempotent-live",
            "type": "tool_call",
        }
        out = node._run_one(call, "tool_calls", self._runtime("idempotent-live"))

        self.assertEqual(str(out.content), "11")
        tool_ids = [c.args[0] for c in mock_govern.call_args_list]
        self.assertTrue(any(tid.endswith("/_execute_tool_sync") for tid in tool_ids))
        self.assertFalse(any(tid.endswith("/_run_one") for tid in tool_ids))


if __name__ == "__main__":
    unittest.main()
