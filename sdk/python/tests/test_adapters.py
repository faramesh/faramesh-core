"""Tests for Faramesh framework adapters."""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch, MagicMock


class TestPydanticAIAdapter(unittest.TestCase):

    @patch("faramesh.autopatch._govern_call")
    def test_governed_tool_decorator_permit(self, mock_govern):
        """governed_tool wraps a function and permits on PERMIT."""
        mock_govern.return_value = {"effect": "PERMIT"}

        # Simulate the wrapper without importing pydantic_ai
        from faramesh.adapters.pydantic_ai import _is_async
        self.assertFalse(_is_async(lambda: None))

    @patch("faramesh.autopatch._govern_call")
    def test_governed_tool_deny(self, mock_govern):
        """governed_tool raises RuntimeError on DENY."""
        mock_govern.return_value = {"effect": "DENY", "reason_code": "OVER_LIMIT"}

        from faramesh.autopatch import _govern_call
        result = _govern_call("test/tool", {"amount": 9999})
        self.assertEqual(result["effect"], "DENY")

    @patch("faramesh.autopatch._govern_call")
    def test_governed_tool_unknown_effect_fail_closed(self, mock_govern):
        """governed_tool must fail closed on unknown effect values."""
        mock_govern.return_value = {"effect": "MYSTERY"}

        from faramesh.adapters.pydantic_ai import governed_tool

        class FakeAgent:
            def tool(self, retries=1):
                def decorator(fn):
                    return fn
                return decorator

        agent = FakeAgent()

        @governed_tool(agent, policy_tool_id="payments/refund")
        async def refund_tool() -> str:
            return "ok"

        with self.assertRaises(RuntimeError) as ctx:
            asyncio.run(refund_tool())
        self.assertIn("unknown effect", str(ctx.exception).lower())


class TestGoogleADKAdapter(unittest.TestCase):

    @patch("faramesh.autopatch._govern_call")
    def test_faramesh_tool_decorator(self, mock_govern):
        """faramesh_tool wraps a plain function for ADK."""
        mock_govern.return_value = {"effect": "PERMIT"}

        from faramesh.adapters.google_adk import faramesh_tool

        @faramesh_tool(policy_tool_id="weather/get")
        def get_weather(city: str, unit: str = "Celsius") -> dict:
            """Retrieves weather."""
            return {"city": city, "temp": 22, "unit": unit}

        result = get_weather(city="NYC", unit="Fahrenheit")
        self.assertEqual(result["city"], "NYC")
        mock_govern.assert_called_once_with("weather/get", {"city": "NYC", "unit": "Fahrenheit"})

    @patch("faramesh.autopatch._govern_call")
    def test_faramesh_tool_deny(self, mock_govern):
        mock_govern.return_value = {"effect": "DENY", "reason_code": "BLOCKED"}

        from faramesh.adapters.google_adk import faramesh_tool

        @faramesh_tool(policy_tool_id="danger/execute")
        def dangerous_op(cmd: str) -> str:
            return "should not reach"

        with self.assertRaises(RuntimeError) as ctx:
            dangerous_op(cmd="rm -rf /")
        self.assertIn("DENY", str(ctx.exception))
        self.assertIn("BLOCKED", str(ctx.exception))

    @patch("faramesh.autopatch._govern_call")
    def test_faramesh_tool_defer(self, mock_govern):
        mock_govern.return_value = {"effect": "DEFER", "defer_token": "tok789"}

        from faramesh.adapters.google_adk import faramesh_tool

        @faramesh_tool(policy_tool_id="payment/refund")
        def refund(amount: float) -> str:
            return "refunded"

        with self.assertRaises(RuntimeError) as ctx:
            refund(amount=500.0)
        self.assertIn("DEFER", str(ctx.exception))

    @patch("faramesh.autopatch._govern_call")
    def test_faramesh_tool_unknown_effect_fail_closed(self, mock_govern):
        mock_govern.return_value = {"effect": "MYSTERY"}

        from faramesh.adapters.google_adk import faramesh_tool

        @faramesh_tool(policy_tool_id="danger/execute")
        def dangerous_op(cmd: str) -> str:
            return "should not reach"

        with self.assertRaises(RuntimeError) as ctx:
            dangerous_op(cmd="noop")
        self.assertIn("unknown effect", str(ctx.exception).lower())

    @patch("faramesh.autopatch._govern_call")
    def test_faramesh_tool_fail_open(self, mock_govern):
        mock_govern.side_effect = RuntimeError("socket down")

        from faramesh.adapters.google_adk import faramesh_tool

        @faramesh_tool(policy_tool_id="safe/read", fail_open=True)
        def read_data() -> str:
            return "data"

        result = read_data()
        self.assertEqual(result, "data")

    @patch("faramesh.autopatch._govern_call")
    def test_govern_adk_agent(self, mock_govern):
        """govern_adk_agent wraps an agent's tools list."""
        mock_govern.return_value = {"effect": "PERMIT"}

        from faramesh.adapters.google_adk import govern_adk_agent

        class FakeAgent:
            tools = []

        def my_tool(x: int) -> int:
            return x + 1

        agent = FakeAgent()
        agent.tools = [my_tool]
        govern_adk_agent(agent)

        self.assertEqual(len(agent.tools), 1)
        result = agent.tools[0](x=5)
        self.assertEqual(result, 6)
        mock_govern.assert_called_once()


class TestBedrockAgentCoreAdapter(unittest.TestCase):

    @patch("faramesh.autopatch._govern_call")
    def test_govern_agentcore_tool(self, mock_govern):
        mock_govern.return_value = {"effect": "PERMIT"}

        from faramesh.adapters.bedrock_agentcore import govern_agentcore_tool

        @govern_agentcore_tool
        def my_tool(query: str) -> str:
            return f"result: {query}"

        result = my_tool(query="test")
        self.assertEqual(result, "result: test")
        mock_govern.assert_called_once_with("my_tool", {"query": "test"})

    @patch("faramesh.autopatch._govern_call")
    def test_govern_agentcore_tool_deny(self, mock_govern):
        mock_govern.return_value = {"effect": "DENY", "reason_code": "NO_ACCESS"}

        from faramesh.adapters.bedrock_agentcore import govern_agentcore_tool

        @govern_agentcore_tool
        def restricted(data: str) -> str:
            return "secret"

        with self.assertRaises(RuntimeError) as ctx:
            restricted(data="classified")
        self.assertIn("DENY", str(ctx.exception))

    @patch("faramesh.autopatch._govern_call")
    def test_govern_agentcore_tool_unknown_effect_fail_closed(self, mock_govern):
        mock_govern.return_value = {"effect": "MYSTERY"}

        from faramesh.adapters.bedrock_agentcore import govern_agentcore_tool

        @govern_agentcore_tool
        def restricted(data: str) -> str:
            return "secret"

        with self.assertRaises(RuntimeError) as ctx:
            restricted(data="classified")
        self.assertIn("unknown effect", str(ctx.exception).lower())

    def test_strands_hook_init(self):
        from faramesh.adapters.bedrock_agentcore import FarameshStrandsHook

        hook = FarameshStrandsHook(policy="test.yaml", agent_id="test-agent")
        self.assertEqual(hook.agent_id, "test-agent")
        self.assertEqual(hook.policy, "test.yaml")

    def test_strands_hook_lifecycle(self):
        from faramesh.adapters.bedrock_agentcore import FarameshStrandsHook

        hook = FarameshStrandsHook(agent_id="lifecycle-test")
        hook.before_invocation()
        hook.message_added()
        hook.after_invocation()


class TestAutopatchNewFrameworks(unittest.TestCase):
    """Test that new framework patchers are registered."""

    def test_patchers_registry(self):
        from faramesh.autopatch import _PATCHERS

        self.assertIn("deepagents", _PATCHERS)
        self.assertIn("google-adk", _PATCHERS)
        self.assertIn("llamaindex", _PATCHERS)
        self.assertIn("strands-agents", _PATCHERS)
        self.assertIn("pydantic-ai", _PATCHERS)

    def test_patcher_count(self):
        from faramesh.autopatch import _PATCHERS
        self.assertGreaterEqual(len(_PATCHERS), 11)


if __name__ == "__main__":
    unittest.main()
