"""Policy/FPL harness checks for DeepAgents-shaped tool identifiers."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from faramesh.gate import GateDecision

import faramesh.autopatch as autopatch


class TestDeepAgentsPolicyFPLHarness(unittest.TestCase):
    def _decision(
        self,
        *,
        outcome: str,
        reason_code: str = "RULE_PERMIT",
        provenance_id: str | None = None,
    ) -> GateDecision:
        return GateDecision.from_dict(
            {
                "outcome": outcome,
                "reason_code": reason_code,
                "reason": None,
                "request_hash": "req-hash",
                "policy_version": "v1",
                "policy_hash": "policy-hash",
                "profile_id": None,
                "profile_version": None,
                "profile_hash": None,
                "runtime_version": "runtime-v1",
                "provenance_id": provenance_id,
            }
        )

    @patch("os.path.exists", return_value=False)
    @patch("faramesh.gate.gate_decide")
    def test_govern_call_parses_deepagents_execute_layer_ids(self, mock_gate_decide, _mock_exists):
        mock_gate_decide.return_value = self._decision(outcome="EXECUTE")

        result = autopatch._govern_call(
            "task/research-agent/_execute_tool_sync",
            {
                "description": "research latest model updates",
                "subagent_type": "research-agent",
            },
        )

        self.assertEqual(result["effect"], "PERMIT")
        mock_gate_decide.assert_called_once_with(
            "auto-patched",
            "task/research-agent",
            "_execute_tool_sync",
            {
                "description": "research latest model updates",
                "subagent_type": "research-agent",
            },
        )

    @patch("os.path.exists", return_value=False)
    @patch("faramesh.gate.gate_decide")
    def test_govern_call_parses_deepagents_async_subagent_ops(self, mock_gate_decide, _mock_exists):
        mock_gate_decide.return_value = self._decision(outcome="DEFER", provenance_id="tok-deep-1")

        result = autopatch._govern_call(
            "start_async_task/_execute_tool_async",
            {
                "description": "collect benchmark results",
                "subagent_type": "researcher",
            },
        )

        self.assertEqual(result["effect"], "DEFER")
        self.assertEqual(result["defer_token"], "tok-deep-1")
        mock_gate_decide.assert_called_once_with(
            "auto-patched",
            "start_async_task",
            "_execute_tool_async",
            {
                "description": "collect benchmark results",
                "subagent_type": "researcher",
            },
        )


if __name__ == "__main__":
    unittest.main()
