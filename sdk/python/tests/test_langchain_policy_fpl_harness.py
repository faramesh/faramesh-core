"""Policy/FPL verification harness for LangChain interception paths.

This module validates policy effect mappings and adapter enforcement behavior
in a deterministic, CI-friendly way.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import faramesh.autopatch as autopatch
from faramesh.adapters import langchain as langchain_adapter
from faramesh.gate import GateDecision


class TestLangChainPolicyFPLHarness(unittest.TestCase):
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
    def test_gate_outcome_to_effect_mapping_matrix(self, mock_gate_decide, _mock_exists):
        cases = [
            ("EXECUTE", "PERMIT", "RULE_PERMIT", None),
            ("PERMIT", "PERMIT", "RULE_PERMIT", None),
            ("HALT", "DENY", "RULE_DENY", None),
            ("DENY", "DENY", "RULE_DENY", None),
            ("ABSTAIN", "DEFER", "DEFER_APPROVAL", "prov-1"),
            ("DEFER", "DEFER", "DEFER_APPROVAL", "prov-2"),
        ]

        for outcome, expected_effect, reason_code, provenance_id in cases:
            with self.subTest(outcome=outcome):
                mock_gate_decide.return_value = self._decision(
                    outcome=outcome,
                    reason_code=reason_code,
                    provenance_id=provenance_id,
                )
                result = autopatch._govern_call("payment/refund/invoke", {"amount": 700})

                self.assertEqual(result["effect"], expected_effect)
                if expected_effect == "DENY":
                    self.assertEqual(result["reason_code"], reason_code)
                if expected_effect == "DEFER":
                    self.assertEqual(result["defer_token"], provenance_id)

    @patch("os.path.exists", return_value=False)
    @patch("faramesh.gate.gate_decide")
    def test_govern_call_parses_tool_and_operation_for_fpl_scopes(
        self, mock_gate_decide, _mock_exists
    ):
        mock_gate_decide.return_value = self._decision(outcome="EXECUTE")

        autopatch._govern_call("vault/probe/invoke", {"scope": "payments"})

        mock_gate_decide.assert_called_once_with(
            "auto-patched",
            "vault/probe",
            "invoke",
            {"scope": "payments"},
        )

    @patch("faramesh.autopatch._govern_call")
    def test_adapter_enforce_policy_matrix(self, mock_govern):
        payload = {
            "framework": "langchain",
            "method": "invoke",
            "tool_name": "payment_refund",
            "tool_call_id": "call-1",
            "input": {"amount": 700},
        }

        mock_govern.return_value = {"effect": "PERMIT"}
        langchain_adapter._enforce_policy(
            tool_id="payment_refund/invoke",
            payload=payload,
            fail_open=False,
        )

        mock_govern.return_value = {"effect": "DENY", "reason_code": "RULE_DENY"}
        with self.assertRaises(RuntimeError) as deny_ctx:
            langchain_adapter._enforce_policy(
                tool_id="payment_refund/invoke",
                payload=payload,
                fail_open=False,
            )
        self.assertIn("DENY", str(deny_ctx.exception))

        mock_govern.return_value = {"effect": "DEFER", "defer_token": "tok-1"}
        with self.assertRaises(RuntimeError) as defer_ctx:
            langchain_adapter._enforce_policy(
                tool_id="payment_refund/invoke",
                payload=payload,
                fail_open=False,
            )
        self.assertIn("DEFER", str(defer_ctx.exception))

        mock_govern.return_value = {"effect": "UNRECOGNIZED"}
        with self.assertRaises(RuntimeError) as unknown_ctx:
            langchain_adapter._enforce_policy(
                tool_id="payment_refund/invoke",
                payload=payload,
                fail_open=False,
            )
        self.assertIn("unknown effect", str(unknown_ctx.exception).lower())

    @patch("faramesh.autopatch._govern_call")
    def test_adapter_fail_open_behavior_for_transport_errors(self, mock_govern):
        payload = {
            "framework": "langchain",
            "method": "invoke",
            "tool_name": "http_get",
            "tool_call_id": "call-2",
            "input": {"url": "https://example.com"},
        }

        mock_govern.side_effect = RuntimeError("transport down")

        langchain_adapter._enforce_policy(
            tool_id="http_get/invoke",
            payload=payload,
            fail_open=True,
        )

        with self.assertRaises(RuntimeError):
            langchain_adapter._enforce_policy(
                tool_id="http_get/invoke",
                payload=payload,
                fail_open=False,
            )


if __name__ == "__main__":
    unittest.main()
