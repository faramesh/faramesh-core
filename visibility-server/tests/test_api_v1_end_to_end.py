from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

TEST_ROOT = Path(__file__).resolve().parents[1]
if str(TEST_ROOT) not in sys.path:
    sys.path.insert(0, str(TEST_ROOT))

from app import main as visibility_main
from app.state import EventStore


class VisibilityV1ApiE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.dpr_db_path = Path(self.tmpdir.name) / "faramesh.db"
        self.state_db_path = Path(self.tmpdir.name) / "visibility.db"

        self.store = EventStore(
            dpr_db_path=self.dpr_db_path,
            state_db_path=self.state_db_path,
            max_actions=100,
        )

        self.patchers = [
            patch.object(visibility_main, "STORE", self.store),
            patch.object(visibility_main, "_start_worker", lambda *_args, **_kwargs: None),
        ]
        for patcher in self.patchers:
            patcher.start()

        self.client = TestClient(visibility_main.app)
        self.client.__enter__()

    def tearDown(self) -> None:
        try:
            self.client.__exit__(None, None, None)
        finally:
            for patcher in reversed(self.patchers):
                patcher.stop()
            self.tmpdir.cleanup()

    def test_v1_actions_lists_deferred_action(self) -> None:
        self.store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-v1-list",
                "agent_id": "agent-e2e",
                "session_id": "sess-e2e",
                "tool_id": "payment/refund",
                "tool_name": "payment",
                "operation": "refund",
                "effect": "DEFER",
                "reason_code": "RULE_DEFER",
                "reason": "Human approval required for high-value refund",
                "defer_token": "tok-v1-list",
                "timestamp": "2026-04-06T14:00:00Z",
                "args": {"amount": 1200, "currency": "USD"},
            }
        )

        res = self.client.get("/v1/actions?limit=10")
        self.assertEqual(res.status_code, 200)

        items = res.json()
        self.assertIsInstance(items, list)
        self.assertEqual(len(items), 1)

        action = items[0]
        self.assertEqual(action["id"], "call-v1-list")
        self.assertEqual(action["status"], "pending_approval")
        self.assertEqual(action["tool"], "payment")
        self.assertEqual(action["operation"], "refund")
        self.assertEqual(action["approval_token"], "tok-v1-list")
        self.assertEqual(action["params"]["amount"], 1200)

    def test_v1_actions_state_matrix_uses_domain_tool_names(self) -> None:
        self.store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-state-infra",
                "agent_id": "agent-platform",
                "session_id": "sess-platform",
                "tool_id": "infra_status/invoke",
                "effect": "PERMIT",
                "reason_code": "RULE_PERMIT",
                "reason": "infra deploy allowed",
                "timestamp": "2026-04-06T15:00:00Z",
                "args": {"target": "staging"},
            }
        )
        self.store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-state-db",
                "agent_id": "agent-platform",
                "session_id": "sess-platform",
                "tool_id": "db_readonly_query/invoke",
                "effect": "DENY",
                "reason_code": "RULE_DENY",
                "reason": "db query denied",
                "timestamp": "2026-04-06T15:00:01Z",
                "args": {"sql": "drop table users"},
            }
        )
        self.store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-state-bash",
                "agent_id": "agent-platform",
                "session_id": "sess-platform",
                "tool_id": "bash_run/invoke",
                "effect": "DENY",
                "reason_code": "RULE_DENY",
                "reason": "bash execution denied",
                "timestamp": "2026-04-06T15:00:02Z",
                "args": {"cmd": "rm -rf /tmp/example"},
            }
        )
        self.store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-state-payments",
                "agent_id": "agent-platform",
                "session_id": "sess-platform",
                "tool_id": "payments_refund/invoke",
                "effect": "DEFER",
                "reason_code": "RULE_DEFER",
                "reason": "payments refund requires approval",
                "defer_token": "tok-state-payments",
                "timestamp": "2026-04-06T15:00:03Z",
                "args": {"amount": 1800, "currency": "USD"},
            }
        )

        res = self.client.get("/v1/actions?limit=20")
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertEqual(len(items), 4)

        by_id = {item["id"]: item for item in items}
        self.assertEqual(by_id["call-state-infra"]["tool"], "infra")
        self.assertEqual(by_id["call-state-infra"]["operation"], "status")
        self.assertEqual(by_id["call-state-infra"]["status"], "allowed")
        self.assertEqual(by_id["call-state-db"]["tool"], "db")
        self.assertEqual(by_id["call-state-db"]["operation"], "readonly_query")
        self.assertEqual(by_id["call-state-db"]["status"], "denied")
        self.assertEqual(by_id["call-state-bash"]["tool"], "bash")
        self.assertEqual(by_id["call-state-bash"]["operation"], "run")
        self.assertEqual(by_id["call-state-bash"]["status"], "denied")
        self.assertEqual(by_id["call-state-payments"]["tool"], "payments")
        self.assertEqual(by_id["call-state-payments"]["operation"], "refund")
        self.assertEqual(by_id["call-state-payments"]["status"], "pending_approval")

        pending = self.client.get("/v1/actions?status=pending_approval&limit=10")
        self.assertEqual(pending.status_code, 200)
        pending_items = pending.json()
        self.assertEqual(len(pending_items), 1)
        self.assertEqual(pending_items[0]["id"], "call-state-payments")

        with patch.object(visibility_main, "send_json_request", return_value={"ok": True}):
            deny_res = self.client.post(
                "/v1/actions/call-state-payments/approval",
                json={"token": "tok-state-payments", "approve": False, "reason": "denied in test"},
            )
        self.assertEqual(deny_res.status_code, 200)
        denied = deny_res.json()
        self.assertEqual(denied["status"], "denied")

    def test_v1_action_approval_round_trip(self) -> None:
        self.store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-v1-approval",
                "agent_id": "agent-e2e",
                "session_id": "sess-e2e",
                "tool_id": "payment/refund",
                "tool_name": "payment",
                "operation": "refund",
                "effect": "DEFER",
                "reason_code": "RULE_DEFER",
                "reason": "Approval required",
                "defer_token": "tok-v1-approval",
                "timestamp": "2026-04-06T14:01:00Z",
                "args": {"amount": 3200, "currency": "USD"},
            }
        )

        with patch.object(visibility_main, "send_json_request", return_value={"ok": True}) as mocked:
            res = self.client.post(
                "/v1/actions/call-v1-approval/approval",
                json={
                    "token": "tok-v1-approval",
                    "approve": True,
                    "reason": "approved by e2e test",
                },
            )

        self.assertEqual(res.status_code, 200)
        updated = res.json()
        self.assertEqual(updated["id"], "call-v1-approval")
        self.assertEqual(updated["status"], "approved")
        self.assertEqual(updated["approval_token"], "tok-v1-approval")

        self.assertTrue(mocked.called)
        sent_payload = mocked.call_args.args[1]
        self.assertEqual(sent_payload["type"], "approve_defer")
        self.assertEqual(sent_payload["defer_token"], "tok-v1-approval")
        self.assertTrue(sent_payload["approved"])


if __name__ == "__main__":
    unittest.main()
