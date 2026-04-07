from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

TEST_ROOT = Path(__file__).resolve().parents[1]
if str(TEST_ROOT) not in sys.path:
    sys.path.insert(0, str(TEST_ROOT))

from app.state import EventStore, parse_timestamp


class EventStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "faramesh.db"
        self._create_db(self.db_path)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _create_db(self, path: Path) -> None:
        conn = sqlite3.connect(path)
        try:
            conn.execute(
                """
                CREATE TABLE dpr_records (
                    record_id TEXT PRIMARY KEY,
                    record_hash TEXT,
                    prev_record_hash TEXT,
                    reason_code TEXT,
                    reason TEXT,
                    created_at TEXT
                )
                """
            )
            conn.execute(
                """
                INSERT INTO dpr_records (record_id, record_hash, prev_record_hash, reason_code, reason, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "rec-1",
                    "hash-1",
                    "hash-0",
                    "RULE_DEFER",
                    "db-linked reason",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def test_state_mapping_for_decisions_and_defer_resolution(self) -> None:
        store = EventStore(self.db_path)

        store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-defer",
                "agent_id": "agent-a",
                "tool_id": "payment/refund",
                "effect": "DEFER",
                "reason_code": "REFUND_REVIEW",
                "defer_token": "tok-1",
                "timestamp": "2026-04-06T10:00:00Z",
                "record_id": "rec-1",
            }
        )
        action = store.get_action("call-defer")
        self.assertIsNotNone(action)
        self.assertEqual(action["state"], "pending")
        self.assertEqual(action["record_hash"], "hash-1")

        store.ingest_callback_event(
            {
                "event_type": "defer_resolved",
                "defer_token": "tok-1",
                "status": "approved",
                "reason": "operator approved",
                "timestamp": "2026-04-06T10:00:01Z",
            }
        )
        action = store.get_action("call-defer")
        self.assertIsNotNone(action)
        self.assertEqual(action["state"], "approved")

        store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-permit",
                "agent_id": "agent-a",
                "tool_id": "http/get",
                "effect": "PERMIT",
                "reason_code": "ALLOW",
                "timestamp": "2026-04-06T10:00:02Z",
            }
        )
        permit = store.get_action("call-permit")
        self.assertIsNotNone(permit)
        self.assertEqual(permit["state"], "allowed")

        store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-deny",
                "agent_id": "agent-a",
                "tool_id": "shell/run",
                "effect": "DENY",
                "reason_code": "BLOCKED",
                "timestamp": "2026-04-06T10:00:03Z",
            }
        )
        deny = store.get_action("call-deny")
        self.assertIsNotNone(deny)
        self.assertEqual(deny["state"], "denied")

    def test_legacy_projection_contains_real_tool_and_context(self) -> None:
        store = EventStore(self.db_path)
        store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-legacy",
                "agent_id": "agent-legacy",
                "tool_id": "payment/refund",
                "tool_name": "payment",
                "operation": "refund",
                "effect": "DEFER",
                "reason_code": "RULE_DEFER",
                "reason": "Refund exceeds policy threshold",
                "defer_token": "tok-legacy",
                "timestamp": "2026-04-06T11:00:00Z",
                "blast_radius": "external",
                "reversibility": "reversible",
                "principal_id": "spiffe://mesh/agent/payment",
                "principal_method": "spiffe",
                "record_id": "rec-1",
                "args": {"order_id": "ord-1", "amount": 4200},
            }
        )

        legacy = store.get_legacy_action("call-legacy")
        self.assertIsNotNone(legacy)
        self.assertEqual(legacy["tool"], "payment")
        self.assertEqual(legacy["operation"], "refund")
        self.assertEqual(legacy["status"], "pending_approval")
        self.assertEqual(legacy["approval_token"], "tok-legacy")
        self.assertEqual(legacy["params"]["order_id"], "ord-1")
        self.assertEqual(legacy["context"]["principal_method"], "spiffe")
        self.assertEqual(legacy["context"]["record_hash"], "hash-1")

    def test_public_projection_redacts_sensitive_fields(self) -> None:
        store = EventStore(self.db_path)
        store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-public",
                "agent_id": "agent-public",
                "tool_id": "payment/refund",
                "tool_name": "payment",
                "operation": "refund",
                "effect": "DEFER",
                "reason_code": "RULE_DEFER",
                "reason": "Refund exceeds policy threshold",
                "defer_token": "tok-public",
                "timestamp": "2026-04-06T11:10:00Z",
                "args": {"order_id": "ord-1", "amount": 4200},
            }
        )

        action = store.get_public_action("call-public")
        self.assertIsNotNone(action)
        self.assertEqual(action["defer_token"], "")
        self.assertEqual(action["params"]["keys"], ["amount", "order_id"])
        self.assertTrue(action["params"]["redacted"])
        self.assertEqual(action["timeline"][0]["defer_token"], "")
        self.assertEqual(action["timeline"][0]["args"]["keys"], ["amount", "order_id"])

        legacy = store.get_legacy_action("call-public", redact_sensitive=True)
        self.assertIsNotNone(legacy)
        self.assertIsNone(legacy["approval_token"])
        self.assertEqual(legacy["context"]["defer_token"], "")
        self.assertEqual(legacy["params"]["keys"], ["amount", "order_id"])

    def test_state_db_persists_actions_across_restarts(self) -> None:
        state_db = Path(self.tmpdir.name) / "visibility.db"
        store = EventStore(self.db_path, state_db_path=state_db)
        store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-persist",
                "agent_id": "agent-p",
                "tool_id": "mail/send",
                "effect": "PERMIT",
                "timestamp": "2026-04-06T12:00:00Z",
            }
        )

        restored = EventStore(self.db_path, state_db_path=state_db)
        action = restored.get_action("call-persist")
        self.assertIsNotNone(action)
        self.assertEqual(action["agent_id"], "agent-p")

    def test_timeline_ordering_under_concurrent_events(self) -> None:
        store = EventStore(self.db_path)
        base = datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc)
        events = []
        for offset in [3, 1, 2, 0]:
            ts = (base + timedelta(milliseconds=offset)).isoformat().replace("+00:00", "Z")
            events.append(
                {
                    "event_type": "decision",
                    "call_id": "call-order",
                    "agent_id": "agent-order",
                    "tool_id": "tool/order",
                    "effect": "PERMIT",
                    "reason_code": f"R{offset}",
                    "timestamp": ts,
                }
            )

        with ThreadPoolExecutor(max_workers=4) as pool:
            for event in events:
                pool.submit(store.ingest_callback_event, event)

        action = store.get_action("call-order")
        self.assertIsNotNone(action)
        timeline = action["timeline"]
        ordered = [parse_timestamp(item["timestamp"]) for item in timeline]
        self.assertEqual(ordered, sorted(ordered))

    def test_dpr_linkage_attaches_hashes_to_timeline(self) -> None:
        store = EventStore(self.db_path)
        store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-linked",
                "agent_id": "agent-l",
                "tool_id": "tool/l",
                "effect": "DEFER",
                "reason_code": "RULE_DEFER",
                "record_id": "rec-1",
                "timestamp": "2026-04-06T10:00:00Z",
            }
        )

        action = store.get_action("call-linked")
        self.assertIsNotNone(action)
        self.assertEqual(action["record_hash"], "hash-1")
        self.assertEqual(action["prev_record_hash"], "hash-0")
        self.assertEqual(action["reason"], "db-linked reason")

        timeline = action["timeline"]
        self.assertGreaterEqual(len(timeline), 1)
        self.assertEqual(timeline[0]["record_id"], "rec-1")
        self.assertEqual(timeline[0]["record_hash"], "hash-1")

    def test_audit_shadow_is_collapsed_when_callback_arrives(self) -> None:
        store = EventStore(self.db_path)

        store.ingest_audit_event(
            {
                "agent_id": "agent-shadow",
                "tool_id": "safe_status/invoke",
                "effect": "PERMIT",
                "reason_code": "RULE_PERMIT",
                "timestamp": "2026-04-06T10:00:00Z",
            }
        )

        before = store.list_actions(limit=10)
        self.assertEqual(len(before), 1)
        self.assertTrue(str(before[0]["call_id"]).startswith("audit::"))

        store.ingest_callback_event(
            {
                "event_type": "decision",
                "call_id": "call-real",
                "agent_id": "agent-shadow",
                "tool_id": "safe_status/invoke",
                "effect": "PERMIT",
                "reason_code": "RULE_PERMIT",
                "timestamp": "2026-04-06T10:00:00.100Z",
            }
        )

        action = store.get_action("call-real")
        self.assertIsNotNone(action)
        self.assertEqual(action["tool_name"], "safe_status")
        self.assertEqual(action["operation"], "invoke")

        after = store.list_actions(limit=10)
        matching = [a for a in after if a.get("agent_id") == "agent-shadow" and a.get("tool_id") == "safe_status/invoke"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["call_id"], "call-real")


if __name__ == "__main__":
    unittest.main()
