from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _decision_effect_to_state(effect: str) -> str:
    normalized = (effect or "").upper()
    if normalized == "DEFER":
        return "pending"
    if normalized == "DENY":
        return "denied"
    if normalized == "PERMIT":
        return "allowed"
    return "allowed"


def _defer_status_to_state(status: str) -> str:
    normalized = (status or "").lower()
    if normalized == "approved":
        return "approved"
    return "denied"


def _split_tool_id(tool_id: str) -> tuple[str, str]:
    text = (tool_id or "").strip()
    if not text:
        return "", ""
    parts = text.rsplit("/", 1)
    if len(parts) != 2:
        return text, "invoke"
    return parts[0], parts[1] or "invoke"


def _normalize_domain_tool_name(tool_name: str, operation: str) -> tuple[str, str]:
    raw = (tool_name or "").strip()
    if not raw:
        return raw, operation

    for domain in ("bash", "db", "infra", "payments"):
        prefix = f"{domain}_"
        if raw == domain:
            return domain, operation
        if raw.startswith(prefix):
            op = raw[len(prefix) :].strip() or operation
            return domain, op

    return raw, operation


class EventStore:
    """Action timeline store with optional DPR linkage and SQLite persistence."""

    def __init__(
        self,
        dpr_db_path: Path,
        max_actions: int = 2000,
        state_db_path: Path | None = None,
    ) -> None:
        self._dpr_db_path = Path(dpr_db_path)
        self._state_db_path = Path(state_db_path) if state_db_path else None
        self._max_actions = max_actions
        self._lock = threading.RLock()
        self._actions: dict[str, dict[str, Any]] = {}
        self._token_index: dict[str, str] = {}
        self._dpr_columns: set[str] | None = None

        if self._state_db_path is not None:
            self._init_state_db()
            self._load_state_db()

    def ingest_callback_event(self, event: dict[str, Any]) -> None:
        event_type = str(event.get("event_type") or "").strip().lower()
        if event_type == "decision":
            self._ingest_callback_decision(event)
            return
        if event_type == "defer_resolved":
            self._ingest_callback_defer_resolved(event)
            return

    def ingest_audit_event(self, event: dict[str, Any]) -> None:
        effect = str(event.get("effect") or "").upper()
        if not effect:
            return

        timestamp = str(event.get("timestamp") or utc_now_iso())
        defer_token = str(event.get("defer_token") or "")
        agent_id = str(event.get("agent_id") or "")
        session_id = str(event.get("session_id") or "")
        tool_id = str(event.get("tool_id") or "")
        tool_name = str(event.get("tool_name") or "")
        operation = str(event.get("operation") or "")
        reason = str(event.get("reason") or "")
        reason_code = str(event.get("reason_code") or "")
        record_id = str(event.get("record_id") or "")
        args = event.get("args") if isinstance(event.get("args"), dict) else {}

        with self._lock:
            call_id = ""
            if defer_token and defer_token in self._token_index:
                call_id = self._token_index[defer_token]
            if not call_id:
                call_id = self._find_recent_call(agent_id, tool_id)
            if not call_id:
                ts = int(parse_timestamp(timestamp).timestamp() * 1_000_000)
                call_id = f"audit::{agent_id or 'unknown'}::{tool_id or 'unknown'}::{ts}"

            state = _decision_effect_to_state(effect)
            action = self._upsert_action(call_id, agent_id, tool_id)
            if session_id:
                action["session_id"] = session_id
            action["decision_effect"] = effect
            action["state"] = state
            action["reason_code"] = reason_code or str(action.get("reason_code") or "")
            action["reason"] = reason or str(action.get("reason") or "")
            action["updated_at"] = timestamp
            if tool_name:
                action["tool_name"] = tool_name
            if operation:
                action["operation"] = operation
            if record_id:
                action["record_id"] = record_id
            if isinstance(args, dict) and args:
                action["params"] = args

            action["blast_radius"] = str(event.get("blast_radius") or action.get("blast_radius") or "")
            action["reversibility"] = str(event.get("reversibility") or action.get("reversibility") or "")
            action["incident_category"] = str(event.get("incident_category") or action.get("incident_category") or "")
            action["incident_severity"] = str(event.get("incident_severity") or action.get("incident_severity") or "")
            action["policy_version"] = str(event.get("policy_version") or action.get("policy_version") or "")
            action["principal_id"] = str(event.get("principal_id") or action.get("principal_id") or "")
            action["principal_method"] = str(event.get("principal_method") or action.get("principal_method") or "")

            if defer_token:
                action["defer_token"] = defer_token
                self._token_index[defer_token] = call_id

            self._append_timeline(
                action,
                {
                    "source": "audit",
                    "state": state,
                    "effect": effect,
                    "reason_code": action.get("reason_code") or "",
                    "reason": action.get("reason") or "",
                    "timestamp": timestamp,
                    "defer_token": defer_token,
                    "record_id": action.get("record_id") or "",
                    "args": action.get("params") or {},
                },
            )
            self._persist_action(action)
            self._enforce_retention()

    def list_actions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            actions = [self._clone_action(a) for a in self._actions.values()]

        # Hide synthetic audit shadow rows when a callback row exists for
        # the same agent/tool within a short time window.
        real_actions = [a for a in actions if not str(a.get("call_id") or "").startswith("audit::")]
        filtered: list[dict[str, Any]] = []
        for action in actions:
            call_id = str(action.get("call_id") or "")
            if not call_id.startswith("audit::"):
                filtered.append(action)
                continue

            action_ts = parse_timestamp(str(action.get("updated_at") or ""))
            should_skip = False
            for real in real_actions:
                if str(real.get("agent_id") or "") != str(action.get("agent_id") or ""):
                    continue
                if str(real.get("tool_id") or "") != str(action.get("tool_id") or ""):
                    continue
                real_ts = parse_timestamp(str(real.get("updated_at") or ""))
                if abs((real_ts - action_ts).total_seconds()) <= 5.0:
                    should_skip = True
                    break

            if not should_skip:
                filtered.append(action)

        filtered.sort(key=lambda item: parse_timestamp(str(item.get("updated_at") or "")), reverse=True)
        return filtered[: max(1, limit)]

    def get_action(self, call_id: str) -> dict[str, Any] | None:
        with self._lock:
            action = self._actions.get(call_id)
            if action is None:
                return None
            return self._clone_action(action)

    def get_public_action(self, call_id: str) -> dict[str, Any] | None:
        action = self.get_action(call_id)
        if action is None:
            return None
        return self.to_public_action(action)

    def pending_defers(self) -> list[dict[str, Any]]:
        with self._lock:
            pending = [
                self._clone_action(action)
                for action in self._actions.values()
                if action.get("state") == "pending" and action.get("defer_token")
            ]
        pending.sort(key=lambda item: parse_timestamp(str(item.get("updated_at") or "")), reverse=True)
        return pending

    def pending_public_defers(self) -> list[dict[str, Any]]:
        return [self.to_public_action(item) for item in self.pending_defers()]

    def count(self) -> int:
        with self._lock:
            return len(self._actions)

    def resolve_call_for_token(self, defer_token: str) -> str | None:
        with self._lock:
            return self._token_index.get(defer_token)

    def list_legacy_actions(
        self,
        limit: int = 50,
        status: str | None = None,
        agent: str | None = None,
        tool: str | None = None,
        query: str | None = None,
        redact_sensitive: bool = False,
    ) -> list[dict[str, Any]]:
        projector = self.to_public_legacy_action if redact_sensitive else self.to_legacy_action
        items = [projector(item) for item in self.list_actions(limit=max(limit, 5000))]
        filtered: list[dict[str, Any]] = []
        status_norm = (status or "").strip().lower()
        agent_norm = (agent or "").strip().lower()
        tool_norm = (tool or "").strip().lower()
        query_norm = (query or "").strip().lower()

        for item in items:
            if status_norm and status_norm != "all" and str(item.get("status") or "").lower() != status_norm:
                continue
            if agent_norm and agent_norm not in str(item.get("agent_id") or "").lower():
                continue
            if tool_norm and tool_norm not in str(item.get("tool") or "").lower():
                continue
            if query_norm:
                haystack = " ".join(
                    [
                        str(item.get("tool") or ""),
                        str(item.get("operation") or ""),
                        str(item.get("agent_id") or ""),
                        str(item.get("reason") or ""),
                        str(item.get("risk_level") or ""),
                        str(item.get("context", {}).get("blast_radius") or ""),
                    ]
                ).lower()
                if query_norm not in haystack:
                    continue
            filtered.append(item)

        filtered.sort(key=lambda item: parse_timestamp(str(item.get("updated_at") or "")), reverse=True)
        return filtered[: max(1, limit)]

    def get_legacy_action(self, call_id: str, redact_sensitive: bool = False) -> dict[str, Any] | None:
        item = self.get_action(call_id)
        if item is None:
            return None
        if redact_sensitive:
            return self.to_public_legacy_action(item)
        return self.to_legacy_action(item)

    def list_public_actions(self, limit: int = 100) -> list[dict[str, Any]]:
        return [self.to_public_action(item) for item in self.list_actions(limit=limit)]

    def to_legacy_action(self, action: dict[str, Any]) -> dict[str, Any]:
        call_id = str(action.get("call_id") or "")
        tool_name = str(action.get("tool_name") or "")
        operation = str(action.get("operation") or "")
        if not tool_name or not operation:
            split_tool, split_op = _split_tool_id(str(action.get("tool_id") or ""))
            if not tool_name:
                tool_name = split_tool
            if not operation:
                operation = split_op

        tool_name, operation = _normalize_domain_tool_name(tool_name, operation)

        decision_effect = str(action.get("decision_effect") or "").upper()
        decision = "allow"
        if decision_effect == "DENY":
            decision = "deny"
        elif decision_effect == "DEFER":
            decision = "require_approval"

        state = str(action.get("state") or "")
        status = "allowed"
        if state == "pending":
            status = "pending_approval"
        elif state == "denied":
            status = "denied"
        elif state == "approved":
            status = "approved"
        elif state == "executing":
            status = "executing"
        elif state == "failed":
            status = "failed"
        elif state == "succeeded":
            status = "succeeded"

        reason_code = str(action.get("reason_code") or "")
        reason = str(action.get("reason") or "").strip()
        if not reason and reason_code:
            reason = _plain_reason_from_code(reason_code)

        blast_radius = str(action.get("blast_radius") or "")
        reversibility = str(action.get("reversibility") or "")
        incident_severity = str(action.get("incident_severity") or "")

        if blast_radius and reason:
            reason = f"{reason} (blast radius: {blast_radius})"

        context = {
            "call_id": call_id,
            "session_id": str(action.get("session_id") or ""),
            "tool_id": str(action.get("tool_id") or ""),
            "reason_code": reason_code,
            "rule_id": str(action.get("rule_id") or ""),
            "policy_version": str(action.get("policy_version") or ""),
            "blast_radius": blast_radius,
            "reversibility": reversibility,
            "incident_category": str(action.get("incident_category") or ""),
            "incident_severity": incident_severity,
            "principal_id": str(action.get("principal_id") or ""),
            "principal_method": str(action.get("principal_method") or ""),
            "record_id": str(action.get("record_id") or ""),
            "record_hash": str(action.get("record_hash") or ""),
            "prev_record_hash": str(action.get("prev_record_hash") or ""),
            "defer_token": str(action.get("defer_token") or ""),
            "timeline_count": len(action.get("timeline") or []),
        }

        out = {
            "id": call_id,
            "agent_id": str(action.get("agent_id") or ""),
            "tool": tool_name,
            "operation": operation,
            "params": action.get("params") if isinstance(action.get("params"), dict) else {},
            "context": context,
            "decision": decision,
            "status": status,
            "reason": reason,
            "risk_level": _derive_risk_level(blast_radius, incident_severity),
            "policy_version": str(action.get("policy_version") or ""),
            "created_at": str(action.get("created_at") or action.get("updated_at") or utc_now_iso()),
            "updated_at": str(action.get("updated_at") or utc_now_iso()),
            "approval_token": str(action.get("defer_token") or "") or None,
            "reason_code": reason_code,
            "blast_radius": blast_radius,
            "reversibility": reversibility,
            "incident_severity": incident_severity,
            "timeline": [dict(item) for item in action.get("timeline") or []],
        }
        return out

    def to_public_action(self, action: dict[str, Any]) -> dict[str, Any]:
        public = self._clone_action(action)
        public["defer_token"] = ""
        public["params"] = _redacted_mapping_summary(public.get("params"))
        public["timeline"] = [_redact_timeline_event(item) for item in public.get("timeline") or []]
        return public

    def to_public_legacy_action(self, action: dict[str, Any]) -> dict[str, Any]:
        return self.to_legacy_action(self.to_public_action(action))

    def _ingest_callback_decision(self, event: dict[str, Any]) -> None:
        call_id = str(event.get("call_id") or "").strip()
        if not call_id:
            ts = int(parse_timestamp(str(event.get("timestamp") or utc_now_iso())).timestamp() * 1_000_000)
            call_id = f"callback::{ts}"

        agent_id = str(event.get("agent_id") or "")
        session_id = str(event.get("session_id") or "")
        tool_id = str(event.get("tool_id") or "")
        effect = str(event.get("effect") or "").upper()
        reason_code = str(event.get("reason_code") or "")
        reason = str(event.get("reason") or "")
        record_id = str(event.get("record_id") or "")
        defer_token = str(event.get("defer_token") or "")
        timestamp = str(event.get("timestamp") or utc_now_iso())
        tool_name = str(event.get("tool_name") or "")
        operation = str(event.get("operation") or "")
        rule_id = str(event.get("rule_id") or "")
        args = event.get("args") if isinstance(event.get("args"), dict) else {}

        split_tool, split_op = _split_tool_id(tool_id)
        if not tool_name:
            tool_name = split_tool
        if not operation:
            operation = split_op

        linkage = self._fetch_dpr_linkage(record_id) if record_id else {}

        with self._lock:
            shadow_id = self._find_recent_audit_shadow_call(agent_id, tool_id, timestamp)
            if shadow_id:
                self._adopt_shadow_action(shadow_id, call_id)

            state = _decision_effect_to_state(effect)
            action = self._upsert_action(call_id, agent_id, tool_id)
            if session_id:
                action["session_id"] = session_id
            action["decision_effect"] = effect
            action["state"] = state
            action["reason_code"] = reason_code or str(linkage.get("reason_code") or action.get("reason_code") or "")
            action["reason"] = reason or str(linkage.get("reason") or action.get("reason") or "")
            action["updated_at"] = timestamp
            action["record_id"] = record_id
            action["tool_name"] = tool_name
            action["operation"] = operation
            action["rule_id"] = rule_id or str(action.get("rule_id") or "")
            if linkage:
                action["record_hash"] = str(linkage.get("record_hash") or "")
                action["prev_record_hash"] = str(linkage.get("prev_record_hash") or "")
                action["incident_category"] = str(linkage.get("incident_category") or action.get("incident_category") or "")
                action["incident_severity"] = str(linkage.get("incident_severity") or action.get("incident_severity") or "")
                action["policy_version"] = str(linkage.get("policy_version") or action.get("policy_version") or "")

            action["blast_radius"] = str(event.get("blast_radius") or action.get("blast_radius") or "")
            action["reversibility"] = str(event.get("reversibility") or action.get("reversibility") or "")
            action["incident_category"] = str(event.get("incident_category") or action.get("incident_category") or "")
            action["incident_severity"] = str(event.get("incident_severity") or action.get("incident_severity") or "")
            action["policy_version"] = str(event.get("policy_version") or action.get("policy_version") or "")
            action["principal_id"] = str(event.get("principal_id") or action.get("principal_id") or "")
            action["principal_method"] = str(event.get("principal_method") or action.get("principal_method") or "")
            if isinstance(args, dict) and args:
                action["params"] = args

            if defer_token:
                action["defer_token"] = defer_token
                self._token_index[defer_token] = call_id

            self._append_timeline(
                action,
                {
                    "source": "callback",
                    "state": state,
                    "effect": effect,
                    "reason_code": action.get("reason_code") or "",
                    "reason": action.get("reason") or "",
                    "timestamp": timestamp,
                    "record_id": record_id,
                    "record_hash": action.get("record_hash") or "",
                    "prev_record_hash": action.get("prev_record_hash") or "",
                    "defer_token": defer_token,
                    "args": action.get("params") or {},
                },
            )
            self._persist_action(action)
            self._enforce_retention()

    def _ingest_callback_defer_resolved(self, event: dict[str, Any]) -> None:
        defer_token = str(event.get("defer_token") or "").strip()
        if not defer_token:
            return

        status = str(event.get("status") or "").lower()
        state = _defer_status_to_state(status)
        timestamp = str(event.get("timestamp") or utc_now_iso())
        reason = str(event.get("reason") or "")

        with self._lock:
            call_id = self._token_index.get(defer_token)
            if not call_id:
                call_id = f"defer::{defer_token}"

            agent_id = str(event.get("agent_id") or "")
            action = self._upsert_action(call_id, agent_id, "")
            action["state"] = state
            action["updated_at"] = timestamp
            action["defer_token"] = defer_token
            if reason:
                action["reason"] = reason

            self._append_timeline(
                action,
                {
                    "source": "callback",
                    "state": state,
                    "effect": status.upper(),
                    "reason_code": "",
                    "reason": reason,
                    "timestamp": timestamp,
                    "defer_token": defer_token,
                },
            )
            self._persist_action(action)
            self._enforce_retention()

    def _find_recent_call(self, agent_id: str, tool_id: str) -> str:
        if not agent_id or not tool_id:
            return ""
        candidates = [
            action
            for action in self._actions.values()
            if action.get("agent_id") == agent_id and action.get("tool_id") == tool_id
        ]
        if not candidates:
            return ""
        candidates.sort(key=lambda item: parse_timestamp(str(item.get("updated_at") or "")), reverse=True)
        return str(candidates[0].get("call_id") or "")

    def _find_recent_audit_shadow_call(self, agent_id: str, tool_id: str, timestamp: str) -> str:
        target_ts = parse_timestamp(timestamp)
        best_id = ""
        best_delta = float("inf")
        for call_id, action in self._actions.items():
            if not str(call_id).startswith("audit::"):
                continue
            if str(action.get("agent_id") or "") != agent_id:
                continue
            if str(action.get("tool_id") or "") != tool_id:
                continue
            action_ts = parse_timestamp(str(action.get("updated_at") or ""))
            delta = abs((target_ts - action_ts).total_seconds())
            if delta <= 5.0 and delta < best_delta:
                best_delta = delta
                best_id = call_id
        return best_id

    def _adopt_shadow_action(self, shadow_id: str, real_call_id: str) -> None:
        if not shadow_id or shadow_id == real_call_id:
            return
        shadow = self._actions.pop(shadow_id, None)
        if shadow is None:
            return

        target = self._actions.get(real_call_id)
        if target is None:
            shadow["call_id"] = real_call_id
            self._actions[real_call_id] = shadow
            token = str(shadow.get("defer_token") or "")
            if token and self._token_index.get(token) == shadow_id:
                self._token_index[token] = real_call_id
            self._delete_state_action(shadow_id)
            self._persist_action(shadow)
            return

        target_timeline = target.setdefault("timeline", [])
        target_timeline.extend([dict(item) for item in shadow.get("timeline", [])])
        target_timeline.sort(key=lambda item: parse_timestamp(str(item.get("timestamp") or "")))

        for key in (
            "session_id",
            "reason",
            "reason_code",
            "record_id",
            "record_hash",
            "prev_record_hash",
            "defer_token",
            "tool_name",
            "operation",
            "blast_radius",
            "reversibility",
            "incident_category",
            "incident_severity",
            "policy_version",
            "principal_id",
            "principal_method",
        ):
            if not target.get(key) and shadow.get(key):
                target[key] = shadow[key]

        target_ts = parse_timestamp(str(target.get("updated_at") or ""))
        shadow_ts = parse_timestamp(str(shadow.get("updated_at") or ""))
        if shadow_ts > target_ts:
            target["updated_at"] = shadow.get("updated_at")

        self._delete_state_action(shadow_id)
        self._persist_action(target)

    def _upsert_action(self, call_id: str, agent_id: str, tool_id: str) -> dict[str, Any]:
        tool_name, operation = _split_tool_id(tool_id)
        action = self._actions.get(call_id)
        if action is None:
            now = utc_now_iso()
            action = {
                "call_id": call_id,
                "agent_id": agent_id,
                "session_id": "",
                "tool_id": tool_id,
                "tool_name": tool_name,
                "operation": operation,
                "decision_effect": "",
                "reason_code": "",
                "reason": "",
                "rule_id": "",
                "state": "pending",
                "defer_token": "",
                "record_id": "",
                "record_hash": "",
                "prev_record_hash": "",
                "blast_radius": "",
                "reversibility": "",
                "incident_category": "",
                "incident_severity": "",
                "policy_version": "",
                "principal_id": "",
                "principal_method": "",
                "params": {},
                "created_at": now,
                "updated_at": now,
                "timeline": [],
            }
            self._actions[call_id] = action
        else:
            if agent_id:
                action["agent_id"] = agent_id
            if tool_id:
                action["tool_id"] = tool_id
                action["tool_name"] = tool_name
                action["operation"] = operation
        return action

    def _append_timeline(self, action: dict[str, Any], event: dict[str, Any]) -> None:
        timeline = action.setdefault("timeline", [])
        timeline.append(
            {
                "source": str(event.get("source") or ""),
                "state": str(event.get("state") or ""),
                "effect": str(event.get("effect") or ""),
                "reason_code": str(event.get("reason_code") or ""),
                "reason": str(event.get("reason") or ""),
                "timestamp": str(event.get("timestamp") or utc_now_iso()),
                "record_id": str(event.get("record_id") or ""),
                "record_hash": str(event.get("record_hash") or ""),
                "prev_record_hash": str(event.get("prev_record_hash") or ""),
                "defer_token": str(event.get("defer_token") or ""),
                "args": event.get("args") if isinstance(event.get("args"), dict) else {},
            }
        )
        timeline.sort(key=lambda item: parse_timestamp(str(item.get("timestamp") or "")))

    def _clone_action(self, action: dict[str, Any]) -> dict[str, Any]:
        cloned = dict(action)
        cloned["timeline"] = [dict(item) for item in action.get("timeline", [])]
        if isinstance(cloned.get("params"), dict):
            cloned["params"] = dict(cloned["params"])
        return cloned

    def _fetch_dpr_linkage(self, record_id: str) -> dict[str, str]:
        if not record_id or not self._dpr_db_path.exists():
            return {}

        columns = self._dpr_table_columns()
        if not columns:
            return {}

        wanted = [
            "record_hash",
            "prev_record_hash",
            "reason_code",
            "reason",
            "created_at",
            "incident_category",
            "incident_severity",
            "policy_version",
            "credential_scope",
            "args_structural_sig",
        ]
        present = [name for name in wanted if name in columns]
        if not present:
            return {}

        query = f"SELECT {', '.join(present)} FROM dpr_records WHERE record_id = ? LIMIT 1"
        try:
            conn = sqlite3.connect(self._dpr_db_path)
            try:
                row = conn.execute(query, (record_id,)).fetchone()
            finally:
                conn.close()
        except sqlite3.Error:
            return {}

        if row is None:
            return {}

        out: dict[str, str] = {}
        for idx, key in enumerate(present):
            out[key] = str(row[idx] or "")
        return out

    def _dpr_table_columns(self) -> set[str]:
        if self._dpr_columns is not None:
            return self._dpr_columns
        if not self._dpr_db_path.exists():
            self._dpr_columns = set()
            return self._dpr_columns

        try:
            conn = sqlite3.connect(self._dpr_db_path)
            try:
                rows = conn.execute("PRAGMA table_info(dpr_records)").fetchall()
            finally:
                conn.close()
        except sqlite3.Error:
            self._dpr_columns = set()
            return self._dpr_columns

        self._dpr_columns = {str(row[1]) for row in rows if len(row) >= 2}
        return self._dpr_columns

    def _enforce_retention(self) -> None:
        if len(self._actions) <= self._max_actions:
            return

        ordered = sorted(
            self._actions.values(),
            key=lambda action: parse_timestamp(str(action.get("updated_at") or "")),
        )
        to_remove = len(self._actions) - self._max_actions
        for idx in range(to_remove):
            candidate = ordered[idx]
            call_id = str(candidate.get("call_id") or "")
            if not call_id:
                continue
            removed = self._actions.pop(call_id, None)
            if removed is None:
                continue
            token = str(removed.get("defer_token") or "")
            if token and self._token_index.get(token) == call_id:
                del self._token_index[token]
            self._delete_state_action(call_id)

    def _init_state_db(self) -> None:
        if self._state_db_path is None:
            return
        self._state_db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._state_db_path)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS visibility_actions (
                    call_id TEXT PRIMARY KEY,
                    updated_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_visibility_actions_updated_at ON visibility_actions(updated_at DESC)"
            )
            conn.commit()
        finally:
            conn.close()

    def _load_state_db(self) -> None:
        if self._state_db_path is None or not self._state_db_path.exists():
            return
        conn = sqlite3.connect(self._state_db_path)
        try:
            rows = conn.execute(
                "SELECT payload_json FROM visibility_actions ORDER BY updated_at DESC"
            ).fetchall()
        finally:
            conn.close()

        with self._lock:
            for (payload,) in rows:
                try:
                    action = json.loads(payload)
                except Exception:
                    continue
                call_id = str(action.get("call_id") or "").strip()
                if not call_id:
                    continue
                self._actions[call_id] = action
                token = str(action.get("defer_token") or "")
                if token:
                    self._token_index[token] = call_id

    def _persist_action(self, action: dict[str, Any]) -> None:
        if self._state_db_path is None:
            return
        call_id = str(action.get("call_id") or "").strip()
        if not call_id:
            return

        payload = json.dumps(action, separators=(",", ":"), sort_keys=True)
        updated_at = str(action.get("updated_at") or utc_now_iso())

        conn = sqlite3.connect(self._state_db_path)
        try:
            conn.execute(
                """
                INSERT INTO visibility_actions(call_id, updated_at, payload_json)
                VALUES(?, ?, ?)
                ON CONFLICT(call_id) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    payload_json=excluded.payload_json
                """,
                (call_id, updated_at, payload),
            )
            conn.commit()
        finally:
            conn.close()

    def _delete_state_action(self, call_id: str) -> None:
        if self._state_db_path is None:
            return
        conn = sqlite3.connect(self._state_db_path)
        try:
            conn.execute("DELETE FROM visibility_actions WHERE call_id = ?", (call_id,))
            conn.commit()
        finally:
            conn.close()


def _derive_risk_level(blast_radius: str, incident_severity: str) -> str:
    sev = (incident_severity or "").strip().lower()
    blast = (blast_radius or "").strip().lower()
    if sev in {"critical", "high"}:
        return "high"
    if blast in {"system", "external"}:
        return "high"
    if sev in {"medium"}:
        return "medium"
    if blast in {"scoped", "local"}:
        return "medium"
    return "low"


def _plain_reason_from_code(reason_code: str) -> str:
    code = (reason_code or "").strip().upper()
    mapping = {
        "RULE_DENY": "Blocked by policy rule.",
        "RULE_PERMIT": "Allowed by policy rule.",
        "RULE_DEFER": "Requires human approval before execution.",
        "POLICY_DENY": "Denied by policy.",
        "CALLBACK_ERROR": "Denied because callback enforcement failed.",
        "WAL_WRITE_FAILURE": "Denied because audit write failed (fail-closed).",
        "IDENTITY_UNVERIFIED": "Denied because identity verification failed.",
        "PRINCIPAL_REVOKED": "Denied because principal identity is revoked.",
    }
    if code in mapping:
        return mapping[code]
    if not code:
        return ""
    return f"Policy decision: {code}."


def _redacted_mapping_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    keys = sorted(str(key) for key in value.keys())
    if not keys:
        return {}
    return {
        "redacted": True,
        "key_count": len(keys),
        "keys": keys,
    }


def _redact_timeline_event(event: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(event)
    redacted["defer_token"] = ""
    redacted["args"] = _redacted_mapping_summary(event.get("args"))
    return redacted
