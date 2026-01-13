# server/models.py
# Action schema
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional
from datetime import datetime
import uuid
import json


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class Status(str, Enum):
    PENDING_DECISION = "pending_decision"
    ALLOWED = "allowed"
    DENIED = "denied"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"

@dataclass
class Action:
    id: str
    agent_id: str
    tool: str
    operation: str
    params: Dict[str, Any]
    context: Dict[str, Any]
    decision: Optional[Decision]
    status: Status
    reason: Optional[str]
    risk_level: Optional[str]
    created_at: datetime
    updated_at: datetime
    approval_token: Optional[str]  # simple magic link token
    policy_version: Optional[str] = None
    # tenant_id and project_id kept as optional for compatibility but ignored in core
    tenant_id: Optional[str] = None
    project_id: Optional[str] = None

    @staticmethod
    def new(
        agent_id: str,
        tool: str,
        operation: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> "Action":
        now = datetime.utcnow()
        return Action(
            id=str(uuid.uuid4()),
            agent_id=agent_id,
            tool=tool,
            operation=operation,
            params=params,
            context=context or {},
            decision=None,
            status=Status.PENDING_DECISION,
            reason=None,
            risk_level=None,
            created_at=now,
            updated_at=now,
            approval_token=None,
            tenant_id=tenant_id,
            project_id=project_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "operation": self.operation,
            "params": self.params,
            "context": self.context,
            "decision": self.decision.value if self.decision else None,
            "status": self.status.value,
            "reason": self.reason,
            "risk_level": self.risk_level,
            "policy_version": self.policy_version,
            "tenant_id": self.tenant_id,
            "project_id": self.project_id,
            "created_at": self.created_at.isoformat() + "Z",
            "updated_at": self.updated_at.isoformat() + "Z",
        }

    @staticmethod
    def from_row(row) -> "Action":
        # Helper to safely get optional fields (works with both dict and sqlite3.Row)
        def _get(row, key, default=None):
            if hasattr(row, 'get'):
                return row.get(key, default)
            try:
                # sqlite3.Row supports 'in' operator and indexing
                if key in row.keys():
                    return row[key]
                return default
            except (KeyError, IndexError, TypeError):
                return default
        
        return Action(
            id=row["id"],
            agent_id=row["agent_id"],
            tool=row["tool"],
            operation=row["operation"],
            params=json.loads(row["params_json"]),
            context=json.loads(row["context_json"]),
            decision=Decision(row["decision"]) if row["decision"] else None,
            status=Status(row["status"]),
            reason=_get(row, "reason"),
            risk_level=_get(row, "risk_level"),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            approval_token=_get(row, "approval_token"),
            policy_version=_get(row, "policy_version"),
            tenant_id=_get(row, "tenant_id"),
            project_id=_get(row, "project_id"),
        )
