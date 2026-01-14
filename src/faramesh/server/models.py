# server/models.py
# Action schema
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class DecisionOutcome(str, Enum):
    """Explicit decision outcomes for execution gate."""
    EXECUTE = "EXECUTE"
    ABSTAIN = "ABSTAIN"
    HALT = "HALT"


# Reason codes for decisions
REASON_CODE_POLICY_ALLOW = "POLICY_ALLOW"
REASON_CODE_POLICY_DENY = "POLICY_DENY"
REASON_CODE_POLICY_REQUIRE_APPROVAL = "POLICY_REQUIRE_APPROVAL"
REASON_CODE_RISK_UPGRADE = "RISK_UPGRADE"
REASON_CODE_DEFAULT_DENY_NO_MATCH = "DEFAULT_DENY_NO_MATCH"
REASON_CODE_PROFILE_DISALLOWS_TOOL = "PROFILE_DISALLOWS_TOOL"
REASON_CODE_PROFILE_RULE_DENY = "PROFILE_RULE_DENY"
REASON_CODE_PROFILE_MISSING_REQUIRED_CONTROL = "PROFILE_MISSING_REQUIRED_CONTROL"
REASON_CODE_INTERNAL_ERROR = "INTERNAL_ERROR"
REASON_CODE_MISSING_POLICY = "MISSING_POLICY"
REASON_CODE_PROFILE_LOAD_ERROR = "PROFILE_LOAD_ERROR"


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
    version: int = 1  # Optimistic locking version
    # Execution gate fields
    outcome: Optional[DecisionOutcome] = None
    reason_code: Optional[str] = None
    reason_details: Optional[Dict[str, Any]] = None
    request_hash: Optional[str] = None
    policy_hash: Optional[str] = None
    runtime_version: Optional[str] = None
    profile_id: Optional[str] = None
    profile_version: Optional[str] = None
    profile_hash: Optional[str] = None
    provenance_id: Optional[str] = None

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
            version=1,
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
            "version": self.version,
            "created_at": self.created_at.isoformat() + "Z",
            "updated_at": self.updated_at.isoformat() + "Z",
            "outcome": self.outcome.value if self.outcome else None,
            "reason_code": self.reason_code,
            "reason_details": self.reason_details,
            "request_hash": self.request_hash,
            "policy_hash": self.policy_hash,
            "runtime_version": self.runtime_version,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "profile_hash": self.profile_hash,
            "provenance_id": self.provenance_id,
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
        
        # Safe JSON parsing with error handling
        def _safe_json_loads(value, default=None):
            if value is None:
                return default if default is not None else {}
            try:
                return json.loads(value) if isinstance(value, str) else value
            except (json.JSONDecodeError, TypeError) as e:
                # Log error but return safe default
                import logging
                logging.warning(f"Failed to parse JSON in from_row: {e}, using default")
                return default if default is not None else {}
        
        # Safe datetime parsing with error handling
        def _safe_datetime_parse(value, default=None):
            if value is None:
                return default if default is not None else datetime.utcnow()
            try:
                return datetime.fromisoformat(value)
            except (ValueError, TypeError) as e:
                import logging
                logging.warning(f"Failed to parse datetime in from_row: {e}, using default")
                return default if default is not None else datetime.utcnow()
        
        # Safe enum parsing with error handling
        def _safe_enum_parse(enum_class, value, default=None):
            if value is None:
                return default
            try:
                return enum_class(value)
            except ValueError:
                import logging
                logging.warning(f"Invalid {enum_class.__name__} value: {value}, using default")
                return default
        
        return Action(
            id=_get(row, "id", ""),
            agent_id=_get(row, "agent_id", ""),
            tool=_get(row, "tool", ""),
            operation=_get(row, "operation", ""),
            params=_safe_json_loads(_get(row, "params_json"), {}),
            context=_safe_json_loads(_get(row, "context_json"), {}),
            decision=_safe_enum_parse(Decision, _get(row, "decision"), None),
            status=_safe_enum_parse(Status, _get(row, "status"), Status.PENDING_DECISION),
            reason=_get(row, "reason"),
            risk_level=_get(row, "risk_level"),
            created_at=_safe_datetime_parse(_get(row, "created_at")),
            updated_at=_safe_datetime_parse(_get(row, "updated_at")),
            approval_token=_get(row, "approval_token"),
            policy_version=_get(row, "policy_version"),
            tenant_id=_get(row, "tenant_id"),
            project_id=_get(row, "project_id"),
            version=_get(row, "version", 1),
            outcome=_safe_enum_parse(DecisionOutcome, _get(row, "outcome"), None),
            reason_code=_get(row, "reason_code"),
            reason_details=_safe_json_loads(_get(row, "reason_details_json"), None),
            request_hash=_get(row, "request_hash"),
            policy_hash=_get(row, "policy_hash"),
            runtime_version=_get(row, "runtime_version"),
            profile_id=_get(row, "profile_id"),
            profile_version=_get(row, "profile_version"),
            profile_hash=_get(row, "profile_hash"),
            provenance_id=_get(row, "provenance_id"),
        )
