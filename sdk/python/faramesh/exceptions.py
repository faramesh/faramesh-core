"""Structured denial exceptions for adapter integrations."""

from __future__ import annotations

from typing import Any, Dict, Optional


class ToolDeniedException(Exception):
    """Raised when the daemon denies or defers a governed tool call."""

    def __init__(
        self,
        message: str = "",
        *,
        code: str = "",
        rule_id: str = "",
        rule_ref: str = "",
        human_message: str = "",
        resolution: Optional[Dict[str, Any]] = None,
        structured_denial: Optional[Dict[str, Any]] = None,
        effect: str = "",
        defer_token: str = "",
    ) -> None:
        payload = structured_denial or {}
        self.code = code or str(payload.get("code", ""))
        self.rule_id = rule_id or str(payload.get("rule_id", ""))
        self.rule_ref = rule_ref or str(payload.get("rule_ref", ""))
        self.human_message = human_message or str(payload.get("human_message", message))
        res = resolution if resolution is not None else payload.get("resolution")
        self.resolution: Dict[str, Any] = dict(res) if isinstance(res, dict) else {}
        self.effect = effect
        self.defer_token = defer_token
        self.approval_id = str(self.resolution.get("approval_id", "") or "")
        msg = self.human_message or message or self.code or "tool call denied"
        super().__init__(msg)

    @classmethod
    def from_govern_result(cls, result: Dict[str, Any]) -> "ToolDeniedException":
        denial = result.get("structured_denial")
        if not isinstance(denial, dict):
            denial = {}
        return cls(
            human_message=str(denial.get("human_message", result.get("reason_code", ""))),
            code=str(denial.get("code", result.get("reason_code", ""))),
            rule_id=str(denial.get("rule_id", "")),
            rule_ref=str(denial.get("rule_ref", "")),
            resolution=denial.get("resolution") if isinstance(denial.get("resolution"), dict) else None,
            structured_denial=denial,
            effect=str(result.get("effect", "")),
            defer_token=str(result.get("defer_token", "")),
        )
