"""Local governance gate helper: `govern()` raises on deny/defer instead of returning."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .client import DeferredError, DenyError, FarameshError
from .gate import GateDecision, gate_decide


def govern(
    agent_id: str,
    tool: str,
    operation: str,
    params: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> GateDecision:
    """Call gate/decide and return only when execution would be allowed.

    - **EXECUTE** / **PERMIT**: returns :class:`GateDecision`.
    - **HALT** / **DENY**: raises :class:`DenyError`.
    - **ABSTAIN** / **DEFER** / **PENDING**: raises :class:`DeferredError`.

    This is the thin client-side enforcement surface expected by agent integrations
    (see product TODO: ``govern()``, ``DenyError``, ``DeferredError``).
    """
    d = gate_decide(agent_id, tool, operation, params, context)
    o = (d.outcome or "").upper()
    if o in ("EXECUTE", "PERMIT"):
        return d
    if o in ("HALT", "DENY"):
        raise DenyError(
            f"governance denied: {d.reason_code or 'unknown'}",
            reason_code=d.reason_code or "",
            reason=d.reason,
            decision=d,
        )
    if o in ("ABSTAIN", "DEFER", "PENDING"):
        raise DeferredError(
            f"governance deferred: {d.reason_code or 'unknown'}",
            reason_code=d.reason_code or "",
            reason=d.reason,
            decision=d,
        )
    raise FarameshError(f"unexpected gate outcome: {d.outcome!r}")
