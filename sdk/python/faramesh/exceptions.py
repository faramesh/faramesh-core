"""Faramesh exception hierarchy."""


class FarameshError(Exception):
    """Base class for all Faramesh errors."""


class DenyError(FarameshError):
    """Raised when the governance policy denies a tool call.

    Attributes:
        rule_id: The ID of the rule that denied the call, or None for default deny.
        reason_code: Machine-readable denial reason code.
        reason: Human-readable denial explanation.
    """

    def __init__(self, tool_id: str, rule_id: str | None, reason_code: str, reason: str):
        self.tool_id = tool_id
        self.rule_id = rule_id
        self.reason_code = reason_code
        self.reason = reason
        super().__init__(
            f"DENY  {tool_id}  rule={rule_id or 'default'}  reason={reason}"
        )


class DeferredError(FarameshError):
    """Raised when a tool call is deferred pending human approval.

    The SDK blocks waiting for resolution. This exception is only raised
    if the DEFER times out or is explicitly denied by the approver.

    Attributes:
        tool_id: The tool that was deferred.
        defer_token: The token to use for approval via `faramesh agent approve`.
        reason: Why the call was deferred.
    """

    def __init__(self, tool_id: str, defer_token: str, reason: str, expired: bool = False):
        self.tool_id = tool_id
        self.defer_token = defer_token
        self.reason = reason
        self.expired = expired
        if expired:
            msg = f"DEFER expired  {tool_id}  token={defer_token}  Approve: faramesh agent approve {defer_token}"
        else:
            msg = f"DEFER denied  {tool_id}  token={defer_token}"
        super().__init__(msg)


class DaemonError(FarameshError):
    """Raised when the faramesh daemon cannot be started or contacted."""
