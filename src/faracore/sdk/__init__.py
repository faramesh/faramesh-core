"""FaraCore Python SDK - Production-ready client for the FaraCore Execution Governor API.

Quick Start:
    >>> from faracore import configure, submit_action, approve_action
    >>> configure(base_url="http://localhost:8000", token="dev-token")
    >>> action = submit_action("my-agent", "http", "get", {"url": "https://example.com"})
    >>> print(f"Action {action['id']} status: {action['status']}")
"""

from .client import (
    # Configuration
    configure,
    ClientConfig,
    
    # Core functions
    submit_action,
    submit_actions,
    submit_actions_bulk,
    submit_and_wait,
    block_until_approved,
    get_action,
    list_actions,
    approve_action,
    deny_action,
    start_action,
    replay_action,
    wait_for_completion,
    apply,
    tail_events,
    stream_events,
    
    # Convenience aliases
    allow,
    deny,
    
    # Exceptions
    FaraCoreError,
    FaraCoreAuthError,
    FaraCoreNotFoundError,
    FaraCorePolicyError,
    FaraCoreTimeoutError,
    FaraCoreConnectionError,
    FaraCoreValidationError,
    FaraCoreServerError,
    FaraCoreBatchError,
    FaraCoreDeniedError,
    
    # Legacy class-based API (for backward compatibility)
    ExecutionGovernorClient,
    GovernorConfig,
    GovernorError,
    GovernorTimeoutError,
    GovernorAuthError,
    GovernorConnectionError,
)

# Import new modules
from .governed_tool import governed_tool
from .snapshot import ActionSnapshotStore, get_default_store
from .policy_helpers import validate_policy_file, test_policy_against_action

# Import version
from .client import __version__

# Import policy models
from .policy import (
    Policy,
    PolicyRule,
    MatchCondition,
    RiskRule,
    RiskLevel,
    create_policy,
)

__all__ = [
    # Configuration
    "configure",
    "ClientConfig",
    
    # Core functions
    "submit_action",
    "submit_actions",
    "submit_actions_bulk",
    "submit_and_wait",
    "block_until_approved",
    "get_action",
    "list_actions",
    "approve_action",
    "deny_action",
    "start_action",
    "replay_action",
    "wait_for_completion",
    "apply",
    "tail_events",
    "stream_events",
    
    # Convenience aliases
    "allow",
    "deny",
    
    # Policy models
    "Policy",
    "PolicyRule",
    "MatchCondition",
    "RiskRule",
    "RiskLevel",
    "create_policy",
    
    # Policy helpers
    "validate_policy_file",
    "test_policy_against_action",
    
    # Decorators
    "governed_tool",
    
    # Utilities
    "ActionSnapshotStore",
    "get_default_store",
    
    # Exceptions
    "FaraCoreError",
    "FaraCoreAuthError",
    "FaraCoreNotFoundError",
    "FaraCorePolicyError",
    "FaraCoreTimeoutError",
    "FaraCoreConnectionError",
    "FaraCoreValidationError",
    "FaraCoreServerError",
    "FaraCoreBatchError",
    "FaraCoreDeniedError",
    
    # Legacy API
    "ExecutionGovernorClient",
    "GovernorConfig",
    "GovernorError",
    "GovernorTimeoutError",
    "GovernorAuthError",
    "GovernorConnectionError",
    
    # Version
    "__version__",
]
