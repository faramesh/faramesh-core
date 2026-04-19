"""Faramesh Python SDK - Production-ready client for the Faramesh Execution Governor API.

This SDK provides a complete interface to interact with Faramesh, including:
- Submitting actions for governance evaluation
- Batch submission of multiple actions
- Submit and wait for completion (with auto-approval)
- Approving/denying pending actions
- Starting action execution
- Replaying actions
- Listing and querying action history
- Streaming events via SSE
- Loading actions from YAML/JSON files
- Typed policy objects for client-side policy building

Example usage:
    >>> from faramesh import configure, submit_action, submit_and_wait, approve_action
    >>> configure(base_url="http://localhost:8000", token="dev-token")
    >>>
    >>> # Simple submit
    >>> action = submit_action("test-agent", "http", "get", {"url": "https://example.com"})
    >>>
    >>> # Submit and wait (with auto-approval)
    >>> final = submit_and_wait("agent", "http", "get", {"url": "https://example.com"}, auto_approve=True)
    >>>
    >>> # Batch submit
    >>> actions = submit_actions([{...}, {...}])
"""

# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
import json
import time
import warnings
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Union, Callable
from pathlib import Path
from urllib.parse import urlparse
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError as RequestsConnectionError

try:
    import yaml
except ImportError:
    yaml = None  # Optional dependency


__version__ = "0.3.2"


# Global configuration
_config: Optional[ClientConfig] = None


@dataclass
class ClientConfig:
    """Configuration for the Faramesh SDK client."""
    base_url: str = "http://127.0.0.1:8000"
    agent_id: str = "default-agent"
    token: Optional[str] = None
    timeout: float = 30.0
    max_retries: int = 3
    retry_backoff_factor: float = 0.5
    # Telemetry callbacks
    on_request_start: Optional[Callable[[str, str], None]] = None  # (method, url)
    on_request_end: Optional[Callable[[str, str, int, float], None]] = None  # (method, url, status_code, duration_ms)
    on_error: Optional[Callable[[Exception], None]] = None  # (error)

    def __post_init__(self):
        """Normalize base_url and load from env if not set."""
        self.base_url = self.base_url.rstrip("/")
        if not self.token:
            # Check FARAMESH_TOKEN first, then legacy FARA_AUTH_TOKEN for backward compatibility
            self.token = os.getenv("FARAMESH_TOKEN") or os.getenv("FARA_AUTH_TOKEN")
        if self.base_url == "http://127.0.0.1:8000":
            # Allow override via env (check FARAMESH_BASE_URL first, then legacy FARA_API_BASE)
            env_url = os.getenv("FARAMESH_BASE_URL") or os.getenv("FARA_API_BASE")
            if env_url:
                self.base_url = env_url.rstrip("/")
        parsed = urlparse(self.base_url)
        if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
            warnings.warn(
                f"Faramesh base_url uses plain HTTP with non-localhost host ({parsed.hostname}). "
                "Use https:// in production to protect governance decisions and credentials in transit.",
                stacklevel=2,
            )
        # Load retry config from env
        if self.max_retries == 3:
            retries_env = os.getenv("FARAMESH_RETRIES")
            if retries_env:
                try:
                    self.max_retries = int(retries_env)
                except ValueError:
                    pass
        if self.retry_backoff_factor == 0.5:
            backoff_env = os.getenv("FARAMESH_RETRY_BACKOFF")
            if backoff_env:
                try:
                    self.retry_backoff_factor = float(backoff_env)
                except ValueError:
                    pass


class FarameshError(Exception):
    """Base exception for all Faramesh SDK errors."""
    pass


class FarameshAuthError(FarameshError):
    """Raised when authentication fails (401)."""
    pass


class FarameshNotFoundError(FarameshError):
    """Raised when a resource is not found (404)."""
    pass


class FarameshPolicyError(FarameshError):
    """Raised when an action is denied by policy."""
    pass


class FarameshTimeoutError(FarameshError):
    """Raised when a request times out."""
    pass


class FarameshConnectionError(FarameshError):
    """Raised when connection to server fails."""
    pass


class FarameshValidationError(FarameshError):
    """Raised when request validation fails (422)."""
    pass


class FarameshServerError(FarameshError):
    """Raised when server returns 5xx error."""
    pass


class FarameshBatchError(FarameshError):
    """Raised when batch operation has errors and raise_on_error=True."""
    def __init__(self, message: str, successes: List[Dict[str, Any]], errors: List[Dict[str, Any]]):
        super().__init__(message)
        self.successes = successes
        self.errors = errors


class FarameshDeniedError(FarameshError):
    """Raised when an action is denied and helper expects success."""
    pass


class DenyError(FarameshDeniedError):
    """Raised by :func:`faramesh.govern.govern` when the gate denies execution."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str = "",
        reason: Optional[str] = None,
        decision: Optional[Any] = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.reason = reason
        self.decision = decision


class DeferredError(FarameshError):
    """Raised by :func:`faramesh.govern.govern` when the gate defers (human-in-the-loop)."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str = "",
        reason: Optional[str] = None,
        decision: Optional[Any] = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.reason = reason
        self.decision = decision


def configure(
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    timeout: Optional[float] = None,
    max_retries: Optional[int] = None,
    retry_backoff_factor: Optional[float] = None,
    on_request_start: Optional[Callable[[str, str], None]] = None,
    on_request_end: Optional[Callable[[str, str, int, float], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
) -> None:
    """Configure the global SDK client.

    Args:
        base_url: Base URL of the Faramesh server (default: http://127.0.0.1:8000)
        token: Authentication token (can also be set via FARAMESH_TOKEN env var)
        timeout: Request timeout in seconds (default: 30.0)
        max_retries: Maximum number of retries for failed requests (default: 3)
        retry_backoff_factor: Backoff factor for retries (default: 0.5)
        on_request_start: Callback called before each request (method, url)
        on_request_end: Callback called after each request (method, url, status_code, duration_ms)
        on_error: Callback called on errors (error)

    Example:
        >>> configure(base_url="http://localhost:8000", token="my-token")
        >>>
        >>> # With telemetry callbacks
        >>> def on_start(method, url):
        ...     print(f"Starting {method} {url}")
        >>> configure(on_request_start=on_start)
    """
    global _config
    existing_config = _get_config() if _config else None
    _config = ClientConfig(
        base_url=base_url or os.getenv("FARAMESH_BASE_URL") or os.getenv("FARA_API_BASE") or "http://127.0.0.1:8000",
        token=token,
        timeout=timeout or 30.0,
        max_retries=max_retries or 3,
        retry_backoff_factor=retry_backoff_factor or 0.5,
        on_request_start=on_request_start or (existing_config.on_request_start if existing_config else None),
        on_request_end=on_request_end or (existing_config.on_request_end if existing_config else None),
        on_error=on_error or (existing_config.on_error if existing_config else None),
    )


def _get_config() -> ClientConfig:
    """Get the current configuration, initializing if needed."""
    global _config
    if _config is None:
        _config = ClientConfig()
    return _config


def _make_request(
    method: str,
    path: str,
    json_data: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Make an HTTP request to the Faramesh API with retry logic.

    Args:
        method: HTTP method (GET, POST, etc.)
        path: API path (e.g., "/v1/actions")
        json_data: JSON body for POST/PUT requests
        params: Query parameters for GET requests

    Returns:
        Parsed JSON response as dict

    Raises:
        FarameshAuthError: On 401 authentication failure
        FarameshNotFoundError: On 404 not found
        FarameshPolicyError: On policy denial
        FarameshValidationError: On 422 validation error
        FarameshTimeoutError: On timeout
        FarameshConnectionError: On connection failure
        FarameshServerError: On 5xx server errors
    """
    config = _get_config()
    url = f"{config.base_url}/{path.lstrip('/')}"
    headers = {"Content-Type": "application/json"}

    if config.token:
        headers["Authorization"] = f"Bearer {config.token}"

    session = requests.Session()
    last_exception = None

    # Call telemetry callback
    if config.on_request_start:
        try:
            config.on_request_start(method, url)
        except Exception:
            pass  # Don't fail on callback errors

    start_time = time.time()

    for attempt in range(config.max_retries + 1):
        try:
            response = session.request(
                method=method,
                url=url,
                json=json_data,
                params=params,
                headers=headers,
                timeout=config.timeout,
            )

            duration_ms = (time.time() - start_time) * 1000

            # Handle specific status codes
            if response.status_code == 401:
                error_msg = f"Authentication failed (401) on {path}: {response.text}"
                error = FarameshAuthError(error_msg)
                if config.on_error:
                    try:
                        config.on_error(error)
                    except Exception:
                        pass
                if config.on_request_end:
                    try:
                        config.on_request_end(method, url, 401, duration_ms)
                    except Exception:
                        pass
                raise error
            elif response.status_code == 404:
                error_msg = f"Resource not found (404) on {path}"
                error = FarameshNotFoundError(error_msg)
                if config.on_error:
                    try:
                        config.on_error(error)
                    except Exception:
                        pass
                if config.on_request_end:
                    try:
                        config.on_request_end(method, url, 404, duration_ms)
                    except Exception:
                        pass
                raise error
            elif response.status_code == 422:
                try:
                    error_detail = response.json()
                    detail_msg = error_detail.get("detail", response.text)
                    error_msg = f"Validation error (422) on {path}: {detail_msg}"
                except:
                    error_msg = f"Validation error (422) on {path}: {response.text}"
                error = FarameshValidationError(error_msg)
                if config.on_error:
                    try:
                        config.on_error(error)
                    except Exception:
                        pass
                if config.on_request_end:
                    try:
                        config.on_request_end(method, url, 422, duration_ms)
                    except Exception:
                        pass
                raise error
            elif response.status_code >= 500:
                error_msg = f"Server error ({response.status_code}) on {path}: {response.text}"
                error = FarameshServerError(error_msg)
                # Retry on 5xx errors
                if attempt < config.max_retries:
                    if config.on_error:
                        try:
                            config.on_error(error)
                        except Exception:
                            pass
                    time.sleep(config.retry_backoff_factor * (2 ** attempt))
                    continue
                if config.on_request_end:
                    try:
                        config.on_request_end(method, url, response.status_code, duration_ms)
                    except Exception:
                        pass
                raise error

            # Check for policy denial in response body
            response.raise_for_status()
            data = response.json()

            # Check if action was denied (only for submit_action, not for other operations)
            # We allow denied actions to be returned for get_action, approve_action, etc.
            if isinstance(data, dict) and method == "POST" and path == "/v1/actions":
                if data.get("status") == "denied":
                    reason = data.get("reason", "Action denied by policy")
                    error = FarameshPolicyError(f"Action denied by policy: {reason}")
                    if config.on_error:
                        try:
                            config.on_error(error)
                        except Exception:
                            pass
                    if config.on_request_end:
                        try:
                            config.on_request_end(method, url, response.status_code, duration_ms)
                        except Exception:
                            pass
                    raise error
                if data.get("decision") == "deny" and data.get("status") != "pending_approval":
                    reason = data.get("reason", "Action denied by policy")
                    error = FarameshPolicyError(f"Action denied by policy: {reason}")
                    if config.on_error:
                        try:
                            config.on_error(error)
                        except Exception:
                            pass
                    if config.on_request_end:
                        try:
                            config.on_request_end(method, url, response.status_code, duration_ms)
                        except Exception:
                            pass
                    raise error

            # Call success telemetry callback
            if config.on_request_end:
                try:
                    config.on_request_end(method, url, response.status_code, duration_ms)
                except Exception:
                    pass

            return data

        except (FarameshAuthError, FarameshNotFoundError, FarameshPolicyError, FarameshValidationError, FarameshServerError):
            raise
        except Timeout as e:
            last_exception = FarameshTimeoutError(f"Request timed out after {config.timeout}s: {url}")
            if attempt < config.max_retries:
                if config.on_error:
                    try:
                        config.on_error(last_exception)
                    except Exception:
                        pass
                time.sleep(config.retry_backoff_factor * (2 ** attempt))
                continue
            if config.on_error:
                try:
                    config.on_error(last_exception)
                except Exception:
                    pass
            if config.on_request_end:
                try:
                    duration_ms = (time.time() - start_time) * 1000
                    config.on_request_end(method, url, 0, duration_ms)
                except Exception:
                    pass
            raise last_exception
        except RequestsConnectionError as e:
            last_exception = FarameshConnectionError(f"Failed to connect to {config.base_url}: {str(e)}")
            if attempt < config.max_retries:
                if config.on_error:
                    try:
                        config.on_error(last_exception)
                    except Exception:
                        pass
                time.sleep(config.retry_backoff_factor * (2 ** attempt))
                continue
            if config.on_error:
                try:
                    config.on_error(last_exception)
                except Exception:
                    pass
            if config.on_request_end:
                try:
                    duration_ms = (time.time() - start_time) * 1000
                    config.on_request_end(method, url, 0, duration_ms)
                except Exception:
                    pass
            raise last_exception
        except RequestException as e:
            # Check if it's a connection error wrapped in RequestException
            error_str = str(e).lower()
            if "connection" in error_str or "failed to resolve" in error_str or "name or service not known" in error_str:
                last_exception = FarameshConnectionError(f"Failed to connect to {config.base_url}: {str(e)}")
                if attempt < config.max_retries:
                    if config.on_error:
                        try:
                            config.on_error(last_exception)
                        except Exception:
                            pass
                    time.sleep(config.retry_backoff_factor * (2 ** attempt))
                    continue
                if config.on_error:
                    try:
                        config.on_error(last_exception)
                    except Exception:
                        pass
                if config.on_request_end:
                    try:
                        duration_ms = (time.time() - start_time) * 1000
                        config.on_request_end(method, url, 0, duration_ms)
                    except Exception:
                        pass
                raise last_exception
            # Retry on 5xx errors
            if attempt < config.max_retries and hasattr(e, 'response') and e.response is not None and e.response.status_code >= 500:
                if config.on_error:
                    try:
                        config.on_error(FarameshServerError(f"Server error: {str(e)}"))
                    except Exception:
                        pass
                time.sleep(config.retry_backoff_factor * (2 ** attempt))
                continue
            last_exception = FarameshError(f"Request failed on {path}: {str(e)}")
            if attempt == config.max_retries:
                if config.on_error:
                    try:
                        config.on_error(last_exception)
                    except Exception:
                        pass
                if config.on_request_end:
                    try:
                        duration_ms = (time.time() - start_time) * 1000
                        config.on_request_end(method, url, 0, duration_ms)
                    except Exception:
                        pass
                raise last_exception

    if last_exception:
        if config.on_error:
            try:
                config.on_error(last_exception)
            except Exception:
                pass
        if config.on_request_end:
            try:
                duration_ms = (time.time() - start_time) * 1000
                config.on_request_end(method, url, 0, duration_ms)
            except Exception:
                pass
        raise last_exception
    error = FarameshError(f"Request failed after {config.max_retries + 1} attempts on {path}")
    if config.on_error:
        try:
            config.on_error(error)
        except Exception:
            pass
    raise error


def submit_action(
    agent_id: str,
    tool: str,
    operation: str,
    params: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Submit an action for governance evaluation.

    Args:
        agent_id: Identifier for the agent submitting the action
        tool: Tool name (e.g., "shell", "http", "stripe")
        operation: Operation name (e.g., "run", "get", "create")
        params: Action parameters (default: {})
        context: Additional context (default: {})

    Returns:
        Action response dict with fields: id, status, decision, reason, risk_level, etc.

    Raises:
        FarameshPolicyError: If action is denied by policy
        FarameshError: On other errors

    Example:
        >>> action = submit_action("my-agent", "http", "get", {"url": "https://example.com"})
        >>> print(f"Action {action['id']} status: {action['status']}")
    """
    payload = {
        "agent_id": agent_id,
        "tool": tool,
        "operation": operation,
        "params": params or {},
        "context": context or {},
    }
    return _make_request("POST", "/v1/actions", json_data=payload)


def submit_actions(
    actions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Submit multiple actions in batch.

    Args:
        actions: List of action specifications. Each dict should have:
            - agent_id (required)
            - tool (required)
            - operation (required)
            - params (optional, default: {})
            - context (optional, default: {})

    Returns:
        List of action response dicts

    Raises:
        FarameshError: On errors

    Example:
        >>> actions = submit_actions([
        ...     {"agent_id": "agent1", "tool": "http", "operation": "get", "params": {"url": "https://example.com"}},
        ...     {"agent_id": "agent2", "tool": "http", "operation": "get", "params": {"url": "https://example.org"}},
        ... ])
        >>> for action in actions:
        ...     print(f"Action {action['id']}: {action['status']}")
    """
    results = []
    for action_spec in actions:
        try:
            result = submit_action(
                agent_id=action_spec["agent_id"],
                tool=action_spec["tool"],
                operation=action_spec["operation"],
                params=action_spec.get("params", {}),
                context=action_spec.get("context", {}),
            )
            results.append(result)
        except Exception as e:
            # Include error in results for failed actions
            results.append({
                "error": str(e),
                "action_spec": action_spec,
            })
    return results


def submit_actions_bulk(
    actions: List[Dict[str, Any]],
    *,
    raise_on_error: bool = False,
) -> List[Dict[str, Any]]:
    """Submit multiple actions in batch with error handling control.

    Args:
        actions: List of action specifications. Each dict should have:
            - agent_id (required)
            - tool (required)
            - operation (required)
            - params (optional, default: {})
            - context (optional, default: {})
        raise_on_error: If True, raise FarameshBatchError on any failure.
                        If False, return list with error placeholders.

    Returns:
        List of action response dicts (or error dicts if raise_on_error=False)

    Raises:
        FarameshBatchError: If raise_on_error=True and any action fails

    Example:
        >>> actions = submit_actions_bulk([
        ...     {"agent_id": "agent1", "tool": "http", "operation": "get", "params": {"url": "https://example.com"}},
        ...     {"agent_id": "agent2", "tool": "http", "operation": "get", "params": {"url": "https://example.org"}},
        ... ], raise_on_error=True)
    """
    successes = []
    errors = []

    for i, action_spec in enumerate(actions):
        try:
            result = submit_action(
                agent_id=action_spec["agent_id"],
                tool=action_spec["tool"],
                operation=action_spec["operation"],
                params=action_spec.get("params", {}),
                context=action_spec.get("context", {}),
            )
            successes.append(result)
        except Exception as e:
            error_entry = {
                "error": str(e),
                "index": i,
                "action_spec": action_spec,
            }
            errors.append(error_entry)
            if not raise_on_error:
                successes.append(error_entry)

    if raise_on_error and errors:
        raise FarameshBatchError(
            f"Batch submission failed: {len(errors)} of {len(actions)} actions failed",
            successes=successes,
            errors=errors,
        )

    return successes


def block_until_approved(
    action_id: str,
    *,
    poll_interval: int = 2,
    timeout: int = 300,
) -> Dict[str, Any]:
    """Block until an action is approved or denied.

    Repeatedly polls get_action until status is "approved" or "denied",
    or timeout is exceeded.

    Args:
        action_id: Action ID to wait for
        poll_interval: Seconds between polls (default: 2)
        timeout: Maximum seconds to wait (default: 300)

    Returns:
        Action dict with status "approved" or "denied"

    Raises:
        FarameshDeniedError: If action is denied
        FarameshTimeoutError: If timeout exceeded
        FarameshError: On other errors

    Example:
        >>> action = submit_action("agent", "http", "get", {"url": "https://example.com"})
        >>> if action["status"] == "pending_approval":
        ...     approved = block_until_approved(action["id"])
    """
    start_time = time.time()

    while True:
        elapsed = time.time() - start_time
        if elapsed > timeout:
            raise FarameshTimeoutError(f"Timeout waiting for approval after {timeout}s")

        action = get_action(action_id)
        status = action.get("status")

        if status == "approved":
            return action
        elif status == "denied":
            reason = action.get("reason", "Action denied")
            raise FarameshDeniedError(f"Action denied: {reason}")
        elif status in ("allowed", "succeeded", "failed"):
            # Already processed, return as-is
            return action

        # Still pending, wait and poll again
        time.sleep(poll_interval)


def submit_and_wait(
    agent_id: str,
    tool: str,
    operation: str,
    params: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    *,
    require_approval: bool = False,
    auto_start: bool = False,
    timeout: int = 300,
    poll_interval: int = 1,
) -> Dict[str, Any]:
    """Submit an action and wait for completion with approval handling.

    This is a convenience function that combines submit, approve (if needed),
    start, and wait_for_completion.

    Args:
        agent_id: Identifier for the agent submitting the action
        tool: Tool name
        operation: Operation name
        params: Action parameters (default: {})
        context: Additional context (default: {})
        require_approval: If True, expect approval flow (default: False)
        auto_start: If True, automatically start after approval/allowed (default: False)
        timeout: Maximum seconds to wait (default: 300)
        poll_interval: Seconds between polls (default: 1)

    Returns:
        Final action dict (status: succeeded, failed, or denied)

    Raises:
        FarameshDeniedError: If action is denied
        FarameshTimeoutError: If timeout exceeded
        FarameshError: On other errors

    Example:
        >>> action = submit_and_wait(
        ...     "my-agent",
        ...     "http",
        ...     "get",
        ...     {"url": "https://example.com"},
        ...     auto_start=True,
        ...     timeout=120
        ... )
        >>> print(f"Final status: {action['status']}")
    """
    # Submit action
    action = submit_action(agent_id, tool, operation, params, context)
    status = action.get("status")

    # If denied, raise immediately
    if status == "denied":
        reason = action.get("reason", "Action denied by policy")
        raise FarameshDeniedError(f"Action denied: {reason}")

    # If pending approval
    if status == "pending_approval":
        if require_approval:
            # Wait for approval
            action = block_until_approved(action["id"], poll_interval=poll_interval, timeout=timeout)
            status = action.get("status")
        else:
            # Return immediately if not requiring approval
            return action

    # If allowed and auto_start, start and wait
    if status == "allowed" and auto_start:
        action = start_action(action["id"])
        return wait_for_completion(action["id"], poll_interval=poll_interval, timeout=timeout)

    # If already approved and auto_start, start and wait
    if status == "approved" and auto_start:
        action = start_action(action["id"])
        return wait_for_completion(action["id"], poll_interval=poll_interval, timeout=timeout)

    # Otherwise return as-is
    return action
    if action["status"] == "pending_approval":
        if auto_approve:
            action = approve_action(action["id"], token=action.get("approval_token"))
        else:
            raise FarameshError(
                f"Action {action['id']} requires approval. "
                f"Use approve_action() or set auto_approve=True"
            )

    # Check if denied
    if action["status"] == "denied":
        return action

    # Start execution if allowed/approved
    if action["status"] in ("allowed", "approved"):
        action = start_action(action["id"])

    # Wait for completion
    return wait_for_completion(action["id"], poll_interval=poll_interval, timeout=timeout)


def get_action(action_id: str) -> Dict[str, Any]:
    """Get an action by ID.

    Args:
        action_id: Action ID (full UUID or prefix)

    Returns:
        Action response dict

    Raises:
        FarameshNotFoundError: If action not found

    Example:
        >>> action = get_action("12345678-1234-1234-1234-123456789abc")
    """
    return _make_request("GET", f"/v1/actions/{action_id}")


def list_actions(
    limit: int = 20,
    offset: int = 0,
    agent_id: Optional[str] = None,
    tool: Optional[str] = None,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List actions with optional filters.

    Args:
        limit: Maximum number of actions to return (default: 20)
        offset: Offset for pagination (default: 0)
        agent_id: Filter by agent ID
        tool: Filter by tool name
        status: Filter by status (e.g., "pending_approval", "allowed", "denied")

    Returns:
        List of action dicts

    Example:
        >>> actions = list_actions(limit=10, status="pending_approval")
        >>> for action in actions:
        ...     print(f"{action['id']}: {action['status']}")
    """
    params = {"limit": limit, "offset": offset}
    if agent_id:
        params["agent_id"] = agent_id
    if tool:
        params["tool"] = tool
    if status:
        params["status"] = status

    response = _make_request("GET", "/v1/actions", params=params)
    if isinstance(response, list):
        return response
    return response.get("actions", [])


def approve_action(
    action_id: str,
    token: Optional[str] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Approve a pending action.

    Args:
        action_id: Action ID to approve
        token: Approval token (required if action requires approval)
        reason: Optional reason for approval

    Returns:
        Updated action dict

    Raises:
        FarameshNotFoundError: If action not found
        FarameshError: If action is not in pending_approval status or token invalid

    Example:
        >>> action = submit_action("agent", "shell", "run", {"cmd": "ls"})
        >>> if action["status"] == "pending_approval":
        ...     approved = approve_action(action["id"], token=action["approval_token"])
    """
    if token is None:
        # Try to get the action first to extract token
        action = get_action(action_id)
        if action.get("status") != "pending_approval":
            raise FarameshError(f"Action {action_id} is not pending approval (status: {action.get('status')})")
        token = action.get("approval_token")
        if not token:
            raise FarameshError(f"Approval token not found for action {action_id}")

    payload = {
        "token": token,
        "approve": True,
    }
    if reason:
        payload["reason"] = reason

    return _make_request("POST", f"/v1/actions/{action_id}/approval", json_data=payload)


def deny_action(
    action_id: str,
    token: Optional[str] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Deny a pending action.

    Args:
        action_id: Action ID to deny
        token: Approval token (required if action requires approval)
        reason: Optional reason for denial

    Returns:
        Updated action dict

    Raises:
        FarameshNotFoundError: If action not found
        FarameshError: If action is not in pending_approval status or token invalid

    Example:
        >>> action = submit_action("agent", "shell", "run", {"cmd": "rm -rf /"})
        >>> if action["status"] == "pending_approval":
        ...     denied = deny_action(action["id"], token=action["approval_token"], reason="Too dangerous")
    """
    if token is None:
        # Try to get the action first to extract token
        action = get_action(action_id)
        if action.get("status") != "pending_approval":
            raise FarameshError(f"Action {action_id} is not pending approval (status: {action.get('status')})")
        token = action.get("approval_token")
        if not token:
            raise FarameshError(f"Approval token not found for action {action_id}")

    payload = {
        "token": token,
        "approve": False,
    }
    if reason:
        payload["reason"] = reason

    return _make_request("POST", f"/v1/actions/{action_id}/approval", json_data=payload)


def start_action(action_id: str) -> Dict[str, Any]:
    """Start execution of an approved or allowed action.

    Args:
        action_id: Action ID to start

    Returns:
        Updated action dict

    Raises:
        FarameshNotFoundError: If action not found
        FarameshError: If action is not in allowed/approved status

    Example:
        >>> action = submit_action("agent", "http", "get", {"url": "https://example.com"})
        >>> if action["status"] == "allowed":
        ...     started = start_action(action["id"])
    """
    return _make_request("POST", f"/v1/actions/{action_id}/start")


def replay_action(action_id: str) -> Dict[str, Any]:
    """Replay an action by creating a new action with the same parameters.

    Args:
        action_id: Action ID to replay

    Returns:
        New action dict

    Raises:
        FarameshNotFoundError: If action not found
        FarameshError: If action cannot be replayed (must be allowed/approved/succeeded)

    Example:
        >>> original = get_action("123")
        >>> if original["status"] in ("allowed", "approved", "succeeded"):
        ...     replayed = replay_action("123")
    """
    # Get original action
    original = get_action(action_id)

    status = original.get("status")
    if status not in ("allowed", "approved", "succeeded"):
        raise FarameshError(
            f"Cannot replay action {action_id} with status '{status}'. "
            "Only allowed, approved, or succeeded actions can be replayed."
        )

    # Create new action with same payload
    context = original.get("context", {})
    if not isinstance(context, dict):
        context = {}

    new_context = {
        **context,
        "replayed_from": action_id,
        "replay": True,
    }

    return submit_action(
        agent_id=original["agent_id"],
        tool=original["tool"],
        operation=original["operation"],
        params=original.get("params", {}),
        context=new_context,
    )


def wait_for_completion(
    action_id: str,
    poll_interval: float = 1.0,
    timeout: float = 60.0,
) -> Dict[str, Any]:
    """Wait for an action to complete (succeeded or failed).

    Args:
        action_id: Action ID to wait for
        poll_interval: Seconds between polls (default: 1.0)
        timeout: Maximum seconds to wait (default: 60.0)

    Returns:
        Final action dict

    Raises:
        FarameshTimeoutError: If timeout exceeded
        FarameshError: On other errors

    Example:
        >>> action = start_action("123")
        >>> final = wait_for_completion(action["id"], timeout=120)
        >>> print(f"Final status: {final['status']}")
    """
    start_time = time.time()

    while True:
        action = get_action(action_id)
        status = action.get("status")

        if status in ("succeeded", "failed", "denied"):
            return action

        if time.time() - start_time > timeout:
            raise FarameshTimeoutError(
                f"Action {action_id} did not complete within {timeout}s. "
                f"Current status: {status}"
            )

        time.sleep(poll_interval)


def apply(file_path: Union[str, Path]) -> Dict[str, Any]:
    """Load an action from a YAML or JSON file and submit it.

    Args:
        file_path: Path to YAML or JSON file

    Returns:
        Action response dict

    Raises:
        FileNotFoundError: If file doesn't exist
        FarameshValidationError: If file format is invalid
        FarameshError: On other errors

    Example:
        >>> action = apply("./action.yaml")
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # Load file
    try:
        if path.suffix in (".yaml", ".yml"):
            with open(path, "r") as f:
                data = yaml.safe_load(f)
        elif path.suffix == ".json":
            with open(path, "r") as f:
                data = json.load(f)
        else:
            # Try YAML first, then JSON
            try:
                with open(path, "r") as f:
                    data = yaml.safe_load(f)
            except:
                with open(path, "r") as f:
                    data = json.load(f)
    except Exception as e:
        raise FarameshValidationError(f"Failed to parse file {file_path}: {e}")

    # Validate required fields
    required = ["agent_id", "tool", "operation"]
    missing = [f for f in required if f not in data]
    if missing:
        raise FarameshValidationError(f"Missing required fields: {', '.join(missing)}")

    # Submit action
    return submit_action(
        agent_id=data["agent_id"],
        tool=data["tool"],
        operation=data["operation"],
        params=data.get("params", {}),
        context=data.get("context", {}),
    )


def tail_events(
    callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    action_id: Optional[str] = None,
) -> None:
    """Stream events via Server-Sent Events (SSE).

    This function connects to the /v1/events SSE endpoint and streams
    events in real-time. For each event, it calls the callback function.

    Args:
        callback: Function to call for each event. Receives event dict.
                  If None, prints events to stdout.
        action_id: Optional action ID to filter events (if supported by server)

    Raises:
        FarameshConnectionError: If SSE connection fails
        FarameshError: On other errors

    Example:
        >>> def handle_event(event):
        ...     print(f"Event: {event.get('event_type')} - {event.get('action_id')}")
        >>>
        >>> tail_events(callback=handle_event)
    """
    stream_events(callback=callback, action_id=action_id)


def stream_events(
    callback: Callable[[Dict[str, Any]], None],
    *,
    event_types: Optional[List[str]] = None,
    stop_after: Optional[int] = None,
    timeout: Optional[int] = None,
    action_id: Optional[str] = None,
) -> None:
    """Stream events via Server-Sent Events (SSE) with advanced options.

    This function connects to the /v1/events SSE endpoint and streams
    events in real-time. For each event, it calls the callback function.

    Args:
        callback: Function to call for each event. Receives event dict.
        event_types: Optional list of event types to filter (e.g., ["action_created", "action_approved"])
        stop_after: Optional number of events to process before stopping
        timeout: Optional timeout in seconds (None = no timeout)
        action_id: Optional action ID to filter events

    Raises:
        FarameshConnectionError: If SSE connection fails
        FarameshError: On other errors
        FarameshTimeoutError: If timeout exceeded

    Example:
        >>> def handle_event(event):
        ...     print(f"Event: {event.get('event_type')} - {event.get('action_id')}")
        >>>
        >>> stream_events(handle_event, event_types=["action_created"], stop_after=10)
    """
    config = _get_config()

    try:
        import sseclient
    except ImportError:
        raise FarameshError(
            "SSE support requires sseclient. Install with: pip install sseclient"
        )

    url = f"{config.base_url}/v1/events"
    headers = {"Accept": "text/event-stream"}
    if config.token:
        headers["Authorization"] = f"Bearer {config.token}"

    try:
        response = requests.get(url, headers=headers, stream=True, timeout=timeout)
        response.raise_for_status()

        client = sseclient.SSEClient(response)

        event_count = 0
        start_time = time.time()

        for event in client.events():
            # Check timeout
            if timeout and (time.time() - start_time) > timeout:
                raise FarameshTimeoutError(f"Stream timeout after {timeout}s")

            if event.event == 'message' or not event.event:
                try:
                    data = json.loads(event.data)

                    # Filter by action_id if specified
                    if action_id and data.get('action_id') != action_id:
                        continue

                    # Filter by event_types if specified
                    if event_types:
                        event_type = data.get('event_type') or data.get('type')
                        if event_type not in event_types:
                            continue

                    callback(data)
                    event_count += 1

                    # Stop after N events if specified
                    if stop_after and event_count >= stop_after:
                        break

                except json.JSONDecodeError:
                    continue
    except requests.exceptions.Timeout:
        raise FarameshTimeoutError(f"SSE stream timeout after {timeout or 'default'}s")
    except requests.exceptions.RequestException as e:
        raise FarameshConnectionError(f"Failed to connect to SSE stream: {str(e)}")


# Convenience aliases
allow = approve_action
deny = deny_action


# Legacy class-based API (for backward compatibility)
class ExecutionGovernorClient:
    """Legacy class-based API. Use module-level functions instead.

    This class is maintained for backward compatibility. New code should use
    the module-level functions: submit_action, get_action, approve_action, etc.
    """

    def __init__(self, base_url: Optional[Union[str, ClientConfig]] = None, config: Optional[ClientConfig] = None):
        """Initialize client with base_url string or ClientConfig object.

        Args:
            base_url: Base URL string (e.g., "http://127.0.0.1:8000") or ClientConfig object
            config: ClientConfig object (deprecated, use base_url parameter)
        """
        # Support both string and ClientConfig for backward compatibility
        if isinstance(base_url, ClientConfig):
            config = base_url
            base_url = None
        elif base_url is None and config is None:
            config = _get_config()
        elif isinstance(base_url, str):
            # Create config from string
            config = ClientConfig(base_url=base_url)
        elif config is not None:
            # Use provided config
            pass
        else:
            config = _get_config()

        self.config = config
        # Store agent_id if present
        if hasattr(config, 'agent_id'):
            self.agent_id = config.agent_id
        else:
            self.agent_id = "default-agent"
        configure(
            base_url=config.base_url,
            token=config.token,
            timeout=config.timeout,
            max_retries=config.max_retries,
        )

    def submit_action(
        self,
        tool: str,
        operation: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit action (uses agent_id from config)."""
        return submit_action(
            agent_id=self.agent_id,
            tool=tool,
            operation=operation,
            params=params,
            context=context,
        )

    def get_action(self, action_id: str) -> Dict[str, Any]:
        """Get action by ID."""
        return get_action(action_id)

    def list_actions(
        self,
        limit: int = 20,
        offset: int = 0,
        agent_id: Optional[str] = None,
        tool: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List actions."""
        return list_actions(limit=limit, offset=offset, agent_id=agent_id, tool=tool, status=status)

    def approve_action(self, action_id: str, token: Optional[str] = None, reason: Optional[str] = None) -> Dict[str, Any]:
        """Approve action."""
        return approve_action(action_id, token=token, reason=reason)

    def deny_action(self, action_id: str, token: Optional[str] = None, reason: Optional[str] = None) -> Dict[str, Any]:
        """Deny action."""
        return deny_action(action_id, token=token, reason=reason)

    def start_action(self, action_id: str) -> Dict[str, Any]:
        """Start action."""
        return start_action(action_id)

    def replay_action(self, action_id: str) -> Dict[str, Any]:
        """Replay action."""
        return replay_action(action_id)

    def wait_for_completion(self, action_id: str, poll_interval: float = 1.0, timeout: float = 60.0) -> Dict[str, Any]:
        """Wait for completion."""
        return wait_for_completion(action_id, poll_interval=poll_interval, timeout=timeout)

    def apply(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Apply action from file."""
        return apply(file_path)


# Backward compatibility aliases
GovernorConfig = ClientConfig
GovernorError = FarameshError
GovernorTimeoutError = FarameshTimeoutError
GovernorAuthError = FarameshAuthError
GovernorConnectionError = FarameshConnectionError
