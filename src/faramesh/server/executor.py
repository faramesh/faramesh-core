# src/faramesh/server/executor.py
from __future__ import annotations

import logging
import subprocess
import threading
from datetime import datetime
from typing import Any

from .models import Action, Decision, Status
from .policy_engine import PolicyEngine
from .security.guard import (
    SecurityError,
    enforce_no_side_effects,
    sanitize_shell_command,
)
from .settings import get_settings


class ActionExecutor:
    """Basic action executor for core operations."""
    
    def __init__(self, store: Any):
        self.store = store
        self.running = {}
        self.execution_start_times = {}
        self._lock = threading.Lock()  # Thread safety for running dict

        # load policy from env or default
        settings = get_settings()
        self.policies = PolicyEngine(settings.policy_file)
        self.action_timeout = settings.action_timeout

    def run_shell(self, action: Action):
        """Execute shell commands asynchronously with timeout support.
        
        CRITICAL: This function enforces that no shell commands execute
        until the action is explicitly approved. This is the core security
        guarantee of Faramesh.
        """
        # CRITICAL SECURITY CHECK: No execution until approved
        try:
            enforce_no_side_effects(action.status.value, action.decision.value if action.decision else "deny")
        except SecurityError as e:
            logging.error(f"SECURITY VIOLATION: Attempted to execute unapproved action {action.id}: {e}")
            action.status = Status.FAILED
            action.reason = f"Security violation: {e}"
            try:
                self.store.update_action(action)
                self.store.create_event(action.id, "failed", {"reason": action.reason, "error": "security_violation"})
            except Exception:
                pass
            return
        
        # Check if already running (thread-safe check with lock)
        with self._lock:
            if action.id in self.running:
                logging.warning(f"Action {action.id} is already executing")
                return

        # Defensive check for params
        if not isinstance(action.params, dict):
            logging.error(f"Action {action.id} has invalid params: {type(action.params)}")
            action.status = Status.FAILED
            action.reason = "Invalid params: must be a dictionary"
            try:
                self.store.update_action(action)
                self.store.create_event(action.id, "failed", {"reason": action.reason})
            except Exception as e:
                logging.error(f"Failed to update action status: {e}")
            return

        cmd = action.params.get("cmd") or ""
        if not cmd:
            action.status = Status.FAILED
            action.reason = "Missing cmd parameter"
            try:
                self.store.update_action(action)
                self.store.create_event(action.id, "failed", {"reason": action.reason})
            except Exception as e:
                logging.error(f"Failed to update action status: {e}")
            return

        # Sanitize command (additional safety layer)
        try:
            cmd = sanitize_shell_command(cmd)
        except SecurityError as e:
            logging.error(f"Command sanitization failed for action {action.id}: {e}")
            action.status = Status.FAILED
            action.reason = f"Invalid command: {e}"
            try:
                self.store.update_action(action)
                self.store.create_event(action.id, "failed", {"reason": action.reason, "error": "command_validation_failed"})
            except Exception:
                pass
            return

        # Get timeout from context or use default (with defensive checks)
        timeout_seconds = self.action_timeout
        if isinstance(action.context, dict):
            timeout_value = action.context.get("timeout")
            if isinstance(timeout_value, (int, float)) and timeout_value > 0:
                # Cap timeout at reasonable maximum (1 hour) to prevent hangs
                timeout_seconds = min(timeout_value, 3600)
        
        # Final validation
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            timeout_seconds = self.action_timeout
        
        start_time = datetime.utcnow()
        with self._lock:
            self.execution_start_times[action.id] = start_time

        def worker():
            try:
                # Use shell=True but with sanitized command
                # Note: The real security is in requiring approval before this runs
                proc = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                
                # Wait with timeout
                try:
                    out, err = proc.communicate(timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    # Force kill the process and wait for it to terminate
                    try:
                        proc.kill()
                    except Exception as e:
                        logging.warning(f"Failed to kill timed-out process for action {action.id}: {e}")
                    
                    # Wait for process to terminate (with timeout to prevent hanging)
                    try:
                        # proc.wait() doesn't support timeout in Python < 3.3, use poll() instead
                        import time
                        start = time.time()
                        while proc.poll() is None and (time.time() - start) < 5.0:
                            time.sleep(0.1)
                        if proc.poll() is None:
                            logging.error(f"Process for action {action.id} did not terminate after kill")
                        else:
                            proc.wait()  # Clean up the process
                    except Exception as e:
                        logging.warning(f"Error waiting for process termination: {e}")
                    
                    fresh = self.store.get_action(action.id)
                    if fresh:
                        fresh.status = Status.TIMEOUT
                        fresh.reason = f"Action timed out after {timeout_seconds} seconds"
                        try:
                            self.store.create_event(fresh.id, "failed", {"reason": fresh.reason, "error": "timeout"})
                        except Exception:
                            pass
                        try:
                            self.store.update_action(fresh)
                        except Exception as e:
                            logging.error(f"Failed to update action after timeout: {e}")
                    with self._lock:
                        self.execution_start_times.pop(action.id, None)
                        self.running.pop(action.id, None)
                    return

                fresh = self.store.get_action(action.id)
                if not fresh:
                    return

                if proc.returncode == 0:
                    fresh.status = Status.SUCCEEDED
                    # Safe decode with fallback
                    try:
                        fresh.reason = out.decode("utf-8", errors="replace") or "ok"
                    except (UnicodeDecodeError, AttributeError):
                        fresh.reason = "Execution completed (output encoding issue)"
                    try:
                        self.store.create_event(fresh.id, "succeeded", {"reason": fresh.reason})
                    except Exception:
                        pass
                else:
                    fresh.status = Status.FAILED
                    # Safe decode with fallback
                    try:
                        msg = err.decode("utf-8", errors="replace") or f"exit {proc.returncode}"
                    except (UnicodeDecodeError, AttributeError):
                        msg = f"exit {proc.returncode} (error output encoding issue)"
                    fresh.reason = msg
                    try:
                        self.store.create_event(fresh.id, "failed", {"reason": fresh.reason, "error": msg})
                    except Exception:
                        pass

                try:
                    self.store.update_action(fresh)
                except Exception as e:
                    logging.error(f"Failed to update action after execution: {e}")

            except Exception as e:
                # Ensure process is cleaned up even on error
                try:
                    if 'proc' in locals() and proc.poll() is None:
                        # Process is still running, kill it
                        proc.kill()
                        # Wait for process to terminate (with timeout to prevent hanging)
                        import time
                        start = time.time()
                        while proc.poll() is None and (time.time() - start) < 2.0:
                            time.sleep(0.1)
                        if proc.poll() is not None:
                            proc.wait()  # Clean up the process
                except Exception:
                    pass  # Best effort cleanup
                
                fresh = self.store.get_action(action.id)
                if fresh:
                    fresh.status = Status.FAILED
                    fresh.reason = f"Execution error: {str(e)}"
                    try:
                        self.store.create_event(fresh.id, "failed", {"reason": fresh.reason, "error": str(e)})
                    except Exception:
                        pass
                    try:
                        self.store.update_action(fresh)
                    except Exception as e2:
                        logging.error(f"Failed to update action after execution error: {e2}")
            finally:
                # Ensure cleanup happens even if there's an error
                with self._lock:
                    self.execution_start_times.pop(action.id, None)
                    self.running.pop(action.id, None)

        th = threading.Thread(target=worker, daemon=True)
        with self._lock:
            self.running[action.id] = th
        th.start()

    def try_execute(self, action: Action, skip_policy_check: bool = False):
        """Evaluate policy + maybe execute.
        
        CRITICAL SECURITY: This function enforces that no execution occurs
        until the action is explicitly approved. This is the core security
        guarantee of Faramesh.
        
        Args:
            action: Action to execute
            skip_policy_check: If True, skip policy evaluation (for already-approved actions)
        """
        # CRITICAL: Enforce no side effects on pending actions
        try:
            enforce_no_side_effects(
                action.status.value,
                action.decision.value if action.decision else "deny"
            )
        except SecurityError as e:
            logging.error(f"SECURITY VIOLATION: Attempted to execute unapproved action {action.id}: {e}")
            action.status = Status.FAILED
            action.reason = f"Security violation: {e}"
            try:
                self.store.update_action(action)
                self.store.create_event(action.id, "failed", {"reason": action.reason, "error": "security_violation"})
            except Exception as e:
                logging.error(f"Failed to update action after security violation: {e}")
            return False
        
        if not skip_policy_check:
            # 1) evaluate policy with error handling
            try:
                decision, reason, risk = self.policies.evaluate(
                    tool=action.tool,
                    operation=action.operation,
                    params=action.params,
                    context=action.context or {},
                )
            except Exception as e:
                logging.error(f"Policy evaluation error for action {action.id}: {e}")
                # Deny by default for safety
                decision = Decision.DENY
                reason = f"Policy evaluation error: {str(e)}"

            # 2) apply decision
            if decision == Decision.DENY:
                action.status = Status.DENIED
                action.reason = reason
                try:
                    self.store.update_action(action, expected_version=None)
                except Exception as e:
                    logging.error(f"Failed to update denied action: {e}")
                return False

            if decision == Decision.REQUIRE_APPROVAL:
                action.status = Status.PENDING_APPROVAL
                action.reason = reason
                try:
                    self.store.update_action(action, expected_version=None)
                except Exception as e:
                    logging.error(f"Failed to update pending action: {e}")
                return False

        # ALLOW or already approved - execute
        # Double-check status before execution
        if action.status not in (Status.ALLOWED, Status.APPROVED):
            logging.error(f"Attempted to execute action {action.id} with invalid status: {action.status.value}")
            action.status = Status.FAILED
            action.reason = f"Cannot execute action in status: {action.status.value}"
            try:
                self.store.update_action(action)
                self.store.create_event(action.id, "failed", {"reason": action.reason})
            except Exception:
                pass
            return False
        
        if action.tool == "shell":
            action.status = Status.EXECUTING
            action.reason = "Executing"
            try:
                self.store.update_action(action)
            except Exception as e:
                logging.error(f"Failed to update action to executing: {e}")
                return False
            
            # Write event: started (may already exist from /start endpoint, but ensure it's here)
            try:
                self.store.create_event(action.id, "started", {})
            except Exception as e:
                logging.warning(f"Failed to create 'started' event: {e}")
            
            self.run_shell(action)
            return True

        # unknown tool — allow but do nothing
        action.status = Status.SUCCEEDED
        action.reason = "No executor for this tool type"
        try:
            self.store.update_action(action)
            self.store.create_event(action.id, "succeeded", {"reason": "No executor"})
        except Exception as e:
            logging.error(f"Failed to update action for unknown tool: {e}")
        return True
