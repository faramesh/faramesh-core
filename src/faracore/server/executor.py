# src/faracore/server/executor.py
from __future__ import annotations

import subprocess
import threading
from datetime import datetime
from typing import Any

from .models import Action, Status, Decision
from .policy_engine import PolicyEngine
from .settings import get_settings


class ActionExecutor:
    """Basic action executor for core operations."""
    
    def __init__(self, store: Any):
        self.store = store
        self.running = {}
        self.execution_start_times = {}

        # load policy from env or default
        settings = get_settings()
        self.policies = PolicyEngine(settings.policy_file)
        self.action_timeout = settings.action_timeout

    def run_shell(self, action: Action):
        """Execute shell commands asynchronously with timeout support."""
        if action.id in self.running:
            return

        cmd = action.params.get("cmd") or ""
        if not cmd:
            action.status = Status.FAILED
            action.reason = "Missing cmd"
            self.store.update_action(action)
            return

        # Get timeout from context or use default
        timeout_seconds = action.context.get("timeout") or self.action_timeout
        start_time = datetime.utcnow()
        self.execution_start_times[action.id] = start_time

        def worker():
            try:
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
                    proc.kill()
                    proc.wait()
                    fresh = self.store.get_action(action.id)
                    if fresh:
                        fresh.status = Status.TIMEOUT
                        fresh.reason = f"Action timed out after {timeout_seconds} seconds"
                        try:
                            self.store.create_event(fresh.id, "failed", {"reason": fresh.reason, "error": "timeout"})
                        except Exception:
                            pass
                        self.store.update_action(fresh)
                    self.execution_start_times.pop(action.id, None)
                    self.running.pop(action.id, None)
                    return

                fresh = self.store.get_action(action.id)
                if not fresh:
                    return

                if proc.returncode == 0:
                    fresh.status = Status.SUCCEEDED
                    fresh.reason = out.decode("utf-8") or "ok"
                    try:
                        self.store.create_event(fresh.id, "succeeded", {"reason": fresh.reason})
                    except Exception:
                        pass
                else:
                    fresh.status = Status.FAILED
                    msg = err.decode("utf-8") or f"exit {proc.returncode}"
                    fresh.reason = msg
                    try:
                        self.store.create_event(fresh.id, "failed", {"reason": fresh.reason, "error": msg})
                    except Exception:
                        pass

                self.store.update_action(fresh)

            except Exception as e:
                fresh = self.store.get_action(action.id)
                if fresh:
                    fresh.status = Status.FAILED
                    fresh.reason = f"Execution error: {str(e)}"
                    try:
                        self.store.create_event(fresh.id, "failed", {"reason": fresh.reason, "error": str(e)})
                    except Exception:
                        pass
                    self.store.update_action(fresh)
            finally:
                self.execution_start_times.pop(action.id, None)
                self.running.pop(action.id, None)

        th = threading.Thread(target=worker, daemon=True)
        self.running[action.id] = th
        th.start()

    def try_execute(self, action: Action, skip_policy_check: bool = False):
        """Evaluate policy + maybe execute.
        
        Args:
            action: Action to execute
            skip_policy_check: If True, skip policy evaluation (for already-approved actions)
        """
        if not skip_policy_check:
            # 1) evaluate policy
            decision, reason, risk = self.policies.evaluate(
                tool=action.tool,
                operation=action.operation,
                params=action.params,
                context=action.context or {},
            )

            # 2) apply decision
            if decision == Decision.DENY:
                action.status = Status.DENIED
                action.reason = reason
                self.store.update_action(action)
                return False

            if decision == Decision.REQUIRE_APPROVAL:
                action.status = Status.PENDING_APPROVAL
                action.reason = reason
                self.store.update_action(action)
                return False

        # ALLOW or already approved - execute
        if action.tool == "shell":
            action.status = Status.EXECUTING
            action.reason = "Executing"
            self.store.update_action(action)
            # Write event: started (may already exist from /start endpoint, but ensure it's here)
            try:
                self.store.create_event(action.id, "started", {})
            except Exception:
                pass
            self.run_shell(action)
            return True

        # unknown tool — allow but do nothing
        action.status = Status.SUCCEEDED
        action.reason = "No executor"
        self.store.update_action(action)
        try:
            self.store.create_event(action.id, "succeeded", {"reason": "No executor"})
        except Exception:
            pass
        return True
