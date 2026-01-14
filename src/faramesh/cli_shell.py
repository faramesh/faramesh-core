"""Interactive REPL shell for Faramesh."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any, Dict, Optional

try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False

from .cli import (
    HAS_RICH,
    _find_action_by_prefix,
    _get_auth_token,
    _get_base_url,
    _handle_request_error,
    _make_request,
    _print_error,
    _print_success,
    _truncate_uuid,
)

if HAS_RICH:
    from rich.console import Console
    from rich.panel import Panel


class FaraShell:
    """Interactive REPL for Faramesh commands."""
    
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.base_url = _get_base_url(args)
        self.token = _get_auth_token(args)
        self.console = Console() if HAS_RICH else None
        self.history_file = os.path.expanduser("~/.faramesh_history")
        
        # Setup readline history
        if HAS_READLINE:
            try:
                readline.read_history_file(self.history_file)
            except FileNotFoundError:
                pass
            readline.set_history_length(1000)
            
            # Tab completion for commands
            readline.set_completer(self._complete)
            readline.parse_and_bind("tab: complete")
    
    def _complete(self, text: str, state: int) -> Optional[str]:
        """Tab completion handler."""
        commands = [
            'submit', 'approve', 'deny', 'start', 'replay', 'history',
            'get', 'list', 'tail', 'explain', 'events', 'curl', 'exit', 'help'
        ]
        matches = [cmd for cmd in commands if cmd.startswith(text.lower())]
        if state < len(matches):
            return matches[state]
        return None
    
    def _parse_command(self, line: str) -> tuple[str, list[str]]:
        """Parse command line into command and args."""
        parts = line.strip().split()
        if not parts:
            return "", []
        cmd = parts[0].lower()
        args_list = parts[1:]
        return cmd, args_list
    
    def _parse_params(self, args_list: list[str]) -> Dict[str, Any]:
        """Parse key=value pairs from args."""
        params = {}
        for arg in args_list:
            if '=' in arg:
                key, value = arg.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Remove quotes
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                
                # Try JSON parsing
                try:
                    parsed_value = json.loads(value)
                except (json.JSONDecodeError, ValueError):
                    parsed_value = value
                
                params[key] = parsed_value
        return params
    
    def _cmd_submit(self, args_list: list[str]) -> None:
        """Submit a new action."""
        if len(args_list) < 3:
            self._print_help("submit agent=<id> tool=<name> op=<name> [param key=value ...]")
            return
        
        params_dict = self._parse_params(args_list)
        
        agent_id = params_dict.pop('agent', None)
        tool = params_dict.pop('tool', None)
        operation = params_dict.pop('op', None) or params_dict.pop('operation', None)
        
        if not all([agent_id, tool, operation]):
            _print_error("Missing required: agent, tool, op")
            self._print_help("submit agent=<id> tool=<name> op=<name> [param key=value ...]")
            return
        
        payload = {
            "agent_id": agent_id,
            "tool": tool,
            "operation": operation,
            "params": params_dict
        }
        
        try:
            r = _make_request("POST", f"{self.base_url}/v1/actions", json=payload, token=self.token)
            r.raise_for_status()
            action = r.json()
            
            action_id = action.get('id', 'N/A')
            short_id = _truncate_uuid(action_id, full=False)
            status = action.get('status', 'unknown')
            
            _print_success(f"Action submitted: {short_id} ({status})")
            
            # Show next actions
            if status == 'pending_approval':
                print(f"  → approve {short_id}")
                print(f"  → deny {short_id}")
            elif status in ('allowed', 'approved'):
                print(f"  → start {short_id}")
        except Exception as e:
            _handle_request_error(e, self.base_url)
    
    def _cmd_approve(self, args_list: list[str]) -> None:
        """Approve an action."""
        if not args_list:
            _print_error("Usage: approve <id>")
            return
        
        action_id = args_list[0]
        self._approve_or_deny(action_id, approve=True)
    
    def _cmd_deny(self, args_list: list[str]) -> None:
        """Deny an action."""
        if not args_list:
            _print_error("Usage: deny <id>")
            return
        
        action_id = args_list[0]
        self._approve_or_deny(action_id, approve=False)
    
    def _approve_or_deny(self, action_id: str, approve: bool) -> None:
        """Approve or deny an action."""
        # Resolve ID
        try:
            r = _make_request("GET", f"{self.base_url}/v1/actions/{action_id}", token=self.token)
            r.raise_for_status()
            full_id = action_id
        except Exception:
            matches = _find_action_by_prefix(self.base_url, action_id, self.token)
            if len(matches) == 0:
                _print_error(f"No action found: {action_id}")
                return
            elif len(matches) > 1:
                _print_error(f"Multiple matches: {action_id}")
                return
            full_id = matches[0]['id']
        
        # Get action
        r = _make_request("GET", f"{self.base_url}/v1/actions/{full_id}", token=self.token)
        r.raise_for_status()
        action = r.json()
        
        if action.get('status') != 'pending_approval':
            _print_error(f"Action not pending approval (status: {action.get('status')})")
            return
        
        approval_token = action.get('approval_token')
        if not approval_token:
            _print_error("No approval token")
            return
        
        # Submit
        payload = {"token": approval_token, "approve": approve}
        r = _make_request("POST", f"{self.base_url}/v1/actions/{full_id}/approval", json=payload, token=self.token)
        r.raise_for_status()
        
        verb = "approved" if approve else "denied"
        _print_success(f"Action {_truncate_uuid(full_id)} {verb}")
    
    def _cmd_start(self, args_list: list[str]) -> None:
        """Start action execution."""
        if not args_list:
            _print_error("Usage: start <id>")
            return
        
        action_id = args_list[0]
        # Resolve ID
        try:
            r = _make_request("GET", f"{self.base_url}/v1/actions/{action_id}", token=self.token)
            r.raise_for_status()
            full_id = action_id
        except Exception:
            matches = _find_action_by_prefix(self.base_url, action_id, self.token)
            if len(matches) == 0:
                _print_error(f"No action found: {action_id}")
                return
            elif len(matches) > 1:
                _print_error(f"Multiple matches: {action_id}")
                return
            full_id = matches[0]['id']
        
        r = _make_request("POST", f"{self.base_url}/v1/actions/{full_id}/start", token=self.token)
        r.raise_for_status()
        _print_success(f"Action {_truncate_uuid(full_id)} started")
    
    def _cmd_history(self, args_list: list[str]) -> None:
        """Show action history."""
        from .cli import cmd_list
        # Create mock args
        class MockArgs:
            limit = 20
            full = False
            json = False
            host = getattr(self.args, 'host', None)
            port = getattr(self.args, 'port', None)
            token = self.token
        
        cmd_list(MockArgs())
    
    def _cmd_help(self, args_list: list[str]) -> None:
        """Show help."""
        self._print_help()
    
    def _print_help(self, specific: Optional[str] = None) -> None:
        """Print help message."""
        if specific:
            print(f"Usage: {specific}")
            return
        
        help_text = """
[Commands]
  submit agent=<id> tool=<name> op=<name> [param key=value ...]
    Submit a new action
    
  approve <id>          Approve a pending action
  deny <id>             Deny a pending action
  start <id>            Start execution of an action
  replay <id>           Replay an action
  
  history               Show recent actions
  get <id>              Get action details
  explain <id>          Explain policy decision
  
  exit, quit            Exit shell
  help                  Show this help

[Examples]
  submit agent=bot tool=shell op=run cmd="echo hi"
  approve 2755d4a8
  start 2755d4a8
"""
        if self.console:
            self.console.print(Panel(help_text, title="Faramesh Shell", border_style="cyan"))
        else:
            print(help_text)
    
    def run(self) -> None:
        """Run the interactive shell."""
        if self.console:
            self.console.print("[cyan]Faramesh Interactive Shell[/cyan]")
            self.console.print("Type 'help' for commands, 'exit' to quit\n")
        else:
            print("Faramesh Interactive Shell")
            print("Type 'help' for commands, 'exit' to quit\n")
        
        while True:
            try:
                line = input("fara> ").strip()
                if not line:
                    continue
                
                cmd, args_list = self._parse_command(line)
                
                if cmd in ('exit', 'quit'):
                    break
                elif cmd == 'help':
                    self._cmd_help(args_list)
                elif cmd == 'submit':
                    self._cmd_submit(args_list)
                elif cmd == 'approve':
                    self._cmd_approve(args_list)
                elif cmd == 'deny':
                    self._cmd_deny(args_list)
                elif cmd == 'start':
                    self._cmd_start(args_list)
                elif cmd == 'history':
                    self._cmd_history(args_list)
                elif cmd == 'replay':
                    from .cli_actions import cmd_action_replay
                    class MockArgs:
                        id = args_list[0] if args_list else None
                        json = False
                        host = getattr(self.args, 'host', None)
                        port = getattr(self.args, 'port', None)
                        token = self.token
                    if MockArgs.id:
                        cmd_action_replay(MockArgs())
                elif cmd == 'get':
                    from .cli import cmd_get
                    class MockArgs:
                        id = args_list[0] if args_list else None
                        json = False
                        host = getattr(self.args, 'host', None)
                        port = getattr(self.args, 'port', None)
                        token = self.token
                    if MockArgs.id:
                        cmd_get(MockArgs())
                elif cmd == 'explain':
                    from .cli import cmd_explain
                    class MockArgs:
                        id = args_list[0] if args_list else None
                        host = getattr(self.args, 'host', None)
                        port = getattr(self.args, 'port', None)
                        token = self.token
                    if MockArgs.id:
                        cmd_explain(MockArgs())
                else:
                    _print_error(f"Unknown command: {cmd}. Type 'help' for help.")
            except KeyboardInterrupt:
                print("\n")
                break
            except EOFError:
                print("\n")
                break
            except Exception as e:
                _print_error(f"Error: {e}")
        
        # Save history
        if HAS_READLINE:
            try:
                readline.write_history_file(self.history_file)
            except Exception:
                pass
        
        if self.console:
            self.console.print("\n[cyan]Goodbye![/cyan]")
        else:
            print("\nGoodbye!")


def cmd_shell(args: argparse.Namespace) -> None:
    """Start interactive shell."""
    shell = FaraShell(args)
    shell.run()
