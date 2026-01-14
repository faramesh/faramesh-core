"""New fara action namespace commands with rich UX."""

from __future__ import annotations

import json
import sys
from typing import Any, Dict

from .cli import (
    HAS_RICH,
    _find_action_by_prefix,
    _get_auth_token,
    _get_base_url,
    _handle_request_error,
    _make_request,
    _print_error,
    _print_json,
    _print_success,
    _truncate_uuid,
)

if HAS_RICH:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table


def _parse_params(params_list: list[str]) -> Dict[str, Any]:
    """Parse --param key=value arguments into a dict.
    
    Supports:
    - --param key=value
    - --param key="value with spaces"
    - --param nested.key=value (creates nested dict)
    """
    result = {}
    for param_str in params_list:
        if '=' not in param_str:
            _print_error(f"Invalid parameter format: {param_str}. Use key=value")
            sys.exit(1)
        
        key, value = param_str.split('=', 1)
        key = key.strip()
        value = value.strip()
        
        # Remove quotes if present
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        
        # Try to parse as JSON (for numbers, booleans, arrays, objects)
        try:
            parsed_value = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            # If not valid JSON, treat as string
            parsed_value = value
        
        # Handle nested keys (e.g., "nested.key" -> {"nested": {"key": value}})
        if '.' in key:
            parts = key.split('.')
            current = result
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = parsed_value
        else:
            result[key] = parsed_value
    
    return result


def cmd_action_submit(args):
    """Submit a new action with rich UX."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Parse params from --param arguments
    params = _parse_params(args.param) if hasattr(args, 'param') and args.param else {}
    
    # Build request payload
    payload = {
        "agent_id": args.agent,
        "tool": args.tool,
        "operation": args.operation,
        "params": params,
    }
    
    if hasattr(args, 'context') and args.context:
        payload["context"] = _parse_params(args.context)
    
    try:
        r = _make_request("POST", f"{base_url}/v1/actions", json=payload, token=token)
        r.raise_for_status()
        action = r.json()
        
        if args.json:
            _print_json(action)
            return
        
        # Get action ID and status (used in both rich and plain output)
        action_id = action.get('id', 'N/A')
        short_id = _truncate_uuid(action_id, full=False)
        status = action.get('status', 'unknown')
        
        # Rich output with next-action suggestions
        if HAS_RICH:
            console = Console()
            
            # Status color
            status_colors = {
                'allowed': 'green',
                'approved': 'green',
                'pending_approval': 'yellow',
                'denied': 'red',
                'succeeded': 'green',
                'failed': 'red',
            }
            status_color = status_colors.get(status, 'white')
            
            # Display action summary
            
            table = Table(box=box.ROUNDED, show_header=False)
            table.add_column("Field", style="cyan", width=20)
            table.add_column("Value", style="white")
            
            table.add_row("Action ID", f"{short_id} ({action_id if len(action_id) > 8 else ''})")
            table.add_row("Status", f"[{status_color}]{status}[/{status_color}]")
            table.add_row("Decision", action.get('decision', 'N/A'))
            table.add_row("Risk Level", action.get('risk_level', 'N/A'))
            table.add_row("Tool", action.get('tool', 'N/A'))
            table.add_row("Operation", action.get('operation', 'N/A'))
            
            if action.get('reason'):
                table.add_row("Reason", action.get('reason'))
            
            console.print(Panel(table, title="Action Submitted", border_style="cyan"))
            
            # Next-action suggestions
            suggestions = []
            if status == 'pending_approval':
                suggestions.append(f"  • Approve: fara action approve {short_id}")
                suggestions.append(f"  • Deny: fara action deny {short_id}")
            elif status in ('allowed', 'approved'):
                suggestions.append(f"  • Start: fara action start {short_id}")
            elif status == 'denied':
                suggestions.append("  • Action was denied. Check policy or reason.")
            
            if suggestions:
                console.print("\n[cyan]Next steps:[/cyan]")
                for suggestion in suggestions:
                    console.print(suggestion)
            
            # SDK examples from API response
            if action.get('python_example') or action.get('js_example'):
                console.print("\n[cyan]SDK Examples:[/cyan]")
                if action.get('python_example'):
                    console.print("[bold]Python:[/bold]")
                    console.print(Panel(action['python_example'], border_style="blue", padding=(1, 1)))
                if action.get('js_example'):
                    console.print("[bold]JavaScript:[/bold]")
                    console.print(Panel(action['js_example'], border_style="yellow", padding=(1, 1)))
        else:
            # Fallback plain text
            print(f"✓ Action submitted: {short_id}")
            print(f"  Status: {status}")
            print(f"  Decision: {action.get('decision', 'N/A')}")
            if status == 'pending_approval':
                print(f"\nNext: fara action approve {short_id}")
            elif status in ('allowed', 'approved'):
                print(f"\nNext: fara action start {short_id}")
            
            # SDK examples from API response
            if action.get('python_example'):
                print("\nPython SDK Example:")
                print(action['python_example'])
            if action.get('js_example'):
                print("\nJavaScript SDK Example:")
                print(action['js_example'])
    except Exception as e:
        _handle_request_error(e, base_url)


def cmd_action_approve(args):
    """Approve a pending action."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Resolve action ID (supports prefix matching)
    action_id = None
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
        r.raise_for_status()
        action_id = args.id
    except Exception:
        matches = _find_action_by_prefix(base_url, args.id, token)
        if len(matches) == 0:
            _print_error(f"No action found matching '{args.id}'")
            sys.exit(1)
        elif len(matches) > 1:
            _print_error(f"Multiple actions match prefix '{args.id}':")
            for match in matches:
                print(f"  {match['id']} - {match.get('status', 'N/A')}", file=sys.stderr)
            sys.exit(1)
        action_id = matches[0]['id']
    
    # Get action to retrieve approval token
    r = _make_request("GET", f"{base_url}/v1/actions/{action_id}", token=token)
    r.raise_for_status()
    action = r.json()
    
    if action.get('status') != 'pending_approval':
        _print_error(f"Action {_truncate_uuid(action_id)} is not pending approval (status: {action.get('status')})")
        sys.exit(1)
    
    approval_token = action.get('approval_token')
    if not approval_token:
        _print_error("No approval token found")
        sys.exit(1)
    
    # Submit approval
    payload = {
        "token": approval_token,
        "approve": True,
        "reason": getattr(args, 'reason', None)
    }
    
    r = _make_request("POST", f"{base_url}/v1/actions/{action_id}/approval", json=payload, token=token)
    r.raise_for_status()
    result = r.json()
    
    if args.json:
        _print_json(result)
    else:
        _print_success(f"Action {_truncate_uuid(action_id)} approved")
        if HAS_RICH:
            console = Console()
            console.print(f"  Status: [green]{result.get('status', 'N/A')}[/green]")
            console.print(f"  Next: fara action start {_truncate_uuid(action_id)}")
        else:
            print(f"  Status: {result.get('status', 'N/A')}")
            print(f"  Next: fara action start {_truncate_uuid(action_id)}")


def cmd_action_deny(args):
    """Deny a pending action."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Resolve action ID
    action_id = None
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
        r.raise_for_status()
        action_id = args.id
    except Exception:
        matches = _find_action_by_prefix(base_url, args.id, token)
        if len(matches) == 0:
            _print_error(f"No action found matching '{args.id}'")
            sys.exit(1)
        elif len(matches) > 1:
            _print_error(f"Multiple actions match prefix '{args.id}':")
            for match in matches:
                print(f"  {match['id']} - {match.get('status', 'N/A')}", file=sys.stderr)
            sys.exit(1)
        action_id = matches[0]['id']
    
    # Get action
    r = _make_request("GET", f"{base_url}/v1/actions/{action_id}", token=token)
    r.raise_for_status()
    action = r.json()
    
    if action.get('status') != 'pending_approval':
        _print_error(f"Action {_truncate_uuid(action_id)} is not pending approval (status: {action.get('status')})")
        sys.exit(1)
    
    approval_token = action.get('approval_token')
    if not approval_token:
        _print_error("No approval token found")
        sys.exit(1)
    
    # Submit denial
    payload = {
        "token": approval_token,
        "approve": False,
        "reason": getattr(args, 'reason', None)
    }
    
    r = _make_request("POST", f"{base_url}/v1/actions/{action_id}/approval", json=payload, token=token)
    r.raise_for_status()
    result = r.json()
    
    if args.json:
        _print_json(result)
    else:
        _print_success(f"Action {_truncate_uuid(action_id)} denied")
        if HAS_RICH:
            console = Console()
            console.print(f"  Status: [red]{result.get('status', 'N/A')}[/red]")
        else:
            print(f"  Status: {result.get('status', 'N/A')}")


def cmd_action_start(args):
    """Start execution of an approved/allowed action."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Resolve action ID
    action_id = None
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
        r.raise_for_status()
        action_id = args.id
    except Exception:
        matches = _find_action_by_prefix(base_url, args.id, token)
        if len(matches) == 0:
            _print_error(f"No action found matching '{args.id}'")
            sys.exit(1)
        elif len(matches) > 1:
            _print_error(f"Multiple actions match prefix '{args.id}':")
            for match in matches:
                print(f"  {match['id']} - {match.get('status', 'N/A')}", file=sys.stderr)
            sys.exit(1)
        action_id = matches[0]['id']
    
    # Start execution
    r = _make_request("POST", f"{base_url}/v1/actions/{action_id}/start", token=token)
    r.raise_for_status()
    result = r.json()
    
    if args.json:
        _print_json(result)
    else:
        _print_success(f"Action {_truncate_uuid(action_id)} execution started")
        if HAS_RICH:
            console = Console()
            console.print(f"  Status: [blue]{result.get('status', 'N/A')}[/blue]")
        else:
            print(f"  Status: {result.get('status', 'N/A')}")


def cmd_action_replay(args):
    """Replay an action execution."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Resolve action ID
    action_id = None
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
        r.raise_for_status()
        action_id = args.id
    except Exception:
        matches = _find_action_by_prefix(base_url, args.id, token)
        if len(matches) == 0:
            _print_error(f"No action found matching '{args.id}'")
            sys.exit(1)
        elif len(matches) > 1:
            _print_error(f"Multiple actions match prefix '{args.id}':")
            for match in matches:
                print(f"  {match['id']} - {match.get('status', 'N/A')}", file=sys.stderr)
            sys.exit(1)
        action_id = matches[0]['id']
    
    # Get original action
    r = _make_request("GET", f"{base_url}/v1/actions/{action_id}", token=token)
    r.raise_for_status()
    original = r.json()
    
    if original.get('status') not in ('allowed', 'approved'):
        _print_error(f"Can only replay allowed/approved actions (current status: {original.get('status')})")
        sys.exit(1)
    
    # Create new action with same payload
    new_action = {
        "agent_id": original.get('agent_id'),
        "tool": original.get('tool'),
        "operation": original.get('operation'),
        "params": original.get('params', {}),
        "context": original.get('context', {})
    }
    
    r = _make_request("POST", f"{base_url}/v1/actions", json=new_action, token=token)
    r.raise_for_status()
    replayed = r.json()
    
    if args.json:
        _print_json(replayed)
    else:
        _print_success(f"Action replayed: {_truncate_uuid(replayed.get('id', 'N/A'))}")
        if HAS_RICH:
            console = Console()
            console.print(f"  Original: {_truncate_uuid(action_id)}")
            console.print(f"  New: {_truncate_uuid(replayed.get('id', 'N/A'))}")
            console.print(f"  Status: {replayed.get('status', 'N/A')}")
        else:
            print(f"  Original: {_truncate_uuid(action_id)}")
            print(f"  New: {_truncate_uuid(replayed.get('id', 'N/A'))}")
            print(f"  Status: {replayed.get('status', 'N/A')}")


def cmd_history(args):
    """Show action history (alias for list with better UX)."""
    from .cli import cmd_list
    # Map history args to list args
    args.limit = getattr(args, 'limit', 20)
    args.full = getattr(args, 'full', False)
    args.json = getattr(args, 'json', False)
    return cmd_list(args)
