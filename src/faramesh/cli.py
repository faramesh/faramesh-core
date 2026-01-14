from __future__ import annotations

# SPDX-License-Identifier: Elastic-2.0
import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

import requests

from .server.policy_engine import PolicyEngine
from .server.settings import get_settings

# Try to import optional dependencies for prettier output
try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False


# -------------------------- UTIL --------------------------

def _get_base_url(args: argparse.Namespace) -> str:
    """Get base URL with precedence: CLI args > ENV > defaults."""
    host = args.host if hasattr(args, 'host') and args.host else os.getenv("FARAMESH_HOST") or os.getenv("FARA_API_HOST", "127.0.0.1")
    port = args.port if hasattr(args, 'port') and args.port else int(os.getenv("FARAMESH_PORT") or os.getenv("FARA_API_PORT", "8000"))
    # Check if full URL is in env
    api_base = os.getenv("FARAMESH_BASE_URL") or os.getenv("FARA_API_BASE")
    if api_base:
        return api_base
    return f"http://{host}:{port}"


def _get_auth_token(args: argparse.Namespace) -> Optional[str]:
    """Get auth token with precedence: CLI args > ENV."""
    if hasattr(args, 'token') and args.token:
        return args.token
    return os.getenv("FARAMESH_TOKEN") or os.getenv("FARA_AUTH_TOKEN")


def _make_request(method: str, url: str, **kwargs) -> requests.Response:
    """Make HTTP request with auth token if available."""
    token = kwargs.pop('token', None)
    headers = kwargs.get('headers', {})
    if token:
        headers['Authorization'] = f'Bearer {token}'
    kwargs['headers'] = headers
    return requests.request(method, url, **kwargs)


def _print_json(obj: Any) -> None:
    """Print JSON output."""
    print(json.dumps(obj, indent=2, default=str))


def _print_error(msg: str) -> None:
    """Print error message."""
    if HAS_RICH:
        console = Console(file=sys.stderr)
        console.print(f"[red]❌ Error:[/red] {msg}")
    else:
        print(f"❌ Error: {msg}", file=sys.stderr)


def _print_success(msg: str) -> None:
    """Print success message."""
    if HAS_RICH:
        console = Console()
        console.print(f"[green]✓[/green] {msg}")
    else:
        print(f"✓ {msg}")


def _truncate_uuid(uuid_str: str, full: bool = False) -> str:
    """Truncate UUID to first 8 chars unless full is True."""
    if full or len(uuid_str) <= 8:
        return uuid_str
    return uuid_str[:8]


def _find_action_by_prefix(base_url: str, prefix: str, token: Optional[str] = None) -> list[dict]:
    """Find actions matching a prefix. Returns list of matching actions."""
    try:
        r = _make_request("GET", f"{base_url}/v1/actions", params={"limit": 1000}, token=token)
        r.raise_for_status()
        actions = r.json()
        matches = [a for a in actions if a['id'].startswith(prefix)]
        return matches
    except Exception:
        return []


def _format_table_rich(data: list[dict], columns: list[tuple], title: Optional[str] = None) -> None:
    """Format data as a rich table."""
    console = Console()
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    
    for col_name, col_key, width in columns:
        table.add_column(col_name, width=width, overflow="fold")
    
    for row in data:
        table.add_row(*[str(row.get(col_key, "")) for _, col_key, _ in columns])
    
    if title:
        console.print(Panel(table, title=title, border_style="cyan"))
    else:
        console.print(table)


def _format_table_tabulate(data: list[dict], columns: list[tuple]) -> None:
    """Format data as a tabulate table."""
    headers = [col_name for col_name, _, _ in columns]
    rows = []
    for row in data:
        rows.append([str(row.get(col_key, "")) for _, col_key, _ in columns])
    print(tabulate(rows, headers=headers, tablefmt="grid"))


def _format_table_plain(data: list[dict], columns: list[tuple]) -> None:
    """Format data as a plain text table."""
    # Calculate column widths
    widths = {}
    for col_name, col_key, width in columns:
        widths[col_key] = max(len(col_name), width or 0)
        for row in data:
            val = str(row.get(col_key, ""))
            if len(val) > widths[col_key]:
                widths[col_key] = len(val)
    
    # Print header
    header_parts = []
    for col_name, col_key, _ in columns:
        header_parts.append(col_name.ljust(widths[col_key]))
    print(" | ".join(header_parts))
    print("-" * (sum(widths.values()) + len(columns) * 3 - 3))
    
    # Print rows
    for row in data:
        row_parts = []
        for _, col_key, _ in columns:
            val = str(row.get(col_key, ""))
            row_parts.append(val.ljust(widths[col_key]))
        print(" | ".join(row_parts))


def _format_table(data: list[dict], columns: list[tuple], title: Optional[str] = None) -> None:
    """Format data as a table using the best available formatter."""
    if HAS_RICH:
        _format_table_rich(data, columns, title)
    elif HAS_TABULATE:
        _format_table_tabulate(data, columns)
    else:
        _format_table_plain(data, columns)


def _handle_request_error(e: Exception, base_url: str) -> None:
    """Handle request errors gracefully."""
    if isinstance(e, requests.exceptions.ConnectionError):
        _print_error(f"Could not connect to {base_url}")
        print("Make sure the server is running or set FARA_API_BASE environment variable", file=sys.stderr)
        sys.exit(1)
    elif isinstance(e, requests.exceptions.HTTPError):
        try:
            error_detail = e.response.text
        except Exception:
            error_detail = str(e)
        _print_error(f"HTTP {e.response.status_code}: {error_detail}")
        sys.exit(1)
    else:
        _print_error(str(e))
        sys.exit(1)


# -------------------------- HELP MENU --------------------------

def print_help() -> None:
    """Print a beautiful help menu."""
    # Sophisticated panther face ASCII art from panther.md
    panther = """

     
     
     
     
     
     
                                                  ,▄╗_
                                          _╓▄φ▓▓▓▌║▓║░
                                        ╓A║▓▓▓▓▓▓▓▓▓▓▓▄,
                                      ╓ÆV▓▓▓▓▓▓▓▓▓▓▓▓▓▀▓░
                                    ▄#▀╠╣╫▓▓▓▓▓▓▓H▓▓▓▓▌║▒
                                  ╓▀╣▓▓▓▓▓▓▓▓▓Å▓▓▄╙▓▓▓▓▓▀H
                                 ╔Ñ╣▓▓▓▓▓▓▓▓▓▓▓░║▓▓▓▓▓▓╝╙
                                 ▓H╠▓▓▓▓▓▓▓▓▓▓▓▓▄║▒ ╙▀╙
                               ,▓Ñφ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▌║▒
                              ╔▓╓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▌▓░
                             ╔▓╔▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓║▓▓▓║▌
                            ╓▓\▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▓▓▓║▌
                            ╣▒║▓▓▓▓▓▓▓▓▓▓▓▓▓▓║▓▓J▓▌▓M
                         ╓#%▀░╣▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒║▓H╫▓▓_
                        φ▌φ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓φ▌▓▓Ö▓,
                       ╓▓▐▓▓▓▓▓▓▓▓▓▓▓▓▓▌▓▓▓▓▓▓▓▓▓▀╣▓╙▌
                       ║▌║▓▓╝▓▓▓▓▓▓▓▓▓▓▌║▓▓▓▓▓▓▓▒▓▓▓▒▓▄▄▄▄,
                       ╙▓║▓▓▓Å▓▓▓▓▌╫▓▓▓▓╙▓▓▓▓▓▌φ▓▓▓▓▓▓▓▓▓▓▓▓▄,
                        ▓▒▓▓▓▓╬▓▓▓▓╙▓▓▓▓⌐╫▓▓▓▓▒▓▓▓▓▓▓░└└╙▀▌╙▓▓▄
                        ╙▓▒▓▓▓▓▓▓▓▓▓Å▓▓▌%░╙▓▓▓▓▓▓▓▓╫Ñ     ║▌⌠▓▓H
                         └╫▄╙▓▓▓▓▓▓▌▓╬▓▓▓╬▀▄╠╠▀▓▓▌ª╠▌╗_ ,▄▓Ñ╔▓▓▒
                          j▒▓▄╠▀▓▓▓▓▄╙▓▓▓▓▓▓▓▓▓▀▓▓▓▓▓▓▓▀▀╠▄▓▓▓▓¬
                           ²╙▓▓▓▓▓▀▀▀╙╙╙▀▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓╙
                              ¬└          └╙╙▀▀▓▓▓▓▓▓▓▓▀▀▀╙,
     
     
     
     
     
     
    
"""
    
    if HAS_RICH:
        console = Console()
        from rich.text import Text
        
        # Create yellow panther on navy blue background
        # Use rich's styling to fill the entire panel with navy blue
        panther_lines = panther.strip().split('\n')
        styled_lines = []
        for line in panther_lines:
            styled_lines.append(Text(line, style="yellow on navy_blue"))
        
        panther_text = Text("\n").join(styled_lines)
        console.print(Panel(
            panther_text, 
            border_style="yellow", 
            padding=(1, 2), 
            box=box.ROUNDED,
            style="on navy_blue"
        ))
    else:
        # Fallback: print with ANSI codes if terminal supports it
        try:
            # Navy blue background: \033[44m, Yellow text: \033[33m, Reset: \033[0m
            panther_lines = panther.strip().split('\n')
            for line in panther_lines:
                print("\033[44m\033[33m" + line + "\033[0m")
        except Exception:
            # Ultimate fallback: just print the panther
            print(panther.strip())
    
    print("\n[Action Management]")
    print("  list              List recent actions")
    print("  list --full       List with full UUIDs and params")
    print("  list --json       Output as JSON")
    print("  get <id>          Get action details (supports prefix)")
    print("  get <id> --json   Get action as JSON")
    print("  tail              Stream live actions via SSE (like kubectl logs)")
    print("  approve <id>      Approve a pending action (supports prefix)")
    print("  deny <id>         Deny a pending action (supports prefix)")
    print("  logs <id>         Show status transitions for an action")
    print("  events <id>       Show event timeline for an action")
    print("  curl <id>         Print ready-to-copy curl commands")
    print("  allow <id>        Alias for approve")
    print("  replay <id>       Replay an allowed/approved action")
    print("")
    print("[DX Commands]")
    print("  init              Scaffold a working starter layout")
    print("  explain <id>      Explain why an action was allowed/denied")
    print("  build-ui          Build the web UI")
    print("  doctor            Sanity check user environment")
    print("  policy-diff <old> <new>  Show differences between policy files")
    print("  init-docker       Generate Docker configuration files")
    print("")
    print("[Policy Management]")
    print("  policy-test <file>    Test action against policy")
    print("  policy-validate <file> Validate policy file")
    print("  policy-refresh        Refresh policy cache")
    print("")
    print("[Server Management]")
    print("  serve            Start the Faramesh server")
    print("  serve --watch    Start server with policy hot-reload")
    print("  migrate          Run database migrations")
    print("")
    print("[Global Options]")
    print("  --host HOST      API host (default: 127.0.0.1)")
    print("  --port PORT      API port (default: 8000)")
    print("  --token TOKEN    Auth token override")
    print("")
    print("[Examples]")
    print("  faramesh list")
    print("  faramesh list --full")
    print("  faramesh list --json")
    print("  faramesh get 2755d4a8")
    print("  faramesh get 2755d4a8 --json")
    print("  faramesh approve 2755d4a8")
    print("  faramesh curl 2755d4a8")
    print("  faramesh tail")
    print("  faramesh logs 2755d4a8")
    print("  faramesh --host localhost --port 9000 list")
    print("")


# -------------------------- POLICY COMMANDS --------------------------

def cmd_policy_test(args):
    """Evaluate a JSON action file against the active policy."""
    try:
        settings = get_settings()
        engine = PolicyEngine(settings.policy_file)

        with open(args.file) as f:
            data = json.load(f)

        tool = data["tool"]
        op = data["operation"]
        params = data.get("params", {})
        ctx = data.get("context", {})

        decision, reason, risk = engine.evaluate(tool, op, params, ctx)

        out = {
            "decision": decision.value,
            "reason": reason,
            "risk": risk,
            "policy_version": engine.policy_version(),
        }

        if args.json:
            _print_json(out)
        else:
            status_icon = "✓" if decision.value == "allow" else "❌"
            print(f"{status_icon} Decision: {decision.value.upper()}")
            print(f"   Reason: {reason}")
            print(f"   Risk: {risk or 'N/A'}")
            print(f"   Policy: {engine.policy_version()}")

        if decision.value == "deny":
            sys.exit(1)
    except FileNotFoundError:
        _print_error(f"File not found: {args.file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        _print_error(f"Invalid JSON: {e}")
        sys.exit(1)
    except Exception as e:
        _print_error(f"Policy test failed: {e}")
        sys.exit(1)


def cmd_policy_refresh(args):
    try:
        settings = get_settings()
        engine = PolicyEngine(settings.policy_file)
        engine.refresh()
        _print_success(f"Policy refreshed. Active version: {engine.policy_version()}")
    except Exception as e:
        _print_error(f"Failed to refresh policy: {e}")
        sys.exit(1)


def cmd_policy_validate(args):
    """Validate a policy file and print errors if any."""
    try:
        PolicyEngine(args.file)
        _print_success("Policy is valid")
    except Exception as e:
        _print_error(f"Policy invalid: {e}")
        sys.exit(1)


def cmd_policy_new(args):
    """Scaffold a new policy file into policies/user/ directory."""
    from pathlib import Path
    
    # Create policies/user directory if it doesn't exist
    # Use current working directory, not package root
    base_path = Path.cwd()
    user_policies_dir = base_path / "policies" / "user"
    user_policies_dir.mkdir(parents=True, exist_ok=True)
    
    # Create policy file
    policy_file = user_policies_dir / f"{args.name}.yaml"
    
    # Also try package root if cwd doesn't have policies
    if not (base_path / "policies").exists():
        package_root = Path(__file__).resolve().parents[2]
        alt_user_policies_dir = package_root / "policies" / "user"
        alt_user_policies_dir.mkdir(parents=True, exist_ok=True)
        policy_file = alt_user_policies_dir / f"{args.name}.yaml"
    
    if policy_file.exists():
        _print_error(f"Policy file already exists: {policy_file}")
        _print_error("Use a different name or delete the existing file.")
        sys.exit(1)
    
    # Template policy content
    template = f"""# Policy: {args.name}
# Custom policy rules for {args.name}

rules:
  # Example: Allow HTTP GET requests
  - match:
      tool: http
      op: get
    allow: true
    description: "Allow HTTP GET requests"
    risk: low

  # Example: Require approval for shell commands
  - match:
      tool: shell
      op: "*"
    require_approval: true
    description: "Require approval for shell commands"
    risk: high

  # Default deny (should be last)
  - match:
      tool: "*"
      op: "*"
    deny: true
    description: "Default deny - deny unknown actions"
    risk: high

# Optional: Risk scoring rules
# risk:
#   rules:
#     - name: dangerous_patterns
#       when:
#         tool: shell
#         pattern: "rm -rf|shutdown|reboot"
#       risk_level: high
"""
    
    policy_file.write_text(template)
    
    if HAS_RICH:
        console = Console()
        console.print(f"[green]✓[/green] Created policy file: {policy_file}")
        console.print("\n[cyan]Next steps:[/cyan]")
        console.print(f"  1. Edit {policy_file} to customize rules")
        console.print("  2. Test with: [bold]fara policy-test <action.json>[/bold]")
        console.print(f"  3. Validate with: [bold]fara policy-validate {policy_file}[/bold]")
    else:
        print(f"✓ Created policy file: {policy_file}")
        print("\nNext steps:")
        print(f"  1. Edit {policy_file} to customize rules")
        print("  2. Test with: fara policy-test <action.json>")
        print(f"  3. Validate with: fara policy-validate {policy_file}")


# -------------------------- ACTION COMMANDS --------------------------

def cmd_list(args):
    """List recent actions with status and truncated params."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    try:
        params = {"limit": args.limit}
        r = _make_request("GET", f"{base_url}/v1/actions", params=params, token=token)
        r.raise_for_status()
        actions = r.json()
        
        if args.json:
            _print_json(actions)
            return
        
        if not actions:
            print("No actions found.")
            return
        
        # Prepare table data with colors
        table_data = []
        for a in actions:
            action_id = a['id'] if args.full else _truncate_uuid(a['id'])
            params_str = json.dumps(a.get("params", {}))
            if not args.full and len(params_str) > 50:
                params_str = params_str[:47] + "..."
            
            status = a.get('status', 'N/A')
            risk = a.get('risk_level', 'N/A')
            
            table_data.append({
                'id': action_id,
                'status': status,
                'risk': risk,
                'tool': a.get('tool', 'N/A'),
                'operation': a.get('operation', 'N/A'),
                'params': params_str,
                'created': a.get('created_at', '')[:19] if a.get('created_at') else 'N/A',
            })
        
        # Color-coded columns
        if HAS_RICH:
            console = Console()
            table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
            table.add_column("ID", style="cyan", width=12 if args.full else 10)
            table.add_column("Status", width=18)
            table.add_column("Risk", width=8)
            table.add_column("Tool", style="yellow", width=12)
            table.add_column("Operation", style="yellow", width=15)
            table.add_column("Params", style="green", width=40)
            table.add_column("Created", style="blue", width=20)
            
            for row in table_data:
                status = row['status']
                risk = row['risk']
                
                # Color status
                status_color = {
                    'denied': 'red',
                    'pending_approval': 'yellow',
                    'allowed': 'green',
                    'approved': 'green',
                    'succeeded': 'green',
                    'failed': 'red',
                    'executing': 'blue'
                }.get(status, 'white')
                
                # Color risk
                risk_color = {
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'green'
                }.get(risk, 'white')
                
                table.add_row(
                    row['id'],
                    f"[{status_color}]{status}[/{status_color}]",
                    f"[{risk_color}]{risk}[/{risk_color}]",
                    row['tool'],
                    row['operation'],
                    row['params'],
                    row['created']
                )
            
            console.print(Panel(table, title=f"Actions ({len(actions)})", border_style="cyan"))
        else:
            columns = [
                ("ID", "id", 12 if args.full else 10),
                ("Status", "status", 18),
                ("Risk", "risk", 8),
                ("Tool", "tool", 12),
                ("Operation", "operation", 15),
                ("Params", "params", 40),
                ("Created", "created", 20),
            ]
            _format_table(table_data, columns, title=f"Actions ({len(actions)})")
        
    except Exception as e:
        _handle_request_error(e, base_url)


def cmd_get(args):
    """Get action details by ID."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Try direct fetch first (in case it's a full UUID)
    action_id = args.id
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
        r.raise_for_status()
    except Exception:
        # Not a full UUID, try prefix matching
        matches = _find_action_by_prefix(base_url, args.id, token)
        
        if len(matches) == 0:
            _print_error(f"No action found matching '{args.id}'")
            sys.exit(1)
        elif len(matches) > 1:
            _print_error(f"Multiple actions match prefix '{args.id}':")
            for match in matches:
                print(f"  {match['id']} - {match.get('status', 'N/A')}", file=sys.stderr)
            print("Please use a longer prefix to uniquely identify the action.", file=sys.stderr)
            sys.exit(1)
        
        action_id = matches[0]['id']
    
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{action_id}", token=token)
        r.raise_for_status()
        action = r.json()
        
        if args.json:
            _print_json(action)
        else:
            if HAS_RICH:
                console = Console()
                table = Table(box=box.ROUNDED, show_header=False)
                table.add_column("Field", style="cyan", width=20)
                table.add_column("Value", style="white")
                
                table.add_row("ID", action['id'])
                table.add_row("Status", action.get('status', 'N/A'))
                table.add_row("Tool", action.get('tool', 'N/A'))
                table.add_row("Operation", action.get('operation', 'N/A'))
                table.add_row("Decision", action.get('decision', 'N/A'))
                table.add_row("Reason", action.get('reason', 'N/A'))
                table.add_row("Risk Level", action.get('risk_level', 'N/A'))
                table.add_row("Created", action.get('created_at', 'N/A'))
                table.add_row("Updated", action.get('updated_at', 'N/A'))
                table.add_row("Params", json.dumps(action.get('params', {}), indent=2))
                
                console.print(Panel(table, title=f"Action {action['id']}", border_style="cyan"))
            else:
                print(f"ID: {action['id']}")
                print(f"Status: {action.get('status', 'N/A')}")
                print(f"Tool: {action.get('tool', 'N/A')}")
                print(f"Operation: {action.get('operation', 'N/A')}")
                print(f"Decision: {action.get('decision', 'N/A')}")
                print(f"Reason: {action.get('reason', 'N/A')}")
                print(f"Risk Level: {action.get('risk_level', 'N/A')}")
                print(f"Created: {action.get('created_at', 'N/A')}")
                print(f"Updated: {action.get('updated_at', 'N/A')}")
                print(f"Params: {json.dumps(action.get('params', {}), indent=2)}")
    except Exception as e:
        _handle_request_error(e, base_url)


def cmd_tail(args):
    """Stream live actions via SSE (like kubectl logs)."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Try SSE first, fallback to polling
    sse_url = f"{base_url}/v1/events"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    if HAS_RICH:
        console = Console()
        console.print("[cyan]Streaming actions (press CTRL+C to stop)...[/cyan]\n")
    else:
        print("Streaming actions (press CTRL+C to stop)...\n")
    
    try:
        import sseclient
        response = requests.get(sse_url, headers=headers, stream=True, timeout=None)
        response.raise_for_status()
        
        client = sseclient.SSEClient(response)
        
        for event in client.events():
            if event.event == 'message' or not event.event:
                try:
                    data = json.loads(event.data)
                    event_type = data.get('type', '')
                    action_data = data.get('data', {})
                    
                    if 'action.' in event_type:
                        action_id = _truncate_uuid(action_data.get('id', ''))
                        status = action_data.get('status', 'N/A')
                        tool = action_data.get('tool', 'N/A')
                        op = action_data.get('operation', 'N/A')
                        
                        # Color code by status
                        status_colors = {
                            'denied': 'red',
                            'pending_approval': 'yellow',
                            'allowed': 'green',
                            'approved': 'green',
                            'succeeded': 'green',
                            'failed': 'red',
                            'executing': 'blue'
                        }
                        color = status_colors.get(status, 'white')
                        
                        timestamp = time.strftime('%H:%M:%S')
                        
                        if HAS_RICH:
                            console.print(f"[{timestamp}] [{color}]{status:18}[/{color}] {action_id} | {tool:12} | {op}")
                        else:
                            print(f"[{timestamp}] {status:18} {action_id} | {tool:12} | {op}")
                except (json.JSONDecodeError, KeyError):
                    pass
    except ImportError:
        # Fallback to polling if sseclient not available
        if HAS_RICH:
            console = Console()
            console.print("[yellow]sseclient not installed, falling back to polling...[/yellow]")
        else:
            print("sseclient not installed, falling back to polling...")
        
        seen_ids = set()
        while True:
            try:
                r = _make_request("GET", f"{base_url}/v1/actions", params={"limit": 50}, token=token)
                r.raise_for_status()
                actions = r.json()
                
                new_actions = [a for a in actions if a['id'] not in seen_ids]
                if new_actions:
                    for action in reversed(new_actions):
                        action_id = _truncate_uuid(action['id'])
                        status = action.get('status', 'N/A')
                        tool = action.get('tool', 'N/A')
                        op = action.get('operation', 'N/A')
                        
                        status_colors = {
                            'denied': 'red',
                            'pending_approval': 'yellow',
                            'allowed': 'green',
                            'approved': 'green',
                            'succeeded': 'green',
                            'failed': 'red'
                        }
                        color = status_colors.get(status, 'white')
                        timestamp = time.strftime('%H:%M:%S')
                        
                        if HAS_RICH:
                            console.print(f"[{timestamp}] [{color}]{status:18}[/{color}] {action_id} | {tool:12} | {op}")
                        else:
                            print(f"[{timestamp}] {status:18} {action_id} | {tool:12} | {op}")
                        seen_ids.add(action['id'])
                
                time.sleep(2)
            except KeyboardInterrupt:
                break
            except Exception as e:
                _handle_request_error(e, base_url)
                break
    except KeyboardInterrupt:
        if HAS_RICH:
            console = Console()
            console.print("\n[green]✓[/green] Stopped streaming")
        else:
            print("\n✓ Stopped streaming")
    except Exception as e:
        _handle_request_error(e, base_url)


def cmd_logs(args):
    """Show status transitions for an action."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Try direct fetch first (in case it's a full UUID)
    action_id = args.id
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
        r.raise_for_status()
    except Exception:
        # Not a full UUID, try prefix matching
        matches = _find_action_by_prefix(base_url, args.id, token)
        
        if len(matches) == 0:
            _print_error(f"No action found matching '{args.id}'")
            sys.exit(1)
        elif len(matches) > 1:
            _print_error(f"Multiple actions match prefix '{args.id}':")
            for match in matches:
                print(f"  {match['id']} - {match.get('status', 'N/A')}", file=sys.stderr)
            print("Please use a longer prefix to uniquely identify the action.", file=sys.stderr)
            sys.exit(1)
        
        action_id = matches[0]['id']
    
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{action_id}", token=token)
        r.raise_for_status()
        action = r.json()
        
        if args.json:
            _print_json(action)
        else:
            print(f"Action: {action['id']}")
            print(f"Status: {action.get('status', 'N/A')}")
            print(f"Decision: {action.get('decision', 'N/A')}")
            print(f"Reason: {action.get('reason', 'N/A')}")
            print("\nTimeline:")
            print(f"  Created: {action.get('created_at', 'N/A')}")
            print(f"  Updated: {action.get('updated_at', 'N/A')}")
            
            # Show status history if available
            if action.get('status') == 'pending_approval':
                print("\n  → Currently awaiting approval")
            elif action.get('status') == 'approved':
                print(f"\n  → Approved at {action.get('updated_at', 'N/A')}")
            elif action.get('status') == 'denied':
                print(f"\n  → Denied at {action.get('updated_at', 'N/A')}")
    except Exception as e:
        _handle_request_error(e, base_url)


def cmd_events(args):
    """Show event timeline for an action."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Try direct fetch first (in case it's a full UUID)
    action_id = args.id
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
        r.raise_for_status()
    except Exception:
        # Not a full UUID, try prefix matching
        matches = _find_action_by_prefix(base_url, args.id, token)
        
        if len(matches) == 0:
            _print_error(f"No action found matching '{args.id}'")
            sys.exit(1)
        elif len(matches) > 1:
            _print_error(f"Multiple actions match prefix '{args.id}':")
            for match in matches:
                print(f"  {match['id']} - {match.get('status', 'N/A')}", file=sys.stderr)
            print("Please use a longer prefix to uniquely identify the action.", file=sys.stderr)
            sys.exit(1)
        
        action_id = matches[0]['id']
    
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{action_id}/events", token=token)
        r.raise_for_status()
        events = r.json()
        
        if args.json:
            _print_json(events)
        else:
            if HAS_RICH:
                console = Console()
                table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
                table.add_column("Time", style="cyan", width=20)
                table.add_column("Event", style="white", width=20)
                table.add_column("Details", style="yellow")
                
                for event in events:
                    time_str = event.get('created_at', '')[:19] if event.get('created_at') else 'N/A'
                    event_type = event.get('event_type', 'N/A')
                    meta = event.get('meta', {})
                    details = json.dumps(meta) if meta else ''
                    if len(details) > 60:
                        details = details[:57] + "..."
                    table.add_row(time_str, event_type, details)
                
                console.print(Panel(table, title=f"Event Timeline - {action_id[:8]}", border_style="cyan"))
            else:
                print(f"Event Timeline for {action_id}")
                print("=" * 60)
                for event in events:
                    time_str = event.get('created_at', '')[:19] if event.get('created_at') else 'N/A'
                    event_type = event.get('event_type', 'N/A')
                    meta = event.get('meta', {})
                    print(f"{time_str} | {event_type:20} | {json.dumps(meta) if meta else ''}")
    except Exception as e:
        _handle_request_error(e, base_url)


def _approve_action(base_url: str, action_id: str, approve: bool, reason: Optional[str], token: Optional[str] = None, json_output: bool = False) -> None:
    """Approve or deny an action."""
    try:
        # First get the action to retrieve approval token
        r = _make_request("GET", f"{base_url}/v1/actions/{action_id}", token=token)
        r.raise_for_status()
        data = r.json()

        token_val = data.get("approval_token")
        if not token_val:
            status = data.get('status', 'N/A')
            if status in ('approved', 'denied', 'allowed', 'succeeded', 'failed'):
                # Action already processed, just inform user
                action_word = "approved" if approve else "denied"
                if json_output:
                    _print_json(data)
                else:
                    _print_error(f"Action {action_id[:8]} is already {status}. Cannot {action_word}.")
                    print(f"Current status: {status}", file=sys.stderr)
                # Exit with 0 for already-processed actions (informational)
                return
            else:
                _print_error("No approval token found (action may already be approved/denied)")
                print(f"Current status: {status}", file=sys.stderr)
                sys.exit(1)

        # Submit approval
        r = _make_request(
            "POST",
            f"{base_url}/v1/actions/{action_id}/approval",
            json={"token": token_val, "approve": approve, "reason": reason},
            token=token
        )
        r.raise_for_status()
        result = r.json()
        
        if json_output:
            _print_json(result)
        else:
            action = "approved" if approve else "denied"
            _print_success(f"Action {action_id[:8]} {action}")
            print(f"  Status: {result.get('status', 'N/A')}")
            print(f"  Reason: {result.get('reason', 'N/A')}")
    except Exception as e:
        _handle_request_error(e, base_url)


def cmd_approve(args):
    """Approve a pending action."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Try direct fetch first (in case it's a full UUID)
    action_id = None
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
        r.raise_for_status()
        action_id = args.id  # Full UUID worked
    except Exception:
        # Not a full UUID, try prefix matching
        matches = _find_action_by_prefix(base_url, args.id, token)
        
        if len(matches) == 0:
            _print_error(f"No action found matching '{args.id}'")
            sys.exit(1)
        elif len(matches) > 1:
            _print_error(f"Multiple actions match prefix '{args.id}':")
            for match in matches:
                print(f"  {match['id']} - {match.get('status', 'N/A')}", file=sys.stderr)
            print("Please use a longer prefix to uniquely identify the action.", file=sys.stderr)
            sys.exit(1)
        
        action_id = matches[0]['id']
    
    _approve_action(base_url, action_id, True, args.reason, token, json_output=getattr(args, 'json', False))


def cmd_deny(args):
    """Deny a pending action."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Try direct fetch first (in case it's a full UUID)
    action_id = None
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
        r.raise_for_status()
        action_id = args.id  # Full UUID worked
    except Exception:
        # Not a full UUID, try prefix matching
        matches = _find_action_by_prefix(base_url, args.id, token)
        
        if len(matches) == 0:
            _print_error(f"No action found matching '{args.id}'")
            sys.exit(1)
        elif len(matches) > 1:
            _print_error(f"Multiple actions match prefix '{args.id}':")
            for match in matches:
                print(f"  {match['id']} - {match.get('status', 'N/A')}", file=sys.stderr)
            print("Please use a longer prefix to uniquely identify the action.", file=sys.stderr)
            sys.exit(1)
        
        action_id = matches[0]['id']
    
    _approve_action(base_url, action_id, False, args.reason, token, json_output=getattr(args, 'json', False))


def cmd_allow(args):
    """Alias for approve."""
    cmd_approve(args)


def cmd_curl(args):
    """Print ready-to-copy curl commands for an action."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Try direct fetch first (in case it's a full UUID)
    action_id = args.id
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
        r.raise_for_status()
    except Exception:
        # Not a full UUID, try prefix matching
        matches = _find_action_by_prefix(base_url, args.id, token)
        
        if len(matches) == 0:
            _print_error(f"No action found matching '{args.id}'")
            sys.exit(1)
        elif len(matches) > 1:
            _print_error(f"Multiple actions match prefix '{args.id}':")
            for match in matches:
                print(f"  {match['id']} - {match.get('status', 'N/A')}", file=sys.stderr)
            print("Please use a longer prefix to uniquely identify the action.", file=sys.stderr)
            sys.exit(1)
        
        action_id = matches[0]['id']
    
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{action_id}", token=token)
        r.raise_for_status()
        action = r.json()
        
        status = action.get('status', '')
        approval_token = action.get('approval_token')
        
        print(f"# Action: {action_id}")
        print(f"# Status: {status}\n")
        
        if status == 'pending_approval' and approval_token:
            print("# Approve:")
            curl_lines = [f'curl -X POST {base_url}/v1/actions/{action_id}/approval \\']
            if token:
                curl_lines.append(f'  -H "Authorization: Bearer {token}" \\')
            curl_lines.append('  -H "Content-Type: application/json" \\')
            curl_lines.append(f'  -d \'{{"token": "{approval_token}", "approve": true}}\'')
            print('\n'.join(curl_lines))
            print()
            print("# Deny:")
            curl_lines = [f'curl -X POST {base_url}/v1/actions/{action_id}/approval \\']
            if token:
                curl_lines.append(f'  -H "Authorization: Bearer {token}" \\')
            curl_lines.append('  -H "Content-Type: application/json" \\')
            curl_lines.append(f'  -d \'{{"token": "{approval_token}", "approve": false}}\'')
            print('\n'.join(curl_lines))
        elif status in ('approved', 'allowed'):
            print("# Start execution:")
            curl_lines = [f'curl -X POST {base_url}/v1/actions/{action_id}/start']
            if token:
                curl_lines[0] += ' \\'
                curl_lines.append(f'  -H "Authorization: Bearer {token}"')
            print('\n'.join(curl_lines))
        elif status in ('denied', 'succeeded', 'failed'):
            print("No followup supported for this status.")
        else:
            print(f"# Status '{status}' does not support curl commands.")
            
    except Exception as e:
        _handle_request_error(e, base_url)


# ------------------------- PARSER -------------------------

def make_parser():
    p = argparse.ArgumentParser(
        prog="faramesh",
        description="Faramesh - Agent Action Governor CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False  # We'll handle help manually
    )
    
    # Global flags
    p.add_argument("--host", type=str, help="API host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, help="API port (default: 8000)")
    p.add_argument("--token", type=str, help="Auth token override")
    p.add_argument("--json", action="store_true", help="Output as JSON")
    p.add_argument("-h", "--help", action="store_true", help="Show help message")
    
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")
    
    # List command
    p_list = sub.add_parser("list", help="List recent actions")
    p_list.add_argument("--limit", type=int, default=20, help="Limit number of results")
    p_list.add_argument("--full", action="store_true", help="Show full UUIDs")
    p_list.add_argument("--json", action="store_true", help="Output as JSON")
    p_list.set_defaults(func=cmd_list)
    
    # Get command
    p_get = sub.add_parser("get", help="Get action details")
    p_get.add_argument("id", help="Action ID")
    p_get.add_argument("--json", action="store_true", help="Output as JSON")
    p_get.set_defaults(func=cmd_get)
    
    # Tail command
    p_tail = sub.add_parser("tail", help="Watch new actions (polling)")
    p_tail.set_defaults(func=cmd_tail)
    
    # Approve command
    p_approve = sub.add_parser("approve", help="Approve a pending action")
    p_approve.add_argument("id", help="Action ID or prefix")
    p_approve.add_argument("--reason", default=None, help="Approval reason")
    p_approve.add_argument("--json", action="store_true", help="Output as JSON")
    p_approve.set_defaults(func=cmd_approve)
    
    # Deny command
    p_deny = sub.add_parser("deny", help="Deny a pending action")
    p_deny.add_argument("id", help="Action ID or prefix")
    p_deny.add_argument("--reason", default=None, help="Denial reason")
    p_deny.add_argument("--json", action="store_true", help="Output as JSON")
    p_deny.set_defaults(func=cmd_deny)
    
    # Allow command (alias)
    p_allow = sub.add_parser("allow", help="Alias for approve")
    p_allow.add_argument("id", help="Action ID or prefix")
    p_allow.add_argument("--reason", default=None, help="Approval reason")
    p_allow.add_argument("--json", action="store_true", help="Output as JSON")
    p_allow.set_defaults(func=cmd_allow)
    
    # Logs command
    p_logs = sub.add_parser("logs", help="Show status transitions for an action")
    p_logs.add_argument("id", help="Action ID")
    p_logs.add_argument("--json", action="store_true", help="Output as JSON")
    p_logs.set_defaults(func=cmd_logs)
    
    # Events command
    p_events = sub.add_parser("events", help="Show event timeline for an action")
    p_events.add_argument("id", help="Action ID or prefix")
    p_events.add_argument("--json", action="store_true", help="Output as JSON")
    p_events.set_defaults(func=cmd_events)
    
    # Curl command
    p_curl = sub.add_parser("curl", help="Print ready-to-copy curl commands for an action")
    p_curl.add_argument("id", help="Action ID or prefix")
    p_curl.set_defaults(func=cmd_curl)
    
    # Server command
    p_serve = sub.add_parser("serve", help="Start the Faramesh server")
    p_serve.add_argument("--host", type=str, default=None, help="Host to bind to (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=None, help="Port to bind to (default: 8000)")
    p_serve.add_argument("--reload", action="store_true", help="Enable auto-reload (development)")
    p_serve.add_argument("--watch", action="store_true", help="Hot reload policy file when modified (deprecated, use --hot-reload)")
    p_serve.add_argument("--hot-reload", action="store_true", help="Hot reload policy file when modified (local mode only)")
    p_serve.add_argument("--log-level", type=str, default="info", 
                        choices=["critical", "error", "warning", "info", "debug", "trace"], 
                        help="Log level")
    p_serve.set_defaults(func=cmd_serve)
    
    # Policy commands (both namespace and hyphenated for compatibility)
    def _setup_policy_commands():
        p_policy = sub.add_parser("policy", help="Policy management commands")
        policy_sub = p_policy.add_subparsers(dest="policy_cmd", metavar="SUBCOMMAND")
        
        # policy new
        p_policy_new = policy_sub.add_parser("new", help="Scaffold a new policy file")
        p_policy_new.add_argument("name", help="Policy name (without .yaml extension)")
        p_policy_new.set_defaults(func=cmd_policy_new)
        
        # policy validate
        p_policy_validate = policy_sub.add_parser("validate", help="Validate policy file")
        p_policy_validate.add_argument("file", help="Policy file path")
        p_policy_validate.set_defaults(func=cmd_policy_validate)
        
        # policy test
        p_policy_test = policy_sub.add_parser("test", help="Test action against policy")
        p_policy_test.add_argument("file", help="JSON action file")
        p_policy_test.add_argument("--json", action="store_true", help="Output as JSON")
        p_policy_test.set_defaults(func=cmd_policy_test)
        
        # policy diff
        p_policy_diff = policy_sub.add_parser("diff", help="Show differences between two policy files")
        p_policy_diff.add_argument("old_file", help="Old policy file path")
        p_policy_diff.add_argument("new_file", help="New policy file path")
        p_policy_diff.set_defaults(func=cmd_policy_diff)
    
    _setup_policy_commands()
    
    # Also keep hyphenated versions for backward compatibility
    p_pt = sub.add_parser("policy-test", help="Test action against policy (alias)")
    p_pt.add_argument("file", help="JSON action file")
    p_pt.add_argument("--json", action="store_true", help="Output as JSON")
    p_pt.set_defaults(func=cmd_policy_test)
    
    p_pr = sub.add_parser("policy-refresh", help="Refresh policy cache")
    p_pr.set_defaults(func=cmd_policy_refresh)
    
    p_pv = sub.add_parser("policy-validate", help="Validate policy file (alias)")
    p_pv.add_argument("file", help="Policy file path")
    p_pv.set_defaults(func=cmd_policy_validate)
    
    p_pn = sub.add_parser("policy-new", help="Scaffold a new policy file (alias)")
    p_pn.add_argument("name", help="Policy name (without .yaml extension)")
    p_pn.set_defaults(func=cmd_policy_new)
    
    p_policy_diff_alias = sub.add_parser("policy-diff", help="Show differences between two policy files (alias)")
    p_policy_diff_alias.add_argument("old_file", help="Old policy file path")
    p_policy_diff_alias.add_argument("new_file", help="New policy file path")
    p_policy_diff_alias.set_defaults(func=cmd_policy_diff)
    
    # Migration command
    p_migrate = sub.add_parser("migrate", help="Run database migrations")
    p_migrate.set_defaults(func=cmd_migrate)
    
    # DX Commands
    p_init = sub.add_parser("init", help="Scaffold a working starter layout")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing files")
    p_init.set_defaults(func=cmd_init)
    
    p_explain = sub.add_parser("explain", help="Explain why an action was allowed, denied, or required approval")
    p_explain.add_argument("id", help="Action ID or prefix")
    p_explain.set_defaults(func=cmd_explain)
    
    p_verify_log = sub.add_parser("verify-log", help="Verify tamper-evident audit log chain for an action")
    p_verify_log.add_argument("id", help="Action ID or prefix")
    p_verify_log.set_defaults(func=cmd_verify_log)
    
    p_replay_decision = sub.add_parser("replay-decision", help="Replay a decision to verify determinism")
    p_replay_decision.add_argument("id", nargs="?", help="Action ID or prefix")
    p_replay_decision.add_argument("--provenance-id", help="Provenance ID to replay")
    p_replay_decision.set_defaults(func=cmd_replay_decision)
    
    p_build_ui = sub.add_parser("build-ui", help="Build the web UI")
    p_build_ui.set_defaults(func=cmd_build_ui)
    
    p_doctor = sub.add_parser("doctor", help="Sanity check user environment")
    p_doctor.set_defaults(func=cmd_doctor)
    
    p_replay = sub.add_parser("replay", help="Replay an action execution")
    p_replay.add_argument("id", help="Action ID or prefix")
    p_replay.set_defaults(func=cmd_replay)
    
    
    p_init_docker = sub.add_parser("init-docker", help="Generate Docker configuration files")
    p_init_docker.add_argument("--force", action="store_true", help="Overwrite existing files")
    p_init_docker.set_defaults(func=cmd_init_docker)
    
    # New fara action namespace - lazy import to avoid circular deps
    def _setup_action_commands():
        from .cli_actions import (
            cmd_action_approve,
            cmd_action_deny,
            cmd_action_replay,
            cmd_action_start,
            cmd_action_submit,
            cmd_history,
        )
        
        p_action = sub.add_parser("action", help="Action management commands")
        action_sub = p_action.add_subparsers(dest="action_cmd", metavar="SUBCOMMAND")
        
        # action submit
        p_action_submit = action_sub.add_parser("submit", help="Submit a new action")
        p_action_submit.add_argument("agent", help="Agent ID")
        p_action_submit.add_argument("tool", help="Tool name")
        p_action_submit.add_argument("operation", help="Operation name")
        p_action_submit.add_argument("--param", action="append", default=[], 
                                     help="Parameter as key=value (can be used multiple times)")
        p_action_submit.add_argument("--context", action="append", default=[],
                                     help="Context as key=value (can be used multiple times)")
        p_action_submit.add_argument("--json", action="store_true", help="Output as JSON")
        p_action_submit.set_defaults(func=cmd_action_submit)
        
        # action approve
        p_action_approve = action_sub.add_parser("approve", help="Approve a pending action")
        p_action_approve.add_argument("id", help="Action ID or prefix")
        p_action_approve.add_argument("--reason", help="Approval reason")
        p_action_approve.add_argument("--json", action="store_true", help="Output as JSON")
        p_action_approve.set_defaults(func=cmd_action_approve)
        
        # action deny
        p_action_deny = action_sub.add_parser("deny", help="Deny a pending action")
        p_action_deny.add_argument("id", help="Action ID or prefix")
        p_action_deny.add_argument("--reason", help="Denial reason")
        p_action_deny.add_argument("--json", action="store_true", help="Output as JSON")
        p_action_deny.set_defaults(func=cmd_action_deny)
        
        # action start
        p_action_start = action_sub.add_parser("start", help="Start execution of an action")
        p_action_start.add_argument("id", help="Action ID or prefix")
        p_action_start.add_argument("--json", action="store_true", help="Output as JSON")
        p_action_start.set_defaults(func=cmd_action_start)
        
        # action replay
        p_action_replay = action_sub.add_parser("replay", help="Replay an action")
        p_action_replay.add_argument("id", help="Action ID or prefix")
        p_action_replay.add_argument("--json", action="store_true", help="Output as JSON")
        p_action_replay.set_defaults(func=cmd_action_replay)
        
        # history (alias for list)
        p_history = sub.add_parser("history", help="Show action history")
        p_history.add_argument("--limit", type=int, default=20, help="Number of actions to show")
        p_history.add_argument("--full", action="store_true", help="Show full UUIDs")
        p_history.add_argument("--json", action="store_true", help="Output as JSON")
        p_history.set_defaults(func=cmd_history)
    
    _setup_action_commands()
    
    # Shell command
    p_shell = sub.add_parser("shell", help="Start interactive REPL shell")
    from .cli_shell import cmd_shell
    p_shell.set_defaults(func=cmd_shell)
    
    # Apply command (request-by-file)
    p_apply = sub.add_parser("apply", help="Submit action from YAML/JSON file")
    p_apply.add_argument("file", help="Path to action YAML/JSON file")
    p_apply.add_argument("--json", action="store_true", help="Output as JSON")
    from .cli_apply import cmd_apply
    p_apply.set_defaults(func=cmd_apply)
    
    # Token management namespace
    def _setup_token_commands():
        from .cli_token import cmd_token_create, cmd_token_list, cmd_token_revoke
        
        p_token = sub.add_parser("token", help="Token management")
        token_sub = p_token.add_subparsers(dest="token_cmd", metavar="SUBCOMMAND")
        
        # token create
        p_token_create = token_sub.add_parser("create", help="Create a new token")
        p_token_create.add_argument("name", help="Token name")
        p_token_create.add_argument("--ttl", help="Time to live (e.g., '1h', '30m', '7d')")
        p_token_create.set_defaults(func=cmd_token_create)
        
        # token list
        p_token_list = token_sub.add_parser("list", help="List all tokens")
        p_token_list.add_argument("--json", action="store_true", help="Output as JSON")
        p_token_list.set_defaults(func=cmd_token_list)
        
        # token revoke
        p_token_revoke = token_sub.add_parser("revoke", help="Revoke a token")
        p_token_revoke.add_argument("id", help="Token ID")
        p_token_revoke.set_defaults(func=cmd_token_revoke)
    
    _setup_token_commands()
    
    return p


def cmd_init(args):
    """Scaffold a working starter layout."""
    from pathlib import Path
    
    base_path = Path.cwd()
    policies_dir = base_path / "policies"
    env_example = base_path / ".env.example"
    
    created = []
    
    # Create policies directory
    if not policies_dir.exists():
        policies_dir.mkdir(parents=True, exist_ok=True)
        created.append("policies/")
    
    # Create default.yaml
    default_yaml = policies_dir / "default.yaml"
    default_content = """# Faramesh Default Policy
# Rules are evaluated in order - first match wins

rules:
  # Deny unknown tools by default (deny-by-default security)
  - match:
      tool: "*"
      op: "*"
    deny: true
    description: "Default deny rule - deny unknown actions"
    risk: "high"

# Optional: Risk scoring rules
# risk:
#   rules:
#     - name: dangerous_shell
#       when:
#         tool: shell
#         operation: run
#         pattern: "rm -rf|shutdown|reboot"
#       risk_level: high
"""
    
    if not default_yaml.exists() or args.force:
        default_yaml.write_text(default_content)
        created.append("policies/default.yaml")
    
    # Create .env.example
    env_example_content = """# Faramesh Configuration
# Copy this file to .env and customize as needed

# Server Configuration
FARAMESH_HOST=127.0.0.1
FARAMESH_PORT=8000
FARAMESH_TOKEN=
FARAMESH_ENABLE_CORS=1

# Policy Configuration
FARA_POLICY_FILE=policies/default.yaml

# Database Configuration
FARA_DB_BACKEND=sqlite
FARA_SQLITE_PATH=data/actions.db
# FARA_POSTGRES_DSN=postgresql://user:pass@localhost/faramesh

# Demo Mode (seeds sample data if DB is empty)
FARAMESH_DEMO=0
"""
    
    if not env_example.exists() or args.force:
        env_example.write_text(env_example_content)
        created.append(".env.example")
    
    # Print results
    if HAS_RICH:
        console = Console()
        if created:
            console.print("[green]✓[/green] Created starter files:")
            for item in created:
                console.print(f"  • {item}")
            console.print("\n[cyan]Next steps:[/cyan]")
            console.print("  1. Review policies/default.yaml")
            console.print("  2. Copy .env.example to .env and customize")
            console.print("  3. Run: [bold]faramesh serve[/bold]")
        else:
            console.print("[yellow]⚠[/yellow] Files already exist. Use --force to overwrite.")
    else:
        if created:
            print("✓ Created starter files:")
            for item in created:
                print(f"  • {item}")
            print("\nNext steps:")
            print("  1. Review policies/default.yaml")
            print("  2. Copy .env.example to .env and customize")
            print("  3. Run: faramesh serve")
        else:
            print("⚠ Files already exist. Use --force to overwrite.")


def cmd_explain(args):
    """Explain why an action was allowed, denied, or required approval."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Find action
    action_id = args.id
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
        r.raise_for_status()
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
    
    try:
        # Get action
        r = _make_request("GET", f"{base_url}/v1/actions/{action_id}", token=token)
        r.raise_for_status()
        action = r.json()
        
        # Get policy info
        from pathlib import Path

        from faramesh.server.policy_engine import PolicyEngine
        from faramesh.server.settings import get_settings
        
        settings = get_settings()
        policy_file = settings.policy_file
        policy_path = Path(policy_file)
        if not policy_path.is_absolute():
            package_root = Path(__file__).resolve().parents[2]
            policy_path = package_root / policy_file
        
        # Re-evaluate to get rule info
        try:
            engine = PolicyEngine(str(policy_path))
            decision, reason, risk = engine.evaluate(
                tool=action['tool'],
                operation=action['operation'],
                params=action['params'],
                context=action.get('context', {})
            )
        except Exception:
            # Re-evaluation failed, use values from action dict
            pass
        
        # Print explanation
        if HAS_RICH:
            console = Console()
            console.print(f"\n[bold cyan]Action Explanation: {action_id[:8]}[/bold cyan]\n")
            
            # Status
            status = action.get('status', 'N/A')
            status_color = {
                'denied': 'red',
                'pending_approval': 'yellow',
                'allowed': 'green',
                'approved': 'green',
                'succeeded': 'green',
                'failed': 'red'
            }.get(status, 'white')
            console.print(f"[bold]Status:[/bold] [{status_color}]{status}[/{status_color}]")
            
            # Outcome (if available)
            outcome = action.get('outcome')
            if outcome:
                outcome_color = {
                    'EXECUTE': 'green',
                    'ABSTAIN': 'yellow',
                    'HALT': 'red'
                }.get(outcome, 'white')
                console.print(f"[bold]Outcome:[/bold] [{outcome_color}]{outcome}[/{outcome_color}]")
            
            # Decision
            decision_val = action.get('decision', 'N/A')
            console.print(f"[bold]Decision:[/bold] {decision_val}")
            
            # Reason Code (if available)
            reason_code = action.get('reason_code')
            if reason_code:
                console.print(f"[bold]Reason Code:[/bold] {reason_code}")
            
            # Reason
            reason_val = action.get('reason', 'N/A')
            console.print(f"[bold]Reason:[/bold] {reason_val}")
            
            # Risk Level
            risk_val = action.get('risk_level', 'N/A')
            risk_color = {'high': 'red', 'medium': 'yellow', 'low': 'green'}.get(risk_val, 'white')
            console.print(f"[bold]Risk Level:[/bold] [{risk_color}]{risk_val}[/{risk_color}]")
            
            # Version binding info
            if action.get('request_hash') or action.get('policy_hash') or action.get('runtime_version'):
                console.print(f"\n[bold]Version Binding:[/bold]")
                if action.get('request_hash'):
                    console.print(f"  Request Hash: {action['request_hash'][:16]}...")
                if action.get('policy_hash'):
                    console.print(f"  Policy Hash: {action['policy_hash'][:16]}...")
                if action.get('profile_hash'):
                    console.print(f"  Profile Hash: {action['profile_hash'][:16]}...")
                if action.get('runtime_version'):
                    console.print(f"  Runtime Version: {action['runtime_version']}")
                if action.get('provenance_id'):
                    console.print(f"  Provenance ID: {action['provenance_id'][:16]}...")
            
            # Policy File
            console.print(f"\n[bold]Policy File:[/bold] {policy_path}")
            if policy_path.exists():
                console.print(f"[bold]Policy Version:[/bold] {action.get('policy_version', 'N/A')}")
            else:
                console.print("[red]⚠ Policy file not found[/red]")
            
            # Profile info (if available)
            if action.get('profile_id'):
                console.print(f"\n[bold]Profile:[/bold] {action.get('profile_id')} (v{action.get('profile_version', 'N/A')})")
            
            # Tool/Operation
            console.print(f"\n[bold]Tool:[/bold] {action.get('tool', 'N/A')}")
            console.print(f"[bold]Operation:[/bold] {action.get('operation', 'N/A')}")
            
            # Params summary
            params = action.get('params', {})
            if params:
                console.print(f"\n[bold]Params:[/bold] {json.dumps(params, indent=2)}")
        else:
            print(f"\nAction Explanation: {action_id[:8]}\n")
            print(f"Status: {action.get('status', 'N/A')}")
            if action.get('outcome'):
                print(f"Outcome: {action['outcome']}")
            print(f"Decision: {action.get('decision', 'N/A')}")
            if action.get('reason_code'):
                print(f"Reason Code: {action['reason_code']}")
            print(f"Reason: {action.get('reason', 'N/A')}")
            print(f"Risk Level: {action.get('risk_level', 'N/A')}")
            
            # Version binding info
            if action.get('request_hash') or action.get('policy_hash') or action.get('runtime_version'):
                print(f"\nVersion Binding:")
                if action.get('request_hash'):
                    print(f"  Request Hash: {action['request_hash'][:16]}...")
                if action.get('policy_hash'):
                    print(f"  Policy Hash: {action['policy_hash'][:16]}...")
                if action.get('profile_hash'):
                    print(f"  Profile Hash: {action['profile_hash'][:16]}...")
                if action.get('runtime_version'):
                    print(f"  Runtime Version: {action['runtime_version']}")
                if action.get('provenance_id'):
                    print(f"  Provenance ID: {action['provenance_id'][:16]}...")
            
            print(f"\nPolicy File: {policy_path}")
            if policy_path.exists():
                print(f"Policy Version: {action.get('policy_version', 'N/A')}")
            else:
                print("⚠ Policy file not found")
            
            if action.get('profile_id'):
                print(f"\nProfile: {action.get('profile_id')} (v{action.get('profile_version', 'N/A')})")
            
            print(f"\nTool: {action.get('tool', 'N/A')}")
            print(f"Operation: {action.get('operation', 'N/A')}")
            params = action.get('params', {})
            if params:
                print(f"\nParams: {json.dumps(params, indent=2)}")
    except Exception as e:
        _handle_request_error(e, base_url)


def cmd_build_ui(args):
    """Build the web UI."""
    import shutil
    import subprocess
    from pathlib import Path
    
    # Find UI folder (web/ relative to package root)
    package_root = Path(__file__).resolve().parents[2]
    web_dir = package_root / "web"
    
    if not web_dir.exists():
        _print_error(f"UI folder not found: {web_dir}")
        _print_error("Expected web/ directory in project root")
        sys.exit(1)
    
    if HAS_RICH:
        console = Console()
        console.print("[cyan]Building UI...[/cyan]")
    else:
        print("Building UI...")
    
    # Check for node_modules
    node_modules = web_dir / "node_modules"
    if not node_modules.exists():
        if HAS_RICH:
            console.print("[yellow]Installing dependencies...[/yellow]")
        else:
            print("Installing dependencies...")
        try:
            subprocess.run(["npm", "install"], cwd=web_dir, check=True)
        except subprocess.CalledProcessError as e:
            _print_error(f"npm install failed: {e}")
            sys.exit(1)
        except FileNotFoundError:
            _print_error("npm not found. Please install Node.js and npm.")
            sys.exit(1)
    
    # Build
    try:
        if HAS_RICH:
            console.print("[cyan]Running npm run build...[/cyan]")
        else:
            print("Running npm run build...")
        subprocess.run(["npm", "run", "build"], cwd=web_dir, check=True)

        # After build, copy assets into src/faramesh/web so the API
        # can serve them without any extra wiring.
        build_dir = web_dir / "dist"
        target_dir = package_root / "src" / "faramesh" / "web"

        if not build_dir.exists():
            _print_error(f"Build output not found at {build_dir}")
            _print_error("Check your Vite config or npm build step.")
            return

        # Recreate target_dir and copy files in (keep it simple; this
        # directory is generated output only).
        if target_dir.exists():
            for child in target_dir.iterdir():
                # Keep git placeholders
                if child.name == ".gitkeep":
                    continue
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
        else:
            target_dir.mkdir(parents=True, exist_ok=True)

        # Copy build output into target_dir
        for child in build_dir.iterdir():
            dest = target_dir / child.name
            if child.is_dir():
                shutil.copytree(child, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(child, dest)

        if HAS_RICH:
            console.print("[green]✓ UI built and assets copied into src/faramesh/web[/green]")
        else:
            print("✓ UI built and assets copied into src/faramesh/web")
    except subprocess.CalledProcessError as e:
        _print_error(f"Build failed: {e}")
        sys.exit(1)
    except FileNotFoundError:
        _print_error("npm not found. Please install Node.js and npm.")
        sys.exit(1)


def cmd_doctor(args):
    """Sanity check user environment."""
    import os
    import sys as sys_module
    from pathlib import Path
    
    issues = []
    warnings = []
    
    # Check Python version
    if sys_module.version_info < (3, 9):
        issues.append(f"Python version {sys_module.version} is too old. Requires 3.9+")
    else:
        if HAS_RICH:
            console = Console()
            console.print(f"[green]✓[/green] Python {sys_module.version_info.major}.{sys_module.version_info.minor}.{sys_module.version_info.micro}")
        else:
            print(f"✓ Python {sys_module.version_info.major}.{sys_module.version_info.minor}.{sys_module.version_info.micro}")
    
    # Check database
    try:
        from faramesh.server.storage import get_store
        store = get_store()
        # Try to connect
        if hasattr(store, '_connect'):
            conn = store._connect()
            conn.close()
            if HAS_RICH:
                console.print("[green]✓[/green] Database exists and is writable")
            else:
                print("✓ Database exists and is writable")
        else:
            warnings.append("Could not verify database connection")
    except Exception as e:
        warnings.append(f"Database check skipped: {e}")
    
    # Check policy file
    from faramesh.server.settings import get_settings
    settings = get_settings()
    policy_path = Path(settings.policy_file)
    if not policy_path.is_absolute():
        package_root = Path(__file__).resolve().parents[2]
        policy_path = package_root / settings.policy_file
    
    if policy_path.exists():
        if HAS_RICH:
            console.print(f"[green]✓[/green] Policy file exists: {policy_path}")
        else:
            print(f"✓ Policy file exists: {policy_path}")
    else:
        issues.append(f"Policy file not found: {policy_path}")
    
    # Check token
    token = os.getenv("FARAMESH_TOKEN") or os.getenv("FARA_AUTH_TOKEN")
    if token:
        if HAS_RICH:
            console.print("[green]✓[/green] Auth token configured")
        else:
            print("✓ Auth token configured")
    else:
        warnings.append("No auth token configured (FARAMESH_TOKEN or FARA_AUTH_TOKEN)")
    
    # Check UI assets (optional)
    package_root = Path(__file__).resolve().parents[2]
    web_build = package_root / "web" / "dist"
    web_src = package_root / "src" / "faramesh" / "web"
    
    if web_build.exists() or web_src.exists():
        if HAS_RICH:
            console.print("[green]✓[/green] UI assets found")
        else:
            print("✓ UI assets found")
    else:
        warnings.append("UI assets not found. Run 'faramesh build-ui' to build.")
    
    # Print results
    if issues:
        if HAS_RICH:
            console.print("\n[red]Issues found:[/red]")
            for issue in issues:
                console.print(f"  [red]✗[/red] {issue}")
        else:
            print("\nIssues found:")
            for issue in issues:
                print(f"  ✗ {issue}")
    
    if warnings:
        if HAS_RICH:
            console.print("\n[yellow]Warnings:[/yellow]")
            for warning in warnings:
                console.print(f"  [yellow]⚠[/yellow] {warning}")
        else:
            print("\nWarnings:")
            for warning in warnings:
                print(f"  ⚠ {warning}")
    
    if not issues and not warnings:
        if HAS_RICH:
            console.print("\n[green]✓ All checks passed![/green]")
        else:
            print("\n✓ All checks passed!")
        return 0
    
    return 1 if issues else 0


def cmd_verify_log(args):
    """Verify tamper-evident audit log chain for an action."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Find action
    action_id = args.id
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
        r.raise_for_status()
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
    
    try:
        # Get events
        r = _make_request("GET", f"{base_url}/v1/actions/{action_id}/events", token=token)
        r.raise_for_status()
        events = r.json()
        
        if not events:
            _print_error(f"No events found for action {action_id[:8]}")
            sys.exit(1)
        
        # Verify chain
        from faramesh.server.canonicalization import canonicalize_event_payload, compute_event_hash
        
        prev_hash = None
        broken_index = None
        
        for i, event in enumerate(events):
            # Build event dict for canonicalization
            event_dict = {
                "id": event.get("id"),
                "action_id": event.get("action_id"),
                "event_type": event.get("event_type"),
                "created_at": event.get("created_at"),
                "meta": event.get("meta", {}),
            }
            
            # Compute expected hash
            expected_hash = compute_event_hash(event_dict, prev_hash)
            actual_hash = event.get("record_hash")
            
            if not actual_hash:
                if HAS_RICH:
                    console = Console()
                    console.print(f"[yellow]⚠[/yellow] Event {i} ({event.get('event_type')}) has no record_hash - chain verification skipped")
                else:
                    print(f"⚠ Event {i} ({event.get('event_type')}) has no record_hash - chain verification skipped")
                prev_hash = None
                continue
            
            if actual_hash != expected_hash:
                broken_index = i
                break
            
            # Check prev_hash matches
            if prev_hash is not None and event.get("prev_hash") != prev_hash:
                broken_index = i
                break
            
            prev_hash = actual_hash
        
        if broken_index is not None:
            _print_error(f"Audit chain verification FAILED at event {broken_index}")
            if broken_index < len(events):
                event = events[broken_index]
                print(f"  Event ID: {event.get('id', 'N/A')}")
                print(f"  Event Type: {event.get('event_type', 'N/A')}")
                if HAS_RICH:
                    console = Console()
                    console.print(f"[red]Chain integrity compromised[/red]")
                else:
                    print("Chain integrity compromised")
            sys.exit(1)
        else:
            if HAS_RICH:
                console = Console()
                console.print(f"[green]✓[/green] Audit chain verification PASSED for {len(events)} events")
            else:
                print(f"✓ Audit chain verification PASSED for {len(events)} events")
    
    except Exception as e:
        _handle_request_error(e, base_url)


def cmd_replay_decision(args):
    """Replay a decision to verify determinism."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    action_id = None
    
    if args.provenance_id:
        # Find action by provenance_id
        try:
            r = _make_request("GET", f"{base_url}/v1/actions", params={"limit": 1000}, token=token)
            r.raise_for_status()
            actions = r.json()
            matches = [a for a in actions if a.get('provenance_id') == args.provenance_id]
            if not matches:
                _print_error(f"No action found with provenance_id '{args.provenance_id}'")
                sys.exit(1)
            if len(matches) > 1:
                _print_error(f"Multiple actions match provenance_id '{args.provenance_id}'")
                sys.exit(1)
            action_id = matches[0]['id']
        except Exception as e:
            _handle_request_error(e, base_url)
    elif args.id:
        # Find action by ID
        try:
            r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
            r.raise_for_status()
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
    else:
        _print_error("Must provide either action ID or --provenance-id")
        sys.exit(1)
    
    try:
        # Get original action
        r = _make_request("GET", f"{base_url}/v1/actions/{action_id}", token=token)
        r.raise_for_status()
        original = r.json()
        
        # Extract payload
        payload = {
            "agent_id": original['agent_id'],
            "tool": original['tool'],
            "operation": original['operation'],
            "params": original['params'],
            "context": original.get('context', {}),
        }
        
        # Call gate/decide endpoint
        r = _make_request("POST", f"{base_url}/v1/gate/decide", json=payload, token=token)
        r.raise_for_status()
        new_decision = r.json()
        
        # Compare
        mismatches = []
        
        if new_decision.get('outcome') != original.get('outcome'):
            mismatches.append(f"outcome: {original.get('outcome')} != {new_decision.get('outcome')}")
        
        if new_decision.get('reason_code') != original.get('reason_code'):
            mismatches.append(f"reason_code: {original.get('reason_code')} != {new_decision.get('reason_code')}")
        
        if new_decision.get('policy_hash') != original.get('policy_hash'):
            mismatches.append("policy_hash mismatch (policy may have changed)")
        
        if new_decision.get('profile_hash') != original.get('profile_hash'):
            mismatches.append("profile_hash mismatch (profile may have changed)")
        
        if new_decision.get('runtime_version') != original.get('runtime_version'):
            mismatches.append(f"runtime_version: {original.get('runtime_version')} != {new_decision.get('runtime_version')}")
        
        if mismatches:
            _print_error(f"Decision replay FAILED - mismatches detected:")
            for mismatch in mismatches:
                print(f"  - {mismatch}", file=sys.stderr)
            sys.exit(1)
        else:
            if HAS_RICH:
                console = Console()
                console.print(f"[green]✓[/green] Decision replay PASSED - outcome and hashes match")
            else:
                print("✓ Decision replay PASSED - outcome and hashes match")
    
    except Exception as e:
        _handle_request_error(e, base_url)


def cmd_replay(args):
    """Replay an action execution."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    # Find action
    action_id = args.id
    try:
        r = _make_request("GET", f"{base_url}/v1/actions/{args.id}", token=token)
        r.raise_for_status()
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
    
    try:
        # Get original action
        r = _make_request("GET", f"{base_url}/v1/actions/{action_id}", token=token)
        r.raise_for_status()
        original = r.json()
        
        # Check if replayable
        if original.get('status') not in ('allowed', 'approved', 'succeeded'):
            _print_error(f"Action status '{original.get('status')}' is not replayable. Only 'allowed' or 'approved' actions can be replayed.")
            sys.exit(1)
        
        # Create new action with same payload
        new_action = {
            "agent_id": original['agent_id'],
            "tool": original['tool'],
            "operation": original['operation'],
            "params": original['params'],
            "context": {
                **(original.get('context') or {}),
                "replayed_from": action_id,
                "replay": True
            }
        }
        
        # Submit new action
        r = _make_request("POST", f"{base_url}/v1/actions", json=new_action, token=token)
        r.raise_for_status()
        new = r.json()
        
        if HAS_RICH:
            console = Console()
            console.print("[green]✓[/green] Replayed action")
            console.print(f"Original: {action_id}")
            console.print(f"New: {new['id']}")
            console.print(f"Status: {new.get('status')}")
        else:
            print("✓ Replayed action")
            print(f"Original: {action_id}")
            print(f"New: {new['id']}")
            print(f"Status: {new.get('status')}")
    except Exception as e:
        _handle_request_error(e, base_url)


def cmd_policy_diff(args):
    """Show differences between two policy files."""
    from pathlib import Path

    import yaml
    
    old_file = Path(args.old_file)
    new_file = Path(args.new_file)
    
    if not old_file.exists():
        _print_error(f"Old policy file not found: {old_file}")
        sys.exit(1)
    
    if not new_file.exists():
        _print_error(f"New policy file not found: {new_file}")
        sys.exit(1)
    
    try:
        with open(old_file) as f:
            old_policy = yaml.safe_load(f) or {}
        with open(new_file) as f:
            new_policy = yaml.safe_load(f) or {}
        
        old_rules = old_policy.get('rules', [])
        new_rules = new_policy.get('rules', [])
        
        # Simple diff
        if old_rules == new_rules:
            if HAS_RICH:
                console = Console()
                console.print("[green]No changes detected[/green]")
            else:
                print("No changes detected")
            return
        
        # Show differences
        if HAS_RICH:
            console = Console()
            console.print("[bold]Policy Differences:[/bold]\n")
            console.print(f"[cyan]Old:[/cyan] {old_file}")
            console.print(f"[cyan]New:[/cyan] {new_file}\n")
            
            # Count rules
            console.print(f"Old rules: {len(old_rules)}")
            console.print(f"New rules: {len(new_rules)}")
            
            # Show rule differences (simplified)
            if len(old_rules) != len(new_rules):
                console.print(f"\n[yellow]Rule count changed: {len(old_rules)} → {len(new_rules)}[/yellow]")
            
            # Show added/removed (simplified comparison)
            old_rule_descriptions = [r.get('description', '') for r in old_rules if isinstance(r, dict)]
            new_rule_descriptions = [r.get('description', '') for r in new_rules if isinstance(r, dict)]
            
            added = set(new_rule_descriptions) - set(old_rule_descriptions)
            removed = set(old_rule_descriptions) - set(new_rule_descriptions)
            
            if added:
                console.print("\n[green]Added rules:[/green]")
                for desc in added:
                    console.print(f"  + {desc}")
            
            if removed:
                console.print("\n[red]Removed rules:[/red]")
                for desc in removed:
                    console.print(f"  - {desc}")
        else:
            print("Policy Differences:\n")
            print(f"Old: {old_file}")
            print(f"New: {new_file}\n")
            print(f"Old rules: {len(old_rules)}")
            print(f"New rules: {len(new_rules)}")
            
            if len(old_rules) != len(new_rules):
                print(f"\nRule count changed: {len(old_rules)} → {len(new_rules)}")
    except Exception as e:
        _print_error(f"Error comparing policies: {e}")
        sys.exit(1)


def cmd_init_docker(args):
    """Generate Docker configuration files."""
    from pathlib import Path
    
    base_path = Path.cwd()
    created = []
    
    # docker-compose.yaml
    compose_file = base_path / "docker-compose.yaml"
    compose_content = """version: '3.8'

services:
  faramesh:
    build: .
    ports:
      - "8000:8000"
    environment:
      - FARAMESH_HOST=0.0.0.0
      - FARAMESH_PORT=8000
      - FARAMESH_ENABLE_CORS=1
      - FARAMESH_DEMO=1
      - FARA_POLICY_FILE=policies/default.yaml
    volumes:
      - ./data:/app/data
      - ./policies:/app/policies
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 10s
      timeout: 5s
      retries: 3

  # Optional: Demo agent
  # demo-agent:
  #   build:
  #     context: .
  #     dockerfile: Dockerfile.demo
  #   depends_on:
  #     - faramesh
  #   environment:
  #     - FARA_API_BASE=http://faramesh:8000
"""
    
    if not compose_file.exists() or args.force:
        compose_file.write_text(compose_content)
        created.append("docker-compose.yaml")
    
    # Dockerfile
    dockerfile = base_path / "Dockerfile"
    dockerfile_content = """FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    curl \\
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml ./
COPY src/ ./src/
COPY policies/ ./policies/
COPY alembic.ini ./
COPY alembic/ ./alembic/

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Create data directory
RUN mkdir -p /app/data

# Expose port
EXPOSE 8000

# Set environment variables with defaults
ENV FARAMESH_HOST=0.0.0.0
ENV FARAMESH_PORT=8000
ENV FARAMESH_ENABLE_CORS=1
ENV FARA_DB_BACKEND=sqlite
ENV FARA_SQLITE_PATH=/app/data/actions.db

# Run migrations and start server
CMD ["sh", "-c", "faramesh migrate && faramesh serve --host ${FARAMESH_HOST} --port ${FARAMESH_PORT}"]
"""
    
    if not dockerfile.exists() or args.force:
        dockerfile.write_text(dockerfile_content)
        created.append("Dockerfile")
    
    # .env.example (reuse from init if exists, otherwise create)
    env_example = base_path / ".env.example"
    if not env_example.exists():
        # Use same content as init command
        env_content = """# Faramesh Configuration
# Copy this file to .env and customize as needed

# Server Configuration
FARAMESH_HOST=127.0.0.1
FARAMESH_PORT=8000
FARAMESH_TOKEN=
FARAMESH_ENABLE_CORS=1

# Policy Configuration
FARA_POLICY_FILE=policies/default.yaml

# Database Configuration
FARA_DB_BACKEND=sqlite
FARA_SQLITE_PATH=data/actions.db
# FARA_POSTGRES_DSN=postgresql://user:pass@localhost/faramesh

# Demo Mode (seeds sample data if DB is empty)
FARAMESH_DEMO=0
"""
        env_example.write_text(env_content)
        created.append(".env.example")
    
    # Print results
    if HAS_RICH:
        console = Console()
        if created:
            console.print("[green]✓[/green] Created Docker files:")
            for item in created:
                console.print(f"  • {item}")
            console.print("\n[cyan]Next steps:[/cyan]")
            console.print("  1. Review docker-compose.yaml")
            console.print("  2. Run: [bold]docker compose up[/bold]")
        else:
            console.print("[yellow]⚠[/yellow] Files already exist. Use --force to overwrite.")
    else:
        if created:
            print("✓ Created Docker files:")
            for item in created:
                print(f"  • {item}")
            print("\nNext steps:")
            print("  1. Review docker-compose.yaml")
            print("  2. Run: docker compose up")
        else:
            print("⚠ Files already exist. Use --force to overwrite.")


def cmd_serve(args):
    """Start the Faramesh server."""
    try:
        import uvicorn
    except ImportError:
        _print_error("uvicorn is not installed. Please install it with: pip install uvicorn")
        sys.exit(1)
    
    settings = get_settings()
    # Precedence: CLI args > ENV vars > settings > defaults
    host = args.host or os.getenv("FARAMESH_HOST") or settings.api_host or "127.0.0.1"
    port = args.port or (int(os.getenv("FARAMESH_PORT")) if os.getenv("FARAMESH_PORT") else None) or settings.api_port or 8000
    
    # Hot reload policy if --hot-reload flag or --watch (deprecated) or FARAMESH_HOT_RELOAD env var
    hot_reload_enabled = (
        args.hot_reload or 
        args.watch or 
        os.getenv("FARAMESH_HOT_RELOAD") == "1"
    )
    
    # Only enable hot reload for local policy files (not remote/token mode)
    policy_file_path = Path(settings.policy_file)
    if not policy_file_path.is_absolute():
        package_root = Path(__file__).resolve().parents[2]
        policy_file_path = package_root / settings.policy_file
    
    is_local_policy = policy_file_path.exists() and policy_file_path.is_file()
    
    if hot_reload_enabled and is_local_policy:
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
            
            # Use the already-resolved policy_file_path from above
            class PolicyWatcher(FileSystemEventHandler):
                def __init__(self, policy_path):
                    self.policy_path = policy_path
                    self.last_modified = policy_path.stat().st_mtime if policy_path.exists() else 0
                    self.last_valid_policy = None
                
                def on_modified(self, event):
                    if event.src_path == str(self.policy_path):
                        try:
                            # Import here to avoid circular imports
                            from faramesh.server.main import policies
                            
                            # Store current policy as backup
                            self.last_valid_policy = policies.cached_policy.copy() if policies.cached_policy else None
                            
                            # Try to reload
                            policies.refresh()
                            
                            # Success - log with timestamp
                            from datetime import datetime
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            if HAS_RICH:
                                console = Console()
                                console.print(f"[green]✓[/green] Policy reloaded from {self.policy_path} at {timestamp}")
                            else:
                                print(f"✓ Policy reloaded from {self.policy_path} at {timestamp}")
                        except Exception as e:
                            # Validation error - keep prior valid policy
                            if self.last_valid_policy and policies.cached_policy != self.last_valid_policy:
                                policies.cached_policy = self.last_valid_policy
                            
                            # Log error clearly
                            error_msg = str(e)
                            if HAS_RICH:
                                console = Console()
                                console.print(f"[red]⚠[/red] Policy reload failed: {error_msg}")
                                console.print("[yellow]⚠[/yellow] Keeping previous valid policy active")
                            else:
                                print(f"⚠ Policy reload failed: {error_msg}")
                                print("⚠ Keeping previous valid policy active")
            
            if policy_file_path.exists():
                event_handler = PolicyWatcher(policy_file_path)
                observer = Observer()
                observer.schedule(event_handler, str(policy_file_path.parent), recursive=False)
                observer.start()
                if HAS_RICH:
                    console = Console()
                    console.print(f"[cyan]Watching policy file: {policy_file_path}[/cyan]")
                else:
                    print(f"Watching policy file: {policy_file_path}")
            else:
                if HAS_RICH:
                    console = Console()
                    console.print(f"[yellow]⚠[/yellow] Policy file not found: {policy_file_path}")
                else:
                    print(f"⚠ Policy file not found: {policy_file_path}")
        except ImportError:
            if HAS_RICH:
                console = Console()
                console.print("[yellow]⚠[/yellow] watchdog not installed. Install with: pip install watchdog")
                console.print("[yellow]⚠[/yellow] Falling back to manual policy refresh (use policy-refresh command)")
            else:
                print("⚠ watchdog not installed. Install with: pip install watchdog")
                print("⚠ Falling back to manual policy refresh (use policy-refresh command)")
    
    if hot_reload_enabled and not is_local_policy:
        # Hot reload requested but not a local file
        if HAS_RICH:
            console = Console()
            console.print("[yellow]⚠[/yellow] Hot reload only available for local policy files")
        else:
            print("⚠ Hot reload only available for local policy files")
    
    print(f"Starting Faramesh server on http://{host}:{port}")
    if hot_reload_enabled and is_local_policy:
        print("Policy hot-reload enabled (--hot-reload or FARAMESH_HOT_RELOAD=1)")
    print("Press CTRL+C to stop")
    
    import asyncio
    import contextlib
    
    # Suppress asyncio CancelledError noise during shutdown
    # uvicorn creates its own event loop, so we patch asyncio.get_event_loop()
    # to ensure any loop created has our exception handler
    _original_get_event_loop = asyncio.get_event_loop
    
    def _get_event_loop_with_handler():
        """Get event loop and set exception handler to suppress CancelledError."""
        try:
            loop = _original_get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        def suppress_cancelled_error(loop, context):
            """Suppress CancelledError exceptions during shutdown."""
            exception = context.get('exception')
            if isinstance(exception, asyncio.CancelledError):
                return  # Suppress CancelledError
            # Use default handler for other exceptions
            loop.default_exception_handler(context)
        
        loop.set_exception_handler(suppress_cancelled_error)
        return loop
    
    # Temporarily patch get_event_loop
    asyncio.get_event_loop = _get_event_loop_with_handler
    
    try:
        # Suppress KeyboardInterrupt cleanly
        with contextlib.suppress(KeyboardInterrupt):
            uvicorn.run(
                "faramesh.server.main:app",
                host=host,
                port=port,
                reload=args.reload,
                log_level=args.log_level.lower() if args.log_level else "info",
            )
    except KeyboardInterrupt:
        # This should rarely be reached due to suppress, but handle it cleanly
        pass
    except Exception as e:
        _print_error(f"Server failed to start: {e}")
        sys.exit(1)
    finally:
        # Restore original get_event_loop
        asyncio.get_event_loop = _original_get_event_loop
    
    # Clean exit message
    print("\n✓ Server stopped")


def cmd_migrate(args):
    """Run database migrations."""
    try:
        import subprocess

        from faramesh.server.storage import SQLiteStore

        settings = get_settings()
        backend = settings.db_backend.lower()

        if backend == "sqlite":
            SQLiteStore(settings.sqlite_path)
            _print_success(f"SQLite migrations completed at {settings.sqlite_path}")
            return

        # Postgres path: run alembic with the configured DSN
        project_root = Path(__file__).resolve().parents[3]
        env = os.environ.copy()
        env.update(
            {
                "FARA_DB_BACKEND": backend,
                "FARA_POSTGRES_DSN": settings.postgres_dsn,
            }
        )
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=project_root,
            env=env,
        )
        if result.returncode == 0:
            _print_success("Postgres migrations completed successfully")
        else:
            _print_error("Migration failed")
            sys.exit(1)
    except Exception as e:
        _print_error(f"Migration error: {e}")
        sys.exit(1)


def main():
    parser = make_parser()
    args = parser.parse_args()
    
    # Handle help - check if cmd attribute exists (new parser style)
    if hasattr(args, 'cmd'):
        if args.help or not args.cmd:
            print_help()
            if not args.cmd:
                sys.exit(0)
            return
        
        # Handle fara action subcommands
        if args.cmd == 'action' and hasattr(args, 'action_cmd'):
            if not args.action_cmd:
                # Show action subcommand help
                parser.parse_args(['action', '--help'])
                sys.exit(0)
            # Functions are already set via set_defaults in parser
            # Just ensure func exists
            if not hasattr(args, 'func'):
                print_help()
                sys.exit(1)
        elif args.cmd == 'history':
            # Function is already set via set_defaults
            pass
        elif args.cmd == 'shell':
            from .cli_shell import cmd_shell
            args.func = cmd_shell
        elif args.cmd == 'apply':
            # Function is already set via set_defaults
            pass
        elif args.cmd == 'token' and hasattr(args, 'token_cmd'):
            if not args.token_cmd:
                parser.parse_args(['token', '--help'])
                sys.exit(0)
            # Functions are already set via set_defaults
            pass
        elif args.cmd == 'policy' and hasattr(args, 'policy_cmd'):
            if not args.policy_cmd:
                parser.parse_args(['policy', '--help'])
                sys.exit(0)
            # Functions are already set via set_defaults
            pass
    
    elif '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        sys.exit(0)
    
    # Merge global json flag into subcommand args if not already set
    if hasattr(args, 'func') and hasattr(args, 'json') and not args.json:
        # Check if global --json was set
        if '--json' in sys.argv:
            args.json = True
    
    try:
        if hasattr(args, 'func'):
            result = args.func(args)
            # Some commands return exit codes
            if isinstance(result, int):
                sys.exit(result)
        else:
            print_help()
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n✓ Interrupted")
        sys.exit(130)
    except Exception as e:
        _print_error(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
