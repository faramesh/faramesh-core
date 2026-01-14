"""Token management commands: fara token create/list/revoke"""

from __future__ import annotations

import secrets
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .cli import HAS_RICH, _print_error, _print_success

if HAS_RICH:
    from rich import box
    from rich.console import Console
    from rich.table import Table


# Simple file-based token storage (can be replaced with DB later)
TOKEN_FILE = Path.home() / ".faramesh_tokens.json"


def _load_tokens() -> dict:
    """Load tokens from file."""
    import json
    if TOKEN_FILE.exists():
        try:
            with open(TOKEN_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_tokens(tokens: dict) -> None:
    """Save tokens to file."""
    import json
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(TOKEN_FILE, 'w') as f:
        json.dump(tokens, f, indent=2)


def _parse_ttl(ttl_str: str) -> Optional[datetime]:
    """Parse TTL string like '1h', '30m', '7d'."""
    if not ttl_str:
        return None
    
    ttl_str = ttl_str.lower().strip()
    
    multipliers = {
        's': 1,
        'm': 60,
        'h': 3600,
        'd': 86400,
    }
    
    try:
        if ttl_str[-1] in multipliers:
            value = int(ttl_str[:-1])
            seconds = value * multipliers[ttl_str[-1]]
            return datetime.utcnow() + timedelta(seconds=seconds)
        else:
            # Assume hours if no unit
            hours = int(ttl_str)
            return datetime.utcnow() + timedelta(hours=hours)
    except ValueError:
        _print_error(f"Invalid TTL format: {ttl_str}. Use format like '1h', '30m', '7d'")
        return None


def cmd_token_create(args):
    """Create a new token."""
    name = args.name
    ttl_str = getattr(args, 'ttl', None)
    
    expires_at = _parse_ttl(ttl_str) if ttl_str else None
    
    # Generate token
    token = secrets.token_urlsafe(32)
    
    # Load existing tokens
    tokens = _load_tokens()
    
    # Create token entry
    token_id = secrets.token_urlsafe(16)
    tokens[token_id] = {
        "name": name,
        "token": token,
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "active": True
    }
    
    _save_tokens(tokens)
    
    _print_success(f"Token '{name}' created")
    
    if HAS_RICH:
        console = Console()
        console.print(f"\n[bold]Token ID:[/bold] {token_id}")
        console.print(f"[bold]Token:[/bold] {token}")
        console.print("\n[cyan]Export:[/cyan]")
        console.print(f"export FARAMESH_TOKEN={token}")
        if expires_at:
            console.print(f"\n[yellow]Expires:[/yellow] {expires_at.isoformat()}")
    else:
        print(f"\nToken ID: {token_id}")
        print(f"Token: {token}")
        print(f"\nexport FARAMESH_TOKEN={token}")
        if expires_at:
            print(f"\nExpires: {expires_at.isoformat()}")


def cmd_token_list(args):
    """List all tokens."""
    tokens = _load_tokens()
    
    if not tokens:
        _print_error("No tokens found")
        return
    
    if args.json:
        import json
        print(json.dumps(tokens, indent=2))
        return
    
    if HAS_RICH:
        console = Console()
        table = Table(box=box.ROUNDED)
        table.add_column("ID", style="cyan", width=20)
        table.add_column("Name", style="white", width=20)
        table.add_column("Created", style="blue", width=20)
        table.add_column("Expires", style="yellow", width=20)
        table.add_column("Status", style="green", width=10)
        
        for token_id, token_data in tokens.items():
            created = token_data.get('created_at', 'N/A')
            expires = token_data.get('expires_at', 'Never')
            status = "Active" if token_data.get('active', True) else "Revoked"
            
            # Check if expired
            if expires and expires != 'Never':
                try:
                    exp_dt = datetime.fromisoformat(expires)
                    if datetime.utcnow() > exp_dt:
                        status = "Expired"
                except Exception:
                    pass
            
            table.add_row(
                token_id[:16],
                token_data.get('name', 'N/A'),
                created[:10] if len(created) > 10 else created,
                expires[:10] if isinstance(expires, str) and len(expires) > 10 else str(expires),
                status
            )
        
        console.print(table)
    else:
        print("ID                 Name                 Created            Expires            Status")
        print("-" * 90)
        for token_id, token_data in tokens.items():
            created = token_data.get('created_at', 'N/A')[:10]
            expires = token_data.get('expires_at', 'Never')
            if isinstance(expires, str) and len(expires) > 10:
                expires = expires[:10]
            status = "Active" if token_data.get('active', True) else "Revoked"
            print(f"{token_id[:16]:<20} {token_data.get('name', 'N/A'):<20} {created:<20} {str(expires):<20} {status}")


def cmd_token_revoke(args):
    """Revoke a token."""
    token_id = args.id
    tokens = _load_tokens()
    
    if token_id not in tokens:
        _print_error(f"Token not found: {token_id}")
        sys.exit(1)
    
    tokens[token_id]['active'] = False
    _save_tokens(tokens)
    
    _print_success(f"Token '{tokens[token_id].get('name', token_id)}' revoked")
