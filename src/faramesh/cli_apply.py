"""Request-by-file support: fara apply ./action.yaml"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

from .cli import (
    HAS_RICH,
    _get_auth_token,
    _get_base_url,
    _handle_request_error,
    _make_request,
    _print_error,
    _print_success,
)

if HAS_RICH:
    from rich.console import Console


def cmd_apply(args):
    """Apply an action from a YAML file."""
    base_url = _get_base_url(args)
    token = _get_auth_token(args)
    
    file_path = Path(args.file)
    if not file_path.exists():
        _print_error(f"File not found: {file_path}")
        sys.exit(1)
    
    try:
        # Load YAML file
        with open(file_path, 'r') as f:
            if file_path.suffix in ('.yaml', '.yml'):
                data = yaml.safe_load(f)
            elif file_path.suffix == '.json':
                data = json.load(f)
            else:
                # Try YAML first, then JSON
                try:
                    f.seek(0)
                    data = yaml.safe_load(f)
                except Exception:
                    f.seek(0)
                    data = json.load(f)
        
        # Validate required fields
        required = ['agent_id', 'tool', 'operation']
        missing = [f for f in required if f not in data]
        if missing:
            _print_error(f"Missing required fields: {', '.join(missing)}")
            sys.exit(1)
        
        # Build payload
        payload = {
            "agent_id": data['agent_id'],
            "tool": data['tool'],
            "operation": data['operation'],
            "params": data.get('params', {}),
            "context": data.get('context', {})
        }
        
        # Submit action
        r = _make_request("POST", f"{base_url}/v1/actions", json=payload, token=token)
        r.raise_for_status()
        action = r.json()
        
        if args.json:
            print(json.dumps(action, indent=2))
        else:
            action_id = action.get('id', 'N/A')
            short_id = action_id[:8] if len(action_id) > 8 else action_id
            status = action.get('status', 'unknown')
            
            _print_success(f"Action applied: {short_id} ({status})")
            
            if HAS_RICH:
                console = Console()
                console.print(f"  ID: {action_id}")
                console.print(f"  Status: {status}")
                console.print(f"  Decision: {action.get('decision', 'N/A')}")
                
                if status == 'pending_approval':
                    console.print(f"\n[cyan]Next:[/cyan] fara action approve {short_id}")
            else:
                print(f"  ID: {action_id}")
                print(f"  Status: {status}")
                if status == 'pending_approval':
                    print(f"\nNext: fara action approve {short_id}")
    
    except yaml.YAMLError as e:
        _print_error(f"Invalid YAML: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        _print_error(f"Invalid JSON: {e}")
        sys.exit(1)
    except Exception as e:
        _handle_request_error(e, base_url)
