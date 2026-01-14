# server/main.py
# SPDX-License-Identifier: Elastic-2.0
from __future__ import annotations

import json
import os
import secrets
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from .auth import AuthMiddleware
from .decision_engine import evaluate_decision
from .errors import (
    ActionNotExecutableError,
    ActionNotFoundError,
    UnauthorizedError,
    ValidationError,
)
from .events import emit_action_event, get_event_manager
from .executor import ActionExecutor
from .metrics import action_duration_seconds, actions_total, errors_total, get_metrics_response
from .models import Action, Decision, DecisionOutcome, Status
from .policy_engine import PolicyEngine
from .profiles import load_profile_from_env
from .security.guard import (
    SecurityError,
    enforce_no_side_effects,
    validate_action_params,
    validate_context,
    validate_external_string,
    validate_policy_decision,
)
from .settings import get_settings
from .storage import get_store

settings = get_settings()
store = get_store()
executor = ActionExecutor(store)
policies = PolicyEngine(settings.policy_file)
# Load runtime version
try:
    from faramesh import __version__ as runtime_version_str
except ImportError:
    runtime_version_str = "unknown"

app = FastAPI(title="Faramesh - Agent Action Governor")

# Global exception handler for unhandled errors
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch all unhandled exceptions and return proper error responses."""
    import logging
    
    logging.error(f"Unhandled exception: {exc}", exc_info=True)
    errors_total.inc()
    
    return JSONResponse(
        status_code=500,
        content={
            "detail": f"Internal server error: {str(exc)}",
            "error_type": type(exc).__name__,
        }
    )

# CORS middleware - enabled by default to maintain current behavior
# Can be explicitly controlled via FARAMESH_ENABLE_CORS env var
# Default: enabled (maintains current behavior)
# Set FARAMESH_ENABLE_CORS=0 to disable, FARAMESH_ENABLE_CORS=1 to explicitly enable
enable_cors_env = os.getenv("FARAMESH_ENABLE_CORS")
if enable_cors_env is None or enable_cors_env == "1":
    # Default behavior: CORS enabled (maintains backward compatibility)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Add auth middleware if token is configured
# Check FARAMESH_TOKEN env var first, then settings.auth_token
auth_token = os.getenv("FARAMESH_TOKEN") or settings.auth_token
if auth_token:
    app.add_middleware(AuthMiddleware, auth_token=auth_token)

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)

WEB_ROOT = Path(__file__).resolve().parents[1] / "web"
if WEB_ROOT.exists():
    app.mount("/app", StaticFiles(directory=WEB_ROOT), name="app")

    @app.get("/")
    def root():
        return FileResponse(WEB_ROOT / "index.html")


@app.get("/playground")
def playground_page():
    """Interactive policy playground page."""
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Faramesh Policy Playground</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; }
        body { 
            font-family: system-ui, -apple-system, sans-serif; 
            max-width: 900px; 
            margin: 0 auto; 
            padding: 20px; 
            background: #f5f5f5;
        }
        h1 { color: #333; margin-bottom: 10px; }
        .subtitle { color: #666; margin-bottom: 30px; }
        .form-container {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .form-group { margin-bottom: 20px; }
        label { 
            display: block; 
            margin-bottom: 8px; 
            font-weight: 600; 
            color: #333;
        }
        input, textarea, select { 
            width: 100%; 
            padding: 10px; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            font-size: 14px;
        }
        textarea { 
            font-family: 'Monaco', 'Menlo', monospace; 
            min-height: 120px; 
            resize: vertical;
        }
        button { 
            background: #007bff; 
            color: white; 
            border: none; 
            padding: 12px 24px; 
            border-radius: 4px; 
            cursor: pointer; 
            font-size: 16px;
            font-weight: 600;
        }
        button:hover { background: #0056b3; }
        button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .response { 
            background: #f8f9fa; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            padding: 20px; 
            margin-top: 20px;
        }
        .response pre { 
            margin: 0; 
            overflow-x: auto; 
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .status-allow { color: #28a745; font-weight: 600; }
        .status-deny { color: #dc3545; font-weight: 600; }
        .status-pending { color: #ffc107; font-weight: 600; }
        .error { 
            background: #f8d7da;
            border-color: #f5c6cb;
            color: #721c24;
        }
        .success { 
            background: #d4edda;
            border-color: #c3e6cb;
            color: #155724;
        }
        .info { 
            background: #d1ecf1;
            border-color: #bee5eb;
            color: #0c5460;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <h1>Faramesh Policy Playground</h1>
    <p class="subtitle">Test policy decisions locally without submitting real actions</p>
    
    <div class="info">
        <strong>Note:</strong> This playground evaluates policy decisions only. It does not save or modify policy files.
    </div>
    
    <div class="form-container">
        <form id="playgroundForm">
            <div class="form-group">
                <label for="agent_id">Agent ID</label>
                <input type="text" id="agent_id" name="agent_id" value="test-agent" required>
            </div>
            
            <div class="form-group">
                <label for="tool">Tool</label>
                <select id="tool" name="tool" required>
                    <option value="http">http</option>
                    <option value="shell">shell</option>
                    <option value="stripe">stripe</option>
                    <option value="github">github</option>
                </select>
            </div>
            
            <div class="form-group">
                <label for="operation">Operation</label>
                <input type="text" id="operation" name="operation" value="get" required>
            </div>
            
            <div class="form-group">
                <label for="params">Params (JSON)</label>
                <textarea id="params" name="params" placeholder='{"url": "https://example.com"}'>{}</textarea>
            </div>
            
            <button type="submit" id="submitBtn">Evaluate Policy</button>
        </form>
        
        <div id="response" class="response" style="display: none;"></div>
    </div>
    
    <script>
        const form = document.getElementById('playgroundForm');
        const responseDiv = document.getElementById('response');
        const submitBtn = document.getElementById('submitBtn');
        
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            submitBtn.disabled = true;
            submitBtn.textContent = 'Evaluating...';
            responseDiv.style.display = 'none';
            
            const formData = new FormData(form);
            let params = {};
            try {
                params = JSON.parse(formData.get('params') || '{}');
            } catch (err) {
                responseDiv.className = 'response error';
                responseDiv.innerHTML = '<pre>Error: Invalid JSON in params field\\n' + err.message + '</pre>';
                responseDiv.style.display = 'block';
                submitBtn.disabled = false;
                submitBtn.textContent = 'Evaluate Policy';
                return;
            }
            
            const payload = {
                agent_id: formData.get('agent_id'),
                tool: formData.get('tool'),
                operation: formData.get('operation'),
                params: params
            };
            
            try {
                const res = await fetch('/playground/eval', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                
                const data = await res.json();
                
                if (!res.ok) {
                    throw new Error(data.detail || 'Evaluation failed');
                }
                
                const status = data.status || data.decision || 'unknown';
                const statusClass = status === 'allow' || status === 'allowed' ? 'status-allow' :
                                   status === 'deny' || status === 'denied' ? 'status-deny' :
                                   'status-pending';
                
                responseDiv.className = 'response success';
                responseDiv.innerHTML = `
                    <div style="margin-bottom: 15px;">
                        <strong>Status:</strong> <span class="${statusClass}">${status}</span>
                    </div>
                    ${data.reason ? `<div style="margin-bottom: 15px;"><strong>Reason:</strong> ${data.reason}</div>` : ''}
                    ${data.risk_level ? `<div style="margin-bottom: 15px;"><strong>Risk Level:</strong> ${data.risk_level}</div>` : ''}
                    <pre>${JSON.stringify(data, null, 2)}</pre>
                `;
            } catch (error) {
                responseDiv.className = 'response error';
                responseDiv.innerHTML = '<pre>Error: ' + error.message + '</pre>';
            }
            
            responseDiv.style.display = 'block';
            submitBtn.disabled = false;
            submitBtn.textContent = 'Evaluate Policy';
        });
    </script>
</body>
</html>"""
    return HTMLResponse(content=html_content)


@app.post("/playground/eval")
def playground_eval(request: ActionRequest):
    """Evaluate policy decision for an action (playground endpoint).
    
    This endpoint evaluates policy decisions without creating actual actions.
    It's for testing policy rules locally.
    """
    # Use the same policy evaluation logic as /v1/actions
    # Note: evaluate() doesn't take agent_id, but we can include it in context
    context = request.context or {}
    context["agent_id"] = request.agent_id
    
    decision, reason, risk_level = policies.evaluate(
        tool=request.tool,
        operation=request.operation,
        params=request.params or {},
        context=context,
    )
    
    # Map decision to status
    if decision == Decision.ALLOW:
        status = "allowed"
    elif decision == Decision.DENY:
        status = "denied"
    else:
        status = "pending_approval"
    
    return {
        "status": status,
        "decision": decision.value,
        "reason": reason,
        "risk_level": risk_level,
        "agent_id": request.agent_id,
        "tool": request.tool,
        "operation": request.operation,
    }


@app.get("/play")
def playground():
    """Web playground for testing actions."""
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Faramesh Playground</title>
    <meta charset="utf-8">
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .container { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: 600; }
        input, textarea, select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        textarea { font-family: monospace; min-height: 150px; }
        button { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .response { background: #f8f9fa; border: 1px solid #ddd; border-radius: 4px; padding: 15px; }
        .response pre { margin: 0; overflow-x: auto; }
        .snippet { background: #282c34; color: #abb2bf; padding: 15px; border-radius: 4px; margin-top: 10px; }
        .snippet pre { margin: 0; }
        .snippet-header { color: #61afef; margin-bottom: 10px; font-weight: 600; }
        .error { color: #e06c75; }
        .success { color: #98c379; }
    </style>
</head>
<body>
    <h1>Faramesh Playground</h1>
    <p>Test actions and see SDK code snippets</p>
    
    <div class="container">
        <div>
            <h2>Action Form</h2>
            <form id="actionForm">
                <div class="form-group">
                    <label>Agent ID</label>
                    <input type="text" id="agentId" value="test-agent" required>
                </div>
                <div class="form-group">
                    <label>Tool</label>
                    <select id="tool" required>
                        <option value="shell">shell</option>
                        <option value="http">http</option>
                        <option value="stripe">stripe</option>
                        <option value="github">github</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Operation</label>
                    <input type="text" id="operation" value="run" required>
                </div>
                <div class="form-group">
                    <label>Params (JSON)</label>
                    <textarea id="params" required>{"cmd": "echo hello"}</textarea>
                </div>
                <div class="form-group">
                    <label>Context (JSON, optional)</label>
                    <textarea id="context">{}</textarea>
                </div>
                <button type="submit">Submit Action</button>
            </form>
        </div>
        
        <div>
            <h2>Response</h2>
            <div id="response" class="response" style="display: none;">
                <div id="responseContent"></div>
                <div id="snippets"></div>
            </div>
        </div>
    </div>
    
    <script>
        const form = document.getElementById('actionForm');
        const responseDiv = document.getElementById('response');
        const responseContent = document.getElementById('responseContent');
        const snippetsDiv = document.getElementById('snippets');
        
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const agentId = document.getElementById('agentId').value;
            const tool = document.getElementById('tool').value;
            const operation = document.getElementById('operation').value;
            let params, context;
            
            try {
                params = JSON.parse(document.getElementById('params').value);
                context = JSON.parse(document.getElementById('context').value || '{}');
            } catch (err) {
                responseDiv.style.display = 'block';
                responseContent.innerHTML = '<p class="error">Invalid JSON: ' + err.message + '</p>';
                return;
            }
            
            try {
                const response = await fetch('/v1/actions', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ agent_id: agentId, tool, operation, params, context })
                });
                
                const action = await response.json();
                
                responseDiv.style.display = 'block';
                responseContent.innerHTML = '<pre>' + JSON.stringify(action, null, 2) + '</pre>';
                
                // Build curl snippet
                const baseUrl = window.location.origin || 'http://127.0.0.1:8000';
                const payload = JSON.stringify({ agent_id: agentId, tool, operation, params, context }, null, 2);
                const curlSnippet = `curl -X POST ${baseUrl}/v1/actions \\\n  -H "Content-Type: application/json" \\\n  -d '${payload.replace(/'/g, "\\'")}'`;
                
                // Show SDK + curl snippets
                snippetsDiv.innerHTML = '';
                
                snippetsDiv.innerHTML += '<div class="snippet"><div class="snippet-header">curl</div><pre>' +
                    curlSnippet.replace(/</g, '&lt;').replace(/>/g, '&gt;') +
                    '</pre></div>';

                if (action.js_example) {
                    snippetsDiv.innerHTML += '<div class="snippet"><div class="snippet-header">JavaScript SDK</div><pre>' + 
                        action.js_example.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</pre></div>';
                }
                if (action.python_example) {
                    snippetsDiv.innerHTML += '<div class="snippet"><div class="snippet-header">Python SDK</div><pre>' + 
                        action.python_example.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</pre></div>';
                }
            } catch (err) {
                responseDiv.style.display = 'block';
                responseContent.innerHTML = '<p class="error">Error: ' + err.message + '</p>';
            }
        });
    </script>
</body>
</html>"""
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html_content)


# Demo seed mode - only if FARAMESH_DEMO=1 and DB is empty
def _seed_demo_actions():
    """Seed demo actions if FARAMESH_DEMO=1 and database is empty."""
    if os.getenv("FARAMESH_DEMO") != "1":
        return
    
    if store.count_actions() > 0:
        return  # DB not empty, skip seeding
    
    # Create demo actions
    now = datetime.utcnow()
    demo_actions = []
    
    # 1. Denied HTTP action
    action1 = Action(
        id=str(uuid.uuid4()),
        agent_id="demo",
        tool="http",
        operation="delete",
        params={"url": "https://example.com/api/users/123"},
        context={"demo": True},
        decision=Decision.DENY,
        status=Status.DENIED,
        reason="demo seed",
        risk_level="high",
        created_at=now,
        updated_at=now,
        approval_token=None,
        policy_version=None,
    )
    demo_actions.append(action1)
    
    # 2. Allowed HTTP action
    action2 = Action(
        id=str(uuid.uuid4()),
        agent_id="demo",
        tool="http",
        operation="get",
        params={"url": "https://api.example.com/data"},
        context={"demo": True},
        decision=Decision.ALLOW,
        status=Status.ALLOWED,
        reason="demo seed",
        risk_level="low",
        created_at=now,
        updated_at=now,
        approval_token=None,
        policy_version=None,
    )
    demo_actions.append(action2)
    
    # 3. Pending approval shell action
    action3 = Action(
        id=str(uuid.uuid4()),
        agent_id="demo",
        tool="shell",
        operation="run",
        params={"cmd": "rm -rf /tmp/test"},
        context={"demo": True},
        decision=Decision.REQUIRE_APPROVAL,
        status=Status.PENDING_APPROVAL,
        reason="demo seed",
        risk_level="high",
        created_at=now,
        updated_at=now,
        approval_token=secrets.token_urlsafe(16),
        policy_version=None,
    )
    demo_actions.append(action3)
    
    # 4. Approved shell action
    action4 = Action(
        id=str(uuid.uuid4()),
        agent_id="demo",
        tool="shell",
        operation="run",
        params={"cmd": "echo 'Hello from Faramesh'"},
        context={"demo": True},
        decision=Decision.ALLOW,
        status=Status.APPROVED,
        reason="demo seed",
        risk_level="medium",
        created_at=now,
        updated_at=now,
        approval_token=None,
        policy_version=None,
    )
    demo_actions.append(action4)
    
    # 5. Succeeded action
    action5 = Action(
        id=str(uuid.uuid4()),
        agent_id="demo",
        tool="http",
        operation="post",
        params={"url": "https://api.example.com/webhook", "data": {"event": "test"}},
        context={"demo": True},
        decision=Decision.ALLOW,
        status=Status.SUCCEEDED,
        reason="demo seed",
        risk_level="low",
        created_at=now,
        updated_at=now,
        approval_token=None,
        policy_version=None,
    )
    demo_actions.append(action5)
    
    # Insert all demo actions
    store.seed_demo_actions(demo_actions)


# Run demo seed on startup
_seed_demo_actions()


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/ready")
def ready():
    """Readiness check endpoint."""
    return {"status": "ready"}


@app.get("/metrics")
def metrics():
    """Prometheus metrics endpoint."""
    return get_metrics_response()


@app.get("/v1/policy/info")
def get_policy_info():
    """Get policy file information."""
    policy_file = settings.policy_file
    policy_path = Path(policy_file)
    
    # Resolve relative paths
    if not policy_path.is_absolute():
        package_root = Path(__file__).resolve().parents[2]
        policy_path = package_root / policy_file
    
    policy_exists = policy_path.exists()
    policy_version = policies.policy_version() if policy_exists else None
    
    return {
        "policy_file": policy_file,
        "policy_path": str(policy_path),
        "exists": policy_exists,
        "policy_version": policy_version,
    }


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    agent_id: str
    tool: str
    operation: str
    params: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None


class ResultRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    success: bool
    error: Optional[str] = None


class ActionResponse(BaseModel):
    id: str
    agent_id: str
    tool: str
    operation: str
    params: Dict[str, Any]
    context: Dict[str, Any]
    status: str
    decision: Optional[str]
    reason: Optional[str]
    risk_level: Optional[str]
    approval_token: Optional[str]
    policy_version: Optional[str]
    created_at: str
    updated_at: str
    js_example: Optional[str] = None
    python_example: Optional[str] = None
    # Execution gate fields
    outcome: Optional[str] = None
    reason_code: Optional[str] = None
    reason_details: Optional[Dict[str, Any]] = None
    request_hash: Optional[str] = None
    policy_hash: Optional[str] = None
    runtime_version: Optional[str] = None
    profile_id: Optional[str] = None
    profile_version: Optional[str] = None
    profile_hash: Optional[str] = None
    provenance_id: Optional[str] = None


def _build_sdk_examples(action: Action) -> Dict[str, Optional[str]]:
    """
    Build JS and Python SDK example snippets for an action.

    These are purely DX helpers and do not affect core behavior.
    """
    import logging
    
    # Use API base from settings if available, fall back to localhost
    try:
        api_base = settings.api_base if getattr(settings, "api_base", None) else "http://127.0.0.1:8000"
    except Exception as e:
        logging.warning(f"Failed to get API base from settings: {e}")
        api_base = "http://127.0.0.1:8000"

    # Make params/context JSON pretty for embedding in code blocks
    # Use safe serialization with error handling
    try:
        params = getattr(action, "params", None) or {}
        params_json = json.dumps(params, indent=2, default=str)
    except (TypeError, ValueError) as e:
        logging.warning(f"Failed to serialize params for SDK example: {e}")
        params_json = "{}"

    try:
        context = getattr(action, "context", None) or {}
        context_json = json.dumps(context, indent=2, default=str)
    except (TypeError, ValueError) as e:
        logging.warning(f"Failed to serialize context for SDK example: {e}")
        context_json = "{}"

    # Safe string formatting with defensive checks
    agent_id = getattr(action, "agent_id", "unknown")
    tool = getattr(action, "tool", "unknown")
    operation = getattr(action, "operation", "unknown")
    
    # Escape quotes in strings to prevent injection in code examples
    def escape_for_code(s: str) -> str:
        if not isinstance(s, str):
            return str(s)
        return s.replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
    
    safe_api_base = escape_for_code(api_base)
    safe_agent_id = escape_for_code(agent_id)
    safe_tool = escape_for_code(tool)
    safe_operation = escape_for_code(operation)

    python_example = (
        "from faramesh_sdk import configure, submit_action\n\n"
        f"configure(base_url=\"{safe_api_base}\", token=\"your-token\")\n"
        "action = submit_action(\n"
        "action = client.submit_action(\n"
        f"    tool=\"{safe_tool}\",\n"
        f"    operation=\"{safe_operation}\",\n"
        f"    params={params_json},\n"
        f"    context={context_json},\n"
        ")\n"
    )

    js_example = (
        "import {{ configure, submitAction }} from \"@faramesh/sdk\";\n\n"
        f"configure({{ baseUrl: \"{safe_api_base}\", token: \"your-token\" }});\n\n"
        "const action = await submitAction(\n"
        f"  \"{safe_agent_id}\",\n"
        f"  \"{safe_tool}\",\n"
        f"  \"{safe_operation}\",\n"
        f"  {params_json},\n"
        f"  {context_json}\n"
        ");\n"
    )

    return {
        "python_example": python_example,
        "js_example": js_example,
    }


def action_to_response(action: Action, override: Optional[datetime] = None):
    """
    Convert an Action to the public response model, including optional
    SDK snippets for DX. Existing fields and shapes remain unchanged.
    """
    if not action:
        raise ValueError("action cannot be None")
    
    # Defensive checks for required fields
    if not hasattr(action, "status") or not action.status:
        raise ValueError("action must have a status")
    
    updated = override or action.updated_at
    if not updated:
        updated = datetime.utcnow()
    
    examples = _build_sdk_examples(action)

    return ActionResponse(
        id=getattr(action, "id", "unknown"),
        agent_id=getattr(action, "agent_id", "unknown"),
        tool=getattr(action, "tool", "unknown"),
        operation=getattr(action, "operation", "unknown"),
        params=getattr(action, "params", {}),
        context=getattr(action, "context", {}),
        status=action.status.value,
        decision=action.decision.value if hasattr(action, "decision") and action.decision else None,
        reason=getattr(action, "reason", None),
        risk_level=getattr(action, "risk_level", None),
        approval_token=getattr(action, "approval_token", None),
        policy_version=getattr(action, "policy_version", None),
        created_at=action.created_at.isoformat() + "Z" if hasattr(action, "created_at") and action.created_at else datetime.utcnow().isoformat() + "Z",
        updated_at=updated.isoformat() + "Z",
        js_example=examples.get("js_example"),
        python_example=examples.get("python_example"),
        outcome=action.outcome.value if hasattr(action, "outcome") and action.outcome else None,
        reason_code=getattr(action, "reason_code", None),
        reason_details=getattr(action, "reason_details", None),
        request_hash=getattr(action, "request_hash", None),
        policy_hash=getattr(action, "policy_hash", None),
        runtime_version=getattr(action, "runtime_version", None),
        profile_id=getattr(action, "profile_id", None),
        profile_version=getattr(action, "profile_version", None),
        profile_hash=getattr(action, "profile_hash", None),
        provenance_id=getattr(action, "provenance_id", None),
    )


@app.post("/v1/actions/{action_id}/result", response_model=ActionResponse)
def record_action_result(action_id: str, body: ResultRequest):
    """Record the result of an action execution."""
    try:
        # Validate action_id
        try:
            validate_external_string(action_id, "action_id")
        except SecurityError as e:
            raise ValidationError(f"Invalid action_id: {e}")
        
        # Get action with error handling
        try:
            action = store.get_action(action_id)
        except Exception as e:
            import logging
            logging.error(f"Database error getting action {action_id}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve action: {str(e)}"
            )
        
        if not action:
            raise ActionNotFoundError(action_id)

        if action.status not in (
            Status.EXECUTING,
            Status.ALLOWED,
            Status.APPROVED,
            Status.PENDING_APPROVAL,
        ):
            raise ActionNotExecutableError(
                action_id,
                f"Action is not in an executable status (current: {action.status.value})"
            )

        # Store original version for optimistic locking
        original_version = action.version

        if body.success:
            action.status = Status.SUCCEEDED
            action.reason = "Execution completed"
            event_type = "succeeded"
        else:
            action.status = Status.FAILED
            # Validate error message if provided
            error_msg = body.error or "Execution failed"
            if error_msg:
                try:
                    # Truncate error message if too long
                    if len(error_msg) > 1000:
                        error_msg = error_msg[:1000] + "... (truncated)"
                except Exception:
                    error_msg = "Execution failed"
            action.reason = error_msg
            event_type = "failed"

        action.updated_at = datetime.utcnow()
        
        # Update with optimistic locking
        try:
            success = store.update_action(action, expected_version=original_version)
            if not success:
                # Version mismatch - retry once
                action = store.get_action(action_id)
                if action:
                    if body.success:
                        action.status = Status.SUCCEEDED
                        action.reason = "Execution completed"
                    else:
                        action.status = Status.FAILED
                        action.reason = body.error or "Execution failed"
                    action.updated_at = datetime.utcnow()
                    retry_success = store.update_action(action, expected_version=action.version)
                    if not retry_success:
                        raise HTTPException(
                            status_code=409,
                            detail="Action was modified by another request. Please refresh and try again."
                        )
                else:
                    raise HTTPException(
                        status_code=409,
                        detail="Action was modified by another request. Please refresh and try again."
                    )
        except Exception as e:
            import logging
            logging.error(f"Database error updating action {action_id}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to update action: {str(e)}"
            )
        
        # Write event: succeeded or failed (best effort)
        try:
            store.create_event(action_id, event_type, {
                "reason": action.reason,
                "error": body.error if not body.success else None
            })
        except Exception as e:
            import logging
            logging.warning(f"Failed to create '{event_type}' event: {e}")
        
        return action_to_response(action)
        
    except (ActionNotFoundError, ActionNotExecutableError, ValidationError):
        raise
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logging.error(f"Unexpected error in record_action_result: {e}", exc_info=True)
        errors_total.inc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@app.post("/v1/actions", response_model=ActionResponse)
async def submit_action(req: ActionRequest):
    """Submit a new action for policy evaluation."""
    start_time = time.time()
    
    try:
        # Validate all external string inputs
        agent_id = validate_external_string(req.agent_id, "agent_id")
        tool = validate_external_string(req.tool, "tool")
        operation = validate_external_string(req.operation, "operation")
        
        # Validate and sanitize params
        try:
            validated_params = validate_action_params(req.params or {}, tool)
        except SecurityError as e:
            raise ValidationError(f"Invalid action parameters: {e}")
        
        # Validate context
        try:
            validated_context = validate_context(req.context)
        except SecurityError as e:
            raise ValidationError(f"Invalid context: {e}")
        
        # Load profile if available
        profile = load_profile_from_env()
        
        # Evaluate decision using centralized decision engine
        decision_result = evaluate_decision(
            agent_id=agent_id,
            tool=tool,
            operation=operation,
            params=validated_params,
            context=validated_context,
            policy_engine=policies,
            profile=profile,
            runtime_version=runtime_version_str,
        )
        
        # Map DecisionOutcome back to Decision enum for compatibility
        if decision_result.outcome == DecisionOutcome.EXECUTE:
            decision = Decision.ALLOW
            action_status = Status.ALLOWED
        elif decision_result.outcome == DecisionOutcome.HALT:
            decision = Decision.DENY
            action_status = Status.DENIED
        else:  # ABSTAIN
            decision = Decision.REQUIRE_APPROVAL
            action_status = Status.PENDING_APPROVAL
        
        # Create action with decision result fields
        action = Action.new(
            agent_id=agent_id,
            tool=tool,
            operation=operation,
            params=validated_params,
            context=validated_context,
        )
        
        # Set decision fields
        action.decision = decision
        action.status = action_status
        action.reason = decision_result.reason
        # Extract risk_level from reason_details if available, else infer from outcome
        if decision_result.reason_details and "risk_level" in decision_result.reason_details:
            action.risk_level = decision_result.reason_details["risk_level"]
        else:
            action.risk_level = "high" if decision_result.outcome == DecisionOutcome.HALT else "low"
        action.policy_version = decision_result.policy_version
        
        # Set execution gate fields
        action.outcome = decision_result.outcome
        action.reason_code = decision_result.reason_code
        action.reason_details = decision_result.reason_details
        action.request_hash = decision_result.request_hash
        action.policy_hash = decision_result.policy_hash
        action.runtime_version = decision_result.runtime_version
        action.profile_id = decision_result.profile_id
        action.profile_version = decision_result.profile_version
        action.profile_hash = decision_result.profile_hash
        action.provenance_id = decision_result.provenance_id
        
        if decision == Decision.REQUIRE_APPROVAL:
            action.approval_token = secrets.token_urlsafe(16)

        # Note: enforce_no_side_effects is NOT called here because we're just creating the action.
        # It will be called when execution is attempted (in executor.py and start_execution endpoint).

        # Store action with error handling
        try:
            store.create_action(action)
        except Exception as e:
            import logging
            logging.error(f"Failed to create action in database: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create action: {str(e)}"
            )
        
        # Write event: created (best effort)
        try:
            store.create_event(action.id, "created", {"decision": decision.value if decision else None, "risk_level": action.risk_level})
        except Exception as e:
            import logging
            logging.warning(f"Failed to create 'created' event: {e}")
        
        # Write event: decision_made (best effort)
        try:
            store.create_event(action.id, "decision_made", {
                "decision": decision.value if decision else None,
                "outcome": action.outcome.value if action.outcome else None,
                "reason_code": action.reason_code,
                "reason": action.reason,
                "risk_level": action.risk_level,
                "request_hash": action.request_hash,
            })
        except Exception as e:
            import logging
            logging.warning(f"Failed to create 'decision_made' event: {e}")
        
        # Emit event (best effort)
        try:
            await emit_action_event("action.created", action)
        except Exception as e:
            import logging
            logging.warning(f"Failed to emit action.created event: {e}")
        
        # Record metrics
        duration = time.time() - start_time
        try:
            actions_total.labels(status=action.status.value, tool=action.tool).inc()
            action_duration_seconds.labels(tool=action.tool, operation=action.operation).observe(duration)
        except Exception as e:
            import logging
            logging.warning(f"Failed to record metrics: {e}")
        
        return action_to_response(action)
        
    except ValidationError:
        raise
    except SecurityError as e:
        raise ValidationError(f"Security validation failed: {e}")
    except Exception as e:
        import logging
        logging.error(f"Unexpected error in submit_action: {e}", exc_info=True)
        errors_total.inc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


class GateDecisionRequest(BaseModel):
    """Request model for gate decide endpoint."""
    model_config = ConfigDict(extra="forbid")
    
    agent_id: str
    tool: str
    operation: str
    params: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None


class GateDecisionResponse(BaseModel):
    """Response model for gate decide endpoint."""
    outcome: str
    reason_code: str
    reason: Optional[str] = None
    request_hash: str
    policy_version: Optional[str] = None
    policy_hash: Optional[str] = None
    profile_id: Optional[str] = None
    profile_version: Optional[str] = None
    profile_hash: Optional[str] = None
    runtime_version: Optional[str] = None
    provenance_id: Optional[str] = None


@app.post("/v1/gate/decide", response_model=GateDecisionResponse)
async def gate_decide(req: GateDecisionRequest):
    """
    Decide-only execution gate endpoint.
    
    Evaluates policy and profile but does NOT create an action or trigger execution.
    Returns decision with version-bound fields for replay and audit.
    """
    try:
        # Validate inputs
        agent_id = validate_external_string(req.agent_id, "agent_id")
        tool = validate_external_string(req.tool, "tool")
        operation = validate_external_string(req.operation, "operation")
        
        # Validate and sanitize params
        try:
            validated_params = validate_action_params(req.params or {}, tool)
        except SecurityError as e:
            raise ValidationError(f"Invalid action parameters: {e}")
        
        # Validate context
        try:
            validated_context = validate_context(req.context)
        except SecurityError as e:
            raise ValidationError(f"Invalid context: {e}")
        
        # Load profile if available
        profile = load_profile_from_env()
        
        # Evaluate decision using centralized decision engine
        decision_result = evaluate_decision(
            agent_id=agent_id,
            tool=tool,
            operation=operation,
            params=validated_params,
            context=validated_context,
            policy_engine=policies,
            profile=profile,
            runtime_version=runtime_version_str,
        )
        
        return GateDecisionResponse(
            outcome=decision_result.outcome.value,
            reason_code=decision_result.reason_code,
            reason=decision_result.reason,
            request_hash=decision_result.request_hash,
            policy_version=decision_result.policy_version,
            policy_hash=decision_result.policy_hash,
            profile_id=decision_result.profile_id,
            profile_version=decision_result.profile_version,
            profile_hash=decision_result.profile_hash,
            runtime_version=decision_result.runtime_version,
            provenance_id=decision_result.provenance_id,
        )
        
    except ValidationError:
        raise
    except Exception as e:
        import logging
        logging.error(f"Unexpected error in gate_decide: {e}", exc_info=True)
        errors_total.inc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/v1/actions/{action_id}", response_model=ActionResponse)
def get_action(action_id: str):
    """Get a specific action by ID."""
    try:
        # Validate action_id
        try:
            validate_external_string(action_id, "action_id")
        except SecurityError as e:
            raise ValidationError(f"Invalid action_id: {e}")
        
        # Get action with error handling
        try:
            action = store.get_action(action_id)
        except Exception as e:
            import logging
            logging.error(f"Database error getting action {action_id}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve action: {str(e)}"
            )
        
        if not action:
            raise ActionNotFoundError(action_id)
        
        return action_to_response(action)
        
    except (ActionNotFoundError, ValidationError):
        raise
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logging.error(f"Unexpected error in get_action: {e}", exc_info=True)
        errors_total.inc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    token: str
    approve: bool
    reason: Optional[str] = None


@app.post("/v1/actions/{action_id}/approval", response_model=ActionResponse)
async def approve_action(action_id: str, body: ApprovalRequest):
    """Approve or deny a pending action."""
    try:
        # Validate action_id
        try:
            validate_external_string(action_id, "action_id")
        except SecurityError as e:
            raise ValidationError(f"Invalid action_id: {e}")
        
        # Get action with error handling
        try:
            action = store.get_action(action_id)
        except Exception as e:
            import logging
            logging.error(f"Database error getting action {action_id}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve action: {str(e)}"
            )
        
        if not action:
            raise ActionNotFoundError(action_id)
        
        if action.status != Status.PENDING_APPROVAL:
            raise ActionNotExecutableError(
                action_id,
                f"Action is not in pending_approval status (current: {action.status.value})"
            )
        
        # Validate approval token
        if not action.approval_token:
            raise UnauthorizedError("Action has no approval token")
        
        if body.token != action.approval_token:
            raise UnauthorizedError("Invalid approval token")

        # Store original version for optimistic locking
        original_version = action.version

        if body.approve:
            action.status = Status.APPROVED
            action.decision = Decision.ALLOW
            action.reason = body.reason or "Approved by human"
            action.approval_token = None
        else:
            action.status = Status.DENIED
            action.decision = Decision.DENY
            action.reason = body.reason or "Denied by human"
            action.approval_token = None
        
        action.updated_at = datetime.utcnow()
        
        # Update with optimistic locking
        try:
            success = store.update_action(action, expected_version=original_version)
            if not success:
                # Version mismatch - retry once
                action = store.get_action(action_id)
                if action and action.status == Status.PENDING_APPROVAL:
                    # Retry update
                    if body.approve:
                        action.status = Status.APPROVED
                        action.decision = Decision.ALLOW
                    else:
                        action.status = Status.DENIED
                        action.decision = Decision.DENY
                    action.updated_at = datetime.utcnow()
                    retry_success = store.update_action(action, expected_version=action.version)
                    if not retry_success:
                        raise HTTPException(
                            status_code=409,
                            detail="Action was modified by another request. Please refresh and try again."
                        )
                else:
                    raise HTTPException(
                        status_code=409,
                        detail="Action was modified by another request. Please refresh and try again."
                    )
        except Exception as e:
            import logging
            logging.error(f"Database error updating action {action_id}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to update action: {str(e)}"
            )
        
        # Write event: approved or denied (best effort)
        try:
            event_type = "approved" if body.approve else "denied"
            store.create_event(action_id, event_type, {"reason": body.reason})
        except Exception as e:
            import logging
            logging.warning(f"Failed to create '{event_type}' event: {e}")
        
        # Emit event (best effort)
        try:
            event_type = "action.approved" if body.approve else "action.denied"
            await emit_action_event(event_type, action)
        except Exception as e:
            import logging
            logging.warning(f"Failed to emit {event_type} event: {e}")

        return action_to_response(action)
        
    except (ActionNotFoundError, ActionNotExecutableError, UnauthorizedError, ValidationError):
        raise
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logging.error(f"Unexpected error in approve_action: {e}", exc_info=True)
        errors_total.inc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@app.post("/v1/actions/{action_id}/start", response_model=ActionResponse)
def start_execution(action_id: str):
    """Start execution of an approved/allowed action."""
    try:
        # Validate action_id
        try:
            validate_external_string(action_id, "action_id")
        except SecurityError as e:
            raise ValidationError(f"Invalid action_id: {e}")
        
        # Get action with error handling
        try:
            action = store.get_action(action_id)
        except Exception as e:
            import logging
            logging.error(f"Database error getting action {action_id}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve action: {str(e)}"
            )
        
        if not action:
            raise ActionNotFoundError(action_id)
        
        if action.status not in (Status.ALLOWED, Status.APPROVED):
            raise ActionNotExecutableError(
                action_id,
                f"Action must be in 'allowed' or 'approved' status to start execution (current: {action.status.value})"
            )
        
        # CRITICAL: Enforce no side effects on pending
        try:
            enforce_no_side_effects(action.status.value, action.decision.value if action.decision else "deny")
        except SecurityError as e:
            import logging
            logging.error(f"SECURITY VIOLATION: Attempted to start execution of unapproved action {action_id}: {e}")
            raise HTTPException(
                status_code=403,
                detail=f"Security violation: {e}"
            )
        
        # Write event: started (executor will also write it, but this ensures it's there)
        try:
            store.create_event(action_id, "started", {})
        except Exception as e:
            import logging
            logging.warning(f"Failed to create 'started' event: {e}")
        
        # Start execution - skip policy check since action is already approved/allowed
        # Note: executor will also write "started" event, but that's okay (idempotent)
        try:
            executor.try_execute(action, skip_policy_check=True)
        except Exception as e:
            import logging
            logging.error(f"Failed to start execution for action {action_id}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to start execution: {str(e)}"
            )
        
        # Get updated action
        try:
            action = store.get_action(action_id)
            if not action:
                raise ActionNotFoundError(action_id)
        except Exception as e:
            import logging
            logging.error(f"Database error getting updated action {action_id}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve updated action: {str(e)}"
            )
        
        return action_to_response(action)
        
    except (ActionNotFoundError, ActionNotExecutableError, ValidationError):
        raise
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logging.error(f"Unexpected error in start_execution: {e}", exc_info=True)
        errors_total.inc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


def action_to_response_safe(action: Action) -> dict:
    """Convert action to response dict, hiding approval_token for list responses."""
    resp = action_to_response(action)
    # Convert Pydantic model to dict
    if hasattr(resp, 'model_dump'):
        resp_dict = resp.model_dump()
    elif hasattr(resp, 'dict'):
        resp_dict = resp.dict()
    else:
        resp_dict = dict(resp)
    resp_dict.pop('approval_token', None)
    return resp_dict

@app.get("/v1/actions")
def list_actions(
    limit: int = 20,
    offset: int = 0,
    agent_id: Optional[str] = None,
    tool: Optional[str] = None,
    status: Optional[str] = None,
):
    """List actions with optional filtering."""
    try:
        # Validate limit and offset types and values
        try:
            limit = int(limit)
        except (ValueError, TypeError):
            limit = 20
        try:
            offset = int(offset)
        except (ValueError, TypeError):
            offset = 0
        
        if limit < 1:
            limit = 20
        if limit > 1000:
            limit = 1000  # Cap at reasonable maximum
        if offset < 0:
            offset = 0
        
        filters = {}
        if agent_id:
            try:
                filters["agent_id"] = validate_external_string(agent_id, "agent_id")
            except SecurityError as e:
                raise ValidationError(f"Invalid agent_id filter: {e}")
        if tool:
            try:
                filters["tool"] = validate_external_string(tool, "tool")
            except SecurityError as e:
                raise ValidationError(f"Invalid tool filter: {e}")
        if status:
            try:
                filters["status"] = validate_external_string(status, "status")
            except SecurityError as e:
                raise ValidationError(f"Invalid status filter: {e}")
        
        try:
            actions = store.list_actions(limit=limit, offset=offset, **filters)
        except Exception as e:
            import logging
            logging.error(f"Database error in list_actions: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to list actions: {str(e)}"
            )
        
        return [action_to_response_safe(a) for a in actions]
        
    except ValidationError:
        raise
    except Exception as e:
        import logging
        logging.error(f"Unexpected error in list_actions: {e}", exc_info=True)
        errors_total.inc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/v1/actions/{action_id}/events")
def get_action_events(action_id: str):
    """Get event timeline for an action."""
    try:
        # Validate action_id
        try:
            validate_external_string(action_id, "action_id")
        except SecurityError as e:
            raise ValidationError(f"Invalid action_id: {e}")
        
        # Verify action exists
        try:
            action = store.get_action(action_id)
        except Exception as e:
            import logging
            logging.error(f"Database error getting action {action_id}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve action: {str(e)}"
            )
        
        if not action:
            raise ActionNotFoundError(action_id)
        
        # Get events with error handling
        try:
            events = store.get_events(action_id)
        except Exception as e:
            import logging
            logging.error(f"Database error getting events for action {action_id}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve events: {str(e)}"
            )
        
        return events
        
    except (ActionNotFoundError, ValidationError):
        raise
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logging.error(f"Unexpected error in get_action_events: {e}", exc_info=True)
        errors_total.inc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/v1/events")
async def stream_events(request: Request):
    """Server-Sent Events stream for real-time action updates."""
    event_manager = get_event_manager()
    return await event_manager.stream_events(request)
