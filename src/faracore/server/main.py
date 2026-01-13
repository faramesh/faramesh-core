# server/main.py
from __future__ import annotations
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, List
import os
import secrets
import time
import uuid

from fastapi import FastAPI, HTTPException, Request
from starlette.requests import Request as StarletteRequest
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .models import Action, Status, Decision
from .settings import get_settings
from .storage import get_store
from .policy_engine import PolicyEngine
from .executor import ActionExecutor
from .auth import AuthMiddleware
from .errors import (
    ActionNotFoundError,
    ActionNotExecutableError,
    UnauthorizedError,
)
from .events import get_event_manager, emit_action_event
from .metrics import get_metrics_response, requests_total, errors_total, actions_total, action_duration_seconds

settings = get_settings()
store = get_store()
executor = ActionExecutor(store)
policies = PolicyEngine(settings.policy_file)

app = FastAPI(title="FaraCore - Agent Action Governor")

# CORS middleware - enabled by default to maintain current behavior
# Can be explicitly controlled via FARACORE_ENABLE_CORS env var
# Default: enabled (maintains current behavior)
# Set FARACORE_ENABLE_CORS=0 to disable, FARACORE_ENABLE_CORS=1 to explicitly enable
enable_cors_env = os.getenv("FARACORE_ENABLE_CORS")
if enable_cors_env is None or enable_cors_env == "1":
    # Default behavior: CORS enabled (maintains backward compatibility)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Add auth middleware if token is configured
# Check FARACORE_TOKEN env var first, then settings.auth_token
auth_token = os.getenv("FARACORE_TOKEN") or settings.auth_token
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
    <title>FaraCore Policy Playground</title>
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
    <h1>FaraCore Policy Playground</h1>
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
    <title>FaraCore Playground</title>
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
    <h1>FaraCore Playground</h1>
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


# Demo seed mode - only if FARACORE_DEMO=1 and DB is empty
def _seed_demo_actions():
    """Seed demo actions if FARACORE_DEMO=1 and database is empty."""
    if os.getenv("FARACORE_DEMO") != "1":
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
        params={"cmd": "echo 'Hello from FaraCore'"},
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
    agent_id: str
    tool: str
    operation: str
    params: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None


class ResultRequest(BaseModel):
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


def _build_sdk_examples(action: Action) -> Dict[str, Optional[str]]:
    """
    Build JS and Python SDK example snippets for an action.

    These are purely DX helpers and do not affect core behavior.
    """
    # Use API base from settings if available, fall back to localhost
    try:
        api_base = settings.api_base if getattr(settings, "api_base", None) else "http://127.0.0.1:8000"
    except Exception:
        api_base = "http://127.0.0.1:8000"

    # Make params/context JSON pretty for embedding in code blocks
    try:
        params_json = json.dumps(action.params or {}, indent=2)
    except Exception:
        params_json = "{}"

    try:
        context_json = json.dumps(action.context or {}, indent=2)
    except Exception:
        context_json = "{}"

    python_example = (
        "from faracore.sdk.client import ExecutionGovernorClient, GovernorConfig\n\n"
        f"config = GovernorConfig(base_url=\"{api_base}\", agent_id=\"{action.agent_id}\")\n"
        "client = ExecutionGovernorClient(config)\n\n"
        "action = client.submit_action(\n"
        f"    tool=\"{action.tool}\",\n"
        f"    operation=\"{action.operation}\",\n"
        f"    params={params_json},\n"
        f"    context={context_json},\n"
        ")\n"
    )

    js_example = (
        "import { ExecutionGovernorClient } from \"@fara/core\";\n\n"
        f"const client = new ExecutionGovernorClient(\"{api_base}\", {{ agentId: \"{action.agent_id}\" }});\n\n"
        "const action = await client.submitAction({\n"
        f"  tool: \"{action.tool}\",\n"
        f"  operation: \"{action.operation}\",\n"
        f"  params: {params_json},\n"
        f"  context: {context_json},\n"
        "});\n"
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
    updated = override or action.updated_at
    examples = _build_sdk_examples(action)

    return ActionResponse(
        id=action.id,
        agent_id=action.agent_id,
        tool=action.tool,
        operation=action.operation,
        params=action.params,
        context=action.context,
        status=action.status.value,
        decision=action.decision.value if action.decision else None,
        reason=action.reason,
        risk_level=action.risk_level,
        approval_token=action.approval_token,
        policy_version=getattr(action, "policy_version", None),
        created_at=action.created_at.isoformat() + "Z",
        updated_at=updated.isoformat() + "Z",
        js_example=examples.get("js_example"),
        python_example=examples.get("python_example"),
    )


@app.post("/v1/actions/{action_id}/result", response_model=ActionResponse)
def record_action_result(action_id: str, body: ResultRequest):
    action = store.get_action(action_id)
    if not action:
        raise ActionNotFoundError(action_id)

    if action.status not in (
        Status.EXECUTING,
        Status.ALLOWED,
        Status.APPROVED,
        Status.PENDING_APPROVAL,
    ):
        raise ActionNotExecutableError(action_id, action.status.value)

    if body.success:
        action.status = Status.SUCCEEDED
        action.reason = "Execution completed"
        event_type = "succeeded"
    else:
        action.status = Status.FAILED
        action.reason = body.error or "Execution failed"
        event_type = "failed"

    action.updated_at = datetime.utcnow()
    store.update_action(action)
    
    # Write event: succeeded or failed
    try:
        store.create_event(action_id, event_type, {"reason": action.reason, "error": body.error if not body.success else None})
    except Exception:
        pass
    
    return action_to_response(action)


@app.post("/v1/actions", response_model=ActionResponse)
async def submit_action(req: ActionRequest):
    start_time = time.time()
    
    ctx = req.context or {}

    action = Action.new(
        agent_id=req.agent_id,
        tool=req.tool,
        operation=req.operation,
        params=req.params,
        context=ctx,
    )
    
    decision, reason, risk = policies.evaluate(
        tool=req.tool,
        operation=req.operation,
        params=req.params,
        context=ctx,
    )
    action.decision = decision
    action.reason = reason
    action.risk_level = risk
    action.policy_version = policies.policy_version()

    if decision == Decision.ALLOW:
        action.status = Status.ALLOWED
    elif decision == Decision.DENY:
        action.status = Status.DENIED
    else:
        action.status = Status.PENDING_APPROVAL
        action.approval_token = secrets.token_urlsafe(16)

    store.create_action(action)
    
    # Write event: created
    try:
        store.create_event(action.id, "created", {"decision": decision.value if decision else None, "risk_level": risk})
    except Exception:
        pass  # Don't fail if event write fails
    
    # Write event: decision_made
    try:
        store.create_event(action.id, "decision_made", {"decision": decision.value if decision else None, "reason": reason, "risk_level": risk})
    except Exception:
        pass
    
    # Emit event
    try:
        await emit_action_event("action.created", action)
    except Exception:
        pass  # Don't fail if events fail
    
    # Record metrics
    duration = time.time() - start_time
    actions_total.labels(status=action.status.value, tool=action.tool).inc()
    action_duration_seconds.labels(tool=action.tool, operation=action.operation).observe(duration)
    
    return action_to_response(action)


@app.get("/v1/actions/{action_id}", response_model=ActionResponse)
def get_action(action_id: str):
    action = store.get_action(action_id)
    if not action:
        raise ActionNotFoundError(action_id)
    
    return action_to_response(action)


class ApprovalRequest(BaseModel):
    token: str
    approve: bool
    reason: Optional[str] = None


@app.post("/v1/actions/{action_id}/approval", response_model=ActionResponse)
async def approve_action(action_id: str, body: ApprovalRequest):
    action = store.get_action(action_id)
    if not action:
        raise ActionNotFoundError(action_id)
    if action.status != Status.PENDING_APPROVAL:
        raise ActionNotExecutableError(action_id, action.status.value)
    if body.token != action.approval_token:
        raise UnauthorizedError("Invalid approval token")

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
    store.update_action(action)
    
    # Write event: approved or denied
    try:
        event_type = "approved" if body.approve else "denied"
        store.create_event(action_id, event_type, {"reason": body.reason})
    except Exception:
        pass
    
    # Emit event
    try:
        event_type = "action.approved" if body.approve else "action.denied"
        await emit_action_event(event_type, action)
    except Exception:
        pass

    return action_to_response(action)


@app.post("/v1/actions/{action_id}/start", response_model=ActionResponse)
def start_execution(action_id: str):
    action = store.get_action(action_id)
    if not action:
        raise ActionNotFoundError(action_id)
    
    if action.status not in (Status.ALLOWED, Status.APPROVED):
        raise ActionNotExecutableError(action_id, action.status.value)
    
    # Write event: started (executor will also write it, but this ensures it's there)
    try:
        store.create_event(action_id, "started", {})
    except Exception:
        pass
    
    # Start execution - skip policy check since action is already approved/allowed
    # Note: executor will also write "started" event, but that's okay (idempotent)
    executor.try_execute(action, skip_policy_check=True)
    
    # Get updated action
    action = store.get_action(action_id)
    return action_to_response(action)


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
    filters = {}
    if agent_id:
        filters["agent_id"] = agent_id
    if tool:
        filters["tool"] = tool
    if status:
        filters["status"] = status
    
    actions = store.list_actions(limit=limit, offset=offset, **filters)
    
    return [action_to_response_safe(a) for a in actions]


@app.get("/v1/actions/{action_id}/events")
def get_action_events(action_id: str):
    """Get event timeline for an action."""
    action = store.get_action(action_id)
    if not action:
        raise ActionNotFoundError(action_id)
    
    events = store.get_events(action_id)
    return events


@app.get("/v1/events")
async def stream_events(request: Request):
    """Server-Sent Events stream for real-time action updates."""
    event_manager = get_event_manager()
    return await event_manager.stream_events(request)
