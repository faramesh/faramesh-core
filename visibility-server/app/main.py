from __future__ import annotations

import os
import shlex
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.integrity import run_integrity_check
from app.socket_client import send_json_request, stream_json_lines
from app.state import EventStore, utc_now_iso

VISIBILITY_DIR = Path(__file__).resolve().parents[1]
UI_DIR = VISIBILITY_DIR / "ui"
CORE_DIR = Path(os.getenv("FARAMESH_CORE_DIR", str(VISIBILITY_DIR.parent)))
SOCKET_PATH = Path(os.getenv("FARAMESH_SOCKET", "/tmp/faramesh.sock"))
DB_PATH = Path(
    os.getenv(
        "FARAMESH_DPR_DB",
        str(CORE_DIR / ".tmp" / "langchain-real" / "data" / "faramesh.db"),
    )
)
STATE_DB_PATH = Path(
    os.getenv(
        "FARAMESH_VISIBILITY_DB",
        str(CORE_DIR / ".tmp" / "visibility" / "visibility.db"),
    )
)
EVENT_RETENTION = int(os.getenv("FARAMESH_EVENT_RETENTION", "2000"))
STREAM_RETRY_SECONDS = float(os.getenv("FARAMESH_STREAM_RETRY_SECONDS", "1.0"))
INTEGRITY_TIMEOUT_SECONDS = int(os.getenv("FARAMESH_INTEGRITY_TIMEOUT_SECONDS", "30"))
AUDIT_COMMAND = shlex.split(
    os.getenv("FARAMESH_AUDIT_COMMAND", "go run ./cmd/faramesh audit verify {db_path}")
)

STORE = EventStore(
    dpr_db_path=DB_PATH,
    max_actions=EVENT_RETENTION,
    state_db_path=STATE_DB_PATH,
)
STOP_EVENT = threading.Event()
WORKER_THREADS: dict[str, threading.Thread] = {}


class StreamRuntime:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._connected: dict[str, bool] = {"callback": False, "audit": False}
        self._errors: dict[str, str] = {"callback": "", "audit": ""}
        self._last_event_at: str = ""

    def set_connected(self, stream_name: str, connected: bool, error_message: str = "") -> None:
        with self._lock:
            self._connected[stream_name] = connected
            self._errors[stream_name] = error_message

    def mark_event(self) -> None:
        with self._lock:
            self._last_event_at = utc_now_iso()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "connected": dict(self._connected),
                "errors": dict(self._errors),
                "last_event_at": self._last_event_at,
            }


RUNTIME = StreamRuntime()


class ResolutionBody(BaseModel):
    token: str
    reason: str | None = None


class DeferResolutionBody(BaseModel):
    reason: str | None = None


class ApprovalBody(BaseModel):
    token: str
    approve: bool
    reason: str | None = None


app = FastAPI(
    title="Faramesh Visibility Server",
    version="0.1.0",
    description="Live visibility into governance lifecycle and DPR integrity.",
)

app.mount("/ui", StaticFiles(directory=str(UI_DIR)), name="ui")


def _run_stream_loop(stream_name: str, subscribe_payload: dict[str, object], handler) -> None:
    while not STOP_EVENT.is_set():
        try:
            RUNTIME.set_connected(stream_name, True, "")
            for event in stream_json_lines(SOCKET_PATH, subscribe_payload):
                if STOP_EVENT.is_set():
                    break
                if event.get("subscribed"):
                    continue
                handler(event)
                RUNTIME.mark_event()
            RUNTIME.set_connected(stream_name, False, f"{stream_name} stream disconnected")
        except Exception as exc:  # noqa: BLE001
            RUNTIME.set_connected(stream_name, False, str(exc))
        if STOP_EVENT.wait(STREAM_RETRY_SECONDS):
            break


def _start_worker(stream_name: str, subscribe_payload: dict[str, object], handler) -> None:
    worker = threading.Thread(
        target=_run_stream_loop,
        args=(stream_name, subscribe_payload, handler),
        name=f"visibility-{stream_name}-stream",
        daemon=True,
    )
    WORKER_THREADS[stream_name] = worker
    worker.start()


def _resolve_defer(token: str, approved: bool, reason: str) -> dict[str, object]:
    payload = {
        "type": "approve_defer",
        "defer_token": token,
        "approved": approved,
        "reason": reason,
    }
    response = send_json_request(SOCKET_PATH, payload)
    if not bool(response.get("ok")):
        raise HTTPException(status_code=409, detail=response)

    STORE.ingest_callback_event(
        {
            "event_type": "defer_resolved",
            "defer_token": token,
            "status": "approved" if approved else "denied",
            "reason": reason,
            "timestamp": utc_now_iso(),
        }
    )
    return response


def _daemon_call(payload: dict[str, Any], timeout_seconds: float = 1.5) -> dict[str, Any]:
    try:
        response = send_json_request(SOCKET_PATH, payload, timeout_seconds=timeout_seconds)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    if isinstance(response, dict):
        return response
    return {"value": response}


def _runtime_snapshot() -> dict[str, Any]:
    status = _daemon_call({"type": "status"})
    identity = _daemon_call({"type": "identity", "op": "whoami"})
    identity_trust = _daemon_call({"type": "identity", "op": "trust_level"})
    credential_health = _daemon_call({"type": "credential", "op": "health"})
    credential_list = _daemon_call({"type": "credential", "op": "list"})
    sessions = _daemon_call({"type": "session", "op": "list"})
    models = _daemon_call({"type": "model", "op": "list"})

    credentials = []
    if isinstance(credential_list.get("credentials"), list):
        credentials = credential_list["credentials"]

    return {
        "daemon_status": status,
        "identity": {
            "whoami": identity,
            "trust": identity_trust,
        },
        "vault": {
            "health": credential_health,
            "credentials": credentials,
            "count": len(credentials),
        },
        "sessions": sessions,
        "models": models,
        "socket_path": str(SOCKET_PATH),
        "dpr_db_path": str(DB_PATH),
        "visibility_db_path": str(STATE_DB_PATH),
    }


@app.on_event("startup")
def on_startup() -> None:
    STOP_EVENT.clear()
    _start_worker("callback", {"type": "callback_subscribe"}, STORE.ingest_callback_event)
    _start_worker("audit", {"type": "audit_subscribe"}, STORE.ingest_audit_event)


@app.on_event("shutdown")
def on_shutdown() -> None:
    STOP_EVENT.set()
    for worker in WORKER_THREADS.values():
        worker.join(timeout=2)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    index_path = UI_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="ui not found")
    return FileResponse(index_path)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    runtime = RUNTIME.snapshot()
    daemon_status = _daemon_call({"type": "status"}, timeout_seconds=1.0)
    daemon_ok = "error" not in daemon_status
    daemon_error = str(daemon_status.get("error") or "")

    return {
        "ok": True,
        "daemon_ok": daemon_ok,
        "daemon_error": daemon_error,
        "daemon_status": daemon_status,
        "socket_path": str(SOCKET_PATH),
        "db_path": str(DB_PATH),
        "visibility_db_path": str(STATE_DB_PATH),
        "streams": runtime["connected"],
        "stream_errors": runtime["errors"],
        "last_event_at": runtime["last_event_at"],
        "actions_tracked": STORE.count(),
    }


@app.get("/health")
def health() -> dict[str, Any]:
    return healthz()


@app.get("/v1/health")
def v1_health() -> dict[str, Any]:
    return healthz()


@app.get("/runtime")
def runtime_details() -> dict[str, Any]:
    return _runtime_snapshot()


@app.get("/v1/runtime")
def v1_runtime_details() -> dict[str, Any]:
    return _runtime_snapshot()


@app.get("/actions")
def list_actions(limit: int = 200) -> dict[str, Any]:
    bounded_limit = max(1, min(limit, 1000))
    items = STORE.list_actions(limit=bounded_limit)
    return {"count": len(items), "items": items}


@app.get("/actions/{call_id:path}")
def get_action(call_id: str) -> dict[str, Any]:
    action = STORE.get_action(call_id)
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")
    return action


def _resolve_action_defer_token(call_id: str, provided_token: str) -> str:
    action = STORE.get_action(call_id)
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")

    token = str(action.get("defer_token") or "").strip()
    if not token:
        raise HTTPException(status_code=409, detail="action has no defer token")

    cleaned = provided_token.strip()
    if not cleaned or cleaned != token:
        raise HTTPException(status_code=403, detail="invalid approval token")

    state = str(action.get("state") or "")
    if state != "pending":
        raise HTTPException(status_code=409, detail=f"action is not pending (state={state})")

    return token


@app.get("/v1/actions")
def list_v1_actions(
    limit: int = 50,
    status: str | None = None,
    agent: str | None = None,
    tool: str | None = None,
    q: str | None = None,
) -> list[dict[str, Any]]:
    bounded_limit = max(1, min(limit, 1000))
    return STORE.list_legacy_actions(
        limit=bounded_limit,
        status=status,
        agent=agent,
        tool=tool,
        query=q,
    )


@app.get("/v1/actions/{call_id:path}")
def get_v1_action(call_id: str) -> dict[str, Any]:
    action = STORE.get_legacy_action(call_id)
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")
    return action


@app.post("/v1/actions/{call_id:path}/approval")
def approve_v1_action(call_id: str, body: ApprovalBody) -> dict[str, Any]:
    action = STORE.get_legacy_action(call_id)
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")

    token = str(action.get("approval_token") or "").strip()
    if not token:
        raise HTTPException(status_code=409, detail="action has no approval token")

    provided_token = body.token.strip()
    if not provided_token or provided_token != token:
        raise HTTPException(status_code=403, detail="invalid approval token")

    if str(action.get("status") or "") != "pending_approval":
        raise HTTPException(status_code=409, detail="action is not pending approval")

    reason_default = "approved via visibility server" if body.approve else "denied via visibility server"
    reason = (body.reason or reason_default).strip() or reason_default
    _resolve_defer(token, approved=body.approve, reason=reason)

    updated = STORE.get_legacy_action(call_id)
    if updated is None:
        raise HTTPException(status_code=404, detail="action not found after approval")
    return updated


@app.post("/actions/{call_id:path}/approve")
def approve_action(call_id: str, body: ResolutionBody) -> dict[str, Any]:
    token = _resolve_action_defer_token(call_id, body.token)
    reason = (body.reason or "approved via visibility server").strip() or "approved via visibility server"
    result = _resolve_defer(token, approved=True, reason=reason)
    return {"ok": True, "result": result, "call_id": call_id}


@app.post("/actions/{call_id:path}/deny")
def deny_action(call_id: str, body: ResolutionBody) -> dict[str, Any]:
    token = _resolve_action_defer_token(call_id, body.token)
    reason = (body.reason or "denied via visibility server").strip() or "denied via visibility server"
    result = _resolve_defer(token, approved=False, reason=reason)
    return {"ok": True, "result": result, "call_id": call_id}


@app.get("/defers/pending")
def pending_defers() -> dict[str, Any]:
    items = STORE.pending_defers()
    return {"count": len(items), "items": items}


@app.post("/defers/{token}/approve")
def approve_defer(token: str, body: DeferResolutionBody) -> dict[str, Any]:
    reason = (body.reason or "approved via visibility server").strip() or "approved via visibility server"
    result = _resolve_defer(token, approved=True, reason=reason)
    return {"ok": True, "result": result}


@app.post("/defers/{token}/deny")
def deny_defer(token: str, body: DeferResolutionBody) -> dict[str, Any]:
    reason = (body.reason or "denied via visibility server").strip() or "denied via visibility server"
    result = _resolve_defer(token, approved=False, reason=reason)
    return {"ok": True, "result": result}


@app.get("/integrity/verify")
def integrity_verify() -> dict[str, Any]:
    result = run_integrity_check(
        command_template=AUDIT_COMMAND,
        db_path=DB_PATH,
        cwd=CORE_DIR,
        timeout_seconds=INTEGRITY_TIMEOUT_SECONDS,
    )
    result["db_path"] = str(DB_PATH)
    return result


@app.get("/v1/integrity/verify")
def v1_integrity_verify() -> dict[str, Any]:
    return integrity_verify()
