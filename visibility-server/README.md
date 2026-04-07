# Faramesh Visibility Server

Local FastAPI service for live governance visibility.

## What it does

- Subscribes to daemon callback stream via `callback_subscribe`
- Subscribes to daemon audit stream via `audit_subscribe`
- Maintains an action timeline keyed by call id with SQLite persistence
- Links callback `record_id` values to DPR hash fields from SQLite
- Exposes old-Faramesh style action and approval endpoints for operators
- Runs integrity verification with `faramesh audit verify`
- Surfaces runtime identity and credential-vault health
- Serves a web UI for action lifecycle and defer controls

Sensitive values are redacted from the HTTP API surface:

- Runtime credential responses expose metadata only, never raw key material
- Action responses redact raw tool params and defer/approval tokens
- Browser approval flows resolve pending actions by call id without exposing the underlying token

## Endpoints

- `GET /healthz`
- `GET /health`
- `GET /runtime`
- `GET /actions`
- `GET /actions/{call_id}`
- `GET /v1/actions`
- `GET /v1/actions/{call_id}`
- `POST /v1/actions/{call_id}/approval`
- `GET /defers/pending`
- `POST /defers/{token}/approve`
- `POST /defers/{token}/deny`
- `GET /integrity/verify`

## Run

```bash
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core/visibility-server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8787 --reload
```

Open http://127.0.0.1:8787

## Configuration

Environment variables:

- `FARAMESH_SOCKET` (default: `/tmp/faramesh.sock`)
- `FARAMESH_DPR_DB` (default: `../.tmp/langchain-real/data/faramesh.db`)
- `FARAMESH_CORE_DIR` (default: parent folder of `visibility-server`)
- `FARAMESH_VISIBILITY_DB` (default: `../.tmp/visibility/visibility.db`)
- `FARAMESH_AUDIT_COMMAND` (default: `go run ./cmd/faramesh audit verify {db_path}`)
- `FARAMESH_STREAM_RETRY_SECONDS` (default: `1.0`)
- `FARAMESH_EVENT_RETENTION` (default: `2000`)
- `FARAMESH_INTEGRITY_TIMEOUT_SECONDS` (default: `30`)

## Test

```bash
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core/visibility-server
python3 -m unittest discover -s tests -v
```
