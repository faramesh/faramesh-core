# Browser / WASM agents (remote daemon)

Browsers and WASM sandboxes **do not** embed the Go WAL or DPR stack. Treat them as **untrusted clients** that call a **remote** `faramesh serve` (or cluster sidecar) over **HTTPS** with authenticated requests.

## Pattern

1. **Backend-for-frontend** or extension holds short-lived credentials; the browser calls **your** API only.
2. Your service forwards tool/capability requests to **`faramesh`** (SDK or HTTP authorize) and returns only **allow/deny/defer** outcomes and safe metadata — never raw policy YAML to the client.
3. Use **`vars.deployment_kind`** / **`vars.faramesh_version`** in policy to tighten rules for `unknown` or non-server environments.

## Out of scope here

- In-browser WAL or tamper-evident storage without a dedicated threat model.
- Direct browser → daemon exposure without TLS and auth.

See **`internal/adapter/serverless`** for HTTP handler shapes when mounting authorize behind API Gateway / Cloud Run.
