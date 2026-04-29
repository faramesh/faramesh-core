# MCP Interception and Governance (Power-User Spec)

This is the full technical specification for Faramesh MCP governance.

For fast setup, use:

- [MCP_INTERCEPTION_GOVERNANCE_PLAN.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/MCP_INTERCEPTION_GOVERNANCE_PLAN.md)

## Scope

This spec covers Faramesh MCP governance through:

- HTTP gateway (`faramesh serve --mcp-proxy-port ... --mcp-target ...`)
- stdio wrapper (`faramesh mcp wrap -- <mcp-server-cmd>`)

It does not rely on SDK monkeypatching to govern MCP calls.

## Upstream MCP Baseline

Reference repository audited:

- `https://github.com/modelcontextprotocol/modelcontextprotocol`
- audited revision: `f01dd9810a92b9a4e1f71e3c8c9df56c717e9836`

Primary sources used in the original hardening effort:

- `docs/specification/2025-06-18/basic/index.mdx`
- `docs/specification/2025-06-18/basic/lifecycle.mdx`
- `docs/specification/2025-06-18/basic/transports.mdx`
- `docs/specification/2025-06-18/basic/utilities/cancellation.mdx`
- `docs/specification/2025-06-18/basic/utilities/progress.mdx`
- `docs/specification/2025-06-18/basic/utilities/ping.mdx`
- `schema/2025-06-18/schema.ts`

## Architecture Summary

### Stdio mode

`MCP client <-> faramesh mcp wrap <-> upstream stdio MCP server`

- line-based JSON-RPC processing
- `tools/call` intercepted and governed
- non-tool methods pass through
- unsolicited upstream notifications/requests forwarded to client

### HTTP mode

`MCP client <-> faramesh MCP HTTP gateway <-> upstream MCP HTTP server`

- Streamable HTTP methods proxied (`GET`, `HEAD`, `OPTIONS`, `DELETE`)
- JSON-RPC `POST` validated and handled
- `tools/call` governed before upstream forwarding

## Message and Transport Semantics

### JSON-RPC validation

Gateway enforces:

- `jsonrpc` must be `2.0`
- valid request/notification/response shape
- invalid shapes rejected early (`400` in HTTP, JSON-RPC parse/shape errors in stdio wrapper handling)

### One-way semantics

HTTP:

- client-sent notifications/responses are forwarded upstream
- gateway returns `202 Accepted` on successful one-way forwarding

stdio:

- notification/response input lines are forwarded one-way
- no synthetic response line generated

### Batch behavior

- batch members are processed in order
- notification/response members are forwarded and omitted from output array
- if all entries are one-way, gateway returns `202` for HTTP batch

## Governance Path

`tools/call` flow:

1. Parse params (`name`, `arguments`)
2. Build canonical action request
3. Evaluate through pipeline
4. Handle decision:

- `PERMIT`/`SHADOW`/`SHADOW_PERMIT`: forward upstream and apply post-scan to tool output
- `DENY`: return JSON-RPC error (`-32003`)
- `DEFER`: return pending-approval payload with token

Non-`tools/call` methods:

- forwarded upstream without governance mutation

## Hardening Controls

### 1. Origin controls

- allow when no `Origin`
- allow same-host origin
- allow loopback origins (`localhost` and loopback IPs)
- allow explicit origin allowlist (`--mcp-allowed-origins`)

### 2. Edge auth modes

Configured with `--mcp-edge-auth-mode`:

- `off`
- `bearer`
- `mtls`
- `bearer_or_mtls`

Behavior:

- `bearer`: requires `Authorization: Bearer <token>` matching configured token
- `mtls`: requires client certificate presence on TLS connection
- `bearer_or_mtls`: allows either valid bearer or client cert

Notes:

- bearer token source can be flag or `FARAMESH_MCP_EDGE_AUTH_BEARER_TOKEN`
- with `mtls` mode on plain HTTP (no TLS), requests are unauthorized

### 3. Protocol-version strict mode

Configured with:

- `--mcp-protocol-version-mode off|strict`
- `--mcp-protocol-version <version>` (default `2025-06-18`)

Strict behavior:

- ingress request must include `MCP-Protocol-Version` with exact configured value
- upstream response must include matching `MCP-Protocol-Version`
- mismatch/missing request header -> `400`
- mismatch/missing upstream response header -> `502`

### 4. Session lifecycle controls

Configured with:

- `--mcp-session-ttl <duration>`
- `--mcp-session-idle-timeout <duration>`

Behavior (for requests with `Mcp-Session-Id`):

- first seen session initializes creation and last-seen timestamps
- if elapsed lifetime exceeds TTL -> request unauthorized and state removed
- if idle interval exceeds idle timeout -> request unauthorized and state removed
- `DELETE` request terminates tracked session and replay cache for that session

### 5. SSE replay (Last-Event-ID)

Configured with:

- `--mcp-sse-replay-enabled`
- `--mcp-sse-replay-max-events <int>`
- `--mcp-sse-replay-max-age <duration>`

Behavior:

- replay cache is per session (`Mcp-Session-Id`)
- on GET SSE with `Last-Event-ID`, gateway replays cached events after that ID
- when replay cache satisfies continuation, consumed replay state is not forwarded upstream via `Last-Event-ID`
- cache is bounded by event count and age
- if event lacks `id:`, gateway assigns deterministic replay ID for caching

## CLI and Config Surface

### `faramesh serve` MCP flags

Base:

- `--mcp-proxy-port`
- `--mcp-target`
- `--mcp-allowed-origins`

Advanced hardening:

- `--mcp-edge-auth-mode off|bearer|mtls|bearer_or_mtls`
- `--mcp-edge-auth-bearer-token <token>`
- `--mcp-protocol-version-mode off|strict`
- `--mcp-protocol-version 2025-06-18`
- `--mcp-session-ttl 30m`
- `--mcp-session-idle-timeout 10m`
- `--mcp-sse-replay-enabled`
- `--mcp-sse-replay-max-events 256`
- `--mcp-sse-replay-max-age 10m`

Env var support:

- `FARAMESH_MCP_EDGE_AUTH_BEARER_TOKEN`

## Production Example

```bash
faramesh serve \
  --policy policy.yaml \
  --mcp-proxy-port 19092 \
  --mcp-target http://127.0.0.1:8080 \
  --mcp-allowed-origins https://app.example.com \
  --mcp-edge-auth-mode bearer \
  --mcp-edge-auth-bearer-token "$FARAMESH_MCP_EDGE_AUTH_BEARER_TOKEN" \
  --mcp-protocol-version-mode strict \
  --mcp-protocol-version 2025-06-18 \
  --mcp-session-ttl 30m \
  --mcp-session-idle-timeout 10m \
  --mcp-sse-replay-enabled \
  --mcp-sse-replay-max-events 256 \
  --mcp-sse-replay-max-age 10m
```

## Verified Implementation Map

Core implementation:

- `internal/adapter/mcp/gateway.go`
- `cmd/faramesh/mcp.go`
- `cmd/faramesh/serve.go`
- `internal/daemon/daemon.go`
- `internal/adapter/mcp/postscan.go`

Tests:

- `internal/adapter/mcp/gateway_http_test.go`
- `internal/adapter/mcp/gateway_stdio_test.go`
- `internal/adapter/mcp/testdata/stdio_notify/main.go`

## Test Coverage Highlights

HTTP tests include:

- tool permit/deny and initialize forwarding
- notification/response accepted one-way semantics
- batch notification accepted semantics
- origin block/allow behavior
- DELETE passthrough
- session isolation with `Mcp-Session-Id`
- edge auth mode enforcement (`bearer`, `mtls`)
- strict protocol-version request/response enforcement
- session TTL expiry
- session termination on DELETE
- SSE replay with `Last-Event-ID`

stdio tests include:

- tool permit/deny and passthrough
- batch behavior
- notification no-response path
- response no-response path
- unsolicited upstream notification forwarding

## Validation Commands

```bash
go test ./internal/adapter/mcp ./cmd/faramesh ./internal/daemon
go test ./...
```

## Guidance for LangChain, LangGraph, Deep Agents, MCP clients

Fast adoption path:

1. Keep your existing runtime entrypoint.
2. Put Faramesh at the MCP boundary (`mcp wrap` or MCP HTTP gateway).
3. Start with deny-by-default policy for sensitive tools.
4. Add edge auth and strict protocol mode before internet-facing exposure.
5. Use session ID headers (`Mcp-Session-Id`) for stable lifecycle and replay behavior.
6. Run full test suite before release.
