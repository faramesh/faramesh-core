# Faramesh Core

**Documentation:** https://docs.faramesh.dev  
**Registry:** https://registry.faramesh.dev  
**Authoritative spec:** [`docs/internal/FARAMESH.md`](docs/internal/FARAMESH.md)  
**Registry platform:** [`../docs/internal/FARAMESH_REGISTRY_PLATFORM.md`](../docs/internal/FARAMESH_REGISTRY_PLATFORM.md)  
**Local registry dev:** [`../faramesh-registry/README.md`](../faramesh-registry/README.md)

## Faramesh

Faramesh governs AI agent tool calls **before** they execute. You declare one stack per directory in `governance.fms` (FPL, YAML, or JSON). `faramesh apply` compiles that file and runs a daemon that evaluates every tool call, writes tamper-evident decision records (DPR/WAL), brokers credentials through providers, and returns PERMIT, DENY, or DEFER.

## Install (recommended)

You do **not** need Go installed to use Faramesh day-to-day.

### curl

```bash
curl -fsSL https://raw.githubusercontent.com/faramesh/faramesh-core/main/install.sh | bash
```

### npm

```bash
npx @faramesh/cli@latest
```

The `@faramesh/cli` package downloads the release binary for your OS/arch on `postinstall` (see `npm/`).

### git clone (contributors / offline)

```bash
git clone https://github.com/faramesh/faramesh-core.git
cd faramesh-core
./install.sh --install-dir="$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
faramesh version
```

## Quick start

```bash
faramesh init
faramesh dev          # stub providers + in-memory WAL
faramesh apply        # compile governance.fms and start the daemon
```

Guides: [Quickstart](https://docs.faramesh.dev/quickstart/) · [CLI](https://docs.faramesh.dev/cli/) · [Stack model](https://docs.faramesh.dev/stack/)

## SDK transport (Phase 10)

SDKs auto-select governance transport:

| Priority | Variable | Use |
|----------|----------|-----|
| 1 | `FARAMESH_REMOTE_URL` | HTTPS `POST /v1/evaluate` (Lambda, Cloud Run, remote daemon) |
| 2 | `FARAMESH_SOCKET` | Unix socket JSON-RPC `govern` (local `faramesh apply` / `run`) |
| 3 | `FARAMESH_BASE_URL` | HTTPS fallback when socket file is absent |

Optional: `FARAMESH_TOKEN` (Bearer), `FARAMESH_AGENT_ID`, `FARAMESH_PRINCIPAL_TOKEN`.

## Developing from source

Only needed when changing the Go runtime:

```bash
go test ./...
go install ./cmd/faramesh   # or: go build -o faramesh ./cmd/faramesh
```

Local registry:

```bash
# terminal 1
cd ../faramesh-registry && go run ./cmd/registry -catalog catalog

# terminal 2
export FARAMESH_REGISTRY_URL=http://127.0.0.1:9876
faramesh init && faramesh check
```

E2E smoke: `./tests/e2e_v2_smoke.sh`

## Repository layout (Terraform-style)

| Path | Role |
|------|------|
| `governance.fms` | Declarative stack (your project) |
| `.faramesh/` | Compiled policy + state (`apply` output) |
| `cmd/faramesh/` | CLI |
| `internal/core/governance/` | Compiler + `check` / `plan` / `apply` |
| `internal/daemon/` | Long-running enforcement |
| `internal/provider/` | Provider protocol + launcher |
| `sdk/python`, `sdk/node` | Agent SDKs + autopatch |

## License

See repository license file.
