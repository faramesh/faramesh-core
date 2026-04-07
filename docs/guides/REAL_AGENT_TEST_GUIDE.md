# Real Agent Test Guide (Run Now)

This runbook gives you a **right-now, reproducible** way to test governance against the real LangChain demo path and then against your own real agent script.

## Fastest Path (30 Seconds)

Use the minimal-interaction wizard:

```bash
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core
make govern-wizard
```

Use defaults and press Enter. The wizard is for any agent command; default command is LangChain-first (`python faramesh-core/demo_interactive_ai_agent.py`) so you can validate quickly, then swap to your own command.

## Scope (important)

This validates a **specific end-to-end integration path**. It does **not** by itself prove:

- complete framework/path coverage,
- universal non-leakage guarantees,
- full adversarial robustness.

## What You Will Validate

1. Strict daemon startup + identity signal + Vault broker + DEFER workflow + DPR recording in one scenario.
2. Deny-path behavior for an adversarial tool call (`shell/run`).
3. Secret sentinel non-persistence check in Faramesh runtime artifacts.
4. The same scenario in both:
   - YAML policy mode (`policies/langchain_single_agent.yaml`)
   - FPL policy mode (`policies/langchain_single_agent.fpl`)

## Prerequisites

Run from `faramesh-core`.

```bash
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core
```

Required tools:

```bash
command -v go
command -v python3
command -v vault
```

## Path A: Run The Real-Stack Scenario (YAML)

This is the quickest verified path.

```bash
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core
export FARAMESH_LANGCHAIN_REAL_IDP_PROVIDER=default
make langchain-real
```

Expected final line:

```text
langchain real-stack governance passed
```

## Path B: Run The Same Scenario In FPL Mode

```bash
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core
make langchain-real-fpl
```

Expected final line:

```text
langchain real-stack governance passed
```

## Artifacts To Inspect

Default paths from the real-stack harness:

- Agent output: `.tmp/langchain-real/agent_output.log`
- Daemon log: `.tmp/langchain-real/daemon.log`
- DPR DB: `.tmp/langchain-real/data/faramesh.db`

Quick checks:

```bash
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core

tail -n 200 .tmp/langchain-real/agent_output.log
tail -n 200 .tmp/langchain-real/daemon.log
```

Query DPR evidence:

```bash
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core
python3 - <<'PY'
import sqlite3

db = '.tmp/langchain-real/data/faramesh.db'
agent_id = 'langchain-single'
con = sqlite3.connect(db)
cur = con.cursor()

checks = [
    ("http permit", "select count(*) from dpr_records where agent_id=? and tool_id='http/get' and effect='PERMIT'"),
    ("vault permit brokered", "select count(*) from dpr_records where agent_id=? and tool_id='vault/probe' and effect='PERMIT' and credential_brokered=1 and credential_source='vault'"),
    ("shell deny", "select count(*) from dpr_records where agent_id=? and tool_id='shell/run' and effect='DENY'"),
    ("refund defer", "select count(*) from dpr_records where agent_id=? and tool_id='payment/refund' and effect='DEFER'"),
]

for label, q in checks:
    cur.execute(q, (agent_id,))
    print(f"{label}: {cur.fetchone()[0]}")

con.close()
PY
```

Leak sentinel check (should return no matches):

```bash
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core
SECRET_SENTINEL="vault-real-credential"
rg -a -n --fixed-strings "$SECRET_SENTINEL" \
  .tmp/langchain-real/agent_output.log \
  .tmp/langchain-real/daemon.log \
  .tmp/langchain-real/data || true
```

## Run Against Your Own Real Agent Script (Manual Flow)

Use this when you want to run your own Python agent file now.

### 1) Build + prep strict artifacts

```bash
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core

RUN_DIR="$PWD/.tmp/real-agent-manual"
BIN="$RUN_DIR/faramesh"
SOCKET="$RUN_DIR/faramesh.sock"
DATA_DIR="$RUN_DIR/data"
POLICY="$PWD/policies/langchain_single_agent.yaml"
MANIFEST="$RUN_DIR/integrity.json"
BUILDINFO="$RUN_DIR/buildinfo.json"

mkdir -p "$RUN_DIR" "$DATA_DIR"
rm -f "$SOCKET"

go build -o "$BIN" ./cmd/faramesh
"$BIN" verify manifest-generate --base-dir "$PWD" --output "$MANIFEST" "$POLICY"
"$BIN" verify buildinfo --emit > "$BUILDINFO"
```

### 2) Start daemon (strict preflight)

```bash
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core

RUN_DIR="$PWD/.tmp/real-agent-manual"
BIN="$RUN_DIR/faramesh"
SOCKET="$RUN_DIR/faramesh.sock"
DATA_DIR="$RUN_DIR/data"
POLICY="$PWD/policies/langchain_single_agent.yaml"
MANIFEST="$RUN_DIR/integrity.json"
BUILDINFO="$RUN_DIR/buildinfo.json"
VAULT_ADDR="http://127.0.0.1:18200"
VAULT_TOKEN="root"

FARAMESH_SPIFFE_ID="spiffe://example.org/agent/my-real-agent" "$BIN" serve \
  --policy "$POLICY" \
  --socket "$SOCKET" \
  --data-dir "$DATA_DIR" \
  --strict-preflight \
  --idp-provider default \
  --vault-addr "$VAULT_ADDR" \
  --vault-token "$VAULT_TOKEN" \
  --vault-mount secret \
  --integrity-manifest "$MANIFEST" \
  --integrity-base-dir "$PWD" \
  --buildinfo-expected "$BUILDINFO" \
  --log-level warn
```

Open a second terminal for the agent run.

### 3) Verify daemon is reachable

```bash
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core
RUN_DIR="$PWD/.tmp/real-agent-manual"
BIN="$RUN_DIR/faramesh"
SOCKET="$RUN_DIR/faramesh.sock"

"$BIN" --daemon-socket "$SOCKET" status
"$BIN" --daemon-socket "$SOCKET" identity verify --spiffe "spiffe://example.org/agent/my-real-agent"
```

### 4) Run your real agent under Faramesh governance

```bash
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core
RUN_DIR="$PWD/.tmp/real-agent-manual"
BIN="$RUN_DIR/faramesh"
SOCKET="$RUN_DIR/faramesh.sock"

FARAMESH_SOCKET="$SOCKET" \
FARAMESH_AGENT_ID="my-real-agent" \
"$BIN" run --enforce full --policy "$PWD/policies/langchain_single_agent.yaml" -- \
  python /ABSOLUTE/PATH/TO/YOUR_REAL_AGENT.py
```

Notes:

- `faramesh run` injects framework autopatch via `FARAMESH_AUTOLOAD=1`.
- If your agent emits DEFER tokens, resolve them with:

```bash
"$BIN" agent approve <TOKEN> --socket "$SOCKET"
"$BIN" agent deny <TOKEN> --socket "$SOCKET"
```

### 5) Stop daemon

Use `Ctrl+C` in the daemon terminal.

## Troubleshooting

- If you see `vault CLI is required`, install Vault CLI.
- If strict preflight fails on IdP config, set `--idp-provider default` for local/no-external-IdP runs.
- If your custom agent does not use LangChain tool dispatch points, autopatch interception may not trigger for that path.
