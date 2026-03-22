# Databricks / Spark driver attachment

Faramesh does **not** ship a JVM-native driver or in-process Spark hook. Govern tool calls from **Python** or **Scala** workloads by sending decisions to a **remote** `faramesh serve` (or sidecar) over HTTP/SDK — same policy bundle as everywhere else.

## Recommended pattern

1. Run **`faramesh serve`** (or a sidecar container) reachable from the cluster driver and workers on a stable URL or Unix socket.
2. From driver or notebook code, use **`faramesh-python-sdk-code`** (`govern()` / client) or HTTP to the daemon’s authorize path so each sensitive action (REST, JDBC, file writes) is evaluated before execution.
3. Keep **secrets and JDBC URLs** out of policy text; use **`credential` broker** or env-injected vars and reference them only by key in `when:` / args.

## Caveats

- **Executors** may not share the driver’s network identity — design policy around **agent_id** / workload tags passed explicitly in requests, not only host IP.
- **Long-running clusters** should use **policy hot-reload** (`--policy-url` + poll) or restart the sidecar when bundles change.

See root **`deploy/README.md`** for runtime **`vars.*`** (deployment, region, version) in `when:` clauses.
