# Kubernetes sidecar example

- **`sidecar-deployment.example.yaml`** — two-container pod: your agent and `faramesh serve` share **`emptyDir`** at `/var/run/faramesh` for the Unix socket (`FARAMESH_SOCKET`).
- **`FARAMESH_REGION`** is wired from the node region label when present; policy can use **`when: vars.region == "..."`** (see `internal/core/runtimeenv`).
- Replace **`your-agent:latest`** and **`faramesh:local`** with your images; apply ConfigMap + Deployment: `kubectl apply -f sidecar-deployment.example.yaml`.

For HTTP ext-authz instead of Unix socket, run **`faramesh serve --proxy-port ...`** and point your mesh at the proxy (see `ONE_PLAN` / proxy adapter docs).
