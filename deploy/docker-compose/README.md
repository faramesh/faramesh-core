# Docker Compose (reference)

`docker-compose.example.yml` shows an **agent** container and **`faramesh serve`** sharing a **Unix socket** volume (`FARAMESH_SOCKET`). Build the governance image from repo root:

```bash
docker build -t faramesh:local -f faramesh-core/Dockerfile faramesh-core
```

For HTTP-only attachment, drop the socket volume and point the SDK at **`http://faramesh:PORT`** instead.

See **`docs/dev/ENFORCEMENT_STACK_AND_TRUST.md`** — Compose gives container isolation, not full egress control unless you add **network policies** / **proxy** sidecars.
