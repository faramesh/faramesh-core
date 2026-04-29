# Docker Compose (reference)

`docker-compose.example.yml` shows an **agent** container and **`faramesh serve`** sharing a **Unix socket** volume (`FARAMESH_SOCKET`). Build the governance image from repo root:

```bash
docker build -t faramesh:local -f faramesh-core/Dockerfile faramesh-core
```

For HTTP-only attachment, drop the socket volume and point the SDK at **`http://faramesh:PORT`** instead.

Compose gives container isolation, but not full egress control by itself. For stronger network control, pair Compose with explicit network policy/proxy controls and follow the public enforcement guidance in the repository **`README.md`**.
