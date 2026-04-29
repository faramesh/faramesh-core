# AWS ECS / Fargate

- **`task-definition.example.json`** — two-container task: shared volume for the Unix socket (use **`empty`** for EC2 launch type; for Fargate use a bind from EFS or a named volume your platform supports — Fargate does not support `empty` host volumes; prefer **EFS** for `/policy` and an **EFS access point** or sidecar-only **tmpfs** via `linuxParameters` if your orchestration allows).
- In practice many teams run **`faramesh serve`** as a **sidecar** with **`emptyDir`-equivalent** only on Kubernetes; on ECS, use **bind mount from a shared volume** the platform provides or TCP adapters (`--grpc-port` / proxy) instead of a file socket.

Set **`AWS_REGION`** so **`vars.region`** resolves; set **`FARAMESH_K8S_NAMESPACE`** only if you reuse policy that branches on namespace (usually leave empty on ECS).
