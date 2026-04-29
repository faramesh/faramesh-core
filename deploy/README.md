# Deployment references

Reference layouts for attaching **`faramesh`** to agents in production environments. All use the same **`faramesh-core`** binary; tune images, secrets, and networking for production.

| Path | Description |
|------|-------------|
| **`kubernetes/`** | Sidecar Deployment + ConfigMap policy; **`POD_NAMESPACE`** for **`vars.k8s_namespace`**. |
| **`systemd/`** | VM / bare metal service unit. |
| **`ecs/`** | AWS ECS task definition sketch (Fargate volume caveats in README). |
| **`aws-lambda/`** | Lambda vs full daemon; serverless authorize handler vs remote **`faramesh serve`**. |
| **`docker-compose/`** | Socket-volume sidecar example for local / CI. |
| **`google-cloud-run/`** | Cloud Run + serverless handler notes. |

Runtime policy variables (**`vars.deployment_kind`**, **`vars.runtime_kind`**, **`vars.region`**, **`vars.k8s_namespace`**, **`vars.faramesh_version`**, optional **`vars.trust_level`** / hints) are set in **`internal/core/runtimeenv`** (`PolicyVarOverlay`).
