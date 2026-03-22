# Deployment references

Reference layouts for attaching **`faramesh`** to agents in different environments. All use the same **`faramesh-core`** binary; tune images, secrets, and networking for production.

| Path | Description |
|------|-------------|
| **`kubernetes/`** | Sidecar Deployment + ConfigMap policy; **`POD_NAMESPACE`** for **`vars.k8s_namespace`**. |
| **`systemd/`** | VM / bare metal service unit. |
| **`github-actions/`** | CI policy validation workflow. |
| **`ecs/`** | AWS ECS task definition sketch (Fargate volume caveats in README). |
| **`nomad/`** | HashiCorp Nomad job sketch. |
| **`aws-lambda/`** | Lambda vs full daemon; serverless authorize handler vs remote **`faramesh serve`**. |
| **`databricks/`** | Spark/Databricks: remote daemon + SDK/HTTP; no JVM shim in-repo. |
| **`browser-remote/`** | Browser/WASM: BFF + remote daemon; no in-browser WAL. |
| **`docker-compose/`** | Socket-volume sidecar example for local / CI. |
| **`google-cloud-run/`** | Cloud Run + serverless handler notes. |
| **`modal/`** | Modal.com workers → remote daemon pattern. |

Runtime policy variables (**`vars.deployment_kind`**, **`vars.runtime_kind`**, **`vars.region`**, **`vars.k8s_namespace`**, **`vars.faramesh_version`**, optional **`vars.trust_level`** / hints) are set in **`internal/core/runtimeenv`** (`PolicyVarOverlay`). Trust model: **`docs/dev/ENFORCEMENT_STACK_AND_TRUST.md`**.
