# Google Cloud Run (reference)

Use the same **`faramesh-core`** container as a **separate Cloud Run service** (governance API) or as a **second container** in a multi-container revision (sidecar pattern when available in your org).

- **Authorize path:** mount **`internal/adapter/serverless`** `NewAuthorizeHandler` behind API Gateway / Cloud Run **HTTP** invocations.
- **Policy:** bake policy into the image, or fetch from **Secret Manager** at startup and write to a local file path used by `--policy`.
- **vars.runtime_kind:** set to **`gcp_cloud_run`** automatically when **`K_SERVICE`** + **`K_REVISION`** are present (see **`runtimeenv.RuntimeKind`**).

Egress control on Cloud Run requires **VPC connector + firewall / centralized NAT** — document your org’s pattern; Faramesh does not replace Cloud IAM.
