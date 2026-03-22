# AWS Lambda attachment

`faramesh-core` is a **long-lived process**; it is **not** intended to run *inside* the Lambda sandbox as the governance engine for every invocation. Use one of these patterns:

## A) Authorize handler only (lightweight)

Use **`internal/adapter/serverless`** — `NewAuthorizeHandler` — in a **small** Go Lambda that evaluates a single request against a loaded policy bundle (embed or S3). Same JSON body shape as **`/v1/authorize`** on the proxy. Cold-start friendly; no WAL/DPR unless you add external stores.

## B) Sidecar or shared service (full DPR)

Run **`faramesh serve`** on **ECS**, **EKS**, or **EC2**; Lambda calls it over **HTTPS** or **gRPC** for decisions. **`vars.deployment_kind`** is **`aws_lambda`** in Lambda when **`AWS_LAMBDA_FUNCTION_NAME`** is set; the daemon sees **`unknown`** or **`aws_lambda`** depending on where it runs — scope `when:` rules accordingly.

## Environment

- Set **`FARAMESH_REGION`** or rely on **`AWS_REGION`** for **`vars.region`**.
- For fleet dashboards, point **`--cloud-sync-*`** (if enabled) at your sink; see daemon flags.

See **`deploy/ecs/`** for a containerized full daemon next to other workloads.
