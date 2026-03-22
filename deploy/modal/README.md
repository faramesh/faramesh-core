# Modal (reference)

Modal functions/containers are **short-lived** and **managed**. Treat Faramesh as:

1. **Remote daemon:** run **`faramesh serve`** in your VPC or Cloud Run; Modal code calls **`authorize`** over HTTPS with a service identity.
2. **vars.runtime_kind:** when **`MODAL_TASK_ID`** is set, policy sees **`modal`** (see **`runtimeenv.RuntimeKind`**).

**Credential broker:** provision Modal secrets **only** as short-lived tokens fetched from Faramesh; avoid long-lived API keys in Modal **Secrets** if you need broker semantics.

Kernel-level egress capture inside Modal workers is **platform-dependent** — assume **Layer 3 (credential + semantic governance)** unless Modal exposes custom network plumbing.
