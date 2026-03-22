# GitHub Actions

- **`example-workflow.yml`** — validate policy on push; adjust `go install` path if the module is private or use a release tarball.
- Set **`FARAMESH_REGION`** / **`FARAMESH_K8S_NAMESPACE`** in job `env:` if workflows need **`vars.*`** in policy (usually N/A for CI-only validation).
