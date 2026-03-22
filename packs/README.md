# Seed policy packs (open repo)

Illustrative **YAML** policies for `faramesh policy validate`, demos, and Hub-style distribution tests.
These are **starting points** — tune `rules`, `budget`, and `tools` for production.

| Pack | Intent |
|------|--------|
| `financial-saas` | Payments/refund governance, block shell on financial profile |
| `healthcare` | PHI-sensitive paths, verified principal gates |
| `devops-safe` | Production mutation denial, shell deferral |
| `ai-safety` | Webhook and HTTP posture for LLM agents |
| `startup-default` | Deny-by-default with narrow permits |

Validation: `go test ./packs/...` from `faramesh-core` (see `packs/validate_test.go`).
