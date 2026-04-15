# Seed policy packs (open repo)

Illustrative **YAML** policies (with optional **`policy.fpl`** sidecars on embedded `faramesh-*` catalog packs) for `faramesh policy validate`, demos, and Hub-style distribution tests.
These are **starting points** — tune `rules`, `budget`, and `tools` for production.

| Pack | Intent |
|------|--------|
| `financial-saas` | Payments/refund governance, block shell on financial profile |
| `healthcare` | PHI-sensitive paths, verified principal gates |
| `devops-safe` | Production mutation denial, shell deferral |
| `ai-safety` | Webhook and HTTP posture for LLM agents |
| `startup-default` | Deny-by-default with narrow permits |

Validation: `make packs-verify` (or `go test ./packs/...`) from `faramesh-core` — **`validate_test.go`** validates **every** on-disk `policy.yaml` **and** compiles **every** `policy.fpl` in each pack directory; **`catalog_bundled_test.go`** asserts every **embedded** bundled pack `Lookup`s, validates YAML, requires **non-empty `PolicyFPL`**, installs via `hub.WritePackToDiskWithMode`; **`bundled_fpl_compile_test.go`** runs **`fpl.ParseDocument` + `fpl.CompileDocument`** on each embedded sidecar).
