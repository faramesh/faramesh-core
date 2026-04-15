# Security Policy

We take security seriously. Faramesh is a security-critical system — it governs what AI agents can do. Responsible disclosure helps us keep everyone safe.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

---

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

### Option 1: GitHub Security Advisory (Preferred)

1. Go to https://github.com/faramesh/faramesh-core/security/advisories/new
2. Click "Report a vulnerability"
3. Fill out the form
4. Submit privately

### Option 2: Email

Email: **security@faramesh.dev**

---

## What to Include

1. **Description** — Clear description of the vulnerability.
2. **Affected components** — Which part of Faramesh is affected (policy engine, sandbox, credential broker, daemon, etc.).
3. **Steps to reproduce** — Detailed steps or proof-of-concept.
4. **Impact assessment** — What an attacker could do.
5. **Suggested fix** — If you have ideas (optional).

---

## Response Timeline

- **Acknowledgment**: Within 3 business days
- **Initial assessment**: Within 7 business days
- **Updates**: We'll keep you informed of remediation progress
- **Resolution**: Critical issues are prioritized for immediate patching

---

## Security Architecture

Faramesh enforces governance through a nine-layer enforcement stack. Security is not optional — it is the product.

### Enforcement layers (Linux)

Active layers (implemented and tested):

1. **Framework auto-patch** — hooks into agent tool dispatch (Python; Node alpha)
2. **seccomp-BPF** — restricts system calls at the kernel level
3. **Landlock LSM** — restricts filesystem access
4. **Network namespace** — isolates agent network access
5. **Credential broker** — strips ambient API keys, issues scoped secrets via Vault (AWS/GCP backends are scaffolded, not production-ready)
6. **Policy engine** — deterministic rule evaluation, no AI in the loop

Scaffolded layers (interfaces exist, not yet production-ready):

7. **eBPF inspection** — probe interface defined; BPF program loading not yet wired (Attach returns explicit fallback/not-implemented and never claims attachment)
8. **eBPF baselining** — design target, not implemented
9. **MicroVM isolation** — optional Firecracker/Kata boundary (not included in this repo)

### Security properties

- **Fail-closed**: If Faramesh itself errors, the action is denied.
- **No ambient credentials**: API keys are stripped from the agent environment.
- **Tamper-evident audit**: Every decision is hash-chained (SHA-256). Altering a record breaks the chain.
- **Mandatory deny (`deny!`)**: FPL's `deny!` is a compile-time constraint. No child policy, no priority rule, nothing can override it.

### Best practices for operators

1. **Keep updated** — always use the latest version.
2. **Use FPL `deny!`** — for rules that must never be overridden.
3. **Enable the credential broker** — never let agents hold raw API keys.
4. **Review audit logs** — run `faramesh audit verify <path-to-faramesh.wal>` regularly for full chain validation.
5. **Use the full sandbox on Linux** — `faramesh run --enforce full`.

---

## Security Updates

Security fixes are released as patch versions and documented in GitHub Security Advisories.

---

## See Also

- [Contributing](CONTRIBUTING.md) — contribution guidelines
- [Code of Conduct](CODE_OF_CONDUCT.md) — community guidelines
