# Contributing to Faramesh

Thank you for your interest in contributing to Faramesh! This guide covers everything you need to get started.

## Project Layout

```
faramesh-core/
├── cmd/faramesh/          # CLI entry point (Cobra commands)
├── internal/
│   ├── core/              # Core logic
│   │   ├── engine/        # Policy engine and decision pipeline
│   │   ├── fpl/           # FPL parser, compiler, decompiler
│   │   ├── credential/    # Credential broker backends
│   │   └── sandbox/       # Kernel sandbox (seccomp, Landlock; eBPF scaffold)
│   ├── daemon/            # HTTP/gRPC daemon
│   └── adapter/           # Framework auto-patchers
├── examples/              # FPL policy examples
├── npm/                   # npm package (npx @faramesh/cli)
├── docs/                  # Documentation
├── tests/                 # Integration and end-to-end tests
├── deploy/                # Deployment manifests (Docker, Helm, systemd)
├── Formula/               # Homebrew formula
└── Makefile               # Build, test, release targets
```

---

## Development Setup

### Prerequisites

- Go 1.22+
- Git
- Make (optional but recommended)

### Building from Source

```bash
git clone https://github.com/faramesh/faramesh-core.git
cd faramesh-core

# Build
go build -o faramesh ./cmd/faramesh

# Verify
./faramesh version
```

### Running Tests

```bash
# All tests
go test -race ./...

# Specific package
go test -race ./internal/core/fpl/...

# With verbose output
go test -race -v ./...
```

---

## Coding Standards

### Go Code

- Follow the [Effective Go](https://go.dev/doc/effective_go) guide and [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments).
- Use `go vet` and `golangci-lint` before committing.
- Add tests for new functionality. Aim for high coverage on policy engine and FPL parser code.
- Keep packages small and focused. Avoid circular imports.

### FPL Policies

- Example policies in `examples/` must be valid FPL that passes `faramesh policy validate`.
- When adding new FPL features, add golden test vectors in `internal/core/fpl/testdata/`.

### Linting

```bash
# Vet
go vet ./...

# golangci-lint (if installed)
golangci-lint run
```

---

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Make Changes

- Write code following coding standards.
- Add tests for new features.
- Update documentation as needed.

### 3. Test Your Changes

```bash
# Run tests
go test -race ./...

# Build and verify
go build -o faramesh ./cmd/faramesh
./faramesh version

# Validate example policies
./faramesh policy validate examples/payment-bot.fpl
```

### 4. Commit Changes

```bash
git add .
git commit -m "feat: add new feature"
```

**Commit Message Format:**
- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation changes
- `test:` — Test additions/changes
- `refactor:` — Code refactoring
- `chore:` — Maintenance tasks

### 5. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub.

---

## Pull Request Checklist

Before submitting a pull request, ensure:

- [ ] `go test -race ./...` passes
- [ ] `go vet ./...` passes
- [ ] Documentation updated if the change is user-facing
- [ ] Example FPL policies still validate
- [ ] No hardcoded secrets or credentials
- [ ] Commit messages follow the format above
- [ ] Breaking changes documented in the PR description

---

## Testing Guidelines

### Unit Tests

Test individual functions:

```go
func TestPolicyEvaluation(t *testing.T) {
    engine := NewEngine("examples/payment-bot.fpl")
    result := engine.Evaluate("shell/run", map[string]any{"cmd": "echo hello"})
    if result.Effect != Deny {
        t.Errorf("expected deny, got %s", result.Effect)
    }
}
```

### Golden Tests

FPL parser and compiler changes should update golden test files in `internal/core/fpl/testdata/`.

### Integration Tests

End-to-end tests in `tests/` exercise the daemon, CLI, and policy pipeline together.

---

## Code Review Process

1. **CI runs** — tests, vet, build, cross-compile.
2. **Maintainer review** — code quality, tests, docs.
3. **Address feedback** — iterate.
4. **Merge** — once approved, maintainers merge.

---

## Getting Help

- [GitHub Issues](https://github.com/faramesh/faramesh-core/issues/new) — bug reports and feature requests
- [GitHub Discussions](https://github.com/faramesh/faramesh-core/discussions) — questions and ideas
- [Documentation](https://faramesh.dev/docs) — guides and reference

---

## See Also

- [Code of Conduct](CODE_OF_CONDUCT.md) — community guidelines
- [Security Policy](SECURITY.md) — vulnerability reporting
