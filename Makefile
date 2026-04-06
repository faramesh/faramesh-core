# Faramesh Core — local developer entrypoints (CI: monorepo `.github/workflows/faramesh-core-release-gate.yml`).
.PHONY: all build build-release compile clean test test-race vet sbom docker verify-reproducible release install setup setup-status setup-stop langchain-single langchain-real langchain-real-fpl langgraph-real langgraph-real-fpl burst-rate-harness defer-timeout-resume-harness langchain-wizard govern-wizard

all: vet compile test build

# Compile every package (no link of cmd/faramesh); fast compile-only check.
compile:
	go build ./...

# Dev binary → bin/faramesh (gitignored under /bin/).
build:
	go build -o bin/faramesh ./cmd/faramesh

# Static binary flags aligned with Dockerfile (CGO off, trimpath, strip symbols).
build-release:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=dev" -o bin/faramesh ./cmd/faramesh

clean:
	rm -rf bin/

test:
	go test ./... -count=1

test-race:
	go test ./... -count=1 -race

# participle grammar tags in internal/core/fpl are not valid reflect.StructTag (expected).
vet:
	go vet $$(go list ./... | grep -v '/internal/core/fpl$$')

sbom:
	go run ./cmd/faramesh sbom

docker:
	docker build -t faramesh:local -f Dockerfile .

# Build the release binary twice and compare SHA-256 hashes to verify determinism.
verify-reproducible:
	@echo "==> Building first artifact…"
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=dev" -o bin/faramesh-repro-a ./cmd/faramesh
	@echo "==> Building second artifact…"
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=dev" -o bin/faramesh-repro-b ./cmd/faramesh
	@HASH_A=$$(shasum -a 256 bin/faramesh-repro-a | awk '{print $$1}'); \
	 HASH_B=$$(shasum -a 256 bin/faramesh-repro-b | awk '{print $$1}'); \
	 echo "  a: $$HASH_A"; \
	 echo "  b: $$HASH_B"; \
	 if [ "$$HASH_A" = "$$HASH_B" ]; then \
	   echo "==> ✔ Reproducible build verified"; \
	 else \
	   echo "==> ✘ Build is NOT reproducible" >&2; exit 1; \
	 fi
	@rm -f bin/faramesh-repro-a bin/faramesh-repro-b

# Full release pipeline: build, checksum manifest, SBOM.
release: build-release
	@echo "==> Generating SHA-256 manifest…"
	@shasum -a 256 bin/faramesh > bin/faramesh_checksums.txt
	@echo "==> Generating SBOM…"
	@go run ./cmd/faramesh sbom > bin/faramesh_sbom.json 2>/dev/null || true
	@echo ""
	@echo "Release artifacts in bin/:"
	@ls -lh bin/
	@echo ""
	@echo "✔ Release build complete"

# Install to /usr/local/bin.
install: build-release
	@echo "==> Installing faramesh to /usr/local/bin…"
	install -m 755 bin/faramesh /usr/local/bin/faramesh
	@echo "✔ Installed $$(faramesh --version 2>&1 || echo 'faramesh')"

# Canonical local setup entrypoint (wizard by default).
setup:
	bash scripts/faramesh_setup.sh

# Show setup-managed runtime status.
setup-status:
	bash scripts/faramesh_setup.sh status

# Stop setup-managed runtime.
setup-stop:
	bash scripts/faramesh_setup.sh stop

# Strict end-to-end smoke for a single LangChain agent governed over socket.
langchain-single:
	bash tests/langchain_single_agent_governed.sh

# Real-stack strict governance test for a single LangChain agent with Vault + identity gates (FPL-first by default).
langchain-real:
	bash tests/langchain_single_agent_real_stack.sh

# Compatibility alias for explicit FPL naming.
langchain-real-fpl:
	bash tests/langchain_single_agent_real_stack_fpl.sh

# Real-stack strict governance test for a single LangGraph ToolNode flow (FPL-first by default).
langgraph-real:
	bash tests/langgraph_single_agent_real_stack.sh

# Compatibility alias for explicit FPL naming.
langgraph-real-fpl:
	bash tests/langgraph_single_agent_real_stack_fpl.sh

# Deterministic burst rate-limit harness for SDK socket + proxy adapters.
burst-rate-harness:
	bash tests/burst_rate_limit_harness.sh

# Defer timeout/resume stress harness for late resolve and conflict stability.
defer-timeout-resume-harness:
	bash tests/defer_timeout_resume_stress_harness.sh

# Minimal-interaction installer/wizard for governed LangChain agent runs.
langchain-wizard:
	bash scripts/faramesh_govern_wizard.sh --agent-cmd "python ../demo_interactive_ai_agent.py"

# Minimal-interaction installer/wizard for any agent command.
govern-wizard:
	bash scripts/faramesh_govern_wizard.sh
