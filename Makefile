# Faramesh Core — local developer entrypoints (CI: monorepo `.github/workflows/faramesh-core-release-gate.yml`).
.PHONY: all build build-release compile clean test test-race vet sbom docker verify-reproducible release install

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
