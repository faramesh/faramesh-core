# Faramesh Core — local developer entrypoints (CI: monorepo `.github/workflows/faramesh-core-release-gate.yml`).
.PHONY: all build build-release compile clean test test-race vet sbom docker

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
