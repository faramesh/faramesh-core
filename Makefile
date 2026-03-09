VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS = -X main.version=$(VERSION) -s -w
CGO_ENABLED = 0

BINARY = faramesh
CMD = ./cmd/faramesh
DIST = dist

.PHONY: all build test clean demo lint release

all: build

## build: Compile the faramesh binary for the current platform.
build:
	CGO_ENABLED=$(CGO_ENABLED) go build -ldflags="$(LDFLAGS)" -o $(BINARY) $(CMD)
	@echo "Built: ./$(BINARY)"

## demo: Run faramesh demo using the just-built binary.
demo: build
	./$(BINARY) demo

## test: Run all Go tests.
test:
	go test -race ./...

## lint: Run go vet and staticcheck.
lint:
	go vet ./...
	@which staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "(staticcheck not installed)"

## release: Cross-compile binaries for all supported platforms.
release: clean
	@mkdir -p $(DIST)
	GOOS=linux   GOARCH=amd64  CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-amd64   $(CMD)
	GOOS=linux   GOARCH=arm64  CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-arm64   $(CMD)
	GOOS=darwin  GOARCH=amd64  CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-darwin-amd64  $(CMD)
	GOOS=darwin  GOARCH=arm64  CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-darwin-arm64  $(CMD)
	GOOS=windows GOARCH=amd64  CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-windows-amd64.exe $(CMD)
	@echo "Release binaries in $(DIST)/"
	@ls -lh $(DIST)/

## docker: Build the Docker image.
docker:
	docker build -t faramesh/faramesh:$(VERSION) -t faramesh/faramesh:latest .

## clean: Remove build artifacts.
clean:
	rm -f $(BINARY)
	rm -rf $(DIST)/

## install: Install faramesh to /usr/local/bin.
install: build
	install -m 755 $(BINARY) /usr/local/bin/$(BINARY)
	@echo "Installed: /usr/local/bin/$(BINARY)"

## policy-check: Validate all policy files in policies/.
policy-check: build
	@for f in policies/*.yaml; do \
		./$(BINARY) policy validate "$$f" || exit 1; \
	done

## help: Show this help.
help:
	@grep -E '^## ' Makefile | sed 's/^## /  /'
