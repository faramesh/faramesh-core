# Install (Simple)

## Option A: Homebrew (recommended)

```bash
brew install faramesh/tap/faramesh
```

## Option B: Go toolchain

```bash
go install github.com/faramesh/faramesh-core/cmd/faramesh@latest
```

## Option C: Build from source

```bash
git clone https://github.com/faramesh/faramesh-core.git
cd faramesh-core
go build -o faramesh ./cmd/faramesh
```

Run it:

```bash
./faramesh --help
```

## Option D: Put it on PATH

```bash
sudo install -m 0755 faramesh /usr/local/bin/faramesh
faramesh --help
```

## Check install

```bash
faramesh --version
```

## First command after install

```bash
faramesh wizard first-run
```

If `--version` is not available in your shell, run:

```bash
faramesh --help
```

## Optional: run tests before using in production

```bash
go test ./...
```
