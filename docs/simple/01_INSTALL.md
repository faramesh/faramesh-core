# Install (Simple)

## Option A: Build from source

```bash
git clone https://github.com/faramesh/faramesh-core.git
cd faramesh-core
go build -o faramesh ./cmd/faramesh
```

Run it:

```bash
./faramesh --help
```

## Option B: Put it on PATH

```bash
sudo install -m 0755 faramesh /usr/local/bin/faramesh
faramesh --help
```

## Check install

```bash
faramesh version
```

If `version` is not available in your shell, run:

```bash
faramesh --help
```

## Optional: run tests before using in production

```bash
go test ./...
```
