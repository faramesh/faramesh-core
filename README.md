# Faramesh Core

[Faramesh](https://faramesh.dev) governs AI agent tool calls **before** they execute. Declare your stack in `governance.fms`, then use the CLI to compile policy and run enforcement.

**Documentation:** https://docs.faramesh.dev

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/faramesh/faramesh-core/main/install.sh | bash
```

Or:

```bash
npx @faramesh/cli@latest
```

## Quick start

```bash
faramesh init
faramesh check
faramesh plan
faramesh apply
```

Use `faramesh dev` when you want stub providers and in-memory state while wiring your agent locally.

- [Quickstart](https://docs.faramesh.dev/quickstart/)
- [CLI](https://docs.faramesh.dev/cli/)
- [Stack model](https://docs.faramesh.dev/stack/)

## Contributing

Build and test instructions: [CONTRIBUTING.md](CONTRIBUTING.md).

## License

See [LICENSE](LICENSE).
