# Faramesh CLI

Install the Faramesh command-line tool from npm and run it through `npx`, `npm exec`, or a global install.

## Install

Use `npx` without installing anything globally:

```bash
npx @faramesh/cli@latest init
```

Or with `npm exec`:

```bash
npm exec --yes @faramesh/cli@latest -- init
```

Or install globally:

```bash
npm install -g @faramesh/cli
```

## Commands

The package exposes the full Faramesh CLI. Start with `init`, then use `--help` to explore the rest of the command surface.

```bash
faramesh --help
```

## What it does

Faramesh sits between your AI agent and the tools it calls. Every tool call is checked against policy before it runs.

- Permit means the action runs.
- Deny means nothing runs and the agent gets a reason.
- Defer means a human can review the decision before execution.

## Learn more

- [Documentation](https://docs.faramesh.dev/)
- [GitHub](https://github.com/faramesh/faramesh-core)
- [FPL language docs](https://docs.faramesh.dev/fpl/)
