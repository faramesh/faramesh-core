# Socket E2E acceptance (corpus)

Wraps `tests/socket_e2e_acceptance.sh`: builds `faramesh`, runs strict preflight + integrity manifest, starts the Unix-socket daemon with `policies/demo.fpl`, exercises CLI subcommands (session, model, credential, incident, etc.), and validates JSON-RPC `govern` compatibility for Node- and Python-style payloads.

**Status:** `wip` in the coverage matrix — runtime integration smoke, not the tier-A WAL + `hook_truth` agent contract.
