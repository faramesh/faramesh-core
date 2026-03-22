# Nomad

- **`agent.nomad.hcl`** — reference job with a **host volume** (register the host volume name in Nomad agent config) and a **`template`** stanza pulling policy from Consul KV (`faramesh/policy.yaml`). Replace with **artifact** or **volume** for policy distribution.
- Align **`FARAMESH_SOCKET`** with the shared mount path.
