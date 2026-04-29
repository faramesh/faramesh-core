# systemd (VM / bare metal)

1. Install the `faramesh` binary to `/usr/local/bin/faramesh` and policy to `/etc/faramesh/policy.yaml`.
2. Create user `faramesh` or change `User=` / `Group=` in the unit.
3. `sudo cp faramesh-serve.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now faramesh-serve`
4. Point agents at `FARAMESH_SOCKET=/run/faramesh/faramesh.sock` (matches `RuntimeDirectory=faramesh` → `/run/faramesh`).

Optional: use **socket activation** with a `.socket` unit that creates the path before `serve` starts (not shipped here; use distro docs).

For **`vars.region`** / **`vars.k8s_namespace`**, set environment in the unit file, e.g. `Environment=FARAMESH_REGION=eu-west-1`.
