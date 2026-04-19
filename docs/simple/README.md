# Simple Docs Index

These docs are written in very plain language.

Last refreshed: 2026-04-15

Recommended rollout flow in this repo:

1. `faramesh wizard first-run`
2. `faramesh up --policy policy.yaml`
3. `faramesh run --broker -- python your_agent.py`
4. `faramesh approvals`
5. `faramesh explain <action-id>`
6. `faramesh audit tail`
7. `faramesh down`
8. `faramesh discover` -> `faramesh attach`
9. `faramesh coverage` -> `faramesh gaps` -> `faramesh suggest`
10. `faramesh pack shadow` -> `faramesh pack enforce`

Read in this order:

1. [00_START_HERE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/00_START_HERE.md)
2. [01_INSTALL.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/01_INSTALL.md)
3. [02_QUICKSTART.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/02_QUICKSTART.md)
4. [03_POLICY_SIMPLE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/03_POLICY_SIMPLE.md)
5. [04_RUN_AND_MONITOR.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/04_RUN_AND_MONITOR.md)
6. [05_APPROVALS.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/05_APPROVALS.md)
7. [06_ADAPTERS.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/06_ADAPTERS.md)
8. [07_PRODUCTION_SETUP.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/07_PRODUCTION_SETUP.md)
9. [08_TROUBLESHOOTING.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/08_TROUBLESHOOTING.md)

For a one-page map of all major features in simple language:

10. [FEATURES_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/FEATURES_QUICK_GUIDE.md)
