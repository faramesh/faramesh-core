# faramesh

**Unified governance plane for AI agents** — pre-execution authorization, policy-as-code, tamper-evident audit trail.

```bash
pip install faramesh
```

## Quick start

```python
from faramesh import govern

@govern
def send_email(to: str, subject: str, body: str) -> dict:
    ...  # your email sending code

# Now every call passes through the Faramesh policy engine
send_email("ceo@example.com", "Q4 Forecast", "...")
```

## Policy as code

```yaml
# policy.yaml
version: "1"
tools:
  - name: send_email
    rules:
      - when: 'args.to matches ".*@external\\.com"'
        effect: DEFER          # human approval required for external emails
      - effect: PERMIT
```

## Links

- [Documentation](https://faramesh.dev/docs)
- [GitHub](https://github.com/faramesh/faramesh-core)
- [Issues](https://github.com/faramesh/faramesh-core/issues)
