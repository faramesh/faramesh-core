# Frequently Asked Questions

## General

### What is Faramesh?

Faramesh is an execution gatekeeper for AI agents that intercepts tool calls before execution, evaluates them against configurable policies, requires human approval when necessary, and logs every decision for audit purposes. It provides policy-driven governance, risk scoring, and human-in-the-loop approval workflows.

### How does Faramesh differ from other agent frameworks?

Faramesh focuses specifically on **governance and safety**—it doesn't build agents, it governs them. It provides policy-driven control, risk scoring, and human-in-the-loop approval workflows that work with any agent framework (LangChain, CrewAI, AutoGen, MCP, LangGraph, LlamaIndex).

### Do I need to modify my existing agents?

No. Faramesh integrates via SDKs that wrap your existing tools. Your agents call the SDK instead of tools directly, and Faramesh handles the governance layer transparently. See [Govern Your Own Tool](docs/govern-your-own-tool.md) for a step-by-step tutorial.

### What happens if Faramesh is down?

This depends on your integration pattern. The SDK can be configured to fail-open (allow actions) or fail-closed (deny actions) when Faramesh is unavailable. Production deployments should run Faramesh as a critical service with appropriate redundancy and monitoring.

### Can I use Faramesh in production?

Yes. Faramesh Core is production-ready with:
- PostgreSQL support for scalable storage
- Comprehensive REST API
- Web UI for monitoring and approvals
- Robust error handling and validation
- Prometheus metrics for observability
- Policy hot reload (for local files)

For enterprise features like SSO, RBAC, multi-org management, and advanced routing, consider [Faramesh Horizon](../README.md#faramesh-cloud-products) (hosted) or [Faramesh Nexus](../README.md#faramesh-cloud-products) (on-prem).

## Policies

### How do policies work?

Policies are YAML files that define rules evaluated in order (first-match-wins). Each rule can:
- `allow`: Allow the action immediately
- `deny`: Deny the action immediately
- `require_approval`: Require human approval before execution

If no rule matches, actions are **denied by default** (secure-by-default). See [Policy Configuration](docs/POLICIES.md) for details.

### What's the difference between policy rules and risk scoring?

- **Policy rules** determine the decision (allow/deny/require_approval)
- **Risk scoring** provides an independent assessment (low/medium/high) that can automatically upgrade decisions

For example, if a policy rule would `allow` an action but risk scoring marks it as `high` risk, Faramesh automatically changes the decision to `require_approval` for safety.

### Can I test policies without creating real actions?

Yes. Use the policy playground:
- **Web UI**: Visit `http://127.0.0.1:8000/playground`
- **API**: `POST /playground/eval` endpoint

Both allow you to test policy decisions without creating actual actions.

### How do I update policies in production?

1. **Hot Reload** (development/local): Use `faramesh serve --hot-reload` to automatically reload policy files when changed
2. **Manual Refresh**: Use `faramesh policy-refresh` to reload the policy
3. **Server Restart**: Restart the server with the new policy file

For production, we recommend using a deployment process that validates policies before deploying and restarts the server.

### Can I use multiple policy files?

Currently, Faramesh uses a single policy file (default: `policies/default.yaml`). You can organize rules within that file using YAML structure. Policy packs (see [Policy Packs](docs/POLICY_PACKS.md)) provide a way to organize reusable policy templates.

## Integration

### Can I integrate with CI/CD pipelines?

Yes. Faramesh provides CLI tools and APIs that can be integrated into CI/CD workflows to govern automated actions and deployments. You can:
- Submit actions via API
- Check approval status
- Approve/deny via API or CLI
- Monitor via metrics endpoint

### How do I integrate with my agent framework?

Faramesh provides integrations for:
- **LangChain**: See [examples/langchain/](../examples/langchain/)
- **CrewAI**: See [examples/crewai/](../examples/crewai/)
- **AutoGen**: See [examples/autogen/](../examples/autogen/)
- **MCP**: See [examples/mcp/](../examples/mcp/)
- **LangGraph**: See [examples/langgraph/](../examples/langgraph/)
- **LlamaIndex**: See [examples/llamaindex/](../examples/llamaindex/)

See [Integration Guide](docs/INTEGRATIONS.md) for details.

### Can I wrap my own custom tools?

Yes. See [Govern Your Own Tool](docs/govern-your-own-tool.md) for a step-by-step tutorial on wrapping custom tools with Faramesh governance.

## Deployment

### What databases are supported?

Faramesh supports:
- **SQLite** (default, for development)
- **PostgreSQL** (recommended for production)

Set `FARA_DB_BACKEND=postgres` and provide `FARA_POSTGRES_DSN` connection string.

### Is there a hosted version?

Yes. [Faramesh Horizon](../README.md#faramesh-cloud-products) provides a fully-managed SaaS offering with instant onboarding, automatic upgrades, and approval routing via Slack and email.

### Can I deploy on Kubernetes?

Yes. Faramesh can be deployed on Kubernetes. Use the Docker image and configure:
- Persistent volume for SQLite (or use PostgreSQL)
- ConfigMap/Secret for policy files and environment variables
- Service for API access
- Ingress for web UI

See [Docker Deployment](docs/DOCKER.md) for details.

## Approvals

### How do I handle approvals in automated workflows?

For automated workflows, you can:
1. Configure policies to allow low-risk actions automatically
2. Use the API to check approval status and poll for completion
3. Integrate with approval systems via the API
4. Use [Faramesh Horizon](../README.md#faramesh-cloud-products) or [Nexus](../README.md#faramesh-cloud-products) for advanced routing (Slack, email, etc.)

### Can I automate approvals?

Yes, but use caution. You can:
- Configure policies to automatically allow low-risk actions
- Use the API to programmatically approve actions (e.g., based on risk level or other criteria)
- Set up automated approval workflows

**Warning**: Automating approvals reduces the safety benefits of human-in-the-loop. Only automate approvals for actions you trust completely.

### How do approval tokens work?

When an action requires approval, Faramesh generates an `approval_token`. This token must be included in the approval request to prevent unauthorized approvals. The token is included in the action response and can be retrieved via the API.

## Observability

### Can I export audit logs?

Yes. All actions and events are stored in the database and can be exported via:
- **API**: `GET /v1/actions` and `GET /v1/actions/{id}/events`
- **CLI**: `faramesh list --json` and `faramesh events <id> --json`
- **Database**: Direct database queries (SQLite or PostgreSQL)

[Faramesh Nexus](../README.md#faramesh-cloud-products) includes advanced audit export features with long-term retention.

### What metrics are available?

Faramesh exposes Prometheus metrics at `/metrics`:
- `faramesh_requests_total{method,endpoint,status}` - HTTP request counts
- `faramesh_errors_total{error_type}` - Error counts by type
- `faramesh_actions_total{status,tool}` - Action counts by status and tool
- `faramesh_action_duration_seconds_bucket{...}` - Action execution duration histogram

See [Observability](docs/OBSERVABILITY.md) for details.

### Can I integrate with Grafana?

Yes. The Prometheus metrics endpoint can be scraped by Prometheus and visualized in Grafana. You can create dashboards for:
- Action throughput
- Approval rates
- Error rates
- Policy decision distribution
- Risk level distribution

## Security

### How secure is Faramesh?

Faramesh implements multiple security layers:
- **Deny-by-default**: Actions are denied unless explicitly allowed
- **Input validation**: All inputs are validated and sanitized
- **Command sanitization**: Shell commands are sanitized before execution
- **Optimistic locking**: Prevents race conditions in concurrent scenarios
- **No side effects until approval**: Policy evaluation has no side effects

See [Security Guardrails](docs/SECURITY-GUARDRAILS.md) for details.

### How do I report security vulnerabilities?

Please report security vulnerabilities via:
- **GitHub Security Advisory**: [Create a security advisory](https://github.com/faramesh/faramesh-core/security/advisories/new)
- **Email**: security@faramesh.dev (if available)

See [SECURITY.md](../SECURITY.md) for details.

### Does Faramesh store sensitive data?

Faramesh stores:
- Action metadata (tool, operation, params, context)
- Event timeline
- Approval decisions and reasons

**Important**: Faramesh does not execute actions—it only governs them. Execution happens in your environment. Ensure your execution environment handles sensitive data appropriately.

## Licensing

### What license is Faramesh under?

Faramesh Core is available under the **Elastic License 2.0**. See [LICENSE](../LICENSE) for details.

**Key points:**
- Free to use, modify, and integrate in your products
- Cannot offer Faramesh Core as a competing hosted service
- See LICENSE for full terms

### Can I use Faramesh in commercial products?

Yes. The Elastic License 2.0 allows commercial use, modification, and integration. You cannot offer Faramesh Core itself as a competing hosted service.

## Troubleshooting

### Server won't start

**Check:**
1. Is port 8000 available? (`lsof -i :8000`)
2. Are dependencies installed? (`pip install -e .`)
3. Check server logs for errors
4. Run `faramesh doctor` to check environment

### Actions not showing in UI

**Check:**
1. Browser console for errors
2. SSE connection in Network tab (should see `/v1/events` stream)
3. Server logs for errors
4. API health: `curl http://127.0.0.1:8000/health`

### Policy not working

**Check:**
1. Does `policies/default.yaml` exist?
2. Run `faramesh policy-validate policies/default.yaml`
3. Run `faramesh policy-refresh`
4. Check policy YAML syntax
5. Check server logs for policy loading errors

### CLI command not found

If `faramesh` command is not found:
1. Install: `pip install -e .`
2. Use: `python3 -m faramesh.cli <command>` instead
3. Check PATH includes Python scripts directory

## Support

### Where can I get help?

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/faramesh/faramesh-core/issues)
- **Discussions**: [GitHub Discussions](https://github.com/faramesh/faramesh-core/discussions)
- **Troubleshooting**: [Troubleshooting Guide](docs/Troubleshooting.md)

### How do I contribute?

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on contributing code, documentation, or reporting issues.
