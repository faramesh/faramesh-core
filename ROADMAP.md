# Faramesh Roadmap

This roadmap outlines the product vision and future phases for Faramesh.

## Product Phases

### Phase 1: Faramesh Core (Open Source) ✅

**Status:** Available Now

Faramesh Core is the open-source foundation that provides:

- **Policy-Driven Governance**: YAML-based policies with first-match-wins evaluation
- **Risk Scoring**: Automatic risk assessment (low/medium/high)
- **Human-in-the-Loop**: Approval workflows for high-risk actions
- **REST API**: Complete REST API for integration
- **Web UI**: Modern dashboard for monitoring and approvals
- **CLI**: Comprehensive command-line interface
- **SDKs**: Python and Node.js SDKs
- **Framework Integrations**: One-line governance for LangChain, CrewAI, AutoGen, MCP, LangGraph, LlamaIndex
- **Docker Support**: Easy deployment with Docker Compose
- **SQLite & PostgreSQL**: Flexible database options
- **Policy Hot Reload**: Update policies without restarting
- **Prometheus Metrics**: Observability and monitoring
- **Security Guardrails**: Input validation, command sanitization, deny-by-default

**Use Cases:**
- Development and testing
- Small to medium teams
- Self-hosted deployments
- Custom integrations

---

### Phase 2: Faramesh Horizon (Hosted Control Plane) 🚧

**Status:** Coming Soon

Faramesh Horizon is a fully-managed SaaS offering that builds on Faramesh Core:

**Additional Features:**
- **Instant Onboarding**: No deployment required, start in minutes
- **Fully-Managed Service**: Automatic updates, scaling, and maintenance
- **Usage Tracking & Metrics**: Advanced analytics and reporting
- **API Keys & Secrets Management**: Secure credential management
- **Approval Routing**: Slack and email notifications for approvals
- **Multi-Tenant Support**: Isolated workspaces for teams
- **SLA Guarantees**: Uptime and performance guarantees

**Use Cases:**
- Startups and small teams
- Quick prototyping and testing
- Teams without DevOps resources
- Rapid deployment needs

**Value Proposition:**
Get started immediately without infrastructure management. Focus on building agents while Faramesh handles the governance infrastructure.

---

### Phase 3: Faramesh Nexus (Enterprise/On-Prem) 🚧

**Status:** Coming Soon

Faramesh Nexus is an enterprise-grade deployment that runs in your infrastructure:

**Additional Features:**
- **SSO Integration**: Single Sign-On with SAML/OIDC
- **RBAC**: Role-Based Access Control for teams
- **Multi-Org Management**: Manage multiple organizations
- **Advanced Audit Exports**: Long-term retention and compliance
- **Air-Gap Compatibility**: Deploy in isolated environments
- **Advanced Routing**: Custom approval workflows and integrations
- **Enterprise Support**: Dedicated support and SLAs
- **Custom Integrations**: API for custom approval systems

**Use Cases:**
- Enterprise organizations
- Regulated industries (finance, healthcare, etc.)
- Security-critical environments
- Organizations requiring full control
- Compliance and audit requirements

**Value Proposition:**
Enterprise-grade governance with full control over your infrastructure. Deploy in your VPC or Kubernetes cluster with advanced security and compliance features.

---

## Relationship Between Phases

```
┌─────────────────────────────────────────┐
│  Faramesh Core (OSS)                    │
│  - Policy Engine                        │
│  - API, CLI, SDKs                      │
│  - Web UI                              │
│  - Basic Auth                          │
└─────────────────────────────────────────┘
              │
    ┌─────────┴─────────┐
    │                   │
    ▼                   ▼
┌──────────┐      ┌──────────┐
│ Horizon  │      │  Nexus   │
│ (Cloud)  │      │(Enterprise)│
│          │      │          │
│ + Managed│      │ + SSO    │
│ + Routing│      │ + RBAC   │
│ + Metrics│      │ + Audit  │
└──────────┘      └──────────┘
```

**Core is the Engine**: All phases build on Faramesh Core's open-source foundation.

**Horizon and Nexus are Accelerators**: They add managed services, enterprise features, and advanced capabilities on top of Core.

---

## Current Focus

### Immediate Priorities

1. **Stability & Performance**
   - Performance optimization
   - Bug fixes and stability improvements
   - Enhanced error handling

2. **Documentation**
   - Complete documentation rewrite (in progress)
   - More examples and tutorials
   - Video guides

3. **Community**
   - Growing the open-source community
   - Gathering feedback from early adopters
   - Building integrations

### Near-Term (Next 3-6 Months)

1. **Enhanced Integrations**
   - More framework integrations
   - Pre-built connectors
   - Integration templates

2. **Policy Enhancements**
   - More policy packs
   - Policy templates
   - Policy testing tools

3. **UI Improvements**
   - Enhanced filtering and search
   - Bulk operations
   - Advanced analytics

### Long-Term (6-12 Months)

1. **Faramesh Horizon**
   - SaaS platform launch
   - Managed infrastructure
   - Approval routing

2. **Faramesh Nexus**
   - Enterprise features
   - SSO and RBAC
   - Advanced audit

---

## Contributing to the Roadmap

We welcome community input on the roadmap:

- **GitHub Discussions**: [Share your ideas](https://github.com/faramesh/faramesh-core/discussions)
- **GitHub Issues**: [Request features](https://github.com/faramesh/faramesh-core/issues/new)
- **Design Partners**: [Join as a design partner](docs/DESIGN_PARTNER_GUIDE.md)

---

## Version History

### v0.2.0 (Current)

- Complete documentation rewrite
- Enhanced CLI with DX features
- Policy hot reload
- Framework integrations (6 frameworks)
- Security enhancements
- Improved error handling

### v0.1.0

- Initial release
- Core policy engine
- REST API
- Web UI
- Python SDK
- Basic integrations

---

## See Also

- [Changelog](CHANGELOG.md) - Detailed release notes
- [Architecture](ARCHITECTURE.md) - System architecture
- [Contributing](CONTRIBUTING.md) - How to contribute
- [Design Partner Guide](docs/DESIGN_PARTNER_GUIDE.md) - Early adopter program
