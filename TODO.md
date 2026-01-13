# Enterprise Features Not Included in FaraCore

FaraCore is intentionally minimal to maximize adoption. The following features are available in **Faramesh Enterprise**:

## Multi-Tenancy & Access Control
- Multi-tenant support (org_id, project_id)
- Role-Based Access Control (RBAC)
- User management
- Project/workspace isolation

## Authentication & Authorization
- API key management (generation, scoping, rotation, expiration)
- JWT authentication with refresh tokens
- SSO integration (OIDC/SAML)
- Auth0/Okta integration
- Multi-factor authentication (MFA)

## Connectors
- Stripe (payments)
- GitHub (repositories, issues, PRs)
- Jira (tickets, workflows)
- Linear (issues, projects)
- AWS (EC2, S3, Lambda, etc.)
- Google Cloud Platform (GCP)
- Microsoft Azure
- MongoDB, Firebase, Cassandra
- Twitter, Facebook, Instagram
- Shopify, WooCommerce

## Webhooks & Notifications
- Webhook subscriptions
- Email notifications (SMTP)
- Slack notifications
- Custom webhook endpoints

## Advanced Policy Features
- Database-backed policies
- Policy versioning and testing
- Shadow mode for policies
- Tool schema versioning
- Policy migration tools
- CLI policy validation (`faramesh policy validate`, `diff`, `test`)

## Execution & Sandboxing
- Batch execution
- Subprocess sandboxing (whitelisted commands, resource limits)
- Controlled filesystem (whitelisted paths, quarantine writes)
- Puppeteer/Playwright browser automation wrappers

## Rate Limiting & Budgets
- Global rate limiting
- Per-tool rate limiting
- Budget enforcement (max_amount, max_daily_amount, max_calls_per_hour)
- Budget tracking and alerts

## Compliance & Privacy
- GDPR compliance (data deletion, export, consent)
- CCPA compliance
- Data privacy manager
- Audit logs for critical actions

## Archival & Tamper-Evidence
- S3 archival with Object Lock
- Merkle tree/hash chaining for actions
- Archive lifecycle management
- Archive indexing

## Observability & Analytics
- Advanced dashboards
- Aggregate views API (top tools, failures, latency, budget)
- Export pipelines (Datadog, Prometheus, Grafana, SIEM)
- SIEM integration
- Custom analytics

## High Availability & Scaling
- Kubernetes deployment manifests
- Horizontal Pod Autoscaler (HPA)
- Health/readiness checks
- Leader election
- PostgreSQL replication
- Load balancing
- Circuit breaker patterns

## Enterprise CLI Commands
- `faramesh policy create/update/delete`
- `faramesh policy activate`
- `faramesh migrate rollback`
- `faramesh migrate status`
- `faramesh migrate backup`
- `faramesh watch <action_id>`

## Enterprise SDK Modules
- HTTP interceptors (Axios, Fetch)
- Child process wrappers
- Advanced retry logic
- Connection pooling
- Request batching

---

**Note**: This list represents features available in Faramesh Enterprise. FaraCore focuses on core governance functionality to maximize adoption and community growth.
