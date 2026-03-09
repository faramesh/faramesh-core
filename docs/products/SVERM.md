# Sverm — Multi-Agent Coordination and Cross-Agent Governance PRD

**Product:** Faramesh Sverm  
**Repo (planned):** `faramesh/sverm`  
**License:** Commercial (part of Horizon Enterprise tier)  
**Name:** "Sverm" is Norwegian/Swedish for "swarm" — reflects the product's focus on governing swarms of cooperating agents.  
**Relationship to Core:** Sverm is the cross-agent layer that Core cannot be. Core governs individual agent tool calls. Sverm governs agent coordination: what plans they can form, what authority they can delegate, what sequences they collectively execute.

---

## The Problem Core Cannot Solve

Faramesh Core provides L1 (invariant, deterministic) enforcement at the individual tool call level. This is correct and complete for single agents. It is insufficient for multi-agent systems.

Consider three agents: Agent A reads 50 customer records, Agent B sends those records to an external API, Agent C deletes the originals. Each individual call passes policy. The sequence — data exfiltration and deletion — is invisible to any single agent's governance because the sequence is distributed across agent boundaries.

This is the **cross-agent emergent plan problem**, and it cannot be solved at L1. It requires:
1. A complete view of all agents' DPR streams simultaneously
2. Correlation of events across agent boundaries by timestamp and data provenance
3. Cross-agent sequence pattern analysis running as a stateful streaming computation
4. Detection algorithms that fire on distributed patterns, not individual calls

Sverm is that system. It operates at **L3** (best-effort, probabilistic, detection not prevention) for cross-agent patterns while maintaining L1 guarantees for individual agents.

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │              Sverm Engine                │
                    │                                         │
  Agent A DPR ─────►│   Kafka/NATS Consumer                   │
  Agent B DPR ─────►│   Cross-Agent Event Correlator          │──► Alerts
  Agent C DPR ─────►│   Sequence Pattern Evaluator            │──► DEFER Triggers
  Agent N DPR ─────►│   Behavioral Anomaly Detector           │──► Horizon Dashboard
                    │                                         │
                    │   State: Redis (sliding windows)        │
                    │   Storage: PostgreSQL (pattern history) │
                    └─────────────────────────────────────────┘
```

---

## Core Features

### Cross-Agent Sequence Rules (Sverm Policy Language)

Sverm extends FPL with cross-agent sequence conditions:

```yaml
# sverm-policy.yaml
sverm-version: "1.0"
org-id: acme-corp

sequence_rules:
  - id: sverm-001
    description: "Detect read-then-exfil pattern across agents"
    pattern:
      - agent_pattern: "*"
        tool_pattern: "read_customer_*"
        outcome: PERMIT
        count_min: 20
        window_minutes: 30
        
      - agent_pattern: "*"
        tool_pattern: "http/post"
        outcome: PERMIT
        within_minutes: 10    # after first pattern
        destination: external  # not in org allowlist
        
    on_match:
      effect: alert
      severity: critical
      notify: pagerduty
      finding_code: CROSS_AGENT_DATA_EXFIL
      
  - id: sverm-002
    description: "Detect credential read followed by admin action (across agents)"
    pattern:
      - tool_pattern: "*credential*"
        outcome: PERMIT
      - tool_pattern: "admin/*"
        within_minutes: 10
        different_agent_than_step_1: true  # flag if it's a DIFFERENT agent
        
    on_match:
      effect: defer_next_matching
      severity: high
      finding_code: CROSS_AGENT_PRIVILEGE_ESCALATION
      
  - id: sverm-003
    description: "Multi-agent orchestration exceeds total budget"
    type: aggregate
    tool_pattern: "stripe/*"
    window_minutes: 60
    aggregate_metric: total_business_cost_usd
    threshold: 10000
    on_exceed:
      effect: defer_all_matching
      notify: finance-ops
```

### Google ADK Pattern Governance

Sverm has native understanding of Google ADK's multi-agent patterns:

#### Sequential Agent Governance
```yaml
sequential_pipeline:
  pipeline_id: "trip-planner"
  agents_in_order: ["food-agent", "transport-agent", "aggregator"]
  
  session_state_policy:
    # Session state written between agents must pass scanning
    write_scan: [injection, pii, secrets]
    read_sanitize: true
    undeclared_key_policy: deny
    
  pipeline_seal:
    # Each agent seals its output; next agent verifies the seal
    enabled: true
    on_tamper: deny
    
  phase_completion_requirements:
    - agent: "food-agent"
      required_keys: ["restaurant_finding"]
      min_tool_calls: 1
      on_incomplete: deny_next_phase
```

#### Parallel Agent Governance
```yaml
parallel_fan_out:
  orchestration_id: "parallel-research"
  agents: ["research-a", "research-b", "research-c"]
  
  aggregate_budget:
    max_cost_usd: 50.00
    per_agent_max_cost_usd: 20.00
    on_exceed: cancel_remaining
    
  namespace_isolation:
    # Each agent writes to its own namespace in session state
    enforce_agent_prefixes: true
    
  aggregation_output_governance:
    scan: [sanctions, pii, injection]
    on_violation: defer
```

#### Orchestrator Routing Governance
```yaml
orchestrator_manifest:
  orchestrator_id: "main-orchestrator"
  
  permitted_invocations:
    - agent_id: "data-reader"
      max_per_session: 5
    - agent_id: "data-writer"
      max_per_session: 3
      requires_prior_agent: "data-reader"   # writer can only be invoked after reader
    - agent_id: "admin-agent"
      requires_approval: true               # always requires DEFER
      
  undeclared_invocation_policy: deny
  routing_scan:
    # Scan what the orchestrator passes to sub-agents as task descriptions
    task_description_scan: [injection]
```

### Delegation Authority Enforcement

The object-capability model for multi-agent authority:

```yaml
delegation_policy:
  # Sub-agents can only receive a subset of orchestrator authority
  authority_reduction: strict   # non-configurable — sub-scope ⊆ parent-scope
  
  cross_org_federation:
    # Trust documents from external orgs
    trusted_orgs:
      - org: "partner-corp.com"
        signed_trust_document_url: "https://partner-corp.com/.well-known/faramesh-trust.json"
        permitted_delegation_scope: ["read_shared_data"]
        
  delegation_chain_rules:
    - id: "no-external-admin"
      when: "delegation.origin_org != this_org"
      tool_pattern: "admin/*"
      effect: deny
      
    - id: "depth-limit"
      when: "delegation.depth > 3"
      tool_pattern: "*"
      effect: deny
```

### Cross-Agent DPR Linkage

When Agent A calls Agent B as a tool (Agent-as-Tool pattern), Sverm maintains bidirectional DPR linkage:

```json
// Agent A's DPR record
{
  "tool_id": "invoke_agent",
  "args_structural_sig": "...",
  "inner_governance_dpr_record_id": "dpr_agent_b_456"
}

// Agent B's DPR record  
{
  "tool_id": "stripe/refund",
  "invoked_by_agent_id": "agent-a",
  "invoked_by_dpr_record_id": "dpr_agent_a_123"
}
```

This makes the complete call graph traceable through the DPR chain.

---

## CLI Commands

```bash
# Sverm manages fleet-wide cross-agent policy
faramesh sverm apply sverm-policy.yaml        # push cross-agent policy to Sverm engine
faramesh sverm status                         # current active sequence rules, recent findings
faramesh sverm findings --last 7d             # all cross-agent pattern matches
faramesh sverm findings --severity critical   # filter by severity

# Multi-agent specific
faramesh sverm trace --session-id abc123      # full multi-agent call graph for a session
faramesh sverm graph --agent orchestrator-bot # visualize agent delegation graph

# Real-time monitoring
faramesh sverm tail                           # live cross-agent event stream
```

---

## What Sverm Is NOT

- **Not a prevention system for cross-agent patterns.** Sverm is detection + alerting (L3). Individual agent enforcement (L1) is Core's job and remains unaffected.
- **Not an agent runtime.** Sverm does not orchestrate agents or route messages between them. It observes and analyzes.
- **Not a replacement for Core.** Every agent still needs its own Core enforcement. Sverm adds the cross-agent layer on top.
- **Not a deterministic guarantee.** Cross-agent sequence detection is probabilistic. A sophisticated attacker who spaces their calls far apart in time may evade detection. The DPR chain still records everything — what Sverm cannot prevent, it makes forensically discoverable.

---

## Technical Requirements

- **Event bus:** Kafka or NATS for DPR record streaming from all Core instances
- **Stream processor:** Apache Flink or Kafka Streams for stateful cross-agent sequence analysis
- **State store:** Redis (sliding windows, correlation state), PostgreSQL (finding history)
- **Deployment:** separate service from Core and Horizon; connects to both

---

## Build Order

1. **v0.1**: Cross-agent DPR aggregator (consume all agents' DPR streams, store in unified PostgreSQL schema)
2. **v0.2**: Basic sequence rule engine (detect simple A→B patterns across agents)
3. **v0.3**: Google ADK pattern support (sequential, parallel, orchestrator manifests)
4. **v0.4**: Delegation authority enforcement + cross-agent DPR linkage
5. **v0.5**: Real-time correlation with Flink + Sverm CLI
6. **v1.0**: Horizon integration (Sverm findings surface in fleet dashboard)
