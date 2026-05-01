## R4-T: Authorization Decisions — MODIFY/STEP_UP/DEFER Effects

**Objective:** Extend the governance decision framework to support three new policy effects that enable nuanced authorization workflows:
- **MODIFY**: Allow an action while enforcing constraints or policy lowering
- **STEP_UP**: Require elevated approval authority before proceeding
- **DEFER Cascades**: Enhance DEFER with dependency tracking and configurable cascade limits

---

## 1. MODIFY Effect — Constrained Authorization

### Semantics

**MODIFY** allows an action to proceed with modifications applied to arguments. This enables "yes, but with constraints" decisions:
- Policy lowering (e.g., reduce requested budget from $10k to $5k)
- Argument validation/transformation (e.g., enforce encryption, rewrite endpoint)
- Workflow branching (e.g., log + audit required before execution)

### Use Cases

1. **Budget Constraints**: "Approve refund, but cap at $500 instead of requested $2000"
2. **Isolation Enforcement**: "Allow shell, but require execution in Docker container"
3. **Audit Binding**: "Permit API call, but require prior compliance audit record"

### Runtime Semantics

When a policy rule returns `modify` effect:
1. Policy engine evaluates the rule and extracts `modifications` from the result
2. Pipeline creates a `Decision` with `Effect: MODIFY` and includes `ModifiedArgs`
3. Agent receives the modified arguments in the decision
4. Agent applies modifications before invoking the tool
5. If agent rejects modifications, it may retry (if `RetryPermitted: true`)

### Decision Fields Added

```go
// In Decision struct:

// ModifiedArgs contains constraint modifications to be applied before execution.
// Policy rules can modify request args: e.g., {"limit": 500, "isolation": "docker"}
ModifiedArgs map[string]any `json:"modified_args,omitempty"`

// ModifyReason explains the constraint (e.g., "budget capped by org policy")
ModifyReason string `json:"modify_reason,omitempty"`

// RequiredModifications indicates whether the agent MUST apply these modifications
// (vs. optional guidance). If true and agent doesn't apply, execution is blocked.
RequiredModifications bool `json:"required_modifications,omitempty"`
```

### Policy Language Extension (FPL)

```yaml
rule refund_capped {
  effect modify {
    limit: min(requested_amount, 500),
    reason: "org tier refund cap"
  }
  when tool == "stripe/refund" && org_tier == "standard"
}

rule shell_containerized {
  effect modify {
    execution_environment: "docker",
    required: true,
    reason: "all shells must run in container"
  }
  when tool == "shell/exec" && env != "sandbox"
}
```

---

## 2. STEP_UP Effect — Elevated Approval Required

### Semantics

**STEP_UP** routes a decision to an elevated approval authority. Unlike DEFER (which routes to standard approvers), STEP_UP enforces:
- Elevated authority check (e.g., must be a manager or security team member)
- Higher scrutiny threshold
- Optional additional validation (e.g., 2-person rule, time-of-day limits)
- Automatic re-escalation if initial approver cannot resolve

### Use Cases

1. **High-Value Actions**: "Refund > $5k requires finance manager approval"
2. **Sensitive Operations**: "Data export requires security team + compliance audit"
3. **Policy Violations**: "Tool usage outside SLA window requires incident commander approval"

### Runtime Semantics

When a policy rule returns `step_up` effect:
1. Policy engine evaluates rule and extracts `elevation_level` and `required_authority`
2. Pipeline creates a `Decision` with `Effect: STEP_UP`
3. Pipeline internally converts STEP_UP to a DEFER with elevated routing metadata
4. Approval system routes to the specified elevated authority group
5. Standard approvers cannot resolve; system re-routes if needed
6. On approval, decision re-evaluates (TOCTOU guard) and proceeds

### Decision Fields Added

```go
// In Decision struct:

// ElevationLevel indicates approval hierarchy level required.
// 0=peer review, 1=manager, 2=director, 3=executive, 4=security/compliance
ElevationLevel int `json:"elevation_level,omitempty"`

// RequiredAuthority is a regex/label matching the approver role.
// E.g., "finance_manager|finance_director", "security_team", "incident_commander"
RequiredAuthority string `json:"required_authority,omitempty"`

// StepUpReason explains why escalation is needed.
StepUpReason string `json:"step_up_reason,omitempty"`

// StepUpToken is set when Effect == STEP_UP (alias for elevated DEFER workflow)
StepUpToken string `json:"step_up_token,omitempty"`
```

### Policy Language Extension (FPL)

```yaml
rule high_value_refund {
  effect step_up {
    level: 1,           # manager approval required
    authority: "finance_manager|finance_director",
    reason: "refund > 5k requires finance manager"
  }
  when tool == "stripe/refund" && requested_amount > 5000
}

rule data_export_sensitive {
  effect step_up {
    level: 2,           # director + compliance required
    authority: "security_team|compliance_officer",
    reason: "PII export requires security/compliance audit"
  }
  when tool == "db/export" && contains_pii == true
}
```

---

## 3. DEFER Cascade — Dependency Tracking & Limits

### Current DEFER Implementation

- Deferred actions stored in queue (memory, Redis, Temporal, etc.)
- Upon approval, re-evaluated at execution time (TOCTOU guard)
- Can cascade to new DEFER if state changed or policy changed
- No explicit cycle detection or cascade depth limiting

### Proposed Enhancements

#### 3.1 Dependency Tracking

When a DEFER approval resolves and cascades to another DEFER, track:
- **Parent DEFER Token**: The original deferred action that triggered this one
- **Dependency Reason**: Why this new DEFER was triggered (e.g., "policy re-evaluation", "elevated authority routing")
- **Cascade Path**: Full lineage from original action to current DEFER

```go
// In defer/workflow.go

type Handle struct {
    // ...existing fields...

    // ParentDeferToken is set if this DEFER was triggered by another DEFER cascade.
    ParentDeferToken string `json:"parent_defer_token,omitempty"`

    // CascadeReason explains why this DEFER was triggered by a cascade.
    // E.g., "policy_changed", "elevated_routing", "toctou_re_evaluation"
    CascadeReason string `json:"cascade_reason,omitempty"`

    // CascadeDepth tracks how deeply nested this DEFER is (0 = original, 1 = first cascade, etc.)
    CascadeDepth int `json:"cascade_depth"`

    // CascadePath contains the full lineage of DEFER tokens from origin.
    CascadePath []string `json:"cascade_path,omitempty"`
}
```

#### 3.2 Cascade Depth Limits

Add configurable limits to prevent runaway cascades:

```go
// In core/types.go

type DeferCascadePolicy struct {
    // MaxDepth prevents infinite cascades. Default: 3 (original + 2 escalations)
    MaxDepth int `json:"max_depth"`

    // OnMaxDepthReached controls behavior when cascade limit is hit.
    // "deny" = treat as final deny, "approve" = auto-approve, "escalate" = route to operator
    OnMaxDepthReached string `json:"on_max_depth_reached"`

    // MaxTotalResolveTime is total time budget for entire cascade resolution.
    // Default: 24 hours. If exceeded, auto-denies.
    MaxTotalResolveTime time.Duration `json:"max_total_resolve_time"`
}
```

#### 3.3 Cycle Detection

Add cycle detection in cascade resolution:

```go
// In defer/workflow.go

// DetectCycle checks if resolving this approval would create a cycle in the cascade graph.
// Returns error if cycle detected (prevents A defers to B defers to A scenarios).
func (h *Handle) DetectCycle() error {
    seen := make(map[string]bool)
    current := h.ParentDeferToken
    for current != "" {
        if seen[current] {
            return fmt.Errorf("cascade cycle detected: %s", current)
        }
        seen[current] = true
        // Fetch parent handle and continue up the chain
        parent, err := getHandle(current) // lookup parent
        if err != nil {
            break
        }
        current = parent.ParentDeferToken
    }
    return nil
}

// GetCascadeMetrics returns statistics about this cascade chain.
func (h *Handle) GetCascadeMetrics() map[string]any {
    return map[string]any{
        "depth":           h.CascadeDepth,
        "total_in_chain":  len(h.CascadePath) + 1,
        "has_parent":      h.ParentDeferToken != "",
        "reason":          h.CascadeReason,
    }
}
```

#### 3.4 Enhanced Approval Validation

Update `validateResumeApproval()` in pipeline.go to:
- Check cascade depth limits before accepting approval
- Verify no cycles exist
- Log cascade metrics for observability

---

## 4. Integration Points

### 4.1 Type System (internal/core/types.go)

**Add Effect types:**
```go
const (
    EffectModify   Effect = "MODIFY"
    EffectStepUp   Effect = "STEP_UP"
    // Existing: EffectPermit, EffectDeny, EffectDefer, EffectShadow, EffectShadowPermit
)
```

**Extend Decision struct:**
- `ModifiedArgs` + `ModifyReason` + `RequiredModifications` (for MODIFY)
- `ElevationLevel` + `RequiredAuthority` + `StepUpReason` + `StepUpToken` (for STEP_UP)

### 4.2 Policy Language (fpl-lang)

**Add to grammar/parser:**
- `modify { ... }` keyword with field extraction
- `step_up { ... }` keyword with elevation_level and authority extraction

### 4.3 Pipeline (internal/core/pipeline.go)

**In Evaluate():**
1. When policy result is `modify`: create Decision with Effect=MODIFY, extract modifications
2. When policy result is `step_up`: create Decision with Effect=STEP_UP, internally trigger elevated DEFER

**In decide():**
1. For MODIFY: caller must apply modifications before invoking tool
2. For STEP_UP: alias to elevated DEFER workflow (reuse existing defer infrastructure)

### 4.4 Defer Backend (internal/core/defer/*)

**Enhancements:**
- Add `ParentDeferToken`, `CascadeReason`, `CascadeDepth`, `CascadePath` fields to Handle
- Implement cycle detection in resolution path
- Add cascade policy configuration and limit enforcement

### 4.5 DPR Audit (internal/core/dpr/record.go)

**Track cascade events:**
```go
// In Record struct, add optional field:
CascadeMetadata map[string]any `json:"cascade_metadata,omitempty"`
// Contains: parent_defer_token, cascade_depth, cascade_reason
```

---

## 5. Implementation Roadmap

### Phase 1: Type System & Decision Framework (2-3 hours)
- [ ] Add `EffectModify`, `EffectStepUp` to core/types.go Effect enum
- [ ] Extend Decision struct with MODIFY and STEP_UP fields
- [ ] Add DeferCascadePolicy struct to types.go
- [ ] Unit tests for new types

### Phase 2: Policy Language Support (4-5 hours)
- [ ] Extend FPL parser to recognize `modify` and `step_up` keywords
- [ ] Update grammar to support modification field extraction
- [ ] Update grammar to support elevation level and authority extraction
- [ ] Parser unit tests

### Phase 3: Pipeline Integration (6-8 hours)
- [ ] Update Evaluate() in pipeline.go to handle MODIFY result
- [ ] Update Evaluate() in pipeline.go to handle STEP_UP result (convert to elevated DEFER)
- [ ] Update decide() to document MODIFY semantics (caller must apply)
- [ ] Add tests for MODIFY/STEP_UP decision creation

### Phase 4: DEFER Cascades (4-6 hours)
- [ ] Extend Handle struct with cascade fields (ParentDeferToken, CascadeDepth, etc.)
- [ ] Implement DetectCycle() in Handle
- [ ] Implement GetCascadeMetrics() in Handle
- [ ] Update validateResumeApproval() to check cascade limits
- [ ] Add DeferCascadePolicy configuration
- [ ] Tests for cycle detection and cascade limits

### Phase 5: DPR & Audit (2-3 hours)
- [ ] Add cascade metadata to DPR Record
- [ ] Update audit CLI to display cascade info
- [ ] Update verify.go to validate cascade chains

### Phase 6: End-to-End Tests & Docs (3-4 hours)
- [ ] E2E tests for MODIFY workflow (policy lowering, argument rewriting)
- [ ] E2E tests for STEP_UP workflow (elevated routing, cascade to DEFER)
- [ ] E2E tests for DEFER cascades (depth limit, cycle detection)
- [ ] Operator runbook for managing elevated approvals
- [ ] Policy examples for common MODIFY/STEP_UP scenarios

**Total Estimated: 25-35 hours**

---

## 6. Testing Strategy

### Unit Tests

| Component | Test Cases |
|-----------|-----------|
| **types.go** | New Effect enums, Decision serialization |
| **FPL Parser** | Parsing modify/step_up from policy YAML, field extraction |
| **pipeline.go** | MODIFY/STEP_UP decision creation, effect dispatch |
| **defer/workflow.go** | Cycle detection, cascade depth tracking, metrics |
| **defer/backends** | Storing/loading cascade metadata in backends |

### Integration Tests

1. **MODIFY workflow**: Policy lowers budget → decision.ModifiedArgs set → Agent applies → Tool executes with modified args
2. **STEP_UP workflow**: Policy triggers STEP_UP → elevated DEFER created → routed to security_team → approval → re-evaluates → PERMIT
3. **DEFER cascade**: Initial DEFER → policy changes → re-evaluation triggers STEP_UP → cascade created → cycle detection blocks loop → resolves correctly
4. **Cascade limits**: Initial DEFER → cascade 1 → cascade 2 → cascade 3 (max_depth=3) → 4th cascade rejected or auto-approved per policy

### E2E Tests

1. High-value refund scenario: Standard refund → PERMIT; high-value → STEP_UP; manager approval → re-evaluate and PERMIT
2. Constraint escalation: Standard shell → PERMIT; sensitive shell (high-value context) → MODIFY with container requirement
3. Cascade resolution: 3-level DEFER chain with correct approvals at each level

---

## 7. Acceptance Criteria

- [ ] MODIFY effect exists and policy rules can return `modify { ... }`
- [ ] STEP_UP effect exists and policy rules can return `step_up { ... }`
- [ ] Pipeline correctly creates Decision with Effect=MODIFY and populates ModifiedArgs
- [ ] Pipeline correctly creates Decision with Effect=STEP_UP and routes to elevated approvers
- [ ] DEFER cascades track ParentDeferToken and CascadeDepth
- [ ] Cycle detection prevents infinite cascades
- [ ] Cascade depth limits enforced; auto-resolve per policy when limit reached
- [ ] E2E tests pass for MODIFY/STEP_UP/cascade scenarios
- [ ] Operator runbooks document use cases and troubleshooting

---

## 8. Risk Mitigations

| Risk | Mitigation |
|------|-----------|
| MODIFY args rejection by agent | RetryPermitted flag; policy documentation |
| STEP_UP approval bottleneck | Configurable escalation routing; auto-approval SLA |
| Cascade runaway | Depth limits (default 3), cycle detection, max total time |
| Policy inconsistency (MODIFY + DENY for same action) | Policy linting; compiler checks in FPL |
| Approval ordering (step_up before modify) | Deterministic policy evaluation order; tests |

---

## References

- Current DEFER implementation: [internal/core/defer/](../internal/core/defer/)
- Policy language: [fpl-lang/docs/](../../fpl-lang/docs/)
- Pipeline: [internal/core/pipeline.go](../internal/core/pipeline.go)
- Types: [internal/core/types.go](../internal/core/types.go)

---

**Status:** Design phase
**Created:** 2025-05-01
**Owner:** R4-T Implementation Sprint
