# FaraCore SDK - OSS Features

## ✅ New Features Added

### 1. Batch Submit ✅

**Python:**
```python
from faracore import submit_actions

actions = submit_actions([
    {"agent_id": "agent1", "tool": "http", "operation": "get", "params": {"url": "https://example.com"}},
    {"agent_id": "agent2", "tool": "http", "operation": "get", "params": {"url": "https://example.org"}},
])
```

**Node:**
```typescript
import { submitActions } from '@faramesh/faracore';

const actions = await submitActions([
  { agent_id: 'agent1', tool: 'http', operation: 'get', params: { url: 'https://example.com' } },
  { agent_id: 'agent2', tool: 'http', operation: 'get', params: { url: 'https://example.org' } },
]);
```

**Benefits:**
- Pure DX improvement
- Makes SDKs look serious for real workloads
- Doesn't weaken monetization (server-side features remain premium)

### 2. Async / Streaming Helpers ✅

#### Submit and Wait

**Python:**
```python
from faracore import submit_and_wait

# Submit and automatically wait for completion
action = submit_and_wait(
    "my-agent",
    "http",
    "get",
    {"url": "https://example.com"},
    auto_approve=True,
    timeout=120.0,
)
print(f"Final status: {action['status']}")
```

**Node:**
```typescript
import { submitAndWait } from '@faramesh/faracore';

const action = await submitAndWait(
  'my-agent',
  'http',
  'get',
  { url: 'https://example.com' },
  {},
  { autoApprove: true, timeout: 60000 }
);
```

#### SSE Tail

**Python:**
```python
from faracore import tail_events

def handle_event(event):
    print(f"Event: {event.get('event_type')} - {event.get('action_id')}")

tail_events(callback=handle_event)
```

**Node:**
```typescript
import { tailEvents } from '@faramesh/faracore';

tailEvents((event) => {
  console.log(`Event: ${event.event_type} - ${event.action_id}`);
});
```

**Benefits:**
- Agents and tool-runners love `await submitAndWait()`
- SSE wrappers provide real-time updates
- Pure adoption fuel

### 3. Typed Policy Objects (Client-Side) ✅

**Python:**
```python
from faracore.sdk.policy import (
    create_policy,
    PolicyRule,
    MatchCondition,
    RiskRule,
    RiskLevel,
)

# Build policy in code
policy = create_policy(
    rules=[
        PolicyRule(
            match=MatchCondition(tool="http", op="get"),
            description="Allow HTTP GET requests",
            allow=True,
            risk=RiskLevel.LOW,
        ),
        PolicyRule(
            match=MatchCondition(tool="shell", op="*"),
            description="Shell commands require approval",
            require_approval=True,
            risk=RiskLevel.MEDIUM,
        ),
        PolicyRule(
            match=MatchCondition(tool="*", op="*"),
            description="Default deny",
            deny=True,
            risk=RiskLevel.HIGH,
        ),
    ],
    risk_rules=[
        RiskRule(
            name="dangerous_shell",
            when=MatchCondition(tool="shell", pattern="rm -rf|shutdown"),
            risk_level=RiskLevel.HIGH,
        ),
    ],
)

# Validate
errors = policy.validate()
if errors:
    print("Errors:", errors)

# Convert to YAML
yaml_str = policy.to_yaml()
```

**Node:**
```typescript
import { createPolicy, validatePolicy, policyToYaml } from '@faramesh/faracore';

const policy = createPolicy([
  {
    match: { tool: 'http', op: 'get' },
    description: 'Allow HTTP GET',
    allow: true,
    risk: 'low',
  },
  {
    match: { tool: 'shell', op: '*' },
    description: 'Shell requires approval',
    require_approval: true,
    risk: 'medium',
  },
  {
    match: { tool: '*', op: '*' },
    description: 'Default deny',
    deny: true,
    risk: 'high',
  },
]);

const errors = validatePolicy(policy);
const yaml = policyToYaml(policy);
```

**Benefits:**
- Build policy payloads in code
- Test policies locally
- TypeScript types / Python models provide type safety
- Server-side DSL, evaluators, and "policy packs" stay Horizon/Nexus

## Implementation Status

### Python SDK ✅
- ✅ `submit_actions()` - Batch submit
- ✅ `submit_and_wait()` - Submit and wait for completion
- ✅ `tail_events()` - SSE streaming wrapper
- ✅ Typed policy models (`Policy`, `PolicyRule`, `MatchCondition`, `RiskRule`)
- ✅ `create_policy()` - Convenience function
- ✅ `policy.validate()` - Client-side validation
- ✅ `policy.to_yaml()` - Convert to YAML

### Node SDK ✅
- ✅ `submitActions()` - Batch submit
- ✅ `submitAndWait()` - Submit and wait for completion
- ✅ `tailEvents()` - SSE streaming wrapper
- ✅ Typed policy interfaces (`Policy`, `PolicyRule`, `MatchCondition`, `RiskRule`)
- ✅ `createPolicy()` - Convenience function
- ✅ `validatePolicy()` - Client-side validation
- ✅ `policyToYaml()` - Convert to YAML

## Test Coverage

### Python SDK
- ✅ 9 tests for policy models (all passing)
- ✅ 5 tests for batch/async features (all passing)
- ✅ Total: 14 new tests passing

### Node SDK
- ✅ TypeScript compilation successful
- ✅ All exports working
- ✅ Examples created

## Examples

### Python Examples
- `examples/sdk_batch_submit.py` - Batch submission
- `examples/sdk_submit_and_wait.py` - Submit and wait
- `examples/sdk_policy_builder.py` - Policy building

### Node Examples
- `sdk/node/examples/batch-submit.js` - Batch submission
- `sdk/node/examples/submit-and-wait.js` - Submit and wait
- `sdk/node/examples/policy-builder.js` - Policy building

## Summary

All three OSS features are implemented and tested:
- ✅ Batch submit - Pure DX, makes SDKs production-ready
- ✅ Async/streaming helpers - `submitAndWait()` and SSE wrappers
- ✅ Typed policy objects - Client-side policy building with validation

**Ready for open-source release!**
