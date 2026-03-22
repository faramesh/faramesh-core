# Faramesh Node.js SDK

Production-ready Node.js client for the Faramesh Execution Governor API.

## Installation

```bash
npm install @faramesh/sdk
```

Or install from local path:

```bash
npm install ../path/to/sdk/node
```

## Quick Start

```typescript
import { configure, submitAction, approveAction } from '@faramesh/sdk';

// Configure SDK (optional - defaults to http://127.0.0.1:8000)
configure({
  baseUrl: 'http://localhost:8000',
  token: 'your-token', // Optional, can also use FARAMESH_TOKEN env var
});

// Submit an action
const action = await submitAction(
  'my-agent',
  'http',
  'get',
  { url: 'https://example.com' }
);

console.log(`Action ${action.id} status: ${action.status}`);

// If action requires approval
if (action.status === 'pending_approval') {
  const approved = await approveAction(
    action.id,
    action.approval_token!,
    'Looks safe'
  );
  console.log(`Action approved: ${approved.status}`);
}
```

## Using CommonJS

```javascript
const { configure, submitAction, getAction } = require('@faramesh/sdk');

configure({ baseUrl: 'http://localhost:8000' });

(async () => {
  const action = await submitAction('agent', 'http', 'get', { url: 'https://example.com' });
  console.log(action);
})();
```

## New Features (OSS SDKs)

### Batch Submit

Submit multiple actions at once:

```typescript
const actions = await submitActions([
  { agent_id: 'agent1', tool: 'http', operation: 'get', params: { url: 'https://example.com' } },
  { agent_id: 'agent2', tool: 'http', operation: 'get', params: { url: 'https://example.org' } },
]);
```

### Submit and Wait

Submit an action and automatically wait for completion:

```typescript
const action = await submitAndWait(
  'my-agent',
  'http',
  'get',
  { url: 'https://example.com' },
  {},
  { autoApprove: true, timeout: 60000 }
);
```

### SSE Event Streaming

Stream events in real-time:

```typescript
tailEvents((event) => {
  console.log(`Event: ${event.event_type} - ${event.action_id}`);
});
```

### Typed Policy Objects

Build policies in code:

```typescript
import { createPolicy, validatePolicy, policyToYaml } from '@faramesh/sdk';

const policy = createPolicy([
  {
    match: { tool: 'http', op: 'get' },
    description: 'Allow HTTP GET',
    allow: true,
    risk: 'low',
  },
]);

const errors = validatePolicy(policy);
const yaml = policyToYaml(policy);
```

### Gate Endpoint & Deterministic Hashing

Get decisions without creating actions and verify hashes client-side:

```typescript
import { gateDecide, computeRequestHash, executeIfAllowed, replayDecision } from '@faramesh/sdk';

// Gate decide (decision only, no action created)
const decision = await gateDecide(
  'my-agent',
  'http',
  'get',
  { url: 'https://example.com' }
);

if (decision.outcome === 'EXECUTE') {
  console.log('Action would be allowed');
} else if (decision.outcome === 'HALT') {
  console.log(`Action would be denied: ${decision.reason_code}`);
}
```

### Compute Request Hash Locally

```typescript
import { computeRequestHash } from '@faramesh/sdk';

const payload = {
  agent_id: 'my-agent',
  tool: 'http',
  operation: 'get',
  params: { url: 'https://example.com' },
  context: {}
};

// Compute hash locally (matches server's request_hash)
const hash = computeRequestHash(payload);
console.log(`Request hash: ${hash}`);
```

### Execute If Allowed (Gated Execution)

```typescript
import { executeIfAllowed } from '@faramesh/sdk';

const result = await executeIfAllowed({
  agentId: 'my-agent',
  tool: 'http',
  operation: 'get',
  params: { url: 'https://example.com' },
  executor: async (tool, op, params, ctx) => {
    // Your actual execution logic
    return { status: 'done' };
  }
});

if (result.executed) {
  console.log('Action executed:', result.executionResult);
} else {
  console.log('Action blocked:', result.reasonCode);
}
```

### Replay Decision

```typescript
import { replayDecision } from '@faramesh/sdk';

// Verify decision is deterministic
const result = await replayDecision({ actionId: 'abc123' });

if (result.success) {
  console.log('Decision replay passed!');
} else {
  console.log('Mismatches:', result.mismatches);
}
```

## API Reference

### Configuration

#### `configure(options?: ClientConfig)`

Configure the global SDK client.

```typescript
configure({
  baseUrl: 'http://localhost:8000',  // Default: http://127.0.0.1:8000
  token: 'your-token',                // Optional, can use FARAMESH_TOKEN env var
  timeoutMs: 30000,                   // Default: 30000
  maxRetries: 3,                      // Default: 3
  retryBackoffFactor: 0.5,            // Default: 0.5
});
```

Environment variables:
- `FARAMESH_BASE_URL` or `FARA_API_BASE` - Base URL
- `FARAMESH_TOKEN` or `FARA_AUTH_TOKEN` - Authentication token

### Core Functions

#### `submitAction(agentId, tool, operation, params?, context?)`

Submit an action for governance evaluation.

#### `submitActions(actions[])`

Submit multiple actions in batch. Returns array of action results (or errors).

#### `submitAndWait(agentId, tool, operation, params?, context?, options?)`

Submit an action and wait for completion. Options:
- `pollInterval` - Milliseconds between polls (default: 1000)
- `timeout` - Maximum milliseconds to wait (default: 60000)
- `autoApprove` - Automatically approve pending actions (default: false)

```typescript
const action = await submitAction(
  'my-agent',
  'http',
  'get',
  { url: 'https://example.com' },
  { source: 'test' }
);
```

Returns: `Promise<Action>`

#### `getAction(actionId)`

Get an action by ID.

```typescript
const action = await getAction('12345678-1234-1234-1234-123456789abc');
```

Returns: `Promise<Action>`

#### `listActions(options?)`

List actions with optional filters.

```typescript
const actions = await listActions({
  limit: 20,
  offset: 0,
  agent_id: 'my-agent',
  tool: 'http',
  status: 'pending_approval',
});
```

Returns: `Promise<Action[]>`

#### `approveAction(actionId, token?, reason?)`

Approve a pending action.

```typescript
const action = await submitAction('agent', 'shell', 'run', { cmd: 'ls' });
if (action.status === 'pending_approval') {
  const approved = await approveAction(
    action.id,
    action.approval_token!,
    'Approved by admin'
  );
}
```

Returns: `Promise<Action>`

#### `denyAction(actionId, token?, reason?)`

Deny a pending action.

```typescript
const denied = await denyAction(
  action.id,
  action.approval_token!,
  'Too dangerous'
);
```

Returns: `Promise<Action>`

#### `startAction(actionId)`

Start execution of an approved or allowed action.

```typescript
const action = await submitAction('agent', 'http', 'get', { url: 'https://example.com' });
if (action.status === 'allowed') {
  const started = await startAction(action.id);
}
```

Returns: `Promise<Action>`

#### `replayAction(actionId)`

Replay an action by creating a new action with the same parameters.

```typescript
const original = await getAction('123');
const replayed = await replayAction('123');
console.log(`Replayed action: ${replayed.id}`);
```

Returns: `Promise<Action>`

#### `waitForCompletion(actionId, pollInterval?, timeout?)`

Wait for an action to complete (succeeded or failed).

```typescript
const action = await startAction('123');
const final = await waitForCompletion(action.id, 1000, 60000);
console.log(`Final status: ${final.status}`);
```

Parameters:
- `pollInterval` - Milliseconds between polls (default: 1000)
- `timeout` - Maximum milliseconds to wait (default: 60000)

Returns: `Promise<Action>`

#### `apply(filePath)`

Load an action from a YAML or JSON file and submit it.

#### `tailEvents(callback?, actionId?)`

Stream events via Server-Sent Events (SSE). Calls callback for each event.

```typescript
// action.yaml
// agent_id: my-agent
// tool: http
// operation: get
// params:
//   url: https://example.com

const action = await apply('./action.yaml');
```

Returns: `Promise<Action>`

### Convenience Aliases

- `allow(actionId, token?, reason?)` - Alias for `approveAction`
- `deny(actionId, token?, reason?)` - Alias for `denyAction`

## Error Handling

The SDK provides typed error classes:

```typescript
import {
  FarameshError,
  FarameshAuthError,
  FarameshNotFoundError,
  FarameshPolicyError,
  FarameshTimeoutError,
  FarameshConnectionError,
  FarameshValidationError,
} from '@faramesh/sdk';

try {
  const action = await submitAction('agent', 'unknown', 'do', {});
} catch (error) {
  if (error instanceof FarameshPolicyError) {
    console.error('Action denied by policy:', error.message);
  } else if (error instanceof FarameshAuthError) {
    console.error('Authentication failed:', error.message);
  } else if (error instanceof FarameshNotFoundError) {
    console.error('Action not found:', error.message);
  } else {
    console.error('Error:', error.message);
  }
}
```

## Complete Example: Approval Flow

```typescript
import {
  configure,
  submitAction,
  approveAction,
  startAction,
  waitForCompletion,
} from '@faramesh/sdk';

configure({ baseUrl: 'http://localhost:8000' });

async function runAction() {
  // Submit action
  const action = await submitAction(
    'my-agent',
    'shell',
    'run',
    { cmd: 'ls -la' }
  );

  console.log(`Action ${action.id} status: ${action.status}`);

  // If pending approval, approve it
  if (action.status === 'pending_approval') {
    const approved = await approveAction(
      action.id,
      action.approval_token!,
      'Approved by automation'
    );
    console.log(`Action approved: ${approved.id}`);

    // Start execution
    const started = await startAction(approved.id);
    console.log(`Action started: ${started.id}`);

    // Wait for completion
    const final = await waitForCompletion(started.id);
    console.log(`Action completed: ${final.status}`);
  }
}

runAction().catch(console.error);
```

## TypeScript Support

Full TypeScript types are included:

```typescript
import { Action, ActionStatus, ClientConfig } from '@faramesh/sdk';

const action: Action = await getAction('123');
const status: ActionStatus = action.status;
```

## Building from Source

```bash
cd sdk/node
npm install
npm run build
```

The built files will be in `dist/`.

## Repository

**Source**: https://github.com/faramesh/faramesh-node-sdk

## License

Elastic License 2.0
