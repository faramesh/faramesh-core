#!/usr/bin/env node
/**
 * Gated Execution Example
 * 
 * Demonstrates using the gate endpoint and canonicalization helpers
 * to implement non-bypassable execution gates.
 * 
 * Usage:
 *   node examples/gated-execution.js
 */

const { 
  configure, 
  gateDecide, 
  executeIfAllowed,
  computeRequestHash,
  replayDecision,
  submitAction,
} = require('../dist');

async function main() {
  // Configure SDK
  configure({ baseUrl: process.env.FARAMESH_BASE_URL || 'http://localhost:8000' });

  console.log('Faramesh Gated Execution Example\n');

  // Example 1: Gate decide (decision only, no action created)
  console.log('1. Gate Decide (pre-check):');
  const decision = await gateDecide(
    'test-agent',
    'http',
    'get',
    { url: 'https://example.com' }
  );
  console.log(`   Outcome: ${decision.outcome}`);
  console.log(`   Reason Code: ${decision.reason_code}`);
  console.log(`   Request Hash: ${decision.request_hash.slice(0, 16)}...`);
  console.log(`   Provenance ID: ${decision.provenance_id?.slice(0, 16)}...`);

  // Example 2: Compute request hash locally
  console.log('\n2. Local Request Hash:');
  const payload = {
    agent_id: 'test-agent',
    tool: 'http',
    operation: 'get',
    params: { url: 'https://example.com' },
    context: {},
  };
  const localHash = computeRequestHash(payload);
  console.log(`   Local Hash: ${localHash.slice(0, 16)}...`);
  console.log(`   Matches Server: ${localHash === decision.request_hash}`);

  // Example 3: Execute if allowed
  console.log('\n3. Execute If Allowed:');
  const result = await executeIfAllowed({
    agentId: 'test-agent',
    tool: 'http',
    operation: 'get',
    params: { url: 'https://example.com' },
    executor: async (tool, op, params, ctx) => {
      console.log(`   [Executor] Would execute: ${tool}:${op}`);
      return { simulated: true };
    },
  });
  console.log(`   Outcome: ${result.outcome}`);
  console.log(`   Executed: ${result.executed}`);
  if (result.executed) {
    console.log(`   Result: ${JSON.stringify(result.executionResult)}`);
  }

  // Example 4: Submit and replay
  console.log('\n4. Submit and Replay Decision:');
  try {
    const action = await submitAction(
      'test-agent',
      'http',
      'get',
      { url: 'https://api.example.com/data' }
    );
    console.log(`   Created Action: ${action.id.slice(0, 8)}...`);
    console.log(`   Action Outcome: ${action.outcome}`);
    
    // Replay the decision
    const replay = await replayDecision({ actionId: action.id });
    console.log(`   Replay Success: ${replay.success}`);
    if (!replay.success) {
      console.log(`   Mismatches: ${replay.mismatches.join(', ')}`);
    }
  } catch (err) {
    console.log(`   Error: ${err.message}`);
  }

  console.log('\nDone!');
}

main().catch(console.error);
