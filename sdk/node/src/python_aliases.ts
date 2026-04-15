/**
 * Python-style names (snake_case) for parity with `faramesh` Python SDK.
 */
export {
  ExecutionGovernorClient,
  type GovernorConfig,
} from "./legacy_client";

export { FarameshError as GovernorError } from "./types";

export { getActiveConfig as get_active_config } from "./client";

export {
  submitAction as submit_action,
  submitActions as submit_actions,
  submitActionsBulk as submit_actions_bulk,
  submitAndWait as submit_and_wait,
  blockUntilApproved as block_until_approved,
  getAction as get_action,
  listActions as list_actions,
  approveAction as approve_action,
  denyAction as deny_action,
  startAction as start_action,
  replayAction as replay_action,
  waitForCompletion as wait_for_completion,
  tailEvents as tail_events,
  streamEvents as stream_events,
  onEvents as on_events,
  gateDecide as gate_decide,
  gateDecideDict as gate_decide_dict,
  replayDecision as replay_decision,
  verifyRequestHash as verify_request_hash,
  executeIfAllowed as execute_if_allowed,
} from "./client";

export {
  canonicalizeActionPayload as canonicalize_action_payload,
  computeRequestHash as compute_request_hash,
} from "./canonicalization";

export { getDefaultStore as get_default_store } from "./snapshot";

export {
  validatePolicyFile as validate_policy_file,
  testPolicyAgainstAction as test_policy_against_action,
} from "./policy-helpers";

export { createPolicy as create_policy } from "./policy";
