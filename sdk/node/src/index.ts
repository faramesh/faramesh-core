/**
 * FaraCore Node.js SDK
 * 
 * Production-ready client for the FaraCore Execution Governor API
 * 
 * @example
 * ```typescript
 * import { configure, submitAction, approveAction } from '@faramesh/faracore';
 * 
 * configure({ baseUrl: 'http://localhost:8000', token: 'dev-token' });
 * 
 * const action = await submitAction('my-agent', 'http', 'get', { url: 'https://example.com' });
 * console.log(`Action ${action.id} status: ${action.status}`);
 * ```
 */

export {
  configure,
  submitAction,
  submitActions,
  submitActionsBulk,
  submitAndWait,
  blockUntilApproved,
  getAction,
  listActions,
  approveAction,
  denyAction,
  startAction,
  replayAction,
  waitForCompletion,
  apply,
  tailEvents,
  onEvents,
  allow,
  deny,
  __version__,
} from "./client";

export {
  Action,
  ActionStatus,
  Decision,
  RiskLevel,
  ClientConfig,
  SubmitActionRequest,
  ListActionsOptions,
  ApprovalRequest,
  FaraCoreError,
  FaraCoreAuthError,
  FaraCoreNotFoundError,
  FaraCorePolicyError,
  FaraCoreTimeoutError,
  FaraCoreConnectionError,
  FaraCoreValidationError,
  FaraCoreServerError,
  FaraCoreBatchError,
  FaraCoreDeniedError,
  FaracoreEvent,
} from "./types";

export {
  governedTool,
  GovernedToolConfig,
} from "./governed-tool";

export {
  ActionSnapshotStore,
  getDefaultStore,
} from "./snapshot";

export {
  validatePolicyFile,
  testPolicyAgainstAction,
} from "./policy-helpers";

export {
  Policy,
  PolicyRule,
  MatchCondition,
  RiskRule,
  RiskLevel as PolicyRiskLevel,
  validatePolicy,
  policyToYaml,
  policyToDict,
  createPolicy,
} from "./policy";

// Default export for CommonJS compatibility
import * as SDK from "./client";
export default SDK;
