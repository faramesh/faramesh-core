/**
 * Faramesh Node.js SDK
 * 
 * Production-ready client for the Faramesh Execution Governor API
 * 
 * @example
 * ```typescript
 * import { configure, submitAction, approveAction } from '@faramesh/sdk';
 * 
 * configure({ baseUrl: 'http://localhost:8000', token: 'dev-token' });
 * 
 * const action = await submitAction('my-agent', 'http', 'get', { url: 'https://example.com' });
 * console.log(`Action ${action.id} status: ${action.status}`);
 * ```
 */

export { getActiveConfig, getActiveConfig as get_active_config } from "./client";

export {
  ExecutionGovernorClient,
  type GovernorConfig,
} from "./legacy_client";

export { FarameshError as GovernorError } from "./types";

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
  streamEvents,
  onEvents,
  allow,
  deny,
  __version__,
  // Gate/Replay helpers
  gateDecide,
  gateDecideDict,
  replayDecision,
  verifyRequestHash,
  executeIfAllowed,
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
  FarameshError,
  FarameshAuthError,
  FarameshNotFoundError,
  FarameshPolicyError,
  FarameshTimeoutError,
  FarameshConnectionError,
  FarameshValidationError,
  FarameshServerError,
  FarameshBatchError,
  FarameshDeniedError,
  DenyError,
  DeferredError,
  FarameshEvent,
  // Gate types
  DecisionOutcome,
  GateDecision,
  ReplayResult,
} from "./types";

// Canonicalization helpers
export {
  canonicalize,
  canonicalizeActionPayload,
  computeRequestHash,
  computeHash,
  CanonicalizeError,
} from "./canonicalization";

export {
  governedTool,
  GovernedToolConfig,
} from "./governed-tool";

export { govern } from "./govern";
export {
  installLangChainInterceptor,
  createLangChainMiddleware,
  LangChainInstallOptions,
  LangChainMiddlewareOptions,
  FarameshLangChainMiddleware,
} from "./langchain";

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

export * from "./python_aliases";

// Default export for CommonJS compatibility
import * as SDK from "./client";
export default SDK;
