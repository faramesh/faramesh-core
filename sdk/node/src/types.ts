/**
 * TypeScript type definitions for Faramesh SDK
 */

export interface Action {
  id: string;
  agent_id: string;
  tool: string;
  operation: string;
  params: Record<string, any>;
  context: Record<string, any>;
  status: ActionStatus;
  decision: Decision | null;
  reason: string | null;
  risk_level: RiskLevel | null;
  approval_token: string | null;
  policy_version: string | null;
  created_at: string;
  updated_at: string;
  js_example?: string;
  python_example?: string;
  // Execution gate fields
  outcome?: DecisionOutcome | null;
  reason_code?: string | null;
  reason_details?: Record<string, any> | null;
  request_hash?: string | null;
  policy_hash?: string | null;
  runtime_version?: string | null;
  profile_id?: string | null;
  profile_version?: string | null;
  profile_hash?: string | null;
  provenance_id?: string | null;
}

export type DecisionOutcome = "EXECUTE" | "ABSTAIN" | "HALT";

export interface GateDecision {
  outcome: DecisionOutcome;
  reason_code: string;
  reason?: string | null;
  request_hash: string;
  policy_version?: string | null;
  policy_hash?: string | null;
  profile_id?: string | null;
  profile_version?: string | null;
  profile_hash?: string | null;
  runtime_version?: string | null;
  provenance_id?: string | null;
}

export interface ReplayResult {
  success: boolean;
  originalOutcome: string;
  replayedOutcome: string;
  originalReasonCode: string;
  replayedReasonCode: string;
  requestHashMatch: boolean;
  policyHashMatch: boolean;
  profileHashMatch: boolean;
  runtimeVersionMatch: boolean;
  mismatches: string[];
}

export type ActionStatus =
  | "allowed"
  | "pending_approval"
  | "approved"
  | "denied"
  | "executing"
  | "succeeded"
  | "failed";

export type Decision = "allow" | "deny" | "require_approval";

export type RiskLevel = "low" | "medium" | "high";

export interface ClientConfig {
  baseUrl?: string;
  token?: string;
  timeoutMs?: number;
  maxRetries?: number;
  retryBackoffFactor?: number;
  onRequestStart?: (method: string, url: string) => void;
  onRequestEnd?: (method: string, url: string, statusCode: number, durationMs: number) => void;
  onError?: (error: Error) => void;
}

export interface SubmitActionRequest {
  agent_id: string;
  tool: string;
  operation: string;
  params?: Record<string, any>;
  context?: Record<string, any>;
}

export interface ListActionsOptions {
  limit?: number;
  offset?: number;
  agent_id?: string;
  tool?: string;
  status?: ActionStatus;
}

export interface ApprovalRequest {
  token: string;
  approve: boolean;
  reason?: string;
}

export class FarameshError extends Error {
  constructor(message: string, public statusCode?: number) {
    super(message);
    this.name = "FarameshError";
    Object.setPrototypeOf(this, FarameshError.prototype);
  }
}

export class FarameshAuthError extends FarameshError {
  constructor(message: string) {
    super(message, 401);
    this.name = "FarameshAuthError";
    Object.setPrototypeOf(this, FarameshAuthError.prototype);
  }
}

export class FarameshNotFoundError extends FarameshError {
  constructor(message: string) {
    super(message, 404);
    this.name = "FarameshNotFoundError";
    Object.setPrototypeOf(this, FarameshNotFoundError.prototype);
  }
}

export class FarameshPolicyError extends FarameshError {
  constructor(message: string) {
    super(message);
    this.name = "FarameshPolicyError";
    Object.setPrototypeOf(this, FarameshPolicyError.prototype);
  }
}

export class FarameshTimeoutError extends FarameshError {
  constructor(message: string) {
    super(message);
    this.name = "FarameshTimeoutError";
    Object.setPrototypeOf(this, FarameshTimeoutError.prototype);
  }
}

export class FarameshConnectionError extends FarameshError {
  constructor(message: string) {
    super(message);
    this.name = "FarameshConnectionError";
    Object.setPrototypeOf(this, FarameshConnectionError.prototype);
  }
}

export class FarameshValidationError extends FarameshError {
  constructor(message: string) {
    super(message, 422);
    this.name = "FarameshValidationError";
    Object.setPrototypeOf(this, FarameshValidationError.prototype);
  }
}

export class FarameshServerError extends FarameshError {
  constructor(message: string) {
    super(message, 500);
    this.name = "FarameshServerError";
    Object.setPrototypeOf(this, FarameshServerError.prototype);
  }
}

export class FarameshBatchError extends FarameshError {
  constructor(
    message: string,
    public successes: Action[],
    public errors: Array<{ error: string; index: number; actionSpec: any }>
  ) {
    super(message);
    this.name = "FarameshBatchError";
    Object.setPrototypeOf(this, FarameshBatchError.prototype);
  }
}

export class FarameshDeniedError extends FarameshError {
  constructor(message: string) {
    super(message);
    this.name = "FarameshDeniedError";
    Object.setPrototypeOf(this, FarameshDeniedError.prototype);
  }
}

/** Raised by {@link govern} when the gate denies execution. */
export class DenyError extends FarameshDeniedError {
  constructor(
    message: string,
    public reasonCode: string = "",
    public reasonDetail?: string | null,
    public decision?: GateDecision
  ) {
    super(message);
    this.name = "DenyError";
    Object.setPrototypeOf(this, DenyError.prototype);
  }
}

/** Raised by {@link govern} when the gate defers (human-in-the-loop). */
export class DeferredError extends FarameshError {
  constructor(
    message: string,
    public reasonCode: string = "",
    public reasonDetail?: string | null,
    public decision?: GateDecision
  ) {
    super(message);
    this.name = "DeferredError";
    Object.setPrototypeOf(this, DeferredError.prototype);
  }
}

export interface FarameshEvent {
  event_type?: string;
  type?: string;
  action_id?: string;
  [key: string]: any;
}
