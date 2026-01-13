/**
 * TypeScript type definitions for FaraCore SDK
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

export class FaraCoreError extends Error {
  constructor(message: string, public statusCode?: number) {
    super(message);
    this.name = "FaraCoreError";
    Object.setPrototypeOf(this, FaraCoreError.prototype);
  }
}

export class FaraCoreAuthError extends FaraCoreError {
  constructor(message: string) {
    super(message, 401);
    this.name = "FaraCoreAuthError";
    Object.setPrototypeOf(this, FaraCoreAuthError.prototype);
  }
}

export class FaraCoreNotFoundError extends FaraCoreError {
  constructor(message: string) {
    super(message, 404);
    this.name = "FaraCoreNotFoundError";
    Object.setPrototypeOf(this, FaraCoreNotFoundError.prototype);
  }
}

export class FaraCorePolicyError extends FaraCoreError {
  constructor(message: string) {
    super(message);
    this.name = "FaraCorePolicyError";
    Object.setPrototypeOf(this, FaraCorePolicyError.prototype);
  }
}

export class FaraCoreTimeoutError extends FaraCoreError {
  constructor(message: string) {
    super(message);
    this.name = "FaraCoreTimeoutError";
    Object.setPrototypeOf(this, FaraCoreTimeoutError.prototype);
  }
}

export class FaraCoreConnectionError extends FaraCoreError {
  constructor(message: string) {
    super(message);
    this.name = "FaraCoreConnectionError";
    Object.setPrototypeOf(this, FaraCoreConnectionError.prototype);
  }
}

export class FaraCoreValidationError extends FaraCoreError {
  constructor(message: string) {
    super(message, 422);
    this.name = "FaraCoreValidationError";
    Object.setPrototypeOf(this, FaraCoreValidationError.prototype);
  }
}

export class FaraCoreServerError extends FaraCoreError {
  constructor(message: string) {
    super(message, 500);
    this.name = "FaraCoreServerError";
    Object.setPrototypeOf(this, FaraCoreServerError.prototype);
  }
}

export class FaraCoreBatchError extends FaraCoreError {
  constructor(
    message: string,
    public successes: Action[],
    public errors: Array<{ error: string; index: number; actionSpec: any }>
  ) {
    super(message);
    this.name = "FaraCoreBatchError";
    Object.setPrototypeOf(this, FaraCoreBatchError.prototype);
  }
}

export class FaraCoreDeniedError extends FaraCoreError {
  constructor(message: string) {
    super(message);
    this.name = "FaraCoreDeniedError";
    Object.setPrototypeOf(this, FaraCoreDeniedError.prototype);
  }
}

export interface FaracoreEvent {
  event_type?: string;
  type?: string;
  action_id?: string;
  [key: string]: any;
}
