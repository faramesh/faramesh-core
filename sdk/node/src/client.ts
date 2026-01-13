/**
 * FaraCore Node.js SDK - Production-ready client
 * 
 * Provides a complete interface to interact with FaraCore, including:
 * - Submitting actions for governance evaluation
 * - Approving/denying pending actions
 * - Starting action execution
 * - Replaying actions
 * - Listing and querying action history
 * - Loading actions from YAML/JSON files
 */

import axios, { AxiosInstance, AxiosError } from "axios";
import * as fs from "fs";
import * as path from "path";
import {
  Action,
  ClientConfig,
  SubmitActionRequest,
  ListActionsOptions,
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

export const __version__ = "0.2.0";

// Global configuration
let globalConfig: ClientConfig | null = null;

/**
 * Configure the global SDK client
 */
export function configure(options: ClientConfig = {}): void {
  const existingConfig = globalConfig;
  globalConfig = {
    baseUrl: options.baseUrl || process.env.FARACORE_BASE_URL || process.env.FARA_API_BASE || "http://127.0.0.1:8000",
    token: options.token || process.env.FARACORE_TOKEN || process.env.FARA_AUTH_TOKEN,
    timeoutMs: options.timeoutMs || 30000,
    maxRetries: options.maxRetries || parseInt(process.env.FARACORE_RETRIES || "3", 10),
    retryBackoffFactor: options.retryBackoffFactor || parseFloat(process.env.FARACORE_RETRY_BACKOFF || "0.5"),
    onRequestStart: options.onRequestStart || existingConfig?.onRequestStart,
    onRequestEnd: options.onRequestEnd || existingConfig?.onRequestEnd,
    onError: options.onError || existingConfig?.onError,
  };
}

function getConfig(): ClientConfig {
  if (!globalConfig) {
    configure();
  }
  return globalConfig!;
}

function createAxiosInstance(config: ClientConfig): AxiosInstance {
  const instance = axios.create({
    baseURL: config.baseUrl!.replace(/\/$/, ""),
    timeout: config.timeoutMs,
    headers: {
      "Content-Type": "application/json",
      ...(config.token ? { Authorization: `Bearer ${config.token}` } : {}),
    },
  });

  return instance;
}

async function makeRequest<T>(
  method: "GET" | "POST" | "PUT" | "DELETE",
  path: string,
  data?: any,
  params?: Record<string, any>
): Promise<T> {
  const config = getConfig();
  const client = createAxiosInstance(config);
  const url = path.startsWith("/") ? path : `/${path}`;
  const fullUrl = `${config.baseUrl}${url}`;

  // Call telemetry callback
  if (config.onRequestStart) {
    try {
      config.onRequestStart(method, fullUrl);
    } catch (e) {
      // Don't fail on callback errors
    }
  }

  const startTime = Date.now();
  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= config.maxRetries!; attempt++) {
    try {
      const response = await client.request<T>({
        method,
        url,
        data,
        params,
      });

      const durationMs = Date.now() - startTime;
      const responseData = response.data as any;

      // Check for policy denial (only for submit_action)
      if (
        method === "POST" &&
        path === "/v1/actions" &&
        responseData &&
        typeof responseData === "object"
      ) {
        if (responseData.status === "denied") {
          const error = new FaraCorePolicyError(
            responseData.reason || "Action denied by policy"
          );
          if (config.onError) {
            try {
              config.onError(error);
            } catch (e) {}
          }
          if (config.onRequestEnd) {
            try {
              config.onRequestEnd(method, fullUrl, response.status, durationMs);
            } catch (e) {}
          }
          throw error;
        }
        if (
          responseData.decision === "deny" &&
          responseData.status !== "pending_approval"
        ) {
          const error = new FaraCorePolicyError(
            responseData.reason || "Action denied by policy"
          );
          if (config.onError) {
            try {
              config.onError(error);
            } catch (e) {}
          }
          if (config.onRequestEnd) {
            try {
              config.onRequestEnd(method, fullUrl, response.status, durationMs);
            } catch (e) {}
          }
          throw error;
        }
      }

      // Call success telemetry callback
      if (config.onRequestEnd) {
        try {
          config.onRequestEnd(method, fullUrl, response.status, durationMs);
        } catch (e) {}
      }

      return responseData;
    } catch (error) {
      const durationMs = Date.now() - startTime;
      
      if (axios.isAxiosError(error)) {
        const axiosError = error as AxiosError;

        // Handle specific status codes
        if (axiosError.response?.status === 401) {
          const err = new FaraCoreAuthError(
            `Authentication failed (401) on ${path}: ${axiosError.response.data || axiosError.message}`
          );
          if (config.onError) {
            try {
              config.onError(err);
            } catch (e) {}
          }
          if (config.onRequestEnd) {
            try {
              config.onRequestEnd(method, fullUrl, 401, durationMs);
            } catch (e) {}
          }
          throw err;
        }
        if (axiosError.response?.status === 404) {
          const err = new FaraCoreNotFoundError(`Resource not found (404) on ${path}`);
          if (config.onError) {
            try {
              config.onError(err);
            } catch (e) {}
          }
          if (config.onRequestEnd) {
            try {
              config.onRequestEnd(method, fullUrl, 404, durationMs);
            } catch (e) {}
          }
          throw err;
        }
        if (axiosError.response?.status === 422) {
          const detail =
            (axiosError.response.data as any)?.detail || axiosError.response.data || axiosError.message;
          const err = new FaraCoreValidationError(`Validation error (422) on ${path}: ${detail}`);
          if (config.onError) {
            try {
              config.onError(err);
            } catch (e) {}
          }
          if (config.onRequestEnd) {
            try {
              config.onRequestEnd(method, fullUrl, 422, durationMs);
            } catch (e) {}
          }
          throw err;
        }

        // Retry on 5xx errors
        if (
          attempt < config.maxRetries! &&
          axiosError.response?.status &&
          axiosError.response.status >= 500
        ) {
          const err = new FaraCoreServerError(
            `Server error (${axiosError.response.status}) on ${path}: ${axiosError.message}`
          );
          if (config.onError) {
            try {
              config.onError(err);
            } catch (e) {}
          }
          const waitTime =
            config.retryBackoffFactor! * Math.pow(2, attempt) * 1000;
          await new Promise((resolve) => setTimeout(resolve, waitTime));
          lastError = error;
          continue;
        }

        // Handle timeout
        if (error.code === "ECONNABORTED" || error.message.includes("timeout")) {
          const err = new FaraCoreTimeoutError(
            `Request timed out after ${config.timeoutMs}ms: ${fullUrl}`
          );
          if (config.onError) {
            try {
              config.onError(err);
            } catch (e) {}
          }
          if (config.onRequestEnd) {
            try {
              config.onRequestEnd(method, fullUrl, 0, durationMs);
            } catch (e) {}
          }
          throw err;
        }

        // Handle connection errors
        if (
          error.code === "ECONNREFUSED" ||
          error.code === "ENOTFOUND" ||
          error.code === "ETIMEDOUT"
        ) {
          const err = new FaraCoreConnectionError(
            `Failed to connect to ${config.baseUrl}: ${error.message}`
          );
        }

        // Other HTTP errors
        const status = axiosError.response?.status || 0;
        const message =
          (axiosError.response?.data as any)?.detail ||
          axiosError.response?.data ||
          axiosError.message;
        throw new FaraCoreError(`Request failed: ${message}`, status);
      }

      // Re-throw known errors
      if (
        error instanceof FaraCoreAuthError ||
        error instanceof FaraCoreNotFoundError ||
        error instanceof FaraCorePolicyError ||
        error instanceof FaraCoreValidationError ||
        error instanceof FaraCoreTimeoutError ||
        error instanceof FaraCoreConnectionError
      ) {
        throw error;
      }

      lastError = error as Error;
      if (attempt < config.maxRetries!) {
        const waitTime =
          config.retryBackoffFactor! * Math.pow(2, attempt) * 1000;
        await new Promise((resolve) => setTimeout(resolve, waitTime));
        continue;
      }
    }
  }

  if (lastError) {
    throw new FaraCoreError(
      `Request failed after ${config.maxRetries! + 1} attempts: ${lastError.message}`
    );
  }

  const durationMs = Date.now() - startTime;
  const err = new FaraCoreError(`Request failed after ${config.maxRetries! + 1} attempts on ${path}`);
  if (config.onError) {
    try {
      config.onError(err);
    } catch (e) {}
  }
  if (config.onRequestEnd) {
    try {
      config.onRequestEnd(method, fullUrl, 0, durationMs);
    } catch (e) {}
  }
  throw err;
}

/**
 * Submit an action for governance evaluation
 */
export async function submitAction(
  agentId: string,
  tool: string,
  operation: string,
  params: Record<string, any> = {},
  context: Record<string, any> = {}
): Promise<Action> {
  const payload: SubmitActionRequest = {
    agent_id: agentId,
    tool,
    operation,
    params,
    context,
  };
  return makeRequest<Action>("POST", "/v1/actions", payload);
}

/**
 * Get an action by ID
 */
export async function getAction(actionId: string): Promise<Action> {
  return makeRequest<Action>("GET", `/v1/actions/${actionId}`);
}

/**
 * List actions with optional filters
 */
export async function listActions(
  options: ListActionsOptions = {}
): Promise<Action[]> {
  const params: Record<string, any> = {
    limit: options.limit || 20,
    offset: options.offset || 0,
  };
  if (options.agent_id) params.agent_id = options.agent_id;
  if (options.tool) params.tool = options.tool;
  if (options.status) params.status = options.status;

  const response = await makeRequest<Action[] | { actions: Action[] }>(
    "GET",
    "/v1/actions",
    undefined,
    params
  );

  if (Array.isArray(response)) {
    return response;
  }
  return (response as any).actions || [];
}

/**
 * Approve a pending action
 */
export async function approveAction(
  actionId: string,
  token?: string,
  reason?: string
): Promise<Action> {
  if (!token) {
    // Try to get the action first to extract token
    const action = await getAction(actionId);
    if (action.status !== "pending_approval") {
      throw new FaraCoreError(
        `Action ${actionId} is not pending approval (status: ${action.status})`
      );
    }
    if (!action.approval_token) {
      throw new FaraCoreError(
        `Approval token not found for action ${actionId}`
      );
    }
    token = action.approval_token;
  }

  const payload = {
    token,
    approve: true,
    ...(reason ? { reason } : {}),
  };

  return makeRequest<Action>("POST", `/v1/actions/${actionId}/approval`, payload);
}

/**
 * Deny a pending action
 */
export async function denyAction(
  actionId: string,
  token?: string,
  reason?: string
): Promise<Action> {
  if (!token) {
    // Try to get the action first to extract token
    const action = await getAction(actionId);
    if (action.status !== "pending_approval") {
      throw new FaraCoreError(
        `Action ${actionId} is not pending approval (status: ${action.status})`
      );
    }
    if (!action.approval_token) {
      throw new FaraCoreError(
        `Approval token not found for action ${actionId}`
      );
    }
    token = action.approval_token;
  }

  const payload = {
    token,
    approve: false,
    ...(reason ? { reason } : {}),
  };

  return makeRequest<Action>("POST", `/v1/actions/${actionId}/approval`, payload);
}

/**
 * Start execution of an approved or allowed action
 */
export async function startAction(actionId: string): Promise<Action> {
  return makeRequest<Action>("POST", `/v1/actions/${actionId}/start`);
}

/**
 * Replay an action by creating a new action with the same parameters
 */
export async function replayAction(actionId: string): Promise<Action> {
  // Get original action
  const original = await getAction(actionId);

  const status = original.status;
  if (!["allowed", "approved", "succeeded"].includes(status)) {
    throw new FaraCoreError(
      `Cannot replay action ${actionId} with status '${status}'. ` +
        "Only allowed, approved, or succeeded actions can be replayed."
    );
  }

  // Create new action with same payload
  const context = original.context || {};
  const newContext = {
    ...context,
    replayed_from: actionId,
    replay: true,
  };

  return submitAction(
    original.agent_id,
    original.tool,
    original.operation,
    original.params || {},
    newContext
  );
}

/**
 * Wait for an action to complete (succeeded or failed)
 */
export async function waitForCompletion(
  actionId: string,
  pollInterval: number = 1000,
  timeout: number = 60000
): Promise<Action> {
  const startTime = Date.now();

  while (true) {
    const action = await getAction(actionId);
    const status = action.status;

    if (["succeeded", "failed", "denied"].includes(status)) {
      return action;
    }

    if (Date.now() - startTime > timeout) {
      throw new FaraCoreTimeoutError(
        `Action ${actionId} did not complete within ${timeout}ms. ` +
          `Current status: ${status}`
      );
    }

    await new Promise((resolve) => setTimeout(resolve, pollInterval));
  }
}

/**
 * Submit multiple actions in batch
 */
export async function submitActions(
  actions: Array<{
    agent_id: string;
    tool: string;
    operation: string;
    params?: Record<string, any>;
    context?: Record<string, any>;
  }>
): Promise<Array<Action | { error: string; action_spec: any }>> {
  const results: Array<Action | { error: string; action_spec: any }> = [];
  
  for (const actionSpec of actions) {
    try {
      const result = await submitAction(
        actionSpec.agent_id,
        actionSpec.tool,
        actionSpec.operation,
        actionSpec.params || {},
        actionSpec.context || {}
      );
      results.push(result);
    } catch (error) {
      results.push({
        error: error instanceof Error ? error.message : String(error),
        action_spec: actionSpec,
      });
    }
  }
  
  return results;
}

// Old submitAndWait removed - replaced by enhanced version below

/**
 * Stream events via Server-Sent Events (SSE)
 */
export async function tailEvents(
  callback?: (event: any) => void,
  actionId?: string
): Promise<void> {
  const config = getConfig();
  const url = `${config.baseUrl}/v1/events`;

  // Try to use EventSource (browser) or eventsource package (Node)
  let EventSourceClass: any;
  
  // Check if we're in a browser environment
  const isBrowser = typeof globalThis !== "undefined" && 
                    typeof (globalThis as any).window !== "undefined";
  
  if (isBrowser && (globalThis as any).window.EventSource) {
    EventSourceClass = (globalThis as any).window.EventSource;
  } else {
    try {
      EventSourceClass = require("eventsource");
    } catch {
      throw new FaraCoreError(
        "SSE support requires 'eventsource' package. Install with: npm install eventsource"
      );
    }
  }

  return new Promise<void>((resolve, reject) => {
    const headers: Record<string, string> = {};
    if (config.token) {
      headers["Authorization"] = `Bearer ${config.token}`;
    }

    const eventSource = new EventSourceClass(url, { headers });

    const defaultCallback = (event: any) => {
      console.log(`Event: ${event.event_type || "unknown"} - ${event.action_id || "N/A"}`);
    };
    const cb = callback || defaultCallback;

    eventSource.onmessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data);
        // Filter by action_id if specified
        if (actionId && data.action_id !== actionId) {
          return;
        }
        cb(data);
      } catch (error) {
        // Ignore parse errors
      }
    };

    eventSource.onerror = (error: any) => {
      eventSource.close();
      reject(
        new FaraCoreConnectionError(
          `Failed to connect to SSE stream: ${error.message || "Unknown error"}`
        )
      );
    };

    eventSource.onopen = () => {
      // Connection established, but don't resolve - keep streaming
    };

    // Note: This Promise never resolves by design - it streams indefinitely
    // To stop, call eventSource.close() from outside or handle process signals
  });
}

/**
 * Load an action from a YAML or JSON file and submit it
 */
export async function apply(filePath: string): Promise<Action> {
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  let data: any;
  const ext = path.extname(filePath).toLowerCase();

  try {
    const content = fs.readFileSync(filePath, "utf-8");
    if (ext === ".json") {
      data = JSON.parse(content);
    } else if (ext === ".yaml" || ext === ".yml") {
      // Try to load yaml if available
      try {
        const yaml = require("yaml");
        data = yaml.parse(content);
      } catch (e) {
        throw new FaraCoreValidationError(
          "YAML support requires 'yaml' package. Install with: npm install yaml"
        );
      }
    } else {
      // Try JSON first, then YAML
      try {
        data = JSON.parse(content);
      } catch {
        try {
          const yaml = require("yaml");
          data = yaml.parse(content);
        } catch (e) {
          throw new FaraCoreValidationError(
            `Failed to parse file ${filePath}: ${e}`
          );
        }
      }
    }
  } catch (error) {
    if (error instanceof FaraCoreValidationError) {
      throw error;
    }
    throw new FaraCoreValidationError(
      `Failed to parse file ${filePath}: ${error}`
    );
  }

  // Validate required fields
  const required = ["agent_id", "tool", "operation"];
  const missing = required.filter((f) => !(f in data));
  if (missing.length > 0) {
    throw new FaraCoreValidationError(
      `Missing required fields: ${missing.join(", ")}`
    );
  }

  // Submit action
  return submitAction(
    data.agent_id,
    data.tool,
    data.operation,
    data.params || {},
    data.context || {}
  );
}

/**
 * Submit multiple actions in batch with error handling control
 */
export async function submitActionsBulk(
  actions: SubmitActionRequest[],
  options?: { raiseOnError?: boolean }
): Promise<(Action | { error: string; index: number })[]> {
  const raiseOnError = options?.raiseOnError || false;
  const successes: Action[] = [];
  const errors: Array<{ error: string; index: number; actionSpec: any }> = [];

  for (let i = 0; i < actions.length; i++) {
    const actionSpec = actions[i];
    try {
      const result = await submitAction(
        actionSpec.agent_id,
        actionSpec.tool,
        actionSpec.operation,
        actionSpec.params || {},
        actionSpec.context || {}
      );
      successes.push(result);
      if (!raiseOnError) {
        // In non-raise mode, include successes in return array
      }
    } catch (error: any) {
      const errorEntry = {
        error: error.message || String(error),
        index: i,
        actionSpec,
      };
      errors.push(errorEntry);
      if (!raiseOnError) {
        successes.push(errorEntry as any);
      }
    }
  }

  if (raiseOnError && errors.length > 0) {
    throw new FaraCoreBatchError(
      `Batch submission failed: ${errors.length} of ${actions.length} actions failed`,
      successes,
      errors
    );
  }

  return successes;
}

/**
 * Block until an action is approved or denied
 */
export async function blockUntilApproved(
  actionId: string,
  options?: { pollIntervalMs?: number; timeoutMs?: number }
): Promise<Action> {
  const pollIntervalMs = options?.pollIntervalMs || 2000;
  const timeoutMs = options?.timeoutMs || 300000;
  const startTime = Date.now();

  while (true) {
    const elapsed = Date.now() - startTime;
    if (elapsed > timeoutMs) {
      throw new FaraCoreTimeoutError(`Timeout waiting for approval after ${timeoutMs}ms`);
    }

    const action = await getAction(actionId);
    const status = action.status;

    if (status === "approved") {
      return action;
    } else if (status === "denied") {
      const reason = action.reason || "Action denied";
      throw new FaraCoreDeniedError(`Action denied: ${reason}`);
    } else if (status === "allowed" || status === "succeeded" || status === "failed") {
      // Already processed, return as-is
      return action;
    }

    // Still pending, wait and poll again
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }
}

/**
 * Enhanced submit and wait with approval handling
 */
export async function submitAndWait(
  config: {
    agentId: string;
    tool: string;
    operation: string;
    params?: any;
    requireApproval?: boolean;
    autoStart?: boolean;
    timeoutMs?: number;
    pollIntervalMs?: number;
  }
): Promise<Action> {
  const {
    agentId,
    tool,
    operation,
    params = {},
    requireApproval = false,
    autoStart = false,
    timeoutMs = 300000,
    pollIntervalMs = 1000,
  } = config;

  // Submit action
  let action = await submitAction(agentId, tool, operation, params);
  let status = action.status;

  // If denied, raise immediately
  if (status === "denied") {
    const reason = action.reason || "Action denied by policy";
    throw new FaraCoreDeniedError(`Action denied: ${reason}`);
  }

  // If pending approval
  if (status === "pending_approval") {
    if (requireApproval) {
      // Wait for approval
      action = await blockUntilApproved(action.id, {
        pollIntervalMs,
        timeoutMs,
      });
      status = action.status;
    } else {
      // Return immediately if not requiring approval
      return action;
    }
  }

  // If allowed and autoStart, start and wait
  if (status === "allowed" && autoStart) {
      action = await startAction(action.id);
    return waitForCompletion(action.id, pollIntervalMs, timeoutMs);
  }

  // If already approved and autoStart, start and wait
  if (status === "approved" && autoStart) {
    action = await startAction(action.id);
    return waitForCompletion(action.id, pollIntervalMs, timeoutMs);
  }

  // Otherwise return as-is
  return action;
}

/**
 * Stream events via Server-Sent Events with advanced options
 */
export function onEvents(
  handler: (event: FaracoreEvent) => void,
  options?: { eventTypes?: string[]; signal?: AbortSignal; actionId?: string }
): () => void {
  const config = getConfig();
  const url = `${config.baseUrl}/v1/events`;

  // Try to use EventSource (browser) or eventsource package (Node)
  let EventSourceClass: any;

  const isBrowser =
    typeof globalThis !== "undefined" &&
    typeof (globalThis as any).window !== "undefined";

  if (isBrowser && (globalThis as any).window.EventSource) {
    EventSourceClass = (globalThis as any).window.EventSource;
  } else {
    try {
      EventSourceClass = require("eventsource");
    } catch {
      throw new FaraCoreError(
        "SSE support requires 'eventsource' package. Install with: npm install eventsource"
      );
    }
  }

  const headers: Record<string, string> = {};
  if (config.token) {
    headers["Authorization"] = `Bearer ${config.token}`;
  }

  const eventSource = new EventSourceClass(url, { headers });

  eventSource.onmessage = (event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data) as FaracoreEvent;

      // Filter by action_id if specified
      if (options?.actionId && data.action_id !== options.actionId) {
        return;
      }

      // Filter by event_types if specified
      if (options?.eventTypes) {
        const eventType = data.event_type || data.type;
        if (!eventType || !options.eventTypes.includes(eventType)) {
          return;
        }
      }

      handler(data);
    } catch (error) {
      // Ignore parse errors
    }
  };

  eventSource.onerror = (error: any) => {
    eventSource.close();
    if (config.onError) {
      try {
        config.onError(new FaraCoreConnectionError(`SSE stream error: ${error.message || "Unknown error"}`));
      } catch (e) {}
    }
  };

  // Handle AbortSignal if provided
  if (options?.signal) {
    options.signal.addEventListener("abort", () => {
      eventSource.close();
    });
  }

  // Return close function
  return () => {
    eventSource.close();
  };
}

// Convenience aliases
export const allow = approveAction;
export const deny = denyAction;
