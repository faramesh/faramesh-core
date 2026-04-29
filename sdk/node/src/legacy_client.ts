/**
 * Class-based API mirroring Python `ExecutionGovernorClient` for backward compatibility.
 * Prefer module-level functions (`submitAction`, …) in new code.
 */

import type { Action, ClientConfig } from "./types";
import {
  configure,
  submitAction as submitActionApi,
  getAction as getActionApi,
  listActions as listActionsApi,
  approveAction as approveActionApi,
  denyAction as denyActionApi,
  startAction as startActionApi,
  replayAction as replayActionApi,
  waitForCompletion as waitForCompletionApi,
  apply as applyApi,
} from "./client";
import type { ListActionsOptions } from "./types";

function isClientConfigObject(v: unknown): v is ClientConfig {
  return typeof v === "object" && v !== null;
}

function resolveConstructorArgs(
  baseUrlOrConfig?: string | ClientConfig,
  legacyConfig?: ClientConfig
): ClientConfig {
  if (isClientConfigObject(baseUrlOrConfig)) {
    return { ...baseUrlOrConfig };
  }
  if (typeof baseUrlOrConfig === "string") {
    return { baseUrl: baseUrlOrConfig, ...(legacyConfig ?? {}) };
  }
  if (legacyConfig) {
    return { ...legacyConfig };
  }
  return {};
}

function pickAgentId(partial: ClientConfig): string {
  const snake = (partial as { agent_id?: string }).agent_id;
  return (
    partial.agentId ??
    snake ??
    process.env.FARAMESH_AGENT_ID ??
    "default-agent"
  );
}

export class ExecutionGovernorClient {
  readonly agentId: string;
  readonly config: ClientConfig;

  /**
   * @param baseUrlOrConfig Base URL string, a `ClientConfig` object (Python: passing `ClientConfig` as first arg), or omit to use current global config / env defaults.
   * @param legacyConfig Optional config when the first argument is a base URL string.
   */
  constructor(baseUrlOrConfig?: string | ClientConfig, legacyConfig?: ClientConfig) {
    const partial = resolveConstructorArgs(baseUrlOrConfig, legacyConfig);
    const agentId = pickAgentId(partial);
    configure({ ...partial, agentId });
    this.agentId = agentId;
    this.config = { ...partial, agentId };
  }

  submitAction(
    tool: string,
    operation: string,
    params: Record<string, any> = {},
    context: Record<string, any> = {}
  ): Promise<Action> {
    return submitActionApi(this.agentId, tool, operation, params, context);
  }

  getAction(actionId: string): Promise<Action> {
    return getActionApi(actionId);
  }

  listActions(options: ListActionsOptions = {}): Promise<Action[]> {
    return listActionsApi(options);
  }

  approveAction(actionId: string, token?: string, reason?: string): Promise<Action> {
    return approveActionApi(actionId, token, reason);
  }

  denyAction(actionId: string, token?: string, reason?: string): Promise<Action> {
    return denyActionApi(actionId, token, reason);
  }

  startAction(actionId: string): Promise<Action> {
    return startActionApi(actionId);
  }

  replayAction(actionId: string): Promise<Action> {
    return replayActionApi(actionId);
  }

  waitForCompletion(
    actionId: string,
    pollInterval: number = 1000,
    timeout: number = 60000
  ): Promise<Action> {
    return waitForCompletionApi(actionId, pollInterval, timeout);
  }

  apply(filePath: string): Promise<Action> {
    return applyApi(filePath);
  }
}

/** @deprecated Use {@link ClientConfig} — Python compatibility alias (`GovernorConfig`). */
export type GovernorConfig = ClientConfig;
