/**
 * Governed tool wrapper for Node.js SDK
 */

import { Action, FaraCoreDeniedError } from "./types";
import { submitAction, blockUntilApproved, waitForCompletion, startAction } from "./client";

export interface GovernedToolConfig {
  agentId: string;
  tool: string;
  operation?: string;
  blockUntilDone?: boolean;
  waitTimeoutMs?: number;
  pollIntervalMs?: number;
}

/**
 * Wrap a function to submit it to FaraCore for governance
 */
export function governedTool<T extends (...args: any[]) => any>(
  config: GovernedToolConfig,
  fn: T
): (...args: Parameters<T>) => Promise<Action> {
  const {
    agentId,
    tool,
    operation,
    blockUntilDone = false,
    waitTimeoutMs = 60000,
    pollIntervalMs = 1000,
  } = config;

  const opName = operation || fn.name;

  return async (...args: Parameters<T>): Promise<Action> => {
    // Submit action with function args/kwargs as params
    const params = {
      args: args.map((a) => String(a)),
      kwargs: {},
    };

    let action = await submitAction(agentId, tool, opName, params);

    if (blockUntilDone) {
      // Wait for approval if needed
      if (action.status === "pending_approval") {
        try {
          action = await blockUntilApproved(action.id, {
            pollIntervalMs,
            timeoutMs: waitTimeoutMs,
          });
        } catch (error) {
          if (error instanceof FaraCoreDeniedError) {
            throw error;
          }
          throw error;
        }
      }

      // Wait for completion
      if (action.status === "allowed" || action.status === "approved") {
        // Start the action if needed
        action = await startAction(action.id);
        // Wait for completion
        action = await waitForCompletion(action.id, pollIntervalMs, waitTimeoutMs);
      } else if (action.status === "executing") {
        // Already executing, just wait
        action = await waitForCompletion(action.id, pollIntervalMs, waitTimeoutMs);
      }
    }

    return action;
  };
}
