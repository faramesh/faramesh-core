/**
 * Strict gate helper: returns only on allow; throws DenyError / DeferredError otherwise.
 * Also provides a simplified `govern()` for the autopatcher that uses
 * Unix domain socket or HTTP fallback.
 */

import { gateDecide } from "./client";
import { DeferredError, DenyError, GateDecision } from "./types";
import { detectTransport, evaluateRemote, governViaSocket } from "./transport";

export interface GovernResult {
  effect: "PERMIT" | "DENY" | "DEFER";
  reasonCode?: string;
  deferToken?: string;
}

export interface GovernRequest {
  toolId: string;
  args: Record<string, any>;
  agentId?: string;
}

/**
 * Call gate/decide and return only when execution would be allowed.
 *
 * - **EXECUTE** / **PERMIT**: returns decision.
 * - **HALT** / **DENY**: throws {@link DenyError}.
 * - **ABSTAIN** / **DEFER** / **PENDING**: throws {@link DeferredError}.
 */
export async function gateGovern(
  agentId: string,
  tool: string,
  operation: string,
  params: Record<string, any> = {},
  context: Record<string, any> = {}
): Promise<GateDecision> {
  const d = await gateDecide(agentId, tool, operation, params, context);
  const o = (d.outcome || "").toUpperCase();
  if (o === "EXECUTE" || o === "PERMIT") {
    return d;
  }
  if (o === "HALT" || o === "DENY") {
    throw new DenyError(
      `governance denied: ${d.reason_code || "unknown"}`,
      d.reason_code || "",
      d.reason ?? undefined,
      d
    );
  }
  if (o === "ABSTAIN" || o === "DEFER" || o === "PENDING") {
    throw new DeferredError(
      `governance deferred: ${d.reason_code || "unknown"}`,
      d.reason_code || "",
      d.reason ?? undefined,
      d
    );
  }
  throw new Error(`unexpected gate outcome: ${d.outcome}`);
}

/**
 * Simplified governance call used by the autopatcher.
 * Tries Unix socket first, falls back to HTTP.
 */
export async function govern(req: GovernRequest): Promise<GovernResult> {
  const agentId = req.agentId || process.env.FARAMESH_AGENT_ID || "auto-patched";

  const parts = req.toolId.split("/");
  const tool = parts.length > 1 ? parts.slice(0, -1).join("/") : req.toolId;
  const operation = parts.length > 1 ? parts[parts.length - 1] : "invoke";
  const toolId = parts.length > 1 ? `${tool}/${operation}` : req.toolId;

  try {
    const transport = detectTransport();
    if (transport.mode === "remote" && transport.remoteURL) {
      const r = await evaluateRemote(transport, agentId, toolId, req.args);
      return mapTransportEffect(r);
    }
    if (transport.socketPath) {
      return await mapTransportEffect(
        await governViaSocket(transport.socketPath, agentId, tool, operation, req.args)
      );
    }
  } catch {
    // Fall through to legacy gate HTTP client.
  }

  try {
    const d = await gateDecide(agentId, tool, operation, req.args);
    const o = (d.outcome || "").toUpperCase();
    if (o === "EXECUTE" || o === "PERMIT") return { effect: "PERMIT" };
    if (o === "HALT" || o === "DENY")
      return { effect: "DENY", reasonCode: d.reason_code };
    if (o === "ABSTAIN" || o === "DEFER" || o === "PENDING")
      return { effect: "DEFER", deferToken: d.provenance_id || "" };
    return { effect: "PERMIT" };
  } catch (err: any) {
    if (err instanceof DenyError) return { effect: "DENY", reasonCode: err.reasonCode };
    if (err instanceof DeferredError) return { effect: "DEFER" };
    throw err;
  }
}

function mapTransportEffect(r: {
  effect: string;
  reason_code?: string;
  defer_token?: string;
}): GovernResult {
  const o = (r.effect || "").toUpperCase();
  if (o === "PERMIT" || o === "EXECUTE") return { effect: "PERMIT" };
  if (o === "DENY" || o === "HALT")
    return { effect: "DENY", reasonCode: r.reason_code || "" };
  if (o === "DEFER" || o === "ABSTAIN" || o === "PENDING")
    return { effect: "DEFER", deferToken: r.defer_token || "" };
  return { effect: "PERMIT" };
}
