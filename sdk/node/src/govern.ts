/**
 * Strict gate helper: returns only on allow; throws DenyError / DeferredError otherwise.
 * Also provides a simplified `govern()` for the autopatcher that uses
 * Unix domain socket or HTTP fallback.
 */

import { gateDecide } from "./client";
import { DeferredError, DenyError, GateDecision } from "./types";
import * as net from "net";
import * as path from "path";

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
  const socketPath = process.env.FARAMESH_SOCKET || "/tmp/faramesh.sock";
  const agentId = req.agentId || process.env.FARAMESH_AGENT_ID || "auto-patched";

  const parts = req.toolId.split("/");
  const tool = parts.length > 1 ? parts.slice(0, -1).join("/") : req.toolId;
  const operation = parts.length > 1 ? parts[parts.length - 1] : "invoke";

  try {
    const stat = await new Promise<boolean>((resolve) => {
      const fs = require("fs");
      fs.access(socketPath, fs.constants.F_OK, (err: any) => resolve(!err));
    });

    if (stat) {
      return await governViaSocket(socketPath, agentId, tool, operation, req.args);
    }
  } catch {
    // Socket not available, fall through to HTTP.
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

function governViaSocket(
  socketPath: string,
  agentId: string,
  tool: string,
  operation: string,
  args: Record<string, any>
): Promise<GovernResult> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "govern",
      params: { agent_id: agentId, tool, operation, args },
    }) + "\n";

    const client = net.createConnection({ path: socketPath }, () => {
      client.write(payload);
    });

    let data = "";
    client.on("data", (chunk) => {
      data += chunk.toString();
      if (data.includes("\n")) {
        client.end();
      }
    });

    client.on("end", () => {
      try {
        const resp = JSON.parse(data.trim());
        const result = resp.result || {};
        const effect = (result.effect || "PERMIT").toUpperCase() as GovernResult["effect"];
        resolve({
          effect,
          reasonCode: result.reason_code || "",
          deferToken: result.defer_token || "",
        });
      } catch (err) {
        reject(new Error(`Failed to parse governance response: ${err}`));
      }
    });

    client.on("error", (err) => {
      reject(new Error(`Faramesh socket error: ${err.message}`));
    });

    client.setTimeout(5000, () => {
      client.destroy();
      reject(new Error("Faramesh socket timeout"));
    });
  });
}
