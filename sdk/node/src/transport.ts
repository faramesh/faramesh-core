/**
 * Governance transport: Unix socket (local daemon) or HTTPS /v1/evaluate.
 */

import * as fs from "fs";
import * as net from "net";

export interface Transport {
  mode: "socket" | "remote";
  socketPath?: string;
  remoteURL?: string;
  token?: string;
}

export function detectTransport(): Transport {
  const remote = (process.env.FARAMESH_REMOTE_URL || "").trim().replace(/\/$/, "");
  if (remote) {
    return {
      mode: "remote",
      remoteURL: remote,
      token: (process.env.FARAMESH_TOKEN || "").trim(),
    };
  }
  const socketPath = (process.env.FARAMESH_SOCKET || "/tmp/faramesh.sock").trim();
  try {
    fs.accessSync(socketPath, fs.constants.F_OK);
    return { mode: "socket", socketPath };
  } catch {
    const base = (process.env.FARAMESH_BASE_URL || "").trim().replace(/\/$/, "");
    if (base) {
      return {
        mode: "remote",
        remoteURL: base,
        token: (process.env.FARAMESH_TOKEN || "").trim(),
      };
    }
    throw new Error(
      `no governance transport: set FARAMESH_SOCKET (${socketPath} missing) or FARAMESH_REMOTE_URL`
    );
  }
}

export async function evaluateRemote(
  transport: Transport,
  agentId: string,
  toolId: string,
  args: Record<string, unknown>,
  actionType = "tool_call"
): Promise<{ effect: string; reason_code?: string; defer_token?: string }> {
  if (!transport.remoteURL) {
    throw new Error("remote transport not configured");
  }
  const res = await fetch(`${transport.remoteURL}/v1/evaluate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(transport.token ? { Authorization: `Bearer ${transport.token}` } : {}),
    },
    body: JSON.stringify({
      agent_id: agentId,
      tool_id: toolId,
      action_type: actionType,
      args,
    }),
  });
  if (!res.ok) {
    throw new Error(`remote evaluate: HTTP ${res.status}`);
  }
  const decision = (await res.json()) as Record<string, string>;
  const effect = String(decision.effect || decision.outcome || "").toUpperCase();
  return {
    effect,
    reason_code: decision.reason_code,
    defer_token: decision.defer_token || decision.provenance_id,
  };
}

export function governViaSocket(
  socketPath: string,
  agentId: string,
  tool: string,
  operation: string,
  args: Record<string, unknown>,
  actionType = "tool_call"
): Promise<{ effect: string; reason_code?: string; defer_token?: string }> {
  const payload = {
    jsonrpc: "2.0",
    id: 1,
    method: "govern",
    params: {
      agent_id: agentId,
      tool,
      operation,
      args,
      action_type: actionType,
      principal_token: process.env.FARAMESH_PRINCIPAL_TOKEN || "",
    },
  };
  return new Promise((resolve, reject) => {
    const conn = net.createConnection(socketPath, () => {
      conn.write(JSON.stringify(payload) + "\n");
    });
    let buf = "";
    conn.on("data", (chunk) => {
      buf += chunk.toString();
    });
    conn.on("end", () => {
      try {
        const resp = JSON.parse(buf) as {
          result?: { effect?: string; reason_code?: string; defer_token?: string };
          error?: { message?: string };
        };
        if (resp.error) {
          reject(new Error(`socket govern: ${resp.error.message || "unknown"}`));
          return;
        }
        const result = resp.result || {};
        resolve({
          effect: String(result.effect || "").toUpperCase(),
          reason_code: result.reason_code,
          defer_token: result.defer_token,
        });
      } catch (err) {
        reject(err);
      }
    });
    conn.on("error", reject);
    conn.setTimeout(30_000, () => {
      conn.destroy();
      reject(new Error("socket govern timeout"));
    });
  });
}
