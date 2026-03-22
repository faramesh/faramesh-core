/**
 * Faramesh Auto-Patcher for Node.js / MCP tool servers.
 *
 * When FARAMESH_AUTOLOAD=1 is set (by `faramesh run`), this module patches
 * the MCP Server's tool call handler so every tool invocation flows through
 * Faramesh governance.
 *
 * Usage:
 *   // Automatic (via NODE_OPTIONS, set by faramesh run):
 *   NODE_OPTIONS="--require @faramesh/sdk/autopatch" node server.js
 *
 *   // Manual:
 *   import { installAutoPatch } from '@faramesh/sdk/autopatch';
 *   installAutoPatch(server);
 */

import { govern, GovernResult } from './govern';

let installed = false;
const patchedServers = new WeakSet<object>();

/**
 * Patch an MCP Server instance so all tool calls are governed.
 */
export function installAutoPatch(server: any): boolean {
  if (patchedServers.has(server)) return false;

  const origSetRequestHandler = server.setRequestHandler?.bind(server);
  if (!origSetRequestHandler) return false;

  server.setRequestHandler = function (schema: any, handler: Function) {
    const methodName = schema?.method || schema?.name || '';
    if (methodName === 'tools/call') {
      const wrappedHandler = async (request: any, extra: any) => {
        const toolName = request?.params?.name || 'unknown';
        const toolArgs = request?.params?.arguments || {};

        try {
          const result: GovernResult = await govern({
            toolId: toolName,
            args: toolArgs,
          });

          if (result.effect === 'DENY') {
            throw new Error(
              `Faramesh DENY: ${result.reasonCode || 'POLICY_DENY'} (tool=${toolName})`
            );
          }
          if (result.effect === 'DEFER') {
            throw new Error(
              `Faramesh DEFER: approval required (token=${result.deferToken}, tool=${toolName})`
            );
          }
        } catch (err: any) {
          if (err.message?.startsWith('Faramesh')) throw err;
          // Governance error → fail-closed
          console.error(`[faramesh] govern error (fail-closed): ${err.message}`);
          throw new Error(`Faramesh governance error: ${err.message}`);
        }

        return handler(request, extra);
      };
      return origSetRequestHandler(schema, wrappedHandler);
    }
    return origSetRequestHandler(schema, handler);
  };

  patchedServers.add(server);
  return true;
}

/**
 * Monkey-patch the global require for @modelcontextprotocol/sdk
 * so that any MCP Server created is auto-patched.
 */
export function installGlobalHook(): void {
  if (installed) return;
  installed = true;

  const Module = require('module');
  const origLoad = Module._load;

  Module._load = function (request: string, parent: any, isMain: boolean) {
    const result = origLoad.call(this, request, parent, isMain);
    if (request === '@modelcontextprotocol/sdk/server/index.js' ||
        request === '@modelcontextprotocol/sdk') {
      const ServerClass = result.Server || result.McpServer;
      if (ServerClass && !ServerClass._farameshPatched) {
        const origConstructor = ServerClass;
        const patchedInstances = new WeakSet();

        const origProto = ServerClass.prototype;
        const origSetReq = origProto.setRequestHandler;
        if (origSetReq) {
          origProto.setRequestHandler = function (schema: any, handler: Function) {
            if (!patchedInstances.has(this)) {
              patchedInstances.add(this);
              installAutoPatch(this);
            }
            return origSetReq.call(this, schema, handler);
          };
        }
        ServerClass._farameshPatched = true;
      }
    }
    return result;
  };
}

// Auto-install when loaded with FARAMESH_AUTOLOAD=1
if (process.env.FARAMESH_AUTOLOAD === '1') {
  installGlobalHook();
}
