import { AsyncLocalStorage } from "async_hooks";
import { govern } from "./govern";

export interface LangChainInstallOptions {
  failOpen?: boolean;
  includeLangGraph?: boolean;
  moduleLoader?: (moduleId: string) => any;
}

export interface LangChainMiddlewareOptions {
  failOpen?: boolean;
}

export interface FarameshLangChainMiddleware {
  wrapToolCall<T>(toolName: string, input: unknown, execute: () => Promise<T>): Promise<T>;
}

const PATCH_MARKER = Symbol.for("faramesh.langchain.patched");
const governanceDepth = new AsyncLocalStorage<number>();

export function installLangChainInterceptor(
  options: LangChainInstallOptions = {}
): Record<string, string[]> {
  const {
    failOpen = false,
    includeLangGraph = true,
    moduleLoader = defaultModuleLoader,
  } = options;

  const patched: Record<string, string[]> = {};

  const baseTool = resolveExport(moduleLoader, [
    ["@langchain/core/tools", "BaseTool"],
    ["langchain/tools", "BaseTool"],
  ]);
  const baseToolMethods = patchPrototypeMethods(baseTool, ["invoke", "ainvoke", "run", "arun"], failOpen, "langchain");
  if (baseToolMethods.length > 0) {
    patched.langchain = baseToolMethods;
  }

  if (includeLangGraph) {
    const toolNode = resolveExport(moduleLoader, [
      ["@langchain/langgraph", "ToolNode"],
      ["@langchain/langgraph/prebuilt", "ToolNode"],
      ["langgraph/prebuilt", "ToolNode"],
    ]);
    const langGraphMethods = patchPrototypeMethods(toolNode, ["invoke", "ainvoke"], failOpen, "langgraph");
    if (langGraphMethods.length > 0) {
      patched.langgraph = langGraphMethods;
    }
  }

  return patched;
}

export function createLangChainMiddleware(
  options: LangChainMiddlewareOptions = {}
): FarameshLangChainMiddleware {
  const failOpen = options.failOpen ?? false;
  return {
    async wrapToolCall<T>(toolName: string, input: unknown, execute: () => Promise<T>): Promise<T> {
      await enforceGovernance(toolName, "middleware", input, failOpen, "langchain");
      return governanceDepth.run(currentGovernanceDepth() + 1, execute);
    },
  };
}

function patchPrototypeMethods(
  ctor: any,
  methodNames: string[],
  failOpen: boolean,
  framework: "langchain" | "langgraph"
): string[] {
  if (!ctor || !ctor.prototype) {
    return [];
  }

  const patched: string[] = [];
  for (const methodName of methodNames) {
    const original = ctor.prototype[methodName];
    if (typeof original !== "function") {
      continue;
    }
    if (!isAsyncFunction(original)) {
      continue;
    }
    if ((original as any)[PATCH_MARKER]) {
      continue;
    }

    const wrapped = async function (this: any, ...args: any[]) {
      if (currentGovernanceDepth() > 0) {
        return original.apply(this, args);
      }

      const toolName = resolveToolName(this, framework);
      const input = extractToolInput(args);
      await enforceGovernance(toolName, methodName, input, failOpen, framework);
      return governanceDepth.run(currentGovernanceDepth() + 1, () => original.apply(this, args));
    };

    (wrapped as any)[PATCH_MARKER] = true;
    ctor.prototype[methodName] = wrapped;
    patched.push(methodName);
  }

  return patched;
}

async function enforceGovernance(
  toolName: string,
  methodName: string,
  input: unknown,
  failOpen: boolean,
  framework: "langchain" | "langgraph"
): Promise<void> {
  try {
    const result = await govern({
      toolId: `${toolName}/${methodName}`,
      args: {
        framework,
        method: methodName,
        tool_name: toolName,
        input: jsonSafe(input),
      },
    });

    if (result.effect === "DENY") {
      throw new Error(`Faramesh DENY: ${result.reasonCode || "POLICY_DENY"} (tool=${toolName})`);
    }
    if (result.effect === "DEFER") {
      throw new Error(
        `Faramesh DEFER: approval required (token=${result.deferToken || ""}, tool=${toolName})`
      );
    }
  } catch (error) {
    if (failOpen) {
      return;
    }
    throw error;
  }
}

function resolveExport(
  moduleLoader: (moduleId: string) => any,
  candidates: Array<[string, string]>
): any {
  for (const [moduleId, exportName] of candidates) {
    try {
      const mod = moduleLoader(moduleId);
      if (mod && mod[exportName]) {
        return mod[exportName];
      }
    } catch {
      // best effort detection
    }
  }
  return null;
}

function defaultModuleLoader(moduleId: string): any {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require(moduleId);
}

function resolveToolName(target: any, framework: "langchain" | "langgraph"): string {
  if (framework === "langgraph") {
    return target?.name || target?.lc_namespace?.join("/") || target?.constructor?.name || "langgraph-tool";
  }
  return target?.name || target?.lc_kwargs?.name || target?.constructor?.name || "langchain-tool";
}

function extractToolInput(args: any[]): unknown {
  if (args.length === 0) {
    return {};
  }
  return args[0];
}

function currentGovernanceDepth(): number {
  return governanceDepth.getStore() ?? 0;
}

function isAsyncFunction(fn: Function): boolean {
  return fn.constructor?.name === "AsyncFunction";
}

function jsonSafe(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value ?? null;
  }
  if (Array.isArray(value)) {
    return value.map((item) => jsonSafe(item));
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out[key] = jsonSafe(item);
    }
    return out;
  }
  if (typeof value === "function") {
    return "[function]";
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  return value;
}
