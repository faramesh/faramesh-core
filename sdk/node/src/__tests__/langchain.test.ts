import { createLangChainMiddleware, installLangChainInterceptor } from "../langchain";
import { govern } from "../govern";

jest.mock("../govern", () => ({
  govern: jest.fn(),
}));

const mockedGovern = govern as jest.MockedFunction<typeof govern>;

class FakeBaseTool {
  name = "weather.lookup";

  async invoke(input: unknown) {
    return { ok: true, input };
  }

  async ainvoke(input: unknown) {
    return { async: true, input };
  }
}

describe("langchain adapter", () => {
  beforeEach(() => {
    mockedGovern.mockReset();
    mockedGovern.mockResolvedValue({ effect: "PERMIT" });
  });

  it("patches async LangChain tool methods", async () => {
    const patched = installLangChainInterceptor({
      moduleLoader: (moduleId: string) => {
        if (moduleId === "@langchain/core/tools") {
          return { BaseTool: FakeBaseTool };
        }
        throw new Error(`unexpected module ${moduleId}`);
      },
      includeLangGraph: false,
    });

    expect(patched.langchain).toEqual(["invoke", "ainvoke"]);

    const tool = new FakeBaseTool();
    const result = await tool.invoke({ city: "Tehran" });

    expect(result).toEqual({ ok: true, input: { city: "Tehran" } });
    expect(mockedGovern).toHaveBeenCalledWith({
      toolId: "weather.lookup/invoke",
      args: {
        framework: "langchain",
        method: "invoke",
        tool_name: "weather.lookup",
        input: { city: "Tehran" },
      },
    });
  });

  it("fails closed by default when governance denies", async () => {
    mockedGovern.mockResolvedValue({ effect: "DENY", reasonCode: "POLICY_DENY" });

    installLangChainInterceptor({
      moduleLoader: (moduleId: string) => {
        if (moduleId === "@langchain/core/tools") {
          return { BaseTool: FakeBaseTool };
        }
        throw new Error(`unexpected module ${moduleId}`);
      },
      includeLangGraph: false,
    });

    const tool = new FakeBaseTool();
    await expect(tool.ainvoke({ city: "Paris" })).rejects.toThrow("Faramesh DENY");
  });

  it("can fail open when governance transport errors", async () => {
    mockedGovern.mockRejectedValue(new Error("socket unavailable"));

    class FailOpenTool {
      name = "support.lookup";

      async invoke(input: unknown) {
        return { passed: true, input };
      }
    }

    installLangChainInterceptor({
      moduleLoader: (moduleId: string) => {
        if (moduleId === "@langchain/core/tools") {
          return { BaseTool: FailOpenTool };
        }
        throw new Error(`unexpected module ${moduleId}`);
      },
      includeLangGraph: false,
      failOpen: true,
    });

    const tool = new FailOpenTool();
    await expect(tool.invoke({ ticket: "123" })).resolves.toEqual({
      passed: true,
      input: { ticket: "123" },
    });
  });

  it("provides middleware wrapper for custom execution flows", async () => {
    const middleware = createLangChainMiddleware();
    const execute = jest.fn(async () => "ok");

    const result = await middleware.wrapToolCall("custom.tool", { q: "status" }, execute);

    expect(result).toBe("ok");
    expect(execute).toHaveBeenCalledTimes(1);
    expect(mockedGovern).toHaveBeenCalledWith({
      toolId: "custom.tool/middleware",
      args: {
        framework: "langchain",
        method: "middleware",
        tool_name: "custom.tool",
        input: { q: "status" },
      },
    });
  });
});
