import { installAutoPatch } from "../autopatch";
import { govern } from "../govern";

jest.mock("../govern", () => ({
  govern: jest.fn(),
}));

const mockedGovern = govern as jest.MockedFunction<typeof govern>;

describe("installAutoPatch", () => {
  beforeEach(() => {
    mockedGovern.mockReset();
  });

  it("wraps MCP tools/call handlers and permits allowed requests", async () => {
    let wrappedHandler: ((request: any, extra: any) => Promise<any>) | undefined;
    const downstream = jest.fn().mockResolvedValue({ content: [] });
    const server = {
      setRequestHandler: jest.fn((schema: any, handler: any) => {
        wrappedHandler = handler;
        return true;
      }),
    };

    mockedGovern.mockResolvedValue({ effect: "PERMIT" });

    expect(installAutoPatch(server)).toBe(true);
    server.setRequestHandler({ method: "tools/call" }, downstream);

    const result = await wrappedHandler?.(
      {
        params: {
          name: "shell/run",
          arguments: { cmd: "pwd" },
        },
      },
      {}
    );

    expect(mockedGovern).toHaveBeenCalledWith({
      toolId: "shell/run",
      args: { cmd: "pwd" },
    });
    expect(downstream).toHaveBeenCalledTimes(1);
    expect(result).toEqual({ content: [] });
  });

  it("fails closed before calling the downstream handler on deny", async () => {
    let wrappedHandler: ((request: any, extra: any) => Promise<any>) | undefined;
    const downstream = jest.fn();
    const server = {
      setRequestHandler: jest.fn((schema: any, handler: any) => {
        wrappedHandler = handler;
        return true;
      }),
    };

    mockedGovern.mockResolvedValue({ effect: "DENY", reasonCode: "POLICY_DENY" });

    installAutoPatch(server);
    server.setRequestHandler({ method: "tools/call" }, downstream);

    await expect(
      wrappedHandler?.(
        {
          params: {
            name: "shell/run",
            arguments: { cmd: "pwd" },
          },
        },
        {}
      )
    ).rejects.toThrow("Faramesh DENY");
    expect(downstream).not.toHaveBeenCalled();
  });
});
