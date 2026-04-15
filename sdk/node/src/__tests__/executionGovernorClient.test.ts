import * as clientMod from "../client";
import { ExecutionGovernorClient } from "../legacy_client";

describe("ExecutionGovernorClient", () => {
  afterEach(() => {
    jest.restoreAllMocks();
    clientMod.configure({ baseUrl: "http://127.0.0.1:9", token: "t-reset" });
  });

  it("delegates submitAction with constructor agent id", async () => {
    const spy = jest.spyOn(clientMod, "submitAction").mockResolvedValue({ id: "a1" } as any);
    const c = new ExecutionGovernorClient({
      baseUrl: "http://127.0.0.1:9",
      token: "tok",
      agentId: "class-agent",
    });
    await c.submitAction("http", "get", { url: "https://ex.test" });
    expect(spy).toHaveBeenCalledWith(
      "class-agent",
      "http",
      "get",
      { url: "https://ex.test" },
      {}
    );
  });

  it("accepts base URL string plus optional second config", async () => {
    jest.spyOn(clientMod, "submitAction").mockResolvedValue({ id: "a2" } as any);
    const c = new ExecutionGovernorClient("http://127.0.0.1:9", {
      token: "t2",
      agentId: "from-second",
    });
    await c.submitAction("stripe", "refund", { amount: 1 });
    expect(clientMod.submitAction).toHaveBeenCalledWith(
      "from-second",
      "stripe",
      "refund",
      { amount: 1 },
      {}
    );
    expect(c.agentId).toBe("from-second");
  });

  it("honors agent_id snake_case on config object", async () => {
    jest.spyOn(clientMod, "submitAction").mockResolvedValue({} as any);
    const c = new ExecutionGovernorClient({
      baseUrl: "http://127.0.0.1:9",
      agent_id: "snake-agent",
    } as any);
    await c.submitAction("http", "get", {});
    expect(clientMod.submitAction).toHaveBeenCalledWith("snake-agent", "http", "get", {}, {});
  });
});
