import axios from "axios";
import { configure, gateDecideDict } from "../client";

describe("gateDecideDict", () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("POSTs /v1/gate/decide and returns raw JSON", async () => {
    const request = jest.fn().mockResolvedValue({
      data: { outcome: "HALT", reason_code: "POLICY", extra: true },
    });
    jest.spyOn(axios, "create").mockReturnValue({ request } as any);

    configure({ baseUrl: "http://127.0.0.1:9", token: "tok" });
    const out = await gateDecideDict("ag", "shell", "run", { cmd: "ls" }, { trace: "1" });

    expect(out).toEqual({
      outcome: "HALT",
      reason_code: "POLICY",
      extra: true,
    });
    expect(request).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "POST",
        url: "/v1/gate/decide",
        data: {
          agent_id: "ag",
          tool: "shell",
          operation: "run",
          params: { cmd: "ls" },
          context: { trace: "1" },
        },
      })
    );
  });
});
