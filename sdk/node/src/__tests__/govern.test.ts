import { govern } from "../govern";
import { gateDecide } from "../client";

jest.mock("../client", () => ({
  gateDecide: jest.fn(),
}));

const mockedGateDecide = gateDecide as jest.MockedFunction<typeof gateDecide>;

describe("govern", () => {
  beforeEach(() => {
    mockedGateDecide.mockReset();
    process.env.FARAMESH_SOCKET = "/tmp/faramesh-test-missing.sock";
    process.env.FARAMESH_AGENT_ID = "sdk-test-agent";
  });

  afterEach(() => {
    delete process.env.FARAMESH_SOCKET;
    delete process.env.FARAMESH_AGENT_ID;
  });

  it("maps permit responses from gate/decide", async () => {
    mockedGateDecide.mockResolvedValue({
      outcome: "PERMIT",
      reason_code: "",
    } as any);

    await expect(
      govern({
        toolId: "stripe/refund",
        args: { amount: 10 },
      })
    ).resolves.toEqual({ effect: "PERMIT" });

    expect(mockedGateDecide).toHaveBeenCalledWith(
      "sdk-test-agent",
      "stripe",
      "refund",
      { amount: 10 }
    );
  });

  it("maps deny responses from gate/decide", async () => {
    mockedGateDecide.mockResolvedValue({
      outcome: "DENY",
      reason_code: "PAYMENTS_BLOCKED",
    } as any);

    await expect(
      govern({
        toolId: "stripe/refund",
        args: { amount: 10 },
      })
    ).resolves.toEqual({
      effect: "DENY",
      reasonCode: "PAYMENTS_BLOCKED",
    });
  });

  it("maps defer responses from gate/decide", async () => {
    mockedGateDecide.mockResolvedValue({
      outcome: "DEFER",
      provenance_id: "defer-123",
    } as any);

    await expect(
      govern({
        toolId: "stripe/refund",
        args: { amount: 10 },
      })
    ).resolves.toEqual({
      effect: "DEFER",
      deferToken: "defer-123",
    });
  });
});
