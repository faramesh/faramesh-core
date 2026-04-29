import { configure, streamEvents, streamEventsDeps } from "../client";

describe("streamEvents", () => {
  const realOnEvents = streamEventsDeps.onEvents;

  beforeEach(() => {
    configure({ baseUrl: "http://127.0.0.1:9", token: "test" });
  });

  afterEach(() => {
    streamEventsDeps.onEvents = realOnEvents;
  });

  it("closes the stream after stopAfter deliveries", async () => {
    const innerStop = jest.fn();
    streamEventsDeps.onEvents = (handler) => {
      queueMicrotask(() => {
        handler({ event_type: "action_created", action_id: "a1" } as any);
        handler({ event_type: "action_created", action_id: "a2" } as any);
      });
      return innerStop;
    };

    const h = jest.fn();
    const stop = streamEvents(h, { stopAfter: 2 });
    await new Promise<void>((resolve) => queueMicrotask(() => resolve()));
    expect(h).toHaveBeenCalledTimes(2);
    expect(innerStop).toHaveBeenCalled();
    stop();
  });

  it("invokes stop when timeout elapses", () => {
    jest.useFakeTimers();
    const innerStop = jest.fn();
    streamEventsDeps.onEvents = () => innerStop;

    streamEvents(() => {}, { timeoutMs: 1000 });
    jest.advanceTimersByTime(1000);
    expect(innerStop).toHaveBeenCalled();
    jest.useRealTimers();
  });
});
