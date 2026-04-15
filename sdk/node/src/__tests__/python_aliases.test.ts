import {
  submitAction,
  submit_action,
  gateDecide,
  gate_decide,
  streamEvents,
  stream_events,
  getDefaultStore,
  get_default_store,
  createPolicy,
  create_policy,
  ExecutionGovernorClient,
  GovernorError,
  FarameshError,
  getActiveConfig,
  get_active_config,
} from "../index";

describe("python_aliases", () => {
  it("exposes snake_case aliases to camelCase APIs", () => {
    expect(submit_action).toBe(submitAction);
    expect(gate_decide).toBe(gateDecide);
    expect(stream_events).toBe(streamEvents);
    expect(get_default_store).toBe(getDefaultStore);
    expect(create_policy).toBe(createPolicy);
  });

  it("re-exports legacy class and GovernorError", () => {
    expect(typeof ExecutionGovernorClient).toBe("function");
    expect(GovernorError).toBe(FarameshError);
  });

  it("aliases get_active_config to getActiveConfig", () => {
    expect(get_active_config).toBe(getActiveConfig);
  });
});
