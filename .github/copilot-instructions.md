# Faramesh Core Copilot Instructions

## Execution Order (Hard Requirement)

Never default to the fastest, easiest, or lowest-effort task order.

Always execute work in structural usability order for real users and agent runtimes:
1. Interception path correctness
2. Patching/autoload correctness
3. Action governance runtime behavior
4. HITL/defer runtime behavior
5. Policy/FPL compilation and load path correctness
6. Identity fail-closed behavior
7. Credential sequestration fail-closed behavior
8. Onboarding/reporting UX
9. Tests, CI wiring, and E2E acceptance gates (last)

## Prioritization Rule

If a lower-layer runtime capability is incomplete, do not move to convenience, reporting, or process layers.

Do not prioritize work because it is quicker to implement. Prioritize work that makes Faramesh operational and safe in production runtime flows.

## Validation Timing

Testing and CI are required, but only after the runtime-critical path above is built and wired end-to-end.
