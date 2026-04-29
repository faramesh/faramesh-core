# Faramesh Adversarial Test Suite

Formal property-testing and attack-simulation suite for [Faramesh Core](https://github.com/faramesh/faramesh-core).

## Purpose

This suite verifies that Faramesh governance cannot be bypassed, oracle-attacked, or double-governed through adversarial inputs. It is designed to run against the `github.com/faramesh/faramesh-core` module.

## Test Categories

### Property Tests (`properties_test.go`)
10 formal Hypothesis-style property tests:
1. **Deny is default** — unknown tools always produce DENY
2. **Kill switch overrides all** — killed agents always get DENY
3. **DENY never leaks policy** — denial tokens are opaque, no rule structure exposed
4. **WAL-before-execute** — every decision has a WAL record; no decision exists without one
5. **Idempotent canonicalization** — `canonicalize(x) == canonicalize(canonicalize(x))`
6. **Budget monotonicity** — session cost never decreases
7. **DPR chain integrity** — hash chain has no gaps, every record points to valid predecessor
8. **No empty decisions** — every Decision has a non-empty Effect and ReasonCode
9. **Timestamp ordering** — DPR timestamps are monotonically non-decreasing per agent
10. **Shadow mode fidelity** — SHADOW decisions record what enforcement would have done

### Bypass Attempts (`bypass_test.go`)
- Unicode confusable injection (Cyrillic "а" vs Latin "a" in tool IDs)
- Null byte injection in arguments
- Argument structure smuggling (extra keys, nested payloads)
- Tool ID prefix/suffix mutation
- Case variation attacks
- Empty and oversized arguments

### Oracle Attack Prevention (`oracle_test.go`)
- Denial token opacity — cannot reconstruct rule structure from tokens
- Timing side-channel — DENY and PERMIT have similar latencies
- Error message uniformity — all denials look identical to the agent
- Policy version probing — version string reveals no rule count or structure

### Double-Govern Detection (`doubleguard_test.go`)
- Detects if the same CAR is evaluated twice
- Ensures idempotency of pipeline evaluation
- Verifies that resubmitting a governed call returns the same decision

## Usage

```bash
go test -v ./...
```

## Dependencies

Requires `github.com/faramesh/faramesh-core` as a dependency.

## License

Mozilla Public License 2.0
