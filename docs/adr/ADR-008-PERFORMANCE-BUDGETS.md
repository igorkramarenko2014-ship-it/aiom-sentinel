# ADR-008: Performance Budgets

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Status
Accepted measurement policy.

## Context
The corpus contains plausible but unmeasured latency/overhead implications and one rejected
zero-overhead assertion.

## Decision
Label every unmeasured value `TARGET_OR_HYPOTHESIS`. Reports include hardware, OS build, storage,
corpus, ruleset, concurrency, cache state, sample size, command, and result distribution.

## Alternatives
Single-point marketing numbers and architecture-free microbenchmarks were rejected.

## Consequences
Budgets require reproducible suites and representative corpora before release gates.

## Security Impact
Resource exhaustion and dropped telemetry become measurable security failures.

## Privacy Impact
Benchmark corpora must be synthetic/authorized and free of accidental user content.

## Availability Impact
Queue, timeout, CPU, memory, and storage budgets constrain rollout and fallback.

## Verification Requirements
Cold/warm, concurrency, large-file, malformed-input, degraded-source, backpressure, and endurance tests.

## Implementation Phase
Every phase; no future runtime authority granted by this ADR.

## Unresolved Questions
Initial hardware tiers, corpora, percentiles, and error budgets require operator approval.
