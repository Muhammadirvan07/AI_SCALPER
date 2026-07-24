# Manual Demo Prepared Intent v1

## Purpose

Manual approval can take longer than the one-second lifetime of runtime risk
evidence. This contract separates approval from execution without extending or
weakening any evidence lifetime.

## Phase 1: prepare

- Accept one finalized M15 `DecisionSnapshot`, reviewed DEMO permit, broker
  specification, and factory-sealed `VerifiedRiskContext`.
- Run the existing fail-closed preconditions and broker sizing calculation.
- Return one exact immutable `TradeIntent` whose expiry is the original candle
  close plus 10 seconds. No new entry window is created.
- Store the exact intent, semantic broker-spec binding, permit, model, and
  sizing quote in the service's deny-by-default prepared-intent registry.
- Do not call the execution coordinator and do not mutate broker state.
- A repeated preparation for the same decision returns the original proposal;
  it never silently creates a replacement intent.

Prepared state is process-local. A restart invalidates every proposal; this is
intentional fail-closed behavior because the 10-second entry window cannot
survive a meaningful restart safely.

## Phase 2: approve and execute

- Accept the exact prepared `TradeIntent` and a signed approval bound to that
  intent, account, server, journal, and DEMO mode.
- Reject unknown, changed, previously delegated, pre-approved, or expired
  proposals before collecting broker evidence.
- After approval, call a trusted fresh-context provider. It must rebuild a new
  broker specification, runtime health facts, market guard, and factory-sealed
  `VerifiedRiskContext`; phase-1 risk evidence is never reused.
- Revalidate every wrapper binding and its one-second expiry, verify semantic
  broker-spec stability, re-run broker sizing, and require the prepared lot to
  remain safe.
- Re-sample the trusted clock immediately before coordinator delegation and
  revalidate the wrapper, approval, permit, quote, and original entry deadline.
- Atomically claim the proposal before delegation. Any delegation attempt makes
  the proposal non-replayable, including exceptions and rejected outcomes.

The coordinator remains responsible for HMAC verification, environment arm,
permit validation, broker preflight, final submission guard, and durable
idempotency.

## Safety invariants

- The 10-second proposal window never extends the one-second risk-fact window.
- `DEMO_AUTO` and `LIVE` remain locked by existing policy.
- No approval can authorize a newly generated or modified intent.
- Stale/future health, guard, broker, conversion, exposure, or risk evidence
  fails before broker submission.
- Phase 1 performs no broker mutation; phase 2 has no direct order primitive and
  delegates only to the existing coordinator.

## Acceptance coverage

Tests cover approval delay greater than one second but inside the original
10-second entry window, expiry at the exact deadline, changed intent, approval
mismatch, stale phase-1 evidence reuse, and replay after delegation.
