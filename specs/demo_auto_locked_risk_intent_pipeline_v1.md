# DEMO_AUTO Locked Risk/Intent Pipeline v1

## Status and scope

This component is the **pre-execution half only** of a future DEMO_AUTO
runtime. It joins a one-use decision IPC input to fresh, factory-sealed risk
facts and records a terminal intent proposal for audit/soak analysis.

It does not make AI_SCALPER ready to submit a demo or live order. The hard
locks remain unchanged:

- `LIVE_ALLOWED = false`
- `SAFE_TO_DEMO_AUTO_ORDER = false`
- `order_capability = DISABLED`
- maximum proposed lot remains `0.01`

## Input contract

The only accepted decision input is an exact
`DemoAutoIPCRiskIntentInput` minted after the decision queue has durably
consumed one signed envelope. The pipeline additionally requires:

- an exact `BrokerSpec` bound to the reviewed stage;
- an exact `VerifiedRiskContext` created by the trusted risk-context factory;
- exact runtime health and market-guard decisions;
- the exact immutable champion model artifact; and
- the same execution-journal incarnation referenced by stage, permit, IPC,
  broker facts, and risk facts.

All facts are rechecked against a trusted UTC clock and have a maximum age of
one second. The M15 entry window and every upstream validity window cap the
proposal expiry.

## Pure locked risk preparation

The pipeline performs no broker I/O. It runs the existing deterministic risk
governor against broker-spec arithmetic to find a conservative proposed lot.
The resulting estimate is labelled:

`BROKER_SPEC_ESTIMATE_REQUIRES_FRESH_BROKER_RESIZING`

This estimate is not acceptable at a future submission boundary. A future
activated runtime must calculate risk again from fresh broker facts using the
broker-native profit and margin calculations before preflight.

Because the policy lock is closed, a valid preparation must produce a sealed
`RiskDecision` denied for exactly `DEMO_AUTO_ORDER_LOCKED`. Any additional
risk, health, timing, binding, model, market, or journal reason produces a
safe-loss tombstone instead of an intent proposal.

## Durable decision-to-intent binding

`ExecutionJournal.record_locked_demo_auto_preparation()` writes the exact
prepared `TradeIntent`, risk decision, broker-spec hash, factory-sealed risk
provenance metadata, health-facts hash, market-guard hash, model-binding hash,
and the non-broker sizing basis directly to terminal `RISK_REJECTED` state.
The `CREATED` and `RISK_REJECTED` transition rows are committed in the same
`BEGIN IMMEDIATE` transaction. Therefore no reader can observe a prepared
proposal in an active state.

Invalid consumed inputs are written by
`ExecutionJournal.record_demo_auto_safe_loss()` as terminal `EXPIRED`
tombstones without a `TradeIntent`.

The existing unique index on `intents.decision_id` provides the invariant:

> one consumed decision can create at most one durable binding across restart
> and concurrency.

A restarted or racing caller receives a non-executable safe-loss receipt with
`DECISION_ALREADY_BOUND`. It cannot replace either the terminal proposal or
the tombstone. Both domains are included in signed semantic journal
checkpoints; authority-bit, hash, payload, or terminal-state drift is rejected.
The validator cross-checks the health and market hashes against the durable
factory-sealed risk provenance and requires the exact terminal transition
chain.

## Explicitly prohibited surfaces

The pipeline has no:

- broker module or transport;
- execution coordinator;
- broker sizing callback;
- order preflight or submission callback;
- executor fence/lease acquisition;
- state transition out of `RISK_REJECTED` or `EXPIRED`;
- policy unlock or activation method.

Neither output is an execution capability. A contained `TradeIntent` is an
expired/short-lived audit proposal tied to a terminal journal record.

## Dormant future integration points

The following independently reviewed changes would all be required before any
DEMO_AUTO order path may exist. This specification does not implement them:

1. `ProductionRuntimeConfig` must gain an externally attested DEMO_AUTO
   profile instead of rejecting every non-manual-DEMO composition.
2. `RuntimeSupervisor` must consume a real signed release/stage authorization
   and remove its current DEMO_AUTO deny only after the operational gates pass.
3. The unconditional `DEMO_AUTO_ORDER_LOCKED` checks in the risk and execution
   coordinator boundaries must remain until a separately approved activation
   changes the central policy.
4. A fresh decision must be revalidated and re-sized from broker-native
   `order_calc_profit`/margin facts. A terminal preparation from this component
   must never be revived or submitted.
5. Broker preflight, fenced submission, acknowledgement, reconciliation, and
   server-side SL/TP confirmation must run through the existing execution
   journal state machine.
6. Release trust must be rooted outside the mutable release process, and the
   remaining legal, evidence, manual-order, soak, failure-drill, security, and
   human-approval gates must be satisfied with real evidence.

Until all six points are implemented and accepted, the only valid behavior is
locked preparation, safe loss, shadow observation, and manual demo testing.

## Acceptance tests

- Valid consumed input creates one terminal `RISK_REJECTED` proposal.
- Restart replay creates no new row and returns safe loss.
- Two concurrent callers yield exactly one preparation winner.
- Expired or risk-infeasible input creates one permanent `EXPIRED` tombstone.
- No preparation appears in `active_intents()`.
- Signed journal semantic validation rejects authority-bit or hash tampering.
- The module and output objects expose no execution/submission surface.
