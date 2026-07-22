# Locked DEMO_AUTO Decision IPC Consumer v1

## Status and scope

This contract closes the one-way boundary between the brokerless decision
runtime and the future DEMO_AUTO risk/intent pipeline. It is a locked software
foundation only. It does not activate DEMO_AUTO, submit an order, call a broker,
mint an environment arm, issue a permit, or satisfy an operational promotion
gate.

The repository invariants remain:

- `live_allowed=false`;
- `safe_to_demo_auto_order=false`;
- `order_capability=DISABLED`;
- no automatic lot/risk expansion; and
- no production-bootstrap or supervisor policy unlock.

## Inputs

`DemoAutoDecisionIPCConsumer` accepts only:

1. an exact sealed `DecisionIPCConsumerPort` minted by the durable queue and
   bound to the reviewed account, server, DEMO environment, journal, commit,
   config, model, data contract, decision issuer, and external checkpoint
   custodian; the consumer does not receive the raw queue, publication method,
   database path, or decision/custody signing providers;
2. an exact signed `StageReadinessAuthorization` for `DEMO_AUTO`;
3. the exact sealed `StageAuthorizationValidation` that proves the
   authorization was authenticated and consumed once by the durable replay
   registry;
4. the exact `StageBinding` referenced by that authorization;
5. an exact future `RuntimeSupervisorBinding` whose mode is `DEMO_AUTO` and
   whose account, server, environment, journal, commit, config, and stage hash
   match the queue/stage lane;
6. the local non-secret account alias whose SHA-256 matches all three bindings;
7. a permit-key provider; the expected permit key ID and SHA-256 fingerprint
   come only from the queue binding already protected by its identity HMAC and
   external checkpoint custody; and
8. a trusted UTC clock.

The constructor rejects any static mismatch before a queue head can be
consumed. The stage authorization and its validation remain deny-only evidence:
their execution, activation, demo-auto, live, and order-capability fields must
all remain false/disabled.

## Per-head processing

`consume_for_risk_intent_pipeline()` performs the following ordered checks:

1. reassert the hard repository locks;
2. revalidate the exact stage/session and supervisor/queue bindings;
3. sample the trusted UTC clock and require the stage request to be currently
   inside its signed issued/expires window;
4. resolve the queue-bound permit key ID, re-check the secret against the
   queue-bound fingerprint, then validate the
   signed `PromotionPermit` as `DEMO_AUTO`, including exact
   account, server, single lane symbol, commit, config, model, journal, and the
   promotion-evidence SHA-256 named by the stage request;
5. read the real process environment using `read_environment_arm()` and require
   the canonical one-second `DEMO_AUTO` arm for the same account/server/journal;
6. durably consume the next signed IPC head through the consume-only port using
   the queue's external
   checkpoint compare-and-swap;
7. sample the trusted clock again, require the stage request to remain current,
   and re-read the real process environment arm; the post-CAS arm must be armed,
   fresh, and have the exact same variable name, binding hash, journal hash,
   and observed-value hash as the pre-CAS arm;
8. require monotonic time plus an unexpired stage, envelope, permit, and both
   arm observations; and
9. require the exact stage symbol/strategy and build/model provenance.

The environment value and permit validation cannot be injected as prebuilt
objects. A missing or invalid control fails before queue consumption. Queue
replay, rollback, fork, gap, signature, SQLite-schema, or external-custody
failure is inherited from `DurableDecisionIPCQueue` and fails closed.

## Outcomes

- A fresh `WAIT` head produces a sealed `DemoAutoIPCNoActionReceipt`.
- An already-expired head produces only the queue's sealed
  `DiscardedDecisionIPCEnvelope`.
- A fresh BUY/SELL candidate produces an exact sealed
  `DemoAutoIPCRiskIntentInput` containing the original verified envelope and
  exact stage, supervisor, permit, and arm evidence.

The risk/intent input is not a `TradeIntent` and contains no execution callback,
adapter, broker module, submit method, unlock method, or secret. Its capability
fields are permanently false/disabled. This avoids circular trust: the decision
producer cannot build an intent and the consumer cannot execute one.

The returned validity deadline is the minimum of the signed stage expiry,
envelope expiry, permit expiry, pre-CAS arm expiry, and post-CAS arm expiry.
If a control expires, the arm changes, the trusted clock regresses, or a binding
mismatch is detected after the external queue CAS has committed, processing is
a deliberate safe loss: the head remains consumed and cannot be replayed, and
no pipeline input is returned.

## Supervisor and production-bootstrap boundary

The input is supervisor-bound but is not yet wired into the Windows production
service. `ProductionRuntimeConfig` remains manual-DEMO-only and
`RuntimeSupervisor.start()` continues to hard-deny `DEMO_AUTO` while
`SAFE_TO_DEMO_AUTO_ORDER=false`. Activating that path requires a separate
reviewed change after all external gates are complete, including signed release
trust, exact Windows deployment, legal/broker approval, manual-demo acceptance,
news and reconciliation evidence, failure drills, and the required demo soak.

No test or local artifact may substitute for those operational gates.

## Acceptance tests

The focused suite must prove:

1. one fresh signed candidate yields one sealed non-executable input and cannot
   be consumed twice;
2. WAIT and expired heads never yield an actionable input;
3. missing arm or invalid permit leaves a still-fresh queue head unconsumed;
4. account, server, commit, config, and stage mismatches fail before consume;
5. expiry during external custody is consumed safe-loss with no replay; and
6. stage expiry and environment-arm replacement during custody are consumed
   safe-loss, and stage expiry caps the emitted input validity;
7. the permit verifier key ID/fingerprint comes from the externally-custodied
   queue binding rather than a consumer constructor argument; and
8. the public consumer exposes no broker, execution, activation, or unlock
   surface; and
9. its decision port exposes binding/checkpoint/ordered consumption only, while
   producer publication and all signing-provider attributes remain absent.
