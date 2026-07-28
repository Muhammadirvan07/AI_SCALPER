# Live Canary Per-Order Execution v1

**Author:** OpenAI Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved for implementation
**Reviewers:** senior architecture, security, and ship-gate

## Context

AI_SCALPER has a verifier-sealed `LiveCanaryRuntimeCandidate` and a short-lived
`LiveCanaryRuntimeLaunchSession`.  The launch session permits one bounded LIVE
process to start, but it intentionally sets `execution_authorized=false` and
`broker_mutation_authorized=false`.  The production supervisor therefore
accepts LIVE observation cycles only and rejects every execution decision with
`LIVE_EXECUTION_PATH_NOT_IMPLEMENTED`.

The existing execution coordinator already provides signed permit and
promotion verification, environment arming, model and risk checks, broker
preflight, supervisor fencing, journal idempotency, global-exposure limits,
daily-entry limits, a durable final submission lease, and an MT5 final guard.
However, LIVE has no independently sealed per-order capability, no exact
champion pin source outside DEMO_AUTO IPC, and no supervisor route that can
deliver a fully bound LIVE intent to that coordinator.  This specification
adds the missing one-order boundary without weakening any existing control.

The checked-in central policy remains locked.  Consequently the implementation
can be exercised only with isolated test-time policy patches until the external
ship gate, operational evidence, and central unlock ceremony are complete.

## Goals

- Mint a verifier-sealed capability for exactly one XAUUSD LIVE canary intent,
  at exactly 0.01 lot, on the exact admitted account, server, journal, model,
  release, and launch session.
- Require a complete fresh chain of signed permit, promotion, news, runtime
  fact, risk, reconciliation, and checkpoint evidence before dispatch.
- Bind the capability into the execution journal, runtime authorization, final
  durable submission lease, and MT5 adapter boundary.
- Add an explicit `LIVE_CANARY_EXECUTE` supervisor action and a separately
  sealed execution result, with no fallback to DEMO or DEMO_AUTO paths.
- Recheck the central policy and all mutable evidence at multiple time-of-use
  boundaries, including immediately before broker submission.
- Preserve all checked-in safety locks, all existing DEMO behavior, and the
  invariant that tests never call a real broker.

## Out of Scope

- OS-1: This change does not set checked-in `execution_policy.LIVE_ALLOWED` or
  `SAFE_TO_DEMO_AUTO_ORDER` to true.
- OS-2: This change does not manufacture broker credentials, external approval,
  promotion evidence, WORM/CAS evidence, news evidence, or launcher custody.
- OS-3: This change does not remove regulatory, broker, risk, calendar, model,
  provider-conformance, or ship-gate requirements.
- OS-4: This change does not enable symbols other than XAUUSD, lots other than
  exactly 0.01, more than one concurrent position, retries, averaging, hedging,
  pyramiding, or recovery orders.
- OS-5: This change does not allow LIVE execution from the dashboard, HTTP,
  WebSocket, CLI, or an unsigned decision source.
- OS-6: This change does not persist raw account IDs, credentials, private keys,
  environment-arm values, or broker request secrets in the new capability.
- OS-7: This change does not alter canonical DEMO or DEMO_AUTO payloads merely
  because optional LIVE inputs and ports exist.

## Functional Requirements

- FR-1: The only new supervisor execution action MUST be
  `LIVE_CANARY_EXECUTE`.  It MUST require a non-empty `intent_id`; every other
  LIVE execution action MUST fail closed.
- FR-2: A `LIVE_CANARY_EXECUTE` action MUST be accepted only by an exact
  LIVE/LIVE supervisor while the central LIVE policy returns `(True, ())` and
  `SAFE_TO_DEMO_AUTO_ORDER` remains false.
- FR-3: LIVE dispatch MUST require the exact verifier-sealed
  `LiveCanaryRuntimeCandidate` and `LiveCanaryRuntimeLaunchSession` already
  bound to the production configuration.  The launch session remains
  launch-only and MUST never itself be treated as order authority.
- FR-4: A LIVE order-input provider MUST return one exact immutable
  `LiveCanaryPreparedOrder` containing an exact `TradeIntent`, `BrokerSpec`,
  sealed `VerifiedRiskContext`, signed `PromotionPermit`, exact
  `RuntimeHealthFacts`, sealed `MarketGuardDecision`, exact
  `ModelArtifactManifest`, and signed `PromotionEvidenceReceipt`.
- FR-5: The prepared intent MUST be LIVE, XAUUSD, exactly 0.01 lot, use the
  candidate account/server and broker symbol, match the supervisor decision's
  `intent_id`, remain inside its one-second intent window, and bind the
  candidate commit, champion config, model artifact, journal, and permit.
- FR-6: LIVE promotion validation MUST derive every champion expectation from
  the exact admitted candidate, never from the receipt being validated and
  never from DEMO_AUTO IPC.
- FR-7: Before requesting order authority, the supervisor MUST durably append a
  `PRE_DISPATCH` record that binds the decision, initial journal/risk/fact/news
  evidence, and exact supervisor lease/fence.
- FR-8: After `PRE_DISPATCH`, the supervisor MUST refresh and verify the
  external supervisor checkpoint, journal checkpoint, risk receipt, runtime
  facts, account snapshot, reconciliation binding, and a strict signed news
  successor.  Any change that is not the required news successor MUST block.
- FR-9: A LIVE authority provider MUST receive only the exact prepared order and
  exact refreshed evidence.  It MUST return a verifier-sealed
  `LiveCanaryOrderAuthorization` minted by the reviewed factory.
- FR-10: The authorization MUST bind hashes of the candidate, launch session,
  supervisor binding and decision, prepared order and intent, broker spec,
  permit validation, promotion validation, environment arm, supervisor and
  journal checkpoints, risk receipt, reconciliation result, signed news guard,
  and the ordered unique runtime-fact receipt set.
- FR-11: The authorization MUST contain only the account hash, never the raw
  account ID.  It MUST bind the exact server, canonical symbol, broker symbol,
  side, intent ID, journal hash, and 0.01 lot.
- FR-12: The authorization lifetime MUST be positive and at most one second,
  MUST not outlive the intent, permit validation, promotion validation,
  environment arm, runtime facts, signed news guard, or launch session, and
  MUST be current at every subsequent boundary.
- FR-13: The authorization MUST be factory-sealed, immutable, exact-type
  checked, and explicitly represent one-order authority with
  `execution_authorized=true`, `broker_mutation_authorized=true`,
  `live_allowed=true`, `safe_to_demo_auto_order=false`, and
  `order_capability=LIVE_CANARY_ONE_ORDER`.
- FR-14: Direct construction, subclassing, copying without the private seal,
  duck typing, cross-candidate substitution, cross-session substitution,
  cross-intent reuse, and stale capability reuse MUST fail.
- FR-15: No authorization-provider callback MAY run after authority issuance
  and before the execution service receives control.  During that final gap,
  the supervisor MUST recheck central policy, launch session, decision age,
  supervisor lease, checkpoints, risk, facts, account snapshot, news guard, and
  exact authorization bindings.
- FR-16: The execution service MUST return an exact verifier-sealed
  `RuntimeLiveCanaryExecutionResult` that binds the authorization and all
  dispatch evidence to one adapter `ExecutionReceipt` and one entry-risk
  evidence set.
- FR-17: The supervisor MUST verify that the execution receipt intent equals the
  decision and authorization intent, append the exact entry-risk event, verify
  the risk-ledger head advance, verify the journal, and advance the external
  checkpoint before recording a completed cycle.
- FR-18: `ExecutionCoordinator.execute_once` MUST require the exact candidate,
  launch session, and per-order authorization for LIVE and MUST forbid those
  inputs in every non-LIVE mode.
- FR-19: The coordinator MUST include the authorization hash in the immutable
  intent journal payload and MUST revalidate it before reservation, before
  runtime-authorization minting, inside the durable final submission guard,
  and immediately before calling the adapter.
- FR-20: The coordinator MUST continue to independently validate the raw permit,
  promotion receipt, environment arm, risk context, model, health, market,
  preflight, journal fence, global exposure, and daily entry count.  A valid
  per-order authorization MUST not bypass or replace any existing control.
- FR-21: `RuntimeAuthorization` MUST cryptographically bind the LIVE per-order
  authorization hash.  Its `allows_order_send` method MUST reject LIVE unless
  that non-zero binding is present and the central LIVE policy is still true.
- FR-22: `MT5Adapter.submit` MUST require the same exact LIVE candidate, launch
  session, and per-order authorization and MUST revalidate them after the
  durable submission lease is acquired and before `order_send`.  Non-LIVE
  submissions MUST reject LIVE-only inputs.
- FR-23: The durable journal authorization-consumption uniqueness constraint
  MUST make one authorization usable for at most one broker submission.  A
  process crash after consumption MUST remain `UNCERTAIN`/reconciliation-only
  and MUST never retry the order automatically.
- FR-24: `ProductionRuntimePorts` MUST expose optional LIVE prepared-order,
  authorization, and execution-cycle ports.  Construction and static contract
  validation MUST invoke none of them.
- FR-25: When the production mode is LIVE and central policy is enabled,
  materialization MUST require all LIVE ports and exact candidate/session
  inputs.  Missing ports MUST block before supervisor start.  Locked checked-in
  source MAY construct dormant optional ports without claiming readiness.
- FR-26: No LIVE provider MAY be called for SHADOW, DEMO, or DEMO_AUTO.  Existing
  DEMO and DEMO_AUTO execution flows and serialized hashes MUST remain stable.
- FR-27: Every denial MUST occur before the next effectful callback, use a stable
  uppercase reason code, latch the existing fail-closed supervisor state when
  required, and expose no sensitive callback exception text.
- FR-28: The checked-in central LIVE lock MUST remain false and repository tests
  MUST use fakes whose `order_send` calls are counted and asserted to remain
  zero for every denial case.

## Non-Functional Requirements

- NFR-1: Every security decision MUST use explicit conditions, never `assert`,
  so behavior is identical under normal Python and `PYTHONOPTIMIZE=2`.
- NFR-2: The implementation MUST add no runtime dependency and MUST support the
  repository's Python 3.12 Windows target.
- NFR-3: Authorization verification and final dispatch checks MUST complete
  within the one-second evidence window; expiration is a denial, not a retry.
- NFR-4: New contracts MUST be deterministic `CanonicalContract` payloads and
  hash identically across supported hosts.
- NFR-5: Focused tests MUST run without network, MT5, credentials, Windows Task
  Scheduler, external storage, or broker access.
- NFR-6: Full normal and optimized suites, compile checks, whitespace checks,
  central-lock checks, and ship-gate audits MUST remain green except for
  externally owned blockers accurately reported by the ship gate.
- NFR-7: Failure messages and audit reason codes MUST be bounded and free of raw
  account IDs, secrets, object addresses, callback text, and broker payloads.
- NFR-8: Optional LIVE parameters MUST preserve source compatibility for
  existing DEMO and DEMO_AUTO callers.

## Acceptance Criteria

### AC-1: Checked-in source cannot mint order authority (FR-2, FR-13, FR-28)

Traceability: FR-2, FR-13, FR-28.

Given the repository's checked-in policy constants
When a caller attempts to mint or verify LIVE per-order authority
Then the operation fails with `LIVE_MODE_POLICY_LOCKED`
And no provider, journal mutation, adapter method, or broker call occurs.

### AC-2: Exact complete evidence mints one short-lived capability (FR-3 through FR-14)

Traceability: FR-3, FR-4, FR-5, FR-6, FR-9, FR-10, FR-11, FR-12, FR-13,
FR-14.

Given a test-only central unlock and exact mutually bound LIVE candidate,
launch session, prepared order, supervisor decision, permit validation,
promotion validation, arm decision, checkpoints, risk, reconciliation, signed
news, and runtime facts
When the reviewed authorization factory runs
Then it returns an exact sealed `LiveCanaryOrderAuthorization`
And the capability is current for no more than one second
And it contains only a hashed account identity.

When any input is missing, forged, subclassed, stale, expanded in scope, or
bound to another candidate/session/intent/account/server/journal/model
Then the factory rejects before returning a capability.

### AC-3: Supervisor dispatch is fail-closed and ordered (FR-1, FR-7 through FR-17)

Traceability: FR-1, FR-7, FR-8, FR-9, FR-10, FR-11, FR-12, FR-13, FR-14,
FR-15, FR-16, FR-17.

Given a LIVE supervisor decision with action `LIVE_CANARY_EXECUTE`
When the exact prepared order and refreshed evidence remain current
Then the supervisor checkpoints `PRE_DISPATCH`, mints and verifies one order
authorization, calls the LIVE execution service once, verifies its sealed
result, and advances risk and journal custody.

When the action is a DEMO action, an intent ID differs, a callback is absent,
or any checkpoint/risk/fact/news/session/policy value changes
Then the supervisor latches fail-closed before the execution service call.

### AC-4: Coordinator and adapter require the same authority (FR-18 through FR-23)

Traceability: FR-18, FR-19, FR-20, FR-21, FR-22, FR-23.

Given an exact authorized LIVE prepared order
When it traverses the coordinator
Then the journal payload, runtime authorization, final lease, and adapter all
bind the same per-order authorization hash
And the adapter may invoke its fake `order_send` at most once.

When the authority is missing, stale, replaced, reused, or no longer matches
the central policy, candidate, session, intent, runtime authorization, or
durable lease
Then submission is held before the fake `order_send` call.

### AC-5: Existing modes remain isolated (FR-22, FR-24 through FR-26)

Traceability: FR-22, FR-24, FR-25, FR-26.

Given existing SHADOW, DEMO, and DEMO_AUTO fixtures
When construction, static validation, startup, and execution tests run
Then no LIVE provider is called and their existing canonical artifacts remain
unchanged.

When LIVE-only evidence is supplied to a non-LIVE coordinator or adapter call
Then it is rejected before mutation.

### AC-6: Crash and replay are safe (FR-17, FR-19, FR-23)

Traceability: FR-17, FR-19, FR-23.

Given a consumed durable submission authorization
When the process fails before or after broker acknowledgement
Then restart reports reconciliation required or uncertain state
And the same intent or per-order authorization cannot produce a second send.

### AC-7: Complete safety gates pass (FR-27, FR-28; NFR-1 through NFR-8)

Traceability: FR-27, FR-28, NFR-1, NFR-2, NFR-3, NFR-4, NFR-5, NFR-6,
NFR-7, NFR-8.

Given the completed implementation
When focused, integration, full, optimized, static, compile, whitespace,
central-lock, and ship-gate checks run
Then all code-controlled gates pass
And the checked-in LIVE lock is still false
And no test or report falsely claims that a real broker order was sent.

## Edge Cases

- EC-1: LIVE action without intent ID, or `NO_ACTION` with intent ID -> reject.
- EC-2: Candidate/session pair is valid for launch but session is expired at
  authorization or adapter time -> reject.
- EC-3: Candidate config hash differs from decision champion config while the
  candidate content hash correctly binds the supervisor -> reject unless both
  distinct bindings match their explicitly designated fields.
- EC-4: Permit or promotion receipt selects its own champion hashes -> reject;
  expectations come only from the admitted candidate.
- EC-5: Lot is `0.0100000001`, `0.009`, NaN, infinity, boolean, or broker-grid
  invalid -> reject.
- EC-6: Required runtime facts are empty, duplicated, unordered, stale, include
  an extra symbol, or omit XAUUSD -> reject.
- EC-7: News successor repeats the previous receipt, rolls sequence backward,
  forks the chain, expires, or enters blackout -> reject.
- EC-8: Journal, risk, supervisor checkpoint, reconciliation, account snapshot,
  or launch session changes during an authorization callback -> reject before
  execution service.
- EC-9: Policy relocks after runtime authorization but before adapter send ->
  durable lease is not used for a broker call; state becomes held/uncertain and
  requires reconciliation.
- EC-10: An execution service returns an unsealed, cross-intent, non-fill, or
  cross-account result -> reject and do not append entry risk evidence.
- EC-11: Duplicate authority hash, duplicate intent, duplicate journal
  authorization consumption, concurrent executor, or stale fence -> reject.
- EC-12: A fake callback raises a secret-bearing exception -> public output uses
  only the designated stable reason code.
- EC-13: Optimized Python removes assertions -> all authorization and order-send
  denials remain active.

## API Contracts

The notation below describes Python keyword-only in-process ports.  It is not a
network API and MUST NOT be exposed directly over HTTP or WebSocket.

Forbidden network contract: `POST /api/v1/live-canary/order-authorizations`
MUST NOT be implemented; an HTTP server would return `404 Not Found` because
the capability factory is intentionally process-local.

```typescript
interface LiveCanaryPreparedOrder {
  intent: TradeIntent;                         // exact LIVE/XAUUSD/0.01 intent
  brokerSymbol: string;                        // exact candidate broker symbol
  brokerSpec: BrokerSpec;
  riskContext: VerifiedRiskContext;
  permit: PromotionPermit;
  permitValidation: PermitValidation;
  healthFacts: RuntimeHealthFacts;
  marketGuard: MarketGuardDecision;
  modelArtifact: ModelArtifactManifest;
  promotionEvidence: PromotionEvidenceReceipt;
  promotionValidation: PromotionEvidenceValidation;
  environmentArm: EnvironmentArmDecision;
}

interface LiveCanaryOrderAuthorization {
  issuedAtUtc: string;
  validUntilUtc: string;                       // lifetime <= 1 second
  candidateSha256: Sha256;
  launchSessionSha256: Sha256;
  supervisorBindingSha256: Sha256;
  supervisorDecisionSha256: Sha256;
  preparedOrderSha256: Sha256;
  intentSha256: Sha256;
  intentId: string;
  accountIdSha256: Sha256;
  server: string;
  symbol: "XAUUSD";
  brokerSymbol: string;
  side: "BUY" | "SELL";
  requestedLot: 0.01;
  journalSha256: Sha256;
  brokerSpecSha256: Sha256;
  permitValidationSha256: Sha256;
  promotionValidationSha256: Sha256;
  environmentArmSha256: Sha256;
  supervisorCheckpointSha256: Sha256;
  journalCheckpointSha256: Sha256;
  riskReceiptSha256: Sha256;
  reconciliationSha256: Sha256;
  newsGuardSha256: Sha256;
  runtimeFactReceiptSha256s: Sha256[];
  executionAuthorized: true;
  brokerMutationAuthorized: true;
  liveAllowed: true;
  safeToDemoAutoOrder: false;
  orderCapability: "LIVE_CANARY_ONE_ORDER";
}

type LivePreparedOrderProvider = (
  decision: RuntimeSupervisorDecision
) => LiveCanaryPreparedOrder;

type LiveAuthorityProvider = (args: {
  candidate: LiveCanaryRuntimeCandidate;
  launchSession: LiveCanaryRuntimeLaunchSession;
  supervisorBinding: RuntimeSupervisorBinding;
  supervisorDecision: RuntimeSupervisorDecision;
  preparedOrder: LiveCanaryPreparedOrder;
  supervisorCheckpoint: RuntimeSupervisorCheckpoint;
  journalCheckpoint: ExecutionJournalCheckpoint;
  riskReceipt: RiskStateReceipt;
  reconciliation: RuntimeReconciliationRiskResult;
  newsGuard: RuntimeNewsGuardReceipt;
  runtimeFacts: RuntimeFactReceipt[];
  now: string;
}) => LiveCanaryOrderAuthorization;

type LiveExecutionCycleProvider = (args: {
  service: LiveRuntimeService;
  decision: RuntimeSupervisorDecision;
  preparedOrder: LiveCanaryPreparedOrder;
  authorization: LiveCanaryOrderAuthorization;
  candidate: LiveCanaryRuntimeCandidate;
  launchSession: LiveCanaryRuntimeLaunchSession;
  supervisorCheckpoint: RuntimeSupervisorCheckpoint;
  journalCheckpoint: ExecutionJournalCheckpoint;
  riskReceipt: RiskStateReceipt;
  reconciliation: RuntimeReconciliationRiskResult;
}) => RuntimeLiveCanaryExecutionResult;
```

All providers are local trusted ports.  Any type mismatch, callback exception,
stale response, or changed binding maps to a stable fail-closed reason code.

## Data Models

`LiveCanaryPreparedOrder` is immutable but is not order authority.  It groups
the exact already-signed domain inputs required by the existing coordinator so
the supervisor can bind one declared intent before requesting authority.

`LiveCanaryOrderAuthorization` is verifier-sealed and exists only in memory.
Its canonical hash is persisted as evidence in the existing immutable intent
payload and is transitively included in `RuntimeAuthorization`.  The existing
durable journal uniqueness constraint consumes the resulting runtime
authorization once; because the latter binds this authorization and this
authorization binds one intent, cross-intent replay is impossible.

`RuntimeLiveCanaryExecutionResult` mirrors the existing sealed DEMO result
shape but additionally binds the candidate, launch session, prepared order,
per-order authorization, and refreshed dispatch evidence.

| Layer | Required LIVE binding | Authority conveyed |
| --- | --- | --- |
| candidate | deployment, model, champion, account hash, limits | none |
| launch session | exact candidate and external launch checkpoint | process launch only |
| prepared order | exact intent plus existing signed domain controls | none |
| per-order authorization | all stable and fresh evidence hashes | one intent only |
| runtime authorization | execution gate plus per-order authorization | one final lease |
| durable journal lease | intent, gate, runtime authorization, request | one send attempt |
| MT5 adapter | all prior bindings plus fresh broker facts | at most one `order_send` |

```text
signed decision -> exact prepared LIVE intent
                         |
                         v
              durable PRE_DISPATCH checkpoint
                         |
                         v
          refresh checkpoints/risk/facts/news/session
                         |
                         v
          sealed one-order LIVE authorization (<=1s)
                         |
                         v
              existing coordinator safety stack
                         |
                         v
       durable final journal lease + adapter recheck
                         |
                         v
              at most one broker submission
```

No database migration is required.  The runtime authorization's existing
approval-binding hash slot is reused for LIVE as a mode-specific one-order
authorization hash; DEMO retains its existing manual-approval meaning and
canonical payload.

## Error Handling

- Authorization construction errors expose stable `LIVE_CANARY_*` reason codes.
- Provider exceptions are converted to `LIVE_CANARY_ORDER_INPUT_FAILED`,
  `LIVE_CANARY_AUTHORITY_PROVIDER_FAILED`, or
  `LIVE_CANARY_EXECUTION_SERVICE_FAILED`; exception text is not propagated.
- Staleness or policy relock after reservation yields a held or uncertain
  journal state with `retry_allowed=false`.
- A broker-call ambiguity remains reconciliation-only and never automatically
  creates another intent or authorization.
- Supervisor integrity failures use the existing critical latch and external
  checkpoint flow.

## Security

- The project owner's standing instruction authorizes implementation and
  review of this security boundary; it does not authorize changing external
  credentials, reviewer identities, keys, or checked-in policy locks.
- The authority is capability-based, exact-type checked, content-addressed,
  short-lived, one-intent bound, and transitively one-use through the durable
  journal.
- Raw account IDs and secrets are excluded from the new authorization payload.
- No provider is invoked during object construction or static validation.
- The adapter remains the final policy enforcement point and independently
  checks policy, authority, journal lease, account, server, symbol, lot,
  spread, margin, exposure, and live terminal identity.

## Observability

- Supervisor receipts record the decision and sealed LIVE result hash.
- The execution journal records the per-order authorization payload hash,
  permit/promotion/arm validation, gate, runtime authorization, final lease,
  broker request hash, and terminal outcome.
- Risk ledger entry evidence is appended only after a verified broker fill.
- Metrics MUST distinguish `LIVE_CANARY_AUTHORIZED`,
  `LIVE_CANARY_HELD_BEFORE_SEND`, `LIVE_CANARY_SUBMITTED`, and
  `LIVE_CANARY_RECONCILIATION_REQUIRED` without exposing secrets.

## Test Plan

- Unit-test direct construction denial, exact success under test-only unlock,
  every field mismatch, scope expansion, expiry, relock, and optimized mode.
- Unit-test supervisor callback order, no-callback denial, strict news
  successor, checkpoint/risk/fact drift, result binding, and risk append.
- Unit-test coordinator champion expectations from candidate, authority hash in
  the journal, revalidation at reservation/final guard, and replay denial.
- Unit-test adapter missing/stale/replaced authorization and assert fake
  `order_send` remains zero; one fully valid fake path may assert exactly one.
- Run all related tests in normal and `PYTHONOPTIMIZE=2`, then the complete
  repository suites, compile checks, static no-effect checks, central-lock
  checks, and ship-gate audit.

## Rollout and Rollback

1. Merge with central LIVE policy still false.
2. Build and verify exact Windows release artifacts and external evidence.
3. Exercise only fake-adapter and read-only production composition tests.
4. Complete ship-gate, operational review, and separate central unlock ceremony.
5. Run one bounded XAUUSD 0.01 canary with one-position enforcement and active
   human monitoring.

Rollback is an immediate central relock followed by supervisor stop.  Any
consumed or uncertain intent remains reconciliation-only; rollback must never
delete journal, risk, WORM, or broker evidence.

## Open Questions

- OQ-1: External reviewer evidence, release identity, credentials, and live
  broker readiness remain ship-gate inputs and cannot be satisfied by source
  code alone.
- OQ-2: A later version may replace the compatibility approval-hash slot in
  `RuntimeAuthorization` with a schema-v2 named field after an explicit
  migration review; v1 intentionally avoids changing existing DEMO hashes.
