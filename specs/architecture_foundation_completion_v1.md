# Spec: Architecture Foundation Completion v1

**Author:** Codex / AI_SCALPER engineering
**Date:** 2026-07-21
**Status:** Approved
**Reviewers:** Project owner (approval by implementation request), Codex architecture review
**Related specs:** `specs/broker_read_only_evidence_phase3.md`, `specs/mt5_candidate_binding_probe.md`

## Context

AI_SCALPER already has a fail-closed decision core, broker adapters, immutable
contracts, a SQLite execution journal, one-shot reconciliation, signed promotion
receipts, deterministic Windows deployment tooling, and local operational audit
exports. The architecture audit dated 2026-07-21 verified 529 tests but found
four remaining local software-foundation gaps at the start of this work:
reconciliation had no owned periodic lifecycle, promotion metrics were accepted
as aggregate inputs rather than independently recalculated, the Windows artifact
was operator tooling rather than a minimal service bundle, and off-host delivery
had no provider-neutral outbox/acknowledgement contract.

This specification closes those four local gaps while preserving every trading
lock. It does not claim broker evidence, legal eligibility, Windows/VPS drills,
external key custody, WORM retention, demo soak, or live readiness. Those facts
require external systems and observation time and remain explicit ship blockers.

Completion evidence: all fifteen acceptance criteria are implemented and the
post-implementation project regression suite passes `558/558` tests on local
CPython 3.12. This evidence closes the repository foundation only and does not
change the external ship blockers above.

## Functional Requirements

- FR-1: A reconciliation supervisor MUST own a bounded or continuous periodic
  lifecycle and MUST reconcile once before reporting a healthy startup.
- FR-2: The supervisor MUST use a durable single-owner lease and MUST reject a
  concurrent owner while the lease is current.
- FR-3: Every supervisor cycle MUST be recorded in an append-only SHA-256 chain
  with trusted UTC timestamps and a verifiable sequence.
- FR-4: A reconciliation exception, corrupt supervisor journal, critical
  reconciliation result, or lost lease MUST latch the execution journal kill
  switch and MUST stop the supervisor.
- FR-5: The supervisor MUST NOT submit, retry, cancel, close, or modify a broker
  order and MUST NOT clear a latched kill switch.
- FR-6: An independent promotion issuer MUST build `LaneEvidence` from raw closed
  trade observations, five rolling-fold observations, parity reports, and a
  verified validation-evidence receipt rather than from caller-claimed metrics.
- FR-7: The issuer MUST independently recalculate trade counts, duration, profit
  factors, cost-adjusted expectancy, deterministic bootstrap 95% lower bound,
  peak-to-trough drawdown, 1.5x/2x cost stress, and parity percentage per lane.
- FR-8: The issuer MUST fail closed for mixed lanes, source overlap, duplicate
  trade IDs, invalid UTC, non-finite numbers, missing five-fold corpus, invalid
  parity, unverified evidence receipt, or ruleset/source drift.
- FR-9: The issuer MAY sign the existing promotion evidence receipt only after
  the sealed readiness calculator reports evidence complete; issuance MUST NOT
  change runtime execution locks or constitute manual ship approval.
- FR-10: The Windows release builder MUST support a separate exact
  `READ_ONLY_SHADOW_SERVICE` profile with its own versioned allowlist and MUST
  preserve the existing deployment-tooling profile without behavior drift.
- FR-11: The read-only service profile MUST reject credentials, runtime/data
  artifacts, setup/generator tooling, execution modules, order primitives,
  undeclared local imports, dirty Git sources, and output inside the repository.
- FR-12: A reproducibility verifier MUST compare two clean Windows CPython 3.12
  build observations for the same commit/tree and exact archive, manifest, and
  release identity hashes, then produce a signed immutable receipt or fail.
- FR-13: An off-host delivery outbox MUST durably enqueue immutable signed
  heartbeat, alert, audit, and backup-anchor envelopes with idempotency keys.
- FR-14: The outbox MUST remove no pending record until an acknowledgement signed
  by an independently supplied remote key verifies the envelope ID, payload
  hash, destination, and remote timestamp.
- FR-15: Off-host timeout, malformed acknowledgement, signature mismatch,
  destination mismatch, replay mismatch, or local integrity failure MUST remain
  pending/failed and MUST be observable without claiming delivery.
- FR-16: All new outputs MUST expose `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `promotion_eligible=false`, and
  `max_lot=0.01` wherever those safety fields are present.

## Non-Functional Requirements

- NFR-1: All persisted timestamps MUST be timezone-aware UTC; naive timestamps
  MUST be rejected.
- NFR-2: Supervisor and delivery SQLite stores MUST use WAL, foreign keys,
  `synchronous=FULL`, a 10-second busy timeout, and `PRAGMA integrity_check`.
- NFR-3: Append operations and acknowledgement transitions MUST be atomic and
  idempotent under process restart.
- NFR-4: Hash/signature verification MUST use canonical JSON, SHA-256, HMAC-SHA256,
  constant-time comparison, and keys of at least 32 bytes. Key storage is not
  implemented by these components.
- NFR-5: Deterministic bootstrap results MUST be reproducible for an explicit
  seed and at least 2,000 resamples.
- NFR-6: Existing public APIs and the deployment-tooling release profile MUST
  remain backward compatible, and the full existing test suite MUST pass.
- NFR-7: New domain components MUST depend on ports/protocols for clocks,
  reconciliation, transport, and key lookup so external providers are adapters.
- NFR-8: New modules MUST compile on CPython 3.12 without requiring a network
  connection during unit tests.

## Acceptance Criteria

### AC-1: Startup and periodic reconciliation (FR-1, FR-3, NFR-1)
Given an empty valid supervisor store and a deterministic UTC clock
When the supervisor runs three bounded cycles
Then it performs exactly three reconciliations, the first before healthy status
And it records three contiguous hash-chained cycle receipts.

### AC-2: Singleton fencing (FR-2, NFR-3)
Given owner A holds an unexpired supervisor lease
When owner B attempts to start
Then owner B is rejected and no reconciliation is performed by owner B.

### AC-3: Fail-closed lifecycle (FR-4, FR-5)
Given a reconciliation dependency raises or returns a critical hold
When the supervisor processes the cycle
Then the execution kill switch is latched, a failure receipt is durable, and
the supervisor stops without invoking any mutation method.

### AC-4: Supervisor restart integrity (FR-2, FR-3, NFR-2)
Given completed cycles exist and the prior lease has expired
When a new process owner resumes
Then it receives a higher fence token and appends to the existing valid chain.

### AC-5: Independent metric recalculation (FR-6, FR-7, NFR-5)
Given one lane with raw OOS and broker-forward closed trades, five folds, full
parity, and a verified validation receipt
When the issuer evaluates the lane twice with the same seed
Then both evaluations have identical counts, PF, drawdown, stress, bootstrap
bound, parity, evidence hash, and readiness result.

### AC-6: Per-lane isolation (FR-8)
Given raw observations contain two symbols, duplicate IDs, or OOS/forward time
overlap
When issuance is attempted
Then issuance fails with an explicit reason and no signed promotion receipt.

### AC-7: Evidence and parity gate (FR-8, FR-9)
Given a receipt verifier reports invalid or any parity report is not full
When issuance is attempted
Then evidence completeness is false and promotion evidence cannot be signed.

### AC-8: Safety locks survive complete evidence (FR-9, FR-16)
Given synthetic raw evidence satisfies every statistical threshold
When the issuer produces sealed readiness
Then manual ship gate remains required and all execution/promotion safety locks
remain false with maximum lot 0.01.

### AC-9: Separate read-only service profile (FR-10, FR-11)
Given a clean Git checkout and the reviewed service allowlist
When a service bundle is built twice
Then both archives are byte-identical and the manifest identifies
`READ_ONLY_SHADOW_SERVICE` with order capability disabled.

### AC-10: Service profile rejects capability drift (FR-11)
Given a service allowlist contains an executor, setup tool, secret, runtime
artifact, undeclared import, or order primitive
When the builder validates it
Then the build is rejected before an archive is written.

### AC-11: Windows reproducibility receipt (FR-12, NFR-4)
Given two distinct clean Windows CPython 3.12 build observations with identical
commit/tree/archive/manifest/release hashes
When an independent key signs the comparison
Then the receipt verifies and binds both build IDs and all exact hashes.

### AC-12: Reproducibility mismatch (FR-12)
Given either observation is dirty, non-Windows, not CPython 3.12, duplicated,
or has any identity/hash mismatch
When comparison is attempted
Then no receipt is issued and the mismatch reason is explicit.

### AC-13: Durable off-host acknowledgement (FR-13, FR-14, NFR-3, NFR-4)
Given a signed envelope is pending and a transport returns a valid independently
signed acknowledgement
When delivery runs
Then exactly that envelope becomes acknowledged and a restart preserves state.

### AC-14: Failed or forged off-host delivery (FR-15)
Given transport timeout or an acknowledgement with a bad signature/binding
When delivery runs
Then the envelope remains pending, the attempt/failure is durable, and delivery
status never claims acknowledged.

### AC-15: Safety regression gate (FR-16, NFR-6, NFR-8)
Given all new code and existing project code
When compilation, focused acceptance tests, the full test suite, release policy
checks, and ship-gate automated checks run
Then there are no regressions and no artifact changes a locked safety value.

## Edge Cases and Error Scenarios

- EC-1: Clock provider returns naive/future-regressing UTC → reject the cycle and
  latch the kill switch when lifecycle integrity is uncertain.
- EC-2: Supervisor database is locked/corrupt/disk write fails → stop and never
  report healthy; external watchdog remains responsible for process alerting.
- EC-3: Broker state call times out after a prior submit → reconcile remains
  uncertain and no resubmission occurs.
- EC-4: Trade R/cost is NaN/infinite, close time is naive, or ID is empty →
  issuer rejects the corpus.
- EC-5: Forward duration has fewer than two timestamps or any source overlaps
  the OOS cutoff → issuer rejects or reports insufficient duration.
- EC-6: Bootstrap corpus has no losses → PF is represented as a finite capped
  diagnostic value suitable for the existing finite contract, not infinity.
- EC-7: Release source changes during construction or an output exists → remove
  any partial paired output and fail.
- EC-8: Two reproducibility observations use the same build ID → reject as a
  replay rather than count it as independent reproduction.
- EC-9: Remote acknowledgement timestamp is naive, predates the envelope, is
  too far in the future, or is replayed for another envelope → reject and retain
  pending state.
- EC-10: Transport writes an envelope but acknowledgement is unavailable → retain
  pending state and allow idempotent retry with the same envelope ID.
- EC-11: HMAC key lookup fails or returns fewer than 32 bytes → fail closed and
  do not persist a false acknowledgement/receipt.
- EC-12: External provider, WORM store, or Windows host is unavailable → local
  foundation tests may pass, but ship status remains `NOT_READY`.

## API Contracts

```typescript
interface ReconciliationCycleReceipt {
  sequence: number;
  cycleId: string;
  ownerId: string;
  fenceToken: number;
  startedAtUtc: string;
  completedAtUtc: string;
  status: "COMPLETE" | "PENDING" | "CRITICAL_HOLD" | "FAILED";
  resultSha256: string;
  previousReceiptSha256: string;
  receiptSha256: string;
  killSwitchLatched: boolean;
}

interface PromotionCorpus {
  symbol: string;
  strategy: string;
  configSha256: string;
  oosTrades: ClosedTradeObservation[];
  forwardTrades: ClosedTradeObservation[];
  rollingFolds: RollingFoldObservation[];
  parityReports: ParityObservation[];
  validationReceipt: ValidationReceiptBinding;
}

interface PromotionIssuerResult {
  laneEvidenceSha256: string;
  readinessSha256: string;
  evidenceComplete: boolean;
  failures: string[];
  promotionReceiptSha256?: string;
  liveAllowed: false;
  safeToDemoAutoOrder: false;
  promotionEligible: false;
  maxLot: 0.01;
}

interface ReproducibilityObservation {
  buildId: string;
  hostAliasSha256: string;
  osName: "WINDOWS";
  pythonVersion: string;
  cleanCheckout: true;
  gitCommit: string;
  gitTree: string;
  archiveSha256: string;
  manifestSha256: string;
  releaseIdentitySha256: string;
  observedAtUtc: string;
}

interface DeliveryEnvelope {
  envelopeId: string;
  idempotencyKey: string;
  destinationId: string;
  artifactType: "HEARTBEAT" | "ALERT" | "AUDIT" | "BACKUP_ANCHOR";
  payloadSha256: string;
  createdAtUtc: string;
  senderKeyId: string;
  signatureHmacSha256: string;
}

interface DeliveryAcknowledgement {
  envelopeId: string;
  destinationId: string;
  payloadSha256: string;
  acknowledgedAtUtc: string;
  remoteKeyId: string;
  signatureHmacSha256: string;
}
```

Errors are typed local exceptions with stable uppercase reason codes. No HTTP
endpoint is introduced; network/storage providers implement the delivery port.

## Data Models

### Supervisor Lease

| Field | Type | Constraints |
|---|---|---|
| singleton | integer | PK, always 1 |
| owner_id | text | non-empty |
| fence_token | integer | positive, monotonically increasing |
| expires_at_utc | text | aware UTC |
| updated_at_utc | text | aware UTC |

### Reconciliation Cycle

| Field | Type | Constraints |
|---|---|---|
| sequence | integer | PK, autoincrement |
| cycle_id | text | unique, immutable |
| owner_id | text | non-empty |
| fence_token | integer | positive |
| payload_json | text | canonical JSON |
| previous_receipt_sha256 | text | 64 lowercase hex or zero anchor |
| receipt_sha256 | text | 64 lowercase hex, unique |

### Closed Trade Observation

| Field | Type | Constraints |
|---|---|---|
| trade_id | string | unique across corpus |
| symbol | string | canonical uppercase |
| strategy | string | uppercase |
| config_sha256 | string | 64 lowercase hex |
| source | enum | `OOS` or `BROKER_FORWARD` |
| closed_at_utc | datetime | aware UTC |
| r_multiple_before_cost | float | finite |
| measured_cost_r | float | finite, nonnegative |

### Rolling Fold Observation

| Field | Type | Constraints |
|---|---|---|
| fold_id | string | unique; exactly five per lane |
| expectancy_r | float | finite; positive fold iff > 0 |

### Reproducibility Receipt

| Field | Type | Constraints |
|---|---|---|
| receipt_id | string | content-derived, immutable |
| first_build_id | string | differs from second |
| second_build_id | string | differs from first |
| common hashes | SHA-256 | exact match across observations |
| issued_at_utc | datetime | aware UTC |
| signer_key_id | string | non-empty |
| signature_hmac_sha256 | SHA-256 | required for verified receipt |

### Delivery Outbox Record

| Field | Type | Constraints |
|---|---|---|
| envelope_id | string | PK, content-derived |
| idempotency_key | string | unique |
| envelope_json | text | canonical signed envelope |
| state | enum | `PENDING` or `ACKNOWLEDGED` |
| attempt_count | integer | nonnegative |
| last_error | text | sanitized, nullable |
| acknowledgement_json | text | immutable once set, nullable |

## Out of Scope

- OS-1: Enabling manual-demo, demo-auto, live trading, higher lot, or promotion
  flags — prohibited until separate approval and external gates pass.
- OS-2: Selecting/provisioning a cloud, Object Lock/WORM, alert vendor, VPN,
  credential manager, or key-management provider — operator/infrastructure work.
- OS-3: Claiming actual off-host durability or independent key custody from a
  local adapter/test — requires external attestation.
- OS-4: Broker/legal eligibility, official calendars, 20-session benchmark,
  8-week/50-forward/100-OOS evidence, demo soak, or XAU live canary.
- OS-5: Order executor implementation changes, broker order submission, kill
  switch reset automation, self-learning model promotion, or automatic scaling.
- OS-6: Replacing the modular-monolith/ports-adapters architecture with
  microservices — operational complexity is not justified for v1.
