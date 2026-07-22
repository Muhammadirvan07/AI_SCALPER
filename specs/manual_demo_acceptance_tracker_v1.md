# Spec: Durable Deny-Only Manual-Demo Acceptance Tracker v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-22
**Status:** Approved
**Reviewers:** AI_SCALPER project owner (explicit implementation instruction on 2026-07-22)
**Related specs:** `specs/account_currency_risk_caps_and_locked_manual_demo_readiness.md`, `specs/architecture_foundation_completion_v1.md`, `specs/demo_auto_soak_tracker_v1.md`

## Context

The live-grade roadmap requires 10 controlled manual-demo orders to prove the
preflight, broker acknowledgement/fill/reject, server-side SL/TP protection,
close, and reconciliation lifecycle before a later demo-auto soak can begin.
The current runtime has sealed MT5 preflight, submission-guard, execution, and
broker-reconciliation types, but no separate durable acceptance ledger that
counts complete clean lifecycles and resets the clean run after a critical
incident.

This feature adds a deny-only, HMAC-anchored SQLite tracker. It consumes only existing sealed
broker types or an HMAC-verified reconciliation-cycle receipt, binds every row
to one exact account/server/journal/build/config/lane, and derives acceptance
progress without creating any broker capability. Its identity, append chain,
materialized state, and exportable assessment checkpoint use domain-separated
HMAC-SHA-256 with a mandatory external key provider. Even after 10 clean completed
orders, this tracker cannot authorize manual-demo, demo-auto, promotion,
execution, or live trading.

## Functional Requirements

- FR-1: The tracker MUST bind one database and tracker UUID to exactly one account-alias SHA-256, broker server, source-journal SHA-256, Git commit hash, configuration SHA-256, lane identifier, key ID, and key fingerprint.
- FR-2: Reopening a database with any changed binding field MUST fail closed before returning or appending evidence.
- FR-3: The tracker MUST use the existing exact sealed `MT5Preflight` and `MT5SubmissionGuard` types as its only preflight input and MUST reject subclasses, mappings, booleans, or caller-created lookalikes.
- FR-4: One preflight observation MUST bind matching intent ID and broker-spec hash, and its submission guard MUST bind the configured account-alias hash and exact server.
- FR-5: The tracker MUST use the existing exact sealed `ExecutionReceipt` type as its only broker acknowledgement/fill/reject input and MUST bind it to an already observed intent, account, server, symbol, and nondecreasing UTC timestamp.
- FR-6: The tracker MUST use the existing exact sealed broker reconciliation evidence type as its only per-intent reconciliation input and MUST bind it to an already observed controlled order.
- FR-7: Orphan, unexplained, aggregate reconciliation, or other cycle-level facts MUST be accepted only through a receipt whose HMAC-SHA256 signature is verified with an injected trusted key provider; raw mappings MUST never be recorded directly.
- FR-8: The HMAC reconciliation-cycle receipt MUST bind the tracker binding hash, receipt ID, observed UTC, orphan-position tickets, orphan-order tickets, unexplained-position tickets, protection failures, volume failures, binding failures, critical reason codes, kill-switch state, signing-key ID, and schema version.
- FR-9: The tracker MUST persist preflight, execution, per-intent reconciliation, and verified cycle observations in an append-only, domain-separated HMAC-SHA-256 chain. Legacy field names `previous_event_sha256` and `event_sha256` remain compatibility aliases for predecessor/event HMAC values.
- FR-10: Every source observation MUST have a deterministic unique hash, and reusing an observation, receipt, execution receipt ID, cycle receipt ID, or intent lifecycle stage MUST fail closed without changing state.
- FR-11: The tracker MUST record whether preflight passed, broker outcome was acknowledged/partial/filled/rejected/uncertain, server-side SL/TP was confirmed, and a broker-derived close was reconciled.
- FR-12: A clean completed order MUST have, after the latest reset, one passed preflight with a clean submission guard, one broker acknowledgement/partial/fill outcome, at least one reconciliation confirming server-side SL/TP, and one valid broker exit-deal close reconciliation.
- FR-13: Preflight rejection and definitive broker rejection MUST be tracked but MUST NOT count as a clean completed order.
- FR-14: Submission uncertainty, reconciliation uncertainty, nonzero exposure in a submission guard, missing SL/TP on a filled/partial position, close without prior protection confirmation, orphan exposure, unexplained exposure, protection/volume/binding failure, kill-switch latch, or a signed critical reason MUST be a critical incident.
- FR-15: A critical incident MUST permanently latch tracker status `FAILED`, reset the clean acceptance run after that event, and retain all earlier audit rows.
- FR-16: The tracker MUST count unique clean completed intent IDs after the latest reset and MUST set `criteria_observed=true` at 10 or more.
- FR-17: Every assessment MUST report `ready=false`, `promotion_eligible=false`, `execution_enabled=false`, `manual_demo_enabled=false`, `safe_to_demo_auto_order=false`, `live_allowed=false`, and `order_capability=DISABLED` regardless of evidence or counts.
- FR-18: All supplied, sealed, verified, stored, and assessment timestamps MUST be timezone-aware UTC and MUST be nondecreasing by event sequence. Observations MUST NOT predate tracker creation or exceed the injected trusted clock; assessments MUST NOT exceed that clock.
- FR-19: Startup, append, listing, verification, assessment, and checkpoint issuance MUST fail closed on SQLite integrity, schema, trigger, unapproved index, binding, identity HMAC, canonical payload, sequence, HMAC chain, event semantics, state HMAC, or durable-head drift.
- FR-20: A deleted chain tail MUST be detected when the durable head remains intact, and restart MUST preserve every valid lifecycle, counter, critical reset, and latch.
- FR-21: The module MUST NOT submit, modify, cancel, or close a broker order; mint or validate an execution permit/approval; read an environment arm; clear a latch; or change execution policy.
- FR-22: `assessment_receipt()` MUST return a sealed HMAC checkpoint bound to exact tracker/binding/key identity, creation time, event count/head, latest event, all assessment counters/status/blockers, permanent failure state, assessment time, and all deny constants.
- FR-23: Reopen or explicit integrity verification MAY accept the latest independently held checkpoint and MUST reject an invalid signature, wrong tracker/binding/key, future checkpoint, rolled-back count, missing/changed prefix, fork/rewrite, lost critical/rejection/orphan history, cleared permanent latch, unexplained reset advancement, or same-head assessment drift.
- FR-24: Valid local progress MAY extend a checkpoint prefix. Within the same clean run, lifecycle counters MUST be nondecreasing. A reset may advance only with additional critical evidence.

## Non-Functional Requirements

- NFR-1: Every connection MUST verify SQLite WAL mode, `synchronous=FULL`, foreign keys, and a 10-second busy timeout; every write MUST use `BEGIN IMMEDIATE`.
- NFR-2: Event insertion and durable-head update MUST commit atomically, while any validation or duplicate failure MUST commit neither.
- NFR-3: SQLite table definitions and append-only trigger definitions MUST be verified exactly, not by name alone.
- NFR-4: Binding hashes, observation hashes, event hashes, HMAC signatures, and durable heads MUST be lowercase 64-character SHA-256 values; Git commit hashes MUST contain 7 through 64 hexadecimal characters.
- NFR-5: HMAC keys MUST contain at least 32 bytes and MUST NOT be persisted in SQLite, event payloads, assessments, or exceptions.
- NFR-6: The tracker MUST store no raw account alias, password, balance, equity, authorization object, order request, or secret material.
- NFR-7: Assessment MUST be deterministic for the same verified database and `as_of_utc`.
- NFR-8: Automated tests MUST cover every acceptance criterion and adversarial edge case in this specification.
- NFR-9: Tracker identity, event, state, and assessment HMACs MUST use separate domains; the mandatory key provider MUST return at least 32 bytes. Raw key material MUST never be persisted or exported.

## Acceptance Criteria

### AC-1: Exact binding and restart (FR-1, FR-2, FR-20)

Given a valid database bound to one account/server/journal/commit/config/lane
When valid lifecycle evidence is appended and the tracker restarts with the same binding
Then all events, counts, head hash, and latch state are identical
And any binding-field change raises a binding error.

The same key ID/secret reopens successfully; changing key ID or secret fails
closed. Reopening against a newer off-host assessment checkpoint rejects an
older valid database, while a genuine prefix extension remains valid.

### AC-2: Sealed preflight boundary (FR-3, FR-4, FR-18)

Given a matching sealed MT5 preflight and sealed submission guard
When the tracker records them
Then it persists their content hashes and normalized facts without persisting raw request or account alias
And a mapping, subclass, directly constructed lookalike, mismatched intent/spec/account/server, or naive timestamp is rejected.

### AC-3: Sealed execution boundary (FR-5, FR-10, FR-11)

Given a previously observed passed preflight
When a matching sealed execution receipt reports acknowledged, partial, filled, rejected, or uncertain
Then the exact outcome and receipt hash are persisted once
And a raw object, binding mismatch, unknown intent, backdated receipt, or duplicate is rejected atomically.

### AC-4: Sealed reconciliation boundary (FR-6, FR-11, FR-12)

Given a controlled order with passed preflight and broker acknowledgement/fill
When sealed reconciliation evidence confirms its position SL/TP and later confirms a valid broker exit-deal close
Then protection and closed/reconciled facts are linked to that intent
And an unsealed mapping, unknown intent, invalid source, or duplicate is rejected.

### AC-5: Ten clean completed orders are observed but cannot unlock (FR-12, FR-16, FR-17)

Given 10 unique intent lifecycles completed after the latest reset with passed preflight, broker fill/ack, confirmed SL/TP, and broker-derived close reconciliation
When the tracker assesses them
Then `clean_completed_orders=10` and `criteria_observed=true`
And all manual-demo, demo-auto, execution, promotion, ready, and live flags remain false with `order_capability=DISABLED`.

### AC-6: Rejects do not count (FR-11, FR-13)

Given a sealed rejected preflight or definitive rejected execution receipt
When it is recorded
Then the rejection counter increases
And no completed-order count increases.

### AC-7: Critical per-intent evidence resets and latches (FR-14, FR-15)

Given completed clean orders followed by submission uncertainty, missing server protection, reconciliation uncertainty, or close without confirmed protection
When the critical sealed observation is appended
Then status becomes `FAILED_LATCHED`, the clean run resets after that event, and prior rows remain
And the latch survives restart.

### AC-8: Signed orphan/unexplained cycle resets and latches (FR-7, FR-8, FR-14, FR-15, NFR-5)

Given an HMAC-signed reconciliation-cycle receipt bound to this tracker with orphan or unexplained exposure
When it is verified with the trusted key provider and recorded
Then the incident counts are persisted, status becomes `FAILED_LATCHED`, and the clean run resets
And a forged signature, short key, unknown key, changed body, wrong binding, or raw mapping is rejected without append.

### AC-9: Duplicate evidence is atomic (FR-10, NFR-2)

Given any previously recorded sealed or signed observation
When the same source receipt, source hash, intent stage, or cycle receipt ID is recorded again
Then a duplicate error is raised
And event count, head, lifecycle facts, and critical counts remain unchanged.

### AC-10: Naive, non-UTC, or decreasing time fails closed (FR-18)

Given a sealed or signed observation with a naive, nonzero-offset, or decreasing timestamp, or an assessment before the latest event
When the tracker processes it
Then validation fails before persistence or assessment.

### AC-11: Tamper and tail deletion fail closed (FR-19, FR-20, NFR-3)

Given a valid multi-event chain
When payload, predecessor, event HMAC, identity HMAC, state HMAC, schema SQL, append-only trigger SQL, or durable head is changed, or the tail is deleted
Then restart and assessment raise an integrity error before returning progress.

### AC-12: SQLite profile and append-only enforcement (FR-9, FR-19, NFR-1, NFR-2)

Given an intact tracker
When storage is inspected and an external client attempts event update/delete
Then WAL, FULL sync, foreign keys, busy timeout, and exact triggers are present
And SQLite rejects event update/delete and durable-head deletion.

### AC-14: Sealed assessment checkpoint and rollback anchor (FR-22, FR-23, FR-24, NFR-9)

Given an independently held signed checkpoint
When an older valid database, divergent legitimate fork, coherently rewritten
same-length chain, regressed permanent counter, wrong key, wrong binding, or
future checkpoint is presented
Then reopen fails closed with an integrity, binding, or rollback error
And direct construction or field mutation of the checkpoint cannot verify.

### AC-13: No execution or unlock surface (FR-17, FR-21, NFR-6)

Given the public API and a criteria-complete database
When source, methods, and serialized assessment are inspected
Then no order runner, mutation adapter, permit, approval, arm, unlock, latch-clear, account alias, or secret is exposed
And all safety fields remain constant deny values.

## Edge Cases and Error Scenarios

- EC-1: Existing empty, partial, foreign, weakened, or extra-table databases are rejected rather than initialized or migrated.
- EC-2: Missing singleton binding/head rows, duplicate JSON keys, noncanonical JSON, sequence gaps, invalid event types, and malformed hashes fail closed.
- EC-3: Equal UTC timestamps are allowed; sequence remains authoritative. Decreasing, pre-creation, and future timestamps are prohibited.
- EC-4: A reconciliation event before preflight/execution is rejected; a close after a critical reset cannot count unless its full lifecycle occurs after that reset.
- EC-5: Multiple protection confirmations may be recorded only when their sealed evidence hashes differ; exact repeats are duplicates.
- EC-6: Partial fill with confirmed protection may proceed toward close, but partial/missing protection is critical and cannot count.
- EC-7: A clean signed reconciliation cycle is tracked without resetting; any critical list entry or kill-switch latch resets once for that event.
- EC-8: Local verification alone cannot distinguish replacement by an older internally valid database. Operations therefore MUST export each accepted assessment receipt to independent append-only/immutable custody and supply the latest accepted receipt on every reopen.
- EC-9: SQLite WAL or FULL sync unavailability fails initialization.

## API Contracts

No HTTP API is introduced; in particular, there is no `POST /manual-demo-acceptance` endpoint.

```typescript
interface ManualDemoBinding {
  account_alias_sha256: string;
  broker_server: string;
  journal_sha256: string;
  commit_sha: string;
  config_sha256: string;
  lane_id: string;
  binding_sha256: string;
}

interface SignedReconciliationCycleBody {
  schema_version: "manual-demo-reconciliation-cycle-v1";
  receipt_id: string;
  binding_sha256: string;
  observed_at_utc: string;
  orphan_position_tickets: string[];
  orphan_order_tickets: string[];
  unexplained_position_tickets: string[];
  protection_failures: string[];
  volume_failures: string[];
  binding_failures: string[];
  critical_reason_codes: string[];
  kill_switch_latched: boolean;
  signing_key_id: string;
  signature_hmac_sha256: string;
}

interface ManualDemoAssessment {
  assessed_at_utc: string;
  status: "OBSERVING" | "CRITERIA_OBSERVED_LOCKED" | "FAILED_LATCHED";
  clean_completed_orders: number;
  criteria_observed: boolean;
  failed_latched: boolean;
  preflight_passed_orders: number;
  broker_acknowledged_or_filled_orders: number;
  rejected_orders: number;
  sl_tp_confirmed_orders: number;
  closed_reconciled_orders: number;
  critical_incidents: number;
  orphan_positions: number;
  orphan_orders: number;
  unexplained_positions: number;
  ready: false;
  promotion_eligible: false;
  execution_enabled: false;
  manual_demo_enabled: false;
  safe_to_demo_auto_order: false;
  live_allowed: false;
  order_capability: "DISABLED";
}

interface ManualDemoAcceptanceTracker {
  record_preflight(preflight: SealedMT5Preflight, guard: SealedMT5SubmissionGuard): EventReceipt;
  record_execution(receipt: SealedExecutionReceipt): EventReceipt;
  record_reconciliation(evidence: SealedBrokerReconciliationEvidence): EventReceipt;
  record_reconciliation_cycle(receipt: VerifiedReconciliationCycleReceipt): EventReceipt;
  assessment(as_of_utc: Date): ManualDemoAssessment;
  assessment_receipt(as_of_utc: Date): ManualDemoAssessmentReceipt;
  events(): EventReceipt[];
  verify_integrity(expected_receipt?: ManualDemoAssessmentReceipt): boolean;
  storage_profile(): Record<string, string | number | boolean>;
}
```

`verify_reconciliation_cycle_receipt(payload, key_provider)` is the only raw
cycle-receipt boundary. It verifies HMAC and returns a sealed internal value;
the tracker rejects the original mapping.

`verify_manual_demo_assessment_receipt(receipt, key_provider)` verifies an
off-host checkpoint without trusting the local database. The tracker
constructor requires `key_id`, `key_provider`, and a trusted UTC clock, and
accepts an optional `expected_receipt` rollback anchor.

## Data Models

### `manual_demo_binding`

| Field | Type | Constraints |
|---|---|---|
| singleton | integer | primary key, exactly 1 |
| schema_version | text | exactly `manual-demo-acceptance-tracker-v1` |
| tracker_id | text | immutable generated UUID namespace |
| account_alias_sha256 | text | 64 lowercase hex; raw alias prohibited |
| broker_server | text | nonempty exact binding |
| journal_sha256 | text | 64 lowercase hex |
| commit_sha | text | 7..64 lowercase hex |
| config_sha256 | text | 64 lowercase hex |
| lane_id | text | nonempty |
| binding_sha256 | text | canonical binding SHA-256 |
| key_id | text | exact external key identifier |
| key_fingerprint_sha256 | text | SHA-256 fingerprint only; never secret |
| created_at_utc | text | canonical trusted UTC |
| identity_hmac_sha256 | text | domain-separated identity HMAC |

### `manual_demo_events`

| Field | Type | Constraints |
|---|---|---|
| sequence | integer | autoincrement primary key; contiguous from 1 |
| event_id | text | deterministic unique ID |
| observation_sha256 | text | unique sealed/signed source hash |
| stage_key | text | uniqueness scope for lifecycle stage or cycle ID |
| event_type | text | preflight, execution, reconciliation, or cycle |
| intent_id | text | nullable only for cycle events |
| observed_at_utc | text | canonical microsecond UTC |
| critical | integer | exactly 0 or 1 |
| payload_json | text | canonical, binding-bound, deny-only facts |
| previous_event_sha256 | text | compatibility name for genesis zero HMAC or prior event HMAC |
| event_sha256 | text | compatibility name for unique domain-separated event HMAC |

### `manual_demo_head`

| Field | Type | Constraints |
|---|---|---|
| singleton | integer | primary key, exactly 1 |
| event_count | integer | equals event row count |
| head_sequence | integer | equals last sequence or zero |
| head_sha256 | text | last event hash or zero hash |
| state_hmac_sha256 | text | HMAC of exact head plus replay-derived assessment projection |

## Out of Scope

- OS-1: Submitting, modifying, cancelling, or closing any broker order.
- OS-2: Creating an order runner, execution adapter, permit, approval, environment arm, promotion, unlock, or latch-clear path.
- OS-3: Changing execution policy, enabling manual-demo/demo-auto/live flags, or changing lot/risk limits.
- OS-4: Claiming demo-auto soak completion, strategy profitability, legal eligibility, production security, broker benchmark completion, or live readiness.
- OS-5: Persisting full broker requests, raw account aliases, credentials, balances, equity, HMAC keys, or other secrets.
- OS-6: Accepting raw caller assertions as broker or reconciliation evidence.
- OS-7: Externally anchored WORM/HMAC assurance against a caller that can coherently rewrite both the SQLite journal and its local head projection.
- OS-7: Implementing the off-host/WORM transport itself. The signed receipt
  and rollback verification boundary are implemented, but custody remains an
  operational dependency and promotion blocker when absent.
