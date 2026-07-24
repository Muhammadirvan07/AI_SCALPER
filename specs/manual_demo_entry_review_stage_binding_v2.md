# Spec: Manual-Demo Entry Review Stage Binding v2

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-24
**Status:** Implemented
**Reviewers:** AI_SCALPER project owner (standing authorization to continue the
roadmap while preserving all execution locks)
**Related specs:** `specs/windows_manual_demo_entry_review_v1.md`,
`specs/demo_auto_stage_authorization_v1.md`,
`specs/production_runtime_supervisor_v1.md`

## Context

The Windows manual-demo entry verifier now proves that the exact three-service
review bundle and all nine externally signed pre-run observations are complete,
while the post-run ten-lifecycle observation is still absent. The existing
stage-authorization boundary separately authenticates a short-lived global
readiness receipt, two human approvals, and an exact `StageBinding`.

Before this change, those two evidence chains were not joined. A valid
`ManualDemoReadinessReceipt` and `StageReadinessRequest` could omit the content
hash of the exact `WindowsManualDemoEntryReview`. Consequently, the runtime
could prove that a stage authorization was authentic without proving which
pre-manual Windows review the readiness authority accepted.

This change makes the exact complete pre-manual review hash and its trusted UTC
check time mandatory in the signed readiness receipt, request, sealed
validation, and durable supervisor startup receipt. It does not import the
operator-only review verifier into the execution release and does not grant an
issuer, private-key loader, activation switch, environment arm, permit, or
broker-order capability.

## Functional Requirements

- FR-1: `ManualDemoReadinessReceipt` MUST bind one non-zero
  `pre_manual_entry_review_sha256`, the exact complete pre-manual status, and
  the review's timezone-aware UTC `checked_at`.
- FR-2: The pre-manual status MUST equal
  `PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS_COMPLETE_ACTIVATION_REVIEW_REQUIRED`.
  Blocked, post-manual, unknown, or caller-defined status values MUST fail.
- FR-3: The signed readiness window MUST start at or after the pre-manual
  review check and MUST expire no later than five minutes after that check.
  The stage request MUST remain fully inside the signed readiness window.
- FR-4: `StageReadinessRequest` MUST explicitly bind the same non-zero
  pre-manual review hash for both `MANUAL_DEMO` and `DEMO_AUTO`.
- FR-5: Stage issuance and validation MUST reject a mismatch between the
  request's review hash and the independently signed readiness receipt.
- FR-6: `StageAuthorizationValidation` MUST expose the exact review hash that
  was authenticated and consumed. Invalid results MUST still identify the
  request-bound review hash without claiming authority.
- FR-7: The runtime supervisor MUST verify that the sealed validation review
  hash equals the signed authorization request before it advances the replay
  checkpoint.
- FR-8: A `DEMO` or `DEMO_AUTO` startup receipt MUST persist the exact
  `stage_pre_manual_entry_review_sha256` alongside the authorization,
  validation, prior external checkpoint, and new replay checkpoint hashes.
- FR-9: Stage startup evidence MUST be all-or-none. Missing, zero, malformed,
  or inconsistent review evidence MUST fail before a `READY` receipt is
  appended.
- FR-10: The stage-readiness, stage-request, and supervisor-receipt schema
  versions MUST advance because their canonical payloads change.
- FR-11: Existing replay, two-human approval, exact binding, external
  checkpoint, risk, news, reconciliation, permit, environment-arm,
  idempotency, and server-side protection controls MUST remain unchanged.
- FR-12: Every artifact and validation result MUST retain
  `execution_authorized=false`, `activation_authorized=false`,
  `safe_to_demo_auto_order=false`, `live_allowed=false`, and
  `order_capability=DISABLED`.
- FR-13: The implementation MUST NOT make the operator-only
  `windows_manual_demo_entry_review` module a dependency of the execution
  release. The readiness authority is responsible for independently verifying
  that public artifact before signing its exact hash.

## Non-Functional Requirements

- NFR-1: Canonical serialization and SHA-256 values MUST be deterministic for
  identical inputs.
- NFR-2: Every timestamp MUST be timezone-aware UTC with offset zero; naive or
  non-UTC values MUST be rejected.
- NFR-3: The additional checks MUST use no network, filesystem, credential,
  private-key, MT5, or broker access.
- NFR-4: Stable uppercase reason codes MUST identify review-reference and
  freshness failures without exposing raw accounts or secret material.
- NFR-5: Focused, integration, full normal, and `PYTHONOPTIMIZE=2` tests MUST
  pass.
- NFR-6: Existing SQLite WAL, append-only trigger, HMAC-chain, replay, and
  external-checkpoint integrity guarantees MUST not be weakened.
- NFR-7: Existing stage validation and supervisor startup performance bounds
  MUST remain suitable for the five-minute authorization window.

## Acceptance Criteria

### AC-1: Complete review is bound end to end (FR-1, FR-4, FR-6, FR-7, FR-8)

Given a complete pre-manual entry review, a signed readiness receipt for its
exact hash, a matching stage request, two independent approvals, and a valid
stage authority signature
When the authorization is validated and consumed at a `DEMO` supervisor
startup
Then validation exposes the same pre-manual review hash
And the durable `STARTUP/READY` receipt contains that exact hash
And every execution and activation flag remains false.

### AC-2: Request/readiness substitution is rejected (FR-4, FR-5)

Given a signed readiness receipt for review A
And a stage request that names review B
When stage authorization issuance or validation runs
Then it rejects with
`MANUAL_READINESS_PRE_MANUAL_REVIEW_MISMATCH`
And no replay event or supervisor `READY` receipt is appended.

### AC-3: Blocked or unknown status cannot be signed (FR-2)

Given a readiness receipt draft with a blocked, post-manual, empty, or unknown
pre-manual status
When the readiness contract is constructed
Then construction fails before signing.

### AC-4: Stale review cannot cover a stage window (FR-3)

Given a pre-manual review check time
When readiness issuance occurs before that check or its expiry extends beyond
five minutes after that check
Then construction fails
And a stage request cannot use the receipt.

### AC-5: Validation rechecks the review binding (FR-5, FR-6)

Given an authorization and a different or tampered readiness receipt
When validation runs against a fresh replay registry
Then the result is invalid with deterministic mismatch reason codes
And `consumed_once` remains false
And the result still cannot grant execution.

### AC-6: Supervisor rejects forged validation provenance (FR-7, FR-9)

Given a stage validator returns a sealed result whose review hash does not
match the signed request
When supervisor startup evaluates it
Then startup fails closed before advancing the external replay checkpoint or
recording `READY`.

### AC-7: Shadow receipts remain review-free (FR-8, FR-9)

Given a `SHADOW` supervisor startup or cycle
When a receipt is appended
Then every stage field, including the pre-manual review hash, is null
And no stage authorization is consumed.

### AC-8: Stage receipt completeness is enforced (FR-8, FR-9)

Given a `DEMO` startup receipt draft with any one stage field absent, including
the pre-manual review hash
When the sealed receipt is constructed
Then it rejects the incomplete stage-evidence set.

### AC-9: No new capability surface appears (FR-11, FR-12, FR-13, NFR-3)

Given the changed modules, imports, APIs, and release allowlists
When static safety checks run
Then there is no operator-verifier import in the execution runtime
And no private-key loader, credential resolver, environment arm, permit
issuer, MT5 initialization, order check, or order send is added
And all safety locks remain false.

### AC-10: Regression remains green (FR-10, NFR-1, NFR-5, NFR-6)

Given the completed implementation
When focused, integration, compilation, dependency, release-policy, normal
full-regression, and optimized full-regression checks run
Then all tests pass
And Git diff validation reports no malformed changes.

## Edge Cases

- EC-1: The review hash is the all-zero SHA-256 → reject.
- EC-2: The review check timestamp is naive or has a non-zero UTC offset →
  reject.
- EC-3: The readiness receipt is issued exactly at review check time and expires
  exactly five minutes later → accept.
- EC-4: The readiness receipt is issued one microsecond before review check →
  reject.
- EC-5: The readiness receipt expires one microsecond after the five-minute
  review boundary → reject.
- EC-6: The request names the correct readiness receipt hash but a different
  review hash → reject independently of the receipt-reference match.
- EC-7: A subclass or unsealed stage validation attempts to inject a matching
  review hash → existing exact-type/seal checks reject it.
- EC-8: A replayed authorization has a valid review hash → replay rejection
  remains authoritative.
- EC-9: A `DEMO_AUTO` request has clean aggregate and promotion evidence but
  omits the pre-manual review hash → reject before issuance.
- EC-10: An old v1 readiness/request or v2 supervisor receipt is supplied to
  the new release → reject schema drift; do not silently infer a review hash.

## API Contracts

No network or HTTP API is added.

The updated signed readiness contract is:

```python
ManualDemoReadinessReceipt(
    binding_sha256=...,
    gate_receipts=...,
    source_validation_receipt_sha256=...,
    pre_manual_entry_review_sha256=...,
    pre_manual_entry_review_checked_at=...,
    pre_manual_entry_review_status=(
        "PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS_COMPLETE_"
        "ACTIVATION_REVIEW_REQUIRED"
    ),
    issued_at=...,
    expires_at=...,
    signer_key_id=...,
    nonce=...,
)
```

The updated request contract is:

```python
StageReadinessRequest(
    binding=...,
    manual_readiness_receipt_sha256=...,
    pre_manual_entry_review_sha256=...,
    acceptance_receipts=...,
    issued_at=...,
    expires_at=...,
    nonce=...,
    mode="MANUAL_DEMO" | "DEMO_AUTO",
    ...,
)
```

The validation result adds:

```python
pre_manual_entry_review_sha256: str
```

The supervisor startup receipt adds:

```python
stage_pre_manual_entry_review_sha256: str | None
```

It is non-null only when all other stage startup fields are non-null.

## Data Models

### `ManualDemoReadinessReceipt` additions

| Field | Type | Constraint |
|---|---|---|
| `pre_manual_entry_review_sha256` | SHA-256 | Non-zero exact canonical review hash |
| `pre_manual_entry_review_checked_at` | UTC datetime | At or before readiness issuance |
| `pre_manual_entry_review_status` | enum | Exact complete/pre-activation-review status |

### `StageReadinessRequest` addition

| Field | Type | Constraint |
|---|---|---|
| `pre_manual_entry_review_sha256` | SHA-256 | Must equal signed readiness receipt |

### `StageAuthorizationValidation` addition

| Field | Type | Constraint |
|---|---|---|
| `pre_manual_entry_review_sha256` | SHA-256 | Exact request-bound value, never authority |

### `RuntimeSupervisorCycleReceipt` addition

| Field | Type | Constraint |
|---|---|---|
| `stage_pre_manual_entry_review_sha256` | SHA-256 or null | Required with all stage fields for execution-mode startup; null otherwise |

No new table, credential record, raw account field, secret field, or broker
state is introduced.

## Out of Scope

- OS-1: Creating or signing the Windows pre-manual review observations.
- OS-2: Loading an offline private key or issuing readiness/stage evidence from
  the runtime service.
- OS-3: Materializing provider overlays, Credential Manager records, Task
  Scheduler tasks, Windows identities, or MT5 sessions.
- OS-4: Enabling `MANUAL_DEMO`, `SAFE_TO_DEMO_AUTO_ORDER`, `LIVE_ALLOWED`, or
  any broker order.
- OS-5: Replacing per-intent approval, one-second environment arm, permit,
  signed news, risk, preflight, idempotency, server-side protection, or
  reconciliation checks.
- OS-6: Recording or fabricating the ten controlled manual-demo lifecycles.
- OS-7: Creating the tenth post-manual observation, opening demo-auto soak, or
  claiming promotion/live readiness.
- OS-8: Changing maximum lot, risk caps, XAUUSD-first rollout, or pair
  expansion policy.
