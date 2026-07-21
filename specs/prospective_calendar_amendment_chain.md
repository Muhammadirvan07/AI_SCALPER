# Spec: Signed Prospective Session-Calendar Amendment Chain

**Author:** AI_SCALPER Engineering
**Date:** 2026-07-21
**Status:** Approved
**Reviewer:** Project owner through the explicit approval of the recommended prospective-amendment architecture
**Related specs:** `phillip_lane_evidence_contract.md`, `phillip_dual_terminal_shadow.md`

## Context

The immutable forward-evidence contract currently requires every holiday and
special-hours closure for the complete observation window to be known before
registration. That rule is safe but impractical for an eight-week broker
window because Phillip Securities Japan publishes some exceptional schedules
only after the regular calendar has been established. Treating a future notice
as if it were already known would be false evidence; waiting for every notice
would make prospective collection impossible.

This feature keeps the original regular-session calendar immutable and adds a
signed, append-only amendment chain. An amendment can only remove future M15
buckets from the open schedule. It cannot create a trading session, alter an
observed period, repair a missing bar after the fact, or unlock execution. A
separate signed completeness attestation is created only after the blind window
ends, confirming that the final amendment head and official-source inventory
were reviewed. Existing `forward-contract-v3` artifacts remain immutable and
load as legacy contracts with no amendment capability.

Architecture decision: the evidence store remains a modular monolith using
ports and filesystem adapters. The forward contract is the immutable aggregate
root; calendar amendments are authenticated domain events; the latest signed
head is a derived pointer; verification replays the immutable history to derive
the effective calendar. No broker or HTTP mutation interface is introduced.

## Functional Requirements

- FR-1: New contracts MUST use `forward-contract-v4` and MUST bind an explicit calendar-amendment policy; legacy `forward-contract-v3` contracts MUST remain readable and immutable.
- FR-2: An amendment-enabled policy MUST permit only `CLOSURE_ONLY_PROSPECTIVE_V1`, MUST bind a minimum lead time of at least one M15 bucket, and MUST require a post-window completeness attestation.
- FR-3: Contract registration MUST create an authenticated sequence-zero calendar-amendment record whose effective hashes equal the immutable base-calendar hashes.
- FR-4: A calendar amendment MUST bind the contract, sequence, previous record HMAC, unique amendment ID, trusted registration time, official HTTPS source metadata, exact affected symbols, exact M15-aligned closures, and resulting effective-calendar hashes.
- FR-5: An amendment MUST only convert buckets that are OPEN in the current effective calendar to CLOSED and MUST NOT reopen, move, widen, shorten, delete, or overlap an earlier closure.
- FR-6: An amendment MUST be registered before every affected bucket by at least the contract-bound minimum lead time and MUST be rejected after the blind boundary, after sealing, or after relevant broker evidence has already been appended.
- FR-7: Effective calendars MUST be derived deterministically by replaying every authenticated amendment in sequence and MUST retain an exact OPEN/CLOSED partition of the original observation window.
- FR-8: Segment append, raw-tick append, paired evidence, coverage verification, evidence roots, shadow planning, and receipts MUST use or bind the current effective calendar and amendment head.
- FR-9: A completeness attestation MUST be allowed only at or after `blind_until_utc`, before sealing, and MUST bind the final amendment head plus a non-empty reviewed official-source inventory.
- FR-10: Mechanical chain validity and calendar completeness MUST be reported separately; missing completeness attestation MUST keep coverage/promotion readiness false without making an otherwise authentic in-progress chain appear corrupt.
- FR-11: Local CLIs MUST support amendment registration and completeness attestation using the existing evidence signing-key provider and MUST NOT accept broker credentials, order arguments, or exported secret material.
- FR-12: Phillip FX and commodity templates MUST reflect the reviewed regular DST schedules using only fully tradable M15 buckets while special-hours attestation and profile registration remain disabled.
- FR-13: All generated artifacts and CLI output MUST retain `execution_enabled=false`, `live_allowed=false`, `safe_to_demo_auto_order=false`, `promotion_eligible=false`, and `max_lot=0.01` where those safety fields apply.

## Non-Functional Requirements

- NFR-S1: Every immutable record MUST use canonical SHA-256 plus HMAC-SHA256 and MUST fail closed on missing, reordered, duplicated, tampered, truncated, or head-mismatched history.
- NFR-S2: Trusted timestamps MUST be timezone-aware UTC; naive, future, stale, rollback, and non-monotonic claims MUST be rejected.
- NFR-S3: Source URLs MUST use HTTPS without embedded credentials, source document hashes MUST be lowercase SHA-256, and source publication/capture MUST precede amendment registration.
- NFR-S4: The first affected bucket MUST start at least 900 seconds after the trusted registration time; a contract MAY require a larger lead but MUST NOT require less.
- NFR-S5: Amendment and completeness writes MUST be protected by the existing per-contract write lock, create immutable history exclusively, and update a head atomically.
- NFR-S6: The current seal MUST prohibit further amendments or completeness writes, and the final evidence root MUST bind the amendment head and completeness artifact state.
- NFR-R1: A crash after immutable-history creation but before head replacement MUST be detectable and MUST NOT permit silent sequence reuse or conflicting history.
- NFR-R2: Existing v3 fixtures, four-symbol XM/FBS behavior, lane-subset behavior, and all project tests MUST remain compatible.
- NFR-A1: Errors MUST expose stable machine-readable codes and MUST not contain signing keys, account numbers, balances, credentials, or broker passwords.
- NFR-A2: The feature MUST remain diagnostic/evidence infrastructure only; it MUST NOT send orders, alter strategy decisions, or change risk limits.

## Acceptance Criteria

### AC-1: Versioned contract and genesis (FR-1, FR-2, FR-3)
Given a valid frozen snapshot, broker binding, instrument specification, base calendar, and amendment-enabled policy
When a new forward contract is registered
Then it is stored as `forward-contract-v4`
And immutable calendar-amendment history sequence zero and its atomic head are created with effective hashes equal to the base hashes.

### AC-2: Legacy compatibility (FR-1, NFR-R2)
Given an authentic existing `forward-contract-v3` artifact
When it is loaded, appended, or verified
Then its base calendar remains the effective calendar
And amendment or completeness registration is rejected as unsupported without mutating the artifact.

### AC-3: Valid prospective closure (FR-4, FR-5, FR-6, FR-7)
Given an unsealed amendment-enabled contract, trusted time, and a currently open future M15 interval beyond the minimum lead
When a signed official-source amendment closes that interval
Then exactly one immutable next-sequence record is created
And replay derives an exact partition with those buckets closed and all other buckets unchanged.

### AC-4: No hindsight repair (FR-5, FR-6, NFR-S2, NFR-S4)
Given a closure that begins too soon, is in the past, touches appended evidence, or was already closed
When amendment registration is attempted
Then it fails before any durable write with a specific reason code
And the previous amendment head remains unchanged.

### AC-5: Chain tamper detection (FR-7, NFR-S1, NFR-R1)
Given a contract with one or more amendments
When a history record is missing, modified, reordered, duplicated, orphaned from the head, or signed by another key
Then forward verification is invalid
And append, shadow collection, completeness attestation, sealing, and receipt generation fail closed.

### AC-6: Effective-calendar runtime parity (FR-8)
Given a valid amended calendar that removes a future M15 bucket
When bar planning, segment validation, raw-tick validation, reconciliation, coverage, and evidence-root calculation run
Then every component uses the same derived effective calendar and amendment head
And no component still expects evidence for the removed bucket.

### AC-7: Completeness attestation (FR-9, FR-10)
Given the blind boundary has passed, the contract is unsealed, the amendment chain is valid, and official source documents have been reviewed
When a signed completeness attestation binds the final head and source inventory
Then verification reports both chain validity and calendar completeness as true
And a later amendment, head change, source tamper, or second attestation is rejected.

### AC-8: Missing completeness remains blocked (FR-9, FR-10, FR-13)
Given a mechanically valid amended contract without a post-window completeness attestation
When verification or receipt generation runs after the blind window
Then evidence integrity can remain valid but calendar completeness and complete coverage remain false
And all promotion/live/order safety flags remain false.

### AC-9: Safe local CLIs (FR-11, FR-13, NFR-A1, NFR-A2)
Given a local Windows evidence-key provider and reviewed JSON input
When either calendar command is invoked
Then it prints the immutable artifact identity and disabled safety capabilities
And password, login, order, lot-change, live-enable, and exported-key arguments are unavailable.

### AC-10: Phillip regular schedules remain gated (FR-12, FR-13)
Given the reviewed official Phillip regular-session sources
When repository templates are inspected
Then FX and XAU schedules contain only fully eligible M15 buckets for the DST regime
And `special_hours_review.attested`, `registration_enabled`, execution, demo-auto, promotion, and live flags remain false.

## Edge Cases and Error Scenarios

- EC-1: Amendment policy is missing from v4, has an unknown field, lead below 900 seconds, or unsupported mode → Reject contract registration.
- EC-2: Amendment ID is invalid or already used → Reject without idempotent overwrite.
- EC-3: Source URL is HTTP, contains credentials, lacks a document hash, or has capture/publication after registration → Reject before history write.
- EC-4: Closure timestamp is naive, unaligned, zero-length, outside the contract window, or uses an unsupported reason → Reject.
- EC-5: Closure targets an unregistered symbol, a currently closed bucket, or overlaps another closure in the same request → Reject the entire amendment atomically.
- EC-6: Trusted clock rolls backward between initial validation and commit → Reject without head advancement.
- EC-7: Seal is active or blind time has started → Reject amendments; completeness remains subject to its separate post-window rules.
- EC-8: Completeness is attempted before blind, with an empty source inventory, against a stale head, or more than once → Reject.
- EC-9: History exists beyond the head after an interrupted commit → Verification reports an orphan-history failure; no automatic repair occurs.
- EC-10: Head references absent history or history has a gap → Verification reports a sequence failure.
- EC-11: Existing evidence includes a target bucket because of a corrupt/future clock → Amendment is rejected as touching observed evidence.
- EC-12: A base-calendar hash or instrument-spec calendar binding changes → Contract verification fails independently of the amendment chain.
- EC-13: Completeness attestation exists but its final-head HMAC or source-inventory hash differs → Completeness and overall verification fail.
- EC-14: An amendment-enabled contract has no amendments → Sequence-zero effective calendar is valid, but post-window completeness is still required.

## API Contracts

No network listener is introduced. For contract notation only, the local
application port is equivalent to `POST /local-evidence/calendar-amendments`;
the implemented adapters are Python functions and command-line programs.

```typescript
interface RegisterCalendarAmendmentRequest {
  artifactRoot: AbsolutePath;
  contractId: string;
  amendmentId: string;
  registeredAtUtc: UtcTimestamp;
  source: OfficialSourceDocument;
  closures: Record<CanonicalSymbol, CalendarClosure[]>;
  expectedPreviousHeadHmacSha256: SHA256;
}

interface AttestCalendarCompletenessRequest {
  artifactRoot: AbsolutePath;
  contractId: string;
  attestationId: string;
  attestedAtUtc: UtcTimestamp;
  finalAmendmentHeadHmacSha256: SHA256;
  reviewedSources: OfficialSourceDocument[];
}

interface EffectiveCalendarView {
  contract: ForwardContractV3 | ForwardContractV4;
  calendars: Record<CanonicalSymbol, SessionCalendarV1>;
  amendmentHead: CalendarAmendmentRecordV1 | null;
  amendmentChainVerified: boolean;
  completenessAttested: boolean;
}

interface CalendarSafetyState {
  execution_enabled: false;
  live_allowed: false;
  safe_to_demo_auto_order: false;
  promotion_eligible: false;
  max_lot: 0.01;
}
```

## Data Models

### Calendar Amendment Policy

| Field | Type | Constraints |
|---|---|---|
| mode | enum | `IMMUTABLE_BASE_V1` or `CLOSURE_ONLY_PROSPECTIVE_V1` |
| minimum_lead_seconds | integer | At least 900 and divisible by 900 |
| completeness_attestation_required | boolean | True for amendment-enabled policy |
| source_document_required | boolean | True for amendment-enabled policy |

### Calendar Amendment Record

| Field | Type | Constraints |
|---|---|---|
| schema_version | string | `calendar-amendment-v1` |
| contract_id / contract_hmac_sha256 | string | Exact immutable aggregate binding |
| sequence | integer | Zero-based contiguous sequence |
| amendment_id | string or null | Null only for genesis; otherwise unique |
| previous_amendment_hmac_sha256 | SHA-256 or null | Null only for genesis |
| registered_at_utc | UTC timestamp | Trusted and monotonic |
| source | object or null | Null only for genesis; HTTPS plus document hash |
| closures | map | Empty only for genesis; exact registered-symbol subset otherwise |
| effective_session_calendar_sha256 | map | Exact registered-symbol set |
| amendment_payload_sha256 | SHA-256 | Canonical record body hash |
| amendment_hmac_sha256 | HMAC-SHA256 | Evidence-key authentication |

### Calendar Completeness Attestation

| Field | Type | Constraints |
|---|---|---|
| schema_version | string | `calendar-completeness-v1` |
| attestation_id | string | Immutable unique ID |
| contract binding | strings | Contract ID and contract HMAC |
| final head binding | strings | Sequence and final amendment HMAC |
| attested_at_utc | UTC timestamp | At or after blind; trusted |
| reviewed_sources | list | Non-empty, normalized, HTTPS, content-hashed |
| reviewed_sources_sha256 | SHA-256 | Canonical list hash |
| payload/HMAC | SHA-256 strings | Canonical integrity and evidence-key signature |

### Effective Calendar View

| Field | Type | Constraints |
|---|---|---|
| base_session_calendars | map | Immutable contract calendars |
| effective_session_calendars | map | Deterministic replay result; never stored as mutable truth |
| amendment_sequence | integer | Latest verified sequence |
| amendment_head_hmac_sha256 | SHA-256 | Included in append artifacts and evidence root |
| amendment_chain_verified | boolean | Mechanical integrity only |
| calendar_completeness_attested | boolean | Independent post-window governance result |

## Out of Scope

- OS-1: Opening demo-auto or live order capability, changing `max_lot`, or issuing promotion permits.
- OS-2: Retroactive repair, reopening sessions, adding bars, or changing strategy/risk/model configuration through a calendar event.
- OS-3: Automatically scraping or trusting broker notices; an operator supplies reviewed official source documents and hashes.
- OS-4: Claiming off-host WORM storage or independent key custody; those remain explicit ship-gate requirements.
- OS-5: Enabling Phillip registration before regulatory review, regular-calendar review, and required source artifacts are complete.
- OS-6: Migrating or rewriting existing v3 contracts; compatibility is read-only and behavior-preserving.
- OS-7: Supporting timeframes other than the contract-bound M15 evidence grid.
