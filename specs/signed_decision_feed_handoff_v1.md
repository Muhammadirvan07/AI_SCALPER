# Spec: Signed Decision Feed Handoff v1

**Author:** AI_SCALPER Engineering  
**Date:** 2026-07-24  
**Status:** Approved  
**Reviewers:** Project owner under the approved Live-Grade v1 roadmap and
standing instruction to continue toward demo-auto soak while preserving every
activation lock  
**Related specs:** `windows_decision_service_release_v1.md`,
`windows_three_service_provider_evidence_input_assembly_v1.md`,
`windows_configured_overlay_candidate_preparation_v1.md`

## Context

The brokerless Windows decision service accepts an exact
`FinalizedM15DecisionInput`, but no production source currently constructs that
type. Broker-facing read-only diagnostics can fetch finalized M15 bars and the
first eligible bid/ask tick, while the decision release intentionally contains
no MT5 SDK, network client, account access, or broker capability. The two
processes therefore have no reviewed handoff through which broker observations
can reach the `FINALIZED_M15_DATA` provider role.

The verified `d153361` base releases prove deterministic packaging, but they do
not close this runtime data boundary. Treating diagnostic SQLite or
`data/*.csv` as the provider would lose exact broker/account binding,
authenticity, conflict detection, and first-eligible-tick semantics. Reusing
validation-evidence archives would also be incorrect because those archives
serve blinded validation and may finalize after the ten-second decision entry
window.

This feature defines a broker-neutral, signed, append-only filesystem handoff.
It authenticates one bounded observation window and reconstructs the exact
brokerless input type without granting trust to the filesystem. It remains a
runtime transport only: it is not validation evidence, provider-conformance
evidence, activation authority, risk approval, or permission to place an
order.

## Functional Requirements

- FR-1: The handoff MUST use an immutable `DecisionFeedBinding` that binds one
  feed ID, exact broker server, exact broker-account identity hash, publisher
  issuer/key identity, publisher key fingerprint, and a non-empty closed set of
  lane bindings.
- FR-2: Each lane binding MUST bind the exact lane ID, canonical symbol,
  broker symbol, source name, data-contract hash, and session-calendar hash
  expected by the brokerless decision producer.
- FR-3: The publisher MUST accept only an exact
  `FinalizedM15DecisionInput` whose lane, symbol, source, data contract, session
  calendar, M15 boundary, finalized bars, quote, and session-closure receipts
  match the selected binding.
- FR-4: The publisher MUST encode each observation as canonical UTF-8 JSON
  containing no unknown fields, duplicate keys, non-finite numbers, naive
  timestamps, secret value, credential, account login, balance, or order
  payload.
- FR-5: Every packet MUST contain a per-lane positive sequence, the prior
  packet content hash or the zero hash at genesis, an observation hash, exact
  publisher identity, canonical issuance time, publisher key fingerprint, and
  HMAC-SHA256 over a domain-separated canonical signing payload.
- FR-6: Publisher and consumer MUST obtain signing/verification key material
  only through a caller-supplied key provider, MUST require at least 32 bytes,
  and MUST verify the material against the fingerprint pinned in the binding.
- FR-7: Publication MUST use one create-exclusive regular file per lane
  sequence, flush file contents durably, and MUST NOT overwrite, truncate,
  rename, delete, acknowledge, or mutate an existing packet.
- FR-8: Repeating the same semantic lane/candle observation MUST be idempotent
  and return the existing verified packet; a different observation for the
  same lane/candle or a concurrent sequence fork MUST fail closed.
- FR-9: A newer observation MUST reference the exact verified current head,
  increment sequence by one, and reject candle rollback, a non-increasing
  boundary, a missing sequence, an invalid immediate predecessor, or a lane
  directory beyond its reviewed capacity.
- FR-10: The consumer MUST stable-read only regular non-symlink/non-reparse
  files beneath the exact configured directory, enforce canonical JSON and
  closed schemas, verify binding, hashes, signature, sequence, immediate
  predecessor, publisher time, and packet size before returning data.
- FR-11: The consumer MUST return `None` only when no packet exists for the
  requested lane; any malformed, forged, stale, future, forked, missing, or
  binding-inconsistent packet MUST raise a stable fail-closed error.
- FR-12: A verified packet MUST reconstruct an exact
  `FinalizedM15DecisionInput` with a defensive-copy pandas frame and exact
  `SignedSessionClosureReceipt` objects, after which the existing producer MUST
  remain responsible for full bar, gap, calendar, freshness, and ten-second
  entry-window validation.
- FR-13: The module MUST expose a factory that returns the existing sealed
  `ReadOnlyFinalizedM15ProviderPort`; arbitrary duck-typed provider results
  MUST remain rejected.
- FR-14: The implementation MUST expose no broker SDK, network, subprocess,
  environment-secret lookup, credential-store, risk, permit, reconciliation,
  executor, task-control, service-control, or order API.
- FR-15: The module MUST retain `order_capability=DISABLED`,
  `live_allowed=false`, `safe_to_demo_auto_order=false`, and `max_lot=0.01`,
  and MUST state that packets are not promotion or validation evidence.
- FR-16: The module MUST be included in
  `WINDOWS_DECISION_SERVICE_V1` as the reviewed implementation option for the
  existing `FINALIZED_M15_DATA` provider role without adding a new provider
  role or changing its provider contract.
- FR-17: Existing decision-producer, configured-release, factory-template, and
  decision-IPC public contracts MUST remain backward compatible.

## Non-Functional Requirements

- NFR-1: A packet MUST contain between 1 and 512 bars, MUST be no larger than
  4 MiB, and a lane MUST contain no more than 10,000 packets before explicit
  feed rotation is required.
- NFR-2: At the 10,000-packet boundary, locating and verifying a valid head
  MUST read at most the head and immediate predecessor packet bodies; directory
  enumeration MAY inspect names but MUST NOT parse every historical body.
- NFR-3: Identical binding, observation, predecessor, sequence, issuance time,
  and key material MUST produce byte-identical canonical packet bytes and
  hashes on CPython 3.12 across macOS and Windows.
- NFR-4: A successful write MUST use `O_EXCL`, mode `0600` where supported,
  file `fsync`, and directory `fsync` where supported; a failed new write MUST
  remove only its incomplete new file.
- NFR-5: All public errors MUST use stable uppercase reason codes and MUST NOT
  include source file contents, raw market frames, credentials, key material,
  account identifiers, balances, or signed packet bodies.
- NFR-6: Focused tests MUST pass under normal Python and
  `PYTHONOPTIMIZE=2`; the full repository regression and deterministic release
  tests MUST remain green.

## Acceptance Criteria

### AC-1: Exact signed round trip (FR-1, FR-2, FR-3, FR-4, FR-5, FR-6, FR-7, FR-10, FR-12, FR-13; NFR-3, NFR-4)

Given a valid binding, exact M15 decision input, empty real directory, and
matching 32-byte publisher key
When the publisher writes sequence one and the sealed provider fetches its lane
Then the packet is canonical, domain-separated, hash-bound, and create-exclusive
And the provider returns an exact `FinalizedM15DecisionInput` equal to the
original observation through defensive copies.

### AC-2: Idempotent replay and conflict denial (FR-7, FR-8, FR-9)

Given a verified packet for one lane and candle
When the same semantic observation is published again
Then no second file is created and the existing packet is returned
And when any bar, quote, receipt, or binding field differs for that candle the
publication fails with `FEED_CANDLE_CONFLICT`.

### AC-3: Ordered per-lane head (FR-5, FR-9, FR-10; NFR-2)

Given two valid increasing observations in one lane
When they are published and fetched
Then sequence two references sequence one's exact content hash
And the consumer returns only sequence two after verifying its immediate
predecessor without parsing all historical packet bodies.

### AC-4: Tamper and forgery fail closed (FR-4, FR-5, FR-6, FR-10, FR-11)

Given a previously valid packet
When canonical content, signature, payload hash, issuer, key fingerprint,
binding, sequence, predecessor, or filename is changed
Then fetching raises a stable feed-integrity reason
And no decision input is returned.

### AC-5: Unsafe filesystem objects fail closed (FR-7, FR-10, FR-11; NFR-4)

Given a packet directory or matching packet path that is missing, oversized,
unstable, symlinked, junctioned, reparse-pointed, non-regular, unreadable, or
already occupied by conflicting bytes
When publish or fetch runs
Then it rejects without overwriting an existing object or leaving a partial
new packet.

### AC-6: Strict schema and bounded input (FR-4, FR-10, FR-11; NFR-1)

Given JSON with duplicate or unknown keys, non-finite values, non-canonical
timestamps, zero hashes, more than 512 bars, more than 4 MiB, or a lane with
more than 10,000 packets
When it is parsed or enumerated
Then it is rejected before key-provider or decision-core use.

### AC-7: Missing input is distinct from invalid input (FR-10, FR-11, FR-13)

Given a valid empty directory containing no packet for the requested lane
When the provider fetches that lane
Then it returns `None`
And any matching but invalid packet instead raises an integrity error.

### AC-8: Producer remains the semantic authority (FR-12, FR-17)

Given a cryptographically valid packet with source freshness false, an invalid
OHLC row, an undeclared bar gap, or a quote outside the entry window
When the existing producer consumes the reconstructed input
Then the producer rejects or holds it under its existing reason path
And the handoff does not bypass producer validation.

### AC-9: Capability boundary remains deny-only (FR-13, FR-14, FR-15, FR-16)

Given the module, decision release allowlist, import closure, CLI surface, and
manifest
When they are inspected and the release is built
Then no broker, credential, network, risk, permit, executor, task, or order
capability is present
And all four safety locks retain their exact values.

### AC-10: Backward compatibility and regression (FR-16, FR-17; NFR-6)

Given the completed implementation and updated exact decision release
allowlist
When focused, optimized, full-regression, import-closure, forbidden-token, and
deterministic-release tests run
Then every test passes
And existing producer/factory/IPC callers require no API change.

## Edge Cases and Error Scenarios

- EC-1: Key provider raises, returns the wrong type, returns fewer than 32
  bytes, or returns a different fingerprint → `FEED_KEY_UNAVAILABLE` or
  `FEED_KEY_FINGERPRINT_MISMATCH`; write/read nothing further.
- EC-2: Trusted clock is naive, non-UTC, ahead/behind inconsistently, or
  regresses between reads → `FEED_CLOCK_INVALID`.
- EC-3: Disk becomes full or access is denied after exclusive creation →
  remove only the incomplete new file and return `FEED_WRITE_FAILED`.
- EC-4: Two publishers race for the same next sequence → exactly one
  create-exclusive write may succeed; the loser stable-reads the winner and
  returns it only for the same semantic observation.
- EC-5: Two publishers race with different next candles → the loser rejects
  the winner as a sequence conflict and does not create a fork.
- EC-6: A matching lane filename has the wrong width, suffix, case, sequence,
  or an unrecognized additional segment → `FEED_DIRECTORY_INVALID`.
- EC-7: Sequence one has a non-zero predecessor or a later sequence has a zero,
  absent, or mismatching predecessor → `FEED_CHAIN_INVALID`.
- EC-8: Historical packet names have a gap or duplicate/case collision →
  `FEED_CHAIN_INVALID`, even when the newest packet is otherwise signed.
- EC-9: Packet issuance is more than one second in the future of trusted UTC →
  `FEED_CLOCK_INVALID`; freshness of market data remains an existing producer
  decision.
- EC-10: The directory contains files for another valid lane → ignore those
  files when fetching the requested lane.
- EC-11: The requested lane does not exist in the binding → reject rather than
  returning `None`.
- EC-12: Immediate predecessor changes between its metadata checks → reject the
  entire fetch as unstable.
- EC-13: A packet has a valid HMAC but source freshness false → reconstruct it;
  the existing producer subsequently rejects it, proving signatures do not
  create semantic truth.
- EC-14: Session-closure receipt list is empty with continuous bars → accept;
  an invalid receipt structure is rejected during reconstruction.

## API Contracts

No HTTP, network, broker, credential-store, subprocess, service-control, task,
risk, execution, or order endpoint is introduced.
HTTP method/path: N/A — no `POST /api/decision-feed` or other HTTP endpoint
exists; the following interfaces are in-process Python contracts only.

```typescript
interface DecisionFeedLaneBinding {
  lane_id: string;
  symbol: string;
  broker_symbol: string;
  source_name: string;
  data_contract_sha256: Sha256;
  session_calendar_sha256: Sha256;
}

interface DecisionFeedBinding {
  schema_version: "signed-decision-feed-binding-v1";
  feed_id: string;
  broker_server: string;
  broker_account_identity_sha256: Sha256;
  publisher_issuer_id: string;
  publisher_key_id: string;
  publisher_key_fingerprint_sha256: Sha256;
  lanes: DecisionFeedLaneBinding[];
  order_capability: "DISABLED";
  live_allowed: false;
  safe_to_demo_auto_order: false;
  max_lot: 0.01;
}

interface DecisionFeedBar {
  open_time_utc: CanonicalUtcTimestamp;
  Open: FinitePositiveNumber;
  High: FinitePositiveNumber;
  Low: FinitePositiveNumber;
  Close: FinitePositiveNumber;
  is_final: boolean;
}

interface SignedDecisionFeedPacket {
  schema_version: "signed-decision-feed-packet-v1";
  feed_id: string;
  lane_id: string;
  symbol: string;
  broker_symbol: string;
  broker_server: string;
  broker_account_identity_sha256: Sha256;
  source_name: string;
  data_contract_sha256: Sha256;
  session_calendar_sha256: Sha256;
  source_aligned: boolean;
  data_fresh: boolean;
  bar_closed_at: CanonicalUtcTimestamp;
  first_eligible_bid: FinitePositiveNumber;
  first_eligible_ask: FinitePositiveNumber;
  first_eligible_at: CanonicalUtcTimestamp;
  finalized_bars: DecisionFeedBar[];
  session_closure_receipts: SignedSessionClosureReceipt[];
  sequence: PositiveInteger;
  previous_packet_sha256: Sha256;
  observation_sha256: Sha256;
  issued_at_utc: CanonicalUtcTimestamp;
  publisher_issuer_id: string;
  publisher_key_id: string;
  publisher_key_fingerprint_sha256: Sha256;
  signature_hmac_sha256: Sha256;
  order_capability: "DISABLED";
  live_allowed: false;
  safe_to_demo_auto_order: false;
  max_lot: 0.01;
  validation_evidence: false;
  promotion_eligible: false;
}

interface DecisionFeedPublisher {
  publish(
    lane: DecisionProducerLaneConfig,
    observation: FinalizedM15DecisionInput,
    issued_at_utc: CanonicalUtcTimestamp
  ): SignedDecisionFeedPacket;
}

interface DecisionFeedConsumer {
  fetch(
    lane: DecisionProducerLaneConfig,
    trusted_now: CanonicalUtcTimestamp
  ): FinalizedM15DecisionInput | null;
}
```

Errors are stable `DecisionFeedError.reason_code` values. Error messages MUST
contain the reason code only.

## Data Models

### DecisionFeedLaneBinding

| Field | Type | Constraints |
|---|---|---|
| `lane_id` | string | Non-empty, unique and case-collision-free |
| `symbol` | uppercase string | Exact canonical strategy symbol |
| `broker_symbol` | string | Exact read-only broker catalog symbol |
| `source_name` | string | Exact producer source binding |
| `data_contract_sha256` | SHA-256 | Non-zero, immutable |
| `session_calendar_sha256` | SHA-256 | Non-zero, immutable |

### DecisionFeedBinding

| Field | Type | Constraints |
|---|---|---|
| `feed_id` | string | Non-empty immutable identity |
| `broker_server` | string | Exact reviewed server |
| `broker_account_identity_sha256` | SHA-256 | Non-zero alias hash; never raw login |
| `publisher_*` | strings/SHA-256 | Exact issuer, key ID, and non-secret fingerprint |
| `lanes` | tuple | Non-empty, sorted canonical closed set |
| safety fields | literals | `DISABLED`, `false`, `false`, `0.01` |

### SignedDecisionFeedPacket

| Field group | Type | Constraints |
|---|---|---|
| identity/binding | strings and SHA-256 | Exact match to binding and lane |
| market observation | timestamps, finite numbers, bars | 1–512 bars, canonical UTC, M15 boundary |
| session receipts | tuple | Closed exact receipt schema |
| chain | integer and SHA-256 | Sequence 1 uses zero predecessor; later uses verified head |
| publisher proof | identity, time, SHA-256 | Domain-separated HMAC, 32-byte minimum key |
| safety | literals | No activation, evidence, promotion, or order authority |

### Filesystem lane stream

| Property | Type | Constraints |
|---|---|---|
| directory | absolute real directory | Pre-provisioned, non-symlink, non-reparse |
| filename | canonical ASCII | Full lane hash + fixed-width sequence + `.json` |
| file | regular immutable JSON | Create-exclusive, ≤4 MiB, mode `0600` where supported |
| retention | append-only v1 | Maximum 10,000 packets per lane; rotation is external |

## Out of Scope

- OS-1: MT5 data acquisition and broker-session login — stays in the
  read-only shadow/exporter process so the decision release remains brokerless.
- OS-2: Issuing session-calendar closure receipts — remains an independent
  reviewed calendar authority and key-custody responsibility.
- OS-3: Independent off-host/WORM validation evidence — a local feed packet is
  runtime transport and cannot satisfy promotion evidence.
- OS-4: Provider-conformance acceptance — requires external real-provider
  probes and review artifacts under the existing conformance spec.
- OS-5: Mutable head files, packet deletion, compaction, or automatic rotation
  — deferred because v1 prioritizes create-exclusive behavior.
- OS-6: M5 or crypto decision lanes — the live-grade v1 decision producer is
  fixed to finalized M15.
- OS-7: Risk approval, `TradeIntent`, permit issuance, reconciliation,
  execution, demo-auto activation, or live activation — separate gated
  services and external acceptance remain mandatory.
