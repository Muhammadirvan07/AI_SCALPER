# Spec: MT5 Read-Only Decision-Feed Publisher v1

**Author:** AI_SCALPER Engineering
**Date:** 2026-07-24
**Status:** Approved
**Reviewers:** Project owner under the approved Live-Grade v1 roadmap
**Related specs:** `signed_decision_feed_handoff_v1.md`,
`brokerless_decision_producer_service_v1.md`,
`windows_decision_service_release_v1.md`

## Context

The brokerless decision service now consumes a signed, append-only
`FinalizedM15DecisionInput` feed, but no production component currently turns
the exact read-only MT5 account observation into that feed. Reusing the
diagnostic paper-trading journal as this boundary would couple runtime
transport to diagnostic state and would not prove that the packet was created
inside the strict ten-second first-eligible-tick window.

This publisher remains in the separate read-only shadow/exporter process. It
receives only a capability-reduced `ReadOnlyMT5Facade`, an immutable feed
binding, externally supplied trusted-clock/key/account-identity/calendar
capabilities, and an already provisioned feed directory. It never receives the
original MetaTrader5 module, an order API, risk approval, permit, environment
arm, or execution journal.

## Functional Requirements

- FR-1: The publisher MUST bind one exact feed, broker server, keyed account
  identity, demo environment, closed lane set, broker symbol, M15 data
  contract, session calendar, and broker UTC-offset rule before reading market
  data.
- FR-2: Every cycle MUST re-attest
  `account.trade_allowed=false`, `terminal.trade_allowed=false`, and
  `terminal.tradeapi_disabled=true`; `account.trade_expert` MAY be observed
  but MUST NOT substitute for those three effective locks.
- FR-3: The connected account MUST be `DEMO`, use the exact broker server, and
  reproduce the feed-bound keyed account identity through a sealed external
  identity capability. Raw login MUST NOT be returned, logged, serialized, or
  accepted as configuration.
- FR-4: Each lane MUST read only finalized broker M15 bars through
  `ReadOnlyMT5Facade`, normalize broker wall-clock timestamps with the exact
  reviewed nonnegative offset, and require the bar tail to close at the current
  trusted UTC M15 boundary.
- FR-5: The publisher MUST select the first broker tick strictly after candle
  close and no later than ten seconds after close. Missing ticks before the
  deadline return `WAITING_ENTRY_TICK`; a stale/closed market or elapsed
  deadline MUST NOT publish a packet.
- FR-6: The publisher MUST compute every discontinuity in the bounded bar
  frame and request exactly one `SignedSessionClosureReceipt` for every gap
  from a sealed external calendar-receipt capability.
- FR-7: The observation MUST retain the exact canonical symbol, broker symbol,
  source name, data-contract hash, calendar hash, finalized bars, first
  eligible bid/ask, and tick time from the feed binding and broker read.
- FR-8: Publication MUST occur only while trusted UTC remains inside the entry
  window and within the lane's strict publish-lag budget after the first
  eligible tick. The publisher MUST pass the earlier of those two deadlines
  into the signed feed, which MUST re-read trusted UTC immediately before a
  new create-exclusive write. Clock regression, future tick, excessive
  latency, write-boundary deadline crossing, or source drift MUST fail closed
  without writing a packet.
- FR-9: Publication MUST delegate to the existing
  `SignedDecisionFeedDirectory` using an exact `DecisionFeedLaneBinding`.
  Idempotent replay MAY confirm the existing packet; conflicting same-candle,
  rollback, fork, tamper, or capacity failure MUST remain rejected by the feed.
- FR-10: One lane acquisition failure MUST produce a deterministic `HOLD`
  lane result without publishing that lane. Account, server, read-only
  attestation, or trusted-clock failure MUST reject the whole cycle before any
  lane publication.
- FR-11: The publisher MUST expose no MetaTrader5 initialization/login
  lifecycle, credential value, key provisioning, scheduler installation,
  subprocess, network client, risk, intent, permit, reconciliation, executor,
  or broker mutation surface.
- FR-12: The publisher and its release definition MUST preserve
  `order_capability=DISABLED`, `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `promotion_eligible=false`,
  `validation_evidence=false`, and `max_lot=0.01`.

## Non-Functional Requirements

- NFR-1: All trusted times MUST be timezone-aware UTC; naive, non-UTC,
  regressing, or inconsistent values fail closed.
- NFR-2: A lane MUST contain between the strategy minimum and 512 finalized
  bars, and its publish-lag budget MUST be positive and no greater than one
  second.
- NFR-3: The publisher binding, lane results, and cycle result MUST be
  immutable exact types with canonical deterministic hashes.
- NFR-4: Provider failures MUST be reduced to stable reason codes and MUST NOT
  expose secret values or raw account identifiers.
- NFR-5: Existing normal and `PYTHONOPTIMIZE=2` repository regressions MUST
  continue to pass.
- NFR-6: The read-only shadow release import closure MUST remain exact and
  source scanning MUST continue to reject order primitives.

## Acceptance Criteria

### AC-1: Exact current-boundary publication (FR-1, FR-3, FR-4, FR-5, FR-7, FR-9)

Given an exact demo account, continuous finalized M15 bars, and one eligible
bid/ask tick inside the ten-second window
When one publisher cycle runs within its latency budget
Then one signed feed packet exists for the exact lane
And the brokerless feed consumer reconstructs the exact observation.

### AC-2: Effective read-only locks are mandatory (FR-2, FR-10, FR-11)

Given any enabled account trading, terminal Algo Trading, or external Python
trading API capability
When a cycle begins
Then it fails before rates, ticks, identity publication, or feed writes
And no mutation API is reachable through the facade.

### AC-3: Account/server mismatch is global fail-closed (FR-1, FR-3, FR-10)

Given a connected server or keyed account identity different from the feed
binding
When a cycle begins
Then the whole cycle is rejected before any lane packet is written
And no raw login appears in the exception or result.

### AC-4: Entry timing is exact (FR-4, FR-5, FR-8; NFR-1)

Given no eligible tick yet, an old market bar, a tick outside the entry window,
or trusted UTC beyond the deadline
When the lane is observed
Then the result is waiting, stale, or missed as appropriate
And no packet is published.

### AC-5: Publish-lag budget is enforced (FR-8; NFR-1, NFR-2)

Given a valid first eligible tick but a regressing clock or processing latency
greater than the bound
When publication is attempted
Then the lane or cycle fails closed before a feed write
And the signed feed independently rejects a new write if its trusted clock has
crossed the supplied deadline after the publisher's final pre-write check.

### AC-6: Calendar gaps use an independent receipt source (FR-6, FR-7)

Given a finalized bar frame with one exact M15-aligned closure interval
When the publisher prepares the observation
Then the external receipt capability receives that exact interval
And exactly one exact signed receipt is included
And missing, extra, or wrong-type receipts reject publication.

### AC-7: Lane failures are isolated (FR-10)

Given a multi-lane binding where one symbol read fails and another lane is
valid
When a cycle runs
Then the failed lane returns `HOLD`
And the valid lane can publish
And the overall cycle visibly reports `HOLD`.

### AC-8: Signed-feed conflicts remain fail-closed (FR-9)

Given an existing packet for one lane and candle
When the same observation is replayed
Then the existing packet is confirmed idempotently
But a different observation for that candle is rejected without overwrite.

### AC-9: Capability boundary remains read-only (FR-11, FR-12; NFR-6)

Given the publisher source, facade, and read-only release allowlist
When capability tests inspect imports, attributes, and source tokens
Then no order/risk/permit/executor capability is present
And all six safety values remain locked.

### AC-10: Full regression remains green (FR-1–FR-12; NFR-5)

Given focused publisher/feed tests and the complete repository suite
When run normally and with `PYTHONOPTIMIZE=2`
Then every test passes without broker, credential, task, network, or order
side effects.

## Edge Cases

- EC-1: A lane exists in publisher configuration but not in the feed binding,
  or vice versa → reject binding construction.
- EC-2: Duplicate/case-colliding lane IDs or broker symbols → reject binding.
- EC-3: Broker offset is negative, above fourteen hours, or boolean → reject
  binding.
- EC-4: Rates are empty, duplicated, non-M15, non-finite, malformed, not
  finalized, or remain non-monotonic after deterministic timestamp
  normalization → lane `HOLD`, no packet. Raw provider ordering MAY be
  normalized before these checks.
- EC-5: Ask is below bid, tick is at/before close, tick is after ten seconds,
  or tick timestamp is ahead of trusted UTC → no packet.
- EC-6: Current bar has been prepublished by the broker → filter it; do not
  treat it as finalized.
- EC-7: Market is closed and the latest finalized bar is older than the current
  boundary → `STALE_MARKET`, not a replay of the old candle.
- EC-8: Calendar receipt provider raises or returns a list/subclass/wrong count
  → lane `HOLD` with no secret detail.
- EC-9: Feed key provider fails, wrong key is present, packet directory is
  unsafe, or write races → existing feed error remains fail-closed.
- EC-10: Account/terminal facts change between cycle attestations → next cycle
  fails before reading/publishing another lane.

## API Contracts

N/A — this component exposes no HTTP endpoint.
HTTP method/path: N/A — no `POST /api/mt5-feed` endpoint exists.

```typescript
interface MT5DecisionFeedPublisherLane {
  lane_id: string;
  broker_time_offset_seconds: number;
  bar_count: number;
  maximum_publish_lag_ms: number;
}

interface MT5DecisionFeedPublisherBinding {
  schema_version: "mt5-readonly-decision-feed-publisher-binding-v1";
  service_id: string;
  environment: "DEMO";
  feed_binding: DecisionFeedBinding;
  lanes: MT5DecisionFeedPublisherLane[];
  order_capability: "DISABLED";
  live_allowed: false;
  safe_to_demo_auto_order: false;
  max_lot: 0.01;
}

interface MT5DecisionFeedLaneResult {
  lane_id: string;
  symbol: string;
  status:
    | "PUBLISHED"
    | "WAITING_ENTRY_TICK"
    | "ENTRY_WINDOW_MISSED"
    | "STALE_MARKET"
    | "HOLD";
  bar_closed_at: CanonicalUtcTimestamp | null;
  packet_sha256: Sha256 | null;
  reason_code: string | null;
}

interface MT5DecisionFeedCycleResult {
  observed_at_utc: CanonicalUtcTimestamp;
  status: "OBSERVED" | "HOLD";
  lanes: MT5DecisionFeedLaneResult[];
  order_capability: "DISABLED";
}
```

The sealed account-identity capability accepts in-memory MT5 account facts and
returns only the keyed SHA-256 identity. The sealed session-closure capability
accepts one exact feed lane plus exact gap intervals and returns only exact
`SignedSessionClosureReceipt` values.

## Data Models

### Publisher lane

| Field | Constraint |
|---|---|
| `lane_id` | Exact case-sensitive member of `DecisionFeedBinding` |
| `broker_time_offset_seconds` | Integer, 0–50,400 |
| `bar_count` | Strategy minimum through 512 |
| `maximum_publish_lag_ms` | Integer, 1–1,000 |

### Publisher binding

| Field | Constraint |
|---|---|
| `service_id` | Non-empty immutable ID |
| `environment` | Exact `DEMO` for v1 |
| `feed_binding` | Exact immutable `DecisionFeedBinding` |
| `lanes` | Exact closed set matching feed lanes |
| safety fields | Exact locked literals |

### Gap interval

| Field | Constraint |
|---|---|
| `closed_from_utc` | Aware UTC M15 boundary |
| `closed_until_utc` | Later aware UTC M15 boundary |

### Cycle result

The cycle result is a deterministic immutable summary. It carries no raw
account facts, market-data frame, signing key, credential value, permit,
intent, position, order, or activation authority.

## Out of Scope

- OS-1: MetaTrader5 initialization, terminal login, password handling, and
  terminal shutdown remain in the reviewed Windows process launcher.
- OS-2: Key provisioning and Windows Credential Manager implementation remain
  external provider/custody responsibilities.
- OS-3: Issuing calendar closure receipts remains an independent calendar
  authority responsibility.
- OS-4: Validation evidence, WORM export, broker benchmarking, and promotion
  receipts remain separate from this runtime transport.
- OS-5: Risk approval, intent creation, permit, execution, reconciliation,
  manual-demo activation, demo-auto activation, and live activation remain
  downstream gated services.
- OS-6: M5 and crypto lanes remain diagnostic challengers and are not admitted
  to the live-grade v1 M15 decision publisher.
