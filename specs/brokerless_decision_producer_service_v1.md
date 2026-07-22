# Brokerless Decision Producer Service v1

## 1. Title and metadata

- Author: AI_SCALPER engineering
- Date: 2026-07-23
- Status: Approved for implementation
- Reviewers: live-grade architecture and ship-gate maintainers

## 2. Context

The live-grade architecture separates deterministic market decisions from every
broker mutation capability.  The existing pure decision core and signed
decision IPC already provide the two inner boundaries, but there is no reviewed
service which connects an injected read-only finalized-data source to those
boundaries while retaining a durable, independently-custodied per-lane cursor.

This service closes only that producer-side gap.  It does not authorize a demo
or live order and it is not a deployment configuration.  It exists so a future
Windows decision process can be wired to reviewed external data, clock, key
custody, and checkpoint services without importing an execution adapter.

## 3. Functional requirements

- **FR-1** The service MUST accept market input only through a sealed read-only
  provider port exposing one fetch operation.
- **FR-2** Each input MUST contain one configured lane, exact finalized UTC M15
  bars, and the first eligible bid/ask observation after the candle boundary.
- **FR-3** Data QC MUST reject non-UTC, unaligned, duplicate, unordered,
  non-final, non-finite, non-positive, or invalid OHLC bars. A timestamp gap is
  accepted only when one exact signed closure receipt covers every missing M15
  slot under the lane-bound session-calendar hash.
- **FR-4** The service MUST reject source name, data-contract, session-calendar,
  symbol, timeframe, freshness, alignment, trusted-clock, or entry-window drift.
- **FR-5** The service MUST compute the decision-data SHA-256 from the exact
  normalized bars, quote, source contract, session-calendar hash, exact closure
  receipt hashes, lane, and candle boundary; it MUST NOT trust a
  provider-supplied decision-data hash.
- **FR-6** The service MUST invoke `build_decision_snapshot`, the existing pure
  shared decision-core adapter, and MUST publish only the exact sealed
  `DecisionSnapshot` through a producer-only IPC port derived from
  `DecisionIPCProducer`.
- **FR-7** At most one exact decision MAY be published for a lane/candle.  The
  exact snapshot hash MUST first be externally checkpointed as `PREPARED` and
  MUST become `PUBLISHED` only after IPC publication. Equal candle
  re-observation MUST be idempotent and older candles MUST fail closed.
- **FR-8** A durable SQLite cursor MUST be bound to the immutable service/lane
  configuration and MUST validate its complete append-only checkpoint chain on
  every opening and mutation boundary.
- **FR-9** Every cursor advance MUST use an external compare-and-swap provider,
  an externally verified exact acknowledgement, and exact post-write readback.
- **FR-10** Restart after publication but before the `PUBLISHED` cursor advance MUST recover by
  recognizing only the decision IPC queue's exact duplicate-snapshot denial,
  then completing the same external-CAS cursor advance.
- **FR-11** Restart after external CAS but before local append MUST import only
  the single exact externally-custodied successor of the local head.
- **FR-12** The runner MUST support a positive bounded cycle count or a
  continuous loop with an injected stop predicate.  It MUST NOT permit an
  unbounded loop without a stop predicate.
- **FR-13** Per-lane input/QC errors MUST produce a non-publishing `HOLD` result.
  Cursor, IPC, custody, or trusted-clock integrity failures MUST stop the
  service.
- **FR-14** The CLI MUST require explicit decision-only acknowledgement and MUST
  offer a validate-only mode that performs no network, broker, or IPC mutation.
- **FR-15** Calendar closure and producer-cursor CAS acknowledgements MUST be
  exact HMAC-authenticated values verified through sealed, binding-pinned
  capabilities. An arbitrary truthy callback MUST NOT establish either trust
  domain.

## 4. Non-functional requirements

- **NFR-1 Security:** production code MUST contain no broker SDK import, account
  credential input, execution adapter, permit, risk approval, or order method.
- **NFR-2 Safety:** `LIVE_ALLOWED`, `SAFE_TO_DEMO_AUTO_ORDER`, and lot locks MUST
  remain unchanged.
- **NFR-3 Durability:** SQLite MUST use WAL, `synchronous=FULL`, foreign keys,
  busy timeout, immediate mutation transactions, and filesystem indirection
  rejection.
- **NFR-4 Determinism:** the same lane/input/config MUST produce the same sealed
  snapshot content hash and decision run ID across restart.
- **NFR-5 Time:** the first eligible quote and trusted processing clock MUST
  remain within the configured maximum processing lag and the shared ten-second
  post-candle window.
- **NFR-6 Capability isolation:** the service-facing data, calendar-verifier,
  cursor-verifier, and publisher ports MUST be immutable, slot-only objects
  exposing neither their underlying callback/object nor execution-like methods.

## 5. Acceptance criteria

- **AC-1 (FR-1, FR-6, NFR-1, NFR-6):** Given sealed read and publish ports, when
  a valid input is processed, then exactly one sealed snapshot is sent to the
  decision IPC producer and neither service port exposes broker mutation state.
- **AC-2 (FR-2 through FR-5):** Given malformed, stale, drifted, or non-final
  data, when a cycle runs, then it returns `HOLD` and publishes nothing.
- **AC-3 (FR-7, FR-8):** Given a published lane/candle and a process restart,
  when the same candle is observed again, then it is `ALREADY_PROCESSED` and no
  second envelope is appended.
- **AC-4 (FR-9):** Given a rejected, malformed, unverified, or inconsistent CAS
  acknowledgement/readback, when cursor advancement is attempted, then local
  state does not advance and the service raises an integrity error.
- **AC-5 (FR-10):** Given a crash after IPC publication, when the same exact
  input is retried, then exact duplicate denial is treated as recovery and the
  cursor advances once.
- **AC-6 (FR-11):** Given an external head one valid successor ahead of local
  state, when the store reopens, then it imports that successor; a jump, fork,
  rollback, or invalid binding is rejected.
- **AC-7 (FR-12):** Given a bounded count, the runner executes exactly that many
  cycles; given continuous mode, it stops only through the injected predicate.
- **AC-8 (FR-14):** Given missing acknowledgement or a non-validate CLI mode,
  the command fails closed without constructing runtime ports.
- **AC-9 (FR-3, FR-15):** Signed exact weekend, holiday, and DST-shifted UTC
  closures retain the required market-bar history; missing, extra, partially
  covering, cross-calendar, future, or tampered receipts return `HOLD` without
  publication.
- **AC-10 (FR-9, FR-15):** A raw `lambda _: True`, forged cursor CAS HMAC,
  wrong verification-key fingerprint, or external checkpoint rollback is
  rejected before local custody can advance.

## 6. Edge cases

- **EC-1** Weekend, holiday, and DST gaps are not inferred from weekdays or a
  local timezone. Only exact aware-UTC intervals signed under the immutable
  lane calendar hash are accepted; market history is never padded with fake
  bars.
- **EC-2** A quote at or before candle close, after ten seconds, ahead of the
  trusted clock, or older than the configured processing lag is rejected.
- **EC-3** An equal candle with changed data is rejected as a replay/fork rather
  than treated as idempotent.
- **EC-4** Empty input returns `NO_INPUT` and does not change custody state.
- **EC-5** SQLite symlink/reparse paths, schema drift, payload tamper, case
  collision, and chain rollback are rejected.
- **EC-6** An exception from the read-only source becomes a per-lane `HOLD`; an
  exception from trusted custody, clock, or IPC publication is service-fatal.

## 7. API contracts

```text
DecisionProducerLaneConfig
  lane_id: str
  symbol: str
  source_name: str
  data_contract_sha256: sha256
  model_version: str
  model_artifact_sha256: sha256
  commit_sha: git hash
  config_sha256: sha256
  session_calendar_sha256: sha256
  session_calendar_issuer_id: str
  session_calendar_key_id: str
  session_calendar_key_fingerprint_sha256: sha256
  maximum_processing_lag_ms: int

FinalizedM15DecisionInput
  lane_id: str
  symbol: str
  source_name: str
  data_contract_sha256: sha256
  session_calendar_sha256: sha256
  source_aligned: bool
  data_fresh: bool
  bar_closed_at: UTC datetime
  first_eligible_bid: float
  first_eligible_ask: float
  first_eligible_at: UTC datetime
  finalized_bars: pandas.DataFrame (defensively copied)
  session_closure_receipts: tuple[SignedSessionClosureReceipt, ...]

ReadOnlyFinalizedM15ProviderPort.fetch(lane) -> FinalizedM15DecisionInput | None
VerifiedSessionCalendarPort.verify_exact_closure(receipt, exact gap) -> None
DecisionProducerCASVerifierPort.verify(acknowledgement) -> bool
DecisionSnapshotPublishPort.publish(snapshot, issued_at_utc) -> DecisionIPCEnvelope
BrokerlessDecisionProducerService.run_cycle() -> DecisionProducerCycleResult
BrokerlessDecisionProducerService.run(max_cycles?, stop_requested?) -> tuple[result]
```

## 8. Data models

| Entity | Required fields | Constraints |
|---|---|---|
| Binding | service ID, calendar-bound lanes, custody issuer/key fingerprint | immutable canonical hash |
| Session closure | lane, symbol, calendar hash, exact UTC interval, issuer/key, HMAC | verified exact gap only |
| Lane cursor | lane ID, symbol, candle close, snapshot hash, state | sorted, unique; `PREPARED` → exact `PUBLISHED` |
| Checkpoint | sequence, predecessor, binding, cursors, issued time | append-only exact chain |
| CAS acknowledgement | expected/observed/accepted heads, result, time | exact type plus external verifier |
| Local state | binding row and checkpoint rows | SQLite WAL/FULL, schema v1 |

## 9. Out of scope

- Broker SDKs and direct broker connectivity.
- Account/server credentials or credential-session receipts.
- Risk decisions, trade intents, permits, approvals, reconciliation, or order
  submission.
- Demo-auto or live activation, deployment, and service credentials.
- Calendar-authoring policy and market-hours inference. The producer only
  verifies exact externally authored closure receipts.
- Promotion evidence.  Producer diagnostics are not broker-forward evidence.
