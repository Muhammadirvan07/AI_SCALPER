# DEMO_AUTO Soak Projection v1

## Status and scope

This component is the fail-closed evidence bridge from a reviewed dormant
`DEMO_AUTO` session and authenticated broker reconciliation facts into
`DemoAutoSoakTracker`. It records what already happened; it cannot submit,
modify, cancel, or retry a broker order and it cannot activate a runtime.

All returned objects and status payloads retain these locks:

- `execution_authorized=false`
- `activation_authorized=false`
- `safe_to_demo_auto_order=false`
- `live_allowed=false`
- `order_capability=DISABLED`

The projection contains no MT5 adapter, broker callback, order dispatcher,
credential, promotion permit, or PnL calculation. Profit, commission, swap,
fee, account balance, and account-currency PnL remain only inside the already
signed upstream broker deal receipt and are never copied into projection or
soak-tracker payloads.

## Exact trust binding

`DemoAutoSoakProjectionBinding` joins an exact `SoakBinding` to an exact
`DemoAutoSessionBinding`. Construction fails unless both identify the same:

1. DEMO candidate, hashed account alias, server, canonical symbol, and lane;
2. journal, commit, configuration, broker-spec, and model hashes;
3. strategy and session identity; and
4. immutable stage binding used to mint the dormant session capability.

Execution evidence, broker evidence, the local projection ledger, independent
checkpoint custody, activation source, closed-deal source, and incident source
use explicit issuer/key identities. Control-plane keys and source keys must be
distinct. The caller supplies key providers; secret material is not persisted.

## Accepted evidence flow

The only supported sequence is:

1. `project_activation(...)` verifies the exact current
   `DemoAutoSessionLease` and `DemoAutoSessionCheckpoint` through the exact
   `DemoAutoSessionCapabilityStore`. It projects one authenticated
   `SOAK_STARTED` fact but does not activate execution.
2. `observe_execution(...)` accepts only an exact sealed DEMO_AUTO
   `TradeIntent`, its sealed `DecisionSnapshot`, a sealed FILLED or RECONCILED
   `ExecutionReceipt`, and a fresh HMAC execution envelope bound to the current
   lease, account, server, symbol, tickets, decision, build, model, and session.
3. `observe_reconciliation(...)` accepts a fresh HMAC
   `BrokerReconciliationReceipt`, exact `ReconciliationResult`, and exact
   monotonic predecessor chain. A clean result becomes an observed fact.
4. `project_closed_trade(...)` accepts only a sealed
   `BrokerClosedTradeReceipt` whose nested sealed `BrokerDealReceipt` objects
   belong to that previously observed execution and clean reconciliation.
   Each distinct exit deal projects exactly one `CLOSED_FILL`.

Manual, PAPER, shadow, synthetic, unsealed, stale, future-dated, wrong-account,
wrong-server, wrong-symbol, wrong-intent, wrong-ticket, wrong-build, wrong-model,
wrong-session, or HMAC-invalid inputs fail closed. Projection never infers a
closed trade from price bars or from an execution receipt alone.

## Idempotency, restart, and concurrency

A broker deal identity includes candidate, hashed account, server, provider,
broker source sequence, and deal ticket. Its tracker event ID is deterministic
from the complete authenticated upstream chain. Therefore:

- an exact replay returns the existing receipt;
- a changed fact under the same identity is rejected;
- restart after the tracker write but before the local projection write safely
  completes the same local event without a second `CLOSED_FILL`; and
- concurrent identical projection attempts serialize through SQLite and
  converge on one projection event and one tracker event.

The component never retries an order while resolving an uncertain projection.

## Critical reconciliation incidents

The following broker reconciliation facts immediately create one authenticated
`CRITICAL_INCIDENT` and latch the soak tracker's demotion state:

| Broker fact | Projected reason |
| --- | --- |
| orphan position | `ORPHAN_BROKER_POSITION` |
| orphan order | `ORPHAN_BROKER_ORDER` |
| missing/invalid server SL or TP | `MISSING_SERVER_SLTP` |
| filled/position volume mismatch | `BROKER_VOLUME_MISMATCH` |
| account, server, symbol, intent, or ticket binding mismatch | `BROKER_BINDING_MISMATCH` |
| kill switch or other critical hold | `CRITICAL_RECONCILIATION` |

Reason selection uses that priority when a receipt reports multiple failures.
Exact receipt replay is idempotent; a forked receipt or source sequence is
rejected. A critical incident cannot be cleared by process restart.

## Persistence and independent custody

The local projection database uses SQLite `journal_mode=WAL`,
`synchronous=FULL`, a signed immutable identity, HMAC-chained append-only event
and checkpoint tables, and UPDATE/DELETE denial triggers. Each append holds the
SQLite single-writer fence until an independent custody adapter:

1. accepts the exact predecessor/head through compare-and-swap;
2. returns a signed acknowledgement; and
3. reads back the exact accepted checkpoint.

Startup verifies schema, identity, every event, every checkpoint, local head,
and the external head. Rollback, truncation, equal-height fork, invalid HMAC,
unexpected schema, CAS conflict, or readback mismatch leaves the projector
unusable. If external custody accepts a checkpoint but the local commit later
fails, the resulting external-ahead state deliberately remains fail-closed and
requires reviewed recovery; it is not silently repaired.

## Time and source limitations

All timestamps are timezone-aware UTC. Execution/reconciliation/source
evidence is deliberately short-lived and must be projected by the online
reconciler within its configured freshness window. Multiple broker exit deals
with exactly the same source timestamp are not given invented ordering; if the
soak tracker cannot accept their strict event ordering, the batch fails closed
for reconciliation review. Actual signed broker timestamps remain preserved.

## Public API

- `DemoAutoSoakProjectionBinding(...)`
- `verify_demo_auto_execution_evidence(...)`
- `DemoAutoSoakProjection.project_activation(...)`
- `DemoAutoSoakProjection.observe_execution(...)`
- `DemoAutoSoakProjection.observe_reconciliation(...)`
- `DemoAutoSoakProjection.project_closed_trade(...)`
- `DemoAutoSoakProjection.status()`
- `issue_demo_auto_soak_projection_cas_acknowledgement(...)` for an independent
  custody adapter

## Acceptance criteria

1. Exact activation/session evidence projects `SOAK_STARTED` once.
2. Exact FILLED/RECONCILED execution and clean closed-deal evidence projects
   one `CLOSED_FILL` per broker deal across replay, restart, and concurrency.
3. Manual/PAPER/shadow/synthetic/unsealed/tampered/cross-binding evidence is
   rejected before tracker mutation.
4. Orphan, protection, volume, binding, and generic critical reconciliation
   states project authenticated incidents and latch demotion.
5. Local tamper, external rollback/fork, replay conflict, and broken custody
   CAS/readback fail closed.
6. No projection payload contains PnL, balance, commission, swap, or fee data.
7. No public method exposes broker execution or changes any safety lock.

## Reliability target

This is a single-tenant, low-QPS, security-sensitive evidence path. RPO is zero
for locally committed and custody-confirmed facts. The restart target is five
minutes after exact local/external head reconciliation. Availability loss is
handled by refusing projection and activation, never by relaxing validation.
