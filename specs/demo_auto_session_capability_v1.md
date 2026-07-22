# DEMO_AUTO Session Capability v1

## Status and scope

This component is a dormant, non-executable foundation for a future reviewed
DEMO_AUTO composition root. It does not authorize an order, contain a broker
adapter, expose an order callback, or change either repository policy lock.

- `LIVE_ALLOWED=false`
- `SAFE_TO_DEMO_AUTO_ORDER=false`
- `order_capability=DISABLED`
- environment restricted to `DEMO`

The existing stage validator consumes a `StageReadinessAuthorization` exactly
once. `DemoAutoSessionCapabilityStore.create()` accepts only the matching
sealed `StageAuthorizationValidation` and records the single `CREATE` event.
Subsequent continuity uses only short-lived signed `RENEW` leases; it never
re-consumes or replaces the startup authorization.

The ledger and session IDs are deterministically derived from the stage
binding hash, authorization ID/hash, and validation hash. The external custody
adapter must enforce `ledger_id` as a globally unique namespace. Consequently,
the same consumed startup result cannot be provisioned under an operator-chosen
second name or against a second local database: the authoritative external
namespace is already non-empty.

## Exact binding

Every lease binds all of the following:

1. exact `StageBinding` and its content hash;
2. hashed account alias, broker server, lane ID, and DEMO environment;
3. journal, commit, config, dependency lock, runtime profile, and model hashes;
4. exact `RuntimeSupervisorBinding`;
5. exact signed supervisor checkpoint hash, event count, and issue time;
6. startup authorization ID/hash and sealed validation hash;
7. predecessor lease hash; and
8. independently custodied session-checkpoint CAS predecessor.

A lease has a maximum lifetime of 60 seconds (30 seconds by default). Renewal
requires the exact current, unexpired lease, a strictly advancing trusted UTC
clock, a fresh nonce, and a non-regressing signed supervisor checkpoint.
Equal-height supervisor forks are rejected. A supervisor checkpoint is also
age-bounded (30 seconds by default and never more than 60 seconds), so a dead
supervisor cannot sustain renewal with an old but correctly signed head.

Only `CREATE` reads and validates the original stage request window. An active
lease may renew after the five-minute stage artifact expires, but only while
the predecessor lease is still active and all current checkpoint/CAS checks
pass. This continuity never changes its non-executable safety fields.

## Persistence and custody

The local ledger uses SQLite with:

- `journal_mode=WAL`;
- `synchronous=FULL`;
- `busy_timeout=10000`;
- an immutable signed identity row;
- append-only event and checkpoint tables; and
- `UPDATE`/`DELETE` denial triggers.

Each event is HMAC chained. Each local checkpoint is signed by a distinct
custody key and links its predecessor. After the local commit, an independent
CAS exporter must return a signed acknowledgement matching the exact expected,
observed, and accepted hashes. Read-after-write must return the same checkpoint.
If export or readback fails, local and external heads differ and the ledger is
unusable until an explicit reviewed recovery; it never silently retries an
order or advances execution.

Restoring an older database, substituting an equal-height valid fork, changing
schema/identity/history, replaying a nonce, or presenting a bad HMAC fails
closed.

## Public API

- `DemoAutoSessionCapabilityStore.provision(...)`
- `create_demo_auto_session_capability(...)`
- `verify_demo_auto_session_capability(...)`
- `renew_demo_auto_session_capability(...)`
- `issue_demo_auto_session_cas_acknowledgement(...)` for a concrete independent
  custody adapter

The returned `DemoAutoSessionLease` is evidence only. It permanently reports
`execution_authorized=false`, `activation_authorized=false`,
`safe_to_demo_auto_order=false`, `live_allowed=false`, and
`order_capability=DISABLED`.

## Acceptance criteria

1. A valid consumed DEMO_AUTO stage result creates sequence one exactly once.
2. A valid current lease renews only before expiry and with advancing UTC.
3. Historical leases, duplicate startup, duplicate nonces, stale leases,
   future controls, clock rollback, and supervisor rollback/forks are rejected.
4. Alternate ledger names, a second local provision for the same deterministic
   external namespace, local rollback, and equal-height custody forks reject.
5. Failed external CAS/readback leaves the local ledger fail-closed.
6. SQLite storage is WAL/FULL and append-only triggers are enforced.
7. No public object or store method exposes broker execution.
8. Focused tests cover creation, renewal, restart, tamper, replay, expiry,
   rollback, fork, CAS failure, supervisor failure, and storage profile.

## Reliability targets

This is a single-tenant, low-QPS control plane (normally no more than one lease
operation per lane every 30 seconds). The local target is p50 <10 ms, p95 <25
ms, and p99 <50 ms per verification under nominal disk conditions. The service
target after host deployment is 99.9% availability; any unavailable dependency
consumes the error budget by denying renewal, never by bypassing checks. RPO is
zero for committed-and-CAS-confirmed checkpoints. RTO is at most five minutes
after a host restart, subject to exact local/external head reconciliation.

## Deferred integration gate

The reviewed Windows composition root must later provide real trusted-clock,
key-vault, current-supervisor-checkpoint, and external CAS custody ports. A
separate approval must decide whether this evidence may be consumed by any
execution boundary. This v1 component intentionally cannot make that decision.
