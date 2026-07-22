# Production Runtime Supervisor v1

## Status and purpose

`live_runtime/runtime_supervisor.py` is a fail-closed orchestration port for one
exact broker account/server runtime. It coordinates existing trusted components;
it is not an order CLI, an MT5 adapter, an approval issuer, a permit issuer, a
credential reader, or a kill-switch reset path.

The supervisor does not make AI_SCALPER live-ready by itself. It supplies the
durable single-owner and startup/cycle ordering boundary required before a demo
soak can be wired to reviewed Windows adapters. The current policy remains:

- `order_capability = DISABLED`
- `execution_enabled = false`
- `manual_demo_enabled = false` as a global capability
- `safe_to_demo_auto_order = false`
- `live_allowed = false`
- `DEMO_AUTO` and `LIVE` supervisor modes are hard denied

A manual `DEMO` action is the sole execution-service path. It requires a sealed,
fresh, one-use `MANUAL_DEMO` stage authorization at startup, a signed current
external replay checkpoint, a fresh exact-intent `ManualDemoApprovalValidation`,
and a separate policy callback that returns the literal boolean `True`. The stage
authorization is consumed once per runtime startup, never once per order. This
narrow one-intent path never changes the global status flags above.

## Locked binding

Every durable receipt and database identity binds exactly to:

- SHA-256 of the reviewed local account alias (the raw alias/login is never
  persisted);
- broker server;
- broker environment;
- account currency;
- execution-journal incarnation SHA-256;
- clean release Git commit SHA (7–64 hexadecimal characters; the full 40-character
  Git SHA is recommended);
- complete runtime configuration SHA-256; and
- runtime mode; and
- exact `StageBinding` SHA-256 for `DEMO`/`DEMO_AUTO` modes; and
- a canonical signed-news trust-profile SHA-256 (reviewed provider ID, key ID,
  ruleset hash, blackout-window hash, and receipt schema) whenever the signed
  path is used.

Opening an existing database with any different value fails. HMAC key material is
provided by an injected key provider and is never stored in SQLite.

## Ports

The supervisor requires injected, testable ports:

1. `ExecutionJournal`-compatible journal identity, integrity, kill-switch status,
   and kill-switch latch operations.
2. Signed semantic execution-journal checkpoint provider plus its cryptographic,
   freshness, exact-binding, state-materialization, and rollback verifier.
3. Durable risk ledger plus an external sealed `RiskStateReceipt` checkpoint.
4. Reconciliation provider returning `ReconciliationResult`.
5. Runtime-fact provider returning signed `RuntimeFactReceipt` objects.
6. Runtime-fact verifier that validates signature, freshness, account/server,
   broker specification, journal, and health facts, and returns the exact receipt.
7. For execution modes, a news/rollover provider returning a sealed
   `RuntimeNewsGuardReceipt`, plus an injected exact-object signature verifier,
   reviewed provider/key IDs, ruleset hash, and blackout-window hash. A raw
   `RuntimeNewsGuard` is accepted only in `SHADOW` when the constructor explicitly
   enables named legacy compatibility.
8. Pure decision provider returning `RuntimeSupervisorDecision`.
9. Trusted UTC clock.
10. For `DEMO`/`DEMO_AUTO`, explicit `RuntimeStageAuthorizationPorts` containing
    the exact authorization/binding, current externally held signed replay
    checkpoint, real durable replay registry, checkpoint key port, and a validator
    that can return only the constructor-sealed validation object.
11. Optional manual-demo approval, policy, and execution-service callbacks.
12. A signed supervisor-checkpoint provider and append-only off-host exporter.
    Every checkpoint binds the immutable local store incarnation, exact receipt
    count/head HMAC, irreversible critical-latch state, accepted news heads, and
    the SHA-256 of the exact externally supplied predecessor. The exporter must
    acknowledge the exact value and read-after-write must return that value.

No port may be inferred from global process state. Unknown, malformed, missing,
stale, or exceptional port results fail closed.

## Startup protocol

`start()` performs the following before any decision provider can run:

1. authenticate and integrity-check the supervisor database, compare it to the
   latest signed off-host supervisor checkpoint, and reject any missing,
   restored, deleted/recreated, or divergent local store;
2. acquire its durable singleton lease and a monotonically increasing fence token;
3. hard-reject `LIVE`; hard-reject `DEMO_AUTO` while
   `SAFE_TO_DEMO_AUTO_ORDER=false` without consuming its authorization;
4. verify exact execution-journal identity, SQLite integrity, and unlatched kill switch;
5. verify a fresh signed semantic execution-journal checkpoint against the current
   materialized state and its off-host append-prefix checkpoint;
6. verify the durable risk ledger against the supplied sealed checkpoint, obtain a
   current sealed receipt, check exact account/server/journal/currency binding, and
   reject a risk loss latch;
7. run a clean broker reconciliation;
8. collect and cryptographically verify at least one runtime-fact receipt;
9. require the recomputed runtime health decision to be healthy, thereby checking
   clock drift, disk, off-host heartbeat, broker/feed state, audit export, backup,
   database integrity, and kill-switch state;
10. authenticate a fresh signed news receipt, require exact provider/key/account/
    server/environment/config/ruleset/window binding, require no news or rollover
    blackout, and compare its sequence/predecessor to the durable accepted head;
11. for `DEMO`, verify that the external stage replay checkpoint is signed and is
    the registry's exact current high-water mark, validate and atomically consume
    the one-use `MANUAL_DEMO` authorization, create and reverify the new signed
    current checkpoint, and require exactly one new replay event; and
12. atomically append a signed `STARTUP/READY` receipt containing the exact stage
    authorization, sealed validation, prior external checkpoint, new replay
    checkpoint, and signed news receipt hashes.

The decision provider is not called during startup.

## Cycle protocol

After validating/refreshing the local fence, each cycle orders external work as:

1. reconcile broker state first;
2. verify the journal and kill switch;
3. refresh and verify the signed semantic journal checkpoint;
4. replay-verify the risk ledger against its checkpoint and refresh its receipt;
5. refresh and verify signed runtime facts;
6. verify a new signed news/rollover receipt and its durable monotonic chain;
7. revalidate the singleton fence;
8. call the decision provider;
9. for `NO_ACTION`, persist the completed receipt;
10. for `MANUAL_DEMO_EXECUTE`, append a signed `PRE_DISPATCH` receipt that binds
   the decision-time evidence and first signed news receipt, then verify the
   exact sealed per-intent approval and explicit policy callback;
11. after those potentially blocking callbacks, re-check decision age, journal
   and kill-switch state, journal custody, risk-ledger high-water, exact signed
   runtime facts, account snapshot, and lease; obtain a **new** signed news
   receipt whose predecessor is the durable `PRE_DISPATCH` news receipt; and
   immediately before dispatch re-check decision/evidence/news freshness and the
   lease again; and
12. append a signed completed cycle receipt containing only hashes/references, not
    credentials or raw broker secrets.

No decision is possible before a successful reconciliation. No execution-service
call is possible in shadow, demo-auto, or live mode.

## Durable SQLite design

The database uses `journal_mode=WAL`, `synchronous=FULL`, foreign keys, and a busy
timeout. It contains:

- `supervisor_identity`: immutable canonical binding, HMAC key ID, random immutable
  store-incarnation hash, and identity HMAC;
- `supervisor_lease`: single mutable owner, monotonic fence token, and UTC expiry;
- `supervisor_critical_state`: singleton HMAC-authenticated irreversible critical
  latch, reason, and UTC timestamp; and
- `supervisor_cycle_receipts`: append-only contiguous sequence, canonical payload,
  predecessor HMAC, and receipt HMAC.

Identity and cycle-receipt updates/deletes are blocked by triggers. Startup and
every append replay SQLite integrity, canonical JSON, contiguous sequence,
predecessor links, and HMAC authentication. Graceful release retains the last fence
token, preventing token reuse after restart. A competing active owner is rejected.

Before every append the local store must equal the exact latest externally
custodied supervisor checkpoint. After the append, a successor checkpoint is
signed with that exact checkpoint's content hash as its predecessor and is
published using compare-and-swap/read-after-write semantics. An exporter outage
leaves the local head ahead of custody and therefore permanently denies restart
until an operator resolves custody; the runtime never overwrites or regresses a
newer unexpected external head. An entirely new database has a different
incarnation and cannot be paired with an old checkpoint.

The local receipt is an audit commitment, not authorization. It binds reconciliation
status, signed journal-checkpoint hash, risk receipt HMAC, verified runtime-fact
hashes, signed news-guard hash/provider/sequence/predecessor, decision ID and
decision-payload hash, execution-service
invocation indicator, result hash, phase/status, release binding, owner, and fence.
`STARTUP` additionally binds the stage mode, authorization ID/hash, sealed
validation hash, prior external checkpoint hash, and post-consumption checkpoint
hash. Authorization IDs/hashes are unique across the durable chain, so a restart
requires a newly issued authorization.

Signed news receipts form a second durable monotonic chain. The append transaction
requires a strictly increasing provider sequence and an exact predecessor equal to
the last accepted receipt hash. Startup and cycle verification reject duplicate or
lower sequences, valid-but-historical replay inside the TTL, and equal-height or
predecessor forks. Supervisor receipt HMAC verification detects local rollback or
mutation of this accepted high-water history.

Manual-demo execution cycles accept two consecutive news receipts. The first is
committed in `PRE_DISPATCH` before approval/policy callbacks; the second must be a
new signed successor and is committed in the final `CYCLE` receipt. This preserves
the same atomic predecessor rules while closing the callback-to-dispatch TOCTOU
window. A callback failure leaves the first receipt auditable and the irreversible
critical latch prevents continuation.

## Critical failure behavior

The following stop the supervisor and latch the execution journal kill switch:

- database, chain, identity, journal, risk-ledger, checkpoint, or fact integrity failure;
- account, server, environment, currency, journal, commit, config, or mode mismatch;
- lease loss or expiry;
- broker reconciliation pending/critical, orphan state, missing protection, volume
  mismatch, binding mismatch, or uncertain intent;
- stale or unhealthy runtime facts;
- missing, stale, forged, rolled-back, or semantically invalid execution-journal
  checkpoint;
- clock, disk, heartbeat, feed, audit-export, or backup failure;
- raw/forged/stale/future/misbound/replayed/rolled-back/forked news receipt,
  stale news feed, news blackout, or rollover blackout;
- missing, stale, misbound, replayed, invalid, or already-used stage authorization;
- invalid, rolled-back, forked, historical, or incorrectly advanced signed stage
  replay checkpoint;
- an already latched journal/risk stop;
- invalid decision, approval, or explicit manual policy denial;
- decision expiry, risk-state change, fact expiry, journal/lease change, or a
  missing/replayed/stale/blackout news refresh at the final dispatch boundary;
- execution-service failure; or
- any unknown exception.

The supervisor never resets a latch. Its own HMAC-authenticated critical latch is
committed before and independently of the execution-journal latch. A failed or
unavailable journal-latch write therefore cannot make restart safe: startup reads
the local critical state and rejects it, while the matching off-host checkpoint
also records the latch. If the external checkpoint is already divergent, the
supervisor latches locally but does not publish over the external high-water.

## Operating assumptions and SLO targets

- One supervisor writer per exact account/server/database; read volume is low.
- Cycle cadence is M5 or M15, so SQLite write throughput is not a constraint.
- Operational data is security-sensitive metadata; raw credentials are out of scope.
- RPO target is zero committed supervisor receipts. `FULL` synchronous transactions
  make the receipt durable before the call returns, subject to host/storage guarantees.
- RTO is deployment dependent; a restart must pass all startup gates and obtain a new
  fence before it is ready.
- Target supervisor overhead is below one second p99 excluding injected broker,
  reconciliation, fact-collection, and decision providers.
- Off-host heartbeat age, clock drift, and disk thresholds are inherited from
  `live_runtime.health` and must not be relaxed in adapters.

## Acceptance tests

`test_live_runtime_runtime_supervisor.py` covers:

- WAL/FULL and immutable receipt contracts;
- strict startup verification with no startup decision;
- mandatory signed semantic journal checkpoint verification on startup and cycles;
- reconciliation-before-facts-before-decision ordering;
- no decision after reconciliation failure;
- singleton owner exclusion and monotonic fencing across restart;
- receipt-chain tamper detection;
- independent critical-latch durability when journal latching is fault-injected;
- irreversible SQL reset prevention and critical-latch restart denial;
- exact supervisor-checkpoint predecessor/CAS chaining;
- restored-old and deleted/recreated database rejection without overwriting the
  off-host high-water checkpoint;
- off-host exporter failure with local critical persistence;
- stale runtime facts and unhealthy news denial;
- signed news exact-verifier/provider/binding checks plus durable replay and fork
  rejection;
- raw account-alias absence from supervisor identity and receipt JSON;
- startup-only one-use `MANUAL_DEMO` validation, durable authorization/validation/
  checkpoint hashes, exact stage binding, invalid external checkpoint rejection,
  replay rejection, and new-authorization-on-restart;
- hard `DEMO_AUTO`/`LIVE` locks;
- sealed exact-intent manual-demo approval and explicit policy requirement;
- policy denial without execution-service invocation;
- kill-switch latching on critical failure; and
- graceful bounded execution with all global execution flags false.

## Deployment integration still required

The reviewed Windows service assembly must create the concrete ports, derive the
commit/config hashes from an approved clean release, retrieve HMAC material from
Windows Credential Manager, and supply real heartbeat/audit/backup/news adapters.
This module intentionally does not provide a launcher that could be mistaken for an
order-capable production command.
