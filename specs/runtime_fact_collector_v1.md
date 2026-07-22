# Runtime Fact Collector v1

## Status and purpose

This contract defines the production boundary that observes runtime health and
mints a short-lived, HMAC-authenticated `RuntimeFactReceipt`. The receipt is a
deny-only input: it can prove that a specific set of observations was collected
for a specific broker lane, but it cannot authorize an order.

The implementation is `live_runtime/runtime_fact_collector.py`. Its consumer
must independently verify the receipt and must still pass every permit, risk,
execution, and reconciliation gate.

## Safety invariants

1. The collector never creates `RiskContext`, `PromotionPermit`, `TradeIntent`,
   an order request, or any execution-arm flag.
2. `live_allowed` and `safe_to_demo_auto_order` are always `false` in both the
   health decision and the signed receipt.
3. Every required provider is explicit. A missing provider, exception, invalid
   type, malformed value, unavailable HMAC key, or adapter binding mismatch
   raises `RuntimeFactCollectionError`; no receipt is returned.
4. A provider that successfully observes an unhealthy state produces a signed
   unhealthy receipt. Provider unavailability never becomes an optimistic
   default and never becomes a healthy receipt.
5. A receipt is valid for at most one second. Stale and not-yet-valid receipts
   fail verification.

## Required observations

One collection for `canonical_symbol + broker_symbol` reads:

- `adapter.assert_account_binding()` for the exact configured account/server;
  the signed account fact includes currency, balance, equity, margin, free
  margin, margin level, and the broker trade flags;
- `adapter.execution_fence_identity()` for the non-secret runtime identity hash
  bound to the exact account login, server, and environment;
- `adapter.get_broker_spec()` for the exact canonical/broker symbol mapping;
- `adapter.current_tick()` for bid, ask, broker timestamp, and measured age;
- `journal.integrity_check()`, `journal.kill_switch_status()`, the journal
  incarnation hash, and the filesystem containing the journal;
- free disk bytes from `shutil.disk_usage()` by default, or an injected test
  provider;
- absolute trusted-clock drift from an explicit provider;
- the last off-host heartbeat timestamp from an explicit provider;
- audit-export health and backup-recency booleans from explicit providers.

`broker_connected=true` is recorded only after the bound adapter calls succeed.
`data_feed_fresh` is derived again at the completion timestamp from the account,
specification, and tick ages. The receipt timestamp is sampled only after all
required providers finish; collection taking over one second fails closed.

The pure `evaluate_runtime_health()` policy remains the single evaluator for
clock, heartbeat, disk, database integrity, broker/feed, audit export, backup,
and latched kill-switch observations.

## Signed receipt binding

`RuntimeFactReceipt` is an immutable canonical contract. Its HMAC-SHA256 covers:

- schema version and one-second validity window;
- account alias, exact server and environment;
- canonical symbol and exact broker symbol;
- runtime account identity hash and derived account-binding hash;
- complete broker account fact and its content hash;
- complete `BrokerSpec` and its content hash;
- complete exact tick fact and its content hash;
- complete `RuntimeHealthFacts` and its content hash;
- recomputed `RuntimeHealthDecision` and its content hash;
- journal incarnation hash;
- signing key identifier;
- the permanently false execution flags.

The signature itself is excluded from the signing payload and the HMAC input is
domain-separated for this receipt type. HMAC secrets must be
at least 32 bytes and must be obtained by key identifier from an external key
provider; secret material is not serialized into the receipt.

## Verification contract

`verify_runtime_fact_receipt()` requires the caller's expected account, server,
environment, symbol mapping, runtime identity hash, broker-spec hash, journal
hash, and key identifier. It also requires an explicit verification-key
provider and trusted UTC clock.

Verification rejects, with auditable reason codes:

- any expected binding mismatch;
- a validity interval longer than one second;
- stale or not-yet-valid receipts;
- schema or execution-unlock changes;
- nested content-hash changes;
- a health decision that does not recompute from the signed facts;
- a missing/unavailable verification key;
- any HMAC mismatch, including otherwise internally consistent tampering.

Returning a verified unhealthy receipt does not make execution healthy. The
consumer must deny whenever `health_decision.healthy` is false.

## Threat model and trust boundary

The receipt detects modification, replay beyond its one-second lifetime,
cross-account/cross-server reuse, cross-symbol reuse, broker-spec drift,
journal substitution, and signing-key confusion. It does not protect against a
compromised trusted-clock source, compromised provider implementation,
exfiltrated HMAC key, compromised Python process, or malicious broker feed.
Those remain deployment/security controls and independent execution gates.

Signing and verification keys should come from Windows Credential Manager (or
an equivalent host secret store), be scoped to one runtime environment, be
rotatable by key ID, and never be stored in the repository or receipt.

## Operating assumptions and targets

- One collector instance serves one configured MT5 terminal/account lane.
- Collection is synchronous and occurs immediately before a decision attempts
  to cross the execution boundary.
- Expected frequency is at most one collection per decision cycle per lane;
  this contract is not a tick-storage service.
- Facts and receipts are internal security-sensitive operational data.
- Availability objective: p99 collection and verification latency below
  500 ms under normal local-host conditions. Any timeout/unavailability denies.
- Freshness objective: receipt lifetime is at most one second end to end.
- RPO: zero for a receipt accepted by an execution boundary; the caller must
  persist its audit record synchronously before relying on it.
- RTO: one successful healthy collection cycle after all required providers and
  dependencies recover. A latched kill switch still requires its separate,
  authorized reset workflow.

## Acceptance tests

The focused suite must prove:

- exact adapter and journal observations are embedded and signed;
- all observed unhealthy facts remain deny-only and auditable;
- missing/unavailable providers and signing keys return no receipt;
- adapter/tick failures return no receipt;
- tampering, stale replay, key mismatch, binding mismatch, and unavailable
  verification keys are rejected;
- receipt lifetime is exactly bounded to the executor's maximum fact age.
- broker-call latency cannot backdate the signed observation timestamp.
