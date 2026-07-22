# Signed Decision IPC v1 (binding v2)

## Purpose

This contract separates the pure decision runtime from the broker-capable
executor. The producer may publish only an exact sealed `DecisionSnapshot`.
It cannot publish a `TradeIntent`, import MT5, submit an order, or grant a
runtime mode.

## Binding

One queue is immutably bound to the account alias hash, broker server, DEMO
environment, execution journal, commit, config, model artifact, stable market
data contract, decision signer, checkpoint custodian, and the expected permit
key ID/fingerprint. The permit trust fields are non-secret and are protected by
the queue identity HMAC plus the externally-custodied checkpoint chain; a
consumer cannot self-assert a replacement verification key. The actual
per-bar `data_sha256` stays inside each signed snapshot and may change every
decision.

## Ordered envelope

Each HMAC envelope contains one snapshot, a monotonically increasing sequence,
the previous envelope hash, and a one-second validity window. Its validity may
never extend the original ten-second post-M15 entry window. Source alignment
and data freshness are mandatory. Re-enveloping an old snapshot and duplicate
snapshot publication are rejected.

The SQLite WAL/FULL store is append-only for envelopes and consumptions. The
reviewed schema, indexes, triggers, `user_version`, safety PRAGMAs, and quick
integrity check are verified on every operation. Database, sidecar, and
explicit parent indirection through symlinks/reparse points is rejected.

## Consumption and recovery

The durable store is never passed directly to the DEMO_AUTO consumer. It mints
an exact sealed `DecisionIPCConsumerPort` whose public capability surface is
limited to the immutable binding, authenticated current checkpoint, and
ordered consume/expired-discard operation. The port has no `publish`, database,
clock, decision-key provider, custody-key provider, checkpoint provider, or
checkpoint-exporter attribute. Publication remains available only through the
separate `DecisionIPCProducer`/durable producer side.

Only the next sequence may be consumed. A fresh envelope yields a sealed
`VerifiedDecisionIPCEnvelope` once. An expired envelope is retained and yields
only a sealed `DiscardedDecisionIPCEnvelope` containing hashes and
`EXPIRED_DISCARDED`; it contains no decision or intent capability. This allows
the executor loop to drain a missed envelope and reach a later fresh decision.

Every mutation publishes a signed checkpoint using compare-and-swap, followed
by read-after-write verification. CAS rejection, ambiguous export, or readback
mismatch permanently latches the local queue fail-closed. There is no automatic
reset or genesis recreation.

## Threat model

The decision and custody signatures are HMACs. A process holding a symmetric
key can both verify and mint artifacts for that key, so “off-host custody” is
independent only when the custody key and CAS implementation are actually held
outside the executor host. This contract detects accidental corruption,
rollback, replay, forks, and callers without the pinned keys. It does not claim
protection after compromise of a pinned HMAC key or arbitrary code execution
inside both trusted processes.

Secrets must come from an OS credential provider. They are never command-line
arguments, configuration-file values, repository contents, or receipt fields.

## Acceptance criteria

- Exact sealed snapshot only; no MT5/order method in the producer.
- Sealed consumer port only; the downstream consumer never receives the raw
  dual-capability queue or its signing-provider/publication surface.
- Stable provenance binding with changing per-bar data hashes supported.
- HMAC, sequence, predecessor, duplicate, freshness, and original-entry-window
  enforcement.
- One-use ordered consumption and authenticated expired-discard recovery.
- External signed CAS/readback and permanent fail-closed ambiguity latch.
- Tamper, rollback, fork, stale, duplicate, schema drift, symlink/reparse, and
  concurrent publisher tests pass.
- This IPC alone never sets `safe_to_demo_auto_order` or `live_allowed` true.
