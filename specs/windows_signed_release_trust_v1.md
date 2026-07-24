# Windows Signed Release Trust v1

Status: implemented as a fail-closed, non-executable foundation. It is not an
authorization to submit broker orders and is not yet wired as a demo-auto or
live unlock.

The v1 signatures are HMAC and therefore are **local/test foundation only**.
A process that receives an HMAC verification secret can also create signatures.
The Windows execution service remains hard-blocked. Production integration
requires either asymmetric signatures with only public verification material
on the release host, or an independently trusted launcher attestation.

## Objective

Prevent the Windows gated service from treating a release-local manifest as
proof of its own trustworthiness. A release is trusted only when an
independent authority signs a short-lived receipt for the exact deployed
release and an independent off-host custody service consumes the receipt once.

The implementation is `live_runtime/signed_release_trust.py`.

## Exact binding

`ReleaseTrustBinding` binds all of the following:

- deterministic `release_identity_sha256`;
- full Git commit and tree object hashes;
- exact `WINDOWS_GATED_EXECUTION_SERVICE_V1` profile;
- hashed reviewed deployment-host alias; and
- hashed least-privilege Windows service-account alias.

Changing any field creates a different binding and causes verification against
the reviewed binding to fail.

## Independent trust roots

`ReleaseTrustPolicy` is pinned outside the release and contains distinct:

- issuer authority ID, key ID, and SHA-256 key fingerprint; and
- off-host replay-custody authority ID, key ID, and SHA-256 key fingerprint.

The two authorities may not reuse an identity, key ID, or key material. The
verifier requires both the policy and a separately supplied expected policy
hash. A key fingerprint merely asserted by a receipt is never accepted.
Issuer and custody key bytes are obtained only through injected key providers;
they are not fields in a manifest, receipt, config file, or CLI argument.

External receipt bytes are accepted only through
`decode_signed_release_trust_receipt()`. It rejects duplicate JSON keys, extra
or missing fields, non-UTC timestamps, unsigned input, and any serialization
that is not the exact canonical representation. Decoding never re-signs data.

## Receipt validity

`SignedReleaseTrustReceipt` contains the exact binding, pinned policy hash,
monotonic sequence, predecessor checkpoint hash, hashed high-entropy nonce,
issuer identity, and an HMAC-SHA-256 signature. Its timestamps are aware UTC:

`issued_at <= not_before < expires_at`

The hard maximum lifetime is five minutes, and a policy may set a shorter
window. Verification rejects a future issue time, a not-yet-valid receipt, and
an expired receipt. Expiry is exclusive.

## Replay, fork, and rollback custody

The verifier cannot consume a receipt using only local state. It requires:

1. an external checkpoint provider;
2. an external atomic compare-and-swap operation; and
3. an independent custody key provider.

The receipt sequence must be exactly the last externally signed checkpoint
sequence plus one, and its predecessor must be the exact checkpoint content
hash. The custody service must reserve every nonce for the lifetime of the
trust domain and reject reuse, including historical reuse. It returns both a
signed checkpoint and signed CAS acknowledgement. The verifier checks their
complete binding and performs read-after-write verification.

The external CAS implementation is responsible for durable nonce uniqueness
and rollback-resistant storage (for example an off-host conditional-write
store with immutable audit export). In addition to checkpoint CAS, the verifier
requires an independent `external_nonce_seen_provider`. The nonce must be
reported unseen before CAS and seen after checkpoint readback. This registry
must retain all nonce history for the trust domain; a head-only CAS therefore
cannot accept a nonce from sequence 1 again at sequence 3. A callback that
merely echoes the proposal without persisting it cannot pass readback.

The trusted clock is sampled before verification and again only after custody
CAS, checkpoint readback, and nonce-registry readback complete. The second
sample may not regress and must remain strictly before receipt expiry. The
verified timestamp is this post-I/O sample, not the pre-CAS time. A receipt
that expires while custody is slow is consumed by custody but rejected for use.

## Deny-only result

`VerifiedReleaseTrustReceipt` proves only that release provenance was verified
and consumed once. It carries the exact `ReleaseTrustBinding`, accepted nonce
hash, receipt expiry, post-I/O verification time, and custody checkpoint hash.
Its `validate_freshness()` helper re-checks time, binding, and nonce, but is not
a consumption registry and must never be used as one-use stage authority. Its
immutable safety fields remain:

- `live_allowed=false`;
- `safe_to_demo_auto_order=false`;
- `promotion_eligible=false`;
- `execution_authority_granted=false`; and
- `stage_authority_granted=false`; and
- `max_lot=0.01`.

The module constants `SIGNED_RELEASE_TRUST_ENABLED` and
`HMAC_RELEASE_TRUST_PRODUCTION_READY` remain `false`. Importing, issuing, or
verifying a receipt never changes the executor mode. A separate, reviewed stage
authorization must bind a future production-grade trust proof together with all
manual-demo and demo-soak gates before any capability can be considered.

## Acceptance coverage

Tests cover:

- exact successful verification with every execution lock still closed;
- receipt signature tampering and wrong independent key material;
- expired, future-issued, and not-yet-valid receipts;
- release identity, Git commit/tree, host, and account mismatches;
- self-asserted policy/key substitution;
- receipt replay, fork, external rollback, and historical nonce reuse even
  when custody CAS retains only its head;
- expiry during slow custody and trusted-clock regression;
- exact verified binding, nonce, expiry, and freshness checks; and
- missing external read-after-write persistence.
