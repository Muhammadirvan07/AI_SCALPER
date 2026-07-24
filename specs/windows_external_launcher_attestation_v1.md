# Windows External Launcher Attestation v1

## Purpose

The Windows execution runner must authenticate the exact deterministic release
before it imports the reviewed provider factory. A shared HMAC secret on the
VPS is not sufficient because the same host could forge a receipt. This
contract adds verification-only RSA public-key trust. The offline issuer keeps
the private key outside the VPS and repository.

A valid launcher attestation proves release provenance only. It never grants a
stage authorization, environment arm, promotion permit, broker mutation,
DEMO_AUTO activation, promotion, or live authority.

## Policy boundary

The ACL-protected external policy binds:

- exact `WINDOWS_GATED_EXECUTION_SERVICE_V1` profile;
- issuer and key identifiers;
- an RSA modulus of at least 3072 bits and exponent 65537;
- canonical public-key fingerprint;
- deployment-host, service-account, and Task Scheduler definition hashes; and
- a maximum validity of five minutes.

The launcher command separately pins the policy SHA-256. The policy and
short-lived attestation files must be regular, stable, non-reparse files
outside the mutable release root.

## Attestation boundary

The canonical signed payload binds the policy, exact release identity, host,
service account, task definition, nonce, issuer/key identity, validity window,
and deny-only safety facts. Verification uses exact
`RSASSA-PKCS1-v1_5-SHA256` encoding with no algorithm negotiation or private
key material in the release.

The runner verifies the attestation before loading the factory and checks its
freshness again after factory materialization. Failure, expiry, path
indirection, policy drift, release drift, signature tampering, or clock
regression stops startup before broker initialization.

## Safety invariants

- `live_allowed=false`
- `safe_to_demo_auto_order=false`
- `execution_authority_granted=false`
- `order_capability=DISABLED`
- minimum RSA modulus is 3072 bits
- policy and attestation JSON use exact schemas, canonical UTF-8 encoding, and
  reject duplicate keys
- validation never reads a private key and exposes no signing function

Release provenance is only one startup gate. All stage, permit, risk,
reconciliation, credential, news, journal, supervisor, demo-soak, legal,
security, temporal, and manual gates remain independently required.

## Acceptance criteria

1. A correctly signed, current, exactly bound RSA-3072 attestation returns a
   sealed deny-only verification result.
2. Release, policy, host, account, task, issuer, key, timestamp, or signature
   drift fails closed.
3. RSA keys below 3072 bits, exponents other than 65537, unknown algorithms,
   noncanonical JSON, duplicate keys, and oversized documents are rejected.
4. Missing attestation arguments stop the service before factory loading.
5. Static validation and `--validate-only` do not read the external trust
   documents or materialize any provider.

## Out of scope

- Issuing or signing attestations on the VPS.
- Replacing one-use stage authorization, permit, environment arm, or journal
  submission fencing.
- Claiming Windows ACL, Task Scheduler, clock, offline-key custody, or failure
  drills have passed before external acceptance evidence exists.
