# Windows LIVE Canary Provider-Bound Runtime Session Handoff v1

**Author:** Codex with the AI_SCALPER project owner
**Date:** 2026-07-30
**Status:** Approved for implementation under the project owner's standing authorization
**Reviewers:** senior architecture, security, and ship-gate boundaries
**Related specs:**
`specs/live_canary_provider_bound_portable_custody_v2.md`,
`specs/windows_execution_provider_bound_runtime_closure_v1.md`,
`specs/windows_live_canary_runtime_candidate_consumer_closure_v1.md`,
`specs/windows_live_canary_execution_materialization_v1.md`, and
`specs/windows_live_canary_external_runtime_hook_lease_v1.md`

## Context

The extracted Windows Execution release owns the exact deny-only runtime
candidate consumer and exact sealed provider-bound launch-session consumer.
The operator boundary owns the admission, provider acceptance, WORM custody,
external CAS reservation, one-use launch capability, and launch-session
producer. Those privileged producer modules are intentionally absent from the
Execution allowlist.

Consequently, a reviewed external LIVE runtime provider can reconstruct the
candidate from independently pinned canonical bytes, but it cannot transfer an
already verified provider-bound launch session into the extracted Execution
process. Copying session fields without a verified transport would lose the
producer's seal. Accepting a signed session document without a second one-use
claim would also permit the same short-lived document to be loaded again by a
restarted or concurrent process.

This feature adds a minimal Execution-side consumer for a short-lived,
provider-bound runtime-session handoff. An independently pinned public policy
contains two distinct RSA authorities: one attests the exact session document,
and one operates an external atomic replay ledger. Every load creates a fresh
random challenge, submits an exact canonical consumption request to that
ledger, and accepts only a challenge-bound signed consumption receipt. Only
after all hashes, signatures, target identities, times, authority separation,
candidate bindings, central LIVE policy checks, and one-use consumption checks
pass may the consumer reconstruct the existing exact sealed session class.

The handoff carries launch-only authority already present in the sealed
session. It never creates per-order authorization, promotion evidence, risk or
news approval, journal lease, final MT5 submission approval, or broker mutation
authority.

## Functional Requirements

- FR-1: A dedicated
  `live_runtime/live_canary_provider_bound_runtime_session_handoff.py` module
  MUST own the strict public-policy, handoff-document, replay-request, and
  replay-receipt contracts consumed by the Windows Execution release.
- FR-2: The public policy MUST use schema
  `live-canary-provider-bound-runtime-session-handoff-policy-v1` and MUST be
  independently pinned by exact non-zero SHA-256.
- FR-3: The policy MUST bind the exact Windows Execution release identity,
  target-host identity, installed-environment identity, deployment-host alias,
  service-account alias, launcher-task definition, LIVE Execution task
  definition, replay-ledger alias, maximum handoff TTL at most 60 seconds, and
  replay-request TTL at most five seconds.
- FR-4: The policy MUST contain a 3072-to-8192-bit RSA handoff public key and a
  distinct 3072-to-8192-bit RSA replay-ledger public key, both using exponent
  65537 and `RSASSA-PKCS1-v1_5-SHA256`.
- FR-5: Handoff and replay issuer IDs, key IDs, and public-key fingerprints MUST
  be pairwise distinct and MUST not occur in the policy's exact sorted
  reserved-authority ID or fingerprint inventories.
- FR-6: The handoff document MUST use schema
  `live-canary-provider-bound-runtime-session-handoff-v1`, contain the exact
  canonical public session payload and its non-zero SHA-256, and bind the exact
  candidate, policy, release, both host identities, installed environment,
  service account, both task definitions, and one-use handoff nonce hashes.
- FR-7: Handoff validity MUST be no more than the policy maximum, no more than
  60 seconds, and no later than the embedded session's `valid_until_utc`,
  provider-acceptance expiry, or provider-bound custody expiry.
- FR-8: The handoff signature MUST cover a domain-separated canonical signing
  payload containing every handoff field except the signature itself.
- FR-9: The consumer MUST require independent non-zero pins for policy bytes,
  handoff bytes, candidate content, session content, handoff nonce, Execution
  release identity, target host, installed environment, deployment host,
  service account, launcher task, and LIVE Execution task definition.
- FR-10: The consumer MUST accept only the exact registered
  `LiveCanaryRuntimeCandidate`, require its candidate hash and release binding,
  and reject subclasses, copied attributes, or forged unsealed objects.
- FR-11: Every document MUST be exact UTF-8 canonical JSON with one final LF,
  a closed field inventory, no duplicate keys, no non-finite values, no
  trailing bytes, and a maximum size of 1 MiB.
- FR-12: Every load attempt that reaches replay consumption MUST generate a
  fresh 32-byte operating-system random challenge and include only its SHA-256
  in a canonical replay-consumption request.
- FR-13: The replay request MUST bind the exact policy, handoff, session,
  candidate, handoff nonce, release, both host identities, installed
  environment, service account, both task definitions, ledger alias, request
  time, expiry, and challenge SHA-256.
- FR-14: The replay consumer callback MUST accept exactly the canonical request
  bytes and return exact canonical replay-receipt bytes; callback exceptions or
  malformed results MUST reject without exposing exception text.
- FR-15: The replay receipt MUST use schema
  `live-canary-provider-bound-runtime-session-consumption-receipt-v1`, bind the
  exact request SHA-256 and every handoff identity, assert one atomic
  consumption, and carry a domain-separated RSA signature from the distinct
  replay authority.
- FR-16: The receipt challenge MUST equal the challenge generated for the
  current load attempt. A receipt from any earlier attempt MUST therefore
  reject even when all other document hashes are unchanged.
- FR-17: The consumer MUST evaluate a trusted UTC clock before handoff
  verification, before replay consumption, and after receipt verification; all
  observations MUST be monotonic and remain inside both handoff and replay
  windows.
- FR-18: The checked-in central LIVE policy MUST be true before and after every
  authority-bearing phase. With the checked-in lock false, document decoding
  MAY succeed but session reconstruction and replay consumption MUST reject.
- FR-19: Only after the signed handoff, signed fresh-challenge consumption
  receipt, independent pins, candidate binding, current times, and central LIVE
  policy pass may the consumer construct the existing exact sealed
  `LiveCanaryProviderBoundRuntimeLaunchSession`.
- FR-20: The reconstructed session canonical payload and content SHA-256 MUST
  exactly equal the signed session payload and independent session pin.
- FR-21: The result MUST remain launch-only:
  `execution_authorized=false`, `broker_mutation_authorized=false`,
  `independent_per_order_authorization_required=true`, and every existing
  promotion, risk/news, journal, and final MT5 guard remains mandatory.
- FR-22: The module MAY expose deterministic policy/handoff decoding and
  domain-separated signing-message helpers, but MUST NOT import, access, store,
  or generate a private key.
- FR-23: The Execution allowlist and critical provider-bound runtime closure
  MUST include only this new consumer module in addition to their current
  members; operator-side session producers and custody authorities remain
  excluded.
- FR-24: The isolated closure probe MUST import the policy decoder, signing
  helpers, loader, exact candidate/session predicates, and runtime-source
  sealer using only allowlisted extracted bytes.
- FR-25: The isolated probe MUST prove malformed policy/handoff input and a
  central-lock-false load reject without calling replay, credentials, network,
  SQLite, MT5, process, Task Scheduler, or broker effects.
- FR-26: Existing candidate, session, bootstrap, per-order authorization,
  provider materialization, configured-candidate, source-bound, conformance,
  release-builder, and release-separation contracts MUST remain compatible
  except for naturally derived new Execution and closure identities.
- FR-27: All new failures MUST use stable uppercase non-secret reason codes and
  MUST not include document bytes, paths, credentials, private keys, provider
  payloads, callback exception text, or broker responses.
- FR-28: A valid policy, handoff, or replay receipt MUST NOT be reported as
  production readiness, per-order authority, broker acknowledgement, or proof
  that LIVE trading has occurred.

## Non-Functional Requirements

- NFR-1: The consumer MUST use Python 3.12 standard library and already
  allowlisted first-party public-key verification/canonicalization primitives
  only.
- NFR-2: Policy and handoff parsing plus signature verification, excluding the
  external replay callback, MUST complete in less than one second on the
  project test host.
- NFR-3: Normal Python and `PYTHONOPTIMIZE=2` MUST make identical security
  decisions; no security decision may rely on `assert`.
- NFR-4: Pure decoding and signing-message construction MUST have no credential,
  private-key, filesystem, network, SQLite, MT5, process, task, or broker
  effect.
- NFR-5: The replay callback MUST be invoked at most once per loader call, and
  never before all static document, signature, pin, candidate, target, time,
  authority-separation, and central-policy checks pass.
- NFR-6: Identical clean commit/tree and allowlist inputs MUST produce
  byte-identical Execution archives, closure records, and identities.
- NFR-7: Focused and full normal/optimized tests, compilation, lint, type
  checking, dependency-lock verification, release separation, and repository
  hygiene checks MUST pass.

## Acceptance Criteria

### AC-1: Strict independently pinned policy and handoff (FR-1, FR-2, FR-3, FR-4, FR-5, FR-6, FR-7, FR-8, FR-9, FR-10, FR-11)

Given exact canonical policy and handoff bytes plus all independent pins
When the Execution consumer decodes and verifies them
Then both RSA authorities, every target identity, the candidate, and exact
session payload are bound
And non-canonical, malformed, weak-key, same-authority, wrong-pin, expired, or
cross-target input rejects before replay consumption.

### AC-2: Fresh-challenge atomic replay consumption (FR-12, FR-13, FR-14, FR-15, FR-16, FR-17, NFR-5)

Given a valid current handoff and an external atomic replay ledger
When the consumer requests one-time use
Then exactly one canonical request contains a new OS-random challenge hash
And only a correctly signed receipt bound to that request and challenge passes
And a prior receipt, wrong challenge, duplicate-use conflict, callback failure,
or malformed receipt rejects.

### AC-3: Exact sealed session reconstruction (FR-18, FR-19, FR-20, FR-21)

Given central LIVE policy true, a valid exact candidate, a valid signed
handoff, and a valid fresh signed replay-consumption receipt
When the consumer completes verification
Then it returns the exact registered provider-bound runtime session class
And the reconstructed canonical session bytes and hash equal the signed and
independently pinned values
And no per-order or broker-mutation authority is created.

### AC-4: Central lock and effect ordering (FR-14, FR-17, FR-18, FR-25, NFR-4, NFR-5)

Given the checked-in central LIVE lock is false or any static input is invalid
When the loader is called
Then it rejects before replay consumption
And no credential, private-key, network, filesystem, SQLite, MT5, process,
Task Scheduler, or broker effect occurs.

### AC-5: Minimal allowlist-only closure (FR-22, FR-23, FR-24, FR-25, FR-28)

Given only files named by the Windows Execution allowlist
When the isolated provider-bound closure probe runs under `python -I -S -B`
Then the handoff consumer, candidate/session contracts, and runtime-source
sealer import successfully
And operator-side producers and private authorities remain absent
And output continues to report LIVE, readiness, and order authority locked.

### AC-6: Adversarial and optimized parity (FR-11, FR-16, FR-27, NFR-2, NFR-3)

Given duplicate-key, invalid-UTF-8, non-finite, oversized, wrong-signature,
wrong-target, wrong-challenge, stale, replayed, subclass, and forged inputs
When focused tests run in normal and optimized Python
Then accept/reject results and stable reason codes are identical
And valid local verification remains within the performance bound.

### AC-7: Downstream and release compatibility (FR-23, FR-24, FR-26, NFR-6, NFR-7)

Given the completed handoff consumer
When focused, downstream, release-builder, full, dependency, static, hygiene,
and deterministic-build gates run
Then all gates pass without producer-module leakage or central-lock change
And two clean builds from the same commit/tree are byte-identical.

## Edge Cases and Error Scenarios

- EC-1: Empty bytes, invalid UTF-8, missing final LF, two final LFs, trailing
  bytes, scalar JSON, duplicate key, `NaN`, or infinity MUST reject.
- EC-2: Missing, extra, reordered, legacy-schema, zero-hash, wrong-pin, or
  non-canonical policy/handoff/receipt fields MUST reject.
- EC-3: RSA modulus below 3072 bits, above 8192 bits, even, prefixed with zero,
  exponent other than 65537, fingerprint mismatch, malformed signature, or
  signature mismatch MUST reject.
- EC-4: Handoff and replay authorities sharing issuer ID, key ID, fingerprint,
  or a reserved authority identity MUST reject.
- EC-5: A session payload whose fixed schema, XAUUSD scope, 0.01 lot, one
  position, launch-only flags, provider binding, or expiry values drift MUST
  reject.
- EC-6: A candidate subclass, forged object, copied attributes, wrong content
  hash, or wrong release manifest binding MUST reject.
- EC-7: Handoff issued in the future, not yet valid, expired, longer than 60
  seconds, or later than the embedded session/provider/custody window MUST
  reject.
- EC-8: A trusted clock returning non-UTC, regression, or a value outside the
  request/handoff window MUST reject.
- EC-9: Random challenge generation that raises, returns a subclass, or returns
  other than exactly 32 bytes MUST reject before callback invocation.
- EC-10: A callback that is non-callable, raises, returns non-bytes, returns an
  oversized document, or is invoked more than once MUST reject safely.
- EC-11: A replay receipt with a prior challenge, different request hash,
  different handoff/session/candidate/nonce/target, `consumed_once=false`,
  wrong authority, future consumption time, expired window, or invalid
  signature MUST reject.
- EC-12: Reusing the same signed handoff in a second loader call MUST generate a
  different challenge; a compliant atomic ledger rejects the second
  consumption, while replaying the first signed receipt fails challenge
  binding.
- EC-13: The central LIVE lock changing false before or after callback or before
  return MUST reject and MUST not return a sealed session.
- EC-14: A valid handoff with no external replay consumer MUST reject; local
  memory-only replay state is insufficient.
- EC-15: Removing or changing handoff-consumer bytes in an extracted release
  MUST change or reject the closure and Execution release identity.
- EC-16: Adding operator-side activation, custody, signer, private-key, or order
  modules to a service allowlist MUST fail release separation.

## API Contracts

HTTP API: N/A — this is an offline Python trust and replay-consumption
boundary. No HTTP endpoint or browser command is introduced. The validator
marker `POST /not-applicable` is documentation-only and MUST NOT be implemented
or exposed.

```typescript
interface ProviderBoundRuntimeSessionHandoffPolicyV1 {
  schema_version: "live-canary-provider-bound-runtime-session-handoff-policy-v1";
  policy_id: string;
  handoff_issuer_id: string;
  handoff_key_id: string;
  handoff_rsa_modulus_hex: string;
  handoff_rsa_exponent: 65537;
  handoff_public_key_fingerprint_sha256: LowerHex64;
  replay_issuer_id: string;
  replay_key_id: string;
  replay_rsa_modulus_hex: string;
  replay_rsa_exponent: 65537;
  replay_public_key_fingerprint_sha256: LowerHex64;
  replay_ledger_alias_sha256: LowerHex64;
  execution_release_identity_sha256: LowerHex64;
  target_host_identity_sha256: LowerHex64;
  installed_environment_sha256: LowerHex64;
  deployment_host_alias_sha256: LowerHex64;
  service_account_alias_sha256: LowerHex64;
  launcher_task_definition_sha256: LowerHex64;
  live_execution_task_definition_sha256: LowerHex64;
  reserved_authority_key_ids: string[];
  reserved_authority_fingerprints_sha256: LowerHex64[];
  maximum_handoff_ttl_seconds: number;
  maximum_replay_request_ttl_seconds: number;
  signature_algorithm: "RSASSA-PKCS1-v1_5-SHA256";
  central_unlock_required: true;
  session_reconstruction_authorized: true;
  direct_execution_authorized: false;
  broker_mutation_authorized: false;
  order_capability: "GATED_PRESENT";
}
```

```typescript
interface ProviderBoundRuntimeSessionHandoffV1 {
  schema_version: "live-canary-provider-bound-runtime-session-handoff-v1";
  handoff_id: string;
  handoff_policy_sha256: LowerHex64;
  candidate_sha256: LowerHex64;
  session_sha256: LowerHex64;
  session: LiveCanaryProviderBoundRuntimeLaunchSessionV2;
  handoff_nonce_sha256: LowerHex64;
  issued_at_utc: CanonicalUtc;
  not_before_utc: CanonicalUtc;
  expires_at_utc: CanonicalUtc;
  execution_release_identity_sha256: LowerHex64;
  target_host_identity_sha256: LowerHex64;
  installed_environment_sha256: LowerHex64;
  deployment_host_alias_sha256: LowerHex64;
  service_account_alias_sha256: LowerHex64;
  launcher_task_definition_sha256: LowerHex64;
  live_execution_task_definition_sha256: LowerHex64;
  handoff_issuer_id: string;
  handoff_key_id: string;
  handoff_public_key_fingerprint_sha256: LowerHex64;
  signature_algorithm: "RSASSA-PKCS1-v1_5-SHA256";
  signature_rsa_pkcs1v15_sha256_hex: LowerHex;
  central_unlock_required: true;
  session_reconstruction_authorized: true;
  direct_execution_authorized: false;
  broker_mutation_authorized: false;
  order_capability: "GATED_PRESENT";
}
```

```python
def decode_live_canary_provider_bound_runtime_session_handoff_policy(
    payload: bytes,
    *,
    expected_policy_sha256: str,
) -> LiveCanaryProviderBoundRuntimeSessionHandoffPolicy:
    """Decode one exact independently pinned public policy."""

def provider_bound_runtime_session_handoff_signing_message(
    handoff_payload: bytes,
) -> bytes:
    """Return the domain-separated message for an exact unsigned signature field."""

def load_live_canary_provider_bound_runtime_session_handoff(
    *,
    policy_payload: bytes,
    handoff_payload: bytes,
    candidate: LiveCanaryRuntimeCandidate,
    expected_policy_sha256: str,
    expected_handoff_sha256: str,
    expected_candidate_sha256: str,
    expected_session_sha256: str,
    expected_handoff_nonce_sha256: str,
    expected_execution_release_identity_sha256: str,
    expected_target_host_identity_sha256: str,
    expected_installed_environment_sha256: str,
    expected_deployment_host_alias_sha256: str,
    expected_service_account_alias_sha256: str,
    expected_launcher_task_definition_sha256: str,
    expected_live_execution_task_definition_sha256: str,
    external_replay_consumer: Callable[[bytes], bytes],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryProviderBoundRuntimeLaunchSession:
    """Verify, consume once externally, and reconstruct one exact sealed session."""
```

## Data Models

### Handoff policy

| Field group | Type | Constraints |
|---|---|---|
| policy identity | canonical identifiers | independently SHA-pinned exact bytes |
| handoff authority | RSA public key | 3072..8192 bits, exponent 65537 |
| replay authority | distinct RSA public key | 3072..8192 bits, exponent 65537 |
| target bindings | SHA-256 values | exact release, hosts, environment, account, tasks, ledger |
| reserved authorities | sorted unique arrays | excludes both new authorities |
| TTLs | integers | handoff 1..60s; replay request 1..5s |
| safety | constants | reconstruction only; no direct order authority |

### Signed handoff

| Field group | Type | Constraints |
|---|---|---|
| handoff/candidate/session | IDs and hashes | exact independent bindings |
| session | closed object | exact provider-bound session v2 payload |
| target bindings | SHA-256 values | equal policy, session, and external pins |
| validity | canonical UTC | ordered and bounded by every session expiry |
| signature | RSA PKCS#1 v1.5 SHA-256 | domain-separated exact signing payload |
| safety | constants | launch-session reconstruction only |

### Replay-consumption request and receipt

| Field group | Type | Constraints |
|---|---|---|
| request | canonical bytes | exact handoff, session, target, nonce, challenge |
| challenge | SHA-256 | derived from fresh exact 32-byte OS randomness |
| receipt | canonical signed object | binds exact request and consumption result |
| consumption | boolean and sequence | exactly true and positive sequence |
| validity | canonical UTC | within request and handoff windows |
| safety | constants | no execution or broker authority |

### Reconstructed session

| Field | Type | Constraints |
|---|---|---|
| class identity | exact registered class | private verifier seal present |
| canonical payload | session v2 | byte/hash equal signed payload |
| launch authority | booleans | bootstrap/process true only from prior session |
| order authority | booleans | direct execution and broker mutation false |
| downstream gates | booleans | per-order, promotion, risk/news, journal, MT5 required |

## Out of Scope

- OS-1: Enabling `execution_policy.LIVE_ALLOWED`; central unlock remains a
  separate ceremony after all authentic external evidence exists.
- OS-2: Operating the handoff signer or replay-ledger service, provisioning
  private keys, credentials, ACLs, Windows tasks, or network endpoints.
- OS-3: Implementing the final concrete 40-provider Windows runtime module or
  its 12 credential references; this feature supplies its exact session input.
- OS-4: Replacing provider acceptance, WORM custody, external launch CAS,
  launcher trust, promotion evidence, risk/news guards, journal leases,
  per-order authorization, or final MT5 submission checks.
- OS-5: Initializing MT5, calling `order_check`/`order_send`, starting a service,
  installing a task, or submitting a broker order during tests or probes.
- OS-6: Treating a successful decode, signature check, replay receipt, sealed
  session reconstruction, release build, or closure probe as production
  readiness or evidence that LIVE trading is active.
