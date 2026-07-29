# Live Canary Provider-Bound Portable Custody and Launch Session v2

**Author:** OpenAI Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved for implementation
**Reviewers:** senior architecture, security, and ship-gate

## Context

Provider-bound prebootstrap admission v1 closes the exact DEMO/LIVE source,
provider review, two-authority acceptance, target-host, installed-environment,
configured-release, task, activation, and candidate lineage. The existing
portable custody and launch-session v1 path predates that proof. It stores the
legacy admission in WORM, reserves a launcher nonce through signed CAS, and
can create a launch-only session after a separately reviewed central unlock.

The v1 path is intentionally sealed and safe for its original contract, but
it cannot prove that the externally accepted 68-provider Windows environment
was the environment released to launch. A central unlock must therefore never
allow a legacy-only session to enter production after provider-bound admission
is available.

This feature adds a separately domain-separated WORM receipt and verifier for
the provider-bound admission, then adds a provider-bound launch-session v2.
The v2 session composes that new custody result with the existing immutable
v1 WORM/CAS reservation rather than rewriting the already reviewed CAS
protocol. Existing v1 canonical documents remain verifiable, but production,
per-order authorization, and Windows LIVE materialization accept only the new
provider-bound session type.

## Goals

- Store and read back the exact provider-bound admission through an
  independently signed, compliance-retained WORM receipt.
- Bind custody policy host/task and custody authority separation to the exact
  provider acceptance policy and provider-bound admission.
- Reuse the existing signed one-use CAS reservation while proving it belongs
  to the same legacy admission, activation, candidate, release, and launcher.
- Produce a new exact-type, verifier-sealed launch-session v2 whose lifetime
  cannot exceed provider acceptance, WORM custody, or v1 launch capability.
- Make all production and per-order consumers reject a legacy-only v1 launch
  session without changing v1 canonical bytes.
- Keep the checked-in central LIVE lock false and perform no real process,
  credential, provider, MT5, broker, permit, or order effect.

## Functional Requirements

- FR-1: A new immutable provider-bound WORM receipt MUST use a new schema and
  RSA signing domain. It MUST bind custody policy, provider-bound admission,
  legacy admission, candidate, DEMO and LIVE source verification projections,
  provider acceptance/policy/review, host, installed environment, configured
  release, task, activation authorization/validation, limiting provider
  expiry, WORM object identity, exact stored bytes, retention interval, and
  custody public authority.
- FR-2: Receipt decoding MUST require exact canonical UTF-8 JSON, exact field
  inventory, no duplicate keys, bounded size, canonical aware-UTC timestamps,
  and a non-empty RSA signature.
- FR-3: Custody verification MUST require an exact
  `LiveCanaryPortableCustodyPolicy`, independent policy hash pin, exact sealed
  `LiveCanaryProviderBoundPrebootstrapAdmission`, exact
  `WindowsLiveProviderAcceptancePolicy`, WORM readback callback, and trusted
  aware-UTC clock.
- FR-4: The provider policy hash MUST match the admission. Custody policy host
  and task MUST match the admission target host and LIVE Execution task. The
  custody key ID and fingerprint MUST be distinct from both provider owner and
  runtime authorities.
- FR-5: The receipt MUST match every bound admission field exactly. Its stored
  hash/size and byte-identical WORM readback MUST equal the provider-bound
  admission canonical bytes.
- FR-6: Verification MUST reject upload before admission, upload in the future,
  stale receipt, insufficient retention, expired retention, expired provider
  acceptance, invalid RSA signature, callback failure, mutable/mismatched
  readback, clock regression, or central-lock drift.
- FR-7: Successful custody verification MUST return a module-sealed immutable
  result binding the receipt, policy, provider-bound admission, legacy
  admission, candidate, acceptance, host/environment/release/task,
  authorization/validation, WORM object, checked time, retention, and the
  earliest of retention and provider-acceptance expiry.
- FR-8: The new launch composition MUST require exact candidate, sealed legacy
  admission, sealed provider-bound admission, sealed provider-bound custody,
  sealed existing v1 one-use capability, exact launcher policy, all existing
  independent pins, two new independent provider-bound pins, external signed
  checkpoint readback, external nonce observation, and trusted clock.
- FR-9: The provider-bound admission MUST bind the supplied legacy admission,
  candidate, activation authorization and validation. The custody result MUST
  bind that exact provider-bound admission and candidate.
- FR-10: Provider-bound host and task MUST equal the launcher policy host and
  task. Provider-bound configured release MUST equal the candidate release and
  launcher-attested release. Installed environment MUST equal the candidate.
- FR-11: The existing v1 activation function MUST remain available for
  compatibility tests, and v1 canonical contracts MUST remain byte-compatible.
  It MUST NOT satisfy the new provider-bound session predicate.
- FR-12: The v2 activation function MUST invoke the existing v1 launch-session
  verifier/consumer for exact checkpoint and nonce handling, then wrap only a
  freshly sealed v1 session after rechecking provider custody, expiry, and
  central policy.
- FR-13: A v2 session MUST include all v1 launch bindings plus hashes of the
  legacy session, provider-bound admission, provider-bound custody, provider
  acceptance, target host, installed environment, LIVE task, and limiting
  provider expiry.
- FR-14: `valid_until_utc` MUST be the minimum of v1 session expiry,
  provider-bound admission expiry, and verified provider-bound custody expiry.
  No caller-selected validity extension is allowed.
- FR-15: Production bootstrap/composition, per-order authorization, and Windows
  LIVE materialization MUST accept only the exact registered provider-bound v2
  session type and its module-owned seal. A v1 session, subclass, duck type,
  copied fields, or `object.__new__` lookalike MUST fail closed.
- FR-16: The v2 session may set launch-only flags true only after the existing
  central LIVE ceremony is already open. It MUST keep
  `execution_authorized=false`, `broker_mutation_authorized=false`,
  `safe_to_demo_auto_order=false`, require independent per-order authority and
  all existing guards, and retain XAUUSD/0.01/one-position scope.
- FR-17: Provider-bound custody verification MUST run only while the checked-in
  central LIVE policy remains locked. V2 session activation MUST use the
  existing reviewed central-unlock checks before and after external reads and
  before returning.
- FR-18: Failures MUST expose stable uppercase reason codes without raw receipt
  bytes, account identifiers, filesystem paths, provider data, credentials,
  private keys, callback text, or nested external exception details.
- FR-19: New custody code MUST contain no private-key/signing implementation,
  filesystem writes, storage client, network client, subprocess, credential
  store, provider import, SQLite, Task Scheduler, MT5, broker mutation, permit
  issuance, central-policy mutation, or order submission.
- FR-20: No synthetic fixture, passing test, provider acceptance, custody
  result, CAS reservation, or v2 session by itself may be represented as
  external evidence or authorization to trade.

## Non-Functional Requirements

- NFR-1: Implementation MUST use Python 3.12 standard-library primitives and
  existing immutable project contracts only.
- NFR-2: Identical inputs and clock readings MUST produce byte-identical
  canonical receipts/results and content SHA-256 values.
- NFR-3: All numeric limits MUST reject booleans and non-finite values; every
  hash and timestamp MUST be validated without `assert`.
- NFR-4: Behavior MUST be identical under normal Python and `python -O` /
  `PYTHONOPTIMIZE=2`.
- NFR-5: In-memory verification and launch wrapping, excluding RSA fixture
  creation and external callback latency, MUST complete in less than two
  seconds on the development host.
- NFR-6: Tests MUST use only synthetic public-key fixtures and in-memory fake
  WORM/CAS providers; they MUST require no Windows, network, credential,
  provider, MT5, scheduler, broker, or private production material.
- NFR-7: Existing v1 focused tests and complete normal/optimized repository
  regressions MUST remain green.

## Acceptance Criteria

### AC-1: Exact provider-bound admission is retained (FR-1, FR-2, FR-3, FR-5)

Given a sealed provider-bound admission and exact signed v2 WORM receipt
When verification reads the exact retained object bytes
Then receipt, policy, admission, activation, source, provider, host,
environment, release, task, object, and retention identities are bound.

### AC-2: Provider and custody trust domains are separated (FR-4)

Given otherwise valid receipt and policy inputs
When custody reuses either provider authority key ID or fingerprint, or policy
host/task differs from the provider-bound admission
Then verification rejects before WORM readback or a sealed result.

### AC-3: Time, retention, and readback fail closed (FR-5, FR-6, FR-7)

Given signed receipt, provider expiry, and WORM object
When upload/age/retention/provider validity is wrong, the clock regresses, the
callback fails, or bytes differ
Then no custody verification is emitted and external details do not escape.

### AC-4: Exact legacy CAS chain is composed, not replaced (FR-8, FR-9, FR-12)

Given one sealed existing v1 one-use reservation for the legacy admission
When v2 activation runs
Then the existing checkpoint and nonce are observed and consumed by the v1
verifier and the same candidate/legacy/provider-bound chain is rechecked.

### AC-5: Windows target and release are exact (FR-10)

Given one provider-bound admission and launcher policy
When host, installed environment, configured release, task, candidate,
authorization, validation, or launcher binding differs
Then v2 activation emits no session.

### AC-6: Earliest lifetime controls launch (FR-13, FR-14, FR-17)

Given distinct v1 capability, provider acceptance, and WORM custody expiries
When v2 session is emitted
Then its validity ends at their exact minimum
And activation at/after that minimum or across clock/policy regression fails.

### AC-7: Downstream rejects legacy-only session (FR-11, FR-15)

Given a valid sealed v1 session and a valid sealed v2 session
When production bootstrap, per-order authorization, or Windows LIVE
materialization validates runtime authority
Then only the exact provider-bound v2 session passes the authority predicate.

### AC-8: V2 remains launch-only and sealed (FR-15, FR-16, FR-18)

Given every exact proof and an independently opened central ceremony
When v2 activation succeeds
Then launch-only flags are true, every order/broker flag remains guarded, all
provider-bound hashes are present, and direct/forged construction is rejected.

### AC-9: No effects and regressions remain green (FR-19, FR-20; NFR-1 through NFR-7)

Given success and rejection paths
When static, focused, dependency, normal, optimized, and full gates run
Then no forbidden effect is reachable, v1 canonical fixtures remain stable,
the checked-in central lock remains false, and no broker order is submitted.

## Edge Cases

- EC-1: Receipt is valid RSA but for a legacy admission -> reject.
- EC-2: Receipt omits one DEMO/LIVE/provider/host/environment/task binding ->
  exact schema or binding rejection.
- EC-3: Provider policy hash matches but custody reuses its owner/runtime key ->
  reject authority reuse.
- EC-4: WORM callback returns text, empty/oversized bytes, or a byte-different
  canonical object -> reject.
- EC-5: Retention remains valid but provider acceptance expires -> reject.
- EC-6: Provider admission is current at custody but expires during launch ->
  reject or clamp session to the earlier expiry.
- EC-7: V1 capability belongs to another legacy admission or candidate ->
  reject before v2 session creation.
- EC-8: Launcher host/task/release differs from provider-bound Windows target
  closure -> reject.
- EC-9: External checkpoint changes between reads or nonce is absent ->
  existing v1 verifier rejects and no v2 session is returned.
- EC-10: V1 session is valid but presented directly to a production consumer ->
  reject exact provider-bound session predicate.
- EC-11: Central LIVE policy is locked, partially enabled, or changes during
  activation -> reject.
- EC-12: Direct constructor, subclass, copied private field, or
  `object.__new__` lookalike -> reject the public v2 predicates.

## API Contracts

HTTP API: N/A. The marker `POST /not-applicable` is documentation-only and
MUST NOT be implemented or exposed.

```python
@dataclass(frozen=True)
class LiveCanaryProviderBoundAdmissionCustodyReceipt(CanonicalContract):
    provider_bound_admission_sha256: str
    legacy_admission_sha256: str
    candidate_sha256: str
    provider_acceptance_sha256: str
    provider_acceptance_valid_until_utc: datetime
    stored_content_sha256: str
    stored_content_size_bytes: int
    signature_rsa_pkcs1v15_sha256_hex: str

def verify_live_canary_provider_bound_admission_custody(
    receipt_payload: bytes,
    *,
    policy: LiveCanaryPortableCustodyPolicy,
    expected_policy_sha256: str,
    admission: LiveCanaryProviderBoundPrebootstrapAdmission,
    provider_acceptance_policy: WindowsLiveProviderAcceptancePolicy,
    object_readback_provider: Callable[[str, str, str], bytes],
    clock_provider: Callable[[], datetime],
) -> VerifiedLiveCanaryProviderBoundAdmissionCustody:
    """Verify exact provider-bound WORM custody without launch authority."""

def activate_live_canary_provider_bound_runtime_launch_session(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    legacy_admission: LiveCanaryPrebootstrapAdmission,
    provider_bound_admission: LiveCanaryProviderBoundPrebootstrapAdmission,
    provider_bound_custody: VerifiedLiveCanaryProviderBoundAdmissionCustody,
    launch_capability: LiveCanaryOneUseLaunchCapability,
    expected_provider_bound_admission_sha256: str,
    expected_provider_bound_custody_sha256: str,
    **existing_v1_launch_arguments: object,
) -> LiveCanaryProviderBoundRuntimeLaunchSession:
    """Return v2 launch-only authority after exact provider-bound checks."""
```

## Data Models

```text
provider-bound admission --signed WORM receipt/readback--> sealed v2 custody
         |                                                     |
legacy admission --existing WORM/CAS--> v1 one-use capability |
         |                                   |                 |
         +--------------------------- v2 launch composition <--+
                                             |
                                             v
                         provider-bound launch session v2
                                             |
                      production/per-order/Windows consumers
```

| Field group | Type | Constraint |
| --- | --- | --- |
| provider-bound receipt | hashes/UTC/RSA | New domain, exact canonical fields, signed externally |
| verified custody | hashes/UTC/seal | Exact WORM bytes and minimum provider/retention expiry |
| existing reservation | v1 sealed contracts | Exact legacy admission checkpoint and nonce CAS |
| provider-bound session | hashes/UTC/seal | V1 session plus provider admission/custody/target closure |
| runtime scope | string/float/integer | XAUUSD, lot 0.01, one position |
| execution safety | booleans/enum | Launch-only; per-order authority and all guards still mandatory |

## Out of Scope

- OS-1: Replacing or rewriting the existing v1 WORM receipt, CAS proposal,
  checkpoint, acknowledgement, or capability schemas.
- OS-2: Creating keys/signatures, implementing an object store/CAS backend, or
  embedding storage, launcher, provider, credential, MT5, or broker clients.
- OS-3: Changing `execution_policy.LIVE_ALLOWED`, symbol/lot bounds, DEMO_AUTO
  policy, or central unlock ceremony.
- OS-4: Treating local fixtures as Windows/provider/custody evidence.
- OS-5: Starting a process, materializing providers, initializing MT5,
  issuing an order permit, mutating a broker, or submitting an order.
- OS-6: Actual XM demo soak, external approvals, first canary execution,
  reconciliation, rollback drill, pair expansion, or lot scaling.

## Assumptions

- The v1 CAS authority and provider-bound WORM authority are represented by
  the same custody policy in v2; policy-pinned key separation from provider,
  launcher, activation, and runtime domains remains mandatory.
- External WORM immutability and CAS atomicity are attested by their signed
  receipts and callbacks; this code verifies rather than implements them.
- The activation request and provider acceptance windows are long enough to
  complete both custody checks and the bounded launch ceremony.
- Downstream runtime consumers can switch to an additive exact v2 session
  predicate without changing the per-order execution contract.

## Risks and Mitigations

- **Risk:** Legacy-only session bypasses provider evidence. **Mitigation:**
  production, per-order, and Windows LIVE consumers require the exact v2 type.
- **Risk:** WORM receipt covers a provider result for another host. **Mitigation:**
  bind host/environment/release/task and require policy host/task equality.
- **Risk:** A valid provider result expires after custody. **Mitigation:** clamp
  custody and session lifetime to the provider-bound limiting expiry.
- **Risk:** New CAS logic introduces a parallel replay ledger. **Mitigation:**
  reuse the existing signed v1 checkpoint/ack/nonce protocol exactly.
- **Risk:** Custody signer can impersonate provider acceptance. **Mitigation:**
  require disjoint custody and provider authority IDs/fingerprints.
- **Risk:** Provider-bound launch is mistaken for order authority. **Mitigation:**
  retain independent per-order authorization and all immediate pre-send guards.

## Open Questions

- Which external WORM repository and CAS service will supply the first real
  v2 receipt/readback/checkpoint evidence on the target Windows host?
- Which reviewed central-policy commit will first make the provider-bound v2
  session reachable after all external gates are accepted?
