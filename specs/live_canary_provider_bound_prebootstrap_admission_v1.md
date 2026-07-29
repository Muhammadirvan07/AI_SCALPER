# Live Canary Provider-Bound Prebootstrap Admission v1

**Author:** OpenAI Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved for implementation
**Reviewers:** senior architecture, security, and ship-gate

## Context

AI_SCALPER has two deliberately separate deny-only proofs. The existing
`LiveCanaryPrebootstrapAdmission` binds a complete non-secret XAUUSD LIVE
runtime candidate to the reviewed DEMO source lineage and one consumed LIVE
activation. The Windows LIVE provider-conformance acceptance independently
binds an exact 68-provider review, a ten-pin LIVE source-bound Execution
candidate, two external RSA authorities, one target Windows host, and one
installed environment.

Neither proof currently establishes that they describe the same candidate,
release, source ancestry, target host, installed environment, activation, and
time window. The provider acceptance also records the time at which it was
checked but intentionally does not become a reusable execution permit. A
caller must not be able to replay a once-valid acceptance after either signed
authority document expires.

This feature adds one additive composition boundary. It re-runs the existing
provider-acceptance verifier at the current trusted time, correlates its exact
LIVE and DEMO ancestry with the existing sealed prebootstrap admission and
runtime candidate, derives the earliest signed-document expiry, and emits a
new verifier-sealed provider-bound admission. The output remains deny-only and
must later replace the legacy admission at the portable-custody boundary.

## Goals

- Bind provider acceptance to the exact activation, runtime candidate, DEMO
  ancestry, LIVE source archive, configured Execution release, host, task,
  and installed environment.
- Make the earliest owner/runtime signature expiry explicit and enforceable
  by downstream custody and launch windows.
- Preserve the existing prebootstrap, source-bound, conformance, and provider
  acceptance schemas and canonical bytes.
- Keep the checked-in central LIVE lock false and grant no launch, execution,
  credential, broker, permit, or order authority.

## Functional Requirements

- FR-1: Assessment MUST require an exact verifier-sealed
  `LiveCanaryPrebootstrapAdmission`, exact `LiveCanaryRuntimeCandidate`, exact
  verifier-sealed DEMO `WindowsExecutionSourceBoundCandidateVerification`,
  and exact verifier-sealed LIVE
  `WindowsLiveCanaryExecutionSourceBoundCandidateVerification`.
- FR-2: The legacy admission MUST bind the exact candidate, DEMO source
  projection, activation trust policy, authorization, request, activation
  binding, and consumed validation supplied to this assessment.
- FR-3: The LIVE source-bound verification MUST contain the exact DEMO
  source-bound archive and binding identity, production source, bootstrap,
  suite, Execution base archive/release, Git commit/tree, and source ancestry
  represented by the sealed DEMO verification and runtime candidate.
- FR-4: The runtime candidate commit MUST equal the LIVE source commit. Its
  release-manifest SHA-256 MUST equal the LIVE configured Execution release
  identity. The LIVE task-definition SHA-256 MUST be retained in the output.
- FR-5: Assessment MUST require the exact v4 provider-conformance review,
  provider acceptance policy, owner acceptance, runtime attestation, owner
  validation receipt bytes, runtime evidence bytes, runtime validation receipt
  bytes, independently supplied policy pin, and independently supplied target
  host pin required by the existing provider-acceptance verifier.
- FR-6: Assessment MUST invoke
  `prepare_windows_live_provider_conformance_acceptance` with those exact
  inputs during the current assessment. It MUST NOT trust a previously emitted
  acceptance JSON, content hash, caller-authored projection, or stale sealed
  acceptance result.
- FR-7: The freshly sealed provider acceptance MUST bind the exact LIVE
  archive/binding, nested DEMO source-bound archive, production source,
  atomic suite, configured Execution release, target host, installed
  environment, provider count 68, and credential-reference count 12.
- FR-8: The runtime candidate installed-environment SHA-256 MUST equal the
  provider acceptance installed-environment SHA-256.
- FR-9: The provider owner/runtime authority key IDs and public-key
  fingerprints MUST be disjoint from every runtime candidate trust identity
  and every activation trust-policy authority identity.
- FR-10: Assessment MUST require exact activation trust policy,
  authorization, and verifier-sealed consumed validation types. Their hashes
  and request/binding lineage MUST equal the legacy admission and candidate.
- FR-11: Assessment MUST use a caller-supplied trusted aware-UTC clock. The
  clock MUST not regress across entry, provider acceptance, and completion.
  Assessment MUST start after all upstream checks and finish strictly before
  the activation request, owner acceptance, and runtime attestation expire.
- FR-12: `provider_acceptance_valid_until_utc` MUST equal the earliest of the
  owner acceptance expiry, runtime attestation expiry, and activation request
  expiry. The result MUST not accept a caller-selected validity value.
- FR-13: Assessment MUST fail if checked-in
  `execution_policy.LIVE_ALLOWED` is not exactly false or if the LIVE policy
  decision differs from `(False, ("LIVE_MODE_LOCKED",))` at entry or
  completion.
- FR-14: A successful result MUST bind the legacy admission, candidate, DEMO
  verification projection, LIVE verification projection, fresh provider
  acceptance, provider policy, review, activation, host, environment,
  configured release, task, Git, symbol, lot, position, check time, and
  validity limit.
- FR-15: A successful result MUST use status
  `PROVIDER_BOUND_PREBOOTSTRAP_EVIDENCE_COMPLETE_CUSTODY_AND_CENTRAL_UNLOCK_REQUIRED`,
  set `provider_accepted=true`, `provider_binding_complete=true`,
  `portable_custody_required=true`, and `central_unlock_required=true`.
- FR-16: A successful result MUST retain `bootstrap_authorized=false`,
  `process_launch_authorized=false`, `execution_authorized=false`,
  `activation_authorized=false`, `broker_mutation_authorized=false`,
  `live_allowed=false`, `safe_to_demo_auto_order=false`,
  `promotion_eligible=false`, `order_capability=DISABLED`, and `max_lot=0.01`.
- FR-17: The result MUST be constructible only through a module-owned verifier
  seal. Direct construction, subclassing, duck typing, copied fields, and
  `object.__new__` lookalikes MUST fail the public seal predicate.
- FR-18: Public failures MUST expose stable uppercase reason codes and MUST
  not include evidence bytes, raw account identifiers, private keys,
  credential material, filesystem locations, or nested exception text.
- FR-19: The module MUST contain no filesystem write, network client,
  subprocess, credential store, private-key operation, provider import,
  SQLite, Task Scheduler, MT5 initialization, process launch, broker mutation,
  permit issuance, central-policy mutation, or order-submission surface.
- FR-20: Existing v1 prebootstrap, provider acceptance, source-bound,
  conformance-review, activation, custody, and launch-session schemas and
  canonical bytes MUST remain unchanged by this additive boundary.

## Non-Functional Requirements

- NFR-1: Implementation MUST use Python 3.12 standard-library primitives and
  existing immutable project contracts only.
- NFR-2: Canonical serialization MUST use repository `CanonicalContract`
  rules, reject non-finite numbers, and reject booleans where numeric values
  are expected.
- NFR-3: Identical exact inputs and trusted clock readings MUST produce
  byte-identical canonical output and content SHA-256.
- NFR-4: Validation MUST not use `assert`, mutable caller-selected authority
  values, copied private seals, or implicit wall-clock access, and MUST behave
  identically under `python -O` / `PYTHONOPTIMIZE=2`.
- NFR-5: In-memory assessment excluding fixture/archive reconstruction MUST
  complete in less than two seconds on the normal development host.
- NFR-6: Focused tests MUST run without Windows, network, credentials,
  providers, MT5, scheduler privileges, broker access, or private keys outside
  synthetic test fixtures already owned by the provider verifier tests.
- NFR-7: Existing focused and full repository tests MUST remain green in
  normal and optimized modes.

## Acceptance Criteria

### AC-1: Exact legacy and LIVE ancestry compose (FR-1, FR-2, FR-3, FR-4)

Given one sealed legacy admission, its exact candidate and DEMO source, and
one LIVE source-bound verification containing that DEMO archive
When provider-bound assessment runs
Then DEMO archive/binding/source/bootstrap/suite/role/Git identities match
And the candidate release and commit match the exact LIVE configured release.

### AC-2: Provider acceptance is re-run, not replayed (FR-5, FR-6, FR-7)

Given exact provider review, policy, two signed authority documents, three
evidence byte sources, and two independent pins
When assessment runs
Then the existing provider verifier is invoked at the current trusted time
And a previous acceptance hash or JSON cannot bypass signature, evidence,
source, host, or freshness verification.

### AC-3: Host and installed environment are exact (FR-7, FR-8)

Given valid signatures for one Windows target
When the host pin, runtime installed-environment hash, LIVE archive, suite,
release, or task differs from the candidate chain
Then assessment fails without a provider-bound result.

### AC-4: Trust domains remain independent (FR-9, FR-10)

Given activation, runtime, service-owner, and Windows-runtime authorities
When a provider authority key ID or fingerprint is reused by either upstream
trust domain
Then assessment rejects before emitting the new admission.

### AC-5: Earliest expiry is authoritative (FR-11, FR-12)

Given owner, runtime, and activation intervals with different expiries
When assessment succeeds
Then `provider_acceptance_valid_until_utc` equals their exact minimum
And assessment at or after any limiting expiry, across clock regression, or
after a provider document expires emits no result.

### AC-6: Central LIVE lock remains mandatory (FR-13)

Given every external proof is valid
When the checked-in LIVE lock is true or its denial reason drifts at entry or
completion
Then assessment fails closed and does not grant custody or launch authority.

### AC-7: Output is sealed, canonical, and deny-only (FR-14, FR-15, FR-16, FR-17)

Given every exact binding passes
When the result is returned
Then all upstream hashes and the earliest expiry are canonical and stable
And provider acceptance is distinguished from runtime/order authority
And all launch, execution, broker, and order flags remain denied.

### AC-8: Substitution and malformed types fail safely (FR-17, FR-18)

Given an unsealed object, cross-candidate proof, wrong scalar type, zero hash,
malformed time, copied seal field, or changed upstream identity
When assessment runs
Then no sealed result is emitted and only a stable reason code is exposed.

### AC-9: Effect-free optimized regression (FR-19, FR-20; NFR-1 through NFR-7)

Given success and rejection paths
When static, focused, related, full, dependency, normal, and optimized checks
run
Then no forbidden effect is reachable, existing canonical contracts remain
unchanged, and the checked-in central LIVE lock remains false.

## Edge Cases

- EC-1: Legacy admission is sealed but belongs to another candidate,
  authorization, validation, policy, DEMO source, or check time -> reject.
- EC-2: LIVE source embeds another DEMO archive, source, bootstrap, suite,
  Execution role, commit, or tree -> reject.
- EC-3: Candidate commit or release manifest differs from LIVE source ->
  reject.
- EC-4: Provider review or acceptance policy is for another LIVE archive,
  host, suite, configured release, or provider inventory -> existing verifier
  rejects.
- EC-5: Runtime attestation environment differs from candidate environment ->
  reject.
- EC-6: Provider count is not 68 or credential-reference count is not 12 ->
  reject.
- EC-7: Owner/runtime key ID or fingerprint collides with runtime/activation
  trust -> reject.
- EC-8: Owner or runtime signature is valid at an earlier time but expired at
  current assessment -> reject; no stale acceptance input is accepted.
- EC-9: Assessment starts inside all windows but completes at the earliest
  expiry -> reject.
- EC-10: Clock returns non-UTC, moves backward, or provider verification time
  predates the outer assessment start -> reject.
- EC-11: Central policy changes between entry and completion -> reject.
- EC-12: Direct constructor, subclass, duck type, or `object.__new__`
  lookalike -> reject the public seal predicate.

## API Contracts

HTTP API: N/A. The marker `POST /not-applicable` is documentation-only and
MUST NOT be implemented or exposed.

```python
@dataclass(frozen=True)
class LiveCanaryProviderBoundPrebootstrapAdmission(CanonicalContract):
    checked_at: datetime
    provider_acceptance_valid_until_utc: datetime
    legacy_admission_sha256: str
    candidate_sha256: str
    demo_source_bound_verification_sha256: str
    live_source_bound_verification_sha256: str
    provider_acceptance_sha256: str
    provider_acceptance_policy_sha256: str
    provider_conformance_review_sha256: str
    target_host_identity_sha256: str
    installed_environment_sha256: str
    live_execution_release_identity_sha256: str
    live_execution_task_definition_sha256: str
    provider_accepted: bool = True
    portable_custody_required: bool = True
    central_unlock_required: bool = True
    bootstrap_authorized: bool = False
    process_launch_authorized: bool = False
    execution_authorized: bool = False
    broker_mutation_authorized: bool = False
    live_allowed: bool = False
    order_capability: str = "DISABLED"

def assess_live_canary_provider_bound_prebootstrap_admission(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    legacy_admission: LiveCanaryPrebootstrapAdmission,
    demo_source_bound_verification: WindowsExecutionSourceBoundCandidateVerification,
    live_source_bound_verification: WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
    conformance_review: WindowsThreeServiceProviderConformanceReview,
    provider_acceptance_policy: WindowsLiveProviderAcceptancePolicy,
    owner_acceptance: WindowsLiveProviderOwnerAcceptance,
    runtime_attestation: WindowsLiveProviderRuntimeAttestation,
    owner_validation_receipt_bytes: bytes,
    runtime_evidence_bytes: bytes,
    runtime_validation_receipt_bytes: bytes,
    expected_provider_acceptance_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    activation_trust_policy: LiveCanaryTrustPolicy,
    authorization: LiveCanaryActivationAuthorization,
    validation: LiveCanaryActivationValidation,
    clock_provider: Callable[[], datetime],
) -> LiveCanaryProviderBoundPrebootstrapAdmission:
    """Return fresh sealed deny-only composition or fail closed."""
```

## Data Models

`LiveCanaryProviderBoundPrebootstrapAdmission` is an immutable in-memory
canonical value with a module-owned verifier seal. Its content identity binds
all existing admission and provider-acceptance inputs plus the limiting
expiry. The result intentionally contains no raw evidence bytes, account
login, credential, private key, provider object, runtime configuration, or
effect callback.

```text
sealed legacy admission + candidate + sealed DEMO source --------+
                                                                  |
sealed LIVE source + exact v4 review -----------------------------+
                                                                  +--> sealed provider-bound admission
policy + two RSA documents + three exact evidence byte sources ---+
                                                                  |
activation policy + authorization + consumed validation ----------+
```

| Field group | Type | Constraint |
| --- | --- | --- |
| upstream admission | SHA-256/ID | Exact legacy admission, candidate, activation, and validation |
| DEMO/LIVE source | SHA-256/Git SHA | Exact sealed ancestry and configured release closure |
| provider acceptance | SHA-256/count/UTC | Freshly verified 68/12 result and earliest expiry |
| Windows target | SHA-256 | Exact host, installed environment, release, and task |
| runtime scope | string/float/integer | XAUUSD, lot 0.01, one position |
| safety | bool/enum | Provider accepted only; custody/unlock required; all effects denied |

## Out of Scope

- OS-1: Replacing this result into portable custody or launch-session APIs;
  that is the next versioned migration after this additive verifier is green.
- OS-2: Changing `execution_policy.LIVE_ALLOWED`, DEMO_AUTO policy, symbol/lot
  bounds, release locks, or any existing canonical schema.
- OS-3: Generating RSA keys/signatures or treating synthetic fixtures as real
  target-Windows evidence.
- OS-4: Reading files, credentials, private keys, provider implementations,
  SQLite state, Task Scheduler, MT5, broker state, or network resources.
- OS-5: Launching a process, materializing a provider, issuing a permit,
  mutating a broker, or submitting an order.
- OS-6: Claiming demo soak, external approvals, WORM/CAS custody, rollback,
  canary completion, or unrestricted live-trading readiness.
- OS-7: Pair expansion, lot scaling, or multi-position execution.

## Assumptions

- Real provider acceptance will be generated only after this composition
  boundary and its downstream custody migration are released to Windows.
- The owner and runtime signed-document expiry values are authoritative and
  remain available to this in-process composition call.
- Existing activation request lifetime is short enough to compose provider
  acceptance and portable custody before the earliest expiry.

## Risks and Mitigations

- **Risk:** A once-valid provider acceptance is replayed after signature
  expiry. **Mitigation:** do not accept an old result; re-run its verifier at
  current trusted time and bind the earliest signed expiry.
- **Risk:** A provider result for one Windows host is combined with another
  runtime candidate. **Mitigation:** bind host, installed environment,
  configured release, task, source archive, suite, and commit exactly.
- **Risk:** Provider authority material is reused by activation or runtime.
  **Mitigation:** require disjoint key IDs and fingerprints.
- **Risk:** Provider acceptance is mistaken for permission to trade.
  **Mitigation:** provider acceptance is the only true authority claim;
  custody, launch, execution, broker mutation, and orders remain false.

## Open Questions

- Which target-Windows operator release will first expose a single CLI that
  recreates the legacy admission and this provider-bound admission in one
  process?
- Which external WORM/CAS authority will sign the first provider-bound
  admission receipt after the downstream custody migration?
