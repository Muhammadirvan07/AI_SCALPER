# Spec: Windows LIVE Provider-Conformance External Acceptance v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved
**Reviewers:** AI_SCALPER project owner under the standing instruction to
continue the live-grade roadmap without weakening any execution or LIVE lock
**Related specs:**
`specs/windows_three_service_provider_conformance_v4.md`,
`specs/windows_live_canary_execution_source_bound_candidate_v1.md`,
`specs/windows_three_service_external_acceptance_v1.md`, and
`specs/live_canary_prebootstrap_admission_v1.md`

## Context

Three-service provider-conformance v4 reconstructs exactly 68 fresh provider
records and binds the 49-port LIVE Execution template to the sealed ten-pin
LIVE source-bound candidate. Its packet intentionally remains
`provider_accepted=false` because a locally generated review cannot authorize
itself. The live-grade chain still lacks a machine-verifiable object proving
that an independent service owner accepted that exact review and that a
separate Windows runtime authority attested the exact target host and runtime
evidence.

The existing three-service external-acceptance dossier is tied to the DEMO
operations-review bundle and its ten operational gates. It cannot be silently
reused as acceptance of the additive LIVE source-bound archive or its v4
provider inventory. Generic live-canary gate receipts also bind only an
evidence hash and do not reconstruct the exact 68-provider packet.

This feature adds a separate, offline RSA verification boundary. It re-runs
the authoritative ten-pin LIVE source verifier, reconstructs the exact v4
review, independently pins the acceptance policy and target Windows host,
requires two distinct RSA authorities, verifies presence and hashes of three
external evidence files, and emits a sealed provider-acceptance result. A
successful result may state `provider_accepted=true`, but it remains
non-executable and must be consumed by a later additive prebootstrap binding.

## Functional Requirements

- FR-1: The verifier MUST require an exact sealed
  `WindowsLiveCanaryExecutionSourceBoundCandidateVerification` and an exact
  sealed v4 `WindowsThreeServiceProviderConformanceReview`; caller-authored
  mappings or lookalike objects MUST NOT satisfy either requirement.
- FR-2: The v4 review MUST use schema
  `windows-three-service-provider-conformance-review-v4`, contain exactly 68
  providers, retain every deny-only field, and carry the exact LIVE source
  binding derived from the supplied sealed source verification.
- FR-3: A canonical acceptance policy MUST bind the exact v4 review SHA-256,
  LIVE-bound archive and binding identities, nested source-bound archive,
  atomic-suite identity, Decision/Execution/Status Monitor configured-release
  identities, target-host identity SHA-256, two RSA public authorities, a
  maximum acceptance lifetime, and the fixed signature algorithm.
- FR-4: The service-owner and Windows-runtime authorities MUST have distinct
  authority IDs, key IDs, public-key fingerprints, and RSA public keys. Each
  RSA key MUST be 3072 through 8192 bits, odd, canonical, and use exponent
  65537.
- FR-5: The verifier MUST require an independently supplied expected policy
  SHA-256 and expected target-host identity SHA-256. Neither pin may be taken
  only from the policy or signed documents being verified.
- FR-6: One canonical service-owner acceptance MUST bind the exact policy,
  v4 review, provider-evidence-set SHA-256, all three configured-release
  identities, target host, provider count 68, source-evidence SHA-256 equal to
  the v4 review content SHA-256, a distinct owner-validation-receipt SHA-256,
  outcome `PASSED`, validity interval, and service-owner authority.
- FR-7: One canonical runtime attestation MUST bind the exact policy, v4
  review, LIVE-bound archive/binding, target host, installed-environment
  SHA-256, runtime-provider-evidence SHA-256, a distinct runtime-validation
  receipt SHA-256, provider count 68, credential-reference count 12, runtime
  mode `LIVE`, outcome `PASSED`, validity interval, and Windows-runtime
  authority.
- FR-8: The service-owner acceptance and runtime attestation MUST each be
  authenticated with `RSASSA-PKCS1-v1_5-SHA256` over a domain-separated,
  canonical unsigned payload. The verifier MUST NOT expose signing or private
  key functionality.
- FR-9: The file API MUST stable-read and hash the exact owner validation
  receipt, runtime provider evidence, and runtime validation receipt. Their
  observed hashes MUST match the signed documents; all three files and hashes
  MUST be pairwise distinct and distinct from the v4 review hash.
- FR-10: Both signed documents MUST be current at the injected trusted UTC
  start and completion times. Their lifetime MUST be positive, no longer than
  the policy maximum, and the runtime observation MUST not predate the latest
  provider evidence observation carried by the v4 review.
- FR-11: A successful assessment MUST use status
  `LIVE_PROVIDER_CONFORMANCE_ACCEPTED_PREBOOTSTRAP_BINDING_REQUIRED`, set
  `provider_accepted=true`, and bind exact hashes for the review, policy,
  signatures, evidence files, LIVE source closure, target host, installed
  environment, three configured releases, and check time.
- FR-12: A successful assessment MUST retain
  `prebootstrap_binding_required=true`, `activation_allowed=false`,
  `execution_enabled=false`, `production_execution_ready=false`,
  `task_install_allowed=false`, `credential_access_performed=false`,
  `provider_imported=false`, `provider_materialized=false`,
  `broker_mutation_performed=false`, `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `promotion_eligible=false`,
  `order_capability=DISABLED`, and `max_lot=0.01`.
- FR-13: A public verifier MUST reconstruct the complete assessment rather
  than trusting its outer content hash and MUST require the exact same sealed
  source and v4 review objects, policy, signed documents, evidence bytes,
  external pins, and trusted time.
- FR-14: The operator CLI MUST independently run the authoritative ten-pin
  LIVE source verifier and v4 review verifier before acceptance assessment.
  It MUST require the complete ten-pin group, exact suite and Execution base,
  review, policy, two signed documents, three evidence files, two independent
  pins, and a create-exclusive output path.
- FR-15: Every input JSON and evidence file MUST be regular, non-empty,
  bounded, non-symlink/non-reparse, stable-read, and create-exclusive where
  applicable. JSON MUST reject duplicate keys, non-finite numbers, malformed
  UTF-8, noncanonical bytes, unknown fields, and wrong scalar types.
- FR-16: The implementation and CLI MUST be included only in the configured
  release operator tooling and absent from Decision, Execution, Status
  Monitor, and read-only-shadow service releases.
- FR-17: Verification MUST NOT read a credential/private key, import or
  materialize a provider, initialize MT5, open SQLite, access a network,
  spawn a subprocess, install/start a task or service, mutate central policy
  or a broker, issue a permit, or submit an order.
- FR-18: Existing v1-v4 provider-conformance, source-bound, external
  acceptance, prebootstrap, and live-canary APIs and canonical bytes MUST
  remain unchanged.

## Non-Functional Requirements

- NFR-1 Security: RSA verification MUST reuse the repository public-key
  primitive, enforce key separation, use constant-bound input sizes, and fail
  closed with stable reason codes without leaking evidence bytes or account
  identifiers.
- NFR-2 Determinism: Identical sealed inputs, canonical documents, evidence
  bytes, external pins, and trusted time MUST produce byte-identical
  assessment content and SHA-256.
- NFR-3 Compatibility: This MUST be an additive v1 contract and MUST NOT
  change any existing schema, validator, service release, or central lock.
- NFR-4 Reliability: Source and v4 review verification MUST finish before any
  acceptance output is published; a changed or existing path MUST never be
  overwritten or deleted.
- NFR-5 Performance: In-memory acceptance preparation and independent
  reconstruction MUST each complete in less than two seconds on the normal
  development host, excluding source-archive reconstruction and fixture
  construction.
- NFR-6 Resource bounds: Policy and each signed JSON document MUST be at most
  1,048,576 bytes; each external evidence file MUST be at most 64 MiB; the
  final assessment MUST be at most 1,048,576 bytes.
- NFR-7 Time: Policy maximum lifetime MUST be 60 through 3,600 seconds;
  timestamps MUST be canonical aware UTC with microsecond `Z` form, and the
  clock MUST be monotonic across verification.
- NFR-8 Regression: Focused tests MUST pass in normal and optimized Python;
  full regression, dependency lock, deterministic configured-tooling, and
  ship-gate checks MUST remain green or retain only documented external/manual
  blockers.

## Acceptance Criteria

### AC-1: Two-authority acceptance is exact and non-executable (FR-1 through FR-12)

Given an exact ten-pin LIVE source result, exact v4 review, independently
pinned policy and host, two distinct valid RSA signatures, and three matching
evidence files
When acceptance is prepared and independently reconstructed
Then the sealed result reports `provider_accepted=true`
And every activation, execution, live, promotion, broker, and order authority
remains denied.

### AC-2: Source and review substitution fail closed (FR-1, FR-2, FR-3, FR-13)

Given a v3 review, unsealed lookalike, different LIVE archive, changed source
binding, changed provider inventory, or recomputed outer review hash
When acceptance verification runs
Then it rejects before provider acceptance.

### AC-3: Policy and host require independent pins (FR-3, FR-5)

Given otherwise valid signed documents
When the expected policy or target-host pin differs
Then verification rejects and no result or output is produced.

### AC-4: Authority separation and RSA authenticity are mandatory (FR-4, FR-8)

Given reused owner/runtime authority identity, key ID, fingerprint, public key,
wrong modulus/exponent, wrong domain, or tampered signature
When policy or signature verification runs
Then acceptance rejects before counting either authority.

### AC-5: Evidence bytes are present and immutable (FR-6, FR-7, FR-9, FR-15)

Given signed evidence hashes
When any required file is absent, empty, oversized, indirect, unstable,
duplicated by content, or changed after signing
Then the file API rejects without output.

### AC-6: Freshness is anchored to provider observations (FR-10, NFR-7)

Given valid signatures whose interval is expired, future, too long, or whose
runtime observation predates the latest v4 provider observation
When acceptance runs
Then it rejects with a stable time reason and grants no acceptance.

### AC-7: CLI re-verifies the complete portable closure (FR-13, FR-14, NFR-4)

Given exact target-Windows files and all ten independent source pins
When the CLI succeeds
Then it has invoked the source verifier, reconstructed the v4 review, hashed
all three evidence files, and written one canonical create-exclusive
assessment
And no caller-supplied projection bypasses those verifiers.

### AC-8: Tampered assessment cannot self-validate (FR-11, FR-12, FR-13)

Given a valid assessment with any binding, acceptance, evidence, status,
safety, or outer content hash changed
When the public assessment verifier runs
Then reconstruction differs and the assessment is rejected.

### AC-9: Operator-only and effect-free boundary (FR-16, FR-17)

Given release allowlists and static/dynamic effect sentinels
When the tooling is built and acceptance verification runs
Then only the configured operator bundle contains this boundary
And credential, provider, SQLite, network, subprocess, scheduler, MT5, broker,
policy, permit, and order effects remain untouched.

### AC-10: Compatibility, bounds, and performance remain safe (FR-18, NFR-2 through NFR-8)

Given existing v1-v4 fixtures plus valid and invalid acceptance fixtures
When focused, optimized, full, dependency, deterministic-release, and
ship-gate checks run
Then canonical compatibility is preserved, bounded in-memory operations meet
their limits, and deployment remains blocked until real target-Windows and all
later live-canary evidence exists.

## Edge Cases

- EC-1: A sealed v3 review or 65-provider review is supplied -> reject.
- EC-2: A lookalike copies every sealed-result field -> reject exact seal.
- EC-3: Policy review, archive, suite, release, or host binding drifts ->
  reject policy or source binding.
- EC-4: Owner and runtime authorities reuse any identity, key, fingerprint, or
  modulus -> reject policy.
- EC-5: RSA modulus is noncanonical, even, below 3072 bits, above 8192 bits,
  or exponent differs from 65537 -> reject.
- EC-6: Signature is empty, wrong length, uppercase/noncanonical, signed over
  another domain, or tampered -> reject.
- EC-7: Signed outcome is not exact `PASSED` or count/mode differs from
  68/12/`LIVE` -> reject.
- EC-8: Owner source evidence is not the v4 review or owner receipt equals the
  review hash -> reject independence.
- EC-9: Runtime evidence, runtime validation receipt, owner validation receipt,
  or review hashes collide -> reject independence.
- EC-10: Signed document is not yet valid, expired, exceeds policy TTL, or
  assessment clock regresses -> reject.
- EC-11: Runtime observation predates one provider evidence record -> reject.
- EC-12: JSON has duplicate/unknown fields, non-finite values, noncanonical
  bytes, malformed UTF-8, wrong schema, or wrong scalar type -> reject.
- EC-13: Evidence file is missing, empty, a directory, symlink/reparse point,
  unstable, replaced during read, or above 64 MiB -> reject.
- EC-14: Output exists or is indirect -> reject without overwrite.
- EC-15: Final assessment says `provider_accepted=false`, grants another
  authority, or changes safety fields -> reject reconstruction.
- EC-16: Partial/mixed ten-pin CLI arguments or wrong archive/suite/base
  release -> reject before acceptance output.

## API Contracts

No HTTP, signing, scheduler, credential, broker, or policy-mutation API is
introduced. In particular, strings such as `POST /acceptance` are explicitly
not routes or contracts; this boundary is an offline Python and CLI verifier.

```python
def prepare_windows_live_provider_conformance_acceptance(
    *,
    source_verification: WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
    conformance_review: WindowsThreeServiceProviderConformanceReview,
    trust_policy: WindowsLiveProviderAcceptancePolicy,
    owner_acceptance: WindowsLiveProviderOwnerAcceptance,
    runtime_attestation: WindowsLiveProviderRuntimeAttestation,
    owner_validation_receipt_bytes: bytes,
    runtime_evidence_bytes: bytes,
    runtime_validation_receipt_bytes: bytes,
    expected_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    clock_provider: Callable[[], datetime],
) -> WindowsLiveProviderConformanceAcceptance: ...

def verify_windows_live_provider_conformance_acceptance(
    payload: Mapping[str, object],
    *,
    source_verification: WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
    conformance_review: WindowsThreeServiceProviderConformanceReview,
    trust_policy: WindowsLiveProviderAcceptancePolicy,
    owner_acceptance: WindowsLiveProviderOwnerAcceptance,
    runtime_attestation: WindowsLiveProviderRuntimeAttestation,
    owner_validation_receipt_bytes: bytes,
    runtime_evidence_bytes: bytes,
    runtime_validation_receipt_bytes: bytes,
    expected_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    clock_provider: Callable[[], datetime],
) -> WindowsLiveProviderConformanceAcceptance: ...
```

Command contract:

```text
python -I -S -B verify_windows_live_provider_conformance_acceptance.py \
  --live-source-bound-candidate <zip> \
  --base-suite-root <directory> \
  --execution-base-release <zip> \
  --expected-live-bound-archive-sha256 <sha256> \
  --expected-source-bound-archive-sha256 <sha256> \
  --expected-source-archive-sha256 <sha256> \
  --expected-champion-archive-sha256 <sha256> \
  --expected-model-artifact-sha256 <sha256> \
  --expected-training-snapshot-sha256 <sha256> \
  --expected-config-sha256 <sha256> \
  --expected-git-commit <full-git-sha> \
  --expected-git-tree <full-git-tree> \
  --expected-suite-identity-sha256 <sha256> \
  --conformance-review <v4-review.json> \
  --trust-policy <public-policy.json> \
  --owner-acceptance <signed-owner.json> \
  --runtime-attestation <signed-runtime.json> \
  --owner-validation-receipt <file> \
  --runtime-evidence <file> \
  --runtime-validation-receipt <file> \
  --expected-policy-sha256 <sha256> \
  --expected-target-host-identity-sha256 <sha256> \
  --output <new-assessment.json>
```

Exit code `0` means the exact dossier was cryptographically accepted but still
cannot execute. Exit code `2` means no assessment is trustworthy.

## Data Models

### `WindowsLiveProviderAcceptancePolicy`

| Field | Type | Constraint |
|---|---|---|
| policy/service binding fields | SHA-256 | Exact v4 review, LIVE closure, suite, and three configured releases |
| `target_host_identity_sha256` | SHA-256 | Exact independently pinned Windows host identity |
| owner authority fields | ID/RSA public key | Independent service-owner authority |
| runtime authority fields | ID/RSA public key | Independent Windows-runtime authority |
| `maximum_acceptance_ttl_seconds` | integer | 60 through 3,600 |
| `signature_algorithm` | enum | `RSASSA-PKCS1-v1_5-SHA256` |
| `schema_version` | enum | `windows-live-provider-acceptance-policy-v1` |
| `content_sha256` | derived | Canonical policy hash |

### `WindowsLiveProviderOwnerAcceptance`

| Field | Type | Constraint |
|---|---|---|
| binding fields | SHA-256 | Exact policy, review, evidence set, releases, and host |
| `provider_count` | integer | Exactly 68 |
| `source_evidence_sha256` | SHA-256 | Exact v4 review content hash |
| `validation_receipt_sha256` | SHA-256 | Exact separate file hash |
| validity fields | UTC | Positive, policy-bounded, current interval |
| authority/signature fields | ID/hex | Exact owner policy key and RSA signature |
| `schema_version` | enum | `windows-live-provider-owner-acceptance-v1` |

### `WindowsLiveProviderRuntimeAttestation`

| Field | Type | Constraint |
|---|---|---|
| binding fields | SHA-256 | Exact policy, review, LIVE archive/binding, and host |
| `installed_environment_sha256` | SHA-256 | Target runtime environment identity |
| runtime evidence fields | SHA-256 | Exact evidence and distinct validation receipt files |
| counts/mode | integer/enum | 68 providers, 12 references, exact `LIVE` |
| validity fields | UTC | Fresh relative to all v4 evidence observations |
| authority/signature fields | ID/hex | Exact runtime policy key and RSA signature |
| `schema_version` | enum | `windows-live-provider-runtime-attestation-v1` |

### `WindowsLiveProviderConformanceAcceptance`

| Field | Type | Constraint |
|---|---|---|
| all evidence bindings | SHA-256/ID | Reconstructed from sealed and signed inputs |
| `provider_accepted` | boolean | Exactly true only in this sealed result |
| `prebootstrap_binding_required` | boolean | Exactly true |
| all execution safety fields | boolean/enum | False/disabled |
| `schema_version` | enum | `windows-live-provider-conformance-acceptance-v1` |
| `content_sha256` | derived | Canonical assessment hash |

## Out of Scope

- OS-1: Generating an RSA key, private key, policy, signature, owner receipt,
  runtime evidence, or validation receipt.
- OS-2: Treating synthetic test signatures as target-Windows evidence.
- OS-3: Reading Credential Manager, importing providers, initializing MT5,
  installing or starting a task/service, or accessing a broker/network.
- OS-4: Binding this result into prebootstrap, launch-session, central unlock,
  per-order authorization, or execution; that requires a later additive spec.
- OS-5: Claiming demo soak, promotion, human approval, WORM/CAS custody,
  rollback, canary, acknowledgement, or reconciliation completion.
- OS-6: Changing existing conformance, source-bound, activation, or
  prebootstrap contracts.
- OS-7: Pair expansion, lot scaling, unattended live execution, or production
  deployment.
