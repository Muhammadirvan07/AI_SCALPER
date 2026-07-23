# Spec: Windows Three-Service External Acceptance Dossier v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-24
**Status:** Approved
**Reviewers:** AI_SCALPER project owner (standing authorization to continue the
Live-Grade roadmap through demo-auto-soak readiness)
**Related specs:** `specs/windows_three_service_demo_soak_operations_v3.md`,
`specs/demo_auto_stage_authorization_v1.md`,
`specs/windows_external_launcher_attestation_v1.md`

## Context

The local decision, execution/reconciliation, and external-status-monitor
services now have separate deterministic configured-release boundaries and one
immutable Windows operations review bundle. That v3 bundle intentionally
remains blocked and lists ten external acceptance gates. It does not currently
define a machine-verifiable way to bind the evidence that closes those gates
back to the exact reviewed plan.

Without a separate acceptance boundary, operators can collect configured
release validation, IPC custody, launcher, Task Scheduler/ACL, off-host
delivery, Windows failure-drill, minimum-lot risk, and manual-demo evidence,
but cannot produce one deterministic dossier showing which exact gate was
accepted by whom and for which exact three-service topology. This feature adds
that missing verification boundary. It remains report-only and cannot install
a task, import a provider, read a credential, initialize MT5, issue stage
authorization, change execution policy, or submit an order.

The operations acceptance authority is an offline RSA public-key trust
boundary. It authenticates evidence references supplied by the responsible
owners. It does not replace the independent acceptance-authority receipts,
two-human approval, manual-demo custody checkpoint, promotion evidence,
environment arm, or runtime stage authorization required by the existing
execution path.

## Functional Requirements

- FR-1: The system MUST verify the complete immutable Windows
  three-service operations review bundle before assessing external acceptance.
- FR-2: The system MUST expose one canonical owner-role assignment for
  every blocker in `EXTERNAL_READINESS_BLOCKERS`, with neither missing nor
  additional gate codes.
- FR-3: An acceptance trust policy MUST bind the exact operations-plan
  SHA-256, review-bundle SHA-256, RSA authority identity and public key, fixed
  gate-owner assignments, signature algorithm, and maximum observation
  lifetime.
- FR-4: The verifier MUST require the trust policy SHA-256 to equal a
  separately supplied expected value; it MUST NOT trust a policy hash obtained
  only from the observations being verified.
- FR-5: Each gate observation MUST bind the exact policy, operations plan,
  review bundle, configured decision/execution/status-monitor release
  identities, gate code, canonical owner role, source-evidence SHA-256,
  independent validation-receipt SHA-256, outcome, validity interval, and
  operations-acceptance authority identity.
- FR-6: Each gate observation MUST be authenticated with
  RSASSA-PKCS1-v1_5-SHA256 using an RSA public key of 3072 to 8192 bits and
  exponent 65537 from the pinned trust policy.
- FR-7: The observations collection MUST contain at most one observation
  per required gate and MUST reject unknown gates, duplicate gates, derived-ID
  mismatch, binding drift, signature tamper, and authority drift.
- FR-8: A missing, signed-failed, not-yet-valid, or expired observation
  MUST leave its gate pending and MUST NOT make external acceptance complete.
- FR-9: External acceptance MUST be complete only when every exact required
  gate has one current, correctly bound, signed `PASSED` observation.
- FR-10: A complete assessment MUST report
  `EXTERNAL_ACCEPTANCE_COMPLETE_ACTIVATION_REVIEW_REQUIRED`; an incomplete
  assessment MUST report `BLOCKED_EXTERNAL_ACCEPTANCE`.
- FR-11: Every assessment MUST retain
  `activation_review_required=true`, `activation_authorized=false`,
  `ready_for_demo_auto_soak=false`, `execution_enabled=false`,
  `live_allowed=false`, `safe_to_demo_auto_order=false`,
  `promotion_eligible=false`, `order_capability=DISABLED`, and
  `max_lot=0.01`.
- FR-12: The project MUST provide a report-only CLI that accepts an
  operations review bundle, trust policy, observations collection, externally
  pinned expected policy hash, trusted UTC check time, and optional create-only
  output path.
- FR-13: The CLI and verifier MUST NOT accept a private key, password,
  account login, credential reference, volume, permit, arm flag, execution
  mode, terminal path, task-install switch, or broker-mutation option.
- FR-14: Input readers MUST reject symlinks/reparse points, non-regular,
  empty, oversized, unstable, duplicate-key, non-finite, malformed, or
  schema-drifted JSON before assessment.
- FR-15: The acceptance implementation MUST be packaged only with the
  operator release and MUST be absent from decision, execution,
  status-monitor, and read-only-shadow service releases.
- FR-16: The implementation MUST NOT issue an observation or policy,
  produce an RSA signature, access a private key, install or start a scheduled
  task, import a configured provider, initialize MT5, call `order_check`, call
  `order_send`, unlock DEMO_AUTO, or grant activation authority.

## Non-Functional Requirements

- NFR-1: Identical verified inputs and check time MUST produce identical
  assessment content and SHA-256.
- NFR-2: Policy and observation JSON files MUST be no larger than
  1,048,576 bytes each, and the review bundle MUST be no larger than
  4,194,304 bytes.
- NFR-3: Every timestamp MUST be timezone-aware UTC and serialize in
  canonical microsecond `Z` form.
- NFR-4: Observation lifetime MUST be positive, no longer than the policy
  maximum, and the policy maximum MUST be between 60 and 86,400 seconds.
- NFR-5: All hashes MUST be lowercase, non-zero, 64-character SHA-256
  values.
- NFR-6: The verifier MUST complete without network, broker, credential,
  scheduler, subprocess, environment, or provider I/O.
- NFR-7: Optional output MUST use exclusive creation and MUST never
  overwrite an existing file.
- NFR-8: Existing normal and `PYTHONOPTIMIZE=2` repository test suites MUST
  continue to pass.

## Acceptance Criteria

### AC-1: Complete signed dossier remains deny-only (FR-1, FR-2, FR-3, FR-5, FR-6, FR-9, FR-10, FR-11)

Given an exact verified v3 review bundle, a separately pinned RSA trust policy,
and one fresh correctly signed `PASSED` observation for every required gate
When the verifier assesses the dossier at trusted UTC
Then the result is
`EXTERNAL_ACCEPTANCE_COMPLETE_ACTIVATION_REVIEW_REQUIRED`
And all required gates are accepted
And no gate is pending
And activation, execution, demo-auto-soak readiness, promotion, and live flags
remain false.

### AC-2: Missing evidence remains visibly blocked (FR-8, FR-10, FR-11)

Given a valid policy and only a subset of required signed observations
When the verifier assesses the dossier
Then the result is `BLOCKED_EXTERNAL_ACCEPTANCE`
And every missing gate appears in the sorted pending-gate list
And the assessment cannot grant activation or order capability.

### AC-3: Signed failed or stale evidence remains pending (FR-8, NFR-3, NFR-4)

Given one correctly signed observation whose outcome is `FAILED`, whose
not-before time is in the future, or whose expiry has passed
When the verifier assesses the dossier
Then that gate remains pending with a deterministic reason
And external acceptance is incomplete.

### AC-4: Policy pin is external to observations (FR-3, FR-4)

Given a structurally valid trust policy and observations bound to it
When the supplied expected policy SHA-256 differs from the policy content hash
Then verification fails with `ACCEPTANCE_POLICY_PIN_MISMATCH`
And no assessment or output is produced.

### AC-5: Binding or signature tamper fails closed (FR-1, FR-5, FR-6, FR-7)

Given an otherwise valid observation
When its gate, owner, evidence hash, release identity, time, authority, policy
binding, or RSA signature is changed
Then verification fails with a deterministic integrity reason
And the observation is not counted as pending or accepted evidence.

### AC-6: Gate inventory and ownership are exact (FR-2, FR-7)

Given a policy or observations collection with an unknown gate, duplicate
gate, missing owner assignment, additional owner assignment, or owner-role
drift
When it is decoded
Then the input is rejected before RSA verification
And no assessment is created.

### AC-7: Strict immutable file handling (FR-14, NFR-2, NFR-7)

Given input that is a symlink/reparse point, directory, empty file, oversized
file, unstable file, duplicate-key JSON, non-finite JSON, malformed JSON, or
wrong schema
When the CLI reads it
Then the CLI exits with a rejection
And no output file is created or overwritten.

### AC-8: CLI is report-only (FR-12, FR-13, FR-16, NFR-6)

Given the CLI source and help contract
When security tests inspect its arguments, imports, and call graph
Then it exposes only review-bundle, policy, observations, expected-policy-hash,
checked-at-UTC, and create-only output inputs
And it has no private-key, credential, terminal, task mutation, provider
import, broker, permit, arm, or execution surface.

### AC-9: Packaging isolates acceptance tooling (FR-15, FR-16)

Given all Windows release allowlists
When release-boundary tests inspect them
Then the module and CLI appear in the operator allowlist
And they are absent from decision, execution, status-monitor, and shadow
service allowlists.

### AC-10: Optimized and full regression remain safe (FR-11, FR-16, NFR-8)

Given focused tests, full repository tests, and optimized-mode tests
When they execute
Then every test passes
And no broker mutation, task installation, credential access, policy unlock,
or order call occurs.

## Edge Cases

- EC-1: Policy RSA modulus is even, non-canonical, smaller than 3072 bits,
  larger than 8192 bits, or paired with an exponent other than 65537 → reject
  policy.
- EC-2: Policy public-key fingerprint does not match modulus and exponent
  → reject policy.
- EC-3: Review bundle content hash is recomputed after nested plan,
  scheduler, failure-manifest, effects, or safety tamper → existing v3
  reconstruction verifier rejects it.
- EC-4: Observation ID does not match its immutable unsigned payload →
  reject observation.
- EC-5: Observation policy/plan/bundle hash or any configured release
  identity differs → reject observation.
- EC-6: Source-evidence hash equals validation-receipt hash or either is the
  zero hash → reject observation to preserve independent review references.
- EC-7: Observation has a valid signature from the policy key but the wrong
  owner role for its gate → reject before counting it.
- EC-8: Observation is valid at assessment start but expires before RSA
  verification completes → re-check trusted UTC and leave it pending.
- EC-9: Trusted clock regresses between pre- and post-verification checks →
  fail closed.
- EC-10: Observations collection is empty → return blocked with every gate
  pending; do not treat absence as malformed evidence.
- EC-11: Optional output already exists or is a symlink → reject without
  overwriting it.
- EC-12: JSON contains a private-key, password, token, secret, login, or
  credential material field → reject before assessment.

## API Contracts

No HTTP API is introduced. In particular, this feature MUST NOT expose an
activation or execution endpoint.

```python
def load_three_service_acceptance_policy(
    path: str | Path,
) -> ThreeServiceAcceptanceTrustPolicy: ...

def load_three_service_acceptance_observations(
    path: str | Path,
) -> tuple[ThreeServiceAcceptanceObservation, ...]: ...

def load_three_service_review_bundle(
    path: str | Path,
) -> Mapping[str, object]: ...

def assess_three_service_external_acceptance(
    *,
    review_bundle: Mapping[str, object],
    trust_policy: ThreeServiceAcceptanceTrustPolicy,
    observations: Sequence[ThreeServiceAcceptanceObservation],
    expected_policy_sha256: str,
    clock_provider: Callable[[], datetime],
) -> ThreeServiceExternalAcceptanceAssessment: ...
```

Command contract:

```text
python -B verify_windows_three_service_external_acceptance.py \
  --review-bundle <v3-review.json> \
  --trust-policy <public-policy.json> \
  --observations <signed-observations.json> \
  --expected-policy-sha256 <externally-pinned-sha256> \
  --checked-at-utc <canonical-UTC-Z> \
  [--output <new-file>]
```

Exit code `0` means the dossier was structurally and cryptographically
assessed; the status field still determines complete versus blocked. Exit code
`2` means verification failed and no report is trustworthy.

## Data Models

### `ThreeServiceAcceptanceTrustPolicy`

| Field | Type | Constraints |
|---|---|---|
| `policy_id` | string | Canonical non-empty identifier |
| `plan_sha256` | SHA-256 | Exact v3 operations plan |
| `review_bundle_sha256` | SHA-256 | Exact reconstructed v3 bundle |
| `authority_id` | string | Exact offline operations-acceptance authority |
| `authority_key_id` | string | Public key identifier |
| `rsa_modulus_hex` | string | Canonical lowercase 3072–8192-bit odd modulus |
| `rsa_exponent` | int | Exactly 65537 |
| `public_key_fingerprint_sha256` | SHA-256 | Derived from modulus and exponent |
| `gate_owner_roles` | mapping | Exactly the canonical required gate-owner mapping |
| `maximum_observation_ttl_seconds` | int | 60–86,400 |
| `signature_algorithm` | enum | `RSASSA-PKCS1-v1_5-SHA256` |
| `schema_version` | enum | `windows-three-service-acceptance-rsa-policy-v1` |
| `content_sha256` | derived | Canonical immutable contract hash |

### `ThreeServiceAcceptanceObservation`

| Field | Type | Constraints |
|---|---|---|
| `observation_id` | string | Derived from immutable unsigned payload |
| `trust_policy_sha256` | SHA-256 | Exact pinned policy |
| `plan_sha256` | SHA-256 | Exact reviewed plan |
| `review_bundle_sha256` | SHA-256 | Exact reviewed bundle |
| `decision_release_identity_sha256` | SHA-256 | Exact configured decision release |
| `execution_release_identity_sha256` | SHA-256 | Exact configured execution release |
| `status_monitor_release_identity_sha256` | SHA-256 | Exact configured monitor release |
| `gate_code` | enum | One canonical external readiness blocker |
| `owner_role` | enum | Exact role assigned to the gate |
| `source_evidence_sha256` | SHA-256 | Immutable underlying evidence |
| `validation_receipt_sha256` | SHA-256 | Independent validation receipt |
| `outcome` | enum | `PASSED` or `FAILED` |
| `observed_at_utc` | UTC datetime | At or before not-before |
| `not_before_utc` | UTC datetime | Start of validity |
| `expires_at_utc` | UTC datetime | Positive policy-bounded lifetime |
| `authority_id` | string | Exact policy authority |
| `authority_key_id` | string | Exact policy public key ID |
| `public_key_fingerprint_sha256` | SHA-256 | Exact policy key fingerprint |
| `signature_rsa_pkcs1v15_sha256_hex` | hex string | Exact modulus-sized signature |
| safety fields | fixed | All execution/activation fields false or disabled |
| `schema_version` | enum | `windows-three-service-acceptance-observation-v1` |

### `ThreeServiceExternalAcceptanceAssessment`

| Field | Type | Constraints |
|---|---|---|
| `plan_sha256` | SHA-256 | Exact reconstructed plan |
| `review_bundle_sha256` | SHA-256 | Exact verified bundle |
| `trust_policy_sha256` | SHA-256 | Exact externally pinned policy |
| `checked_at_utc` | UTC datetime | Trusted assessment time |
| `accepted_gates` | tuple[string] | Sorted current signed passes |
| `pending_gates` | tuple[string] | Sorted missing/failed/not-current gates |
| `pending_reasons` | mapping | One deterministic reason per pending gate |
| `observation_sha256s` | mapping | Gate to exact authenticated observation hash |
| `external_acceptance_complete` | bool | True only with every exact gate accepted |
| `status` | enum | Complete-review-required or blocked |
| safety fields | fixed | No activation, execution, promotion, or order authority |
| `content_sha256` | derived | Canonical assessment hash |

## Out of Scope

- OS-1: Issuing or signing a trust policy or gate observation.
- OS-2: Storing or reading RSA private keys, passwords, tokens, account
  logins, broker credentials, or Windows Credential Manager secrets.
- OS-3: Installing, registering, editing, starting, or stopping Task
  Scheduler definitions or Windows services.
- OS-4: Importing or accepting a configured provider implementation.
- OS-5: Initializing MT5 or checking, sending, modifying, cancelling, or
  closing an order or position.
- OS-6: Replacing detailed configured-release, launcher, Task Scheduler,
  IPC, off-host, failure-drill, risk-feasibility, manual-demo, legal, or
  security verification with caller-supplied booleans.
- OS-7: Issuing or consuming runtime stage authorization, promotion
  evidence, permit, environment arm, or kill-switch reset.
- OS-8: Changing `SAFE_TO_DEMO_AUTO_ORDER`, `LIVE_ALLOWED`, approved symbol
  scope, risk limits, maximum lot, or runtime mode.
- OS-9: Declaring demo-auto soak started; a complete dossier only permits a
  separate human activation-release review.
- OS-10: Satisfying elapsed broker sessions, eight-week forward evidence,
  thirty-day soak, closed-fill counts, or per-lane statistical promotion gates.
