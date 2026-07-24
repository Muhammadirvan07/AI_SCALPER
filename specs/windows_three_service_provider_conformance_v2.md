# Spec: Windows Three-Service Provider Conformance v2

**Author:** Codex with AI_SCALPER project owner  
**Date:** 2026-07-25  
**Status:** Approved  
**Reviewers:** AI_SCALPER project owner under the standing instruction to
continue the live-grade roadmap while preserving every execution and live lock  
**Related specs:**
`specs/windows_three_service_provider_conformance_review_v1.md`,
`specs/windows_three_service_provider_evidence_input_assembly_v1.md`,
`specs/windows_base_suite_configured_release_binding_v1.md`,
`specs/windows_pre_manual_configured_release_admission_v1.md`,
`specs/windows_three_service_external_acceptance_v1.md`

## Context

Provider-conformance v1 binds three configured release identities, the exact
operations-plan and review-bundle hashes, and 65 provider evidence records.
It also requires a caller-supplied
`configured_release_admission_sha256`. The only configured-release admission
artifact implemented by AI_SCALPER is the pre-manual admission. That artifact
cannot exist until nine externally signed pre-manual observations have been
collected, while three of those observations rely on provider-conformance
evidence. The v1 field therefore creates a circular dependency:
provider conformance requires pre-manual admission, while pre-manual admission
requires provider conformance.

The v1 verifier only validates that the supplied admission value is a non-zero
SHA-256; it cannot reconstruct an independently issued artifact for that
value. This permits an arbitrary placeholder hash and makes the intended
phase ordering impossible to prove. The packet documentation also refers to
an observation field named `details_sha256`, although the implemented
external-acceptance contract uses `source_evidence_sha256` and a distinct
`validation_receipt_sha256`.

Version 2 removes the future-admission input. It derives the configured release
set commitment from the three exact configured release identities already
validated by the service factory templates. The packet continues to bind the
operations plan and review bundle so that independent acceptance can bind the
same topology. Exact archive bytes and atomic-suite provenance remain
independently re-verified by the existing pre-manual configured-release
admission after signed observations exist. Version 1 remains readable for
legacy diagnostics but is not a valid source-evidence contract for new
pre-manual or promotion workflows.

## Functional Requirements

- FR-1: The system MUST accept provider-conformance input schema
  `windows-three-service-provider-conformance-input-v2` with exactly
  `schema_version`, `review_id`, `operations_plan_sha256`,
  `operations_review_bundle_sha256`, and `services`.
- FR-2: Version 2 input MUST NOT accept
  `configured_release_admission_sha256`, a pre-manual admission hash, a
  caller-supplied configured-release-set hash, or any unknown field.
- FR-3: The system MUST retain the existing exact service inventory:
  `DECISION`, `EXECUTION`, and `STATUS_MONITOR`, with three distinct non-zero
  configured release identities and the existing authoritative
  profile-specific factory-template validation.
- FR-4: The system MUST retain the existing one-to-one provider evidence
  validation, including all 65 provider bindings, fresh `PASS` evidence, and
  all six exact-true bounded probe claims.
- FR-5: The v2 reviewer MUST derive `configured_release_set_sha256` from the
  canonical sorted tuple of service role and configured release identity. The
  caller MUST NOT supply or override this value.
- FR-6: The v2 review MUST use schema
  `windows-three-service-provider-conformance-review-v2` and MUST omit
  `configured_release_admission_sha256`.
- FR-7: The v2 review MUST continue to include the exact operations-plan hash,
  operations-review-bundle hash, normalized factory templates, provider
  evidence inventories, per-service and aggregate set hashes, checked UTC,
  content SHA-256, readiness blockers, and all deny-only effects.
- FR-8: The existing public prepare and verify APIs MUST accept both v1 and
  v2 documents, select their exact closed field sets from `schema_version`,
  and reconstruct the same version without silent conversion.
- FR-9: The input assembler MUST expose a v2 API that does not accept an
  admission hash and MUST validate its assembled result through the existing
  authoritative provider-conformance reviewer before returning or writing it.
- FR-10: The input-assembly CLI MUST create v2 input when no legacy admission
  argument is supplied. Supplying the existing
  `--configured-release-admission-sha256` argument MUST preserve exact v1
  behavior for compatibility and MUST print that the contract is legacy.
- FR-11: The v1 APIs and schemas MUST remain byte-compatible for existing
  valid v1 inputs, but documentation MUST classify v1 as legacy diagnostic
  evidence that cannot satisfy a new pre-manual or promotion workflow.
- FR-12: New operational documentation MUST define this non-circular order:
  atomic five-role base suite; suite-bound configured releases; immutable
  operations plan/review bundle; provider-conformance v2 packet and independent
  validation receipt; signed pre-manual observations; exact pre-manual
  configured-release admission; controlled manual demo.
- FR-13: External acceptance documentation MUST identify the v2 packet
  content SHA-256 as a candidate `source_evidence_sha256`, never as a
  nonexistent `details_sha256`, and MUST keep the independent validation
  receipt as a different immutable object.
- FR-14: All v2 results MUST retain
  `provider_accepted=false`, `activation_allowed=false`,
  `execution_enabled=false`, `task_install_allowed=false`,
  `credential_access_performed=false`, `provider_imported=false`,
  `provider_materialized=false`, `broker_mutation_performed=false`,
  `live_allowed=false`, `safe_to_demo_auto_order=false`,
  `promotion_eligible=false`, `order_capability=DISABLED`, and
  `max_lot=0.01`.
- FR-15: No v2 path MAY import or materialize a configured provider, access a
  credential or private key, initialize MT5, install or launch a task or
  process, access the network, mutate a broker, issue an observation, sign
  evidence, or grant activation.

## Non-Functional Requirements

- NFR-1 Security: Unknown, cross-version, admission-like, duplicate-key,
  non-finite, zero-hash, malformed, stale, future, oversized, symlink/reparse,
  and unstable inputs MUST fail closed without output.
- NFR-2 Determinism: Semantically identical v2 inputs and trusted time MUST
  produce byte-identical canonical input and review bytes and identical hashes.
- NFR-3 Compatibility: Every existing valid v1 fixture MUST retain the same
  canonical bytes and SHA-256 after v2 support is added.
- NFR-4 Reliability: A document MUST never be interpreted using a field set
  from a different schema version, including when its outer content hash has
  been recomputed.
- NFR-5 Performance: A complete 65-provider v2 assembly, preparation, and
  verification operation MUST each complete in less than two seconds on the
  normal development test host.
- NFR-6 Resource bounds: Existing 4,194,304-byte review/input bounds and exact
  service/provider count limits MUST remain unchanged.
- NFR-7 Regression: Focused tests MUST pass under normal Python and
  `PYTHONOPTIMIZE=2`; the complete repository regression, compilation,
  deterministic release, dependency lock, SBOM, and safety scans MUST remain
  green.

## Acceptance Criteria

### AC-1: V2 removes the circular input (FR-1, FR-2, FR-5, FR-6)

Given valid three-service templates and complete provider evidence
When v2 input is assembled and reviewed
Then neither the input nor review contains
`configured_release_admission_sha256`
And the reviewer derives `configured_release_set_sha256`
And the review uses the exact v2 schema.

### AC-2: V2 remains complete and deny-only (FR-3, FR-4, FR-7, FR-14)

Given a complete valid v2 input
When it is prepared and independently verified
Then all 65 provider records and three distinct configured identities are
reconstructed
And the operations hashes and all aggregate hashes match
And every activation, execution, provider, broker, promotion, and live effect
remains denied.

### AC-3: Admission and schema smuggling fail closed (FR-1, FR-2, FR-8, NFR-1, NFR-4)

Given a v2 input or review containing an admission field, a caller-supplied
release-set hash, a v1-only field, or any unknown field
When preparation or verification runs
Then it rejects with a stable schema reason
And no output is accepted.

### AC-4: Derived release-set commitment cannot be substituted (FR-3, FR-5, FR-7)

Given a valid v2 review whose service identity or derived release-set hash is
changed and whose outer content hash is recomputed
When the public verifier reconstructs it
Then it rejects because the derived commitment no longer matches the exact
service inventory.

### AC-5: V1 compatibility remains exact (FR-8, FR-10, FR-11, NFR-3)

Given an existing valid v1 input
When the same prepare, verify, and legacy CLI paths run after v2 support
Then the canonical v1 input/review bytes and SHA-256 remain unchanged
And the legacy admission field remains present only in the v1 document.

### AC-6: CLI defaults to the non-circular contract (FR-9, FR-10)

Given valid template and compact evidence files
When the input-assembly CLI runs without the legacy admission argument
Then it writes canonical v2 input and prints its v2 schema
And when the legacy argument is explicitly supplied it writes canonical v1
input and prints a legacy diagnostic warning.

### AC-7: Strict file boundary remains enforced (FR-8, FR-9, NFR-1, NFR-6)

Given duplicate-key, non-finite, oversized, symlink/reparse, unstable,
cross-version, missing, or existing-output inputs
When either v1 or v2 file API runs
Then it rejects create-exclusively without overwriting or leaving a partial
output.

### AC-8: Operational sequence is non-circular (FR-11, FR-12, FR-13)

Given the activation runbook and provider-conformance documentation
When their ordered procedure and acceptance field names are inspected
Then configured releases and the operations review precede provider
conformance
And provider conformance precedes signed observations and pre-manual admission
And the packet targets `source_evidence_sha256` with a distinct validation
receipt.

### AC-9: No new authority is reachable (FR-14, FR-15)

Given static and dynamic sentinels for network, credential, private-key,
provider import, subprocess, scheduler, MT5, broker, signing, and activation
boundaries
When v2 assembly, preparation, and verification run
Then every sentinel remains untouched and all fixed locks remain denied.

### AC-10: Performance and regression remain safe (NFR-2, NFR-5, NFR-7)

Given the complete v2 implementation
When focused, optimized, full, compilation, deterministic-release, dependency,
SBOM, and ship-gate checks run
Then all automated checks pass within their bounds and deployment remains
blocked on the documented external evidence.

## Edge Cases and Error Scenarios

- EC-1: V2 input carries the removed admission field even with a valid hash →
  reject exact input schema.
- EC-2: V2 review carries the removed admission field and a recomputed outer
  content hash → reject exact review schema before reconstruction.
- EC-3: V1 schema is paired with v2 fields, or v2 schema is paired with v1
  fields → reject cross-version field drift.
- EC-4: The same configured release identity is reused by two services →
  reject before deriving the release-set hash.
- EC-5: One service identity changes while its template still binds the old
  identity → reject template/release identity mismatch.
- EC-6: Service or provider ordering changes without semantic drift →
  normalize and produce identical bytes.
- EC-7: V2 evidence is exactly 24 hours old → retain the existing inclusive
  freshness behavior; one microsecond older → reject.
- EC-8: Trusted clock is naive, fails, advances to invalidate evidence, or
  regresses → fail closed without output.
- EC-9: V1 legacy CLI argument is empty, zero, malformed, or supplied more
  than once → reject rather than silently switching to v2.
- EC-10: Output exists, is a symlink/reparse point, or an input changes during
  stable read → reject without overwrite.
- EC-11: Documentation or CLI help claims v2 grants provider acceptance,
  activation, demo-auto readiness, or order authority → release-boundary test
  fails.
- EC-12: A v2 packet is used as both source evidence and validation receipt →
  the existing external-acceptance contract rejects equal hashes.

## API Contracts

No HTTP, broker, scheduler, credential, provider, signing, or activation API is
introduced. The documentation-only validator marker `GET /not-applicable`
MUST NOT be implemented or exposed.

```typescript
interface ThreeServiceProviderConformanceInputV2 {
  schema_version: "windows-three-service-provider-conformance-input-v2";
  review_id: CanonicalId;
  operations_plan_sha256: Hex64;
  operations_review_bundle_sha256: Hex64;
  services: ServiceProviderConformanceInput[];
}

interface ThreeServiceProviderConformanceReviewV2 {
  schema_version: "windows-three-service-provider-conformance-review-v2";
  review_id: CanonicalId;
  operations_plan_sha256: Hex64;
  operations_review_bundle_sha256: Hex64;
  services: NormalizedServiceReview[];
  configured_release_set_sha256: Hex64;
  provider_evidence_set_sha256: Hex64;
  provider_count: 65;
  checked_at_utc: CanonicalUtcZ;
  status: "PROVIDER_CONFORMANCE_PACKET_READY_EXTERNAL_SIGNATURE_REQUIRED";
  readiness_blockers: [
    "EXTERNAL_PROVIDER_OWNER_SIGNATURE_REQUIRED",
    "EXTERNAL_PROVIDER_RUNTIME_ATTESTATION_REQUIRED"
  ];
  external_signature_required: true;
  provider_accepted: false;
  activation_allowed: false;
  execution_enabled: false;
  task_install_allowed: false;
  credential_access_performed: false;
  provider_imported: false;
  provider_materialized: false;
  broker_mutation_performed: false;
  live_allowed: false;
  safe_to_demo_auto_order: false;
  promotion_eligible: false;
  order_capability: "DISABLED";
  max_lot: 0.01;
  content_sha256: Hex64;
}
```

```python
def assemble_windows_three_service_provider_conformance_input_v2(
    *,
    review_id: str,
    operations_plan_sha256: str,
    operations_review_bundle_sha256: str,
    factory_templates: Mapping[str, Mapping[str, object]],
    evidence_manifest: Mapping[str, object],
    clock_provider: Callable[[], datetime],
) -> WindowsProviderConformanceInputAssembly:
    ...


def prepare_windows_three_service_provider_conformance_review(
    payload: Mapping[str, object],
    *,
    clock_provider: Callable[[], datetime],
) -> WindowsThreeServiceProviderConformanceReview:
    """Accept exact v1 or v2 input and preserve its version."""


def verify_windows_three_service_provider_conformance_review(
    payload: Mapping[str, object],
    *,
    clock_provider: Callable[[], datetime],
) -> WindowsThreeServiceProviderConformanceReview:
    """Reconstruct exact v1 or v2 review and preserve its version."""
```

Failures use the existing stable
`WindowsProviderConformanceError` and
`WindowsProviderConformanceInputError` reason-code contracts.

## Data Models

| Entity | Field | Type | Constraints |
|---|---|---|---|
| V2 input | `schema_version` | enum | Exact input-v2 value |
| V2 input | `review_id` | string | Canonical non-secret ID |
| V2 input | operations hashes | SHA-256 | Lowercase, non-zero |
| V2 input | `services` | array | Exact three-role inventory |
| Service | configured identity | SHA-256 | Non-zero, unique, template-bound |
| Service | factory template | mapping | Existing authoritative profile schema |
| Service | provider evidence | array | Exact one-to-one provider inventory |
| V2 review | configured set hash | SHA-256 | Derived from sorted role/identity tuples |
| V2 review | evidence-set hashes | SHA-256 | Derived from normalized evidence |
| V2 review | deny-only fields | fixed | Values from FR-14 |
| V2 review | `content_sha256` | SHA-256 | Hash over every preceding review field |
| V1 compatibility | admission hash | SHA-256 | Legacy v1 only; not accepted by v2 |

## Out of Scope

- OS-1: Removing v1 parser compatibility or rewriting historical v1 evidence.
- OS-2: Treating any v1 or v2 packet as provider acceptance, a signature,
  activation authority, demo-auto readiness, promotion evidence, or an order
  permit.
- OS-3: Verifying configured ZIP bytes inside provider-conformance review;
  exact archive and atomic-suite verification remains the responsibility of
  configured-release verification and pre-manual admission.
- OS-4: Issuing an external acceptance policy, observation, signature,
  validation receipt, stage authorization, permit, or environment arm.
- OS-5: Importing/materializing providers, resolving credentials or keys,
  installing/starting tasks, initializing MT5, or accessing a broker.
- OS-6: Changing any strategy, risk cap, symbol scope, lot size, execution
  state machine, or live-trading behavior.
- OS-7: Satisfying manual-demo, demo-auto soak, forward-evidence, OOS,
  statistical, legal, security, or live-canary gates.
