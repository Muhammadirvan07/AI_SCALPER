# Spec: Windows Three-Service Provider Conformance v3

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-28
**Status:** Approved
**Reviewers:** AI_SCALPER project owner under the standing instruction to
continue the live-grade roadmap while preserving every execution and live lock
**Related specs:**
`specs/windows_three_service_provider_conformance_v2.md`,
`specs/windows_execution_source_bound_candidate_v1.md`,
`specs/windows_execution_provider_pack_v1.md`, and
`specs/windows_base_suite_configured_release_binding_v1.md`

## Context

Provider-conformance v2 validates three configured factory templates and 65
fresh provider evidence records, but its Execution identity is supplied by a
standalone template. It does not prove that the template belongs to the exact
configured candidate whose provider source and bootstrap binding were derived
from one independently pinned production-config source archive.

Windows Execution source-bound candidate v1 now closes that lower boundary. It
verifies one exact source archive and one exact 15-file configured candidate
against nine external pins, the atomic base suite, and the canonical Execution
base release. Its sealed verification result exposes no authority and leaves
all order and live locks disabled.

Version 3 makes that sealed result mandatory for new provider-conformance
packets. It embeds a closed projection of the verified source/candidate
lineage, requires the Execution factory template to be the exact canonical
member of that candidate, and cross-checks configured identity, source hash,
bootstrap binding, suite, Execution role, commit, and tree before accepting
the 65-provider evidence input. Version 3 uses the source-bound candidate's
exact `DEMO` runtime mode. Versions 1 and 2 remain byte-compatible diagnostic
contracts; neither is silently promoted to v3.

## Functional Requirements

- FR-1: The system MUST accept input schema
  `windows-three-service-provider-conformance-input-v3` with exactly
  `schema_version`, `review_id`, `operations_plan_sha256`,
  `operations_review_bundle_sha256`, `execution_source_binding`, and
  `services`.
- FR-2: A v3 input or review MUST require an exact sealed
  `WindowsExecutionSourceBoundCandidateVerification` produced by the
  authoritative nine-pin verifier. A caller-supplied mapping alone MUST NOT
  satisfy this requirement.
- FR-3: `execution_source_binding` MUST be derived from the sealed result and
  MUST contain exactly the outer archive, binding, source, bootstrap, stage,
  champion, candidate, configured release, factory template, suite,
  Execution-role, commit, and tree identities defined by this spec.
- FR-4: The v3 Execution factory template MUST use runtime mode `DEMO`; its
  exact canonical byte hash MUST equal
  `execution_factory_template_sha256` from the source-bound result.
- FR-5: The Execution factory template's
  `expected_release_identity_sha256`, `production_config_sha256`, and
  `bootstrap_binding_sha256` MUST equal the corresponding source-bound
  identities.
- FR-6: The v3 source binding MUST retain
  `production_config_sha256 == source_archive_sha256`; the sealed verifier
  MUST already have proved the candidate's suite identity, Execution base
  archive/release identity, full Git commit/tree, and all seven source pins.
- FR-7: The v3 assembler MUST derive the source-binding object from the sealed
  verifier result. It MUST NOT accept a caller-authored source-binding mapping
  or any override for a derived field.
- FR-8: The v3 file assembler MUST independently verify the exact source-bound
  ZIP against all nine external pins, exact atomic-suite root, and exact
  Execution base release before writing a conformance input.
- FR-9: The system MUST retain the exact service inventory
  `DECISION`, `EXECUTION`, and `STATUS_MONITOR`, three distinct configured
  identities, authoritative profile-specific template validation, all 65
  one-to-one fresh `PASS` evidence records, and all six exact-true probe
  claims.
- FR-10: The v3 review MUST use schema
  `windows-three-service-provider-conformance-review-v3`, retain the exact
  source binding, and derive `configured_release_set_sha256` and
  `provider_evidence_set_sha256` from normalized inventories.
- FR-11: Public prepare and verify APIs MUST accept v1, v2, and v3 without
  cross-version field reuse. V1/v2 MUST reject a supplied source-bound
  verification object; v3 MUST reject when it is absent or mismatched.
- FR-12: Existing valid v1 and v2 inputs/reviews MUST retain byte-identical
  canonical bytes and SHA-256 values.
- FR-13: The input CLI MUST preserve explicit legacy v1 behavior, preserve v2
  as the no-source-bound compatibility default, and select v3 only when the
  complete source-bound archive/suite/release/nine-pin argument set is
  supplied. Partial or mixed version arguments MUST reject.
- FR-14: The review CLI MUST require the same complete source-bound
  verification argument set for v3 input and MUST reject those arguments for
  v1/v2 input.
- FR-15: The source-bound verification result MAY expose additional immutable
  lineage fields already present in its v1 manifest/member inventory, but the
  v1 archive schema and archive bytes MUST remain unchanged.
- FR-16: V3 output MUST retain
  `provider_accepted=false`, `activation_allowed=false`,
  `execution_enabled=false`, `task_install_allowed=false`,
  `credential_access_performed=false`, `provider_imported=false`,
  `provider_materialized=false`, `broker_mutation_performed=false`,
  `live_allowed=false`, `safe_to_demo_auto_order=false`,
  `promotion_eligible=false`, `order_capability=DISABLED`, and `max_lot=0.01`.
- FR-17: No v3 path MAY import/materialize a configured provider, access a
  credential/private key, initialize MT5, install/start a task or process,
  access the network, mutate a broker, issue a signature/permit, or grant
  activation.
- FR-18: V3 implementation and CLI import closure MUST remain confined to the
  configured-release operator tooling and absent from all four service
  release allowlists.

## Non-Functional Requirements

- NFR-1 Security: Unknown, cross-version, caller-forged binding, wrong scalar
  type, duplicate-key, non-finite, zero-hash, malformed, stale, future,
  oversized, symlink/reparse, and unstable inputs MUST fail closed without
  output.
- NFR-2 Determinism: Identical semantic inputs, exact artifacts, external pins,
  and trusted time MUST produce byte-identical canonical v3 input/review bytes
  and hashes.
- NFR-3 Compatibility: V1/v2 public APIs, schemas, canonical fixtures, and CLI
  behavior MUST remain unchanged unless v3 arguments are explicitly supplied.
- NFR-4 Reliability: Source-bound verification MUST complete before provider
  evidence normalization or output publication; existing output and replaced
  paths MUST never be overwritten or deleted.
- NFR-5 Performance: Complete v3 assembly, review preparation, and review
  verification MUST each complete in less than three seconds on the normal
  development host, excluding one-time fixture construction.
- NFR-6 Resource bounds: Existing 4,194,304-byte JSON limits, exact
  three-service inventory, exact 65-provider count, and the source-bound ZIP
  limits MUST remain enforced.
- NFR-7 Regression: Focused tests MUST pass under normal and optimized Python;
  full regression, dependency lock, deterministic release, and ship-gate
  checks MUST remain green.

## Acceptance Criteria

### AC-1: Sealed source binding is mandatory (FR-1, FR-2, FR-3, FR-7)

Given a syntactically valid v3 mapping without a sealed source-bound result
When preparation or verification runs
Then it rejects with `EXECUTION_SOURCE_BOUND_VERIFICATION_REQUIRED`
And no review or output is accepted.

### AC-2: Exact Execution closure is reconstructed (FR-4, FR-5, FR-6, FR-9, FR-15)

Given one nine-pin verified source-bound candidate and matching three-service
templates/evidence
When v3 input and review are assembled
Then the Execution configured identity, canonical template bytes, production
source, bootstrap, suite, Execution role, commit, and tree all match
And all 65 provider evidence records are reconstructed.

### AC-3: Cross-candidate substitution fails closed (FR-2 through FR-6)

Given a v3 input whose binding, Execution template, configured identity,
source, bootstrap, suite, role, commit, or tree is replaced and whose outer
content hash is recomputed
When the public verifier runs with the original sealed result
Then it rejects before acceptance.

### AC-4: File assembly performs all nine-pin verification (FR-8, NFR-1)

Given exact source-bound ZIP, suite, Execution release, and nine external pins
When the v3 file assembler runs
Then it invokes the authoritative verifier before output
And any wrong pin, archive drift, symlink, or candidate mismatch produces no
output.

### AC-5: V3 review remains deterministic and deny-only (FR-9, FR-10, FR-16)

Given identical valid v3 inputs and trusted time
When reviews are prepared and independently reconstructed
Then canonical bytes and hashes are identical
And every provider, activation, execution, order, promotion, and live flag
remains denied.

### AC-6: V1 and v2 compatibility remains exact (FR-11, FR-12, NFR-3)

Given existing canonical v1 and v2 fixtures
When v3 support is present but no v3 arguments are supplied
Then their canonical bytes and SHA-256 values remain unchanged
And supplying a source-bound result to either version rejects.

### AC-7: CLI version selection is explicit (FR-13, FR-14)

Given the input and review CLIs
When the complete v3 argument set is supplied
Then they verify the bound artifact and print the exact v3 schema
And partial, mixed legacy/v3, or v3-input-without-verification arguments reject
without output.

### AC-8: File custody remains create-exclusive (FR-8, NFR-4)

Given an existing output, dangling symlink, reparse point, unstable input, or
publication failure
When a v3 file API runs
Then it preserves all pre-existing bytes and removes only its own unchanged
partial output.

### AC-9: No new authority is reachable (FR-16, FR-17, FR-18)

Given static and dynamic sentinels for provider import, credential, key,
network, subprocess, scheduler, service, SQLite, MT5, permit, and broker paths
When v3 assembly/preparation/verification runs
Then every sentinel remains untouched and service release inventories exclude
all v3 tooling.

### AC-10: Performance and release gates remain safe (NFR-2, NFR-5, NFR-7)

Given the complete implementation
When focused, optimized, full, dependency, deterministic-release, and
ship-gate checks run
Then all local automated gates pass and deployment remains blocked on the
documented Windows/provider/manual evidence.

## Edge Cases and Error Scenarios

- EC-1: V3 input carries a v1 admission field or caller-supplied configured
  release-set hash -> reject exact schema.
- EC-2: V1/v2 input carries `execution_source_binding` -> reject exact schema.
- EC-3: A forged object mimics the verification result's attributes -> reject
  because it lacks the verifier seal/type.
- EC-4: Bound archive is valid but its Execution configured identity differs
  from the v3 template -> reject.
- EC-5: Template is semantically equal but its canonical file bytes/hash do
  not equal the bound candidate member -> reject.
- EC-6: Template runtime mode is `DEMO_AUTO` or any value other than exact
  `DEMO` in v3 -> reject.
- EC-7: Template source or bootstrap hash differs from the bound result ->
  reject.
- EC-8: One external source-bound pin is zero, malformed, or belongs to
  another archive/suite/commit/tree -> reject before output.
- EC-9: Source binding uses boolean/integer aliasing or unknown/missing fields
  -> reject exact scalar type/schema.
- EC-10: Review binding is changed and `content_sha256` recomputed -> reject
  sealed reconstruction mismatch.
- EC-11: Source-bound result is supplied with v1/v2 input -> reject version
  confusion rather than ignore it.
- EC-12: Only part of the CLI v3 argument group is supplied -> reject arguments
  rather than fall back to v2.
- EC-13: V3 and legacy admission arguments are combined -> reject.
- EC-14: Evidence is stale/future/failed or a provider inventory drifts ->
  retain existing fail-closed behavior.
- EC-15: Existing output or indirection is present -> reject without overwrite.

## API Contracts

No HTTP, broker, scheduler, credential, signing, or activation API is added.
The documentation-only validator marker `GET /not-applicable` MUST NOT be
implemented or exposed.

```typescript
interface ExecutionSourceBindingV3 {
  bound_archive_sha256: LowerHex64;
  binding_identity_sha256: LowerHex64;
  source_archive_sha256: LowerHex64;
  source_identity_sha256: LowerHex64;
  bootstrap_binding_sha256: LowerHex64;
  stage_binding_sha256: LowerHex64;
  champion_archive_sha256: LowerHex64;
  champion_package_identity_sha256: LowerHex64;
  champion_model_artifact_sha256: LowerHex64;
  champion_training_snapshot_sha256: LowerHex64;
  champion_config_sha256: LowerHex64;
  champion_runtime_binding_sha256: LowerHex64;
  candidate_id: string;
  candidate_content_sha256: LowerHex64;
  production_config_sha256: LowerHex64;
  provider_pack_identity_sha256: LowerHex64;
  provider_configuration_sha256: LowerHex64;
  configured_release_identity_sha256: LowerHex64;
  configured_archive_sha256: LowerHex64;
  execution_factory_template_sha256: LowerHex64;
  task_definition_sha256: LowerHex64;
  suite_identity_sha256: LowerHex64;
  execution_base_archive_sha256: LowerHex64;
  execution_base_release_identity_sha256: LowerHex64;
  git_commit: LowerHex40;
  git_tree: LowerHex40;
}

interface ThreeServiceProviderConformanceInputV3 {
  schema_version: "windows-three-service-provider-conformance-input-v3";
  review_id: CanonicalId;
  operations_plan_sha256: LowerHex64;
  operations_review_bundle_sha256: LowerHex64;
  execution_source_binding: ExecutionSourceBindingV3;
  services: ServiceProviderConformanceInput[];
}

interface ThreeServiceProviderConformanceReviewV3 {
  schema_version: "windows-three-service-provider-conformance-review-v3";
  execution_source_binding: ExecutionSourceBindingV3;
  configured_release_set_sha256: LowerHex64;
  provider_evidence_set_sha256: LowerHex64;
  provider_count: 65;
  provider_accepted: false;
  activation_allowed: false;
  execution_enabled: false;
  order_capability: "DISABLED";
  live_allowed: false;
  content_sha256: LowerHex64;
}
```

```python
def assemble_windows_three_service_provider_conformance_input_v3(
    *,
    review_id: str,
    operations_plan_sha256: str,
    operations_review_bundle_sha256: str,
    factory_templates: Mapping[str, Mapping[str, object]],
    evidence_manifest: Mapping[str, object],
    execution_source_bound_verification:
        WindowsExecutionSourceBoundCandidateVerification,
    clock_provider: Callable[[], datetime],
) -> WindowsProviderConformanceInputAssembly:
    ...


def prepare_windows_three_service_provider_conformance_review(
    payload: Mapping[str, object],
    *,
    clock_provider: Callable[[], datetime],
    execution_source_bound_verification:
        WindowsExecutionSourceBoundCandidateVerification | None = None,
) -> WindowsThreeServiceProviderConformanceReview:
    ...
```

## Data Models

| Entity | Field | Type | Constraint |
|---|---|---|---|
| V3 input | `schema_version` | enum | Exact input-v3 value |
| V3 input/review | `execution_source_binding` | closed object | Derived only from sealed verifier result |
| Source binding | hash fields | lowercase SHA-256 | Non-zero and exact type |
| Source binding | Git fields | lowercase SHA-1 | Full 40-character commit/tree |
| V3 Execution template | runtime mode | enum | Exact `DEMO` |
| V3 Execution template | canonical file hash | SHA-256 | Equal to bound candidate member |
| V3 review | configured/evidence set hashes | SHA-256 | Derived from normalized inventories |
| V1/V2 | existing fields | unchanged | Byte-compatible legacy/compatibility behavior |

## Out of Scope

- OS-1: Provider owner acceptance, external signature, runtime attestation,
  provider materialization, or configured-service activation.
- OS-2: Credential/private-key access, task/service installation or launch,
  SQLite/MT5/network/broker effects, or order submission.
- OS-3: Converting historical v1/v2 packets to v3 or treating them as new
  source-bound evidence.
- OS-4: Issuing signed observations, pre-manual admission, manual-demo permit,
  demo-auto activation, promotion, or live approval.
- OS-5: Proving provider behavior on the external Windows host; v3 binds exact
  artifacts to evidence claims but external runtime review remains mandatory.
- OS-6: Changing strategy logic, risk limits, symbol scope, lot sizing,
  execution state machines, or the Phillip/XM/FINEX lane policies.
