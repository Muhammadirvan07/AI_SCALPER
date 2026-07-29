# Spec: Windows Three-Service Provider Conformance v4

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved
**Reviewers:** AI_SCALPER project owner under the standing instruction to
continue the live-grade roadmap while preserving every execution and live lock
until external evidence is independently verified
**Related specs:**
`specs/windows_three_service_provider_conformance_v3.md`,
`specs/windows_live_canary_execution_configured_candidate_v1.md`,
`specs/windows_live_canary_execution_source_bound_candidate_v1.md`, and
`specs/windows_execution_provider_pack_v1.md`

## Context

Provider-conformance v3 binds the Decision, Execution, and Status Monitor
evidence packet to the sealed Windows Execution source closure, but that
contract deliberately validates the 46-provider `DEMO` Execution template.
The subsequent LIVE configured candidate adds three LIVE-only provider ports,
twelve purpose-bound credential references, and an exact `LIVE` factory
template. Therefore v3 cannot establish conformance evidence for the artifact
that would eventually be considered by the LIVE canary gates.

Windows LIVE canary Execution source-bound candidate v1 now packages that
15-file LIVE configured candidate with its already verified DEMO source
closure. Its authoritative ten-pin verifier reconstructs both nested artifacts
from packaged bytes and returns a sealed, deny-only result covering the outer
archive, source ancestry, suite, configured release, template, provider set,
commit, and tree.

Version 4 consumes that exact sealed result. It binds a three-service packet to
the LIVE Execution template, derives all 49 LIVE provider targets without
provider import or credential access, retains the existing seven Decision and
twelve Status Monitor providers, and therefore requires exactly 68 fresh
provider evidence records. Versions 1 through 3 remain compatible and cannot
be silently interpreted as v4. This packet is evidence preparation only; it
does not accept a provider, activate a service, alter central policy, or grant
order authority.

## Functional Requirements

- FR-1: The system MUST accept input schema
  `windows-three-service-provider-conformance-input-v4` with exactly
  `schema_version`, `review_id`, `operations_plan_sha256`,
  `operations_review_bundle_sha256`, `live_execution_source_binding`, and
  `services`.
- FR-2: A v4 input or review MUST require an exact sealed
  `WindowsLiveCanaryExecutionSourceBoundCandidateVerification` produced by the
  authoritative ten-pin verifier. A caller-authored mapping or lookalike object
  MUST NOT satisfy this requirement.
- FR-3: `live_execution_source_binding` MUST be derived from that sealed result
  and MUST contain exactly the LIVE-bound archive/binding, nested source-bound
  archive/binding, source archive, bootstrap, candidate, provider-pack,
  provider-configuration, LIVE contract-set, configured release/archive,
  factory template, task, suite, Execution-role, commit/tree, provider-count,
  credential-count, and runtime-mode fields defined by this spec.
- FR-4: The v4 Execution factory template MUST use exact runtime mode `LIVE`
  and MUST be validated by
  `validate_windows_live_canary_execution_factory_template`; the generic
  DEMO/DEMO_AUTO template validator MUST NOT authorize v4.
- FR-5: The canonical v4 Execution factory-template byte hash MUST equal
  `execution_factory_template_sha256` in the sealed result. Its configured
  release identity, production-config hash, bootstrap hash,
  provider-configuration hash, LIVE provider contract-set hash, task hash,
  provider count, credential-reference count, and runtime mode MUST match the
  sealed result.
- FR-6: V4 MUST derive each LIVE Execution provider evidence target from the
  exact seven-field template binding. `provider_binding_sha256` MUST equal the
  canonical SHA-256 of `configuration_sha256`, `contract_sha256`,
  `credential_reference_id`, `implementation_sha256`, `port_name`,
  `provider_id`, and `provider_kind`; callers MUST NOT supply or override that
  derived value.
- FR-7: V4 MUST retain exactly the three service roles `DECISION`, `EXECUTION`,
  and `STATUS_MONITOR`, three distinct configured release identities, seven
  Decision providers, 49 LIVE Execution providers, twelve Status Monitor
  providers, and therefore exactly 68 provider evidence records.
- FR-8: Every v4 provider MUST have one and only one fresh `PASS` evidence
  record matching all derived binding fields and all six exact-true probe
  claims already required by the shared evidence manifest v1 contract.
- FR-9: The v4 file assembler MUST verify the exact LIVE source-bound ZIP
  against the complete ten-pin group, exact atomic-suite root, and exact
  Execution base release before it reads provider evidence or publishes
  output.
- FR-10: The v4 review MUST use schema
  `windows-three-service-provider-conformance-review-v4`, retain the exact LIVE
  source binding, and derive configured-release and provider-evidence set
  hashes from normalized inventories.
- FR-11: Public prepare and verify APIs MUST accept v1 through v4 without
  cross-version field reuse. V1/v2 MUST reject any source verification; v3
  MUST accept only the sealed DEMO source-bound result; v4 MUST accept only the
  sealed LIVE source-bound result.
- FR-12: Existing valid v1, v2, and v3 inputs/reviews MUST retain their
  canonical bytes, hashes, provider counts, runtime modes, and error behavior.
- FR-13: The input CLI MUST select v4 only when a distinct
  `--live-execution-source-bound-candidate` argument and every associated
  suite/release/ten-pin argument are supplied. It MUST preserve v1/v2/v3
  selection and reject partial or mixed DEMO/LIVE source groups.
- FR-14: The review CLI MUST inspect the input schema and require the exact
  matching complete v3 or v4 verification group. It MUST reject absent,
  partial, mixed, or wrong-version verification arguments before output.
- FR-15: V4 output MUST retain `provider_accepted=false`,
  `activation_allowed=false`, `execution_enabled=false`,
  `task_install_allowed=false`, `credential_access_performed=false`,
  `provider_imported=false`, `provider_materialized=false`,
  `broker_mutation_performed=false`, `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `promotion_eligible=false`,
  `order_capability=DISABLED`, and `max_lot=0.01`.
- FR-16: No v4 path MAY import or materialize a configured provider, resolve a
  credential/private key, initialize MT5, open the network, install/start a
  task or process, access the live registry, issue a signature/permit, mutate
  central policy or a broker, or submit an order.
- FR-17: V4 implementation and CLI import closure MUST remain confined to the
  configured-release operator tooling and absent from all Decision, Execution,
  Status Monitor, and read-only-shadow service releases.

## Non-Functional Requirements

- NFR-1 Security: Unknown fields, wrong scalar types, duplicate keys,
  non-finite values, zero/malformed hashes, caller-forged bindings,
  cross-version objects, stale/future evidence, oversize input, path
  indirection, and unstable reads MUST fail closed without output.
- NFR-2 Determinism: Identical semantic inputs, exact artifacts, pins, and
  trusted time MUST produce byte-identical canonical v4 input/review bytes and
  hashes.
- NFR-3 Compatibility: V1-v3 public APIs, schema constants, canonical fixtures,
  CLI selection, runtime modes, provider counts, and errors MUST remain
  unchanged unless the complete v4 group is explicitly supplied.
- NFR-4 Reliability: Ten-pin LIVE artifact verification MUST complete before
  provider evidence normalization and output publication; an existing output
  or replaced path MUST never be overwritten or deleted.
- NFR-5 Performance: V4 input assembly, review preparation, and independent
  review verification MUST each complete in less than three seconds on the
  normal development host, excluding one-time artifact fixture construction.
- NFR-6 Resource bounds: Existing 4,194,304-byte JSON limits and archive limits
  MUST remain enforced; v4 MUST enforce exactly three services, 68 providers,
  49 LIVE Execution bindings, and twelve credential references.
- NFR-7 Regression: Focused tests MUST pass under normal and optimized Python;
  full regression, dependency-lock, deterministic-release, and ship-gate
  checks MUST remain green or retain only explicitly documented external/manual
  blockers.

## Acceptance Criteria

### AC-1: Sealed LIVE source binding is mandatory (FR-1, FR-2, FR-3)

Given a syntactically valid v4 input without the sealed LIVE verification
When preparation or verification runs
Then it rejects with `LIVE_EXECUTION_SOURCE_BOUND_VERIFICATION_REQUIRED`
And no packet or output is accepted.

### AC-2: Exact LIVE Execution closure is reconstructed (FR-3 through FR-8)

Given one ten-pin verified LIVE source-bound candidate and matching
three-service templates and evidence
When v4 input and review are assembled
Then the LIVE configured identity, exact template, source ancestry, provider
configuration, contract set, bootstrap, task, suite, commit, and tree match
And the normalized inventory contains exactly 68 providers, including 49
LIVE Execution providers and twelve credential-reference bindings.

### AC-3: LIVE provider binding is derived, not trusted (FR-6, FR-8)

Given the canonical LIVE template and compact external evidence manifest
When v4 assembly derives an Execution target
Then its binding hash includes all seven exact template fields
And any provider ID, credential reference, kind, contract, implementation, or
configuration substitution rejects even if outer hashes are recomputed.

### AC-4: Cross-version and cross-candidate substitution fails (FR-2, FR-5, FR-11)

Given v3/v4 inputs, DEMO/LIVE sealed results, or templates from different
candidates
When public prepare or verify APIs run
Then every wrong-version or cross-candidate combination rejects before
acceptance.

### AC-5: File assembly performs all ten-pin checks (FR-9, NFR-1, NFR-4)

Given exact LIVE source-bound ZIP, suite, Execution release, and ten pins
When the v4 file assembler runs
Then it invokes the authoritative verifier before output
And any wrong pin, archive drift, path indirection, or candidate mismatch
produces no output.

### AC-6: V4 review is deterministic and deny-only (FR-10, FR-15, NFR-2)

Given identical valid v4 input and trusted time
When review preparation and independent reconstruction run
Then canonical bytes and hashes are identical
And every provider, activation, execution, order, promotion, and live flag
remains denied.

### AC-7: V1-v3 compatibility remains exact (FR-11, FR-12, NFR-3)

Given existing canonical v1, v2, and v3 fixtures
When v4 support is present without v4 arguments
Then their bytes, hashes, provider counts, runtime modes, and errors are
unchanged.

### AC-8: CLI selection is complete and explicit (FR-13, FR-14)

Given the input and review CLIs
When one complete v3 or v4 verification group is supplied
Then the exact matching schema is selected and the artifact is verified
And partial, mixed, absent, or wrong-version groups reject without output.

### AC-9: Custody and effects remain safe (FR-16, FR-17, NFR-4)

Given create-exclusive path checks and static/dynamic effect sentinels
When v4 assembly, preparation, verification, or CLI bootstrap runs
Then pre-existing bytes remain unchanged, forbidden effects remain untouched,
and all service release inventories exclude the tooling.

### AC-10: Performance and release gates remain safe (NFR-5, NFR-6, NFR-7)

Given the complete implementation
When focused, optimized, full, dependency, deterministic-release, and
ship-gate checks run
Then local automated gates pass within their bounds
And deployment remains blocked until documented target-Windows, provider,
approval, central-unlock, canary, acknowledgement, and reconciliation evidence
exists.

## Edge Cases and Error Scenarios

- EC-1: V4 carries `execution_source_binding`, a legacy admission field, or an
  unknown field -> reject exact schema.
- EC-2: V1-v3 carries `live_execution_source_binding` -> reject exact schema.
- EC-3: A lookalike object copies every sealed-result attribute -> reject due
  to exact type/seal enforcement.
- EC-4: A sealed DEMO result is supplied to v4 or a sealed LIVE result to v3 ->
  reject version mismatch.
- EC-5: LIVE template runtime mode is not exact `LIVE`, or generic DEMO
  validation would otherwise accept it -> reject.
- EC-6: Template canonical hash, configured identity, source, bootstrap,
  provider configuration, contract set, task, counts, or runtime mode differs
  from the sealed result -> reject.
- EC-7: One LIVE provider binding changes while compact evidence is preserved ->
  reject derived binding mismatch.
- EC-8: One credential reference is missing, duplicated, repurposed, or
  attached to another provider -> reject template or provider evidence.
- EC-9: Provider count is 65, 67, 69, or any value other than exact 68 ->
  reject v4.
- EC-10: One of ten external pins is absent, malformed, zero, or belongs to
  another archive/suite/commit/tree -> reject before output.
- EC-11: Review binding is changed and `content_sha256` recomputed -> reject
  sealed reconstruction mismatch.
- EC-12: V4 verification arguments are partial or mixed with the v3 bound
  archive argument -> reject arguments rather than fall back.
- EC-13: V4 input reaches the review CLI without a complete LIVE verification
  group -> reject before output.
- EC-14: Evidence is stale, future, failed, duplicated, or missing one exact
  probe -> retain existing fail-closed behavior.
- EC-15: Input or output is a symlink/reparse point, changes during stable read,
  exceeds limits, or already exists -> reject without overwrite.

## API Contracts

No HTTP, broker, scheduler, credential, signing, policy-mutation, activation,
or order API is added. The documentation-only validator marker
`GET /not-applicable` MUST NOT be implemented or exposed.

```typescript
interface LiveExecutionSourceBindingV4 {
  live_bound_archive_sha256: LowerHex64;
  live_binding_identity_sha256: LowerHex64;
  source_bound_archive_sha256: LowerHex64;
  source_bound_binding_identity_sha256: LowerHex64;
  source_archive_sha256: LowerHex64;
  bootstrap_binding_sha256: LowerHex64;
  candidate_id: CanonicalId;
  candidate_content_sha256: LowerHex64;
  production_config_sha256: LowerHex64;
  provider_pack_identity_sha256: LowerHex64;
  provider_configuration_sha256: LowerHex64;
  live_provider_contract_set_sha256: LowerHex64;
  configured_release_identity_sha256: LowerHex64;
  configured_archive_sha256: LowerHex64;
  execution_factory_template_sha256: LowerHex64;
  task_definition_sha256: LowerHex64;
  suite_identity_sha256: LowerHex64;
  execution_base_archive_sha256: LowerHex64;
  execution_base_release_identity_sha256: LowerHex64;
  git_commit: LowerHex40;
  git_tree: LowerHex40;
  provider_count: 49;
  credential_reference_count: 12;
  runtime_mode: "LIVE";
}

interface ThreeServiceProviderConformanceInputV4 {
  schema_version: "windows-three-service-provider-conformance-input-v4";
  review_id: CanonicalId;
  operations_plan_sha256: LowerHex64;
  operations_review_bundle_sha256: LowerHex64;
  live_execution_source_binding: LiveExecutionSourceBindingV4;
  services: ServiceProviderConformanceInput[];
}

interface ThreeServiceProviderConformanceReviewV4 {
  schema_version: "windows-three-service-provider-conformance-review-v4";
  live_execution_source_binding: LiveExecutionSourceBindingV4;
  configured_release_set_sha256: LowerHex64;
  provider_evidence_set_sha256: LowerHex64;
  provider_count: 68;
  provider_accepted: false;
  activation_allowed: false;
  execution_enabled: false;
  credential_access_performed: false;
  order_capability: "DISABLED";
  live_allowed: false;
  content_sha256: LowerHex64;
}
```

```python
def assemble_windows_three_service_provider_conformance_input_v4(
    *,
    review_id: str,
    operations_plan_sha256: str,
    operations_review_bundle_sha256: str,
    factory_templates: Mapping[str, Mapping[str, object]],
    evidence_manifest: Mapping[str, object],
    live_execution_source_bound_verification:
        WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
    clock_provider: Callable[[], datetime],
) -> WindowsProviderConformanceInputAssembly:
    ...


def prepare_windows_three_service_provider_conformance_review(
    payload: Mapping[str, object],
    *,
    clock_provider: Callable[[], datetime],
    execution_source_bound_verification:
        WindowsExecutionSourceBoundCandidateVerification | None = None,
    live_execution_source_bound_verification:
        WindowsLiveCanaryExecutionSourceBoundCandidateVerification | None = None,
) -> WindowsThreeServiceProviderConformanceReview:
    ...
```

## Data Models

| Entity | Field | Type | Constraint |
|---|---|---|---|
| V4 input | `schema_version` | enum | Exact input-v4 value |
| V4 input/review | `live_execution_source_binding` | closed object | Derived only from sealed LIVE verifier result |
| LIVE binding | hash fields | lowercase SHA-256 | Non-zero and exact string type |
| LIVE binding | Git fields | lowercase SHA-1 | Full non-zero 40-character commit/tree |
| LIVE binding | `provider_count` | integer | Exact type and value 49; boolean rejected |
| LIVE binding | `credential_reference_count` | integer | Exact type and value 12; boolean rejected |
| LIVE binding | `runtime_mode` | enum | Exact `LIVE` |
| V4 Execution target | `provider_binding_sha256` | SHA-256 | Derived from exact seven-field LIVE template binding |
| V4 review | `provider_count` | integer | Exact 68 |
| V1-v3 | existing fields | unchanged | Byte-compatible version behavior |

## Out of Scope

- OS-1: Provider-owner acceptance, external signatures, runtime attestation,
  provider materialization, credential resolution, or configured-service
  activation.
- OS-2: Task/service installation or launch, private-key access, registry,
  SQLite, MT5, network, broker, central-policy, permit, or order effects.
- OS-3: Converting v1-v3 packets into v4 or treating historical DEMO evidence
  as LIVE provider evidence.
- OS-4: Issuing activation, deployment, promotion, gate, human approval,
  rollback/WORM acknowledgement, or per-order authority.
- OS-5: Proving behavior on the target Windows host; all 68 records remain
  externally produced claims requiring independent ownership and signature.
- OS-6: Changing strategies, risk limits, symbol scope, lot sizing, execution
  state machines, or broker policy.
- OS-7: Unlocking central policy or sending a demo/live broker order; those
  actions require later evidence and ceremonies outside this contract.
