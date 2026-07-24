# Spec: Windows Three-Service Provider Evidence Input Assembly v1

**Author:** Codex with AI_SCALPER project owner  
**Date:** 2026-07-24  
**Status:** Approved  
**Reviewers:** AI_SCALPER project owner under the standing instruction to
continue the live-grade roadmap while preserving every execution lock  
**Related specs:**
`specs/windows_three_service_provider_conformance_review_v1.md`,
`specs/windows_configured_overlay_candidate_preparation_v1.md`

## Context

The provider-conformance reviewer binds three exact configured service factory
templates and 65 provider records: seven decision providers, 46 execution
providers, and 12 external status-monitor providers. Its current input repeats
contract, implementation, configuration, binding, custody, provider-kind, and
credential-reference fields for every provider. Those values already exist in
the factory templates and therefore should not be transcribed by an operator.

Manual repetition creates an avoidable substitution surface. A valid evidence
artifact can be attached to the wrong provider, a binding hash can be copied
from another configured release, or a stale template can be combined with a
new release identity. The current reviewer rejects mismatches, but operators
still have to construct a large document by hand and diagnose the rejection.

This feature assembles the existing conformance-review input from three exact
factory-template JSON files plus a compact external evidence manifest. It
derives every binding field from the validated templates, joins evidence by
service role and provider role, and proves that the resulting input is
accepted by the existing deny-only reviewer before writing it. It does not
create evidence, run provider tests, import providers, accept providers, sign
the review, or grant activation or trading authority.

## Functional Requirements

- FR-1: The assembler MUST accept exactly one decision, one `DEMO_AUTO`
  execution, and one external status-monitor factory template.
- FR-2: Every factory template MUST be validated by its authoritative
  profile-specific validator, MUST bind a distinct non-zero configured release
  identity, and MUST normalize to the same canonical form used by the existing
  provider-conformance reviewer.
- FR-3: The evidence manifest MUST use the closed schema
  `windows-three-service-provider-evidence-manifest-v1`, contain exactly the
  three service roles, and contain exactly one compact evidence record for
  every provider role required by each factory template.
- FR-4: A compact evidence record MUST contain only provider role,
  conformance-suite hash, evidence-artifact hash, reviewer ID, canonical UTC
  observation time, `PASS` result, and the six required exact-true probe
  results.
- FR-5: The assembler MUST derive provider contract, implementation,
  configuration, binding, custody, provider-kind, and credential-reference
  fields exclusively from the validated factory template. Callers MUST NOT be
  able to override those fields.
- FR-6: The assembler MUST join evidence by exact service role and provider
  role, MUST reject missing, extra, duplicate, or case-colliding records, and
  MUST sort services and providers canonically.
- FR-7: The assembler MUST accept non-zero operations-plan,
  operations-review-bundle, and configured-release-admission SHA-256 values
  plus a canonical review ID.
- FR-8: Before writing, the assembler MUST pass the complete derived input
  through `prepare_windows_three_service_provider_conformance_review` using
  the same trusted-clock observation. Failed, partial, stale, future, malformed,
  or binding-inconsistent evidence MUST therefore fail closed.
- FR-9: A successful assembly MUST write the exact existing schema
  `windows-three-service-provider-conformance-input-v1` as canonical UTF-8 JSON
  with one trailing newline and MUST be directly consumable by
  `prepare_windows_three_service_provider_conformance_review.py`.
- FR-10: File inputs MUST be stable-read regular files with no
  symlink/reparse indirection, duplicate JSON keys, non-finite values, or
  unsupported fields. The output MUST be create-exclusive and MUST never
  overwrite an existing path.
- FR-11: The CLI MUST accept explicit paths for the three templates,
  evidence manifest, and new output plus the review ID and three authoritative
  hashes. It MUST expose no credential value, account login, private key,
  permit, stage evidence, environment arm, activation, service-control, or
  order argument.
- FR-12: A successful result MUST report the output SHA-256, exact three
  configured identities, provider count `65`, and status
  `PROVIDER_CONFORMANCE_INPUT_ASSEMBLED_REVIEW_PACKET_NOT_CREATED`.
- FR-13: Every result MUST retain `provider_accepted=false`,
  `activation_allowed=false`, `execution_enabled=false`,
  `task_install_allowed=false`, `credential_access_performed=false`,
  `provider_imported=false`, `provider_materialized=false`,
  `broker_mutation_performed=false`, `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `promotion_eligible=false`,
  `order_capability=DISABLED`, and `max_lot=0.01`.
- FR-14: The assembler and CLI MUST be packaged only in
  `WINDOWS_CONFIGURED_RELEASE_OPERATOR_TOOLING_V1`; all service-release
  inventories MUST remain unchanged.
- FR-15: Existing provider-conformance review preparation and verification
  behavior MUST remain backward compatible.

## Non-Functional Requirements

- NFR-1: Identical semantic inputs with different object/service/provider
  ordering MUST produce byte-identical output and identical SHA-256.
- NFR-2: Each JSON input MUST be bounded to 4 MiB and aggregate input to
  16 MiB. The output MUST remain within the existing 4 MiB conformance-review
  input limit.
- NFR-3: Assembly MUST perform no network, subprocess, environment-variable,
  credential-store, Task Scheduler, service-control, dynamic provider import,
  MT5, broker, or signing I/O.
- NFR-4: A valid 65-provider assembly MUST complete within two seconds on
  the development test host, excluding filesystem scheduling variance.
- NFR-5: Rejections MUST use stable uppercase reason codes and MUST not
  expose source contents, credentials, account identifiers, or key material.
- NFR-6: Focused tests MUST pass normally and under
  `PYTHONOPTIMIZE=2`; the full regression, compilation, dependency-lock, SBOM,
  release-boundary, and security checks MUST remain green.

## Acceptance Criteria

### AC-1: Exact 65-provider input is derived (FR-1, FR-2, FR-3, FR-4, FR-5, FR-6, FR-7, FR-8, FR-9, FR-12, FR-13)

Given three valid factory templates and complete fresh passing compact evidence
When assembly runs
Then it derives all repeated binding fields from the templates
And writes an exact 65-provider conformance input
And the existing conformance reviewer accepts that input
And every activation and execution effect remains false.

### AC-2: Ordering cannot change output (FR-6, FR-9, NFR-1)

Given semantically identical template and evidence documents with reversed
service and provider ordering
When each document is assembled independently
Then the output bytes and SHA-256 are identical.

### AC-3: Caller cannot override binding truth (FR-4, FR-5, FR-10)

Given a compact evidence record containing a repeated binding field or any
unknown field
When assembly runs
Then it rejects the evidence schema before writing output.

### AC-4: Missing, extra, duplicate, or wrong-role evidence fails (FR-3, FR-6)

Given a service or provider evidence set that is missing, extra, duplicated,
case-colliding, or assigned to the wrong service
When assembly runs
Then it rejects with a stable set or schema reason and writes nothing.

### AC-5: Invalid factory topology fails closed (FR-1, FR-2, FR-5)

Given an invalid profile, non-`DEMO_AUTO` execution template, reused release
identity, template/identity mismatch, or provider-binding drift
When assembly runs
Then the authoritative factory validator or topology check rejects before
output.

### AC-6: Invalid evidence remains invalid (FR-8)

Given failed, partial, stale, future, malformed-time, zero-hash, or
secret-pattern reviewer evidence
When assembly runs
Then the existing conformance-review rules reject it before output.

### AC-7: File boundary is strict and create-exclusive (FR-9, FR-10, NFR-2)

Given duplicate-key, non-finite, oversized, symlink/reparse, unstable, missing,
or unreadable input
Or an existing, indirect, or unsafe output path
When the file API runs
Then it rejects without overwriting or leaving a partial output.

### AC-8: CLI is isolated and deny-only (FR-11, FR-12, FR-13, FR-14, NFR-3, NFR-5)

Given the CLI source, help, arguments, imports, and successful output
When they are inspected statically and dynamically
Then no provider, credential, task, process, network, MT5, broker, signing, or
activation capability is reachable
And all safety fields remain denied.

### AC-9: Operator-tooling packaging remains exact (FR-14, FR-15)

Given all release allowlists and a clean Git checkout
When release builders run
Then only configured-release operator tooling gains the assembler module and
CLI
And the tooling archive remains deterministic and self-verifying
And service inventories remain unchanged.

### AC-10: Regression and resource bounds hold (NFR-2, NFR-4, NFR-6)

Given the complete implementation
When focused, optimized, full, compilation, dependency, SBOM, and security
checks run
Then every check passes within the documented bounds.

## Edge Cases

- EC-1: The same configured identity appears under two service roles →
  reject before evidence normalization.
- EC-2: Provider roles differ only by case → reject as a collision.
- EC-3: An evidence record repeats a template-derived hash even with the
  correct value → reject because callers cannot supply binding truth.
- EC-4: Evidence manifest services are reversed → normalize without
  changing output.
- EC-5: Template provider order is reversed → authoritative validator and
  canonical normalization determine output.
- EC-6: Observation is exactly 24 hours old → permitted by the existing
  inclusive freshness boundary; one microsecond older → reject.
- EC-7: Trusted clock moves backwards during assembly → reject and write
  nothing.
- EC-8: Output equals one of the input paths or is inside an indirect
  parent → reject before writing.
- EC-9: Output write fails after exclusive creation → remove only the new
  partial output and preserve all inputs.
- EC-10: Evidence uses one combined suite/artifact hash for multiple
  providers → permitted; independent review decides whether the referenced
  artifact is sufficiently granular.
- EC-11: A template JSON uses harmless whitespace/key ordering → accept
  strict JSON and normalize canonically.
- EC-12: A template or evidence file changes without changing length during
  read → stable-file metadata check rejects.

## API Contracts

No HTTP, network, broker, credential, Task Scheduler, service-control, provider
import, or signing API is introduced.

```typescript
interface CompactProviderEvidence {
  provider_role: string;
  conformance_suite_sha256: Sha256;
  evidence_artifact_sha256: Sha256;
  reviewer_id: string;
  observed_at_utc: CanonicalUtcTimestamp;
  result: "PASS";
  interface_contract_probe_passed: true;
  fail_closed_probe_passed: true;
  secret_non_export_probe_passed: true;
  restart_recovery_probe_passed: true;
  custody_boundary_probe_passed: true;
  deterministic_replay_probe_passed: true;
}

interface ProviderEvidenceManifest {
  schema_version: "windows-three-service-provider-evidence-manifest-v1";
  evidence_set_id: string;
  services: Array<{
    service_role: "DECISION" | "EXECUTION" | "STATUS_MONITOR";
    provider_evidence: CompactProviderEvidence[];
  }>;
}

interface ProviderConformanceInputAssemblyResult {
  status:
    "PROVIDER_CONFORMANCE_INPUT_ASSEMBLED_REVIEW_PACKET_NOT_CREATED";
  output_sha256: Sha256;
  configured_release_identities: Record<string, Sha256>;
  provider_count: 65;
  provider_accepted: false;
  activation_allowed: false;
  execution_enabled: false;
  order_capability: "DISABLED";
}
```

```python
def assemble_windows_three_service_provider_conformance_input(
    *,
    review_id: str,
    operations_plan_sha256: str,
    operations_review_bundle_sha256: str,
    configured_release_admission_sha256: str,
    factory_templates: Mapping[str, Mapping[str, object]],
    evidence_manifest: Mapping[str, object],
    clock_provider: Callable[[], datetime],
) -> WindowsProviderConformanceInputAssembly:
    ...


def assemble_windows_three_service_provider_conformance_input_file(
    *,
    decision_factory_template_path: str | Path,
    execution_factory_template_path: str | Path,
    status_monitor_factory_template_path: str | Path,
    evidence_manifest_path: str | Path,
    output_path: str | Path,
    review_id: str,
    operations_plan_sha256: str,
    operations_review_bundle_sha256: str,
    configured_release_admission_sha256: str,
    clock_provider: Callable[[], datetime],
) -> WindowsProviderConformanceInputAssembly:
    ...
```

Errors are raised as:

```python
WindowsProviderConformanceInputError(reason_code: UPPERCASE_TEXT)
```

## Data Models

| Entity | Field | Type | Constraints |
|---|---|---|---|
| Evidence manifest | `schema_version` | string | Exact v1 value |
| Evidence manifest | `evidence_set_id` | string | Canonical non-secret identifier |
| Evidence manifest | `services` | array | Exactly three unique roles |
| Compact evidence | `provider_role` | string | Exact template role, unique per service |
| Compact evidence | evidence hashes | SHA-256 | Lowercase, non-zero |
| Compact evidence | `reviewer_id` | string | Canonical, non-secret identifier |
| Compact evidence | `observed_at_utc` | timestamp | Canonical aware UTC, fresh |
| Compact evidence | `result` | enum | Exact `PASS` |
| Compact evidence | six probe fields | boolean | Exact `true` |
| Assembly | `conformance_input` | mapping | Existing closed input schema |
| Assembly | `output_sha256` | SHA-256 | Hash of canonical output bytes |
| Assembly | `provider_count` | integer | Exact `65` |
| Assembly | safety/effect fields | fixed values | All denied; max lot `0.01` |

## Out of Scope

- OS-1: Implementing, importing, executing, or accepting any provider.
- OS-2: Generating conformance suites, probe outcomes, evidence hashes, or
  reviewer observations.
- OS-3: Reading Credential Manager, private keys, account login, environment
  arm, permits, or stage evidence.
- OS-4: Signing provider acceptance or changing
  `provider_accepted=false`.
- OS-5: Installing Task Scheduler definitions, starting services,
  initializing MT5, or submitting broker orders.
- OS-6: Enabling `safe_to_demo_auto_order`, `live_allowed`, promotion, or
  production execution readiness.
- OS-7: Replacing independent review of the referenced evidence artifacts.
- OS-8: Changing the existing conformance-review input or packet schema.
