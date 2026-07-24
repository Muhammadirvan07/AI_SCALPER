# Spec: Windows Configured Overlay Candidate Preparation v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-24
**Status:** Approved
**Reviewers:** AI_SCALPER project owner (standing authorization to continue the
roadmap while preserving every execution lock)
**Related specs:** `specs/windows_configured_service_release_v1.md`,
`specs/windows_pre_manual_configured_release_admission_v1.md`

## Context

The configured-service release builder already rejects an invalid base ZIP,
unsafe provider source, secret-bearing configuration, noncanonical factory
manifest, or descriptor drift. The operator must nevertheless construct the
factory manifest and overlay descriptor manually before that builder can run.
That manual step requires copying the base release profile and identity,
hashing the correct release-local factory template and Task Scheduler
definition, hashing every overlay file, and recomputing the canonical factory
contract.

Manual assembly is an avoidable substitution and transcription risk. A
descriptor can accidentally bind the wrong base release, wrong factory
template, wrong task definition, stale provider bytes, or an incorrectly
computed factory contract. The configured-release builder will reject many of
those errors, but it cannot safely infer what the operator intended, and the
current workflow offers no deterministic preparation boundary.

This feature prepares one *candidate* factory manifest and descriptor from
exact local bytes. It verifies the deterministic base release, derives the
correct profile-specific template hash from that archive, stable-reads the
external Task Scheduler definition, inventories a secret-free overlay, and
runs the existing static configured-release validations before writing
anything. It does not claim external provider acceptance and does not import,
materialize, execute, install, or authorize any provider or service.

## Functional Requirements

- FR-1: The preparer MUST accept exactly one deterministic base decision,
  execution, or status-monitor release ZIP and MUST verify its manifest,
  release identity, source inventory, safety locks, and canonical ZIP bytes.
- FR-2: The preparer MUST derive the reviewed factory-template SHA-256 from the
  exact profile-specific factory-template member inside the verified base ZIP;
  callers MUST NOT supply or override that hash.
- FR-3: The preparer MUST stable-read one non-empty, bounded, regular,
  non-symlink/non-reparse Task Scheduler definition and bind its exact SHA-256.
- FR-4: The candidate overlay MUST initially contain exactly
  `reviewed_windows_factory.py`,
  `config/windows_service_config.json`, and one or more Python files below
  `configured_providers/`, including `configured_providers/__init__.py`.
  `config/windows_factory_manifest.json` MUST be absent before preparation.
- FR-5: The preparer MUST accept a non-zero externally derived
  `bootstrap_binding_sha256`, an RFC-compatible overlay ID, and runtime mode
  `DEMO` or `DEMO_AUTO`.
- FR-6: The preparer MUST construct an exact canonical
  `windows-service-factory-manifest-v1` for module
  `reviewed_windows_factory`, attribute `build`, the verified base profile,
  exact factory/config hashes, and canonical factory-contract hash.
- FR-7: The preparer MUST construct an exact canonical
  `windows-configured-service-overlay-v1` descriptor containing the base
  identity/profile, runtime mode, candidate ID, exact provider inventory,
  generated factory-manifest inventory, derived factory-template hash, task
  definition hash, and unchanged safety locks.
- FR-8: Before materializing either output, the preparer MUST run the same
  path, canonical JSON, secret, Python AST, import-closure, forbidden import,
  dynamic-code, process-launch, native-loader, order-primitive, factory
  contract, base-collision, size, and hash validations used by configured
  release assembly.
- FR-9: The generated factory manifest MUST be written create-exclusive to
  `config/windows_factory_manifest.json` inside the overlay, and the descriptor
  MUST be written create-exclusive outside the overlay root.
- FR-10: If either destination already exists, is unavailable, is inside an
  unsafe path relation, or any validation fails, preparation MUST fail closed.
  If the second create-exclusive write fails after the first succeeds, the
  first file created by that invocation MUST be removed.
- FR-11: A successful result MUST identify the base profile and identity,
  overlay ID, runtime mode, factory manifest and descriptor paths and SHA-256,
  factory contract, task definition, reviewed template, and file count.
- FR-12: Every result MUST retain `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `max_lot=0.01`,
  `production_execution_ready=false`, `configured_release_built=false`,
  `provider_materialization_performed=false`,
  `credential_access_performed=false`,
  `task_installation_performed=false`, and
  `broker_mutation_performed=false`.
- FR-13: The CLI MUST expose no password, login, token, private key,
  credential value, permit, environment arm, stage authorization, order, or
  activation argument.
- FR-14: The preparer and CLI MUST be packaged only in the configured-release
  operator-tooling release and MUST remain absent from decision, execution,
  status-monitor, shadow, and production service inventories.
- FR-15: Existing configured-release build and verification behavior MUST
  remain unchanged.

## Non-Functional Requirements

- NFR-1: Identical base, task-definition, overlay, overlay ID, bootstrap hash,
  and runtime-mode inputs MUST produce byte-identical manifest and descriptor
  bytes and identical SHA-256 values.
- NFR-2: Each input MUST use the existing 4 MiB per-file and 64 MiB aggregate
  configured-overlay limits; the base ZIP MUST use the existing archive limits.
- NFR-3: Preparation MUST perform no network, subprocess, environment-variable,
  credential-store, Task Scheduler, service-control, MT5, broker, or provider
  import I/O.
- NFR-4: A valid maximum-size input set MUST complete within five seconds on
  the development test host, excluding filesystem scheduling variance.
- NFR-5: Every rejection MUST use a stable uppercase reason code and MUST not
  expose file contents, secrets, account identifiers, or credential material.
- NFR-6: Focused tests MUST pass with normal Python and `PYTHONOPTIMIZE=2`; the
  full repository regression, compilation, release-boundary, dependency-lock,
  SBOM, and security checks MUST remain green.

## Acceptance Criteria

### AC-1: Valid execution candidate is prepared deterministically (FR-1 through FR-9, FR-11, FR-12, NFR-1)

Given a valid execution base ZIP, safe candidate overlay, exact Task Scheduler
definition, non-zero bootstrap binding, and new output paths
When preparation runs twice in independent directories
Then the generated factory manifests and descriptors are byte-identical
And all bound hashes, identities, paths, and safety locks are exact
And no configured release, provider, task, credential, MT5 session, or order is
materialized.

### AC-2: All three base profiles select their own template (FR-1, FR-2, FR-6, FR-7)

Given valid decision, execution, and status-monitor base ZIPs
When a candidate is prepared for each base
Then each descriptor binds the SHA-256 of the corresponding exact
profile-specific factory-template member
And no caller-selected template hash is accepted.

### AC-3: Invalid base or wrong template inventory fails closed (FR-1, FR-2, FR-10)

Given a tampered, nondeterministic, unsupported, configured, or incomplete base
archive
When preparation runs
Then it rejects before writing either output.

### AC-4: Unsafe or ambiguous overlay fails closed (FR-4, FR-8, FR-10)

Given a missing/extra/symlink/reparse/case-colliding overlay file, a pre-existing
factory manifest, an invalid path, noncanonical JSON, unsafe secret value,
embedded key/token pattern, invalid Python, missing import closure, forbidden
import, dynamic code, process launch, native loader, or order primitive
When preparation runs
Then it rejects with a stable reason and writes nothing.

### AC-5: Task and bootstrap bindings are exact (FR-3, FR-5, FR-7, FR-10)

Given an empty, oversized, symlinked, changing, or unavailable task definition
Or a malformed or zero bootstrap hash
When preparation runs
Then it rejects before output
And a valid input binds the exact task bytes and bootstrap hash.

### AC-6: Outputs are create-exclusive and transactionally cleaned up (FR-9, FR-10)

Given either destination already exists or the descriptor destination becomes
unavailable after validation
When preparation attempts output
Then no existing byte is overwritten
And a factory manifest created by the failed invocation is removed.

### AC-7: Descriptor is accepted by the existing configured builder (FR-6 through FR-8, FR-15)

Given a successfully prepared candidate
When the existing configured-service builder consumes the same base, overlay,
and descriptor
Then it builds and independently verifies a deterministic configured release
without any change to existing builder semantics.

### AC-8: CLI remains offline and deny-only (FR-11, FR-12, FR-13, FR-14, NFR-3, NFR-5)

Given the CLI help, imports, arguments, and successful output
When they are statically and dynamically inspected
Then they expose only preparation inputs and deny-only status
And perform no network, credential, task, provider, process, MT5, or broker
operation.

### AC-9: Packaging isolation remains exact (FR-14, FR-15)

Given all release allowlists
When release-boundary tests inspect them
Then the preparer occurs only in configured-release operator tooling
And all service release inventories remain unchanged.

### AC-10: Regression and resource bounds hold (NFR-2, NFR-4, NFR-6)

Given the complete implementation
When focused, optimized, full regression, compilation, dependency, SBOM, and
release-security checks run
Then every check passes within its documented bound.

## Edge Cases

- EC-1: Descriptor output is placed inside the overlay root → reject before
  writing because it would become an unreviewed overlay member.
- EC-2: Factory-manifest destination already exists as a regular file,
  directory, symlink, or reparse point → reject without modification.
- EC-3: Provider package contains only `__init__.py` → permitted if all static
  contracts otherwise validate; concrete runtime acceptance remains external.
- EC-4: A nested provider package has a relative import outside the overlay/base
  import closure → reject.
- EC-5: Factory source imports a local module that is not present in the exact
  base-plus-overlay inventory → reject.
- EC-6: Task-definition bytes change without changing length during the read →
  stable-file identity/mtime checks reject.
- EC-7: Task definition contains a recognized private-key or token pattern →
  reject without persisting its content.
- EC-8: Base profile is valid but its profile-specific template member is
  absent or its bytes differ from the base manifest inventory → base/template
  verification rejects.
- EC-9: Factory/config/provider source collides with a base member by exact or
  case-folded path → reject.
- EC-10: Descriptor write fails after manifest creation → remove only the new
  manifest and preserve all pre-existing files.
- EC-11: Runtime mode is `LIVE`, lowercase, empty, or another value → reject.
- EC-12: Overlay ID contains whitespace, a path separator, or exceeds the
  existing limit → reject.

## API Contracts

No HTTP, network, broker, credential, Task Scheduler, service-control, or
signing API is introduced.

```typescript
interface ConfiguredOverlayCandidatePreparationRequest {
  baseRelease: LocalFilePath;
  overlayRoot: LocalDirectoryPath;
  taskDefinition: LocalFilePath;
  overlayId: string;
  bootstrapBindingSha256: Sha256;
  runtimeMode: "DEMO" | "DEMO_AUTO";
  descriptorOutput: NewLocalFilePath;
}

interface ConfiguredOverlayCandidatePreparationResult {
  status: "CANDIDATE_PREPARED_EXTERNAL_REVIEW_REQUIRED";
  baseReleaseProfile:
    | "WINDOWS_DECISION_SERVICE_V1"
    | "WINDOWS_GATED_EXECUTION_SERVICE_V1"
    | "WINDOWS_EXTERNAL_STATUS_MONITOR_V1";
  baseReleaseIdentitySha256: Sha256;
  factoryManifestSha256: Sha256;
  descriptorSha256: Sha256;
  configuredReleaseBuilt: false;
  providerMaterializationPerformed: false;
  credentialAccessPerformed: false;
  taskInstallationPerformed: false;
  brokerMutationPerformed: false;
}
```

```python
def prepare_configured_overlay_candidate(
    *,
    base_archive: str | Path,
    overlay_root: str | Path,
    task_definition_path: str | Path,
    overlay_id: str,
    bootstrap_binding_sha256: str,
    runtime_mode: str,
    descriptor_output_path: str | Path,
) -> ConfiguredOverlayCandidatePreparation: ...
```

Command contract:

```text
python -I -S -B prepare_windows_configured_overlay_candidate.py \
  --base-release <base.zip> \
  --overlay-root <candidate-overlay-directory> \
  --task-definition <reviewed-task-definition.xml> \
  --overlay-id <candidate-id> \
  --bootstrap-binding-sha256 <non-zero-sha256> \
  --runtime-mode DEMO_AUTO \
  --descriptor-output <new-descriptor.json>
```

Exit code `0` means candidate bytes were statically prepared and remain subject
to independent external review. Exit code `2` means preparation failed and no
descriptor is trustworthy.

## Data Models

### `ConfiguredOverlayCandidatePreparation`

| Field | Type | Constraints |
|---|---|---|
| base_release_profile | enum | Exact verified decision/execution/monitor profile |
| base_release_identity_sha256 | SHA-256 | Exact deterministic base identity |
| overlay_id | string | Existing canonical ID grammar |
| runtime_mode | enum | `DEMO` or `DEMO_AUTO` |
| factory_manifest_path | path | Fixed overlay-relative manifest path |
| factory_manifest_sha256 | SHA-256 | Exact generated canonical bytes |
| descriptor_path | path | Create-exclusive path outside overlay |
| descriptor_sha256 | SHA-256 | Exact generated canonical bytes |
| factory_contract_sha256 | SHA-256 | Canonical generic factory context |
| bootstrap_binding_sha256 | SHA-256 | Externally derived non-zero binding |
| reviewed_factory_template_sha256 | SHA-256 | Derived from exact base member |
| task_definition_sha256 | SHA-256 | Derived from exact stable task bytes |
| provider_source_relative_paths | tuple[path] | Sorted exact provider inventory |
| file_count | integer | Exact final overlay member count |
| safety fields | fixed | No authority or materialization |

### Candidate Overlay

| Path | Type | Constraint |
|---|---|---|
| `reviewed_windows_factory.py` | Python | Top-level factory source |
| `configured_providers/__init__.py` | Python | Required package root |
| `configured_providers/**/*.py` | Python | Optional exact provider modules |
| `config/windows_service_config.json` | canonical JSON | Non-secret service config |
| `config/windows_factory_manifest.json` | canonical JSON | Generated create-exclusive output |

## Out of Scope

- OS-1: Authoring, selecting, approving, importing, executing, or attesting a
  concrete provider implementation.
- OS-2: Reading, writing, validating, or provisioning passwords, logins,
  tokens, private keys, Credential Manager values, permits, or arm flags.
- OS-3: Installing, editing, starting, or stopping Task Scheduler tasks,
  Windows services, processes, MT5 terminals, orders, or positions.
- OS-4: Signing launcher or external-acceptance evidence.
- OS-5: Claiming that a candidate overlay has passed independent provider,
  security, operations, or human acceptance.
- OS-6: Enabling manual demo, demo-auto, live, promotion, order submission,
  `safe_to_demo_auto_order`, or `production_execution_ready`.
- OS-7: Satisfying manual-demo lifecycles, 30-day/50-fill/20-XAU soak, broker
  sessions, forward/OOS counts, statistical gates, live canary, or scaling.
