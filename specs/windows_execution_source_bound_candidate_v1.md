# Windows Execution Source-Bound Candidate v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-28
**Status:** Approved for implementation
**Reviewers:** project owner, security, ship-gate
**Related specs:** `windows_execution_production_config_source_v1.md`,
`windows_execution_provider_pack_v1.md`,
`windows_configured_service_release_v1.md`,
`windows_atomic_base_release_suite_v1.md`

## Context

The deterministic Execution production-config source now proves that one
canonical `ProductionRuntimeConfig`, one exact `StageBinding`, and one exact
rule-core champion share the same identities. The existing Execution provider
pack separately records the source archive SHA-256, while the configured
candidate separately records the bootstrap safe-binding SHA-256. Both are
validated internally, but the configured-candidate artifact does not contain
the source archive and therefore cannot independently prove that those two
values came from the same seven-pin verification report.

This gap currently defers a mismatched source/provider/candidate rejection
until reviewed factory materialization. The project needs one portable,
deterministic, independently verifiable artifact that packages the exact
source archive and every exact configured-candidate member, proves their
cross-bindings against the same atomic base suite, and fails before provider
conformance or runtime effects.

The artifact is deny-only. It does not accept a provider, read credentials or
private keys, open production SQLite, initialize MT5, access a network,
install a task, start a service, issue a permit, or mutate a broker.

## Functional Requirements

- FR-1: The system MUST build one deterministic ZIP containing exactly one
  canonical binding manifest, one exact seven-pin production-config source
  archive, and all 15 exact files of one validated configured Execution
  candidate.
- FR-2: Preparation MUST validate the atomic base suite and its Execution base
  release before reading candidate authority claims.
- FR-3: Preparation MUST validate the configured Execution candidate against
  that exact suite and Execution release.
- FR-4: Preparation MUST verify the production-config source against its outer
  archive SHA-256 and six independently supplied champion pins.
- FR-5: Preparation MUST parse the exact provider configuration copied inside
  the candidate and require its `production_config_sha256` to equal the
  verified source archive SHA-256.
- FR-6: Preparation MUST require the candidate
  `bootstrap_binding_sha256` to equal the verified source bootstrap binding.
- FR-7: Preparation MUST require candidate Git commit/tree to equal the source
  champion commit/tree and the exact base-suite commit/tree.
- FR-8: Preparation MUST require candidate suite identity and Execution base
  archive/release identities to equal the independently pinned suite and its
  canonical Execution role.
- FR-9: The manifest MUST bind every member path, byte size, SHA-256, source
  verification identities, candidate receipt identities, provider production
  source hash, suite identity, commit/tree, safety state, and effect claims.
- FR-10: The manifest MUST expose one non-self-referential
  `binding_identity_sha256` derived from its canonical manifest core.
- FR-11: The outer ZIP MUST use a closed sorted inventory, fixed timestamp,
  fixed POSIX regular-file mode, deterministic compression, no comments, no
  encryption, no data descriptors, and no trailing bytes.
- FR-12: The public verifier MUST require nine independent pins: bound outer
  archive SHA-256, source archive SHA-256, champion archive/model/snapshot/
  config SHA-256 values, full Git commit, full Git tree, and atomic-suite
  identity SHA-256.
- FR-13: Verification MUST reconstruct the candidate under one bounded private
  temporary directory and invoke the authoritative configured-candidate
  validator against the exact external suite and Execution release.
- FR-14: Verification MUST re-run source verification and all provider,
  bootstrap, suite, role, commit, tree, inventory, and manifest cross-binding
  checks from packaged bytes.
- FR-15: Output publication MUST be create-exclusive, reject path indirection,
  preserve all pre-existing bytes, and remove only the exact regular file
  created by a failing invocation.
- FR-16: The builder and verifier MUST reject duplicate/non-canonical JSON,
  malformed or duplicate/case-folded ZIP members, traversal, metadata drift,
  size/decompression drift, member replacement, output collision, and
  unstable source inputs.
- FR-17: Every successful result MUST retain `provider_accepted=false`,
  `production_execution_ready=false`, `promotion_eligible=false`,
  `order_capability=DISABLED`, `safe_to_demo_auto_order=false`, and
  `live_allowed=false`.
- FR-18: Preparation and verification MUST NOT import a configured provider,
  read credentials/private keys, open production SQLite, initialize MT5,
  access a network, install/start a task or service, issue a permit, or mutate
  a broker.
- FR-19: CLI entry points MUST require `python -I -S -B`, expose no
  secret-bearing option, and print stable reason codes on rejection.
- FR-20: The builder, verifier, and required pure/offline modules MUST exist
  only in configured-release operator tooling; no new CLI may enter Decision,
  Execution, Status Monitor, or Read-Only Shadow service releases.
- FR-21: Existing provider-pack and configured-candidate v1 inputs and schemas
  MUST remain byte-compatible; their standalone success MUST NOT be described
  as source-bound evidence.

## Non-Functional Requirements

- NFR-1 (Fail closed): Any absent, zero, malformed, unpinned, or mismatched
  identity MUST reject before output publication or provider effect.
- NFR-2 (Determinism): Two preparations with identical input bytes and pins
  MUST produce byte-identical archives in normal and optimized CPython 3.12.
- NFR-3 (Portability): Preparation and verification MUST work on Windows
  CPython 3.12 using only the configured tooling release and standard library.
- NFR-4 (Bounds): JSON members MUST be at most 4 MiB, the source archive at
  most 40 MiB, each nested configured release at most 256 MiB, total expanded
  candidate bytes at most 320 MiB, and the outer archive at most 384 MiB.
- NFR-5 (Temporary custody): Verification temporary extraction MUST use a new
  private root, exact relative paths, create-exclusive writes, and guaranteed
  cleanup on success or failure.
- NFR-6 (Reviewability): All cross-bindings MUST be explicit scalar manifest
  fields; none may exist only in generated Python source.
- NFR-7 (Regression): Focused and full normal/optimized tests, compilation,
  dependency-lock verification, release-boundary tests, and repository hygiene
  checks MUST pass.

## Acceptance Criteria

### AC-1: Deterministic exact package (FR-1, FR-9, FR-10, FR-11, NFR-2)

Given one valid source archive, configured Execution candidate, exact suite,
Execution release, and nine valid pins
When two new destination paths are prepared independently
Then the resulting archive bytes are identical
And their outer and binding identities are identical.

### AC-2: Source/provider/bootstrap closure (FR-4, FR-5, FR-6, FR-14)

Given one valid packaged candidate
When its source, provider configuration, and candidate receipt are verified
Then provider `production_config_sha256` equals the source outer hash
And candidate `bootstrap_binding_sha256` equals the source bootstrap binding.

### AC-3: Suite and Git closure (FR-2, FR-3, FR-7, FR-8, FR-12)

Given one valid packaged candidate and independently supplied suite/commit/tree
pins
When verification runs against the exact suite and Execution release
Then candidate, source champion, suite, and Execution role identities all
match the pins.

### AC-4: Mismatch rejection before publication (FR-5, FR-6, FR-7, NFR-1)

Given otherwise valid source and candidate bytes
When the provider source hash, bootstrap binding, commit, or tree differs
Then preparation rejects with a stable cross-binding reason
And no output file or runtime effect is produced.

### AC-5: Independent packaged-byte revalidation (FR-12, FR-13, FR-14, NFR-5)

Given one valid bound archive and nine external pins
When the public verifier runs from a different output location
Then it extracts only the 15 candidate files into a private temporary root
And authoritative source/candidate validators pass
And the temporary root is removed.

### AC-6: Adversarial archive rejection (FR-15, FR-16, NFR-1, NFR-4)

Given a valid bound archive or output destination
When one case adds trailing data, traversal, case-fold collision, duplicate
member, wrong timestamp/mode, non-canonical manifest, member replacement,
oversize metadata, symlink input, or existing target
Then the operation rejects without overwriting or deleting pre-existing data.

### AC-7: Release and effect boundary (FR-17, FR-18, FR-19, FR-20, FR-21)

Given all five service releases plus configured operator tooling
When allowlist, isolated CLI, and static-effect tests run
Then only configured tooling contains the new CLIs
And every success remains deny-only
And no existing v1 schema changes.

### AC-8: Complete regression (NFR-7)

Given the completed implementation
When focused and complete test/dependency/spec/hygiene gates run in normal and
optimized modes
Then every required gate passes
And project ship status remains `DO_NOT_SHIP` until external/manual evidence is
complete.

## Edge Cases and Error Scenarios

- EC-1: Source archive verifies but provider source hash differs -> reject
  before output.
- EC-2: Provider source hash matches but candidate bootstrap differs -> reject
  before output.
- EC-3: Candidate is valid against a different suite or Execution release ->
  reject.
- EC-4: Source champion commit/tree differs from candidate or suite -> reject.
- EC-5: Candidate root contains one extra file, missing file, symlink, reparse
  point, or changed byte -> authoritative candidate validation rejects.
- EC-6: Outer ZIP contains an unknown, duplicate, case-folded, traversing,
  encrypted, data-descriptor, or metadata-drifted member -> reject.
- EC-7: Outer bytes contain data after EOCD -> reject even when caller updates
  only the outer hash pin.
- EC-8: Input changes between metadata capture and read -> reject as unstable.
- EC-9: Output exists or output parent is indirect -> reject and preserve it.
- EC-10: Publication fails after exclusive creation -> remove only the exact
  unchanged file created by that invocation.
- EC-11: Temporary extraction fails part-way -> remove only the new private
  temporary root and perform no external mutation.
- EC-12: A standalone v1 provider pack/candidate passes but no bound archive
  exists -> report it as unbound and ineligible for provider conformance.

## API Contracts

This increment adds offline Python and CLI contracts only. It adds no HTTP API
(including `POST /api/windows-execution-source-bound-candidate`), credential
API, task API, or broker endpoint.

```typescript
interface WindowsExecutionSourceBoundCandidateManifestV1 {
  schema_version: "windows-execution-source-bound-candidate-v1";
  binding_identity_sha256: LowerHex64;
  members: Array<{
    path: string;
    size_bytes: number;
    sha256: LowerHex64;
  }>;
  source: {
    archive_sha256: LowerHex64;
    source_identity_sha256: LowerHex64;
    bootstrap_binding_sha256: LowerHex64;
    stage_binding_sha256: LowerHex64;
    champion_archive_sha256: LowerHex64;
    champion_package_identity_sha256: LowerHex64;
    champion_model_artifact_sha256: LowerHex64;
    champion_training_snapshot_sha256: LowerHex64;
    champion_config_sha256: LowerHex64;
    champion_git_commit: LowerHex40;
    champion_git_tree: LowerHex40;
    champion_runtime_binding_sha256: LowerHex64;
  };
  candidate: {
    candidate_id: string;
    content_sha256: LowerHex64;
    bootstrap_binding_sha256: LowerHex64;
    production_config_sha256: LowerHex64;
    provider_pack_identity_sha256: LowerHex64;
    provider_configuration_sha256: LowerHex64;
    configured_release_identity_sha256: LowerHex64;
    configured_archive_sha256: LowerHex64;
    task_definition_sha256: LowerHex64;
    base_suite_identity_sha256: LowerHex64;
    execution_base_archive_sha256: LowerHex64;
    execution_base_release_identity_sha256: LowerHex64;
    git_commit: LowerHex40;
    git_tree: LowerHex40;
    runtime_mode: "DEMO";
  };
  safety: DenyOnlySafety;
  effects: Record<string, "NOT_PERFORMED" | "PERFORMED_VERIFICATION_ONLY">;
}
```

```text
prepare_windows_execution_source_bound_candidate(
    *,
    base_suite_root,
    execution_base_release,
    production_config_source_archive,
    configured_candidate_root,
    expected_source_archive_sha256,
    expected_champion_archive_sha256,
    expected_model_artifact_sha256,
    expected_training_snapshot_sha256,
    expected_config_sha256,
    expected_git_commit,
    expected_git_tree,
    expected_suite_identity_sha256,
    output,
) -> WindowsExecutionSourceBoundCandidateVerification

verify_windows_execution_source_bound_candidate(
    archive_path,
    *,
    base_suite_root,
    execution_base_release,
    expected_bound_archive_sha256,
    expected_source_archive_sha256,
    expected_champion_archive_sha256,
    expected_model_artifact_sha256,
    expected_training_snapshot_sha256,
    expected_config_sha256,
    expected_git_commit,
    expected_git_tree,
    expected_suite_identity_sha256,
) -> WindowsExecutionSourceBoundCandidateVerification
```

CLI names:

```text
prepare_windows_execution_source_bound_candidate.py
verify_windows_execution_source_bound_candidate.py
```

## Data Models

### Bound archive inventory

| Member | Type | Constraint |
| --- | --- | --- |
| `WINDOWS_EXECUTION_SOURCE_BOUND_CANDIDATE.json` | canonical JSON | Closed manifest, one LF |
| `source/windows-execution-production-config-source-v1.zip` | ZIP bytes | Exact seven-pin source |
| `candidate/<configured-candidate-relative-path>` | bytes | Exact 15-file validated candidate inventory |

### Verification result

| Field | Type | Constraint |
| --- | --- | --- |
| `archive_sha256` | LowerHex64 | Exact outer bound archive |
| `binding_identity_sha256` | LowerHex64 | Canonical manifest-core identity |
| `source_archive_sha256` | LowerHex64 | Exact packaged source archive |
| `bootstrap_binding_sha256` | LowerHex64 | Equal in source and candidate |
| `production_config_sha256` | LowerHex64 | Equal to source outer archive |
| `candidate_content_sha256` | LowerHex64 | Authoritative candidate receipt identity |
| `suite_identity_sha256` | LowerHex64 | Independently pinned exact suite |
| `git_commit` / `git_tree` | LowerHex40 | Equal across source, candidate, suite |
| `safety` / `effects` | closed objects | Deny-only; temp extraction is verification-only |

No database entity or migration is introduced.

## Out of Scope

- OS-1: Provider acceptance or runtime provider materialization; these require
  independent Windows review and conformance evidence.
- OS-2: Credential/private-key provisioning or validation; this artifact
  contains references and fingerprints only.
- OS-3: Task installation, service launch, MT5 initialization, permit issuance,
  manual-demo order, demo-auto activation, or live activation.
- OS-4: Changing provider-pack/configured-candidate v1 schemas or removing
  their existing CLIs; this increment adds a mandatory downstream proof.
- OS-5: Provider-conformance schema v3 integration; the bound artifact becomes
  its required Execution evidence input in the next reviewed increment.
- OS-6: External signing/WORM custody, policy approval, statistical/OOS gates,
  or broker/legal approval.
