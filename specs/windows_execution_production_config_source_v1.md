# Windows Execution Production Configuration Source v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-28
**Status:** Approved for implementation
**Reviewers:** project owner, security, ship-gate
**Related specs:** `windows_execution_provider_pack_v1.md`,
`windows_runtime_stage_champion_configuration_binding_v1.md`,
`runtime_stage_champion_binding_v1.md`,
`rule_core_champion_artifact_v1.md`

## Context

The Windows Execution provider pack binds a caller-supplied
`production_config_sha256`, while the configured-candidate input separately
supplies `bootstrap_binding_sha256`. Runtime materialization later requires an
exact `WindowsExecutionProductionConfigSource`, but no portable, deterministic
source artifact currently proves that these two hashes came from the same
`ProductionRuntimeConfig`, exact `StageBinding`, and independently pinned
rule-core champion.

This creates an avoidable operator boundary: a syntactically valid provider
pack and configured candidate can be assembled from unrelated hashes and only
fail when an externally reviewed runtime hook is materialized. The system must
instead produce one inspectable, deterministic source archive that binds the
canonical production configuration, canonical stage, and exact embedded
champion before provider-pack or configured-candidate review.

The new artifact is deny-only. It contains no credential, private key, permit,
account login, environment arm, or order authority. Preparation and
verification are offline and must not import providers, open SQLite,
initialize MT5, contact a network, install tasks, start services, or mutate a
broker.

## Functional Requirements

- FR-1: The system MUST create a deterministic ZIP containing exactly the
  canonical production configuration, canonical stage binding, exact champion
  archive, and canonical source manifest.
- FR-2: Preparation MUST require six independent champion pins: archive,
  model artifact, training snapshot, config, full Git commit, and full Git
  tree.
- FR-3: Preparation MUST verify the embedded champion against all six pins
  before publishing any output.
- FR-4: The portable verifier MUST enforce the closed
  `windows-production-bootstrap-v2` payload, and the public runtime loader
  MUST reconstruct an exact `ProductionRuntimeConfig` from those bytes.
- FR-5: The stage document MUST be a closed canonical wrapper containing
  `schema_version=stage-readiness-authorization-v3`, the exact
  `StageBinding.to_canonical_dict()` payload, and its exact
  `binding_sha256`.
- FR-6: Preparation and verification MUST require exact equality between the
  production configuration and stage for account alias, server, environment,
  journal, runtime config, dependency lock, broker specification, session
  calendar, manual-demo custodian trust, aggregate stage binding, and all five
  explicit champion identities.
- FR-7: The stage model-artifact identity, config identity, commit, Git tree,
  snapshot identity, archive identity, package identity, and runtime-binding
  identity MUST equal the verified embedded champion.
- FR-8: The stage symbol MUST occur exactly once as a canonical key in the
  production configuration symbol map.
- FR-9: The source manifest MUST bind every member path, size, SHA-256, the
  production source SHA-256, bootstrap safe-binding SHA-256, stage-binding
  SHA-256, package identity, runtime binding, full commit/tree, safety state,
  and effect non-claims.
- FR-10: The manifest MUST have one non-self-referential
  `source_identity_sha256` derived from the canonical manifest core.
- FR-11: The outer archive MUST use one fixed inventory, fixed POSIX mode,
  fixed timestamp, sorted members, no comment, and deterministic compression.
- FR-12: A public verifier MUST require seven external pins: outer archive
  SHA-256 plus the six champion pins.
- FR-13: A public loader MUST return an exact sealed
  `WindowsExecutionProductionConfigSource` whose `source_sha256` is the outer
  archive SHA-256 and whose config is reconstructed from the verified member.
- FR-14: Output publication MUST be create-exclusive, reject symlink/reparse
  indirection, preserve all pre-existing bytes, and remove only the exact
  regular file created by the failing invocation.
- FR-15: The builder and verifier MUST reject duplicate JSON keys, non-finite
  numbers, non-canonical JSON, duplicate/case-folded ZIP members, path
  traversal, encrypted members, data descriptors, trailing bytes, metadata
  drift, unexpected directories, and decompression/size drift.
- FR-16: All successful results MUST retain `provider_accepted=false`,
  `production_execution_ready=false`, `promotion_eligible=false`,
  `order_capability=DISABLED`, `safe_to_demo_auto_order=false`, and
  `live_allowed=false`.
- FR-17: Preparation and verification MUST NOT read credentials or private
  keys, import configured providers, open SQLite, initialize MT5, access a
  network, install or start a task/service, issue a permit, or mutate a broker.
- FR-18: The CLI preparer and verifier MUST run under `python -I -S -B`, print
  stable reason codes on rejection, and expose no secret-bearing option.
- FR-19: The configured-release operator tooling MUST include the preparer,
  verifier, and required pure-validation modules; decision, execution,
  status-monitor, and read-only-shadow service releases MUST NOT include the
  preparer or verifier CLIs.
- FR-20: Existing execution locks, provider-pack schemas, configured-candidate
  schemas, and runtime effect boundaries MUST remain unchanged in this
  increment.

## Non-Functional Requirements

- NFR-1 (Fail closed): Any missing, malformed, zero, mismatched, or
  independently unpinned identity MUST reject before output publication or
  provider effect.
- NFR-2 (Determinism): Two preparations with identical input bytes and pins
  MUST produce byte-identical archives in normal and optimized CPython 3.12.
- NFR-3 (Portability): The archive and verifier MUST work on Windows CPython
  3.12 without third-party packages.
- NFR-4 (Bounded size): Each JSON member MUST be at most 1 MiB, the embedded
  champion at most 32 MiB, and the outer archive at most 40 MiB.
- NFR-5 (Reviewability): All cross-bindings and non-claims MUST be direct
  scalar or closed-object manifest members; no identity may be hidden only in
  generated Python source.
- NFR-6 (Path fidelity): Production filesystem paths MUST be normalized by
  `ProductionRuntimeConfig` on the host preparing the artifact and reproduced
  byte-for-byte by the loader on the consuming host; host/path drift MUST fail
  the safe-binding comparison.
- NFR-7 (Regression): Focused and complete normal/optimized tests,
  compilation, dependency-lock verification, release allowlist tests, and
  repository hygiene checks MUST pass.

## Acceptance Criteria

### AC-1: Deterministic exact archive (FR-1, FR-9, FR-10, FR-11, NFR-2)

Given canonical production configuration and stage documents plus one exact
champion and six valid pins
When two independent output paths are prepared
Then both archive byte streams are identical
And both outer SHA-256 values and source identities are identical.

### AC-2: Seven-pin verification (FR-2, FR-3, FR-7, FR-12)

Given one valid source archive
When the verifier receives the exact outer hash and six champion pins
Then it returns a sealed verification containing the exact source, bootstrap,
stage, package, and runtime identities
And every trading safety flag remains false or disabled.

### AC-3: Cross-source mismatch rejection (FR-6, FR-7, FR-8, FR-17)

Given otherwise valid source inputs
When any stage/config/champion cross-binding differs
Then preparation rejects with a stable mismatch reason
And no provider, credential, SQLite, MT5, network, task, service, permit, or
broker effect occurs.

### AC-4: Runtime source loading (FR-4, FR-5, FR-13, NFR-6)

Given a seven-pin-verified archive on the intended host
When the public loader reconstructs its production configuration
Then the result is an exact `WindowsExecutionProductionConfigSource`
And its `source_sha256` equals the outer archive SHA-256
And its config safe binding equals the manifest bootstrap binding.

### AC-5: Malformed and adversarial archive rejection (FR-14, FR-15)

Given a valid archive or output destination
When one case introduces a duplicate member, case-fold collision, path
traversal, metadata drift, trailing bytes, non-canonical JSON, dangling
symlink, or pre-existing target
Then the operation rejects without overwriting or deleting pre-existing bytes.

### AC-6: Release boundary (FR-18, FR-19, FR-20)

Given all five base-release roles and configured tooling
When allowlist and package tests run
Then only configured tooling contains the new operator CLIs
And no service release gains an activation capability or provider effect.

### AC-7: Complete regression (FR-16, FR-17, NFR-7)

Given the completed implementation
When focused and full verification run in normal and optimized modes
Then all tests, compilation, dependency, spec, and hygiene gates pass
And the system remains in deny-only state.

## Edge Cases and Error Scenarios

- EC-1: Runtime configuration JSON has a duplicate key or trailing newline
  drift beyond its one canonical newline -> reject.
- EC-2: Stage JSON has an extra field or legacy schema -> reject.
- EC-3: Champion archive bytes match their manifest but not one external pin ->
  reject.
- EC-4: Runtime config carries a correct aggregate stage hash but one explicit
  champion pin differs -> reject.
- EC-5: Runtime config and stage match but the embedded champion package
  identity differs -> reject.
- EC-6: Stage symbol is absent or duplicated in the symbol map -> reject.
- EC-7: Input changes between metadata inspection and final read -> reject.
- EC-8: Output parent is a symlink/reparse point or output already exists ->
  reject and preserve it.
- EC-9: Publication fails after exclusive creation -> delete only the unchanged
  exact file created by that invocation; preserve any replacement.
- EC-10: ZIP has a valid central directory followed by appended data -> reject.
- EC-11: Archive verifies on a different host where resolved production paths
  differ -> reconstructed safe binding differs and loading rejects.
- EC-12: `DEMO_AUTO` appears while the centralized policy lock is false ->
  `ProductionRuntimeConfig` rejects; the artifact cannot bypass policy.

## API Contracts

This increment adds offline Python and CLI contracts only. It introduces no
HTTP endpoint (including `POST /api/windows-execution-production-config-source`)
and no broker API.

```typescript
interface WindowsExecutionProductionConfigSourceManifestV1 {
  schema_version: "windows-execution-production-config-source-v1";
  source_identity_sha256: LowerHex64;
  members: Array<{
    path: string;
    size_bytes: number;
    sha256: LowerHex64;
  }>;
  production_config_source_sha256: LowerHex64;
  bootstrap_binding_sha256: LowerHex64;
  stage_binding_sha256: LowerHex64;
  champion: {
    archive_sha256: LowerHex64;
    package_identity_sha256: LowerHex64;
    model_artifact_sha256: LowerHex64;
    training_snapshot_sha256: LowerHex64;
    config_sha256: LowerHex64;
    git_commit: LowerHex40;
    git_tree: LowerHex40;
    runtime_binding_sha256: LowerHex64;
  };
  safety: {
    provider_accepted: false;
    production_execution_ready: false;
    promotion_eligible: false;
    order_capability: "DISABLED";
    safe_to_demo_auto_order: false;
    live_allowed: false;
  };
  effects: Record<string, "NOT_PERFORMED">;
}
```

```text
prepare_windows_execution_production_config_source(
    *,
    production_config_path,
    stage_binding_path,
    champion_artifact_path,
    expected_champion_archive_sha256,
    expected_model_artifact_sha256,
    expected_training_snapshot_sha256,
    expected_config_sha256,
    expected_git_commit,
    expected_git_tree,
    output,
) -> WindowsExecutionProductionConfigSourceVerification

verify_windows_execution_production_config_source(
    archive_path,
    *,
    expected_source_archive_sha256,
    expected_champion_archive_sha256,
    expected_model_artifact_sha256,
    expected_training_snapshot_sha256,
    expected_config_sha256,
    expected_git_commit,
    expected_git_tree,
) -> WindowsExecutionProductionConfigSourceVerification

load_windows_execution_production_config_source(...) ->
    WindowsExecutionProductionConfigSource
```

CLI names:

```text
prepare_windows_execution_production_config_source.py
verify_windows_execution_production_config_source.py
```

## Data Models

### Source archive inventory

| Member | Type | Constraint |
| --- | --- | --- |
| `config/windows_production_runtime_config.json` | canonical JSON | Exact `reviewed_configuration_payload`, one LF |
| `evidence/windows_stage_binding.json` | canonical JSON | Closed schema/binding/hash wrapper, one LF |
| `evidence/rule-core-champion-artifact.zip` | ZIP bytes | Exact six-pin-verified champion |
| `WINDOWS_EXECUTION_PRODUCTION_CONFIG_SOURCE.json` | canonical JSON | Closed manifest, one LF |

### Verification result

| Field | Type | Constraint |
| --- | --- | --- |
| `archive_sha256` | LowerHex64 | Exact outer archive |
| `source_identity_sha256` | LowerHex64 | Canonical manifest-core identity |
| `production_config_source_sha256` | LowerHex64 | Exact config member bytes |
| `bootstrap_binding_sha256` | LowerHex64 | `ProductionRuntimeConfig.safe_binding_sha256` |
| `stage_binding_sha256` | LowerHex64 | `StageBinding.binding_sha256` |
| champion fields | closed object | Exact embedded verifier result |
| safety/effects | closed objects | Deny-only constants |

No database entity or migration is introduced.

## Out of Scope

- OS-1: Creating production credentials, private keys, key fingerprints,
  account logins, or Task Scheduler definitions.
- OS-2: Accepting an external provider implementation or materializing its
  hooks.
- OS-3: Changing provider-pack or configured-candidate schemas in this
  increment; downstream tools consume the emitted hashes in a later reviewed
  integration.
- OS-4: Issuing stage authorization, permits, manual-demo approval, DEMO_AUTO
  activation, or live approval.
- OS-5: Starting services, importing MT5, submitting orders, or mutating a
  broker.
- OS-6: Claiming champion quality, OOS success, promotion eligibility,
  scheduled-shadow success, custody completion, or soak completion.
