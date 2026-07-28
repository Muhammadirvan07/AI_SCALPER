# Windows Runtime Stage Champion Configuration Binding v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-28
**Status:** Approved for implementation
**Reviewers:** project owner, security, ship-gate
**Related specs:** `runtime_stage_champion_binding_v1.md`,
`windows_execution_provider_pack_v1.md`,
`windows_execution_factory_materialization_probe_v1.md`

## Context

`StageBinding` v3 carries the exact champion archive, package, training
snapshot, Git tree, and runtime-binding identities. The Windows production
configuration currently binds only the aggregate stage SHA-256. That aggregate
hash is necessary, but it does not expose independently reviewable champion
pins in the configuration source consumed by the Execution provider.

This increment adds the five identities to `ProductionRuntimeConfig` and
requires exact equality with the separately materialized `StageBinding` before
any credential, SQLite, MT5, network, or execution-provider effect. The change
is deny-only. It does not configure an external provider, approve a champion,
enable DEMO_AUTO, or grant order authority.

## Functional Requirements

- FR-1: `ProductionRuntimeConfig` MUST require exact champion archive, package,
  training snapshot, Git-tree, and runtime-binding identities.
- FR-2: Each SHA-256 identity MUST be a canonical non-zero lower-case
  64-character hexadecimal value; the Git tree MUST be a canonical non-zero
  lower-case 40-character hexadecimal value.
- FR-3: All five identities MUST be included in
  `reviewed_configuration_payload` and therefore in `safe_binding_sha256`.
- FR-4: Static production-bootstrap validation MUST compare all five
  configuration identities with the exact `ProductionRuntimePorts.stage_binding`.
- FR-5: A mismatch MUST fail with `STAGE_BINDING_MISMATCH` before any external
  provider, filesystem database, MT5, network, or broker effect.
- FR-6: The existing aggregate `stage_binding_sha256` comparison MUST remain;
  the explicit fields are additional independent review pins, not a replacement.
- FR-7: Existing release/provider configuration hashes MUST transitively change
  when any champion configuration pin changes.
- FR-8: The production-bootstrap configuration schema MUST advance to v2;
  v1 configurations MUST fail closed instead of being silently upgraded.
- FR-9: Existing execution locks MUST remain unchanged:
  `live_allowed=false`, `safe_to_demo_auto_order=false`,
  `order_capability=DISABLED`, and `promotion_eligible=false` where present.
- FR-10: This increment MUST NOT initialize MT5, read credentials or private
  keys, open SQLite, mutate Task Scheduler, contact a network, or mutate a
  broker.

## Non-Functional Requirements

- NFR-1 (Fail closed): missing, malformed, zero, or mismatched champion pins
  MUST fail construction or static validation.
- NFR-2 (Determinism): identical configuration values MUST produce identical
  safe-binding hashes under normal and optimized CPython 3.12.
- NFR-3 (Reviewability): the five pins MUST be visible as direct scalar members
  of the reviewed configuration payload.
- NFR-4 (Compatibility): manual DEMO and dormant DEMO_AUTO configurations use
  the same exact champion lineage contract; no v1 compatibility fallback is
  permitted.
- NFR-5 (Regression): focused and complete normal/optimized tests, compilation,
  dependency-lock verification, and repository hygiene checks MUST pass.

## Acceptance Criteria

### AC-1: Exact configuration lineage (FR-1, FR-3, FR-7)

Given a valid production runtime configuration
When its reviewed payload is inspected
Then all five champion identities are present
And changing any one changes `safe_binding_sha256`.

### AC-2: Invalid identity rejection (FR-2)

Given a missing, zero, wrong-length, or non-hex champion identity
When the production configuration is constructed
Then construction fails before any provider is invoked.

Given an upper-case hexadecimal identity
When the production configuration is constructed
Then it is canonicalized to lower case before hashing.

### AC-3: Cross-champion configuration rejection (FR-4, FR-5, FR-10)

Given a valid exact stage and an otherwise valid production configuration
When one explicit champion pin differs while the aggregate stage hash is left
unchanged
Then static bootstrap validation raises `STAGE_BINDING_MISMATCH`
And no provider, SQLite, MT5, network, or broker effect occurs.

### AC-4: Aggregate binding and schema retained (FR-6, FR-8)

Given five matching explicit champion pins
When the aggregate stage-binding SHA-256 differs
Then static bootstrap validation still raises `STAGE_BINDING_MISMATCH`.

Given a v1 production-bootstrap configuration
When construction is attempted
Then it fails closed because its canonical champion fields are absent.

### AC-5: Regression and safety (FR-9, FR-10)

Given the completed implementation
When focused and complete verification runs in normal and optimized modes
Then all tests and supply-chain checks pass
And no safety lock changes.

## Edge Cases

- EC-1: Archive matches but package differs -> reject.
- EC-2: Package matches but snapshot differs -> reject.
- EC-3: Git commit matches but Git tree differs -> reject.
- EC-4: Model artifact matches but runtime binding differs -> reject.
- EC-5: All explicit fields match but aggregate stage hash differs -> reject.
- EC-6: A valid upper-case hash is supplied -> normalize lower-case and bind
  the normalized value.
- EC-7: A subclassed or dynamically shaped stage object is supplied -> existing
  exact-type checks remain authoritative.

## API Contracts

This is an internal Python configuration contract only. It introduces no HTTP,
CLI, credential, task-installation, or broker API.
A hypothetical `POST /runtime/windows/champion-pins` endpoint is explicitly
prohibited and MUST NOT be implemented.

```typescript
interface WindowsRuntimeChampionPins {
  championArchiveSha256: LowerHex64;
  championPackageIdentitySha256: LowerHex64;
  championTrainingSnapshotSha256: LowerHex64;
  championGitTree: LowerHex40;
  championRuntimeBindingSha256: LowerHex64;
}
```

No public constructor synthesizes these pins. A reviewed Windows production
configuration source must provide them, and the bootstrap compares them with
the independently supplied exact `StageBinding`.

## Data Models

`ProductionRuntimeConfig` adds five required scalar fields:

| Field | Canonical type | Constraint |
| --- | --- | --- |
| `champion_archive_sha256` | lower hex | exact 64, non-zero |
| `champion_package_identity_sha256` | lower hex | exact 64, non-zero |
| `champion_training_snapshot_sha256` | lower hex | exact 64, non-zero |
| `champion_git_tree` | lower hex | exact 40, non-zero |
| `champion_runtime_binding_sha256` | lower hex | exact 64, non-zero |

All five fields are direct members of `reviewed_configuration_payload`.
`safe_binding_sha256` remains the canonical SHA-256 of that complete payload.
The configuration schema is `windows-production-bootstrap-v2`.

## Out of Scope

- OS-1: selecting or approving a champion;
- OS-2: external registry or WORM custody;
- OS-3: provider-hook implementation or acceptance;
- OS-4: Windows Credential Manager or Task Scheduler provisioning;
- OS-5: manual-demo orders, DEMO_AUTO activation, soak, or LIVE trading.
