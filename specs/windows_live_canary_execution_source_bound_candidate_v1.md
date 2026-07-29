# Windows LIVE Canary Execution Source-Bound Candidate v1

## Title and Metadata

- **Author:** Codex with the AI_SCALPER project owner
- **Date:** 2026-07-29
- **Status:** Approved for implementation
- **Reviewers:** senior architecture, security, and ship-gate boundaries
- **Related contracts:**
  `specs/windows_execution_source_bound_candidate_v1.md`,
  `specs/windows_live_canary_execution_configured_candidate_v1.md`, and
  `specs/live_canary_prebootstrap_admission_v1.md`

## Context

AI_SCALPER now has an exact deny-only Windows LIVE Execution configured
candidate. Separately, the existing Windows Execution source-bound artifact
proves that one DEMO configured candidate, one seven-pin production source,
one champion, and one atomic five-role base suite have matching source,
bootstrap, commit, tree, and release identities. Prebootstrap admission uses
that sealed DEMO ancestry as the reviewed source lineage for the future LIVE
canary.

The LIVE configured candidate is not yet packaged with that independently
verified ancestry. A caller could present both artifacts separately, leaving
the cross-binding to later orchestration. This feature introduces an additive
portable archive that packages the exact prior source-bound archive and all
15 exact LIVE configured-candidate files, re-verifies both from packaged
bytes, and proves their production source, bootstrap, suite, Execution role,
Git commit/tree, and factory-template relationships before any provider
conformance or runtime effect.

The resulting artifact is evidence only. It MUST NOT accept providers, read
credentials, open production state, start a process, initialize MT5, mutate a
broker, open the central LIVE policy, or authorize an order.

## Functional Requirements

- FR-1: The builder MUST create one deterministic ZIP containing exactly one
  canonical binding manifest, one exact verified Windows Execution
  source-bound v1 archive, and all 15 exact files of one validated Windows
  LIVE Execution configured candidate.
- FR-2: The source-bound archive MUST be verified by the authoritative v1
  verifier against its exact outer hash, source hash, champion archive/model/
  snapshot/config hashes, full Git commit/tree, atomic-suite identity, exact
  base-suite root, and exact Execution base release.
- FR-3: The LIVE configured candidate MUST be verified by its authoritative
  validator against the same exact base suite and Execution base release.
- FR-4: The LIVE factory template's `production_config_sha256` MUST equal the
  verified source-bound result's `source_archive_sha256`.
- FR-5: The LIVE candidate and factory template bootstrap hashes MUST equal
  the verified source-bound result's `bootstrap_binding_sha256`.
- FR-6: The LIVE candidate suite identity, Execution base archive/release
  identities, full Git commit/tree, and factory configured-release identity
  MUST match the verified source-bound result and supplied suite.
- FR-7: The LIVE factory template MUST use runtime mode `LIVE`, the canonical
  49-provider contract-set hash, 49 exact provider bindings, and 12 exact
  purpose-bound credential references.
- FR-8: The packaged source-bound archive and original LIVE candidate root
  MUST remain byte-identical and authoritative-valid after successful or
  failed preparation.
- FR-9: The outer manifest MUST bind every payload member path, size, SHA-256,
  source-bound verification identity, LIVE candidate identity, factory
  template identity, source/bootstrap/suite/role/commit/tree closure, safety,
  and effect claims.
- FR-10: The outer manifest MUST expose one non-self-referential
  `binding_identity_sha256` derived from the canonical manifest core.
- FR-11: The outer ZIP MUST use a closed sorted inventory, fixed timestamp,
  fixed POSIX regular-file mode, deterministic compression, no comments, no
  encryption, no data descriptors, and no trailing bytes.
- FR-12: The public verifier MUST require ten independent pins: outer LIVE
  archive SHA-256 plus the nine pins required by the embedded source-bound v1
  verifier.
- FR-13: Verification MUST reconstruct both packaged inputs beneath one new
  private temporary root, invoke both authoritative validators, and delete
  the temporary root on success or failure.
- FR-14: Verification MUST rebuild every manifest field from packaged bytes;
  caller-authored lineage mappings or identity overrides MUST NOT be accepted.
- FR-15: Output publication MUST be create-exclusive, reject path
  indirection, preserve all pre-existing bytes, and remove only an exact
  invocation-created regular file after a failure.
- FR-16: Builder and verifier MUST reject duplicate/noncanonical JSON,
  malformed/duplicate/case-folded/traversing ZIP members, ZIP metadata drift,
  decompression or size drift, source or candidate replacement, unstable
  input, output overlap, symlink, and Windows reparse points.
- FR-17: Successful results MUST retain `provider_accepted=false`,
  `production_execution_ready=false`, `promotion_eligible=false`,
  `order_capability=DISABLED`, `safe_to_demo_auto_order=false`,
  `live_allowed=false`, and `max_lot=0.01`.
- FR-18: Preparation and verification MUST NOT import/materialize a generated
  provider, access credentials/private keys, open SQLite, initialize MT5,
  access a network, install/start a task or service, issue a permit/signature,
  mutate policy, mutate a broker, or submit an order.
- FR-19: CLI entry points MUST require `python -I -S -B`, expose no secret,
  account login, provider acceptance, launcher, central unlock, permit, arm,
  MT5 initialization, or order option, and print stable rejection codes.
- FR-20: The builder, verifier, and new module MUST exist only in configured
  release operator tooling and MUST remain absent from Decision, Execution,
  Status Monitor, and Read-Only Shadow service releases.
- FR-21: Existing source-bound v1 and LIVE configured-candidate schemas,
  bytes, public APIs, and canonical identities MUST remain unchanged.
- FR-22: Local success MUST be described only as source ancestry closure; it
  MUST NOT claim target-Windows provider conformance, task/launcher approval,
  demo soak completion, central unlock, or broker canary completion.

## Non-Functional Requirements

- NFR-1 — Security: Every external scalar and byte source MUST be exact-type,
  bounded, stable, regular, non-symlink/non-reparse, and independently pinned.
- NFR-2 — Determinism: Identical input bytes and pins MUST produce
  byte-identical archives under normal and optimized CPython 3.12.
- NFR-3 — Portability: Preparation and verification MUST run on Windows
  CPython 3.12 from configured operator tooling using only the standard
  library and packaged pure/offline modules.
- NFR-4 — Resource bounds: JSON documents MUST be at most 4 MiB, the embedded
  source-bound archive at most 384 MiB, the configured archive at most 256
  MiB, expanded LIVE candidate files at most 320 MiB, and the outer archive at
  most 768 MiB.
- NFR-5 — Reliability: Enforcement MUST NOT use `assert`; normal and
  optimized execution MUST enforce identical security decisions.
- NFR-6 — Temporary custody: Extraction MUST use create-exclusive writes
  below a new private root and guaranteed identity-safe cleanup.
- NFR-7 — Quality gate: Strict spec validation, focused/full normal and
  optimized tests, Ruff, AST/JSON/whitespace checks, dependency lock, release
  isolation, and ship-gate review MUST pass before commit.

## Acceptance Criteria

### AC-1: Deterministic exact archive (FR-1, FR-9, FR-10, FR-11, NFR-2)

Given one valid source-bound archive, LIVE candidate, suite, release, and pins
When two new output paths are prepared independently
Then both archives contain the exact same 17 members and identical bytes
And both outer and binding identities match.

### AC-2: Authoritative packaged-byte verification (FR-2, FR-3, FR-12, FR-13, FR-14)

Given one valid packaged archive
When the public verifier runs with ten independent pins
Then it re-verifies the embedded source-bound archive and LIVE candidate from
temporary packaged bytes
And removes all temporary material before returning a sealed result.

### AC-3: Source and bootstrap closure (FR-4, FR-5, FR-7)

Given one valid packaged archive
When its LIVE factory template and source-bound result are reconstructed
Then the production-source and bootstrap hashes match exactly
And the LIVE template retains exactly 49 providers and 12 references.

### AC-4: Suite, role, Git, and release closure (FR-6)

Given one exact suite and Execution role
When verification runs
Then source-bound result, LIVE candidate, factory template, suite, archive,
release identity, full commit, and full tree all match.

### AC-5: Cross-artifact substitution fails (FR-4, FR-5, FR-6, NFR-1)

Given otherwise valid artifacts from different source, bootstrap, suite,
Execution release, commit, tree, or candidate
When preparation or verification runs
Then it rejects before publication or success and performs no runtime effect.

### AC-6: Adversarial archive and destination handling (FR-8, FR-15, FR-16)

Given a valid input or output location
When a member is missing/extra/changed, metadata is changed, traversal or
case-fold collision is added, trailing bytes exist, an input changes during
read, or destination already exists/is indirect
Then the operation rejects without altering any pre-existing byte.

### AC-7: CLI and release isolation (FR-18, FR-19, FR-20)

Given the two CLIs and every release allowlist
When help/bootstrap/static-effect/release-builder tests run
Then tooling is present only in configured operator tooling
And no credential, provider, scheduler, policy, MT5, broker, or order effect
is reachable.

### AC-8: Compatibility and honest status (FR-17, FR-21, FR-22)

Given all local tests pass
When existing artifacts and status reports are checked
Then existing identities remain unchanged
And every authority flag stays denied
And the project remains `DO_NOT_SHIP` pending external evidence.

### AC-9: Complete regression (NFR-5, NFR-7)

Given the completed implementation
When focused and full quality gates run normally and with optimization
Then every local automated gate passes with the same fail-closed behavior.

## Edge Cases

- EC-1: The embedded source-bound archive hash is valid but one of its nine
  external pins belongs to another archive -> reject.
- EC-2: The source-bound archive and LIVE candidate use different suites,
  roles, commits, or trees -> reject.
- EC-3: The LIVE production source differs from the verified source archive ->
  reject.
- EC-4: Candidate and factory bootstrap hashes differ from source ancestry ->
  reject.
- EC-5: A valid DEMO configured candidate is substituted for LIVE -> reject.
- EC-6: A LIVE candidate has a changed provider count, credential count,
  contract-set, configured identity, task, or content receipt -> reject.
- EC-7: The outer ZIP contains duplicate, case-colliding, encrypted,
  descriptor-backed, traversing, oversized, metadata-drifted, or trailing
  content -> reject.
- EC-8: Existing output file/directory, dangling symlink, reparse point, or
  indirect parent -> reject without overwrite.
- EC-9: Candidate root includes an extra/missing/symlinked member -> reject.
- EC-10: Publication fails after exclusive creation -> remove only the exact
  invocation-created unchanged output.
- EC-11: Temporary extraction fails part-way -> clean the private temporary
  root and perform no external mutation.
- EC-12: A caller recomputes the manifest after changing an upstream binding
  but lacks matching external pins -> authoritative verification rejects.

## API Contracts

No HTTP, broker, credential, scheduler, policy, signing, activation, or order
API is added. `POST /api/live-source-bound-candidate` is documentation-only
and MUST NOT be implemented.

```typescript
interface WindowsLiveCanaryExecutionSourceBoundCandidateV1 {
  readonly schemaVersion: "windows-live-canary-execution-source-bound-candidate-v1";
  readonly runtimeMode: "LIVE";
  readonly providerCount: 49;
  readonly credentialReferenceCount: 12;
  readonly providerAccepted: false;
  readonly productionExecutionReady: false;
  readonly liveAllowed: false;
  readonly orderCapability: "DISABLED";
}
```

```python
prepare_windows_live_canary_execution_source_bound_candidate(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    demo_source_bound_archive: str | Path,
    live_configured_candidate_root: str | Path,
    expected_source_bound_archive_sha256: str,
    expected_source_archive_sha256: str,
    expected_champion_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
    expected_suite_identity_sha256: str,
    output: str | Path,
) -> WindowsLiveCanaryExecutionSourceBoundCandidateVerification

verify_windows_live_canary_execution_source_bound_candidate(
    archive_path: str | Path,
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    expected_live_bound_archive_sha256: str,
    expected_source_bound_archive_sha256: str,
    expected_source_archive_sha256: str,
    expected_champion_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
    expected_suite_identity_sha256: str,
) -> WindowsLiveCanaryExecutionSourceBoundCandidateVerification
```

Both CLIs return `0` only for an exact deny-only result and `2` for rejection.

## Data Models

| Entity | Field | Type | Constraint |
|---|---|---|---|
| Outer manifest | `schema_version` | enum | Exact v1 value |
| Outer manifest | `binding_identity_sha256` | SHA-256 | Derived from manifest core |
| Outer manifest | `members` | array | Exact sorted 16-payload inventory |
| Source ancestry | identity/hash fields | SHA-256/SHA-1 | Derived from sealed v1 verifier |
| LIVE candidate | identity/hash fields | SHA-256/SHA-1 | Derived from authoritative validator |
| LIVE candidate | `runtime_mode` | enum | Exact `LIVE` |
| LIVE candidate | provider/reference counts | integer | Exactly 49 / 12 |
| Safety | authority fields | false/enum | Exact deny-only object |
| Effects | named effects | enum | Verification-only or not performed |

## Out of Scope

- OS-1: Creating or validating real provider callback implementations.
- OS-2: Reading Windows Credential Manager or any secret/private key.
- OS-3: Installing or starting Task Scheduler, a service, MT5, or a runtime.
- OS-4: Issuing provider acceptance, launcher attestation, promotion, permit,
  arm, deployment signature, or central-policy unlock.
- OS-5: Performing manual-demo, demo-auto soak, broker canary, reconciliation,
  rollback, or expansion orders.
- OS-6: Changing existing v1 source-bound or configured-candidate schemas.
