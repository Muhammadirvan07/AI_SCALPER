# Windows Decision Configured Candidate Assembly v1

## Title and Metadata

- **Author:** Codex with the AI_SCALPER project owner
- **Date:** 2026-07-25
- **Status:** Approved
- **Reviewers:** AI_SCALPER project owner under the standing Live-Grade v1
  roadmap authorization
- **Related contracts:**
  `specs/windows_atomic_base_release_suite_v1.md`,
  `specs/windows_decision_provider_pack_v1.md`,
  `specs/windows_configured_overlay_candidate_preparation_v1.md`,
  `specs/windows_configured_service_release_v1.md`,
  `specs/windows_configured_factory_template_binding_parity_v1.md`, and
  `specs/windows_three_service_provider_conformance_v2.md`

## Context

AI_SCALPER now has an exact atomic five-role base suite, a deterministic
Decision provider-pack generator, a generic configured-overlay preparer, and a
suite-bound configured-release builder. Each boundary verifies its own input,
but the operator still has to join them manually.

The current documented sequence also mutates the validated four-file Decision
provider-pack directory by adding `config/windows_factory_manifest.json`.
After that mutation the original provider-pack validator correctly rejects the
directory because it no longer has its exact four-file inventory. The
configured release can still be valid, but the original reviewed pack evidence
has been destroyed in place and the operator must manually derive the
bootstrap binding and Decision factory-template JSON.

This feature adds one offline, deny-only assembler and one independent
validator. The assembler preserves the original pack, copies its exact bytes
into a candidate root, derives the bootstrap binding from the signed
Decision-producer contract already present in the pack, invokes the existing
authoritative preparer and configured builder, emits the exact Decision
factory-template JSON required by provider-conformance v2, and seals all
artifacts in one closed candidate inventory. It neither accepts providers nor
grants runtime authority.

## Functional Requirements

- FR-1: The assembler MUST accept one exact atomic five-role base-suite root,
  its exact Decision base archive, one exact validated four-file Decision
  provider-pack root, one reviewed Task Scheduler definition, one canonical
  candidate ID, and one new output root.
- FR-2: The assembler MUST independently verify the complete base suite, exact
  Decision role membership, Decision foundation bytes, and provider pack
  before creating output.
- FR-3: The input provider-pack root MUST remain byte-identical and MUST still
  pass its authoritative validator after successful or failed assembly.
- FR-4: The output MUST contain an immutable exact copy of the original
  four-file provider pack below `provider-pack/` and a separate working copy
  below `configured-overlay/`.
- FR-5: The assembler MUST derive `bootstrap_binding_sha256` from the exact
  parsed Decision producer binding in
  `config/windows_service_config.json`; callers MUST NOT supply or override
  it.
- FR-6: The assembler MUST use runtime mode `DEMO_AUTO` and MUST invoke the
  existing generic configured-overlay preparer against only the working copy.
- FR-7: The working overlay MUST contain exactly the original four files plus
  the generated `config/windows_factory_manifest.json`.
- FR-8: The assembler MUST build and independently verify one suite-bound
  `WINDOWS_DECISION_SERVICE_V1` configured release using the exact Decision
  member of the supplied suite.
- FR-9: The assembler MUST emit canonical
  `decision-factory-template.json`, derived from the exact configured release
  identity, factory bytes, service-config bytes, and the seven provider
  bindings parsed from that same config.
- FR-10: The emitted Decision factory template MUST pass
  `validate_windows_decision_service_factory_template` with the exact
  configured release identity and MUST contain exactly seven providers.
- FR-11: The output root MUST contain exactly:
  the four `provider-pack/` members, the five `configured-overlay/` members,
  `configured-overlay.json`, `decision-configured-v1.zip`,
  `decision-configured-v1.zip.manifest.json`,
  `decision-factory-template.json`, `reviewed-task-definition.xml`, and
  `DECISION_CONFIGURED_CANDIDATE.json`.
- FR-12: `DECISION_CONFIGURED_CANDIDATE.json` MUST bind the exact suite,
  Decision base, provider pack, descriptor, task, configured archive,
  configured sidecar, configured identity, Decision factory-template, Git
  commit/tree, complete file inventory, status, effects, safety locks, and a
  content SHA-256 computed over every preceding field.
- FR-13: The output root MUST be created exclusively. A completion marker
  receipt MUST be written last; any root without the exact receipt and exact
  inventory MUST be rejected as incomplete.
- FR-14: On any assembly failure, the implementation MUST remove only the new
  output root created by that invocation and MUST never modify inputs or any
  pre-existing destination.
- FR-15: The independent validator MUST reconstruct every hash, configured
  identity, suite binding, pack validation, overlay partition, task binding,
  factory template, receipt content hash, and exact file set without importing
  or materializing a configured provider.
- FR-16: Output bytes MUST be deterministic for identical inputs except for
  absolute result paths, which MUST remain outside the canonical receipt.
- FR-17: The CLI MUST expose no credential value, password, account login,
  private key, provider acceptance, permit, environment arm, activation,
  order, or live-enable argument.
- FR-18: The assembler, validator, and their implementation MUST exist only in
  the configured-release operator-tooling inventory and MUST remain absent
  from Decision, execution, status-monitor, and read-only-shadow service
  releases.
- FR-19: A successful result MUST remain a candidate requiring external
  provider conformance and MUST NOT claim provider acceptance, task
  installation, production readiness, demo-auto activation, or live
  readiness.
- FR-20: Every path MUST retain
  `order_capability=DISABLED`, `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `max_lot=0.01`,
  `promotion_eligible=false`, and `production_execution_ready=false`.

## Non-Functional Requirements

- NFR-1 — Security: All reads MUST be stable, bounded, regular,
  non-symlink/non-reparse reads. Unknown files, traversal, case collisions,
  duplicate JSON keys, non-finite values, probable secrets, and unstable
  inputs MUST fail closed.
- NFR-2 — Determinism: Two assemblies from byte-identical inputs and identical
  candidate IDs MUST produce byte-identical corresponding files and identical
  candidate content hashes.
- NFR-3 — Resource bounds: Each regular document MUST be at most 4 MiB; total
  non-archive candidate input MUST be at most 64 MiB; archive limits MUST use
  the existing configured-release and base-suite limits.
- NFR-4 — Reliability: Validation MUST behave identically with normal Python
  and `PYTHONOPTIMIZE=2`; security enforcement MUST NOT depend on `assert`.
- NFR-5 — Side effects: Assembly and validation MUST perform zero credential
  access, provider import/materialization, network access, subprocess/service
  launch, Task Scheduler installation, MT5 initialization, broker mutation,
  permit/signature issuance, activation, or order submission.
- NFR-6 — Performance: One complete local fixture assembly and verification
  SHOULD finish within five seconds on the normal development host, excluding
  filesystem scheduling variance.
- NFR-7 — Regression: Focused, optimized, full repository, compilation,
  release-boundary, dependency-lock, SBOM, and ship-gate checks MUST remain
  green.

## Acceptance Criteria

### AC-1: Valid deterministic candidate assembly (FR-1 through FR-13, FR-16)

Given one exact suite, Decision base, provider pack, safe task definition,
candidate ID, and new destination  
When two independent assemblies run  
Then both validate successfully  
And all corresponding output bytes and candidate content hashes are identical
And both original provider-pack roots remain valid and unchanged.

### AC-2: Bootstrap and factory template are derived (FR-5, FR-9, FR-10)

Given a valid provider pack  
When assembly runs  
Then no bootstrap hash is accepted from the caller  
And the receipt bootstrap hash equals the exact parsed producer binding hash  
And the emitted seven-provider template binds the configured identity and
exact factory/configuration hashes.

### AC-3: Exact suite/configured ancestry (FR-2, FR-8, FR-12, FR-15)

Given a valid candidate  
When independent validation runs  
Then it proves the configured release belongs to the exact Decision role of
the same five-role suite  
And reconstructs the base archive, sidecar, suite, Git commit/tree, and
configured identities.

### AC-4: Original pack remains immutable (FR-3, FR-4, FR-14)

Given success, mid-assembly failure, or output collision  
When the original pack bytes and authoritative validation are rechecked  
Then every byte and identity remains unchanged.

### AC-5: Tamper and incomplete output fail closed (FR-11 through FR-15, NFR-1)

Given any missing, extra, changed, symlinked, case-colliding, path-indirected,
noncanonical, or stale candidate member, descriptor, task, ZIP, sidecar,
factory template, or receipt  
When validation runs  
Then it rejects with a stable reason code without importing a provider.

### AC-6: Existing destination and transactional cleanup (FR-13, FR-14)

Given a pre-existing destination or an injected failure after output-root
creation  
When assembly runs  
Then no pre-existing byte is overwritten  
And only the invocation-owned incomplete root is removed.

### AC-7: Provider-pack/overlay partition is exact (FR-4, FR-6, FR-7, FR-15)

Given a valid candidate  
When its two provider inventories are compared  
Then `provider-pack/` is the exact original four-file pack  
And `configured-overlay/` adds only the canonical factory manifest  
And the configured archive contains exactly the working overlay plus the
verified base release.

### AC-8: Effect and release isolation (FR-17, FR-18, FR-19, FR-20, NFR-5)

Given CLI/help/static/runtime sentinels and every release allowlist  
When assembly and validation execute  
Then no forbidden effect occurs  
And the tooling exists only in the configured-release operator release  
And all activation, order, promotion, and live locks remain denied.

### AC-9: Optimized, deterministic, and full regression (NFR-2, NFR-4, NFR-7)

Given the completed implementation  
When focused and full tests run normally and optimized and release/dependency
gates run  
Then every check passes with identical candidate decisions and no ship-gate
regression.

## Edge Cases

- EC-1: The supplied Decision archive belongs to another suite or role →
  reject before output.
- EC-2: The input pack already contains a generated factory manifest → reject
  as a non-exact provider pack.
- EC-3: The task definition is empty, oversized, secret-bearing, symlinked,
  reparse, or changes during read → reject without output.
- EC-4: The producer binding hash is zero, malformed, or changes relative to
  the runtime config → authoritative runtime parsing rejects.
- EC-5: The configured release builds but its independent verifier is patched
  to reject → remove the invocation-owned output root.
- EC-6: Receipt creation fails after every other file exists → the incomplete
  root is removed by the assembler; a crash residue is rejected by the
  validator because the receipt/file set is incomplete.
- EC-7: A contract-projection hash substitutes the exact base-member template
  hash → runtime parity validation rejects.
- EC-8: A provider-pack file and working-overlay file differ by one byte →
  validator rejects even if their individual JSON or Python syntax is valid.
- EC-9: Output root exists as an empty directory, file, symlink, or reparse
  point → reject without modification.
- EC-10: Two processes race for the same output root → only the atomic
  directory creator may continue; the other rejects.
- EC-11: Candidate ID, runtime mode, or safety state drifts in one nested
  artifact → cross-binding validation rejects.
- EC-12: The candidate receipt is copied to a different root with an exact
  inventory → permitted because absolute paths are deliberately not identity
  inputs; all content hashes must still verify.

## API Contracts

No HTTP, broker, credential, scheduler, signing, or activation API is
introduced. `GET /not-applicable` is a documentation-only marker and MUST NOT
be implemented.

```python
def assemble_windows_decision_configured_candidate(
    *,
    base_suite_root: str | Path,
    decision_base_release: str | Path,
    provider_pack_root: str | Path,
    task_definition_path: str | Path,
    candidate_id: str,
    output_root: str | Path,
) -> WindowsDecisionConfiguredCandidate:
    ...

def validate_windows_decision_configured_candidate(
    *,
    base_suite_root: str | Path,
    decision_base_release: str | Path,
    candidate_root: str | Path,
) -> WindowsDecisionConfiguredCandidate:
    ...
```

```typescript
interface WindowsDecisionConfiguredCandidateReceipt {
  schema_version: "windows-decision-configured-candidate-v1";
  candidate_id: CanonicalId;
  status: "EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED";
  git_commit: Hex40;
  git_tree: Hex40;
  base_suite_identity_sha256: Hex64;
  base_suite_manifest_sha256: Hex64;
  decision_base_release_identity_sha256: Hex64;
  decision_base_archive_sha256: Hex64;
  provider_pack_identity_sha256: Hex64;
  bootstrap_binding_sha256: Hex64;
  overlay_descriptor_sha256: Hex64;
  task_definition_sha256: Hex64;
  configured_release_identity_sha256: Hex64;
  configured_archive_sha256: Hex64;
  configured_manifest_sha256: Hex64;
  decision_factory_template_sha256: Hex64;
  provider_count: 7;
  files: CandidateFileEntry[];
  effects: DenyOnlyEffects;
  safety: LockedSafety;
  content_sha256: Hex64;
}
```

## Data Models

| Entity | Field | Type | Constraints |
|---|---|---|---|
| candidate | `candidate_id` | string | Canonical non-secret ID |
| suite | identity/manifest | SHA-256 | Exact verified five-role suite |
| Decision base | identity/archive | SHA-256 | Exact suite Decision role |
| provider pack | identity | SHA-256 | Exact four-file validated pack |
| configured release | identity/archive/sidecar | SHA-256 | Suite-bound Decision profile |
| factory template | template hash | SHA-256 | Exact canonical seven-provider JSON |
| inventory | path/hash/size | array | Exact 14 non-receipt files |
| receipt | `content_sha256` | SHA-256 | Hash of all preceding fields |
| effects | fixed booleans | object | Every external/runtime effect false |
| safety | fixed locks | object | Order/live/demo-auto/promotion denied |

## Out of Scope

- OS-1: Generating or claiming external provider-conformance evidence.
- OS-2: Importing, materializing, or running the generated Decision provider.
- OS-3: Creating Windows Credential Manager values, CAS custody, clock
  attestations, launcher attestations, or Task Scheduler registrations.
- OS-4: Building the execution or Status Monitor configured candidates.
- OS-5: Issuing signed observations, pre-manual admission, stage
  authorization, permit, or environment arm.
- OS-6: Starting manual demo, demo-auto soak, live canary, or any broker order.
- OS-7: Changing strategy, risk, lane, symbol, model, lot, or execution
  semantics.
