# Windows LIVE Canary Execution Configured Candidate v1

## Title and Metadata

- **Author:** Codex with the AI_SCALPER project owner
- **Date:** 2026-07-29
- **Status:** Approved for implementation
- **Reviewers:** senior architecture, security, and ship-gate boundaries
- **Related contracts:**
  `specs/windows_atomic_base_release_suite_v1.md`,
  `specs/windows_configured_service_release_v1.md`,
  `specs/windows_live_canary_execution_materialization_v1.md`, and
  `specs/windows_live_canary_execution_provider_pack_v1.md`

## Context

AI_SCALPER has a deterministic, secret-free Windows LIVE Execution provider
pack. The pack is an exact four-file overlay, but it is not yet bound into an
immutable configured Execution release from the same atomic base suite. The
existing Execution configured-candidate assembler is deliberately limited to
`DEMO` and `DEMO_AUTO`, uses the canonical 46-port factory template, and MUST
not be relabeled as LIVE.

This feature introduces one additive LIVE-only descriptor path, one immutable
15-file candidate, one static 49-port LIVE factory-template receipt, and one
independent validator. It preserves the original four-file provider pack,
builds an exact suite-bound configured release, and records all ancestry and
safety state without importing providers or granting launch/order authority.

## Functional Requirements

- FR-1: The existing `prepare_configured_overlay_candidate` API MUST continue
  to accept only `DEMO` or `DEMO_AUTO` and MUST reject `LIVE`.
- FR-2: A new LIVE-specific configured-overlay preparer MUST accept only the
  Execution base profile, fixed runtime mode `LIVE`, and the additive schema
  `windows-live-canary-configured-service-overlay-v1`.
- FR-3: The LIVE preparer MUST bind the reviewed base-release
  `live_runtime/windows_live_canary_execution_provider.py` bytes as its
  reviewed factory-template source. It MUST reject another role, missing
  source, source drift, or a caller-selected template.
- FR-4: The assembler MUST accept one exact atomic five-role base-suite root,
  its exact Execution base archive, one exact validated four-file LIVE provider
  pack, one reviewed disabled Task Scheduler definition, one canonical
  candidate input, one candidate ID, and one new output root.
- FR-5: The candidate input MUST contain only
  `schema_version`, `bootstrap_binding_sha256`, and the exact non-secret
  `task_scheduler` binding. It MUST use schema
  `windows-live-canary-execution-configured-candidate-input-v1`.
- FR-6: The task binding MUST require service-account logon, limited run level,
  ignore-new multiple-instance policy, a non-empty task path, and six non-zero
  SHA-256 identity/policy pins.
- FR-7: The assembler MUST independently verify the complete base suite, exact
  Execution role, LIVE foundation bytes, and provider pack before output.
- FR-8: The original provider-pack root MUST remain byte-identical and MUST
  still pass its authoritative validator after successful or failed assembly.
- FR-9: The output MUST contain an immutable exact provider-pack copy below
  `provider-pack/` and a separate working copy below `configured-overlay/`.
- FR-10: The working overlay MUST contain exactly the original four files plus
  `config/windows_factory_manifest.json`; runtime mode MUST be derived as
  `LIVE` from the statically parsed provider configuration.
- FR-11: The assembler MUST build and independently verify one suite-bound
  configured release using the exact Execution member of the supplied suite.
  Its inherited `GATED_PRESENT` code capability MUST NOT be represented as
  provider acceptance, live authority, production readiness, or order
  authorization.
- FR-12: The assembler MUST emit canonical
  `live-execution-factory-template.json` with exact configured-release,
  bootstrap, provider-configuration, service-config, production-config,
  49-provider contract, 12-credential-reference, task, safety, and LIVE
  contract-set bindings.
- FR-13: Static factory-template validation MUST reconstruct every provider
  contract/kind/configuration/implementation/credential binding and MUST NOT
  import or materialize the generated provider.
- FR-14: The output root MUST contain exactly:
  the four `provider-pack/` members, the five `configured-overlay/` members,
  `configured-overlay.json`, `live-execution-configured-v1.zip`, its manifest
  sidecar, `live-execution-factory-template.json`,
  `reviewed-task-definition.xml`, and
  `LIVE_EXECUTION_CONFIGURED_CANDIDATE.json`.
- FR-15: The candidate receipt MUST bind the exact suite, Execution base,
  provider pack, provider configuration, LIVE contract set, bootstrap,
  descriptor, task, configured archive/manifest/identity, factory template,
  Git commit/tree, complete file inventory, status, effects, safety, and a
  content SHA-256 over all preceding fields.
- FR-16: The receipt MUST use schema
  `windows-live-canary-execution-configured-candidate-v1` and status
  `EXTERNAL_LIVE_PROVIDER_CONFORMANCE_REQUIRED`.
- FR-17: The completion receipt MUST be written last. Missing, extra, changed,
  symlinked, reparse, noncanonical, or case-colliding members MUST be rejected.
- FR-18: The output root MUST be created exclusively. On failure, cleanup MUST
  remove only the exact invocation-owned root and MUST preserve any replacement
  path or pre-existing input.
- FR-19: Two assemblies from identical bytes and candidate ID MUST produce
  identical corresponding files and candidate content hashes; absolute result
  paths MUST remain outside canonical identity.
- FR-20: The assembler and validator CLIs MUST expose no credential value,
  account login, private key, provider acceptance, launch, central unlock,
  permit, arm, activation, MT5 initialization, or order argument.
- FR-21: LIVE candidate tooling MUST exist only in configured-release operator
  tooling. The LIVE materializer remains only in the Execution base release;
  no offline assembler or validator may enter a service release.
- FR-22: Every pack, descriptor, template, receipt, result, and CLI output MUST
  retain `order_capability=DISABLED`, `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `max_lot=0.01`,
  `promotion_eligible=false`, `provider_accepted=false`, and
  `production_execution_ready=false`.
- FR-23: Successful local assembly MUST NOT claim target-Windows acceptance,
  concrete provider conformance, launcher approval, task installation, central
  unlock, demo soak completion, or broker canary completion.

## Non-Functional Requirements

- NFR-1 — Security: All reads MUST be stable, bounded, regular,
  non-symlink/non-reparse reads. Unknown fields/files, traversal, duplicate
  keys, non-finite values, probable secrets, and unstable input MUST fail
  closed with stable non-secret reason codes.
- NFR-2 — Side effects: Assembly and validation MUST perform zero provider
  import/materialization/request, credential access, SQLite open, network
  access, subprocess/service start, Task Scheduler installation, MT5 import or
  initialization, permit/signature issuance, central-policy mutation, broker
  mutation, or order submission.
- NFR-3 — Compatibility: Existing configured-release, Execution V1 pack, and
  46-port configured-candidate APIs and generated bytes MUST remain unchanged.
- NFR-4 — Determinism: Canonical JSON, fixed ZIP metadata, sorted exact
  inventories, and byte-derived SHA-256 values MUST make independent builds
  reproducible.
- NFR-5 — Resource bounds: Each document MUST be at most 4 MiB; configured
  archives MUST be at most 256 MiB; candidate inventory MUST remain exactly 15
  files.
- NFR-6 — Reliability: Enforcement MUST NOT depend on `assert` and MUST behave
  identically under normal Python and `PYTHONOPTIMIZE=2`.
- NFR-7 — Quality gate: Strict spec validation, focused/full normal and
  optimized tests, Ruff, compile, JSON, scoped diff, dependency lock, release
  builders, and ship-gate review MUST run before commit.

## Acceptance Criteria

### AC-1: Deterministic exact candidate (FR-4, FR-7, FR-8, FR-9, FR-14, FR-17, FR-19)

Given an exact suite, Execution archive, LIVE pack, task, input, and candidate ID
When two independent assemblies run
Then both contain exactly the same 15 files and identical corresponding bytes
And both candidate content hashes are identical
And both original provider packs remain unchanged and valid.

### AC-2: LIVE-only descriptor separation (FR-1, FR-2, FR-3, FR-10)

Given the legacy configured-overlay preparer and the new LIVE preparer
When callers request runtime mode `LIVE`
Then the legacy API rejects it
And only the LIVE API emits the additive LIVE schema for the Execution profile
And both paths retain every safety lock.

### AC-3: Exact LIVE inventory and template (FR-6, FR-12, FR-13, FR-15)

Given a valid candidate
When the embedded provider configuration and LIVE factory template are parsed
Then both bind exactly 49 ordered contracts and 12 credential references
And the LIVE contract-set, configured-release, provider-config, service-config,
production-config, bootstrap, and task hashes all match.

### AC-4: Exact suite and release ancestry (FR-7, FR-11, FR-15)

Given a candidate assembled from one five-role suite
When independent validation runs
Then the configured ZIP is reconstructed as the exact Execution role overlay
And suite identity, suite manifest, base archive, base release, commit, tree,
descriptor, sidecar, and configured identities all match.

### AC-5: Fail-closed tamper and schema handling (FR-5, FR-16, FR-17, FR-22)

Given any duplicate key, secret field, wrong mode/schema/profile, missing or
extra file, byte tamper, source drift, task drift, pack/overlay mismatch,
contract drift, identity drift, symlink/reparse, or noncanonical JSON
When assembly or validation runs
Then it fails before returning a valid result and never imports a provider.

### AC-6: Transactional custody (FR-8, FR-18)

Given an existing output, mid-assembly failure, or replacement of an
invocation-owned root
When cleanup runs
Then no pre-existing or replacement byte is deleted or overwritten.

### AC-7: CLI and release isolation (FR-20, FR-21)

Given the two LIVE candidate CLIs and every release allowlist
When help/bootstrap and release-builder tests run
Then the CLIs expose only static assembly/validation inputs
And they appear only in configured-release operator tooling
And the materializer appears only in the Execution service release.

### AC-8: V1 compatibility (FR-1)

Given all existing V1 configured-release, provider-pack, and candidate tests
When additive LIVE support is present
Then every existing test and canonical V1 contract identity remains unchanged.

### AC-9: Honest result (FR-22, FR-23)

Given all local acceptance tests pass
When status documentation is updated
Then only the configured-candidate source boundary is locally complete
And target-Windows build/acceptance, source binding, external conformance,
central unlock, demo soak, and first broker canary remain blocked.

## Edge Cases

- EC-1: Another suite, another role archive, or mixed commit/tree fails before
  output.
- EC-2: A standard descriptor claiming LIVE or a LIVE descriptor claiming
  DEMO/DEMO_AUTO fails.
- EC-3: LIVE preparation for Decision or Status Monitor fails.
- EC-4: Missing/drifted LIVE materializer source in the base archive fails.
- EC-5: A valid four-file DEMO pack supplied as a LIVE pack fails.
- EC-6: A LIVE pack with one changed credential purpose, provider order,
  contract hash, or implementation hash fails.
- EC-7: A non-empty existing output directory, empty existing directory, file,
  symlink, or reparse point fails without modification.
- EC-8: Candidate/root inputs overlap directly or by ancestry fails.
- EC-9: Task XML is empty, oversized, secret-bearing, unstable, or does not
  match the input task hash.
- EC-10: Configured release has `runtime_mode=LIVE` but any candidate safety
  authority becomes true; outer validation rejects it.
- EC-11: A copied receipt under another exact root is valid because absolute
  paths are excluded from canonical identity.
- EC-12: Crash residue without the receipt or with partial inventory is invalid.

## API Contracts

No HTTP, broker, credential, scheduler, activation, or order API is added.
`GET /not-applicable` is a documentation-only marker and MUST NOT be
implemented. The only new public APIs are offline filesystem boundaries:

```typescript
interface WindowsLiveCanaryExecutionConfiguredCandidate {
  readonly runtimeMode: "LIVE";
  readonly providerCount: 49;
  readonly credentialReferenceCount: 12;
  readonly status: "EXTERNAL_LIVE_PROVIDER_CONFORMANCE_REQUIRED";
  readonly providerAccepted: false;
  readonly productionExecutionReady: false;
  readonly liveAllowed: false;
  readonly orderCapability: "DISABLED";
}
```

```python
prepare_live_canary_configured_overlay_candidate(
    *,
    base_archive: str | Path,
    overlay_root: str | Path,
    task_definition_path: str | Path,
    overlay_id: str,
    bootstrap_binding_sha256: str,
    descriptor_output_path: str | Path,
) -> ConfiguredOverlayCandidatePreparation

assemble_windows_live_canary_execution_configured_candidate(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    provider_pack_root: str | Path,
    task_definition_path: str | Path,
    candidate_input_path: str | Path,
    candidate_id: str,
    output_root: str | Path,
) -> WindowsLiveCanaryExecutionConfiguredCandidate

validate_windows_live_canary_execution_configured_candidate(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    candidate_root: str | Path,
) -> WindowsLiveCanaryExecutionConfiguredCandidate
```

Both CLIs return `0` only for an exact deny-only result and `2` for rejection.
Neither CLI accepts or emits secret material or authority.

## Data Models

| Model | Field | Type | Constraints |
|---|---|---|---|
| Candidate input | `schema_version` | string | Exact LIVE candidate input v1 |
| Candidate input | `bootstrap_binding_sha256` | SHA-256 | Non-zero, caller cannot override derived identities |
| Candidate input | `task_scheduler` | object | Exact ten-field non-secret task binding |
| Candidate receipt | identities | SHA-256 | Exact suite/base/pack/config/contract/bootstrap/overlay/task/release/template bindings |
| Candidate receipt | `files` | array[14] | Sorted exact non-receipt inventory |
| Candidate receipt | `runtime_mode` | string | Exact `LIVE` |
| Candidate receipt | `provider_count` | integer | Exact 49 |
| Candidate receipt | `credential_reference_count` | integer | Exact 12 |
| Candidate receipt | effects | object | Every effect false |
| Candidate receipt | safety | object | Deny-only, max lot 0.01 |
| LIVE factory template | providers | array[49] | Exact ordered public bindings |
| LIVE factory template | credentials | array[12] | Non-secret purpose-bound references |

The candidate receipt contains exact SHA-256 identities for suite, base role,
pack, provider configuration, LIVE contract set, bootstrap, overlay descriptor,
task, configured archive, configured sidecar, configured release, LIVE factory
template, Git commit/tree, and every non-receipt file. Effects and safety are
closed exact objects whose booleans remain false.

The LIVE factory template is canonical JSON and contains only public identities,
non-secret Credential Manager references, provider metadata/hashes, fixed
runtime mode, task binding, and deny-only safety. It contains no provider value,
credential value, login, password, token, private key, permit, arm, account
secret, or broker mutation capability.

## Out of Scope

- OS-1: Concrete provider callback implementation or external provider
  acceptance.
- OS-2: Source-bound candidate packaging and external conformance receipt.
- OS-3: Windows task installation, ACL mutation, service/process launch, or
  uptime.
- OS-4: Credential retrieval, clock/state read, SQLite open, MT5
  import/initialize,
  network access, broker request, or order submission.
- OS-5: Central LIVE policy changes, promotion/gate/human/deployment signatures,
  WORM/CAS custody, demo-auto soak, and first XAUUSD broker canary.
- OS-6: Pair expansion, position scaling, or production rollout.
