# Windows Configured Factory-Template Binding Parity v1

## Title and Metadata

- **Author:** Codex with the AI_SCALPER project owner
- **Date:** 2026-07-25
- **Status:** Approved
- **Reviewers:** AI_SCALPER project owner under the standing Live-Grade v1
  roadmap authorization
- **Related contracts:**
  `specs/windows_configured_overlay_candidate_preparation_v1.md`,
  `specs/windows_configured_service_release_v1.md`,
  `specs/windows_decision_service_runtime_v1.md`, and
  `specs/windows_external_status_monitor_v1.md`

## Context

The approved configured-overlay preparer derives
`reviewed_factory_template_sha256` from the exact profile-specific
factory-template source member inside the verified base release. This binds
the descriptor to the exact reviewed Git/release bytes and prevents an
operator from supplying a substitute hash.

The Decision and external Status Monitor runtime loaders currently interpret
the same field as the hash of a separately derived canonical contract object.
Those values are intentionally different: one identifies exact source bytes,
while the other identifies a semantic contract projection. Consequently, a
configured release produced by the official preparer can pass deterministic
packaging verification and then fail its official runtime static validation.
Manual test fixtures masked the mismatch by supplying the contract hash
directly instead of using the approved preparer.

This specification restores one authoritative meaning without weakening the
runtime boundary. The descriptor field remains the exact base-member SHA-256,
as already required by the approved preparer specification. Runtime loaders
derive the expected value only from the nested, identity-verified base
manifest and its exact source inventory. Semantic factory-template validation
remains independently enforced by the release-local typed contract code.

## Functional Requirements

- FR-1: `reviewed_factory_template_sha256` MUST mean the SHA-256 of the
  exact profile-specific factory-template source member in the verified base
  release.
- FR-2: The Decision loader MUST derive the expected value from
  `live_runtime/windows_decision_service_factory_template.py` in the nested
  base manifest and MUST NOT compare the field to a separately projected
  contract hash.
- FR-3: The external Status Monitor loader MUST derive the expected value
  from
  `live_runtime/windows_external_status_monitor_factory_template.py` in the
  nested base manifest and MUST NOT compare the field to a separately
  projected contract hash.
- FR-4: A required template member that is missing, duplicated,
  hash-invalid, outside the exact base partition, or mismatched with the
  descriptor/binding MUST fail closed before factory import or provider
  materialization.
- FR-5: The generic overlay preparer and configured-release verifier MUST
  retain their existing exact-member derivation and verification behavior.
- FR-6: Existing semantic template validators, factory-contract hashes,
  configured identities, suite ancestry, task hashes, bootstrap hashes, and
  complete source inventories MUST remain independently verified.
- FR-7: The Decision and Status Monitor loaders MUST accept configured
  releases produced by the official generic preparer when all exact bytes and
  contracts are valid.
- FR-8: Manual fixtures MUST use the same exact-member binding as the
  official preparer and MUST NOT bypass it with caller-derived contract
  hashes.
- FR-9: No change MAY add provider import, credential access, process/task
  mutation, MT5 initialization, broker access, permit issuance, activation,
  or order authority.
- FR-10: All safety locks MUST remain
  `live_allowed=false`, `safe_to_demo_auto_order=false`,
  `max_lot=0.01`, `promotion_eligible=false`, and
  `production_execution_ready=false`.

## Non-Functional Requirements

- **NFR-1 — Determinism:** Identical verified configured releases MUST yield
  identical template-member expectations on every supported CPython 3.12
  host.
- **NFR-2 — Security:** The expected hash MUST come only from the nested base
  manifest already bound into the configured release identity; no external
  path, environment value, or caller override is allowed.
- **NFR-3 — Reliability:** Validation MUST behave identically under normal
  Python and `PYTHONOPTIMIZE=2`; enforcement MUST NOT depend on `assert`.
- **NFR-4 — Side effects:** Static validation MUST perform zero provider
  import, credential read, network access, task installation, MT5
  initialization, broker mutation, or order submission.
- **NFR-5 — Regression:** Focused loader/preparer tests and the full repository
  regression MUST remain green in normal and optimized modes.

## Acceptance Criteria

### AC-1: Official Decision candidate roundtrip (FR-1, FR-2, FR-5, FR-7, FR-8)

Given an exact Decision base release and an overlay prepared by the official
generic preparer  
When the configured release is built, extracted, and statically validated by
the Decision loader  
Then validation succeeds without factory import  
And the bound reviewed-template hash equals the exact Decision template member
hash from the nested base manifest.

### AC-2: Official Status Monitor candidate roundtrip (FR-1, FR-3, FR-5, FR-7, FR-8)

Given an exact Status Monitor base release and an overlay prepared by the
official generic preparer  
When the configured release is built, extracted, and statically validated by
the Status Monitor loader  
Then validation succeeds without factory import  
And the bound reviewed-template hash equals the exact Status Monitor template
member hash from the nested base manifest.

### AC-3: Contract-hash substitution is rejected (FR-1 through FR-4)

Given a descriptor whose reviewed-template field contains the canonical
contract-projection hash instead of the exact source-member hash  
When either affected loader validates the configured release  
Then it fails closed before factory import even when every other field is
valid.

### AC-4: Missing or mismatched base member is rejected (FR-2, FR-3, FR-4)

Given a configured release with a missing required template inventory entry or
a descriptor/template hash mismatch  
When static validation runs  
Then it rejects with a stable loader error and does not materialize a
provider.

### AC-5: Independent contract checks remain intact (FR-6)

Given a valid exact-member binding but a drifted runtime provider template,
factory contract, configured identity, suite ancestry, or source inventory  
When validation runs  
Then the pre-existing authoritative check rejects the candidate.

### AC-6: Safety and effect isolation (FR-9, FR-10, NFR-4)

Given valid and invalid parity fixtures  
When focused tests instrument import, credential, process, network, MT5, and
broker boundaries  
Then every sentinel remains untouched and all activation/order locks remain
denied.

### AC-7: Optimized and full regression (NFR-3, NFR-5)

Given the parity implementation  
When focused and complete tests run in normal and optimized modes  
Then every test passes with identical validation decisions.

## Edge Cases

- EC-1: The required path exists only in the configured overlay rather than
  the nested base inventory → reject.
- EC-2: The required base entry uses a case-variant path → reject because
  release paths are exact and case-sensitive.
- EC-3: The source member bytes are changed together with a recomputed
  descriptor but without a valid nested base identity → existing configured
  identity verification rejects first.
- EC-4: The descriptor and binding agree with each other but not with the
  nested base member → loader rejects.
- EC-5: The exact-member hash accidentally equals a different contract
  hash in a synthetic fixture → validation still derives from the named base
  member and does not change semantics.
- EC-6: Validation is invoked with `PYTHONOPTIMIZE=2` → the same mismatch
  is rejected.

## API Contracts

No HTTP or broker API is introduced. `GET /not-applicable` is a
documentation-only marker and MUST NOT be implemented.

```typescript
interface ReviewedTemplateBinding {
  profile:
    | "WINDOWS_DECISION_SERVICE_V1"
    | "WINDOWS_EXTERNAL_STATUS_MONITOR_V1";
  memberPath:
    | "live_runtime/windows_decision_service_factory_template.py"
    | "live_runtime/windows_external_status_monitor_factory_template.py";
  memberSha256: Hex64;
}

interface ConfiguredDescriptorParityResult {
  exactBaseMemberBound: true;
  providerImported: false;
  credentialAccessPerformed: false;
  brokerMutationPerformed: false;
  liveAllowed: false;
  safeToDemoAutoOrder: false;
  maxLot: 0.01;
}
```

## Data Models

| Field | Type | Constraints |
|---|---|---|
| `reviewed_factory_template_sha256` | SHA-256 | Exact required base-member hash |
| `base_release_manifest.source_files` | array | Exact identity-bound inventory |
| template member path | enum | One profile-specific fixed release path |
| safety locks | fixed values | Must remain deny-only |

## Out of Scope

- OS-1: Changing the factory-template source bytes or semantic provider
  contracts.
- OS-2: Changing execution-service overlay semantics.
- OS-3: Importing or accepting a configured provider.
- OS-4: Generating provider-conformance evidence or external signatures.
- OS-5: Installing or starting Windows tasks/services.
- OS-6: Opening manual demo, demo-auto, live trading, or any broker order path.
