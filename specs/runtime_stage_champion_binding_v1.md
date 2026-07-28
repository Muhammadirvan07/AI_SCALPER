# Runtime Stage Champion Binding v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-28
**Status:** Approved
**Reviewers:** project owner, security, ship-gate
**Related specs:** `independent_promotion_champion_binding_v1.md`,
`architecture_foundation_completion_v1.md`, `demo_auto_session_capability_v1.md`

## Context

Promotion evidence v2 signs the exact champion archive, package, training
snapshot, Git tree, runtime binding, quality corpus, and bootstrap identities.
The independent issuer also derives the signed Git commit and model identity
from directly verified champion bytes. The later stage and runtime boundaries,
however, currently compare only the receipt's commit, configuration, and model
hashes against `StageBinding`.

That partial comparison allows two different champion packages with the same
source-model digest to be indistinguishable at the stage boundary. The signed
receipt itself remains tamper-evident, but the stage has no independently bound
expectation for archive, package, snapshot, tree, or runtime-binding identity.
This increment makes those five champion identities part of the exact immutable
stage contract and carries the comparison through promotion validation,
DEMO_AUTO session controls, the runtime supervisor, and every executor
revalidation point.

The change remains deny-only. It does not declare the current Phillip evidence
sufficient, does not enable DEMO_AUTO or LIVE, and performs no network,
credential, MT5, Task Scheduler, registry, or broker action.

## Functional Requirements

- FR-1: `StageBinding` MUST contain exact champion archive, package, training
  snapshot, Git-tree, and runtime-binding identities in addition to its existing
  commit, configuration, and model identities.
- FR-2: Every champion SHA-256 field MUST canonicalize to a non-zero lower-case
  64-character hash and the Git tree MUST canonicalize to an exact non-zero
  lower-case 40-character hash.
- FR-3: Promotion stage authorization MUST compare all five new champion
  identities in the signed promotion receipt with the exact `StageBinding`.
- FR-4: Each mismatch MUST produce a stable, field-specific reason code and
  MUST make stage authorization invalid before replay consumption.
- FR-5: Standalone promotion receipt validation MUST require independently
  supplied expected champion identities and MUST fail closed when any expected
  identity is absent or different.
- FR-6: A sealed `PromotionEvidenceValidation` MUST expose the verified
  champion identities and the runtime supervisor MUST compare every one with
  its exact stage binding.
- FR-7: Every initial, reservation-time, pre-reservation, and pre-send
  promotion revalidation in the executor MUST use the champion identities from
  the exact DEMO_AUTO IPC stage binding.
- FR-8: A missing, invalid, or cross-stage DEMO_AUTO IPC binding MUST NOT allow
  promotion validation to fall back to values supplied by the receipt.
- FR-9: The stage content hash, authorization signatures, acceptance receipts,
  session binding, session lease, and supervisor binding MUST automatically
  change when any champion identity changes.
- FR-9a: The stage-readiness authorization schema MUST advance to v3 because
  the canonical stage binding has new required fields; old v2 artifacts MUST
  fail closed instead of being silently upgraded.
- FR-10: Existing receipt-content-hash bindings for quality corpus and
  bootstrap identities MUST remain intact; this feature MUST NOT duplicate
  those values as caller-controlled execution inputs.
- FR-11: Manual DEMO contracts MAY carry the same exact champion lineage and
  MUST preserve existing behavior apart from the stronger stage identity.
- FR-12: LIVE validation without an independently configured exact stage
  champion binding MUST fail closed; this increment MUST NOT invent a LIVE
  activation path.
- FR-13: All safety outputs MUST retain `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `promotion_eligible=false`, and
  `order_capability=DISABLED` wherever those fields exist.
- FR-14: The implementation MUST NOT initialize MT5, submit or mutate an
  order, read credentials or private keys, mutate Task Scheduler, contact a
  network service, or alter broker state.

## Non-Functional Requirements

- **NFR-1 (Fail closed):** Missing, malformed, mismatched, or subclassed trust
  values MUST return invalid evidence or raise before any execution adapter
  call.
- **NFR-2 (Determinism):** Identical stage and receipt values MUST produce
  identical canonical hashes and reason-code ordering under normal and
  optimized CPython 3.12.
- **NFR-3 (Compatibility):** Existing session serialization MUST round-trip the
  expanded direct scalar stage fields without schema coercion or loss.
- **NFR-4 (Security):** No expected champion value may be inferred only from
  the receipt being validated.
- **NFR-5 (Regression):** Focused tests MUST pass in normal and optimized mode;
  the full project regression, compilation, formatting, dependency-lock, and
  ship-gate checks MUST also pass.
- **NFR-6 (Safety):** Successful validation is evidence eligibility only and
  MUST NOT grant execution, activation, promotion, DEMO_AUTO, or LIVE authority.

## Acceptance Criteria

### AC-1: Exact stage champion identity (FR-1, FR-2, FR-9)

Given a valid stage binding
When its canonical representation is inspected
Then it contains the exact archive, package, snapshot, tree, and runtime-binding
identities
And changing any one changes the stage binding SHA-256.

### AC-2: Malformed identity rejection (FR-2, NFR-1)

Given a zero, wrong-length, or non-hex champion identity
When `StageBinding` is constructed
Then construction fails before an authorization can be issued.

Given a valid upper-case hexadecimal identity
When `StageBinding` is constructed
Then it is canonicalized to lower case before hashing.

### AC-3: Stage authorization rejects cross-champion receipt (FR-3, FR-4)

Given a correctly signed receipt whose commit, configuration, and model match
the stage but one champion identity differs
When DEMO_AUTO stage authorization is validated
Then validation is invalid with the field-specific mismatch reason
And its replay nonce is not consumed.

### AC-4: Standalone validator requires external expectations (FR-5, FR-8,
NFR-4)

Given a correctly signed promotion receipt
When one expected champion pin is missing or differs
Then promotion validation is invalid
And no value read from that receipt substitutes for the missing expectation.

### AC-5: Runtime supervisor rejects lineage substitution (FR-6, NFR-1)

Given an otherwise valid DEMO_AUTO runtime input
When its sealed promotion validation carries a champion identity different from
the stage
Then the supervisor raises its promotion-evidence critical error before any
dispatch authority exists.

### AC-6: Executor revalidates every boundary (FR-7, FR-8, FR-12)

Given a DEMO_AUTO intent and exact IPC stage binding
When promotion evidence is checked initially, at reservation, before final
reservation, or immediately before send
Then all five champion expectations come only from that exact stage binding
And a missing or mismatched binding prevents an adapter submission.

### AC-7: Session lineage is transitive (FR-9, FR-9a, NFR-3)

Given a persisted DEMO_AUTO session binding and lease
When the binding is loaded and verified
Then the expanded stage identity round-trips exactly
And the existing stage-binding SHA-256 checks transitively cover every champion
field
And an old v2 stage-readiness artifact is not accepted as v3.

### AC-8: Receipt hash retains corpus lineage (FR-10)

Given a stage request and permit bound to an exact promotion receipt hash
When quality-corpus or bootstrap identity changes
Then the receipt hash changes and existing request or permit binding rejects it
without accepting a separate caller-supplied corpus identity.

### AC-9: Manual compatibility and safety (FR-11, FR-13, FR-14, NFR-6)

Given a manual DEMO stage using the expanded champion identity
When its existing authorization flow is validated
Then prior manual evidence behavior remains unchanged
And every activation, order, promotion, DEMO_AUTO, and LIVE capability remains
disabled.

### AC-10: Regression gates (NFR-2, NFR-5)

Given the completed implementation
When focused normal and optimized tests plus all repository verification gates
run
Then all checks pass with no weakened safety invariant.

## Edge Cases and Error Scenarios

- EC-1: Receipt archive differs while model, commit, and config match → reject
  with `PROMOTION_CHAMPION_ARCHIVE_MISMATCH`.
- EC-2: Package identity differs → reject with
  `PROMOTION_CHAMPION_PACKAGE_MISMATCH`.
- EC-3: Snapshot identity differs → reject with
  `PROMOTION_CHAMPION_SNAPSHOT_MISMATCH`.
- EC-4: Git tree differs → reject with `PROMOTION_CHAMPION_TREE_MISMATCH`.
- EC-5: Runtime-binding identity differs → reject with
  `PROMOTION_CHAMPION_RUNTIME_BINDING_MISMATCH`.
- EC-6: Expected champion pin is `None`, empty, malformed, or derived only from
  the receipt → standalone validation returns a stable missing/invalid reason.
- EC-7: A valid validation object from another champion reaches the supervisor
  → supervisor raises `DEMO_AUTO_PROMOTION_EVIDENCE_VALIDATION_FAILED`.
- EC-8: A stage binding scalar is changed after session persistence → canonical
  stage hash mismatch rejects the session/IPC chain.
- EC-9: LIVE receipt arrives without a separate exact champion expectation →
  invalid; policy locks remain active.
- EC-10: Quality corpus changes with identical champion bytes → existing exact
  receipt-reference comparison rejects the changed receipt.

## API Contracts

This increment exposes internal Python contracts only. A hypothetical
`POST /runtime/stage/champion` endpoint is explicitly prohibited and MUST NOT be
implemented.

```typescript
interface RuntimeStageChampionIdentity {
  commitSha: LowerHex40;
  configSha256: LowerHex64;
  modelArtifactSha256: LowerHex64;
  championArchiveSha256: LowerHex64;
  championPackageIdentitySha256: LowerHex64;
  championTrainingSnapshotSha256: LowerHex64;
  championGitTree: LowerHex40;
  championRuntimeBindingSha256: LowerHex64;
}

interface PromotionValidationInput {
  signedReceipt: PromotionEvidenceReceiptV2;
  expectedMode: "DEMO_AUTO" | "LIVE";
  expectedLane: string;
  expectedChampion: RuntimeStageChampionIdentity;
}

interface PromotionValidationResult {
  valid: boolean;
  reasonCodes: string[];
  receiptSha256: LowerHex64;
  championArchiveSha256: LowerHex64;
  championPackageIdentitySha256: LowerHex64;
  championTrainingSnapshotSha256: LowerHex64;
  championGitTree: LowerHex40;
  championRuntimeBindingSha256: LowerHex64;
  executionAuthorized: false;
  liveAllowed: false;
}
```

## Data Models

### Expanded StageBinding

| Field | Type | Constraints |
|---|---|---|
| champion_archive_sha256 | LowerHex64 | Exact independently selected champion ZIP |
| champion_package_identity_sha256 | LowerHex64 | Canonical verified package identity |
| champion_training_snapshot_sha256 | LowerHex64 | Exact frozen training snapshot |
| champion_git_tree | LowerHex40 | Exact source tree used by champion |
| champion_runtime_binding_sha256 | LowerHex64 | Exact verified runtime/model binding |

The existing `commit_sha`, `config_sha256`, and `model_artifact_sha256` complete
the stage champion identity. All fields are direct immutable scalars so current
canonical session JSON round-trips without a new nested coercion path.

### PromotionEvidenceValidation

The sealed validation retains its existing fields and exposes all five stage
champion identities. Its `valid` flag means only that signed evidence matched
the provided expectations at `checked_at`; it has no execution-authority field.

No database, HTTP, credential-store, Task Scheduler, broker, or MT5 data model
is added or changed.

## Out of Scope

- OS-1: Generating real OOS, broker-forward, manual-demo, or soak observations.
- OS-2: Selecting or uploading a champion to an external immutable registry.
- OS-3: Automatic champion/challenger promotion, retraining, or online learning.
- OS-4: Introducing a LIVE stage, enabling any execution policy flag, or sending
  a broker order.
- OS-5: Duplicating quality-corpus and bootstrap identities outside the already
  signed and content-hash-bound promotion receipt.
- OS-6: Windows provider conformance, credential provisioning, task installation,
  or deployment mutation; those remain separate externally reviewed gates.
