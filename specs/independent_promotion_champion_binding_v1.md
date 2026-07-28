# Independent Promotion Champion Binding v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-28
**Status:** Approved
**Reviewers:** project owner, security, ship-gate
**Related specs:** `rule_core_champion_artifact_v1.md`,
`architecture_foundation_completion_v1.md`

## Context

The independent promotion issuer recalculates OOS, broker-forward, rolling-fold,
bootstrap, drawdown, stress, and runtime-parity evidence from raw observations.
Its current corpus binds trades to symbol, strategy, and configuration, but the
issuer accepts `model_artifact_sha256` independently when it signs the final
promotion receipt. Rolling-fold and parity observations carry no lane or model
identity. Consequently, a statistically complete corpus can be paired with a
different caller-selected model hash without changing the recalculated metrics.

This increment closes that identity gap. It introduces a sealed champion
observation created only by direct verification of the exact champion ZIP
against six independent pins. Every raw quality observation, the corpus, the
assessment, and the signed promotion receipt bind the same model identity. The
issuer derives the signed commit and model hash from the verified champion; a
caller cannot supply them separately.

The feature does not assert that the current Phillip evidence meets OOS or
forward thresholds. It does not grant demo-auto or live permission, and it
does not access a broker, MT5, credentials, Task Scheduler, network, registry,
or private signing-key store.

## Functional Requirements

- FR-1: A champion observation MUST be created only after direct verification
  of exact champion ZIP bytes against archive, model, training-snapshot,
  configuration, Git commit, and Git tree pins.
- FR-2: Direct construction, subclass substitution, a wrong pin, malformed ZIP,
  or mutated champion bytes MUST be rejected before corpus evaluation.
- FR-3: A closed-trade observation MUST bind exact symbol, strategy,
  configuration SHA-256, model SHA-256, source, close time, return, and measured
  cost.
- FR-4: Every rolling-fold and runtime-parity observation MUST bind the same
  exact symbol, strategy, configuration SHA-256, and model SHA-256 as the
  corpus.
- FR-5: A promotion corpus MUST contain one exact sealed champion observation
  and one explicit model SHA-256 that both match every raw observation.
- FR-6: The corpus MUST reject mixed lanes, mixed models, duplicate IDs,
  non-canonical ordering, invalid source partitions, and overlapping OOS and
  broker-forward time windows.
- FR-7: The system MUST calculate a deterministic quality-corpus SHA-256 over
  the complete raw corpus, validation receipt observation, and verified
  champion observation.
- FR-8: Any change to a raw trade, fold, parity report, validation observation,
  champion identity, or their ordering MUST change the corpus identity or fail
  validation.
- FR-9: The independent issuer MUST derive `commit_sha` and
  `model_artifact_sha256` from the sealed champion observation and MUST NOT
  accept either value as a caller-supplied argument.
- FR-10: Promotion evidence schema v2 MUST sign the exact champion archive,
  package, snapshot, Git-tree, and runtime-binding identities together with the
  quality-corpus and bootstrap receipt identities.
- FR-11: Promotion evidence verification MUST validate every new identity as
  an exact lower-case hash and MUST expose those identities in its sealed
  validation result.
- FR-12: The existing lane readiness thresholds and independent raw-statistic
  calculation MUST remain unchanged.
- FR-13: Complete evidence MUST continue to require a separate manual ship gate
  and MUST retain `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `promotion_eligible=false`, and
  `max_lot=0.01` at this issuer boundary.
- FR-14: This feature MUST NOT initialize MT5, submit an order, read a
  credential, access a private-key store, mutate Task Scheduler, contact a
  network service, or change broker state.
- FR-15: Failure MUST be fail-closed and MUST NOT return a partially trusted
  champion observation, assessment, or signed receipt.

## Non-Functional Requirements

- **NFR-1 (Determinism):** Identical champion bytes, pins, raw observations,
  bootstrap parameters, and receipt inputs MUST produce identical identities.
- **NFR-2 (Isolation):** Core champion and corpus verification MUST use the
  Python standard library and remain compatible with CPython 3.12.
- **NFR-3 (Immutability):** Public observation, corpus, assessment, receipt, and
  validation contracts MUST be frozen values and reject unsafe subclasses at
  trust boundaries.
- **NFR-4 (Security):** External pins MUST be mandatory; no value read only
  from inside the champion archive may substitute for an independent pin.
- **NFR-5 (Regression):** Focused tests MUST pass in normal and optimized mode,
  and the full project suite, compilation, formatting, dependency-lock, and
  ship-gate checks MUST remain green.
- **NFR-6 (Safety):** No successful or failed operation may weaken a central
  trading safety lock or represent quality binding as execution authority.

## Acceptance Criteria

### AC-1: Sealed exact champion observation (FR-1, FR-2, NFR-4)

Given a deterministic champion ZIP and six correct independent pins
When the champion observation factory verifies it
Then it returns a sealed immutable observation containing the exact verified
archive, package, model, snapshot, configuration, commit, tree, and runtime
binding identities.

### AC-2: Champion forgery rejection (FR-1, FR-2, FR-15)

Given direct construction, a subclass, mutated bytes, or any wrong external pin
When a corpus or champion verifier consumes it
Then it fails closed before quality evaluation or receipt signing.

### AC-3: Every observation binds one model lane (FR-3, FR-4, FR-5)

Given trade, fold, and parity observations
When any symbol, strategy, configuration, or model identity differs from the
corpus and champion
Then corpus construction fails with a stable mixed-lane or mixed-model reason.

### AC-4: Canonical corpus identity (FR-6, FR-7, FR-8, NFR-1)

Given identical valid raw observations in canonical order
When two assessments are calculated with the same bootstrap parameters
Then their quality-corpus, bootstrap, parity, readiness, and lane-evidence
identities are identical.

### AC-5: Raw evidence tamper visibility (FR-7, FR-8)

Given a valid corpus
When one return, measured cost, fold expectancy, parity count, validation flag,
or champion identity changes
Then the corpus identity changes or construction fails before issuance.

### AC-6: Non-canonical and duplicate corpus rejection (FR-6)

Given duplicated IDs, unsorted trades, folds, or parity reports, source
partition drift, or overlapping OOS and forward windows
When the corpus is constructed
Then it fails with a stable reason and no assessment is returned.

### AC-7: Issuer derives champion identity (FR-9, FR-10)

Given a complete corpus bound to one sealed champion
When independent promotion evidence is issued
Then the signed receipt commit and model identities equal the verified champion
And the public issuer accepts no caller-supplied commit or model argument.

### AC-8: Signed v2 receipt binds all quality lineage (FR-10, FR-11)

Given a valid assessment and signed receipt
When its canonical signed payload and sealed validation result are inspected
Then they contain the exact champion archive, package, snapshot, tree, runtime
binding, quality-corpus, and bootstrap receipt identities.

### AC-9: Signature and binding tamper rejection (FR-10, FR-11, FR-15)

Given a signed v2 receipt
When any champion or quality identity is changed
Then signature verification fails and receipt validation is invalid.

### AC-10: Safety invariants (FR-12, FR-13, FR-14, NFR-6)

Given a complete champion-bound promotion corpus
When evaluation and issuance succeed
Then readiness still requires the manual ship gate
And all demo-auto, live, promotion, broker-mutation, and order capabilities
remain disabled at this boundary.

### AC-11: Regression gates (NFR-2, NFR-5)

Given the completed implementation
When focused normal/optimized tests and the complete project verification gates
run
Then every test and static check passes without weakening existing contracts.

## Edge Cases and Error Scenarios

- EC-1: Empty, non-bytes, oversized, malformed, or ZIP-tampered champion input
  → exact artifact verifier rejects it; no sealed observation exists.
- EC-2: An internal archive manifest is valid but one external pin differs →
  reject as external-pin mismatch.
- EC-3: Corpus model matches trades but not champion → reject as champion
  model mismatch.
- EC-4: Corpus configuration matches champion but one fold or parity report
  uses another configuration → reject as mixed lane.
- EC-5: Two trades share an ID across OOS and broker-forward partitions →
  reject as duplicate trade ID.
- EC-6: Timestamps are valid but trade tuple order is non-canonical → reject
  rather than silently reorder drawdown inputs.
- EC-7: Bootstrap input contains no trades → preserve the existing
  deterministic zero lower-bound behavior; readiness remains incomplete.
- EC-8: A receipt identity is mutated and re-signed by an untrusted key →
  configured key lookup or signature verification rejects it.

## API Contracts

This increment exposes Python contracts only. A hypothetical
`POST /promotion/champion-bound-evidence` endpoint is explicitly prohibited and
MUST NOT be implemented here.

```typescript
interface VerifiedChampionObservation {
  archiveSha256: LowerHex64;
  packageIdentitySha256: LowerHex64;
  modelArtifactSha256: LowerHex64;
  trainingSnapshotSha256: LowerHex64;
  configSha256: LowerHex64;
  gitCommit: LowerHex40;
  gitTree: LowerHex40;
  runtimeBindingSha256: LowerHex64;
  observationSha256: LowerHex64;
}

interface ChampionBoundPromotionCorpus {
  symbol: string;
  strategy: string;
  configSha256: LowerHex64;
  modelArtifactSha256: LowerHex64;
  champion: VerifiedChampionObservation;
  oosTrades: ClosedTradeObservation[];
  forwardTrades: ClosedTradeObservation[];
  rollingFolds: RollingFoldObservation[];
  parityReports: ParityObservation[];
  validationReceipt: ValidationReceiptObservation;
}

interface PromotionEvidenceReceiptV2 {
  schemaVersion: "promotion-evidence-v2";
  commitSha: LowerHex40;
  configSha256: LowerHex64;
  modelArtifactSha256: LowerHex64;
  championArchiveSha256: LowerHex64;
  championPackageIdentitySha256: LowerHex64;
  championTrainingSnapshotSha256: LowerHex64;
  championGitTree: LowerHex40;
  championRuntimeBindingSha256: LowerHex64;
  qualityCorpusSha256: LowerHex64;
  bootstrapReceiptSha256: LowerHex64;
  liveAllowed: false;
  safeToDemoAutoOrder: false;
  promotionEligible: false;
}
```

## Data Models

### Champion Artifact Observation

| Field | Type | Constraints |
|---|---|---|
| archive_sha256 | LowerHex64 | Exact independently pinned ZIP bytes |
| package_identity_sha256 | LowerHex64 | Verified internal package identity |
| model_artifact_sha256 | LowerHex64 | Verified rule-core source identity |
| training_snapshot_sha256 | LowerHex64 | Exact frozen snapshot identity |
| config_sha256 | LowerHex64 | Exact champion configuration identity |
| git_commit | LowerHex40 | Exact independently pinned source commit |
| git_tree | LowerHex40 | Exact independently pinned source tree |
| runtime_binding_sha256 | LowerHex64 | Verified runtime-model binding |
| observation_sha256 | LowerHex64 | Canonical identity of the fields above |

### Raw Quality Observations

Every trade, fold, and parity record contains exact `symbol`, `strategy`,
`config_sha256`, and `model_artifact_sha256`. Trade records additionally bind
source, canonical UTC close time, return before cost, and measured cost. Fold
and parity IDs are unique and canonically ordered.

### Independent Promotion Assessment

The assessment retains existing `LaneEvidence` and sealed `LaneReadiness`, and
adds the exact champion observation, `quality_corpus_sha256`, bootstrap receipt
identity, and parity identity. Its safety fields remain literal deny-only
values.

### Promotion Evidence Receipt v2

The v2 signed payload retains all v1 lane, broker, journal, readiness,
evidence-store, parity, build, expiry, signer, and nonce bindings. It adds the
exact champion and raw quality lineage fields defined in the API contract.

No database schema, broker configuration, credential store, service schedule,
or execution policy is changed.

## Out of Scope

- OS-1: Collecting new OOS or broker-forward observations; this feature only
  validates and binds supplied evidence.
- OS-2: Declaring the current four-trade diagnostic sample sufficient or
  promoting it to live-grade.
- OS-3: Champion/challenger selection policy, automated retraining, online
  learning, or self-promotion.
- OS-4: External registry upload, storage API inspection, signing-key custody,
  or human quality approval.
- OS-5: Manual-demo, DEMO_AUTO, or live activation; order dispatch and broker
  mutation remain prohibited.
- OS-6: Expanding runtime stage bindings to carry the full archive; the trusted
  signed receipt remains the audit carrier while execution continues to compare
  its existing commit, configuration, and model identities.
