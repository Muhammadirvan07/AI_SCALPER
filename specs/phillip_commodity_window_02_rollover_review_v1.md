# Spec: Phillip Commodity Window 02 Rollover Review Pack V1

**Author:** AI_SCALPER Engineering

**Date:** 2026-08-04

**Status:** Approved for implementation

**Reviewer:** Project owner through the explicit `lanjutkan` request; approval
to apply the proposed after-images, register a contract, install a task, or
enable order execution remains unissued

**Related specs:** `broker_registration_activation_review_pack.md`,
`broker_registration_review_gate.md`, `signed_prewindow_calendar_review.md`,
`phillip_lane_evidence_contract.md`

## Context

The active Phillip Commodity diagnostic profile is bound to the failed,
immutable Window 01/V5 evidence line. Its registration flag is already true,
but order execution, live use, promotion, and demo-auto ordering remain
disabled. The failed V5 contract and V6 scheduler evidence cannot be resumed
because the observation append deadline has passed.

Window 02 now has a review-only schema-v2 calendar template, a signed
pre-window calendar review, and a fresh regulatory observation with distinct
Compliance and Legal reviewers. The next repository change is sensitive: it
must preserve the existing discovery-v3 signing identity, replace only the
selected candidate's regulatory observation, bind the active profile to new
Window 02 snapshot and contract identifiers, and create a signed Window 02
template without altering the review-only source template.

This feature produces a deterministic, content-addressed rollover-review
pack containing the exact bounded after-images. It has no apply path, writes
no tracked file, registers no contract, changes no scheduler, and performs no
broker operation. A later explicit review and clean commit are required before
any after-image can become active.

## Functional Requirements

- FR-1: The system MUST build a rollover-review pack only for
  `phillip-commodity` from a clean tracked Git commit.
- FR-2: The current profile MUST exactly represent the reviewed Window 01
  baseline: key `phillip-commodity-window-01-v1`, snapshot
  `phillip-commodity-dev-pre-window-01-v1`, contract
  `phillip-commodity-window-01-diagnostic-v5`, template
  `config/phillip_commodity_calendar_window_01.template.json`, registration
  enabled, and the existing manual-review registration status.
- FR-3: The system MUST verify the exact HMAC-signed discovery-v3 receipt with
  the unchanged Window 01 evidence key and bind candidate, legal entity,
  server, DEMO environment, XAUUSD symbol, and `XAUUSD.ps01` broker symbol.
- FR-4: The system MUST verify the fresh regulatory observation against the
  exact Window 02 review-only template with exactly one Compliance and one
  Legal approval, candidate-scoped keys, and distinct human reviewer IDs
  compared case-insensitively.
- FR-5: The system MUST verify the signed pre-window calendar review against
  the exact Window 02 review-only template and candidate-scoped calendar key.
- FR-6: The proposed candidate config MAY replace only the selected
  candidate's `regulatory_observation`; all other candidate and root values
  MUST remain semantically identical.
- FR-7: The proposed profile config MAY change only the selected profile's
  snapshot ID to `phillip-commodity-dev-pre-window-02-v1`, contract ID to
  `phillip-commodity-window-02-diagnostic-v1`, template path to
  `config/phillip_commodity_calendar_window_02.template.json`, and status to
  `DIAGNOSTIC_EVIDENCE_REGISTRATION_ROLLED_TO_WINDOW_02_BY_MANUAL_REVIEW`.
  The key name and `registration_enabled=true` MUST remain unchanged.
- FR-8: The proposed signed template MUST be a new file at
  `config/phillip_commodity_calendar_window_02.template.json`. It MAY differ
  from the review-only schema-v2 template only by changing the schema to v3
  and embedding the exact verified `prewindow_calendar_review`.
- FR-9: The review-only template at
  `config/phillip_commodity_calendar_window_02.review-template.json` MUST
  remain unchanged and the signed-template destination MUST not already exist.
- FR-10: Candidate and profile root safety locks MUST remain false for
  execution, credentials, live use, and demo-auto ordering, with maximum lot
  `0.01`. The proposed signed template MUST retain the same safety locks.
- FR-11: The pack MUST bind clean Git commit/tree identity, current and
  proposed profile identifiers, discovery hash, old and new regulatory hashes,
  calendar-review hash and artifact ID, review-template hash/content, and
  exact before/after canonical SHA-256 values for every proposed file.
- FR-12: Each of exactly four proposed files MUST explicitly declare `REPLACE`
  or `CREATE`.
  Replacement entries MUST carry exact base content and before hash; the new
  signed template MUST carry null base content and null before hash.
- FR-13: The pack MUST state `configuration_mutated=false`,
  `registration_enabled=true`, `manual_rollover_required=true`,
  `apply_capability=DISABLED`, `contract_registration=NOT_PERFORMED`,
  `scheduler_mutation=NOT_PERFORMED`, `broker_mutation=NOT_PERFORMED`,
  `order_capability=DISABLED`, `execution_enabled=false`,
  `live_allowed=false`, `safe_to_demo_auto_order=false`,
  `promotion_eligible=false`, and `max_lot=0.01`.
- FR-14: The system MUST write the pack create-exclusively outside the
  repository and MUST NOT expose an apply, patch, commit, contract
  registration, task installation, order, or activation entry point.
- FR-15: A static verifier MUST recompute all hashes and exact structural
  deltas, reject path/operation/content/safety/lane drift, and require no
  secret material.
- FR-16: Credentials MUST be loaded only from Windows Credential Manager by
  candidate-scoped key name; no CLI may accept, print, or export raw key bytes.
- FR-17: The prepare and static-verify tools and their runtime module MUST be
  included in the ordinary Windows release allowlist and covered by its exact
  release-inventory tests, without changing release safety policy. The
  proposed release allowlist after-image MAY add only the new signed Window 02
  template path so a future release cannot omit the active template.
- FR-18: Existing Window 01/V5 files, failed V6 evidence, initial activation
  tooling, other broker profiles, and all order/live locks MUST remain backward
  compatible and unchanged.

## Non-Functional Requirements

- NFR-S1: JSON readers MUST reject duplicate keys, non-finite values, unknown
  fields, malformed UTF-8, symlinks, and directories.
- NFR-S2: The CLI MUST capture Git status, commit, and tree twice; the worktree
  MUST be clean and stable for the complete preparation interval.
- NFR-S3: Cryptographic discovery, regulatory, and calendar verification MUST
  complete before any pack is returned or written.
- NFR-S4: Discovery, Compliance, Legal, and calendar keys MUST be four distinct
  secrets of at least 32 bytes; Compliance and Legal reviewer identities MUST
  be distinct humans, and every reviewer identity MUST reject operator-control
  tokens.
- NFR-S5: Proposed after-images MUST be computed internally from verified
  inputs; callers cannot supply arbitrary after-images.
- NFR-S6: Static verification MUST validate all nested field sets, hashes,
  operations, exact paths, immutable deltas, and safety constants.
- NFR-S7: Output resolution MUST reject repository-contained paths, existing
  files, symlink destinations, and overwrite attempts.
- NFR-R1: Canonical hashes and proposal content MUST be deterministic for
  identical inputs, Git identity, and trusted UTC time on CPython 3.12.
- NFR-R2: The feature MUST perform no network call, broker mutation,
  repository write, contract registration, scheduler mutation, credential
  export, or subprocess other than read-only Git identity commands.
- NFR-A1: CLI output MUST show candidate, proposal hash, source commit,
  current/proposed contract IDs, manual rollover required, configuration
  mutated false, contract registration not performed, scheduler mutation not
  performed, and order capability disabled.
- NFR-A2: CLI arguments MUST NOT expose password, login, account, order, lot,
  live, apply, patch, commit, contract-registration, task-installation,
  signing-key, raw-secret, or key-export controls.
- NFR-C1: Every acceptance criterion and edge case MUST have automated
  coverage, and focused tests, the full project suite in normal and optimized
  mode, release policy, compilation, diff checks, and safety scans MUST pass.

## Acceptance Criteria

### AC-1: Valid Window 02 inputs produce an immutable review pack (FR-1..FR-5, FR-11)

Given the exact active Window 01 baseline, clean Git identity, signed
discovery-v3 receipt, fresh Window 02 regulatory observation, signed Window 02
calendar review, and four matching distinct Credential Manager keys
When the preparation command runs
Then it verifies every signature and lane binding
And writes one deterministic rollover-review pack with exact proposed images.

### AC-2: Existing registration and discovery identity are preserved (FR-2, FR-7)

Given a valid rollover proposal
When the proposed profile is compared with the active profile
Then the evidence key remains `phillip-commodity-window-01-v1`
And registration remains enabled
And only snapshot, contract, template path, and rollover status change.

### AC-3: Signed template is a bounded new file (FR-8, FR-9, FR-12)

Given a valid Window 02 review-only template and calendar review
When the proposed signed template is inspected
Then its operation is `CREATE` with null before image and hash
And only the schema-v3 transition and exact review embedding differ
And the review-only template remains unchanged
And the proposed Windows release allowlist adds only the signed template path.

### AC-4: Candidate proposal is narrowly bounded (FR-6, FR-10)

Given a valid fresh regulatory observation
When the proposed candidate config is compared with the base
Then only `phillip-commodity.regulatory_observation` changes
And every root lock, other candidate, account restriction, and symbol binding
is identical.

### AC-5: Stale or substituted discovery fails closed (FR-3, NFR-S3)

Given a discovery receipt with a wrong HMAC, key, candidate, company, server,
environment, symbol set, broker symbol, or read-only lock
When pack preparation runs
Then no pack or tracked mutation is produced.

### AC-6: Review substitution fails closed (FR-4, FR-5, NFR-S3, NFR-S4)

Given missing, stale, forged, wrong-key, duplicate-reviewer,
operator-token-reviewer, cross-lane, template-drifted, or schedule-drifted
regulatory or calendar evidence
When pack preparation runs
Then verification fails before any proposal or write occurs.

### AC-7: Unsafe or ambiguous baseline is rejected (FR-1, FR-2, FR-9, FR-10)

Given a dirty or changing Git identity, duplicate candidate/profile,
unexpected Window 01 identifier, disabled registration, existing signed
Window 02 destination, malformed template, or unsafe root lock
When preparation runs
Then it fails closed with no output.

### AC-8: Static verifier detects tampering (FR-12, FR-13, FR-15)

Given a pack whose path, operation, before/after image, hash, profile key,
Window ID, review-template binding, safety flag, mutation claim, or proposal
hash is changed
When static verification runs
Then it is rejected without loading any secret.

### AC-9: Output is external, immutable, and non-applying (FR-13, FR-14)

Given valid inputs and an external unused output path
When preparation succeeds
Then tracked repository bytes are unchanged and one pack is written
And an inside-repository, existing, or symlink destination is rejected
And no contract, scheduler, broker, or order mutation occurs.

### AC-10: CLI and release remain fail-closed (FR-14, FR-16, FR-17)

Given command help, success/failure output, and a built Windows release
When inspected
Then no mutation or raw-secret controls exist
And the tools are present in the exact release inventory
And every output states the disabled mutation and order capabilities.

### AC-11: Legacy and full safety regression gate (FR-18, NFR-C1)

Given the complete repository plus this feature
When focused tests, normal and optimized full tests, release builders,
compilation, diff checks, and safety scans run
Then all pass with Window 01/V5 history and global safety locks unchanged.

## Edge Cases and Error Scenarios

- EC-1: Git status is dirty, identity is malformed, or commit/tree changes → reject.
- EC-2: Candidate/profile occurs zero or multiple times → reject.
- EC-3: Current key, snapshot, contract, template, status, or enabled flag differs from the exact Window 01 baseline → reject.
- EC-4: Window 02 signed destination already exists or is a symlink → reject.
- EC-5: Review-only template is not exact schema v2, contains an embedded review, or has the wrong window/time/symbol/safety binding → reject.
- EC-6: Discovery is not v3, is signed by another key, contains raw account fields, or binds another lane → reject.
- EC-7: Regulatory approvals are stale, non-independent, wrong-keyed, operator-token identities, or bound to a different template → reject.
- EC-8: Calendar approval is stale, wrong-keyed, or its schedule/source/window claim differs → reject.
- EC-9: Any two of the four credential secrets are equal → reject.
- EC-10: Candidate proposal changes a root field, another candidate, or any selected field beyond regulatory observation → reject.
- EC-11: Profile proposal changes key name, enabled flag, roots, another profile, or a field beyond the four permitted values → reject.
- EC-12: Signed-template proposal changes schedule, symbols, amendment policy, special-hours claim, or safety lock → reject.
- EC-13: Proposed file count, path, operation, nullability, field set, release-allowlist delta, or canonical hash differs → reject.
- EC-14: Input or output is malformed JSON, duplicate-key JSON, NaN/infinity, symlink, directory, inside-repository, or pre-existing → reject.
- EC-15: A valid review pack is mistaken for applied configuration → mutation fields remain disabled/not performed and no apply API exists.
- EC-16: Initial activation, another broker lane, old V5 contract, or stale V6 scheduler is supplied as Window 02 authority → reject.

## API Contracts

No network endpoint or apply API is introduced. For notation only, the local
port resembles `POST /local-review/phillip-commodity/window-02-rollover`.

```typescript
interface PhillipCommodityWindow02RolloverReview {
  schemaVersion: "phillip-commodity-window-02-rollover-review-v1";
  candidateId: "phillip-commodity";
  generatedAtUtc: UTCInstant;
  sourceGitCommit: GitObjectId;
  sourceGitTree: GitObjectId;
  discoveryKeyName: "phillip-commodity-window-01-v1";
  currentSnapshotId: "phillip-commodity-dev-pre-window-01-v1";
  proposedSnapshotId: "phillip-commodity-dev-pre-window-02-v1";
  currentContractId: "phillip-commodity-window-01-diagnostic-v5";
  proposedContractId: "phillip-commodity-window-02-diagnostic-v1";
  discoveryReceiptSha256: SHA256;
  currentRegulatoryObservationSha256: SHA256;
  proposedRegulatoryObservationSha256: SHA256;
  prewindowCalendarReviewSha256: SHA256;
  calendarReviewArtifactSha256: SHA256;
  reviewTemplatePath: "config/phillip_commodity_calendar_window_02.review-template.json";
  reviewTemplateSha256: SHA256;
  reviewTemplateContent: JSONObject;
  proposedFiles: [
    ProposedReplacement,
    ProposedReplacement,
    ProposedReplacement,
    ProposedCreation
  ];
  configurationMutated: false;
  registrationEnabled: true;
  manualRolloverRequired: true;
  applyCapability: "DISABLED";
  contractRegistration: "NOT_PERFORMED";
  schedulerMutation: "NOT_PERFORMED";
  brokerMutation: "NOT_PERFORMED";
  orderCapability: "DISABLED";
  executionEnabled: false;
  liveAllowed: false;
  safeToDemoAutoOrder: false;
  promotionEligible: false;
  maxLot: 0.01;
  proposalSha256: SHA256;
}

interface ProposedReplacement {
  path: "config/broker_candidates.phase3.json"
      | "config/broker_evidence_profiles.v1.json"
      | "config/windows_release_allowlist.v1.json";
  operation: "REPLACE";
  beforeSha256: SHA256;
  afterSha256: SHA256;
  baseContent: JSONObject;
  proposedContent: JSONObject;
}

interface ProposedCreation {
  path: "config/phillip_commodity_calendar_window_02.template.json";
  operation: "CREATE";
  beforeSha256: null;
  afterSha256: SHA256;
  baseContent: null;
  proposedContent: JSONObject;
}
```

## Data Models

### Exact profile rollover

| Field | Current | Proposed | Constraint |
|---|---|---|---|
| evidence key | Window 01 | Window 01 | MUST remain unchanged |
| snapshot | Window 01 | Window 02 | Exact identifier only |
| contract | Window 01 V5 | Window 02 V1 | Exact identifier only |
| template | signed Window 01 | signed Window 02 | Exact path only |
| registration | true | true | No enable/disable transition |
| status | initial manual review | Window 02 rollover review | Exact status only |

### Proposed tracked file

| Field | Type | Constraint |
|---|---|---|
| path | repository-relative enum | Exactly candidate, profile, release allowlist, or new signed template |
| operation | enum | `REPLACE` for existing config, `CREATE` for signed template |
| before hash/content | SHA-256/object or null | Required for replace; null for create |
| after hash/content | SHA-256/object | Canonical exact proposed image |

## Dependencies

- Existing strict broker candidate/profile/template loaders and canonical JSON hashing.
- Existing discovery-v3 verifier and candidate evidence key in Windows Credential Manager.
- Existing regulatory observation assembler/verifier and Compliance/Legal keys.
- Existing pre-window calendar review verifier and calendar-review key.
- Existing ordinary Windows release builder and release inventory policy.
- Read-only local Git commands for stable commit/tree identity.

## Out of Scope

- OS-1: Applying after-images, editing tracked config, creating or pushing the
  rollover commit, or declaring project-owner rollover approval.
- OS-2: Registering the Window 02 contract, freezing a snapshot, installing or
  enabling a scheduler, running a worker, or collecting acceptance evidence.
- OS-3: Re-signing discovery, changing key custody, issuing reviewer approval,
  downloading sources, or deciding legal/calendar meaning.
- OS-4: Any broker mutation, order submission, demo-auto/live trading,
  promotion, lot increase, or removal of an existing safety lock.
- OS-5: Modifying, deleting, or treating failed V5/V6 artifacts as valid
  acceptance evidence.
