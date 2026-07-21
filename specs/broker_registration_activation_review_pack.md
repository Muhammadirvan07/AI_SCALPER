# Spec: Broker Registration Activation Review Pack

**Author:** AI_SCALPER Engineering

**Date:** 2026-07-21

**Status:** Approved for implementation

**Reviewer:** Project owner through the autonomous implementation request;
manual activation approval remains unissued

**Related specs:** `broker_registration_review_gate.md`,
`signed_prewindow_calendar_review.md`, `phillip_lane_evidence_contract.md`

## Context

AI_SCALPER can prepare and independently verify byte-derived regulatory
evidence, two regulatory approvals, one pre-window calendar review, and one
signed MT5 discovery-v3 receipt. The tracked Phillip candidate, calendar
template, and evidence profile correctly remain inactive. The next repository
change would be security-sensitive because it must insert the exact regulatory
observation, embed the exact calendar review in template schema v3, and enable
only the matching diagnostic registration profile.

Those inputs are currently reviewed independently, but there is no single
immutable package proving that they were simultaneously valid against the same
clean commit and showing the exact bounded configuration changes for a human
reviewer. Manual copy/paste would make lane substitution, stale review,
discovery drift, and unrelated-config changes unnecessarily difficult to
detect.

This feature creates a deterministic, content-addressed activation-review pack.
It fully verifies every prerequisite and contains exact proposed after-images
for the three tracked configuration files. It has no apply command, never
writes a tracked file, and does not constitute activation approval. Only a
later explicit human-reviewed clean commit may apply the proposed changes.

## Functional Requirements

- FR-1: The system MUST build one activation-review pack for exactly one
  disabled broker evidence profile from a clean tracked Git commit.
- FR-2: The pack MUST verify the exact HMAC-signed discovery-v3 receipt with
  the candidate evidence key and bind candidate, legal entity, server,
  environment, required symbol set, and canonical-to-broker symbol map.
- FR-3: The pack MUST verify the assembled regulatory observation with exactly
  two independent regulatory-review keys against a proposed candidate config.
- FR-4: The pack MUST verify the assembled pre-window calendar review with the
  candidate-scoped calendar-review key against the exact current schema-v2
  template and proposed schema-v3 template.
- FR-5: The current candidate config MUST retain `execution_enabled=false` and
  `credentials_allowed=false`; the current profile root MUST retain all order,
  live, demo-auto, and lot locks; and the selected profile MUST still have
  `registration_enabled=false`.
- FR-6: The proposed candidate config MAY replace only the selected
  candidate's `regulatory_observation`; every other candidate and root field
  MUST remain byte-semantically unchanged.
- FR-7: The proposed template MAY change only `schema_version` from v2 to v3
  and add the exact verified `prewindow_calendar_review`; its schedule,
  symbols, safety locks, amendment policy, and special-hours claim MUST remain
  unchanged.
- FR-8: The proposed profile config MAY change only the selected profile's
  `registration_enabled` to true and its status to the exact reviewed
  diagnostic-registration status; all profile root locks and other profiles
  MUST remain unchanged.
- FR-9: The pack MUST bind clean Git commit/tree identity, exact before/after
  SHA-256 values for all three tracked files, discovery hash, regulatory hash,
  calendar-review hash, candidate ID, generated-at UTC, and the full proposed
  base and proposed after-images.
- FR-10: The pack MUST state `configuration_mutated=false`,
  `registration_enabled=false`, `manual_activation_required=true`,
  `apply_capability=DISABLED`, `order_capability=DISABLED`,
  `execution_enabled=false`, `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `promotion_eligible=false`, and
  `max_lot=0.01`.
- FR-11: The system MUST write the pack create-exclusively outside the
  repository and MUST NOT provide an apply, patch, commit, order, or activation
  entry point.
- FR-12: The pack verifier MUST reject content, hash, path, safety, lane, or
  proposed-change drift without requiring access to secret material.
- FR-13: Every credential MUST be loaded from Windows Credential Manager by
  candidate-scoped key name; no CLI may accept, print, or export raw key bytes.
- FR-14: Phillip FX and commodity packs MUST remain independent, and a valid
  artifact from one lane MUST never satisfy the other lane.
- FR-15: Existing v1/v2 plan, calendar, discovery, and disabled-profile
  behavior MUST remain backward compatible.

## Non-Functional Requirements

- NFR-S1: JSON readers MUST reject duplicate keys, non-finite values, unknown
  fields, symlinks, directories, and malformed UTF-8.
- NFR-S2: Source Git identity MUST be clean and bind lowercase commit and tree
  object IDs; caller-provided `clean=true` alone is insufficient in the CLI.
- NFR-S3: Full regulatory, calendar, and discovery cryptographic verification
  MUST occur before a proposal is returned.
- NFR-S4: The exact proposed changes MUST be recomputed and structurally
  constrained; a caller cannot supply arbitrary after-images.
- NFR-S5: Output paths MUST resolve outside the repository and existing or
  symlink destinations MUST never be overwritten.
- NFR-R1: Canonical JSON SHA-256 values MUST be deterministic for identical
  inputs and trusted UTC providers on CPython 3.12.
- NFR-R2: The feature MUST perform no network call, broker mutation, repository
  write, credential export, or subprocess other than read-only Git identity
  commands.
- NFR-A1: CLI output MUST show candidate, proposal hash, source commit, manual
  review required, configuration mutated false, and order capability disabled.
- NFR-A2: CLI arguments MUST NOT expose password, login, account, order, lot,
  live, apply, patch, commit, signing-key, raw-secret, or key-export controls.
- NFR-C1: Every acceptance criterion and edge case MUST have automated
  coverage, and the full project, release-policy, compilation, and safety scans
  MUST pass.

## Acceptance Criteria

### AC-1: Valid lane creates an immutable review pack (FR-1..FR-4, FR-9)

Given a clean commit, matching disabled profile, signed discovery-v3 receipt,
assembled regulatory observation, assembled calendar review, and all matching
Credential Manager keys
When the preparation command runs
Then it verifies every signature and exact lane binding
And writes one deterministic activation-review pack with exact proposed
after-images and before/after hashes.

### AC-2: Repository remains unchanged (FR-5, FR-6, FR-7, FR-8, FR-10, FR-11)

Given a valid pack preparation
When before and after bytes of all tracked configuration files are compared
Then they are identical
And the pack says configuration mutated false, actual registration false,
manual activation required, apply disabled, and order capability disabled.

### AC-3: Discovery substitution fails closed (FR-2, NFR-S3)

Given a discovery receipt with a wrong HMAC, candidate, company, server,
symbol set, broker symbol, environment, or read-only lock
When pack preparation runs
Then no pack is produced and registration remains disabled.

### AC-4: Review substitution fails closed (FR-3, FR-4, FR-14)

Given a missing, stale, forged, wrong-key, cross-lane, or schedule-drifted
regulatory or calendar review
When pack preparation runs
Then verification fails before any proposal or tracked write occurs.

### AC-5: Dirty or ambiguous base is rejected (FR-1, NFR-S1, NFR-S2)

Given a dirty Git worktree, duplicate candidate/profile, malformed config,
already-enabled profile, non-v2 template, or unsafe root lock
When preparation runs
Then it fails closed with no output.

### AC-6: Proposed diff is narrowly bounded (FR-6, FR-7, FR-8, NFR-S4)

Given a valid pack
When the proposed after-images are compared with their base images
Then only the exact selected regulatory observation, v3 calendar-review
embedding, and selected diagnostic registration fields differ
And every other semantic value is identical.

### AC-7: Static verifier detects tampering (FR-10, FR-12)

Given a pack whose proposed content, file path, before/after hash, safety lock,
manual-review flag, or proposal hash is changed
When static verification runs
Then the pack is rejected without loading any secret.

### AC-8: Output is immutable and external (FR-11, NFR-S5)

Given an output inside the repository, an existing output, or a symlink target
When the CLI attempts to write
Then it fails and leaves tracked files unchanged.

### AC-9: CLI has no activation capability (FR-11, FR-13, NFR-A1, NFR-A2)

Given command help and success/failure paths
When they are inspected
Then no apply/order/credential mutation option exists
And output clearly states that manual review is required and order capability
is disabled.

### AC-10: Legacy behavior and safety regression gate (FR-15, NFR-C1)

Given the complete existing project plus this feature
When focused tests, full tests, release checks, compilation, diff checks, and
safety scans run
Then all pass with tracked registration/order/live locks unchanged.

## Edge Cases and Error Scenarios

- EC-1: Git identity is dirty, missing, malformed, or changes between reads → reject.
- EC-2: Candidate/profile/template appears zero or multiple times → reject.
- EC-3: Profile is already enabled or any root execution/live/demo-auto/lot lock drifts → reject.
- EC-4: Candidate credentials become allowed or candidate execution becomes enabled → reject.
- EC-5: Discovery receipt is v1/v2, has a wrong key, contains raw account data, or does not bind the exact lane → reject.
- EC-6: Regulatory approvals are stale, non-independent, wrong-keyed, or bind another template/candidate → reject.
- EC-7: Calendar approval is stale, wrong-keyed, or its schedule/window/source claim differs → reject.
- EC-8: Current template is not schema v2 or already contains a pre-window review → reject.
- EC-9: Proposed template changes schedule, symbols, special-hours claim, amendment policy, or a safety lock → reject.
- EC-10: Proposed candidate replacement changes any field other than the selected regulatory observation → reject.
- EC-11: Proposed profile changes another profile/root or any field beyond selected registration/status → reject.
- EC-12: Any artifact has duplicate keys, unknown fields, NaN/infinity, symlink input, or invalid UTC → reject.
- EC-13: Output is inside the Git repository, already exists, is a symlink, or cannot be durably written → reject.
- EC-14: Pack is valid for one Phillip lane only → the other lane remains disabled and independently blocked.
- EC-15: A valid pack is mistaken for approval → top-level actual registration remains false and no apply API exists.

## API Contracts

No network endpoint or apply API is introduced. For notation only, the local
port resembles `POST /local-review/broker-registration-activation-proposal`.

```typescript
interface ActivationReviewPack {
  schemaVersion: "broker-registration-activation-review-v1";
  candidateId: string;
  generatedAtUtc: UTCInstant;
  sourceGitCommit: GitObjectId;
  sourceGitTree: GitObjectId;
  discoveryReceiptSha256: SHA256;
  regulatoryObservationSha256: SHA256;
  prewindowCalendarReviewSha256: SHA256;
  proposedFiles: [ProposedFile, ProposedFile, ProposedFile];
  configurationMutated: false;
  registrationEnabled: false;
  manualActivationRequired: true;
  applyCapability: "DISABLED";
  orderCapability: "DISABLED";
  executionEnabled: false;
  liveAllowed: false;
  safeToDemoAutoOrder: false;
  promotionEligible: false;
  maxLot: 0.01;
  proposalSha256: SHA256;
}

interface ProposedFile {
  path: "config/broker_candidates.phase3.json"
      | "config/broker_evidence_profiles.v1.json"
      | "config/phillip_fx_calendar_window_01.template.json"
      | "config/phillip_commodity_calendar_window_01.template.json";
  beforeSha256: SHA256;
  afterSha256: SHA256;
  baseContent: JSONObject;
  proposedContent: JSONObject;
}
```

## Data Models

### Verified prerequisite binding

| Field | Type | Constraint |
|---|---|---|
| candidate ID | string | Exact profile/template/discovery/review lane |
| discovery hash | SHA-256 | Signed v3 receipt, exact evidence key |
| regulatory hash | SHA-256 | Two independent reviewer HMACs |
| calendar review hash | SHA-256 | Candidate calendar-review HMAC |
| Git commit/tree | object IDs | Clean source identity |

### Proposed tracked file

| Field | Type | Constraint |
|---|---|---|
| path | repository-relative enum | Exactly one candidate, profile, and template file |
| before hash | SHA-256 | Canonical current content |
| after hash | SHA-256 | Canonical proposed content |
| base content | object | Exact current image for offline bounded-diff verification |
| proposed content | object | Recomputed internally; never caller supplied |

## Out of Scope

- OS-1: Applying the proposed files, editing tracked config, creating the
  approval commit, pushing an activation, or enabling registration.
- OS-2: Issuing compliance, legal, calendar, project-owner, promotion, demo,
  or live approval.
- OS-3: Creating a discovery receipt, downloading official documents, or
  deciding legal/calendar meaning.
- OS-4: Broker data collection, order submission, demo-auto, live trading,
  promotion, lot changes, or scaling.
- OS-5: Replacing external key custody, clean Windows host validation, Object
  Lock/WORM, 20-session benchmark, eight-week evidence, or manual ship gate.
