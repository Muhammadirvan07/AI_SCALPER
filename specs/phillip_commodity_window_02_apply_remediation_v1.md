# Spec: Phillip Commodity Window 02 Apply Remediation V1

**Author:** AI_SCALPER Engineering

**Date:** 2026-08-05

**Status:** Approved for implementation

**Reviewer:** Project owner through the explicit
`LANJUTKAN REMEDIASI APPLY PHILLIP WINDOW 02` instruction

**Related specs:** `phillip_commodity_window_02_rollover_review_v1.md`,
`phillip_lane_evidence_contract.md`,
`phillip_commodity_v6_postrun_acceptance_v1.md`

## Context

The independently reviewed Window 02 rollover pack is valid and binds source
commit `c4f7b88b0b7b3de3833857170f6128ae5f199b27`, source tree
`b388a8c4d626db65669dc066f0346726a5434a0a`, proposal SHA-256
`c3f05b3ce882d41a8f6ece6a43d0c8fb072b804b1aedcc80fa75491c7552b72d`,
and physical file SHA-256
`63cf0a1013b4df52db4ec820c791da2f197e1955a5cbfc9506e628f6ee15e32e`.
It proposes exactly three replacements and one creation, while retaining all
execution, live, promotion, broker, scheduler, and order locks.

A direct trial apply proved that the four after-images are internally exact,
but exposed compatibility assumptions outside the pack. The bounded worker
accepts only the historical Window 01/V5 contract identifier, the dashboard
selects the Window 01 commodity calendar by filename, and several tests derive
historical Window 01 fixtures from whatever profile is currently tracked.
Those assumptions make an otherwise valid state transition fail the project
regression gate.

This remediation applies the four reviewed after-images and makes only the
minimal consumer and test-fixture changes necessary to treat Window 02 as the
active diagnostic profile. It does not register the proposed contract, start
or modify a scheduled task, connect to a broker, enable live trading, or place
an order. Runtime contract-artifact verification remains the authority that
must fail closed until a separately authorized Window 02 contract exists.

## Functional Requirements

- FR-1: The implementation MUST accept only the reviewed rollover pack whose
  physical file, proposal, source commit, source tree, four paths, operations,
  before hashes, and after hashes exactly match this specification.
- FR-2: The implementation MUST replace exactly
  `config/broker_candidates.phase3.json`,
  `config/broker_evidence_profiles.v1.json`, and
  `config/windows_release_allowlist.v1.json`, and MUST create exactly
  `config/phillip_commodity_calendar_window_02.template.json` from the pack's
  canonical proposed contents.
- FR-3: The resulting replacement hashes MUST be
  `a4e987969251106682263f2c10b8f5d25ce17a3a694cb86a0b31132a4970799d`,
  `547a34254163a1f61a33a60035899b8ac167aa3da6e4552f6bf6eadb34edb0be`,
  and `c865663d0356ae594ff92d41c9ed0381f21c0495a2a06b3f8148ef4f5b38c3cc`;
  the created template hash MUST be
  `756c111475aaa920a765e15620d136141997d4cec1a3e44b5b8b1907a6396c64`.
- FR-4: The active Phillip Commodity profile MUST bind snapshot
  `phillip-commodity-dev-pre-window-02-v1`, contract
  `phillip-commodity-window-02-diagnostic-v1`, signed Window 02 template, and
  status
  `DIAGNOSTIC_EVIDENCE_REGISTRATION_ROLLED_TO_WINDOW_02_BY_MANUAL_REVIEW`.
  Its existing discovery key and `registration_enabled=true` MUST remain
  unchanged.
- FR-5: The bounded worker MUST accept only the exact approved diagnostic
  contract identifiers `phillip-commodity-window-01-diagnostic-v5` and
  `phillip-commodity-window-02-diagnostic-v1` for `phillip-commodity`.
  Every other candidate or contract identifier MUST be rejected.
- FR-6: Accepting the Window 02 identifier MUST NOT bypass the tracked profile
  loader, registration-enabled check, contract directory lookup, manifest and
  signature verification, build identity verification, snapshot validation,
  or any later runtime safety gate.
- FR-7: The dashboard file registry MUST select
  `phillip_commodity_calendar_window_02.template.json` as the active Phillip
  Commodity calendar source.
- FR-8: Historical initial-activation and rollover-review tests MUST construct
  explicit Window 01 baseline fixtures rather than infer historical state from
  the active tracked Window 02 profile or release allowlist.
- FR-9: Current-state tests MUST assert the Window 02 contract, template, and
  rollover status, while frozen V5/V6 tests and artifacts MUST continue to
  assert their immutable Window 01 history.
- FR-10: Candidate, profile, template, and root safety values MUST retain
  `execution_enabled=false`, `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `promotion_eligible=false`, maximum lot
  `0.01`, and order capability `DISABLED`.
- FR-11: The remediation MUST NOT register a contract, create or mutate an
  evidence artifact, install/start/change a scheduled task, mutate MT5, contact
  a broker, submit an order, or export credential material.
- FR-12: Documentation MAY report the repository rollover as applied only
  after all required gates pass; it MUST distinguish repository readiness from
  Window 02 contract registration and Windows runtime acceptance.

## Non-Functional Requirements

- NFR-S1: Pack loading and hash comparison MUST be local, deterministic, and
  reject malformed JSON, duplicate keys, non-finite values, path drift,
  operation drift, source-identity drift, and any before/after hash mismatch.
- NFR-S2: The apply MUST begin from the exact clean source commit and MUST
  preserve unrelated user files and untracked dashboard directories.
- NFR-S3: Runtime allowlisting MUST use an immutable exact-value collection;
  prefix, suffix, substring, case-folded, or caller-supplied namespaces are
  prohibited.
- NFR-S4: All existing fail-closed evidence, contract, build identity,
  snapshot, dependency, and order locks MUST remain effective.
- NFR-R1: Focused tests, the complete suite in normal and optimized mode,
  compilation, release-inventory validation, diff checks, and safety scans
  MUST pass before commit or push.
- NFR-R2: A failed gate MUST leave the remediation uncommitted and unpushed.
- NFR-M1: Historical fixture helpers MUST state their historical purpose and
  set every Window 01 field needed by the old workflow explicitly.
- NFR-A1: Dashboard behavior MUST remain local-only and read-only; this change
  introduces no endpoint, CORS, network-listener, or command capability.
- NFR-C1: Each acceptance criterion and relevant edge case MUST be covered by
  an automated test or an exact content/hash gate.

## Acceptance Criteria

### AC-1: Exact reviewed after-images are applied (FR-1, FR-2, FR-3, FR-4)

Given the clean exact source commit and the approved rollover pack
When the repository apply runs
Then exactly the four declared configuration paths receive their proposed
canonical contents
And every resulting SHA-256 equals the reviewed after-image hash.

### AC-2: Window 02 becomes the active diagnostic profile (FR-4, FR-10)

Given the applied profile and signed template
When strict candidate, profile, and calendar loaders run
Then they resolve the Window 02 snapshot, contract, template, and rollover
status
And all live, execution, promotion, auto-order, and lot locks remain exact.

### AC-3: Worker namespace transition remains fail-closed (FR-5, FR-6)

Given a strictly loaded registered Phillip Commodity profile
When its contract is Window 01/V5 or Window 02/V1
Then the worker namespace validator returns that exact identifier
But given any other identifier or candidate it raises before dependency or
broker effects
And a missing or invalid Window 02 contract artifact still fails at the
existing contract verification boundary.

### AC-4: Dashboard follows the active calendar (FR-7)

Given a dashboard snapshot built from repository configuration
When Phillip Commodity calendar data is resolved
Then only the signed Window 02 template is selected as the active source
And no network or mutation capability is added.

### AC-5: Historical workflows remain reproducible (FR-8, FR-9)

Given initial-activation and rollover-review tests
When they build their inputs after the active repository moved to Window 02
Then they reconstruct the exact historical Window 01 baseline and still pass
And frozen V5/V6 artifacts and expectations remain byte-for-byte unchanged.

### AC-6: Current-state assertions are coherent (FR-9)

Given tracked broker profiles, calendars, registration state, and release
allowlist
When current-state validation tests run
Then every active Phillip Commodity assertion reports Window 02 consistently
And no active assertion requires the superseded Window 01 template.

### AC-7: No operational authority is introduced (FR-10, FR-11)

Given the complete diff and all runtime entry points
When safety scans inspect order, live, broker, scheduler, and contract actions
Then no contract registration, scheduler mutation, broker mutation, or order
submission is performed
And order capability remains `DISABLED`.

### AC-8: Full regression and release gates pass (FR-12, NFR-R1, NFR-R2)

Given the complete remediation
When focused tests, complete normal and optimized suites, compilation,
release inventory, diff checks, and safety scans run
Then every required gate passes
And only then may the verified changes be committed and pushed.

## Edge Cases and Error Scenarios

- EC-1: Pack physical hash, proposal hash, source commit/tree, path set,
  operation, or content hash differs -> reject without applying.
- EC-2: A replacement before hash differs or the signed template already
  exists -> reject rather than merge or overwrite ambiguous state.
- EC-3: Git status contains unrelated tracked changes -> do not apply, stage,
  commit, or push over them.
- EC-4: Worker profile names another candidate -> reject before runtime work.
- EC-5: Worker profile uses a prefix/suffix variant or an unapproved Window 02
  revision -> reject exactly.
- EC-6: Window 02 identifier is approved but its contract directory,
  signature, manifest, snapshot, or build identity is absent/invalid -> the
  existing runtime contract gate rejects and no broker effect occurs.
- EC-7: Dashboard Window 02 file is absent or malformed -> existing registry
  and snapshot warnings apply; it MUST NOT silently read Window 01 as active.
- EC-8: Historical tests accidentally read active Window 02 state -> fixture
  construction must fail its explicit Window 01 assertions.
- EC-9: Any frozen V5/V6 source, package, receipt, runbook contract claim, or
  test expectation changes -> reject the remediation diff.
- EC-10: Any safety boolean, maximum lot, order capability, or registration
  enabled value drifts outside the reviewed after-image -> reject.
- EC-11: Any required gate fails -> leave changes local and report the exact
  failure; do not claim completion or push.

## API Contracts

No network API is added or changed. In particular,
`POST /local-only/phillip-commodity/window-02/apply` MUST NOT exist; the path
is notation for a prohibited capability, not an implemented endpoint. The only
new internal contract is an exact worker namespace validator:

```typescript
type PhillipCommodityWorkerContract =
  | "phillip-commodity-window-01-diagnostic-v5"
  | "phillip-commodity-window-02-diagnostic-v1";

function validateWorkerContractId(
  candidateId: "phillip-commodity",
  contractId: string,
): PhillipCommodityWorkerContract;
```

The function raises `RuntimeError` for any candidate or identifier outside the
two-value set. `_worker_contract_id` MUST call it only after the existing
strict tracked profile load with `require_registration_enabled=true`.

The dashboard registry contract changes one value only:

```typescript
interface ActiveCalendarSources {
  phillip_commodity_calendar:
    "phillip_commodity_calendar_window_02.template.json";
}
```

## Data Models

### Reviewed apply identity

| Field | Required value |
|---|---|
| source commit | `c4f7b88b0b7b3de3833857170f6128ae5f199b27` |
| source tree | `b388a8c4d626db65669dc066f0346726a5434a0a` |
| physical pack SHA-256 | `63cf0a1013b4df52db4ec820c791da2f197e1955a5cbfc9506e628f6ee15e32e` |
| proposal SHA-256 | `c3f05b3ce882d41a8f6ece6a43d0c8fb072b804b1aedcc80fa75491c7552b72d` |
| proposed file count | `4` |
| contract registration | `NOT_PERFORMED` |
| scheduler mutation | `NOT_PERFORMED` |
| broker mutation | `NOT_PERFORMED` |
| order capability | `DISABLED` |

### Active Phillip Commodity profile

| Field | Window 02 value | Constraint |
|---|---|---|
| key name | `phillip-commodity-window-01-v1` | preserved discovery identity |
| snapshot ID | `phillip-commodity-dev-pre-window-02-v1` | exact |
| contract ID | `phillip-commodity-window-02-diagnostic-v1` | exact |
| template path | `config/phillip_commodity_calendar_window_02.template.json` | exact |
| registration enabled | `true` | unchanged |
| status | `DIAGNOSTIC_EVIDENCE_REGISTRATION_ROLLED_TO_WINDOW_02_BY_MANUAL_REVIEW` | exact |

### Historical Window 01 fixture

| Field | Historical value |
|---|---|
| snapshot ID | `phillip-commodity-dev-pre-window-01-v1` |
| contract ID | `phillip-commodity-window-01-diagnostic-v5` |
| template path | `config/phillip_commodity_calendar_window_01.template.json` |
| pre-activation registration | `false` |
| pre-activation status | `BLOCKED_PENDING_SIGNED_REGULATORY_CALENDAR_AND_REGISTRATION_REVIEW` |

## Dependencies

- The verified Window 02 rollover pack and its static verifier.
- Existing strict broker profile, calendar, contract, snapshot, signature, and
  build-identity validators.
- Existing local dashboard file registry and snapshot builder.
- Existing ordinary Windows release allowlist and reproducible release tests.
- CPython 3.12 test environments used by the normal and optimized gates.

## Out of Scope

- OS-1: Registering or signing the Window 02 forward contract or creating its
  evidence directory.
- OS-2: Starting, installing, repairing, or changing a Windows scheduled task
  or acceptance run.
- OS-3: Connecting to MT5, collecting broker evidence, mutating a broker, or
  submitting an order.
- OS-4: Enabling live trading, demo auto-ordering, promotion, credentials, or
  increasing the maximum lot.
- OS-5: Re-signing calendar/regulatory/discovery evidence or changing reviewer
  identity and key custody.
- OS-6: Rewriting, deleting, or reclassifying frozen Window 01/V5/V6 evidence,
  packages, receipts, or historical runbooks.
- OS-7: Adding an automatic apply command, remote endpoint, generalized
  contract namespace, or caller-controlled allowlist.
