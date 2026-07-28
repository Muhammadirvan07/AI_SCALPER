# Spec: Windows XM and FINEX Preparation Operator Packages V1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-26
**Status:** Approved
**Reviewers:** AI_SCALPER project owner, security, ship-gate
**Approval basis:** Project owner request on 2026-07-26 to prepare XM and
FINEX in addition to the existing Phillip lane.
**Related specs:** `specs/phillip_lane_evidence_contract.md`,
`specs/broker_registration_review_gate.md`,
`specs/create_exclusive_output_custody_v1.md`

## Context

AI_SCALPER already has technical XM Window 02 code and partial FINEX broker
facts, but neither candidate may be activated from the current Japan operating
jurisdiction. Japan FSA currently lists XM/Tradexfin-related unregistered
operator warnings, so XM is a hard legal hold. FINEX is registered with
Bappebti in Indonesia, but that registration does not establish the project
owner's current Japan eligibility; FINEX discovery remains explicitly
disabled pending a separate eligibility review and API attestation.

The operator needs transferable Windows preparation artifacts comparable to
the Phillip operator handoff without weakening either broker gate. XM's public
site advertises cryptocurrency derivatives for some entities, but exact
availability is account/entity specific and cannot be imported into an XM
binding while the Japan legal gate is closed. FINEX's current official
instrument inventory lists Forex, metals/energy, indices, and stocks, not
cryptocurrency instruments.

This feature produces two candidate-isolated, source-bound ZIP packages. The
XM package proves and explains the legal hold without initializing MT5. The
FINEX package may run only the existing sanitized read-only preflight against
an operator-supplied exact terminal path; it cannot create discovery evidence,
credentials, contracts, scheduled tasks, orders, or promotion evidence.

## Functional Requirements

- FR-1: The builder MUST create one XM package and one FINEX package with
  distinct archives, manifests, extraction helpers, default extraction roots,
  candidate IDs, and operator entry points.
- FR-2: Every package MUST bind the exact Git commit, Git tree, branch name,
  source-file hashes, and archive hash used to build it. The builder MUST
  reject a dirty source checkout before creating the output root.
- FR-3: Every package MUST set `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `promotion_eligible=false`,
  `order_capability=DISABLED`, and `max_lot=0.01`.
- FR-4: The XM operator entry point MUST validate the exact source identity and
  current candidate policy, report `LEGAL_BLOCKED_CURRENT_JAPAN`, and MUST NOT
  initialize MT5, access credentials, create evidence, install tasks, or mutate
  a broker.
- FR-5: The FINEX operator entry point MUST require an absolute, existing,
  non-reparse `terminal64.exe` path, validate the exact source identity and
  Windows dependency lock, and invoke only
  `run_mt5_readonly_preflight.py --candidate finex --terminal-path ...`.
- FR-6: The FINEX package MUST preserve
  `read_only_discovery_allowed=false` and MUST report discovery, contract,
  promotion, scheduled-task, and order capabilities as disabled.
- FR-7: The packages MUST NOT claim XM crypto symbols from public marketing as
  account evidence and MUST record that exact symbols require a future legal
  approval plus fresh read-only discovery.
- FR-8: The FINEX package MUST record the current official inventory categories
  and MUST NOT add a crypto symbol absent from the reviewed FINEX inventory.
- FR-9: Extraction helpers MUST verify the companion manifest, archive SHA-256,
  internal manifest identity, exact member inventory, member hashes, member
  sizes, and destination non-existence before extraction. They MUST extract to
  a candidate-isolated sibling staging directory and publish with a no-replace
  directory move; failed staging evidence is preserved for review.
- FR-10: The build MUST be deterministic for the same Git commit, Git tree,
  profile, and source inventory.
- FR-11: Existing XM, FINEX, FBS, Phillip, dashboard, dependency-lock, and
  release behavior MUST remain backward compatible.

## Non-Functional Requirements

- NFR-S1: Package build and extraction MUST NOT import MetaTrader5, access a
  credential store, initialize a broker terminal, install a scheduled task, or
  call a broker mutation API.
- NFR-S2: Packaged PowerShell MUST NOT contain `order_send`, `order_check`,
  `Register-ScheduledTask`, `Start-ScheduledTask`, `CredRead`, `CredWrite`, or
  code that sets a broker trading flag.
- NFR-S3: Candidate-specific scripts MUST reject a wrong candidate ID, wrong
  source commit/tree, non-ancestor source commit, modified required source,
  mismatched archive, or pre-existing extraction destination before an
  operational check.
- NFR-R1: Package manifests MUST use canonical UTF-8 JSON with stable ordering,
  and ZIP metadata MUST be deterministic.
- NFR-R2: The focused test suite MUST pass in normal and optimized Python modes.
- NFR-R3: The complete project test suite MUST have zero regressions.
- NFR-P1: Each archive MUST contain at most 20 files and be smaller than 2 MiB.

## Acceptance Criteria

### AC-1: Two isolated deterministic packages (FR-1, FR-2, FR-10, NFR-R1)
Given a clean committed implementation and one output directory
When the builder runs twice for the same source identity in separate roots
Then both runs produce byte-identical XM archives and byte-identical FINEX archives
And each package has a distinct candidate ID, entry point, extraction root, and archive identity

### AC-2: Permanent safety boundary (FR-3, FR-6, NFR-S1, NFR-S2)
Given either generated package
When its manifest and packaged scripts are inspected
Then all five safety fields retain their required disabled values
And no credential, task installation, broker initialization during build, or broker mutation path is present

### AC-3: XM remains a non-operational legal hold (FR-4, FR-7, NFR-S3)
Given the XM package and an exact official source checkout
When its operator entry point validates the candidate
Then it reports `LEGAL_BLOCKED_CURRENT_JAPAN`
And it does not invoke the read-only preflight, discovery, contract registration, shadow runner, or MT5

### AC-4: FINEX is limited to sanitized preflight (FR-5, FR-6, NFR-S3)
Given the FINEX package, exact official source checkout, valid dependency lock,
and an exact FINEX `terminal64.exe` path
When its operator entry point runs
Then its only broker-facing child is the existing FINEX read-only preflight
And output continues to state that discovery, promotion, and order capability are disabled

### AC-5: Invalid FINEX terminal fails before preflight (FR-5, NFR-S3)
Given a relative, missing, directory, reparse, or wrongly named terminal path
When the FINEX entry point validates its arguments
Then it fails closed before invoking Python or MT5
And no evidence or task artifact is created

### AC-6: Tamper and collision rejection (FR-2, FR-9, NFR-S3)
Given a modified archive, manifest, member, source binding, or existing destination
When an extraction helper runs
Then it exits nonzero with a specific verification failure
And no existing destination byte is overwritten

### AC-7: Instrument claims remain evidence-bound (FR-7, FR-8)
Given the reviewed official instrument observations
When package metadata is generated
Then XM crypto availability is marked `ACCOUNT_ENTITY_DISCOVERY_REQUIRED`
And FINEX crypto availability is marked `NOT_LISTED_IN_REVIEWED_OFFICIAL_INVENTORY`
And neither package adds BTCUSD or ETHUSD to a broker symbol map

### AC-8: Backward compatibility (FR-11, NFR-R2, NFR-R3)
Given the new builder, profiles, and operator scripts
When focused tests run under normal and optimized Python and the full suite runs
Then all new tests pass in both modes
And the complete suite reports zero failures

## Edge Cases and Error Scenarios

- EC-1: Output archive, manifest, helper, output root, dangling output symlink,
  or extraction destination already exists → Fail before overwriting any
  byte. Output cleanup is permitted only while the root and every leaf retain
  the exact no-follow identities created by the current invocation.
- EC-2: Git commit or tree cannot be resolved → Reject the build or operator
  validation without falling back to the working tree.
- EC-3: Source commit is not an ancestor of the configured official branch →
  Reject the operator check.
- EC-4: Candidate configuration becomes legal-eligible or discovery-enabled
  without a versioned profile update → Reject because the V1 preparation
  package is not an activation package.
- EC-5: XM entry point receives a terminal path or activation flag → Reject as
  an unknown/forbidden argument; never initialize MT5.
- EC-6: FINEX preflight reports an account/server/symbol/safety mismatch →
  Propagate failure while order capability remains disabled.
- EC-7: FINEX dependency lock verification fails → Stop before MT5 import.
- EC-8: ZIP contains a duplicate, absolute, parent-traversal, case-colliding,
  directory, symlink, or unexpected member → Reject extraction.
- EC-9: Package or source file contains a credential-like value → Reject the
  build; do not redact and continue.
- EC-10: Public XM marketing symbols differ from the future account discovery →
  Treat discovery as authoritative only after the legal gate is independently
  reopened; do not backfill the current package.
- EC-11: A generated output root or leaf is replaced during a failure path →
  Preserve the replacement and fail closed; never use recursive unconditional
  cleanup as ownership evidence.

## API Contracts

HTTP contract: N/A — no `GET /api/broker-preparation` or other network
endpoint is introduced; the interfaces below describe local files and CLIs.

```typescript
interface BuildBrokerPreparationPackagesRequest {
  outputRoot: AbsoluteNewDirectory;
  branch: "agent/live-grade-phase3";
}

interface BrokerPreparationManifestV1 {
  schema_version: "ai-scalper-windows-broker-preparation-manifest-v1";
  release_profile:
    | "WINDOWS_XM_JAPAN_LEGAL_HOLD_PREPARATION_V1"
    | "WINDOWS_FINEX_READ_ONLY_PREPARATION_V1";
  candidate_id: "xm" | "finex";
  git_commit: LowerHex40;
  git_tree: LowerHex40;
  official_branch: "agent/live-grade-phase3";
  release_identity_sha256: LowerHex64;
  source_files: SourceFileRecord[];
  safety: SafetyPolicy;
  eligibility: EligibilityPolicy;
  instrument_claims: InstrumentClaims;
  operator_entry_point: string;
  default_extraction_root: AbsoluteWindowsPath;
  production_execution_ready: false;
}

interface CompanionArchiveManifestV1 {
  schema_version: "ai-scalper-windows-broker-preparation-archive-v1";
  archive_name: string;
  archive_sha256: LowerHex64;
  archive_size_bytes: number;
  release_identity_sha256: LowerHex64;
  git_commit: LowerHex40;
  git_tree: LowerHex40;
  files: SourceFileRecord[];
}

interface SafetyPolicy {
  live_allowed: false;
  safe_to_demo_auto_order: false;
  promotion_eligible: false;
  max_lot: 0.01;
  order_capability: "DISABLED";
}
```

CLI:

```text
python -B build_windows_xm_finex_preparation_packages.py \
  --output-root ABSOLUTE_NEW_DIRECTORY \
  [--branch agent/live-grade-phase3]
```

Windows operator entry points:

```text
Test-XMPreparationGate.ps1 [-Repo C:\AI_SCALPER]
Test-FINEXReadOnlyPreflight.ps1 \
  -TerminalPath C:\...\terminal64.exe \
  [-Repo C:\AI_SCALPER] [-Python C:\AI_SCALPER\.venv\Scripts\python.exe]
```

## Data Models

### SourceFileRecord

| Field | Type | Constraints |
|-------|------|-------------|
| `path` | string | Relative POSIX path; no traversal; unique case-insensitively |
| `sha256` | LowerHex64 | SHA-256 of exact archived bytes |
| `size_bytes` | integer | Greater than zero; exact archived size |

### EligibilityPolicy

| Field | Type | Constraints |
|-------|------|-------------|
| `operating_jurisdiction` | string | `JP` for V1 |
| `status` | enum | XM `LEGAL_BLOCKED_CURRENT_JAPAN`; FINEX `PREPARATION_ONLY_ELIGIBILITY_PENDING` |
| `discovery_allowed` | boolean | Always false in V1 |
| `contract_registration_allowed` | boolean | Always false in V1 |
| `task_installation_allowed` | boolean | Always false in V1 |

### InstrumentClaims

| Field | Type | Constraints |
|-------|------|-------------|
| `reviewed_categories` | string[] | Candidate-specific official categories only |
| `crypto_status` | enum | XM discovery-required; FINEX not listed |
| `broker_symbol_map_added` | boolean | Always false |

## Out of Scope

- OS-1: Reopening XM eligibility in Japan or changing the hard deny — requires
  independent legal/compliance approval and a new versioned spec.
- OS-2: Creating XM or FINEX discovery, calendar, contract, evidence key,
  journal, scheduled task, paper order, demo order, or live order.
- OS-3: Storing or collecting broker login IDs, investor/master passwords,
  balances, personal identity, or KYC documents.
- OS-4: Adding XM crypto symbols from marketing pages or assuming future
  entity/account availability.
- OS-5: Adding FINEX crypto support absent official inventory and exact terminal
  discovery.
- OS-6: Modifying existing Phillip V5, FBS, dashboard, release-service, or
  dependency-lock behavior.
