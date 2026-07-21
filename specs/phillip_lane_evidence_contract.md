# Spec: Phillip Lane-Isolated Evidence Contract Preparation

**Author:** AI_SCALPER Engineering
**Date:** 2026-07-21
**Status:** Approved
**Reviewer:** Project owner through the approved Live-Grade v1 roadmap and explicit continuation request
**Related specs:** `phillip_multi_account_binding_probe.md`, `phillip_dual_terminal_shadow.md`

## Context

Phillip Securities Japan exposes the v1 instruments through two separate MT5
demo account contexts. The FX account contains AUDUSD, EURUSD, and USDJPY,
while the commodity account contains XAUUSD. The existing generic evidence
pipeline assumes all four canonical symbols belong to one terminal cohort, so
it cannot create truthful lane-isolated discovery, calendar, or forward
contract inputs for Phillip.

The diagnostic dual shadow is already operational, but its journal is not
promotion evidence. This feature prepares the immutable evidence pipeline for
the two Phillip lanes without enabling registration prematurely. Exact holiday
calendars, signed regulatory approvals, and fresh v3 discovery receipts remain
external gates and must be supplied before a forward contract can be minted.

## Functional Requirements

- FR-1: Evidence discovery MUST accept a non-empty subset of the four v1 canonical symbols and MUST reject unknown or duplicate canonical symbols.
- FR-2: Phillip FX discovery MUST bind exactly AUDUSD, EURUSD, and USDJPY to one explicit terminal executable.
- FR-3: Phillip commodity discovery MUST bind exactly XAUUSD to a different explicit terminal executable.
- FR-4: Evidence discovery MUST NOT accept broker login, password, account name, balance, equity, or order parameters.
- FR-5: Broker calendar templates, prepared plans, and bundles MUST contain exactly the symbols registered for their candidate lane.
- FR-6: Forward contracts MUST record a non-empty canonical subset and all source, specification, calendar, append, verification, and seal operations MUST use only that recorded subset.
- FR-7: The four-symbol XM/FBS behavior MUST remain backward compatible.
- FR-8: Phillip evidence profiles MUST remain registration-disabled until exact calendars and signed regulatory approvals are reviewed.
- FR-9: Every generated artifact MUST retain `execution_enabled=false`, `live_allowed=false`, `safe_to_demo_auto_order=false`, and `max_lot=0.01`.
- FR-10: Existing runtime diagnostic journals MUST NOT be modified, migrated, or counted as forward promotion evidence.

## Non-Functional Requirements

- NFR-S1: Discovery MUST fail closed unless the connected account is DEMO and both account and terminal mutation capabilities are disabled.
- NFR-S2: The terminal executable path MUST be absolute, exist, be a regular file, and have basename `terminal64.exe` before MT5 initialization.
- NFR-S3: Candidate, discovery, plan, calendar, and contract symbol sets MUST match exactly; silent supersets and subsets are prohibited.
- NFR-R1: Artifact writes MUST remain create-exclusive or atomic and MUST never overwrite an existing immutable artifact.
- NFR-R2: Existing four-symbol evidence tests and the full project test suite MUST pass without regression.
- NFR-A1: Contract and discovery CLIs MUST print that order capability remains disabled and MUST not expose secret key material.

## Acceptance Criteria

### AC-1: FX subset discovery (FR-1, FR-2, FR-4, NFR-S1, NFR-S3)
Given a read-only Phillip FX demo facade and the reviewed three-symbol map
When discovery is executed for `phillip-fx`
Then the signed receipt contains exactly AUDUSD, EURUSD, and USDJPY
And it contains no raw account identity or balance fields.

### AC-2: Commodity subset discovery (FR-1, FR-3, NFR-S1, NFR-S3)
Given a read-only Phillip commodity demo facade and the reviewed XAUUSD map
When discovery is executed for `phillip-commodity`
Then the signed receipt contains only XAUUSD
And its account cohort cannot be combined with the FX receipt.

### AC-3: Explicit terminal binding (FR-2, FR-3, NFR-S2)
Given multiple MT5 installations are present
When the evidence discovery CLI is invoked
Then it initializes only the explicitly supplied valid `terminal64.exe` path
And an absent, relative, directory, or incorrectly named path is rejected before MT5 import or initialization.

### AC-4: Lane-aware calendar (FR-5, NFR-S3)
Given an approved lane template, matching signed discovery, and matching candidate config
When a plan and calendar bundle are built
Then every symbol collection contains exactly the lane symbols
And a symbol-set mismatch fails closed.

### AC-5: Lane-aware immutable contract (FR-6, NFR-S3, NFR-R1)
Given a verified four-symbol development snapshot and one approved lane's matching sources, specs, and calendars
When a DIAGNOSTIC forward contract is registered
Then its `symbols` field contains only that canonical lane subset
And anchors, heads, append validation, verification, and coverage use only that subset.

### AC-6: Legacy compatibility (FR-7, NFR-R2)
Given an existing four-symbol XM/FBS fixture
When discovery, planning, calendar generation, contract registration, append, and verification tests run
Then their prior behavior remains valid
And the full project suite has zero regressions.

### AC-7: External gates remain closed (FR-8, FR-9, NFR-A1)
Given tracked Phillip evidence profiles and calendar templates
When an operator attempts contract registration before external attestations are complete
Then registration is rejected before artifact reads
And the message confirms no broker order was submitted.

### AC-8: Diagnostic separation (FR-10)
Given existing Phillip diagnostic SQLite journals
When evidence preparation code is installed
Then those journals are neither read as forward input nor modified
And promotion eligibility remains false.

## Edge Cases and Error Scenarios

- EC-1: Empty symbol map → Reject before account or symbol reads.
- EC-2: Unknown canonical symbol → Reject as outside the v1 allowlist.
- EC-3: Candidate symbol set differs from template → Reject with candidate binding mismatch.
- EC-4: Discovery symbol set differs from plan → Reject before calendar or contract registration.
- EC-5: FX receipt supplied to commodity plan, or the reverse → Reject candidate and symbol binding.
- EC-6: Terminal path is missing, relative, a directory, a symlink, or not named `terminal64.exe` → Reject before MT5 initialization.
- EC-7: Terminal attaches to live or mutation-enabled account → Reject and write no discovery receipt.
- EC-8: Calendar lacks exact special-hours attestation → Reject plan/calendar progression.
- EC-9: Registration profile is disabled → Reject before reading discovery, plan, or calendar artifacts.
- EC-10: Contract symbol is not present in the frozen snapshot → Reject contract registration.
- EC-11: Append attempts an unregistered symbol → Reject with `SYMBOL_NOT_REGISTERED`.
- EC-12: Existing artifact path already exists → Reject without overwrite.

## API Contracts

N/A for HTTP method and path — this feature exposes local fail-closed Python
CLIs and signed filesystem artifacts only; it introduces no network endpoint.

```typescript
interface EvidenceDiscoveryRequest {
  candidate: "phillip-fx" | "phillip-commodity" | string;
  terminalPath: AbsolutePathToTerminal64Exe;
  output: CreateExclusiveJsonPath;
}

interface EvidenceProfile {
  candidate_id: string;
  key_name: string;
  snapshot_id: string;
  contract_id: string;
  template_path: RepositoryRelativePath;
  registration_enabled: boolean;
  status: string;
}

interface LaneForwardContract {
  contract_id: string;
  validation_profile: "DIAGNOSTIC";
  symbols: Array<"XAUUSD" | "EURUSD" | "USDJPY" | "AUDUSD">;
  promotion_profile_eligible: false;
  broker_sources: Record<string, BrokerSource>;
  instrument_specs: Record<string, InstrumentSpec>;
  session_calendars: Record<string, SessionCalendar>;
  contract_payload_sha256: SHA256;
  contract_hmac_sha256: HMACSHA256;
}

interface GateFailure {
  status: "BLOCKED";
  order_capability: "DISABLED";
  reason: string;
}
```

## Data Models

### Lane Symbol Set

| Field | Type | Constraints |
|---|---|---|
| candidate_id | string | Reviewed candidate namespace; immutable within artifacts |
| canonical_symbols | tuple[string] | Non-empty unique subset of the four v1 symbols |
| broker_symbols | map[string,string] | Keys exactly equal canonical symbols |
| terminal_path | absolute path | Runtime-only; never stored in signed evidence or repository config |

### Forward Contract

| Field | Type | Constraints |
|---|---|---|
| symbols | list[string] | Canonical order, non-empty, unique, subset of v1 allowlist |
| broker_sources | map | Exact same keys as `symbols` |
| instrument_specs | map | Exact same keys as `symbols` |
| session_calendars | map | Exact same keys as `symbols` |
| validation_profile | enum | `DIAGNOSTIC` for this feature |
| promotion_profile_eligible | boolean | Always false |
| hashes/HMAC | lowercase hex | Verified before any append or report operation |

## Out of Scope

- OS-1: Enabling `registration_enabled` for Phillip — deferred until signed regulatory and exact calendar attestations exist.
- OS-2: Demo-auto or live order submission — excluded by the Live-Grade v1 rollout sequence.
- OS-3: Reusing diagnostic journal history as forward evidence — prohibited because the contract must be pre-registered.
- OS-4: Stock/index account support — not part of the v1 symbol lanes.
- OS-5: Strategy, thresholds, or position-sizing changes — this feature concerns evidence integrity only.
- OS-6: Credential storage beyond the existing Windows Credential Manager evidence key — broker credentials remain operator-managed inside MT5.
