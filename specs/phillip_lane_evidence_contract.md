# Spec: Phillip Lane-Isolated Evidence Contract Preparation

**Author:** AI_SCALPER Engineering
**Date:** 2026-07-21
**Status:** Approved; bounded-worker addendum approved 2026-07-25
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
promotion evidence. Commodity discovery, regulatory review, calendar review,
and manual registration activation were subsequently completed; FX remains
registration-disabled. Every Commodity source remediation advances to a new
immutable contract namespace before observation begins.

## Functional Requirements

- FR-1: Evidence discovery MUST accept a non-empty subset of the four v1 canonical symbols and MUST reject unknown or duplicate canonical symbols.
- FR-2: Phillip FX discovery and evidence collection MUST bind exactly AUDUSD, EURUSD, and USDJPY to one explicit terminal executable.
- FR-3: Phillip commodity discovery and evidence collection MUST bind exactly XAUUSD to a different explicit terminal executable.
- FR-4: Evidence discovery MUST NOT accept broker login, password, account name, balance, equity, or order parameters.
- FR-5: Broker calendar templates, prepared plans, and bundles MUST contain exactly the symbols registered for their candidate lane.
- FR-6: Forward contracts MUST record a non-empty canonical subset and all source, specification, calendar, append, verification, and seal operations MUST use only that recorded subset.
- FR-7: The four-symbol XM/FBS behavior MUST remain backward compatible.
- FR-8: Phillip evidence profiles MUST remain registration-disabled until exact calendars and signed regulatory approvals are reviewed.
- FR-9: Every generated artifact MUST retain `execution_enabled=false`, `live_allowed=false`, `safe_to_demo_auto_order=false`, and `max_lot=0.01`.
- FR-10: Existing runtime diagnostic journals MUST NOT be modified, migrated, or counted as forward promotion evidence.
- FR-11: A bounded persistent worker MUST run the one-shot evidence boundary every 60 seconds at a deterministic offset so the 60-second append deadline is reachable after an expensive installed-environment verification.
- FR-12: The worker MUST use a new immutable contract and journal namespace whenever its tracked source identity changes.

## Non-Functional Requirements

- NFR-S1: Discovery MUST fail closed unless the connected account is DEMO, `account.trade_allowed=false`, `terminal.trade_allowed=false`, and `terminal.tradeapi_disabled=true`.
- NFR-S1A: `account.trade_expert` MUST be an explicit boolean and MUST be recorded truthfully. A broker-reported `true` is informational when account trading is unavailable and MUST NOT override any effective mutation lock.
- NFR-S2: The terminal executable path MUST be absolute, exist, be a regular file, and have basename `terminal64.exe` before MT5 initialization.
- NFR-S3: Candidate, discovery, plan, calendar, and contract symbol sets MUST match exactly; silent supersets and subsets are prohibited.
- NFR-R1: Artifact writes MUST remain create-exclusive or atomic and MUST never overwrite an existing immutable artifact.
- NFR-R2: Existing four-symbol evidence tests and the full project test suite MUST pass without regression.
- NFR-R3: Exactly one worker process may own a contract at a time through a crash-safe kernel fence distinct from the per-cycle fence.
- NFR-S4: The worker MUST fully hash the installed environment once per bounded process, MUST revalidate the immutable lock contract on every child invocation, MUST bind compact child receipts to the full session receipt hash, and MUST never cache across a process restart.
- NFR-S5: Worker duration MUST be explicit, at least 15 minutes, and no longer than 24 hours. Any child `HOLD` or `BUSY` result MUST stop the worker with a nonzero exit.
- NFR-S6: A scheduled worker MUST run with effective Task Scheduler principal level `Limited` and the exact reviewed effective settings. XML validation MUST apply the Task Scheduler XSD default only when an optional node is absent, MUST reject a missing non-default setting, and MUST independently verify every effective CIM value. Installer and health checks MUST use the same side-effect-free validator and MUST never access an optional XML child through dynamic dotted properties under StrictMode.
- NFR-S7: A scheduler-only remediation MAY retain an already proof-verified frozen worker commit, contract, journal, and audit chain when no worker source or evidence binding changes. It MUST use a new task name and create-exclusive task evidence root, preserve every failed prior task disabled, and bind the exact prior proof receipt hash.
- NFR-S8: Scheduled-worker freshness MUST use the latest HMAC-verified `runtime_status.heartbeat_at_utc`, require strictly monotonic authenticated source-event counts and heartbeats, reject future skew above 60 seconds, and reject age above 180 seconds during an active interval after startup allowance. File and SQLite mtimes MUST NOT be treated as freshness evidence.
- NFR-S9: A scheduler remediation MUST register disabled, validate before enablement, require at least 900 seconds of installation lead, verify the exact first `NextRunTime`, and on any later failure attempt both stop and disable before proving effective state `Disabled`. Disable or state-query failure MUST surface as a distinct fail-closed error.
- NFR-S10: Online scheduler health MUST bind the exact fixed proof-child inventory and every successor predecessor sequence/event-hash/signed-HMAC transition. A full initial walk MUST create an HMAC-signed checkpoint; later checks MAY authenticate only the exact new suffix when they append a signed successor checkpoint, but the resulting audit/checkpoint head MUST exactly equal the read-only HMAC-authenticated live journal count, event hash, signed-head HMAC, status HMAC, and heartbeat. Verification through checkpoint commit MUST be serialized across health processes, and an existing checkpoint MAY be reconciled only when byte-identical. A new checkpoint MUST be flushed under a non-chain temporary name and atomically moved to its create-exclusive final name. Installation MUST fully re-read the historical archive, and an explicit full-archive mode MUST remain available because online incremental health does not re-read checkpointed historical bytes; that explicit mode MUST require a `Ready` task, no active worker interval, and at least 3600 seconds before the next trigger. The manifest is the publication commit marker: an audit without a manifest MAY be ignored as in progress, while a manifest with unavailable or invalid audit bytes MUST fail closed. Phase MUST be sampled after evidence verification, startup grace MAY accept `Queued` only before a current-boundary attempt, MUST reject a task that already attempted and exited, and schedule calculations MUST NOT infer a trigger beyond `EndBoundary`.
- NFR-A1: Contract and discovery CLIs MUST print that order capability remains disabled and MUST not expose secret key material.

## Acceptance Criteria

### AC-1: FX subset discovery (FR-1, FR-2, FR-4, NFR-S1, NFR-S3)
Given a read-only Phillip FX demo facade and the reviewed three-symbol map
When discovery is executed for `phillip-fx`
Then the signed receipt contains exactly AUDUSD, EURUSD, and USDJPY
And it contains no raw account identity or balance fields.
And the observed account expert policy flag is preserved in the signed receipt.

### AC-2: Commodity subset discovery (FR-1, FR-3, NFR-S1, NFR-S3)
Given a read-only Phillip commodity demo facade and the reviewed XAUUSD map
When discovery is executed for `phillip-commodity`
Then the signed receipt contains only XAUUSD
And its account cohort cannot be combined with the FX receipt.

### AC-3: Explicit terminal binding (FR-2, FR-3, NFR-S2)
Given multiple MT5 installations are present
When the evidence discovery CLI or broker-neutral one-shot collector is invoked
Then it initializes only the explicitly supplied valid `terminal64.exe` path
And an absent, relative, directory, symlink, or incorrectly named path is
rejected before MT5 import, operational journal creation, or initialization.
And operational receipts contain only the normalized-path SHA-256, never the
raw local terminal path.

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

### AC-9: Deadline-safe bounded worker (FR-11, FR-12, NFR-R3, NFR-S4, NFR-S5)
Given a new immutable Commodity contract, journal, and exact Windows release
When the bounded worker starts under isolated Python flags
Then the first child invocation carries the full installed-environment receipt
And later child invocations revalidate the lock and carry a compact
same-process session reference
And the verified site-packages path is activated exactly once per process
And every child verifies that the repo/site-packages path binding and
precedence have not drifted without re-entering the non-idempotent activator
And child invocations start on each 60-second boundary plus two seconds
And a second worker cannot acquire the worker fence
And any nonzero child result stops the worker without enabling order
capability.

### AC-10: Effective Task Scheduler contract (NFR-S6)
Given a proof-verified read-only worker and an exported Task Scheduler XML
When the installed task is validated
Then its effective CIM principal run level is `Limited`
And an omitted optional XML `RunLevel` node is accepted
And a present XML node is accepted only when it is `LeastPrivilege`
And schema-default omissions such as `StartWhenAvailable=false` are accepted
only when the corresponding effective CIM value matches
And every missing non-default setting, duplicate node, invalid lexical value,
wrong effective setting, extra action/trigger, or unreadable property fails
closed before any scheduled worker run.

### AC-11: Scheduler-only immutable remediation (NFR-R1, NFR-S7)
Given a valid V5 proof receipt and a V5 task disabled by validator failure
When the scheduler validator is remediated without changing worker source
Then V4 and V5 tasks and their evidence remain present and disabled
And V6 uses a new task name and create-exclusive review, export, and receipt
paths
And V6 continues the exact frozen V5 contract, journal, and HMAC audit chain
And no contract registration, manual task start, order call, or broker
mutation occurs.

### AC-12: Authenticated health and scheduler rollback (NFR-S8, NFR-S9)
Given the exact V5 HMAC audit chain and the new V6 task namespace
When installation or health validation runs
Then no file timestamp contributes to runtime freshness
And active-window freshness is derived from a monotonic signed heartbeat
And V6 cannot be enabled with less than 900 seconds of installation lead
And the first `NextRunTime` equals the reviewed boundary
And the exact V5 proof children and every new predecessor transition are
authenticated through an append-only signed checkpoint chain
And the checkpoint/audit head exactly matches the authenticated live journal
And concurrent health checks cannot fork the checkpoint chain
And installation or explicit full-archive mode authenticates every historical
pair while online mode reports that it validates only the suffix
And incomplete audit publication is distinguished from a committed invalid
pair without using file timestamps
And scheduler phase is resampled after evidence verification without accepting
an early startup exit or inventing a post-expiry run
And any post-registration failure stops and disables V6 or returns
`V6_FAIL_CLOSED_DISABLE_FAILED`.

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
- EC-13: Worker uses a legacy contract namespace, invalid duration, status-only mode, or XM compatibility lane → Reject before worker execution.
- EC-14: A second worker owns the contract → Return `BUSY`; do not queue or run in parallel.
- EC-15: Lock or install-manifest identity changes during a worker session → Stop `HOLD` before the next child runtime import.
- EC-16: Exported task XML omits optional `RunLevel` while effective CIM is `Limited`, or omits a setting whose XSD default equals the reviewed value → Accept only when effective CIM also matches.
- EC-17: Exported task XML omits `StartWhenAvailable=false` → Accept as an XSD-default elision when effective CIM is exactly `false`; reject wrong or unreadable CIM, a wrong explicit value, duplicates, or invalid boolean syntax.
- EC-18: Exported task XML omits a reviewed non-default setting such as `AllowHardTerminate=false`, `AllowStartOnDemand=false`, or `ExecutionTimeLimit=PT0S` → Reject with a named semantic failure rather than `PropertyNotFoundStrict`.
- EC-19: An audit file is touched without a new signed heartbeat, a WAL transaction leaves the main SQLite mtime unchanged, a signed heartbeat goes backward, or it exceeds future/stale limits → Ignore mtimes and reject according to the authenticated heartbeat contract.
- EC-20: V6 enablement is too close to the first boundary, `NextRunTime` differs, rollback disable/query fails, or an instance remains running → Reject installation; attempt stop and disable; require the distinct fail-closed rollback result when `Disabled` cannot be proven.
- EC-21: A proof child is substituted, the proof signing-key/runtime identity drifts, or a middle post-proof audit pair is removed → Reject the proof/checkpoint predecessor chain.
- EC-22: The audit file is visible before its matching manifest → Retain the last signed checkpoint and retry/ignore the uncommitted publication; once the manifest is visible, any missing, reparse-point, changing, or invalid audit bytes are rejected.
- EC-23: Health crosses a trigger boundary during evidence verification, a worker exits during the five-minute startup allowance, or the observation is after the final bounded worker ends → Recompute phase after verification and require the exact `ACTIVE`, `GAP`, or `EXPIRED` state without an invented trigger.
- EC-24: The newest signed checkpoint and matching audit suffix are removed while the live journal remains ahead → Reject live-journal/audit-head mismatch rather than accepting an older valid prefix.
- EC-25: Two health checks race to append a successor, an identical checkpoint already exists, or Task Scheduler reports `Queued` during startup → Serialize through a named mutex; accept only byte-identical checkpoint state and accept `Queued` only before a current-boundary attempt.
- EC-26: A checkpointed historical audit byte changes → Default online mode reports that historical bytes were not re-read; installation or explicit full-archive audit MUST reject the drift.
- EC-27: Explicit full-archive audit is requested while the task is not `Ready`, a worker interval is active, or the next trigger is less than 3600 seconds away → Reject before scanning historical bytes.
- EC-28: Power is lost after a checkpoint temporary file is flushed but before publication → Leave at most an ignored non-chain temporary file; the final checkpoint is either atomically complete or absent.

## API Contracts

N/A for HTTP method and path — this feature exposes local fail-closed Python
CLIs and signed filesystem artifacts only; it introduces no network endpoint.

```typescript
interface EvidenceDiscoveryRequest {
  candidate: "phillip-fx" | "phillip-commodity" | string;
  terminalPath: AbsolutePathToTerminal64Exe;
  output: CreateExclusiveJsonPath;
}

interface EvidenceShadowCycleRequest {
  candidate: "phillip-fx" | "phillip-commodity" | string;
  terminalPath: AbsolutePathToTerminal64Exe;
  artifactRoot: ImmutableEvidenceRoot;
}

interface EvidenceShadowWorkerRequest extends EvidenceShadowCycleRequest {
  worker: true;
  workerDurationSeconds: number; // 900..86400
  journal: NewContractBoundSQLitePath;
  auditExportDir: CreateExclusiveAuditDirectory;
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

- OS-1: Enabling `registration_enabled` for Phillip FX — deferred until its independent signed regulatory and exact calendar attestations exist. Commodity enablement is already a reviewed evidence-only state.
- OS-2: Demo-auto or live order submission — excluded by the Live-Grade v1 rollout sequence.
- OS-3: Reusing diagnostic journal history as forward evidence — prohibited because the contract must be pre-registered.
- OS-4: Stock/index account support — not part of the v1 symbol lanes.
- OS-5: Strategy, thresholds, or position-sizing changes — this feature concerns evidence integrity only.
- OS-6: Credential storage beyond the existing Windows Credential Manager evidence key — broker credentials remain operator-managed inside MT5.
