# Spec: Phillip Commodity Window 02 Read-Only Scheduler V1

**Author:** AI_SCALPER Engineering

**Date:** 2026-08-05

**Status:** Approved for implementation

**Authority:** The project owner continued the Window 02 remediation after
registering and independently displaying the exact immutable contract
identity and complete eight-file inventory.

## Context

The active Phillip Commodity profile now names
`phillip-commodity-window-02-diagnostic-v1`. The contract was registered on
Windows before the observation boundary and is bound to source commit
`da3190013d86426533019d6927a58181c624b1f8`, source tree
`9e84a0d7c9a5b3d4213c6abf0fdf1c8770361d10`, snapshot
`phillip-commodity-dev-pre-window-02-v1`, payload SHA-256
`cbfd753b0aed2d66af56446adc734ce8d62666e309e91bf74d24b4cc56b613a2`,
and physical `contract.json` SHA-256
`ad4fd8853563976483fbffbd3bd97847f7e05c8a4194afd10fa95832e2fe485b`.

The historical V6 task is disabled and remains immutable failed Window 01
history. Its installer cannot be reused: it requires a V5 proof receipt,
the `290cc23d` worker, the Window 01 contract, historical audit files, and a
July 2026 schedule. Window 02 therefore needs a separate source-bound task
that can prove a valid empty contract before the first automatic run.

## Functional requirements

- FR-1: The transfer package MUST bind the exact registered Window 02
  contract, all eight initial artifact files, source commit/tree, snapshot,
  signing-key identifier, registration time, observation start, blind-until,
  and build-identity hash.
- FR-2: The worker source MUST be a clean locked detached worktree at commit
  `da3190013d86426533019d6927a58181c624b1f8` and tree
  `9e84a0d7c9a5b3d4213c6abf0fdf1c8770361d10`.
- FR-3: Before task registration, an authoritative verifier MUST validate the
  dependency lock, current broker profile, Windows Credential Manager key,
  contract HMAC, snapshot, build identity, calendar chain, empty segment/raw
  tick state, and exact physical inventory.
- FR-4: The new task name MUST be
  `AI_SCALPER-PhillipCommodityWindow02-ReadOnlyShadow`; the historical V4,
  V5, and V6 task names MUST never be renamed, removed, started, or enabled.
- FR-5: Any historical task that exists MUST be `Disabled` before the new
  task can be installed.
- FR-6: The task MUST run as the current Windows SID with
  `InteractiveToken` and `LeastPrivilege`, and installation MUST be invoked
  from a non-elevated PowerShell token so the preflight observes the same
  read boundary as the scheduled worker.
- FR-7: The first task boundary MUST be 17 August 2026 06:45 JST
  (`2026-08-16T21:45:00Z`), weekdays only, ending at
  `2026-10-13T00:16:00+09:00`. The worker duration MUST be 84,300 seconds.
  The end boundary is the contract ingestion deadline: 15 minutes of final
  M15 finalization plus the contract's 60-second ingestion grace after
  `blind_until_utc`; it is not a new observation-data interval.
- FR-8: The task MUST be registered disabled, semantically verified, enabled,
  exported, and semantically verified again. A post-registration failure MUST
  leave it disabled.
- FR-9: `AllowStartOnDemand=false`, `StartWhenAvailable=false`, no restart
  policy, `IgnoreNew`, no hard termination, no idle/battery/network gate, no
  wake timer, and unlimited task execution time MUST remain exact.
- FR-10: Installation and health tooling MUST never invoke
  `Start-ScheduledTask`, unregister/delete a task, import MetaTrader5, contact
  a broker, or submit an order.
- FR-11: Pre-start health MUST be valid without a journal. After an automatic
  attempt, health MUST require correct Task Scheduler timing/result and, while
  active beyond startup allowance, an authenticated non-stale runtime status.
- FR-12: Package build and extraction MUST be deterministic,
  content-addressed, create-exclusive, flat-inventory verified, and preserve
  partial output for forensic review.
- FR-13: Git process wrappers MUST tolerate informational native `stderr`
  emitted by Git under Windows PowerShell 5.1 and MUST decide success only
  from the captured native exit code. A retry package MUST use fresh `-r2`
  worktree, runtime, audit, and task-review paths rather than overwrite the
  first transfer's partial worktree.

## Exact registered artifact inventory

| Relative path | Bytes | SHA-256 |
|---|---:|---|
| `anchors/raw_ticks/XAUUSD/000000.json` | 764 | `0954b53a613c2b893da65313cb3cc077d3f3b340405a22f7714295a861112e96` |
| `anchors/segments/XAUUSD/000000.json` | 763 | `fd9d1bd1c28ae38e4fdf4894cc2a78103346dbf121d8e52532da97a9556090ab` |
| `calendar_amendments/000000.json` | 697 | `6f8a7f90c4ba4ea3b05b7d17f731c0c4e47c0187522fb14b89923343b68bc865` |
| `contract.json` | 19601 | `ad4fd8853563976483fbffbd3bd97847f7e05c8a4194afd10fa95832e2fe485b` |
| `heads/calendar_amendments.json` | 697 | `6f8a7f90c4ba4ea3b05b7d17f731c0c4e47c0187522fb14b89923343b68bc865` |
| `heads/raw_ticks/XAUUSD.json` | 764 | `0954b53a613c2b893da65313cb3cc077d3f3b340405a22f7714295a861112e96` |
| `heads/segments/XAUUSD.json` | 763 | `fd9d1bd1c28ae38e4fdf4894cc2a78103346dbf121d8e52532da97a9556090ab` |
| `seal.json` | 571 | `7be98a026bd4a702f17efc70ecadf6d34b7696effb800697c7557603d118ad4a` |

After the first authoritative verification, the frozen validation library
intentionally persists `.contract-write.lock` as one NUL byte. Its SHA-256 is
`6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d`.
Retry installers MUST bind this ninth operational artifact exactly; it is not
observation evidence and does not change any genesis artifact.

The worker may also persist the exact root-level `.shadow-worker.lock` and
`.shadow-cycle.lock` synchronization carriers. They are optional operational
sidecars, not registered evidence, and are excluded from the eight/nine-file
artifact count. If present, the verifier MUST require each exact allowlisted
path to be a stable, one-byte, regular non-reparse file without opening it:
an active Windows byte-range lock may legitimately deny content reads. This
exception MUST NOT apply to any other path, directory, or contract artifact.

## Safety invariants

- `validation_profile=DIAGNOSTIC`
- `promotion_profile_eligible=false`
- `live_allowed=false`
- `order_capability=DISABLED`
- no manual task start
- no broker mutation
- no credential export
- no reuse of V5/V6 proof or journal evidence
- dependency lock SHA-256
  `34087f736724e7d92591f7886f565b15436c59de0d4e80a59e42b04f2851d862`

## Acceptance criteria

1. Two builds from the same tracked commit produce byte-identical archives.
2. Tampered contract fields, bytes, inventory, HMAC authority, snapshot,
   build identity, dependency environment, source commit, source tree, task
   XML, prior-task state, or schedule fail before task enablement.
3. A valid install creates only the locked worktree, new private runtime and
   review directories, installation evidence, and the exact new Scheduled
   Task; it never starts the task.
4. Pre-start health reports the task `Ready`, the first automatic boundary,
   the exact contract identity, and `OrderCapability=DISABLED`.
5. Focused tests, historical V5/V6 tests, full normal and optimized suites,
   compilation, diff checks, and safety scans pass without changing frozen
   historical files.

## Transport revision V2

The first `WINDOW02.V1` transfer extracted successfully on Windows, but its
installer stopped after Git printed the successful worktree progress message
`Preparing worktree (detached HEAD da31900)` to native `stderr`. Windows
PowerShell 5.1 converted that informational stream into a terminating
`NativeCommandError` because the installer is intentionally fail-fast.

`WINDOW02.V2` captures Git output with native-error promotion temporarily set
to `Continue`, restores the caller preference in `finally`, and evaluates the
captured `LASTEXITCODE`. The retry uses paths ending in `-r2`; no V1 partial
output is removed, reused, or overwritten.

## Transport revision V3

V2 reached the authoritative contract verifier and failed before task
registration. The frozen `verify_forward_evidence()` library returns its raw
authenticated mapping; it intentionally does not return the CLI-only fields
`status`, `order_capability`, or `live_allowed`. The V1/V2 verifier fixture had
synthesized those three fields and therefore tested a shape the production
library never emits.

`WINDOW02.V3` pins the exact top-level key set returned by the frozen worker,
validates its diagnostic profile, HMAC form, empty coverage, calendar state,
chain state, external-custody locks, and evidence root, then derives the
hardcoded disabled safety projection only after authentication succeeds. V3
also captures the verifier's native process exit before parsing JSON and uses
fresh create-exclusive paths ending in `-r3`. V1/V2 outputs remain immutable.

## Transport revision V4

V3 reached physical inventory validation only after V2 had invoked the frozen
verification API. That API uses `.contract-write.lock` as an intentionally
persistent kernel-lock carrier, so the post-V2 operational directory contains
nine files even though registration created eight immutable genesis files.

`WINDOW02.V4` authenticates the one-byte lock carrier by exact size and hash,
keeps every genesis artifact byte-bound, and emits missing/unexpected relative
paths for any inventory mismatch. Its retry paths end in `-r4`; V1--V3 output
is preserved and never overwritten.

## Transport revision V5

The final repository-side audit identified two avoidable state assumptions in
V4. It required the operational lock to exist before the first authoritative
call, although a clean registration legitimately starts with eight files, and
the health checker still invoked Python directly under Windows PowerShell
5.1's native-stderr promotion behavior.

`WINDOW02.V5` performs a two-phase inventory proof. Before authority it accepts
only the exact eight-file genesis state or the exact nine-file operational
state. After the frozen verifier returns, it always requires the exact
nine-file operational state and unchanged `contract.json` bytes. Installer and
health native calls capture `LASTEXITCODE` immediately after the process,
temporarily capture native stderr without terminating, restore the caller
preference, and only then parse output. V5 uses fresh create-exclusive `-r5`
paths and leaves V1--V4 evidence untouched.

## Transport revision V6

The verified V5 transfer exposed a Windows PowerShell 5.1 scope error before
any worktree or task mutation. Assigning `$null` to the automatic
`$LASTEXITCODE` variable inside a function created a local shadow, so the
wrapper could not read the exit status written by Git in its parent scope.

`WINDOW02.V6` prohibits assignments to `$LASTEXITCODE` in every Git/Python
wrapper, while retaining stderr capture and an immediate exit-code read after
the known executable returns. Regression tests enforce this invariant for the
installer and health checker. V6 uses fresh create-exclusive `-r6` paths and
preserves all V1--V5 evidence.

## Transport revision V7

The first automatic Window 02 worker created the persistent root-level
`.shadow-worker.lock` and `.shadow-cycle.lock` synchronization carriers. The
installed V6 health checker delegated to a contract verifier that treated
those runtime sidecars as unexpected contract evidence, so an otherwise valid
active worker could not pass health or automatic-run acceptance.

`WINDOW02.V7` is an operator-only remediation. It packages the corrected
metadata-only sidecar verifier and a health checker that binds both the exact
installed V6 package identity and the new V7 operator package identity. It
continues to verify the immutable V6 installation receipt, task XML, frozen
`r6` worker, journal, audit root, contract, and dependency lock. V7 contains no
installer and performs no task registration, enablement, disablement, start,
stop, deletion, worker replacement, broker mutation, or order submission.
Every V1--V6 artifact remains immutable historical evidence.

## Transport revision V8

The `2026-08-21T06:45:00+09:00` boundary was unavailable to the interactive
task token. Windows later recorded `LastTaskResult=0x800710E0` and Operational
Event 153 (`MissedTaskRejected`) for the exact root task when the host/session
became available. V7 correctly rejected health during that still-active missed
interval, but its gap-phase check treated the non-boundary `LastRunTime` as
permanent drift and therefore could not arm acceptance for the next automatic
boundary.

`WINDOW02.V8` remains operator-only. During a schedule gap only, it may classify
the previous boundary as `MISSED_SCHEDULE_VERIFIED_NEXT_BOUNDARY_READY` when
all of these exact conditions hold:

- task state is `Ready` and normalized result is exactly `0x800710E0`;
- `LastRunTime` is after the derived previous scheduled boundary;
- `NextRunTime` equals the derived next weekday `06:45` boundary;
- the enabled Operational log contains exactly one correlated exact-task event
  within 120 seconds of `LastRunTime`;
- that event is provider `Microsoft-Windows-TaskScheduler`, channel
  `Microsoft-Windows-TaskScheduler/Operational`, ID `153`, EventData name
  `MissedTaskRejected`, and contains exactly one `TaskName` data node;
- no event 100, 102, 107, or 110 for the exact task exists in that correlation
  interval.

The exception is prohibited during the active interval, startup allowance,
pre-start, and expired phases. It never converts a missed boundary into
automatic-run acceptance. All source, task XML, receipt, ACL, dependency,
contract, runtime, sidecar, safety, and no-mutation checks remain mandatory.

## Transport revision V9

Windows may publish the exact Event 153 only after the missed boundary's
five-minute startup allowance while the 84,300-second active interval is still
open. `WINDOW02.V9` therefore permits the same fully verified
`MISSED_SCHEDULE_VERIFIED_NEXT_BOUNDARY_READY` classification during either
`ACTIVE` or `GAP`. It remains prohibited during startup allowance, pre-start,
and expired phases.

When that exact classification succeeds during `ACTIVE`, health MUST NOT
require a running worker, journal, or runtime heartbeat that the rejected task
could not have produced. All Event 153 correlation, contradictory-event,
task-state, result, next-boundary, identity, ACL, dependency, contract, and
no-mutation requirements remain mandatory. The classification is readiness
for the next boundary only and MUST NOT satisfy start or completion acceptance.
