# Spec: Phillip Commodity Window 02 Automatic-Run Acceptance Toolkit V1

**Author:** AI_SCALPER Engineering

**Date:** 2026-08-05

**Status:** Approved for implementation

**Reviewers:** project owner, security reviewer, ship-gate reviewer

**Related specs:**
`specs/phillip_commodity_window_02_scheduler_v1.md`,
`specs/phillip_commodity_v6_postrun_acceptance_v3.md`

## Context

The verified Window 02 scheduler package installed
`AI_SCALPER-PhillipCommodityWindow02-ReadOnlyShadow` on Windows. The task is
`Ready`, its first automatic boundary is 17 August 2026 at 06:45 JST, and its
84,300-second worker is expected to remain `Running` until approximately
06:10 JST on the following day. The existing V6 post-run acceptance tool
cannot prove this lifecycle because it accepts only a completed task in
`Ready` state with result zero and a correlated Task Scheduler event 102.
Applying that rule while the Window 02 worker is healthy and `Running` would
produce a false rejection.

Window 02 therefore needs a source-bound, read-only acceptance toolkit with
two distinct claims. The first claim proves that Task Scheduler, rather than
a manual operator, started the expected task at an eligible boundary and that
authenticated runtime evidence advanced while the task remained healthy. The
second claim proves that the same scheduler instance later completed with
process result zero and terminal authenticated evidence. Neither claim
changes the task, the broker terminal, the contract, the journal, or order
capability.

The installed scheduler identity is package commit
`6bdd426ba02818bf3e3669a68820c027b3f6f25a`, package tree
`82a3c509d52d1bf92088d218aa81be1a25b15b24`, frozen worker commit
`da3190013d86426533019d6927a58181c624b1f8`, frozen worker tree
`9e84a0d7c9a5b3d4213c6abf0fdf1c8770361d10`, contract
`phillip-commodity-window-02-diagnostic-v1`, and contract payload SHA-256
`cbfd753b0aed2d66af56446adc734ce8d62666e309e91bf74d24b4cc56b613a2`.
These values are immutable inputs to this specification.

The acceptance toolkit is additionally bound to the V8 operator-only health
remediation at commit `7416ce02c0559033d0976d44f604e7f8155b134c` and tree
`2e0dd3d851fd69e3a96e526f809f02ae3ecc4c60`. A fail-closed Event 153
classification for an earlier missed schedule MAY establish readiness for a
strictly future eligible boundary. It MUST NOT be accepted as evidence that a
task started or completed.

## Functional Requirements

- FR-1: The toolkit MUST bind the exact installed scheduler package commit,
  package tree, frozen worker commit, frozen worker tree, task name, contract
  identifier, contract payload SHA-256, dependency-lock SHA-256, and signing
  key identifier documented in this specification.
- FR-2: The repository builder MUST produce one transferable ZIP containing
  the complete toolkit and an embedded content-addressed manifest; no sidecar
  manifest or external extraction helper MAY be required.
- FR-3: Every toolkit command MUST validate its own extracted flat inventory,
  member sizes, member SHA-256 values, toolkit source commit, and toolkit
  source tree before inspecting operational evidence.
- FR-4: A readiness command MUST verify the exact task definition, task state,
  next eligible boundary, installation receipt, receipt ACL, frozen worktree,
  dependency lock, contract authority, Task Scheduler Operational log, prior
  task states, and exact Commodity MT5 process path without accepting a run.
- FR-5: Every toolkit mode MUST NOT invoke `Start-ScheduledTask`, enable,
  disable, register, unregister, or modify a task; import MetaTrader5; write to
  the worker journal or audit root; change the contract; contact a broker; or
  submit an order.
- FR-6: Collection MUST require an explicit target boundary expressed as a
  canonical RFC 3339 timestamp with `+09:00`, at 06:45 JST on an eligible
  weekday, no earlier than `2026-08-17T06:45:00+09:00`, and before the
  scheduler end boundary `2026-10-13T00:16:00+09:00`.
- FR-7: Watch mode MUST poll local read-only state for one target boundary,
  collect the start archive once eligible, continue monitoring the same task
  instance, and collect the completion archive once eligible; it MUST time out
  without starting or restarting the task.
- FR-8: Start acceptance MUST require exactly one Task Scheduler event 107
  followed by exactly one event 100 for the same nonzero instance identifier,
  with monotonically increasing record identifiers and no correlated event
  110.
- FR-9: Start acceptance MUST require task state `Running`, `LastRunTime`
  within one minute before through five minutes after the target boundary, the
  five-minute startup allowance to have elapsed, and observation before the
  84,300-second active interval ends.
- FR-10: Start acceptance MUST require the Window 02 health checker to pass,
  authenticated status-only verification to return healthy and non-stale,
  and exactly one post-boundary audit/manifest pair whose authenticated
  projection matches the status heartbeat and contains one passing invocation
  terminal event.
- FR-11: Start collection MUST create one create-exclusive archive named
  `phillip-commodity-window-02-automatic-start-YYYYMMDDTHHMMSSZ.zip` with the
  exact start evidence inventory defined in Data Models and MUST immediately
  reverify the bytes it wrote.
- FR-12: Completion acceptance MUST take the verified start archive and its
  expected SHA-256 as inputs and MUST bind the exact target boundary, Task
  Scheduler instance identifier, start record identifier, start bundle
  identity, and start archive bytes.
- FR-13: Completion acceptance MUST require task state `Ready`, normalized
  unsigned `LastTaskResult=0`, the same `LastRunTime` accepted at start, and
  exactly one event 102 for the accepted instance after event 100 and no later
  than the completion observation.
- FR-14: Completion acceptance MUST run after the 84,300-second active
  interval and before the next eligible scheduler boundary, and MUST require a
  final healthy authenticated status plus an audit/manifest pair with a
  heartbeat no earlier than five minutes before the expected worker end.
- FR-15: Completion collection MUST create one create-exclusive archive named
  `phillip-commodity-window-02-automatic-completion-YYYYMMDDTHHMMSSZ.zip`,
  include the exact verified start archive as a nested member, include the
  exact completion evidence inventory defined in Data Models, and immediately
  reverify the bytes it wrote.
- FR-16: The pure-Python verifier MUST independently verify either archive
  from bytes and caller-supplied archive SHA-256 plus toolkit source
  commit/tree, without accessing Task Scheduler, the broker, Credential
  Manager, the live journal, or the original evidence directories.
- FR-17: All JSON readers MUST reject duplicate keys, non-object roots,
  noncanonical identity fields, and unexpected fields; all XML readers MUST
  reject DTD/entity declarations, unexpected namespaces, duplicate required
  nodes, oversized raw XML, and task/provider/channel projection drift.
- FR-18: Every readiness result, archive manifest, verifier result, and failure
  summary MUST preserve `order_capability=DISABLED`, `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `promotion_eligible=false`, zero broker
  orders, no broker mutation, and no Task Scheduler mutation.
- FR-19: Toolkit and acceptance archives MUST be deterministic for identical
  input bytes and normalized metadata, use sorted flat member paths, and reject
  duplicate, absolute, parent-traversal, directory, encrypted, appended, or
  unsupported ZIP members.
- FR-20: PowerShell native-process wrappers MUST run under Windows PowerShell
  5.1, tolerate informational native stderr, capture `$LASTEXITCODE`
  immediately without assigning to or shadowing it, restore caller error
  preferences, and reject missing or nonzero exit codes before parsing output.
- FR-21: Existing output paths MUST never be overwritten. Failure cleanup MUST
  remove only a partial file created by the current process when its filesystem
  identity is unchanged, and MUST preserve substitutions, symlinks, reparse
  points, collisions, and all previously verified evidence.
- FR-22: The toolkit MUST use distinct success states
  `PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_START_ACCEPTANCE_VERIFIED` and
  `PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_COMPLETION_VERIFIED`; a start
  archive MUST NOT claim process completion, and a completion archive MUST NOT
  claim off-host custody, promotion, or live-trading readiness.
- FR-23: Readiness MAY consume the exact V8 historical status
  `MISSED_SCHEDULE_VERIFIED_NEXT_BOUNDARY_READY` only while the requested
  target is strictly in the future. Start and completion acceptance MUST still
  require their own correlated Task Scheduler events and runtime evidence.

## Non-Functional Requirements

- NFR-P1: Watch mode MUST poll no more frequently than once every 15 seconds
  and MUST perform no more than two Task Scheduler state queries per poll.
- NFR-P2: After state first becomes eligible, each archive MUST be collected
  and locally reverified within 120 seconds on the reference Windows host,
  excluding time spent in an OS event-log call that itself times out.
- NFR-P3: Each Task Scheduler event XML document MUST be at most 512 KiB, an
  event set MUST contain at most 4,096 rows, each ordinary evidence member MUST
  be at most 16 MiB, and either acceptance archive MUST be at most 64 MiB.
- NFR-R1: Watch mode MUST have a caller-visible timeout and MUST exit nonzero
  after that timeout while preserving an already verified start archive.
- NFR-R2: Acceptance output writes MUST be create-exclusive and crash-safe;
  no successful or failed run may alter pre-existing bytes.
- NFR-S1: Filesystem inputs MUST be regular non-reparse files beneath exact
  expected roots, and directory enumeration MUST reject symlinks, junctions,
  hard-link count drift where observable, and unexpected members.
- NFR-S2: Collection and verification MUST use CPython 3.12 standard-library
  code under `-I -S -B`; no package installation or network access is allowed.
- NFR-S3: The toolkit MUST NOT export HMAC secret material. It MAY record the
  signing-key identifier and the fact that the source-host authenticator
  passed, but MUST record independent HMAC reverification as `false`.
- NFR-C1: PowerShell wrappers MUST support Windows PowerShell 5.1 and paths
  containing spaces; the Python core MUST pass on CPython 3.12 in normal and
  optimized (`-O`) modes.
- NFR-D1: Two toolkit builds from the same clean Git commit and tree MUST be
  byte-identical. Two acceptance builds from the same captured input bytes and
  normalized observation values MUST also be byte-identical.
- NFR-T1: Focused tests MUST cover every acceptance criterion plus duplicate
  JSON keys, XML projection drift, archive ambiguity, stale/future time,
  manual trigger evidence, wrong instance correlation, output collisions,
  path substitution, PowerShell native-exit handling, and safety scans.

## Acceptance Criteria

### AC-1: Deterministic single-file toolkit (FR-1, FR-2, FR-3, FR-19, NFR-D1)

Given a clean repository at one exact commit and tree
When the Window 02 acceptance toolkit is built twice
Then both commands produce one ZIP each with identical bytes and SHA-256
And each embedded manifest binds the exact installed scheduler and toolkit
source identities
And extracted inventory validation succeeds only for the exact flat members.

### AC-2: Pre-boundary readiness without acceptance (FR-4, FR-18, FR-22)

Given the verified Window 02 task is `Ready` before its target boundary
When the readiness command validates local prerequisites
Then it reports `PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE_READY`
And it reports the exact target boundary and disabled safety projection
And it creates neither a start archive nor a completion archive.

### AC-3: Readiness rejects drift (FR-1, FR-4, FR-21)

Given one task, receipt, ACL, worktree, lock, contract, log, prior-task, or MT5
process-path input differs from its exact required value
When readiness runs
Then it exits nonzero with a stable rejection code
And it does not create, replace, or remove evidence.

### AC-4: Automatic start provenance (FR-6, FR-8, FR-9)

Given an eligible target boundary and a task currently `Running` after startup
allowance
When event evidence contains one event 107 followed by one event 100 for the
same instance and contains no correlated event 110
Then start provenance is accepted
And the accepted last-run timestamp is bound to that target boundary.

### AC-5: Manual or ambiguous start rejected (FR-8, FR-17, NFR-T1)

Given event evidence with a correlated event 110, multiple matching starts,
multiple matching scheduled triggers, a zero/different instance, reordered
record identifiers, or raw XML projection drift
When start collection runs
Then collection exits nonzero
And no start acceptance archive is created.

### AC-6: Authenticated running evidence (FR-9, FR-10, NFR-P2)

Given the automatically started task remains `Running` within its active
interval
When health, status-only, and the unique matching audit pair are captured
after the five-minute startup allowance
Then the status is healthy and non-stale
And the audit terminal outcome is `PASS`
And its heartbeat matches the status transcript and is after task start.

### AC-7: Start archive claim boundary (FR-11, FR-18, FR-22, NFR-R2)

Given all start requirements pass
When start collection writes and reverifies its archive
Then the verifier returns
`PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_START_ACCEPTANCE_VERIFIED`
And `process_completed` is false
And all safety and mutation fields remain deny-only.

### AC-8: Running task is not completion (FR-12, FR-13, FR-22)

Given a valid start archive while the task remains `Running`
When completion collection is attempted
Then it exits nonzero with a completion-state rejection
And it never labels the run completed.

### AC-9: Correlated successful completion (FR-12, FR-13, FR-14)

Given a verified start archive and the same task instance later in `Ready`
state with normalized result zero
When one correlated event 102 follows its accepted event 100 and final
authenticated evidence satisfies the completion freshness window
Then completion evidence is accepted
And the same boundary, instance, and start identity are preserved.

### AC-10: Completion failure rejected (FR-13, FR-14, FR-22)

Given the task is missing event 102, reports a nonzero result, has a different
last-run timestamp or instance, has stale/failed final status, or is observed
at or after the next eligible boundary
When completion collection runs
Then it exits nonzero
And no completion acceptance archive is created.

### AC-11: Self-contained completion archive (FR-12, FR-15, FR-16)

Given valid start and completion evidence
When completion collection writes and reverifies the archive
Then it returns
`PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_COMPLETION_VERIFIED`
And the exact start archive is included and fully reverified as a nested member
And the completion manifest binds both archive identities.

### AC-12: Offline byte verification (FR-16, FR-17, FR-19)

Given a copied acceptance archive, its expected SHA-256, and expected toolkit
source commit/tree
When the pure-Python verifier runs without live Windows resources
Then a valid archive verifies from contained bytes alone
And any changed, appended, duplicated, encrypted, oversized, or unexpected
member causes rejection.

### AC-13: Bounded read-only watcher (FR-5, FR-7, NFR-P1, NFR-R1)

Given watch mode starts before or during one target boundary
When it observes the task through start and completion eligibility
Then it emits each archive at most once and exits zero only after completion
verification
And a timeout exits nonzero without starting, restarting, or changing the task
And a verified start archive survives a later completion timeout.

### AC-14: Output collision and substitution safety (FR-21, NFR-R2, NFR-S1)

Given an output path already exists or is replaced during a failed write
When collection attempts cleanup
Then all pre-existing or replacement bytes remain unchanged
And only an unchanged partial file created by that process may be removed.

### AC-15: Strict structured input handling (FR-17, NFR-P3, NFR-S1)

Given duplicate JSON keys, unknown fields, malformed timestamps, DTD/entity
XML, reparse inputs, traversal paths, unsupported ZIP flags, or an input over
its stated limit
When collection or verification parses the input
Then it fails closed with a stable rejection code before producing acceptance.

### AC-16: Isolated dependency-free execution (FR-16, FR-20, NFR-S2, NFR-C1)

Given only the frozen CPython 3.12 runtime and Windows PowerShell 5.1
When readiness, watch, collection, and offline verification execute
Then Python uses `-I -S -B`
And no site package or network dependency is required
And native stderr does not mask the captured native exit code.

### AC-17: Secret and authority boundary (FR-10, FR-16, FR-18, NFR-S3)

Given authenticated source-host status and audit evidence
When either acceptance archive is created
Then no credential or HMAC secret is exported
And the manifest records source-host authentication as true
And independent HMAC reverification as false
And the archive makes no live, promotion, or custody claim.

### AC-18: Full verification gates (FR-18, FR-20, NFR-C1, NFR-T1)

Given the approved implementation and adversarial fixtures
When focused tests, related scheduler/post-run regression tests, full normal
and optimized test suites, compilation, diff checks, and static safety scans
run
Then every gate passes
And scans find no task-start, task-registration, broker-order, MetaTrader5
import, credential-export, or network primitive in the acceptance tooling.

## Edge Cases

- EC-1: The target timestamp has `Z`, another offset, seconds other than zero,
  a non-06:45 local time, a weekend, or lies outside the schedule → reject it
  before polling.
- EC-2: Watch mode starts after the startup allowance but before worker end →
  allow start collection if the task is still `Running` and all historical
  provenance and fresh runtime evidence remain available.
- EC-3: Watch mode starts after worker completion without a verified start
  archive → reject completion; do not reconstruct a completed claim that
  bypasses the running-state acceptance.
- EC-4: Task state is `Queued` or `Ready` during startup allowance → keep
  polling until allowance expiry; after expiry, reject unless state is
  `Running`.
- EC-5: Task state is `Running` but `LastRunTime` belongs to another boundary
  → reject the start.
- EC-6: An event 107 and event 100 exist but use different instance IDs →
  reject provenance.
- EC-7: Event 110 exists for the accepted instance or within the correlation
  tolerance around its start → reject as possible manual demand start.
- EC-8: The event log is disabled, cleared, wraps past required records, or
  cannot be read → reject; never infer automatic provenance from task state.
- EC-9: Status-only exits zero but its transcript is missing, duplicated, or
  inconsistent with the selected audit pair → reject.
- EC-10: More than one audit pair matches the accepted heartbeat → reject
  ambiguity rather than selecting by filename or filesystem timestamp.
- EC-11: The worker completes with result zero but event 102 is absent → reject
  completion until correlated event evidence is available within the window.
- EC-12: The worker completes after its expected end but before the next
  boundary → accept only if event ordering, result, final heartbeat, and the
  specified completion freshness limits all pass.
- EC-13: The next eligible boundary arrives while the prior task still runs →
  reject completion and report overlap; do not change `IgnoreNew` behavior.
- EC-14: The start archive hash supplied to completion does not match its
  bytes or its nested source identity → reject before reading completion
  evidence.
- EC-15: A prior V4, V5, V6, or obsolete Window 02 task is enabled → readiness
  and collection reject without changing it.
- EC-16: The exact Commodity MT5 process is absent before the target boundary
  → readiness rejects; collection still never launches the terminal.
- EC-17: PowerShell receives informational Git/Python stderr with native exit
  code zero → retain the output and continue; missing or nonzero exit code →
  reject before JSON parsing.
- EC-18: A destination archive, temporary file, dangling symlink, junction, or
  reparse point exists → preserve it and reject the collision.
- EC-19: Local wall clock moves backward, evidence is over five seconds in the
  future, or observed timestamps are not monotonic → reject the affected
  phase.
- EC-20: Start succeeds but completion times out or fails → retain and report
  the verified start archive while making no completion claim.

## API Contracts

The toolkit exposes local command-line contracts only. It MUST NOT expose or
call an HTTP method/path such as `GET /api/acceptance` or
`POST /api/acceptance`, open a listening socket, or send network traffic.

### PowerShell readiness

```powershell
& .\Test-PhillipCommodityWindow02AutomaticRunAcceptanceReadiness.ps1 `
  -TargetBoundary "2026-08-17T06:45:00+09:00"
```

Exit zero returns a formatted object with status
`PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE_READY`. Any failed
precondition exits nonzero and produces no archive.

### PowerShell watch and collection

```powershell
& .\Invoke-PhillipCommodityWindow02AutomaticRunAcceptance.ps1 `
  -Mode Watch `
  -TargetBoundary "2026-08-17T06:45:00+09:00" `
  -OutputRoot "C:\AI_SCALPER_PRIVATE\phillip-window-02-acceptance"
```

`-Mode` accepts exactly `Watch`, `CollectStart`, or `CollectCompletion`.
`CollectCompletion` additionally requires `-StartArchive` and
`-ExpectedStartArchiveSHA256`. `Watch` calculates a bounded timeout from the
target boundary and the 84,300-second worker duration; an optional shorter
timeout may reduce but MUST NOT extend that bound.

### Pure-Python offline verification

```powershell
& $releasePython -I -S -B `
  .\phillip_commodity_window_02_automatic_run_acceptance.py `
  verify-start `
  --archive $startArchive `
  --expected-archive-sha256 $startSHA256 `
  --expected-toolkit-source-commit $toolkitCommit `
  --expected-toolkit-source-tree $toolkitTree

& $releasePython -I -S -B `
  .\phillip_commodity_window_02_automatic_run_acceptance.py `
  verify-completion `
  --archive $completionArchive `
  --expected-archive-sha256 $completionSHA256 `
  --expected-toolkit-source-commit $toolkitCommit `
  --expected-toolkit-source-tree $toolkitTree
```

The Python CLI prints one JSON object to stdout. Rejection prints a stable
single-line error to stderr, returns exit code 2, and prints no verified
status.

```typescript
interface StartAcceptanceSummary {
  status: "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_START_ACCEPTANCE_VERIFIED";
  archive_sha256: string;
  bundle_identity_sha256: string;
  target_boundary_utc: string;
  scheduler_instance_id: string;
  task_start_record_id: number;
  process_completed: false;
  order_capability: "DISABLED";
  live_allowed: false;
}

interface CompletionAcceptanceSummary {
  status: "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_COMPLETION_VERIFIED";
  archive_sha256: string;
  bundle_identity_sha256: string;
  start_archive_sha256: string;
  scheduler_instance_id: string;
  task_completion_record_id: number;
  process_exit_code: 0;
  order_capability: "DISABLED";
  live_allowed: false;
}
```

## Data Models

### Toolkit manifest

| Field | Type | Constraints |
|---|---|---|
| `schema_version` | string | Exact `phillip-commodity-window-02-automatic-run-acceptance-toolkit-v1` |
| `source` | object | Exact clean toolkit branch, 40-hex commit, and 40-hex tree |
| `installed_scheduler` | object | Exact identities in FR-1 plus first/end boundaries and worker duration |
| `members` | array | Sorted exact flat inventory; unique path, byte size, lowercase SHA-256 |
| `safety` | object | Exact disabled/no-mutation projection |
| `toolkit_identity_sha256` | string | SHA-256 of canonical manifest without this field |

### Task observation

| Field | Type | Constraints |
|---|---|---|
| `schema_version` | string | Exact `phillip-commodity-window-02-task-observation-v1` |
| `captured_at_utc` | string | Canonical UTC, monotonic, no more than five seconds in future |
| `target_boundary_utc` | string | Canonical conversion of the explicit eligible JST boundary |
| `task_name` | string | Exact Window 02 task name and root task path |
| `task_state` | string | `Running` for start; `Ready` for completion |
| `last_run_at_utc` | string | Bound to target boundary within FR-9 tolerance |
| `last_task_result` | integer | Unsigned 32-bit; completion requires zero |
| `next_run_time_local` | string | Canonical Tokyo timestamp after target boundary |
| `principal` | object | Exact receipt SID, `InteractiveToken`, `LeastPrivilege` |
| `action` | object | Exact Python, arguments, and frozen working directory from receipt |
| `prior_task_states` | object | Every present historical task is `Disabled` |
| `collection` | object | Read-only APIs and both mutation values `NOT_PERFORMED` |

### Task Scheduler event evidence

| Field | Type | Constraints |
|---|---|---|
| `schema_version` | string | Exact `phillip-commodity-window-02-task-scheduler-events-v1` |
| `captured_at_utc` | string | Canonical UTC at or after task observation |
| `channel` | string | `Microsoft-Windows-TaskScheduler/Operational` |
| `provider` | string | `Microsoft-Windows-TaskScheduler` |
| `task_name` | string | Exact root-qualified Window 02 task |
| `query` | object | Event IDs 100, 102, 107, 110; exact time range; log enabled |
| `events` | array | Ordered unique records with raw XML and its SHA-256 |
| `collection` | object | `Get-WinEvent`, messages not trusted, no mutation |

### Start archive inventory

| Member | Purpose | Binding |
|---|---|---|
| `automatic-start-manifest.json` | Start claim and content index | Canonical bundle identity |
| `audit-export.json` | Matching post-boundary authenticated runtime projection | Audit SHA-256 |
| `audit-manifest.json` | Source-chain and audit binding | Authenticated manifest self-hash |
| `contract-authentication.json` | Fresh authoritative Window 02 contract result | Contract/build/lock identity |
| `health-transcript.txt` | Exact Window 02 health output | Running/ACTIVE/healthy fields |
| `installation-receipt.json` | Installed scheduler authority | Exact receipt schema and fields |
| `installed-task.xml` | Installed task bytes | Receipt-exported XML SHA-256 |
| `receipt-acl-evidence.json` | Receipt ownership/write-boundary observation | Fresh ACL capture |
| `runtime-status-transcript.txt` | Authenticated status-only result | Healthy, non-stale heartbeat |
| `task-observation.json` | Structured scheduler snapshot | Start state and boundary |
| `task-scheduler-events.json` | Raw local trigger evidence | Events 107/100 and no 110 |

### Completion archive inventory

| Member | Purpose | Binding |
|---|---|---|
| `automatic-completion-manifest.json` | Completion claim and content index | Canonical bundle identity |
| `automatic-start-acceptance.zip` | Exact verified start proof | Caller hash and nested full verification |
| `final-audit-export.json` | Final authenticated runtime projection | Audit SHA-256 |
| `final-audit-manifest.json` | Final source-chain and audit binding | Authenticated manifest self-hash |
| `completion-health-transcript.txt` | Exact post-run health output | Ready/result-zero fields |
| `completion-installed-task.xml` | Completion-time task bytes | Same receipt XML SHA-256 |
| `completion-receipt-acl-evidence.json` | Completion-time receipt ACL | Fresh ACL capture |
| `completion-runtime-status-transcript.txt` | Final authenticated status-only result | Healthy final heartbeat |
| `completion-task-observation.json` | Structured post-run scheduler snapshot | Ready/result zero/same boundary |
| `task-scheduler-events.json` | Complete raw trigger lifecycle | Same 107/100 plus correlated 102, no 110 |

### Acceptance manifest invariants

| Field | Type | Constraints |
|---|---|---|
| `schema_version` | string | Phase-specific exact v1 schema |
| `status` | string | Exact phase-specific verified status |
| `candidate_id` | string | Exact `phillip-commodity` |
| `task_name` | string | Exact Window 02 task |
| `toolkit` | object | Toolkit commit, tree, manifest hash, identity hash |
| `installed_scheduler` | object | Exact package/worker/contract identities |
| `target_boundary` | object | Exact local/UTC boundary, expected end, next boundary |
| `scheduler_observation` | object | Phase state, result, and correlated event projection |
| `authenticated_evidence` | object | Heartbeat, audit IDs/hashes, source-host authentication |
| `members` | array | Exact sorted inventory excluding manifest |
| `evidence_set_sha256` | string | Canonical digest of member rows |
| `external_custody` | object | Required later, performed false, no attestation |
| `safety` | object | Exact deny-only projection and zero broker orders |
| `bundle_identity_sha256` | string | SHA-256 of canonical manifest without this field |

## Out of Scope

- OS-1: Starting, retrying, repairing, enabling, disabling, registering, or
  deleting any Scheduled Task.
- OS-2: Installing Python, dependencies, MT5, credentials, the Window 02
  scheduler, or the Window 02 contract.
- OS-3: Broker login, market-data collection, MetaTrader5 import, order
  construction/submission, live trading, or promotion eligibility.
- OS-4: Independent HMAC verification outside the source host, HMAC secret
  export, independent witness attestation, or legal/compliance approval.
- OS-5: Upload to Google Drive, external WORM custody, retention enforcement,
  or a custody acknowledgement receipt; these require a separate reviewed
  handoff specification after local completion acceptance.
- OS-6: Replacing or modifying the installed Window 02 health checker,
  scheduler installer, frozen worker, contract artifacts, journal, audit
  exports, or historical V4/V5/V6 evidence.
- OS-7: Automatically installing the acceptance watcher as a service, startup
  item, or Scheduled Task.
- OS-8: Accepting a run solely from console text, task state, filesystem
  timestamps, event messages, or a manually supplied success assertion.
