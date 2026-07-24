# Windows Demo-Soak Operations v1

## Status

This specification defines a **local, deny-only operations foundation** for the
Windows host that will eventually support controlled manual-demo validation and a
demo-auto soak. It does not authorize installation, order submission, demo-auto,
or live trading.

The typed implementation is `live_runtime/demo_soak_operations.py`. Strict
operator input and immutable review bundles are implemented by
`live_runtime/demo_soak_operations_artifacts.py` and exposed through the
deny-only `prepare_windows_demo_soak_operations.py` CLI. Their immutable safety
state is always:

- `execution_enabled = false`
- `task_install_allowed = false`
- `safe_to_demo_auto_order = false`
- `live_allowed = false`
- `promotion_eligible = false`
- `order_capability = DISABLED`
- `max_lot = 0.01`

## Functional requirements

### FR-1 — Clean release binding

An operations plan MUST bind a clean, tracked release outside the source
repository. The binding includes exact full Git commit and tree SHAs, archive,
manifest, configuration, and reproducibility-receipt SHA-256 values. Every
process entrypoint and the watchdog entrypoint MUST appear in the tracked release
file map with its exact SHA-256. Dirty, untracked, nested-in-repository, missing,
or hash-mismatched builds fail closed.

### FR-2 — Exact runtime and broker binding

The plan MUST bind:

- CPython 3.12 patch version, x86-64 architecture, executable SHA-256,
  dependency-lock SHA-256, and SBOM SHA-256;
- the absolute `terminal64.exe` path, terminal SHA-256 and build number;
- exact broker candidate, company, server, `DEMO` environment, account-alias
  SHA-256, and account currency; and
- canonical-to-broker symbol mappings with exact broker-specification SHA-256.

Raw account login, password, token, or secret material is prohibited.

### FR-3 — Credential references only

The plan MUST contain distinct Windows Credential Manager references for broker
account custody and supervisor, journal, risk-ledger, manual-demo, soak-tracker,
manual-demo external-custody, and off-host HMAC keys. The external-custody key
MUST be distinct from the local manual-demo tracker key. A reference contains
only purpose, target name, key ID,
and backend name. Missing purposes, alternate backends, secret-like keys, or
secret-like command values fail closed.

The module never calls Windows Credential Manager.

### FR-4 — Two-process separation

Exactly two continuously managed runtime process definitions are required:

1. `DECISION_RUNTIME`; and
2. `EXECUTOR_RECONCILER`.

Both use the same reviewed release root and least-privilege service identity,
but distinct task names and tracked entrypoints. Both MUST include
`--deny-orders`; live, demo-auto, enable-order, allow-order, or enabled broker
mutation settings are rejected. This v1 plan therefore models only the safe
composition boundary, not an order-capable launcher.

### FR-5 — Runtime state isolation

Execution journal, risk ledger, supervisor, manual-demo tracker, and soak tracker
SQLite paths MUST be distinct local absolute paths outside both source repository
and release tree. Logs and immutable audit export use separate directories. Path
traversal, UNC paths, relative paths, and code-tree runtime state fail closed.

### FR-6 — Off-host provider references

Heartbeat, audit, backup, alert, and remote-receipt-key destinations are opaque,
distinct provider IDs. URLs and inline endpoints are rejected. Deployment must
map these IDs through a separately reviewed adapter and obtain signed remote
acknowledgements.

### FR-7 — Security posture and thresholds

The configuration requires:

- VPN-only RDP scope;
- no public RDP exposure;
- MFA;
- least-privilege Windows service account;
- exact firewall-policy SHA-256;
- a stable Windows Event Log source;
- clock drift no greater than one second;
- at least 5 GiB configured free-disk floor (10 GiB default);
- heartbeat age no greater than 30 seconds;
- audit-export age no greater than 300 seconds;
- backup-anchor age no greater than 24 hours; and
- watchdog cadence between 10 and 60 seconds.

Relaxed thresholds or missing hardening fail closed.

### FR-8 — Task Scheduler definitions

The plan renders deterministic UTF-16-declared Task Scheduler XML for the two
runtime roles and one status-only watchdog. Definitions use a boot trigger, S4U,
least privilege, single-instance behavior, bounded restart, and disable
start-on-demand. The watchdog receives `--status-only` and `--deny-orders`.

The module also renders deterministic, read-only PowerShell validation commands
using `Get-ScheduledTask`. It MUST NOT emit or execute task registration, task
start, shell execution, deployment, credential access, or broker mutation.

### FR-9 — Required failure drills

The manifest contains exactly these drills:

1. VPS reboot;
2. MT5 restart;
3. network partition;
4. disk full;
5. SQLite contention;
6. SQLite corruption;
7. clock drift; and
8. release rollback.

Each observation binds the plan, clean release, candidate, server, account alias,
evidence SHA-256, UTC timestamp, outcome, and observer key ID. The observation is
HMAC-signed using injected secret material that is never persisted by this
module.

Unsigned, forged, future, pre-manifest, binding-mismatched, replayed, or ambiguous
latest observations fail closed. The latest valid observation controls a drill;
a later signed failure invalidates an earlier pass. The tracker may report
`SIGNED_FAILURE_DRILLS_COMPLETE` only when all eight latest observations are
valid signed passes.

Completing the drill gate still does not set any order, demo-auto, promotion, or
live flag.

### FR-10 — Strict immutable operator review bundle

The operator CLI MUST accept one exact
`windows-demo-soak-operations-input-v1` JSON object. Unknown or duplicate
fields, non-finite numbers, raw secret-like fields or values, symlinks/reparse
points, non-regular files, unstable reads, oversized input, and noncanonical
bindings fail closed.

The generated
`windows-demo-soak-operations-review-bundle-v1` artifact MUST bind:

- the canonical operations plan and its SHA-256;
- the exact failure-drill manifest and its SHA-256;
- all three deterministic Task Scheduler XML reviews;
- all three read-only PowerShell validation scripts;
- the deny-only readiness assessment;
- explicit false side-effect claims; and
- all central safety locks.

The bundle has one content SHA-256 over every field except that hash itself.
Verification MUST reconstruct the typed plan, failure-drill manifest, scheduler
reviews, readiness result, effects, and safety state. Any change to any
component fails verification.

The output path is create-exclusive. Existing files and symlinks MUST never be
overwritten. The CLI MUST NOT access credentials, install or start tasks, launch
processes, access a network, initialize MT5, or call an order API.

## Non-functional requirements

- Validation and rendering are pure and deterministic.
- No import of `MetaTrader5`, subprocess, shell, socket, credential, registry, or
  task-scheduler mutation APIs.
- No background thread or process is started.
- Every timestamp is timezone-aware UTC.
- Every cryptographic reference uses a full SHA-256 except full Git object SHAs,
  which use 40 hexadecimal characters.
- Secret material is accepted only by the explicit in-memory signing/verifying
  boundary and is never included in canonical output.

## Acceptance tests

`test_live_runtime_demo_soak_operations.py` and
`test_windows_demo_soak_operations_artifacts.py` verify:

- valid exact two-process deny-only plans;
- deterministic XML and read-only PowerShell output;
- clean/tracked release and exact entrypoint binding;
- rejection of public RDP, missing VPN/MFA/least privilege, raw secrets, URLs,
  relaxed thresholds, code-tree state paths, and order-enabling arguments;
- exact CPython/MT5/demo-account constraints;
- unsigned, forged, future, mismatched, failed-latest, and replayed drill evidence;
  and
- preservation of all safety locks even when every signed drill passes.
- strict JSON input, immutable create-exclusive output, full deterministic
  bundle reconstruction, tamper detection, and operator-only release
  membership; and
- absence of task, process, MT5, or broker-mutation calls from the review CLI.

## External operational gates

Local software validation cannot substitute for:

- review and installation of Task Scheduler definitions on the exact VPS;
- provisioning and independent attestation of Credential Manager targets;
- endpoint mapping and signed off-host delivery tests;
- clock, disk, Event Log, audit-export, backup, and restore validation;
- ten clean controlled manual-demo orders;
- independent approval and short-lived demo-auto permit/arm controls;
- 30 days, 50 fills, and at least 20 XAU fills of clean demo-auto soak;
- 20 broker sessions, eight weeks, forward/OOS lane thresholds, parity, and cost
  stress evidence; and
- legal, security, and operator approval.

No result from this module is promotion evidence.
