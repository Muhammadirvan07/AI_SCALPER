# Windows Demo-Soak Operations

## Outcome

AI_SCALPER now has a side-effect-free Windows operations contract for reviewing
the host layout that must exist before controlled manual-demo work and a future
demo-auto soak. It validates the exact release, Python runtime, MT5 terminal,
broker account alias, symbol specifications, state paths, service identity,
off-host provider references, and safety thresholds.

It also produces three review artifacts:

1. Task Scheduler XML for a deny-only decision runtime;
2. Task Scheduler XML for a deny-only executor/reconciler boundary; and
3. Task Scheduler XML for a status-only watchdog.

Each task has a read-only PowerShell validation script. The module does not
register or start those tasks.

## Important safety boundary

This is an architecture and operations-plan component, not a deployment command.
All generated plans preserve:

```text
execution_enabled=false
task_install_allowed=false
safe_to_demo_auto_order=false
live_allowed=false
promotion_eligible=false
order_capability=DISABLED
max_lot=0.01
```

The two process definitions are intentionally required to include
`--deny-orders`. The executor/reconciler definition proves process separation and
future composition shape, while remaining reconciliation-only in this version.

The demo-auto decision IPC consumer remains policy-locked in this version. It
can consume and verify one signed decision/stage/permit/environment-arm set and
produce a sealed risk/intent input through a sealed consume-only port, but it
has no publish/signing-provider surface or broker adapter. The dormant
composition seam can reach the existing executor only after every sealed
authority passes. Session dispatch is journal-bound and restart-safe; uncertain
broker submission remains reconciliation-required and cannot be resent. A
passing consumer/dispatch test still does not start the soak while the central
policy lock is false.

## Required Windows layout

Use a clean release directory separate from the Git working tree. Keep mutable
state under an operations directory such as `C:\ProgramData\AI_SCALPER\state`,
not in `C:\AI_SCALPER` and not inside the release bundle. Journal, risk,
supervisor, manual-demo, and soak databases must use different files.

The following items are references, not embedded values:

- broker account custody;
- supervisor HMAC;
- execution-journal HMAC;
- risk-ledger HMAC;
- manual-demo HMAC;
- an independent manual-demo off-host custody HMAC;
- soak-tracker HMAC; and
- off-host delivery HMAC.

They must resolve through Windows Credential Manager during a separately reviewed
deployment integration. Passwords, account logins, API keys, or tokens must never
be added to the plan, task arguments, repository, XML, or validation script.

The manual-demo custody key and provider must be operated independently from
the local tracker key. A current signed high-water checkpoint is mandatory for
aggregate issuance, so restoring an older but internally valid tracker database
fails closed.

Off-host heartbeat, audit, backup, alert, and receipt-key locations are stored as
opaque provider IDs. A reviewed adapter—not this file—maps those IDs to actual
destinations.

## Task Scheduler review

The generated XML uses:

- boot trigger with deterministic delay;
- S4U logon;
- least privilege;
- one instance at a time;
- network-required execution;
- bounded restart on failure;
- no execution time limit for the continuous process; and
- disabled start-on-demand.

The validation script only calls `Get-ScheduledTask` and compares the installed
action, arguments, working directory, principal run level, and logon type. Review
the XML and script before any operator imports a task. Import/install remains an
external action and must not be automated from the development workspace.

## Failure-drill evidence

The failure-drill tracker requires signed evidence for VPS reboot, MT5 restart,
network partition, disk full, SQLite contention, SQLite corruption, clock drift,
and release rollback. A screenshot or verbal confirmation is insufficient by
itself; the observation must bind the evidence hash, exact plan/release/broker
identity, UTC time, result, and independent key ID.

A later signed failure supersedes an earlier pass. Missing, unsigned, forged,
future, mismatched, duplicated, or ambiguous evidence keeps the drill gate
incomplete. Even eight signed passes only complete the failure-drill sub-gate—it
does not enable demo-auto or live trading.

## What remains external

Before demo-auto soak can begin, the exact Windows host still needs reviewed task
installation, provisioned Credential Manager references, real provider adapters,
signed delivery acknowledgements, clock/disk/Event Log/backup attestations, ten
clean manual-demo orders, an offline-issued RSA launcher policy/attestation,
reviewed IPC/session/projection provider wiring, independent approval, and a
short-lived promotion control. After that, the soak itself must still
achieve 30 days, 50 fills, at least 20 XAU fills, and zero critical incidents.

Risk feasibility is also an acceptance input. With `0.01` lot and the locked
absolute caps, some broker symbols cannot provide a valid stop after spread,
commission, slippage, and stop-level constraints. Those candidates must remain
`WAIT`; operations must not loosen the cap merely to increase fill count.

Live trading remains later still: each lane must meet its forward/OOS, duration,
parity, cost-stress, drawdown, broker, security, and legal gates. None of those
facts can be created by local code or a unit test.

See [the normative specification](../specs/windows_demo_soak_operations_v1.md)
for exact validation and acceptance rules.
