# Windows External Status Monitor v1

## Status

- Release profile: `WINDOWS_EXTERNAL_STATUS_MONITOR_V1`
- Runtime class: separately reviewed status-only monitor
- Broker mutation capability: `DISABLED`
- Order capability: `DISABLED`
- Live allowed: `false`
- Safe to demo-auto order: `false`
- Maximum lot: `0.01`

This contract closes the local implementation gap identified by
`windows_dual_release_demo_soak_operations_v2.md`. It does not install a
Windows task, materialize a provider, resolve a credential, initialize MT5,
open demo-auto, or submit an order.

## Security boundary

1. The monitor MUST run under a third identity that is distinct from the
   decision and execution service identities.
2. The monitor MUST bind the exact decision/execution service IDs, configured
   release identities, task-definition hashes, service-account IDs, decision
   IPC binding, heartbeat destination, and alert destination.
3. The monitor source is a reviewed external status provider. Every snapshot
   MUST be aware UTC, content addressed, sequence chained, externally
   attested, and bound to the exact configured services.
4. Durable monitor progress MUST use an external checkpoint CAS. The
   checkpoint is advanced only after every required heartbeat, alert, and
   incident-latch acknowledgement is independently verified.
5. A critical assessment MUST be written to a separately reviewed external
   incident latch before its alert is considered complete. The monitor has no
   authority to clear the latch, mutate the broker, or resume trading.
6. Heartbeats and alerts MUST use distinct destinations and durable outboxes.
   Signed remote acknowledgements are mandatory. Missing or invalid
   acknowledgement is fail-closed.
7. The monitor MUST evaluate:
   - decision and execution task/process state;
   - signed status freshness and chain validity;
   - execution restart reconciliation;
   - trusted-clock drift;
   - free disk;
   - MT5 connectivity;
   - signed news freshness;
   - decision IPC continuity;
   - immutable audit-export freshness;
   - backup-anchor freshness; and
   - off-host delivery health.
8. Snapshot replay, fork, rollback, future timestamps, identity drift, stale
   inputs, unsafe booleans, non-finite values, unverified source signatures,
   or provider acknowledgement drift MUST fail closed.
9. A cycle deadline failure MUST terminate the process boundary. A Python
   worker that exceeded its deadline may not be allowed to return later and
   advance monitor state.
10. The module MUST NOT import `MetaTrader5`, broker adapters, risk, permit,
    executor, reconciliation, credential, subprocess, socket, or Task
    Scheduler mutation code.

## Runtime configuration

The canonical `windows-external-status-monitor-config-v1` document binds:

- monitor, decision, and execution service identities;
- decision/execution configured release identities;
- task definitions and service accounts;
- decision IPC binding;
- external snapshot/checkpoint/latch provider IDs;
- heartbeat and alert destinations;
- bounded polling and cycle deadlines;
- clock/disk/status/audit/backup thresholds; and
- deny-only safety locks.

No password, account login, API token, signing key, URL, mutable status, or
broker symbol belongs in the configuration.

## Status snapshot

One `windows-external-status-snapshot-v1` contains:

- a monotonic sequence and predecessor SHA-256;
- the reviewed source provider and source-attestation SHA-256;
- exact decision and execution observations;
- one host/operations observation; and
- the same deny-only safety locks.

The execution observation MUST prove restart reconciliation. Both service
observations MUST prove status signature and chain verification. A snapshot is
not trusted merely because a provider returned a Python object; all identities,
hashes, timestamps, sequence continuity, and safety values are independently
validated by the monitor.

## Cycle ordering

For each cycle:

1. read the externally held checkpoint;
2. request exactly its successor snapshot;
3. validate and assess the snapshot;
4. if critical, obtain a verified incident-latch acknowledgement;
5. publish and verify the off-host alert when critical;
6. publish and verify the off-host monitor heartbeat; and
7. advance the checkpoint through verified compare-and-swap.

Any failure leaves the checkpoint unchanged. Idempotent envelope and incident
IDs make a retry safe after a process crash.

## Acceptance criteria

- AC-1: a fully healthy exact snapshot produces `HEALTHY` with no reason code.
- AC-2: every monitored threshold and identity drift produces a deterministic
  `CRITICAL` reason code.
- AC-3: sequence replay, fork, rollback, invalid checkpoint, and unverified CAS
  acknowledgement fail closed.
- AC-4: a critical cycle latches the incident and verifies an alert before the
  checkpoint advances.
- AC-5: a healthy cycle emits only a verified heartbeat before the checkpoint
  advances.
- AC-6: delivery, latch, source, clock, or checkpoint failure never advances
  durable progress.
- AC-7: caller-created subclasses or duck-typed contracts are rejected at
  authority boundaries.
- AC-8: timeout and signal-stop behavior are bounded and deterministic.
- AC-9: all safety locks remain false/disabled and maximum lot remains `0.01`.
- AC-10: normal and optimized full-repository regressions remain green.
- AC-11: the deterministic monitor release contains only the status-monitor
  contract, factory template, configured-release verifier, RSA public
  verifier, loader, validator, and runner required by the exact allowlist.
- AC-12: base/configured identity drift, cross-profile launcher trust,
  tampered/extra/empty release members, symlink/reparse points, unreviewed
  imports, and unsealed factory results fail before a monitor cycle.

## External blockers retained

- real provider implementations and independent review;
- Windows Credential Manager and external key/CAS custody;
- reviewed secret-free monitor overlay and exact configured-release acceptance
  on the target Windows host;
- offline launcher-policy and attestation issuance;
- exact Windows/NTFS/Task Scheduler/ACL/service-account acceptance;
- real off-host heartbeat/alert acknowledgement;
- signed failure drills; and
- manual activation approval.
