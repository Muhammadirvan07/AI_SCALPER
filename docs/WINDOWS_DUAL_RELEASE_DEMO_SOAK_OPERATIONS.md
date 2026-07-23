# Windows Dual-Release Demo-Soak Operations

## Current outcome

The current Windows topology is now represented by a strict v2 review contract:

- one deterministic `WINDOWS_DECISION_SERVICE_V1` release;
- one deterministic `WINDOWS_GATED_EXECUTION_SERVICE_V1` release;
- one separate CPython 3.12 environment and least-privilege identity per
  release;
- one explicitly bound `decision-ipc-binding-v2` boundary; and
- one separately reviewed external monitor reference.

The v2 contract does not reuse a release root, Python environment, or service
identity. It does not invent a release-local watchdog: no production watchdog
entrypoint currently exists in either service release.

The legacy v1 operations artifact remains readable for audit history, but its
single-release/fictitious-entrypoint model is not an accepted demo-auto host
contract.

## Review-only safety boundary

The v2 CLI is:

```text
prepare_windows_dual_release_demo_soak_operations.py
```

It exists only in the operator tooling release. It is absent from the decision,
execution, and read-only shadow service releases.

Every generated result is fixed to:

```text
execution_enabled=false
task_install_allowed=false
validation_tasks_only=true
safe_to_demo_auto_order=false
live_allowed=false
promotion_eligible=false
order_capability=DISABLED
max_lot=0.01
```

The CLI does not read Credential Manager, import providers, initialize MT5,
install or start a task, launch a process, access the network, or call an order
API.

## Exact input

Create a non-secret
`windows-dual-release-demo-soak-operations-input-v2` document outside the
repository. It binds:

- both clean release identities, manifests, archives, commit/tree, allowlists,
  reproducibility receipts, and tracked entrypoint hashes;
- both exact Python executables, dependency locks, and SBOMs;
- distinct decision, execution, and monitor service identities;
- the exact Phillip commodity demo account, terminal, `XAUUSD.ps01`, and broker
  specification hash;
- Windows Credential Manager reference IDs only;
- distinct runtime databases outside source and both releases;
- exact decision IPC path/binding/ACL/provider custody;
- off-host heartbeat/audit/backup/alert provider IDs;
- external monitor implementation/configuration/task-definition hashes; and
- VPN/MFA/firewall/Event Log and safe health thresholds.

Unknown fields, inline secrets, URLs in provider IDs, path collisions, release
reuse, service-account reuse, cross-commit builds, non-XAU execution scope,
fake entrypoints, or relaxed locks fail closed.

## Prepare the immutable review

From the operator release on the exact Windows host:

```powershell
python -B .\prepare_windows_dual_release_demo_soak_operations.py `
  --config C:\AI_SCALPER_PRIVATE\operations\dual-release-input-v2.json `
  --issued-at-utc 2026-07-23T18:00:00Z `
  --output C:\AI_SCALPER_PRIVATE\operations\dual-release-review-v2.json
```

The output path must not exist. The artifact contains:

- the canonical plan and plan SHA-256;
- a failure-drill manifest binding both releases;
- exactly two Task Scheduler XML reviews for static port validation;
- two read-only `Get-ScheduledTask` validation scripts;
- explicit external blockers and false side-effect claims; and
- a self-verifying content hash.

The scheduler reviews invoke only:

- `validate_windows_decision_service.py --allow-blocked-report`; and
- `validate_windows_gated_execution_service.py --allow-blocked-report`.

They are acceptance checks, not future runtime tasks. There is deliberately no
generated watchdog task and no runtime runner invocation.

## Remaining path to demo-auto soak

This v2 artifact closes the local topology mismatch. It cannot manufacture the
remaining external facts:

1. materialized and reviewed decision/execution provider factories;
2. external launcher attestations and configured immutable releases;
3. decision IPC key/CAS/acknowledgement custody;
4. an implemented external monitor/watchdog and off-host delivery;
5. exact Task Scheduler/ACL/service-identity acceptance on Windows;
6. Windows hardening and all signed failure drills;
7. broker-native XAUUSD `0.01` minimum-lot risk feasibility; and
8. ten clean controlled manual-demo order lifecycles.

Only after those gates pass may a separately reviewed activation release begin
the 30-day/50-fill/20-XAU demo-auto soak. The normative contract is
[`specs/windows_dual_release_demo_soak_operations_v2.md`](../specs/windows_dual_release_demo_soak_operations_v2.md).
