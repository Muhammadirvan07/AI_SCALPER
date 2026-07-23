# Windows Three-Service Demo-Soak Operations v3

## Current outcome

The current Windows host topology is represented by one strict, immutable v3
review contract containing exactly:

- one configured `WINDOWS_DECISION_SERVICE_V1` release;
- one configured `WINDOWS_GATED_EXECUTION_SERVICE_V1` release;
- one configured `WINDOWS_EXTERNAL_STATUS_MONITOR_V1` release;
- one distinct CPython 3.12 runtime and least-privilege identity per service;
- the exact decision-to-execution IPC binding;
- the monitor checkpoint, latch, acknowledgement, key-custody, heartbeat, and
  alert references; and
- one XAUUSD-only DEMO broker binding.

The v1 and v2 documents remain readable historical review records. New host
reviews use v3 because the monitor is now a full configured release rather
than an external implementation-hash placeholder.

## Non-activating boundary

The operator CLI is:

```text
prepare_windows_three_service_demo_soak_operations.py
```

It is included only in the operator tooling release. It is absent from the
decision, execution, status-monitor, and shadow service releases.

Every successful bundle remains fixed to:

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

The CLI reads one non-secret JSON document and writes one create-exclusive JSON
review. It does not access Credential Manager, import or materialize a
provider, install or start a task, launch a process, open the network,
initialize MT5, or mutate broker state.

## Exact input

Create a
`windows-three-service-demo-soak-operations-input-v3` document outside the
repository. It binds:

- all three base and configured release identities;
- archive, manifest, configuration, reproducibility, Git commit/tree, and
  tracked entrypoint hashes;
- all three exact Python executable, dependency-lock, and SBOM bindings;
- distinct service IDs, accounts, release roots, and validation task hashes;
- secret-free factory contract/manifest/configuration and launcher-policy
  hashes;
- the exact Phillip commodity DEMO terminal, account alias, `XAUUSD.ps01`, and
  broker specification hash;
- opaque Credential Manager references only;
- distinct runtime and decision-IPC databases outside source and releases;
- exact IPC ACL, CAS, acknowledgement, and signing-key custody references;
- monitor snapshot/checkpoint/latch/key/outbox/transport references;
- distinct, off-host-bound heartbeat and alert destinations; and
- VPN/MFA/firewall/Event Log posture and safe health thresholds.

Unknown fields, duplicate JSON keys, non-finite numbers, inline secrets,
symlink/reparse input, oversized or unstable files, path/provider collisions,
identity reuse, cross-commit/tree drift, non-XAU scope, or relaxed safety locks
fail closed.

## Create the review

From the exact operator release on the reviewed Windows host:

```powershell
python -B .\prepare_windows_three_service_demo_soak_operations.py `
  --config C:\AI_SCALPER_PRIVATE\operations\three-service-input-v3.json `
  --issued-at-utc <CURRENT_AWARE_UTC> `
  --output C:\AI_SCALPER_PRIVATE\operations\three-service-review-v3.json
```

The output path must not exist. A successful command reports:

```text
WINDOWS_THREE_SERVICE_DEMO_SOAK_OPERATIONS_REVIEW_READY
Scheduler definitions: THREE_VALIDATION_ONLY
Task installation: DISABLED
Provider materialization: DISABLED
Broker mutation: DISABLED
Order capability: DISABLED
```

The bundle contains:

- the canonical complete plan and plan SHA-256;
- a failure-drill manifest binding all three configured identities and
  release-manifest hashes;
- exactly three deterministic Task Scheduler XML reviews;
- three deterministic read-only PowerShell validation scripts;
- the complete external blocker catalog;
- explicit false side-effect claims and deny-only safety claims; and
- a canonical content SHA-256.

Independent verification reconstructs every typed object and deterministic
rendering. Recomputing the outer hash cannot make altered plan, manifest,
scheduler, readiness, effects, or safety content valid.

## Scheduler review semantics

The three reviews invoke only:

- `validate_windows_decision_service.py --allow-blocked-report`;
- `validate_windows_gated_execution_service.py --allow-blocked-report`; and
- `validate_windows_external_status_monitor.py --allow-blocked-report`.

They do not invoke any runtime runner. They are review material, not installed
tasks and not permission to activate a service.

## Remaining path to demo-auto

The v3 artifact closes the local three-service operations-model gap. It cannot
create the external facts required to start demo-auto:

1. accepted configured releases and independently pinned identities on exact
   Windows x86-64/CPython 3.12;
2. reviewed provider implementations and external key/CAS/latch custody;
3. fresh launcher attestations and exact Task Scheduler/ACL/service identity
   acceptance;
4. Windows hardening, backup/restore evidence, and all signed failure drills;
5. broker-native `0.01` XAUUSD risk-feasibility evidence; and
6. ten clean controlled manual-demo order lifecycles.

Only a separate human-reviewed activation release may begin the
30-day/50-fill/20-XAU demo-auto soak. The normative contract is
[`specs/windows_three_service_demo_soak_operations_v3.md`](../specs/windows_three_service_demo_soak_operations_v3.md).
