# Windows Dual-Release Demo-Soak Operations v2

## Status

This specification replaces the single-release deployment assumptions in
`windows_demo_soak_operations_v1.md` for the current production architecture.
The v1 schema remains readable as a legacy review artifact, but it MUST NOT be
used as the operational contract for a demo-auto host.

The current architecture has three deterministic service releases and three
separate service identities:

1. `WINDOWS_DECISION_SERVICE_V1`, which has no broker or order capability; and
2. `WINDOWS_GATED_EXECUTION_SERVICE_V1`, which contains the exact gated MT5
   boundary; and
3. `WINDOWS_EXTERNAL_STATUS_MONITOR_V1`, which observes status and off-host
   delivery without broker, risk, permit, or order authority.

This v2 operations schema binds the decision/execution pair and references the
third monitor as an independently accepted external service. It intentionally
does not install or render any of the three runtime tasks.

This v2 contract remains review-only. It does not install tasks, materialize
providers, read credentials, initialize MT5, activate demo-auto, or submit an
order.

## Safety invariants

Every plan, review bundle, verification result, and readiness assessment MUST
retain:

- `execution_enabled = false`
- `task_install_allowed = false`
- `validation_tasks_only = true`
- `safe_to_demo_auto_order = false`
- `live_allowed = false`
- `promotion_eligible = false`
- `order_capability = DISABLED`
- `max_lot = 0.01`

## Functional requirements

### FR-1 — Exact dual-release binding

The plan MUST bind one clean decision release and one clean execution release.
Each binding includes the expected release profile and identity, full Git
commit/tree, archive, manifest, configuration, reproducibility receipt, and
tracked-file hashes. Both releases MUST come from the same commit and tree, but
their release roots, release identities, archives, manifests, and allowlists
MUST be distinct.

The decision binding MUST contain the exact tracked
`run_windows_decision_service.py` and `validate_windows_decision_service.py`.
The execution binding MUST contain the exact tracked
`run_windows_gated_execution_service.py` and
`validate_windows_gated_execution_service.py`. Fictitious runtime or watchdog
entrypoints are prohibited.

### FR-2 — Separate Python runtimes and identities

Decision and execution MUST bind distinct absolute `python.exe` paths, exact
CPython 3.12 patch versions, executable hashes, dependency-lock hashes, and SBOM
hashes. They MUST use distinct least-privilege Windows service identities.

A third distinct monitor identity is required as an external reference. A
deterministic monitor release and runtime loader exist, but this contract does
not claim that its configured provider overlay, launcher attestation, task, or
off-host acknowledgements have been accepted.

### FR-3 — XAUUSD-only initial scope

The exact demo account/server/terminal binding MUST be `DEMO` and the symbol set
for the first demo-auto lane MUST be exactly `XAUUSD`. The canonical-to-broker
symbol and broker-specification SHA-256 are bound. FX lanes remain outside the
initial execution scope.

### FR-4 — Explicit decision/execution IPC boundary

The plan MUST bind:

- an absolute local SQLite path outside source and both releases;
- `decision-ipc-binding-v2`;
- the exact immutable IPC binding SHA-256;
- the decision publisher and execution consumer service IDs;
- an ACL-policy SHA-256;
- external checkpoint CAS, producer cursor CAS, acknowledgement verifier, and
  signing-key custody provider IDs; and
- `external_custody_required = true`.

The publisher and consumer IDs MUST equal the corresponding release-role
service IDs. Provider IDs MUST be distinct and MUST not contain URLs or secret
material.

### FR-5 — External monitor boundary

The plan MUST bind the separately reviewed external status-only monitor by
provider ID, implementation/configuration/task-definition hashes, and the
distinct monitor service identity. It MUST bind the same off-host heartbeat and
alert destination IDs used by the operations plan. Its configured release,
provider sources, launcher trust, and task acceptance remain separate reviewed
artifacts.

The local plan MUST NOT render a fictitious watchdog command or claim the
monitor is installed.

### FR-6 — Validation-only scheduler review

The plan renders exactly two deterministic Task Scheduler XML reviews:

1. decision release static port validation; and
2. execution release static port validation.

Each action runs the release-local validator with `--allow-blocked-report`.
Definitions use S4U, least privilege, one instance, no demand start, and the
role-specific Python executable and release root. No generated action may
contain a runtime runner, broker credential, order flag, task registration, or
task start command.

These definitions are acceptance checks only and MUST NOT be represented as
the future runtime service tasks.

### FR-7 — Runtime state isolation

Journal, risk, supervisor, manual-demo, soak, and decision IPC databases MUST be
distinct absolute local paths outside source and both release roots. Logs and
immutable audit export remain separate. Path traversal, UNC paths, code-tree
state, release-tree state, or collisions fail closed.

### FR-8 — Strict immutable v2 review bundle

The operator CLI accepts one exact
`windows-dual-release-demo-soak-operations-input-v2` JSON document and emits one
create-exclusive
`windows-dual-release-demo-soak-operations-review-bundle-v2` document. Unknown
fields, duplicate keys, raw secrets, symlinks/reparse points, unstable reads,
oversized input, non-finite values, or schema drift fail closed.

The bundle binds:

- the canonical dual-release plan and SHA-256;
- a failure-drill manifest containing both release identities and manifests;
- both validation-only scheduler XML reviews and read-only PowerShell
  validators;
- readiness blockers;
- explicit false side-effect claims; and
- every safety invariant.

Verification MUST reconstruct all typed objects and deterministic outputs. Any
tamper fails even when an attacker recomputes the unkeyed outer content hash.

### FR-9 — Honest readiness

Local validation may report `LOCAL_DUAL_RELEASE_PLAN_VALID`, but it MUST retain
external blockers for:

- decision provider factory materialization;
- execution provider factory materialization;
- independent launcher attestations;
- decision/execution IPC custody;
- configured status-monitor provider/release and off-host delivery acceptance;
- exact Windows task/ACL installation acceptance;
- Windows hardening and signed failure drills; and
- ten controlled manual-demo orders.

No local artifact can convert those facts to a pass.

## Non-functional requirements

- Pure validation and rendering are deterministic.
- No module imports `MetaTrader5`, subprocess, shell, socket, credential,
  registry, Task Scheduler mutation, or dynamic provider-loading APIs.
- No process, thread, task, network request, or broker operation is started.
- Timestamps are aware UTC.
- SHA-256 values are canonical lower-case full hashes; Git objects are full
  40-character hashes.
- v1 behavior and artifacts remain unchanged.

## Acceptance tests

Tests MUST prove:

- exact decision/execution profile, entrypoint, release, runtime, and identity
  separation;
- rejection of single-release reuse, runtime reuse, service-account reuse,
  cross-commit releases, fictitious entrypoints, IPC mismatch, path collision,
  non-XAU scope, and embedded secrets;
- exactly two validation-only scheduler definitions and no claim that the
  third runtime task is installed;
- immutable input/bundle parsing, reconstruction, tamper detection, and
  create-exclusive CLI output;
- zero credential/task/process/network/MT5/broker side effects; and
- preservation of all safety locks and all external blockers.

## External completion gates

This contract closes only the local architecture mismatch. Demo-auto soak still
cannot begin until reviewed provider implementations, configured releases,
offline launcher attestations, Windows Credential Manager references, IPC/CAS
custody, configured monitor provider/release acceptance, real off-host
acknowledgements, task/ACL acceptance, hardening/failure drills, minimum-lot
risk feasibility, and ten clean manual-demo lifecycles are proven.
