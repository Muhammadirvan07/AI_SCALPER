# Spec: Windows Three-Service Demo-Soak Operations v3

**Author:** AI_SCALPER engineering
**Date:** 2026-07-24
**Status:** Approved
**Review basis:** User-approved Live-Grade v1 roadmap and locked three-service
architecture
**Supersedes for new host reviews:**
`windows_dual_release_demo_soak_operations_v2.md`
**Compatibility:** v1 and v2 artifacts remain readable as historical,
non-activating review records

## Context

AI_SCALPER now has three deterministic Windows service profiles:
`WINDOWS_DECISION_SERVICE_V1`, `WINDOWS_GATED_EXECUTION_SERVICE_V1`, and
`WINDOWS_EXTERNAL_STATUS_MONITOR_V1`. Each profile has an exact allowlist,
validator, runtime entrypoint, configured-release boundary, and a distinct
authority model. The v2 operations review binds only the decision/execution
pair and represents the monitor as an external hash reference. That is no
longer an accurate model of the local architecture.

The v3 contract must bind all three configured releases, Python runtimes,
service identities, factory/runtime configuration, launcher policy, and
validation tasks as peers. It remains a review-only artifact: external
provider implementations, credentials, launcher attestations, actual Task
Scheduler registration, MT5 access, and order authority are deliberately not
materialized.

Success means the repository can produce and independently verify one strict,
immutable, side-effect-free operations review bundle for the exact
three-service topology. Success does not mean demo-auto is activated.

## Functional Requirements

- FR-1: The system MUST bind exactly one decision, one execution, and one
  status-monitor configured release.
- FR-2: Every service binding MUST include its exact base profile, base and
  configured release identities, archive/manifest/configuration/reproducibility
  hashes, Git commit/tree, tracked file hashes, runtime/validator entrypoint
  hashes, factory contract/manifest hashes, runtime configuration hash, task
  definition hash, and launcher trust-policy hash.
- FR-3: All three services MUST originate from the same full Git
  commit/tree and source repository root, while their configured identities,
  release roots, archives, manifests, configurations, reproducibility
  receipts, Python executables, dependency locks, SBOMs, service IDs, service
  accounts, and task definitions MUST be distinct.
- FR-4: The decision and status-monitor services MUST bind
  `broker_sdk_present=false` and `order_capability=DISABLED`.
- FR-5: The execution service MUST bind
  `broker_sdk_present=true`, `gated_execution_boundary_present=true`, and
  `order_capability=GATED_PRESENT`; these facts MUST NOT change any plan-level
  activation lock.
- FR-6: The status-monitor service MUST bind `status_only=true`, the exact
  decision/execution configured identities, decision IPC binding, distinct
  heartbeat/alert destinations, and external checkpoint/latch/key custody
  provider IDs.
- FR-7: The plan MUST bind the exact XAUUSD-only initial DEMO account,
  terminal, symbol mapping, and broker specification hash.
- FR-8: Decision IPC publisher/consumer identities, SQLite path, ACL hash,
  signing-key custody, producer cursor, checkpoint CAS, and acknowledgement
  verifier MUST match the decision/execution service bindings.
- FR-9: All mutable databases MUST be distinct, absolute local Windows
  paths outside the source tree and all three release roots.
- FR-10: The system MUST render exactly three deterministic
  validation-only Task Scheduler XML reviews, one per release-local validator.
- FR-11: Generated scheduler reviews MUST NOT invoke runtime entrypoints,
  register/start a task, resolve credentials, initialize MT5, activate
  demo-auto/live, or carry order arguments.
- FR-12: Input and output documents MUST use exact schemas, reject unknown
  fields and duplicate JSON keys, require canonical finite values, and reject
  embedded credential/secret material.
- FR-13: The immutable bundle MUST bind the complete plan, a three-release
  failure-drill manifest, three scheduler reviews, readiness blockers,
  side-effect claims, safety locks, and a canonical content SHA-256.
- FR-14: Independent verification MUST reconstruct every typed object and
  deterministic rendering. Recomputed outer hashes MUST NOT make semantically
  altered content valid.
- FR-15: Output creation MUST be create-exclusive and MUST NOT overwrite an
  existing path.
- FR-16: The v3 CLI and modules MUST be included only in the
  release-operator tooling profile, not any service release.
- FR-17: v1 and v2 plan/artifact parsing MUST remain unchanged.
- FR-18: The stale v2 blocker
  `EXTERNAL_MONITOR_WATCHDOG_IMPLEMENTATION_REQUIRED` MUST be replaced by the
  truthful deny-only blocker
  `EXTERNAL_STATUS_MONITOR_CONFIGURED_RELEASE_ACCEPTANCE_REQUIRED`.

## Non-Functional Requirements

- NFR-S1: Every safety result MUST retain
  `live_allowed=false`, `safe_to_demo_auto_order=false`,
  `execution_enabled=false`, `task_install_allowed=false`,
  `promotion_eligible=false`, and `max_lot=0.01`.
- NFR-S2: The v3 modules MUST NOT import MetaTrader5, credential backends,
  provider loaders, subprocess, socket, Task Scheduler mutation, or broker
  execution modules.
- NFR-S3: Exact dataclass types MUST be required at authority boundaries;
  duck-typed values and subclasses MUST be rejected.
- NFR-R1: Two builds from equal input and timestamp MUST produce identical
  plan, scheduler, failure-manifest, bundle, and content hashes.
- NFR-R2: Validation MUST remain correct with `PYTHONOPTIMIZE=2`; security
  MUST NOT depend on `assert`.
- NFR-P1: Parsing and verifying a maximum-size accepted document MUST
  complete synchronously without starting a worker, process, or network call.
- NFR-C1: Existing full repository regression tests MUST remain green in
  normal and optimized modes.

## Acceptance Criteria

### AC-1: Valid three-service plan (FR-1, FR-2, FR-3, FR-7, NFR-S1)

Given three exact configured service bindings from one Git commit/tree
When the v3 plan is constructed
Then all three roles and identities are present and distinct
And the broker binding is exactly one XAUUSD DEMO lane
And every activation lock remains false with maximum lot `0.01`.

### AC-2: Exact role capabilities (FR-4, FR-5, FR-6)

Given one decision, execution, and status-monitor binding
When role capability invariants are validated
Then decision and monitor have no broker SDK or order authority
And execution retains only a locked gated boundary
And monitor is status-only and bound to decision/execution identities.

### AC-3: Cross-release drift rejected (FR-2, FR-3)

Given a valid plan
When any release reuses another root, identity, archive, manifest,
configuration, Python executable, dependency lock, SBOM, service account, or
task-definition hash
Then construction fails with a stable reason code.

### AC-4: IPC and monitor custody exact (FR-6, FR-8, FR-9)

Given valid service, IPC, and monitor custody bindings
When a provider ID is reused across domains, a destination is shared, a
service identity is mismatched, or state is placed inside source/release
Then construction fails before a review bundle exists.

### AC-5: Three validation-only scheduler reviews (FR-10, FR-11)

Given a valid v3 plan
When scheduler review material is rendered
Then exactly three definitions invoke only the exact release-local validators
with `--allow-blocked-report`
And no runtime, registration, start, credential, MT5, demo-auto, live, or order
command appears.

### AC-6: Strict input and immutable verification (FR-12, FR-13, FR-14)

Given one exact canonical v3 input document
When it is loaded, bundled, and verified
Then the reconstructed plan and all deterministic hashes match
And changing any nested field is rejected even if the unkeyed outer content
hash is recomputed.

### AC-7: Safe CLI behavior (FR-15, NFR-S1, NFR-S2)

Given a valid input and a new output path
When the v3 CLI runs
Then it writes one verified bundle and reports review-only status
And performs no credential, provider, task, process, network, MT5, or broker
effect
And a second invocation against the same output path is rejected.

### AC-8: Backward compatibility (FR-17, FR-18, NFR-C1)

Given existing v1/v2 fixtures and the updated truthful v2 blocker
When all repository tests run in normal and optimized modes
Then v1/v2 artifacts remain readable and deny-only
And no existing activation lock is relaxed.

### AC-9: Exact packaging boundary (FR-16, NFR-S2)

Given clean release allowlists
When operator and three service releases are built
Then v3 modules/CLI occur only in operator tooling
And none occur in decision, execution, or status-monitor release inventories.

### AC-10: Optimized-mode enforcement (NFR-R2)

Given Python runs with `PYTHONOPTIMIZE=2`
When every negative binding and tamper case executes
Then each case still fails closed with no side effect.

## Edge Cases and Error Scenarios

- EC-1: Missing or additional service role → reject exact role set.
- EC-2: Same configured or base identity across roles → reject.
- EC-3: Same Git commit but different Git tree → reject.
- EC-4: Nested/case-equivalent release roots → reject.
- EC-5: Python executable under source or any release root → reject.
- EC-6: Zero or malformed SHA-256/Git object → reject.
- EC-7: Monitor references a different decision/execution identity or IPC
  binding → reject.
- EC-8: Monitor heartbeat and alert destination are equal → reject.
- EC-9: Provider IDs collide between IPC, monitor, and off-host domains →
  reject.
- EC-10: Non-XAU initial broker scope → reject.
- EC-11: Unknown, duplicate-key, non-finite, oversized, symlink, unstable,
  or noncanonical input → reject.
- EC-12: Existing output path → reject without mutation.
- EC-13: Bundle tamper plus recomputed content hash → reject by
  reconstruction.
- EC-14: Caller-created subclass at a typed boundary → reject.

## API Contracts

N/A — the feature is a local Python/JSON operator contract; there is no HTTP
method or route.

```text
load_windows_three_service_demo_soak_operations_plan(path)
  -> WindowsThreeServiceDemoSoakOperationsPlan
  raises ThreeServiceOperationsArtifactError

build_windows_three_service_demo_soak_review_bundle(
  plan,
  issued_at_utc
) -> canonical JSON-compatible dict

verify_windows_three_service_demo_soak_review_bundle(bundle)
  -> WindowsThreeServiceDemoSoakOperationsPlan
  raises ThreeServiceOperationsArtifactError

prepare_windows_three_service_demo_soak_operations.py
  --config <exact-v3-input.json>
  --issued-at-utc <aware-UTC>
  --output <new-path>
```

CLI success exit code is `0`. Input, verification, or exclusive-write failure
uses exit code `2`. No CLI option accepts a password, login, token, private
key, permit, arm flag, task-install flag, or order flag.

```typescript
interface ThreeServiceOperationsInputV3 {
  schema_version: "windows-three-service-demo-soak-operations-input-v3";
  decision: ConfiguredServiceRoleBinding;
  execution: ConfiguredServiceRoleBinding;
  status_monitor: ConfiguredServiceRoleBinding;
  broker: MT5AccountBinding;
  ipc: DecisionExecutionIPCBinding;
  monitor: MonitorOperationsBinding;
}

interface ThreeServiceOperationsReviewBundleV3 {
  schema_version:
    "windows-three-service-demo-soak-operations-review-bundle-v3";
  plan_sha256: string;
  failure_drill_manifest_sha256: string;
  scheduler_reviews: SchedulerReview[3];
  content_sha256: string;
}
```

## Data Models

### ConfiguredServiceRoleBinding

| Field group | Constraints |
|---|---|
| role/profile | Exact decision, execution, or monitor mapping |
| release | Exact clean configured release and tracked files |
| identities | Non-zero, distinct base/configured SHA-256 |
| Python | Absolute external CPython 3.12 path, exact hashes |
| entrypoints | Exact role runner/validator and tracked hashes |
| factory/runtime | Exact non-zero contract/manifest/config hashes |
| launcher/task | Exact non-zero external policy/task hashes |
| capabilities | Exact per-role broker/status/order booleans |
| effects | Materialization/installation/attestation remain false |

### MonitorOperationsBinding

| Field group | Constraints |
|---|---|
| observed services | Exact configured decision/execution identities |
| IPC | Exact decision IPC binding SHA-256 |
| providers | Snapshot/checkpoint/latch/key/ack IDs, all distinct |
| destinations | Heartbeat and alert distinct and off-host bound |
| status | `status_only=true`, installed/accepted=false |

### WindowsThreeServiceDemoSoakOperationsPlan

| Field group | Constraints |
|---|---|
| services | Exactly three configured role bindings |
| broker | Exact DEMO XAUUSD-only account/server/terminal/spec |
| storage | Distinct absolute paths outside source/releases |
| security | Three distinct least-privilege identities, VPN/MFA |
| IPC | Exact publisher/consumer, ACL, CAS/key custody |
| monitor | Exact release/service/provider/destination binding |
| safety | All activation/promotion/task locks false |

### Review Bundle

| Field | Constraints |
|---|---|
| schema/version | Exact v3 values |
| plan/hash | Canonical plan and SHA-256 |
| failure manifest/hash | All three releases and required drills |
| scheduler reviews | Exactly three validation-only definitions |
| readiness | Fixed external blockers, never activation authority |
| effects | Every effect false |
| safety | Exact deny-only values |
| content hash | Canonical SHA-256 over all preceding fields |

## Out of Scope

- OS-1: Implementing real provider behavior or supplying credentials.
- OS-2: Issuing RSA private-key signatures or launcher attestations.
- OS-3: Installing, registering, starting, stopping, or restarting Windows
  tasks/services.
- OS-4: Initializing MT5, checking/sending orders, or changing broker state.
- OS-5: Changing `safe_to_demo_auto_order`, `live_allowed`, or maximum lot.
- OS-6: Claiming Windows acceptance, manual-demo completion, soak progress,
  promotion evidence, or live readiness.
- OS-7: Replacing external human approval, legal review, failure drills,
  or temporal broker evidence.
