# Spec: Windows Decision Service Release v1

**Author:** AI_SCALPER Engineering
**Date:** 2026-07-24
**Status:** Approved
**Reviewers:** Project owner under the approved Live-Grade v1 roadmap
**Related specs:** `windows_decision_service_runtime_v1.md`,
`windows_configured_overlay_candidate_preparation_v1.md`,
`windows_external_launcher_attestation_v1.md`,
`signed_decision_feed_handoff_v1.md`

## Context

AI_SCALPER requires the finalized-M15 decision process to run independently
from the MT5 executor. Combining those responsibilities would give the
decision process unnecessary access to risk approval, account state, broker
credentials, and order mutation primitives. The release therefore needs a
cryptographically distinct decision-only identity whose capability can be
audited without trusting its deployment directory.

The repository already has an exact brokerless producer, signed one-use
decision IPC, a configured-release loader, and a public-key launcher trust
boundary. This specification binds those components into a deterministic
Windows release while retaining every checked-in safety lock. It does not
claim that external providers, the Windows host, service identity, or launcher
authority have passed operational acceptance.

Current acceptance evidence includes deterministic release fixtures and the
full repository regression under normal and optimized Python. External
provider conformance, Task Scheduler/ACL acceptance, and real runtime
observations remain separate gates and cannot be inferred from local tests.

## Functional Requirements

- FR-1: The builder MUST accept only a clean Git worktree and the exact
  decision-service allowlist.
- FR-2: The builder MUST bind the full Git commit/tree, every source byte,
  dependency lock, archive inventory, and release identity into a canonical
  deterministic manifest.
- FR-3: The release MUST contain the brokerless finalized-M15 producer, shared
  decision core, signed append-only finalized-M15 feed provider, signed
  decision IPC producer, exact strategy dependencies, configured-release
  verifier/loader, static validator, and runtime runner.
- FR-4: The release MUST NOT contain execution policy, risk approval, permits,
  reconciliation, MT5 or another broker SDK, account credentials, order
  mutation primitives, runtime evidence, or market-data cache.
- FR-5: The runtime runner MUST expose a `--validate-only` path that validates
  the exact configured release and configuration without importing a factory,
  resolving credentials, opening provider state, fetching market data, or
  publishing IPC.
- FR-6: Operational launch MUST require the exact configured release identity,
  a release-local reviewed factory manifest, and a valid short-lived external
  RSA launcher attestation before factory import.
- FR-7: Operational launch MUST accept only an exact sealed
  `WindowsDecisionServiceFactoryResult` containing an exact bound
  `BrokerlessDecisionProducerService`.
- FR-8: The runtime configuration MUST bind all seven provider roles:
  `FINALIZED_M15_DATA`, `TRUSTED_CLOCK`, `IPC_SIGNING_KEY_CUSTODY`,
  `IPC_CHECKPOINT_CAS`, `PRODUCER_CURSOR_CAS`,
  `PRODUCER_CURSOR_ACK_VERIFIER`, and `SESSION_CALENDAR_VERIFIER`.
- FR-9: The runner MUST execute only the configured bounded cycle count and
  MUST terminate the process boundary when a cycle exceeds its configured
  deadline.
- FR-10: The release and runtime MUST preserve `order_capability=DISABLED`,
  `live_allowed=false`, `safe_to_demo_auto_order=false`, and `max_lot=0.01`.
- FR-11: Decision and execution services MUST use distinct release roots,
  configured identities, service-account aliases, state directories, factory
  manifests, provider sets, and launcher attestations.
- FR-12: The release, manifests, and non-secret runtime configuration MUST NOT
  contain credentials, signing secrets, account logins, mutable queue state,
  raw market data, or broker positions.
- FR-13: An operational cycle MAY publish only a signed
  `DecisionSnapshot`; it MUST NOT calculate risk approval, create a
  `TradeIntent`, contact MT5, or submit an order.

## Non-Functional Requirements

- NFR-1: Two builds from the same clean commit and allowlist MUST produce
  byte-identical ZIP archives and release identities.
- NFR-2: Dirty source, tampering, an extra/missing archive member, a symlink or
  reparse point, path indirection, unknown JSON fields, or a hash mismatch MUST
  fail before factory import or any provider effect.
- NFR-3: Third-party dependencies MUST match the dedicated CPython 3.12
  `win_amd64` dependency lock and verified wheel inventory exactly.
- NFR-4: Every trust timestamp consumed at runtime MUST be timezone-aware UTC;
  naive, expired, future, or clock-inconsistent claims MUST fail closed.
- NFR-5: A cycle timeout MUST cause exactly one hard-termination attempt and
  MUST NOT retry the failed cycle in the same process.
- NFR-6: The complete repository regression MUST pass under normal Python and
  optimized Python while the four safety values in FR-10 remain unchanged.

## Acceptance Criteria

### AC-1: Deterministic clean build (FR-1, FR-2, FR-3, FR-12; NFR-1, NFR-3)

Given two clean checkouts of the same reviewed commit and exact allowlist
When each checkout builds `WINDOWS_DECISION_SERVICE_V1`
Then both archives and both release identities are byte-identical
And their manifests bind the same Git commit/tree and source inventory.

### AC-2: Forbidden capability exclusion (FR-3, FR-4, FR-13)

Given the completed decision release archive
When its exact inventory, imports, and forbidden-token policy are validated
Then every required decision component is present
And no broker, risk, permit, reconciliation, credential, or order capability
is present.

### AC-3: Side-effect-free validation (FR-5, FR-8, FR-10)

Given an exact configured decision release and valid non-secret configuration
When the runner is invoked with `--validate-only`
Then the release, factory manifest, seven provider bindings, and safety locks
are verified
And no factory is imported, provider is materialized, credential is resolved,
market data is fetched, or IPC state is opened.

### AC-4: Missing launcher trust rejection (FR-6, FR-10; NFR-2)

Given an exact configured decision release without complete external RSA trust
documents
When operational launch is requested
Then launch fails with `EXTERNAL_RSA_LAUNCHER_ATTESTATION_REQUIRED` before
factory import
And every safety lock remains unchanged.

### AC-5: Attested bounded operation (FR-6, FR-7, FR-8, FR-9, FR-13; NFR-4)

Given an exact configured release, a valid decision-profile RSA attestation,
an exact reviewed factory, and seven correctly bound providers
When the runner executes one configured cycle
Then it returns one bounded decision-cycle status
And the process exposes no broker or order capability.

### AC-6: Release or factory tamper rejection (FR-2, FR-6, FR-7; NFR-2)

Given a previously valid configured release or factory result
When a source byte, inventory member, identity, binding, result type, or
attestation-bound field is changed
Then validation fails before provider use
And no replacement or duck-typed factory result is accepted.

### AC-7: Timeout is terminal (FR-9; NFR-5)

Given an operational decision cycle that exceeds its configured deadline
When the deadline expires
Then the runner invokes the hard process-termination boundary exactly once
And it does not retry or start another cycle in that process.

### AC-8: Safety policy is immutable (FR-10; NFR-6)

Given any builder, validator, configured loader, or runner path
When its manifest and runtime configuration are evaluated
Then order capability is `DISABLED`, live and demo-auto flags are false, and
maximum lot is `0.01`
And any relaxed value is rejected.

### AC-9: Decision/execution separation (FR-4, FR-11, FR-13)

Given the decision and execution release definitions
When their roots, identities, accounts, state, providers, and entrypoints are
compared
Then they are distinct
And the decision release cannot import or invoke the executor boundary.

### AC-10: Dependency and import closure (FR-1, FR-3, FR-4; NFR-3)

Given the reviewed allowlist and dependency lock
When an undeclared local import, broker SDK, dynamic loader, site-package
substitution, or dependency drift is introduced
Then the build or configured loader fails closed
And no archive is accepted as the reviewed release.

### AC-11: Trust time and profile binding (FR-6; NFR-4)

Given an external launcher policy and attestation
When the attestation is naive, expired, future-dated, signed for another
profile, or inconsistent with trusted UTC
Then verification fails before factory import
And the decision runner performs no runtime effect.

### AC-12: Full regression remains green (FR-1, FR-2, FR-3, FR-4, FR-5,
FR-6, FR-7, FR-8, FR-9, FR-10, FR-11, FR-12, FR-13; NFR-6)

Given the tracked project source and tests
When the complete test suite runs in normal and optimized Python
Then every test passes
And release safety values remain unchanged.

## Edge Cases

- EC-1: Dirty or untracked source exists → reject before archive creation.
- EC-2: Archive contains an extra, missing, renamed, symlinked, or reparse-point
  member → reject the configured release before factory import.
- EC-3: Factory manifest is outside the configured release root or is changed
  during stable read → reject path indirection or unstable input.
- EC-4: Launcher policy or attestation is inside the mutable release root →
  reject it as non-external trust.
- EC-5: RSA policy is too weak, cross-profile, unpinned, expired, or has an
  invalid signature → reject operational launch before provider materialization.
- EC-6: One of seven provider roles is missing, duplicated, drifted, or bound
  to the wrong custody identity → reject runtime configuration.
- EC-7: Factory returns a subclass, duck type, unsealed result, wrong service
  ID, or mismatched bootstrap binding → reject the factory result.
- EC-8: A cycle exceeds its deadline or receives a stop signal → stop without
  retrying, publishing a duplicate, or crossing into broker execution.
- EC-9: A local module resolves through `site-packages`, path indirection, or a
  replaced module registry entry → reject the import boundary.
- EC-10: Safety configuration attempts to enable order, demo-auto, live, or a
  lot above `0.01` → reject before runtime.

## API Contracts

N/A — this is a CLI/service release and exposes no HTTP endpoint. Its audited
command and output contracts are:
HTTP method/path: N/A — no `POST /api/windows-decision-service` or other HTTP
endpoint exists.

```typescript
interface DecisionServiceCLIInput {
  releaseRoot: AbsoluteDirectory;
  factoryManifest: ReleaseLocalRegularFile;
  expectedReleaseIdentitySha256: Sha256Hex;
  validateOnly: boolean;
  releaseTrustPolicy?: ExternalStableRegularFile;
  expectedReleaseTrustPolicySha256?: Sha256Hex;
  releaseAttestation?: ExternalStableRegularFile;
}

interface DecisionServiceValidationOutput {
  schema_version: "windows-decision-service-validation-v2";
  status: "STATIC_CONFIGURED_FACTORY_AND_CONFIG_VERIFIED";
  release_profile: "WINDOWS_DECISION_SERVICE_V1";
  service_id: string;
  factory_contract_sha256: Sha256Hex;
  bootstrap_binding_sha256: Sha256Hex;
  factory_imported: false;
  provider_materialized: false;
  market_data_fetch_performed: false;
  ipc_mutation_performed: false;
  broker_mutation_performed: false;
  production_execution_ready: false;
  readiness_blockers: string[];
  order_capability: "DISABLED";
  live_allowed: false;
  safe_to_demo_auto_order: false;
  max_lot: 0.01;
}

interface DecisionServiceRuntimeSummary {
  schema_version: "windows-decision-service-run-v1";
  status: "BOUNDED_DECISION_RUN_COMPLETE";
  service_id: string;
  cycles: number;
  lane_status_counts: Record<string, number>;
  factory_contract_sha256: Sha256Hex;
  order_capability: "DISABLED";
  live_allowed: false;
  safe_to_demo_auto_order: false;
  max_lot: 0.01;
}
```

Errors are fail-closed symbolic codes written to stderr with a non-zero exit
status. Error output MUST NOT contain provider secrets, credentials, raw
market frames, or signed IPC payloads.

## Data Models

### Decision release and runtime entities

| Field/entity | Type | Constraints |
|---|---|---|
| `release_profile` | enum | Exactly `WINDOWS_DECISION_SERVICE_V1` |
| `release_identity_sha256` | SHA-256 hex | Canonical full release identity |
| `git_commit` / `git_tree` | SHA-1 hex | Exact clean source provenance |
| `source_files` | ordered array | Exact allowlisted inventory; no extras |
| `service_id` | string | Must match producer binding and factory result |
| `decision_producer_binding` | immutable object | Exact hash-bound producer/lane contract |
| `decision_feed_binding` | immutable object | Exact broker/account/lane/source/calendar and publisher-key binding |
| `providers` | seven-role array | Exact unique roles and contract/config/custody hashes |
| `max_cycles` | positive integer | Bounded runtime cycle count |
| `poll_seconds` | non-negative finite number | Exact configured interval |
| `cycle_deadline_seconds` | positive finite number | Hard terminal deadline |
| `launcher_attestation` | signed external document | RSA-3072+, short-lived, decision profile, host/service/task bound |
| `factory_result` | sealed exact type | Contains exact `BrokerlessDecisionProducerService` |
| safety fields | literal values | `DISABLED`, `false`, `false`, `0.01` |

No persistent database schema is owned by this release. Provider state,
credential custody, IPC/CAS storage, and monitoring state remain externally
owned and independently accepted.

## Out of Scope

- OS-1: MT5 initialization, account access, preflight, or order submission —
  owned exclusively by the gated execution release.
- OS-2: Risk approval, position sizing, permits, intent creation, and
  reconciliation — owned exclusively by execution/risk boundaries.
- OS-3: Provider implementation or provider acceptance — deployment-specific
  evidence is reviewed through the separate 65-binding conformance process.
- OS-4: Windows account creation, NTFS ACLs, Task Scheduler installation,
  Credential Manager provisioning, VPN/MFA, or offline RSA private-key custody
  — these require target-host operational review.
- OS-5: Enabling `safe_to_demo_auto_order` or `live_allowed` — prohibited until
  the separately approved activation and live-promotion stages.
- OS-6: Claiming demo-auto soak or live readiness from a successful local
  build, static validation, or one operational decision cycle — external,
  manual, and temporal evidence remains mandatory.

## External Blockers

- `EXTERNAL_FINALIZED_M15_DATA_PROVIDER_REQUIRED`
- `EXTERNAL_SIGNED_SESSION_CALENDAR_VERIFIER_REQUIRED`
- `EXTERNAL_TRUSTED_CLOCK_PROVIDER_REQUIRED`
- `EXTERNAL_DECISION_IPC_KEY_CUSTODY_REQUIRED`
- `EXTERNAL_DECISION_IPC_CHECKPOINT_CAS_REQUIRED`
- `EXTERNAL_DECISION_CURSOR_CAS_REQUIRED`
- `EXTERNAL_DECISION_CURSOR_ACK_VERIFIER_REQUIRED`
- `EXTERNAL_PROVIDER_RUNTIME_ATTESTATION_REQUIRED`
- `EXTERNAL_STATUS_MONITOR_CONFIGURED_RELEASE_ACCEPTANCE_REQUIRED`
- `EXACT_WINDOWS_DECISION_SERVICE_ACCEPTANCE_REQUIRED`
