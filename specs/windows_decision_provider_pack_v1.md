# Spec: Windows Decision Provider Pack v1

**Author:** Codex with AI_SCALPER project owner  
**Date:** 2026-07-25  
**Status:** Approved  
**Reviewers:** AI_SCALPER project owner under the standing authorization to
continue the live-grade roadmap while preserving every execution and live
lock  
**Related specs:**
`specs/windows_decision_service_release_v1.md`,
`specs/windows_decision_service_runtime_v1.md`,
`specs/signed_decision_feed_handoff_v1.md`,
`specs/signed_decision_ipc_v1.md`,
`specs/windows_configured_overlay_candidate_preparation_v1.md`,
`specs/windows_three_service_provider_conformance_v2.md`

## Context

The deterministic Windows decision release already contains the shared pure
decision core, signed finalized-M15 feed reader, signed decision IPC queue,
producer cursor store, bounded service runner, configured-release loader, and
seven exact provider contracts. The current release deliberately does not
contain broker access, order primitives, credential values, or a configured
factory.

An operational configured decision release still cannot be materialized from
the current repository. The factory needs exact Windows implementations for
credential-backed key lookup, trusted UTC, finalized-M15 feed access, decision
IPC checkpoint CAS, producer cursor CAS, session-calendar verification, and
the final immutable service composition. The existing overlay validator denies
`site-packages`, dynamic loading, native libraries, process launch, and secret
values. The existing evidence key helper relies on `keyring`, which is
intentionally forbidden in the decision release. Supplying a mock callback or
a factory that raises later would create a package that looks configured but
cannot run and therefore must not be treated as progress toward demo-auto.

This feature adds a reviewed, standard-library-only Windows provider
foundation to the decision base release and an offline generator for one
secret-free decision overlay. Runtime secret material remains in Windows
Credential Manager and is read only for exact pinned key IDs. External CAS is
performed through create-exclusive request and signed-response directories
that must be mounted from an independently controlled custody endpoint.
Generation and validation perform no credential access, provider
materialization, process launch, MT5 access, broker mutation, or order action.

## Functional Requirements

- FR-1: The base decision release MUST expose a Windows-only, read-only
  Credential Manager key provider implemented with reviewed standard-library
  Windows APIs and MUST NOT depend on `keyring`, `pywin32`, a shell, or a
  subprocess.
- FR-2: The credential provider MUST accept exactly one non-secret target
  prefix and an immutable allowlist mapping of key ID to full SHA-256
  fingerprint. It MUST read only the exact generic credential target derived
  from that mapping and MUST reject missing, malformed, short, unexpected, or
  fingerprint-mismatched values.
- FR-3: The credential provider MUST expose only a callable exact-key lookup.
  It MUST NOT expose the native backend, enumerate credentials, create,
  update, delete, print, serialize, cache to disk, or return a secret for an
  unlisted key ID.
- FR-4: The base decision release MUST expose a monotonic trusted-UTC provider
  that returns only timezone-aware UTC, rejects system-clock regression, and
  requires a fresh signed external clock attestation whose measured absolute
  drift does not exceed one second.
- FR-5: The base decision release MUST expose a create-exclusive directory CAS
  client for decision IPC checkpoints and producer cursor checkpoints. Each
  request MUST bind the provider ID, state domain, expected predecessor,
  proposed canonical object and hash, request ID, issued UTC, and expiry.
- FR-6: A CAS client MUST accept only an exact signed response and exact
  readback object for the same request, domain, identity, predecessor, proposal,
  and expiry. Missing, stale, future, duplicate-conflicting, malformed,
  symlink/reparse, rollback, fork, rejection, or readback mismatch MUST fail
  closed.
- FR-7: The external CAS client MUST NOT issue a custody signature, alter a
  remote response, treat a local directory as proof of off-host custody, or
  advance local state without an accepted response and exact readback.
- FR-8: Public strict parsers MUST reconstruct externally stored
  `DecisionIPCCheckpoint`, `DecisionIPCCASAcknowledgement`,
  `DecisionProducerCheckpoint`, and `DecisionProducerCASAcknowledgement`
  values without exposing their private minting seals or weakening existing
  type checks.
- FR-9: The provider foundation MUST build exactly one
  `BrokerlessDecisionProducerService` from:
  - the exact `DecisionProducerBinding` in
    `WindowsDecisionServiceRuntimeConfig`;
  - one exact `DecisionIPCBinding`;
  - one exact `DecisionFeedBinding`;
  - preprovisioned decision IPC and producer cursor SQLite databases;
  - exact signed-feed, CAS, key, calendar, and trusted-clock capabilities.
- FR-10: Materialization MUST verify that service, lane, commit, config, model,
  data-contract, calendar, account-alias, server, environment, issuer, key,
  fingerprint, and queue identities agree across runtime, feed, IPC, and
  provider configuration before opening mutable state.
- FR-11: Runtime materialization MUST open only preprovisioned databases and
  existing regular non-symlink/non-reparse directories. It MUST NOT
  auto-provision a database, create a credential, create an external custody
  root, or silently reset a missing or inconsistent state.
- FR-12: An offline generator MUST accept one exact atomic-suite decision base
  release, one canonical secret-free provider-pack input, and a new overlay
  directory. It MUST write exactly:
  `reviewed_windows_factory.py`,
  `configured_providers/__init__.py`,
  `configured_providers/decision_provider.py`, and
  `config/windows_service_config.json`.
- FR-13: The generator MUST derive all seven
  `DecisionServiceProviderBinding` implementation and configuration hashes
  from the exact generated/provider foundation bytes and canonical non-secret
  configuration. Callers MUST NOT supply or override these derived hashes.
- FR-14: The generated factory MUST construct the exact provider template from
  runtime config and factory context, delegate only to the reviewed decision
  provider foundation, and return only
  `seal_windows_decision_service_factory_result(...)`.
- FR-15: Generator input and generated output MUST contain credential target
  references and key fingerprints only. Passwords, account logins, secret
  bytes, tokens, private keys, environment arms, permits, approvals, and
  credential values MUST be rejected.
- FR-16: Generation MUST validate canonical JSON, closed schemas, Windows
  absolute path policy, role completeness, exact base-suite ancestry,
  cross-binding consistency, provider hashes, source AST, import closure,
  forbidden imports/members, and all fixed safety locks before writing.
- FR-17: Generation MUST be deterministic and create-exclusive. A failure
  after the first output write MUST remove only files created by that
  invocation and MUST preserve all pre-existing files.
- FR-18: A separate validation path MUST verify a generated pack without
  importing its factory, reading credentials, opening provider state, issuing
  CAS requests, starting a service, or publishing a decision.
- FR-19: Every generated and runtime result MUST preserve
  `order_capability=DISABLED`, `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `max_lot=0.01`,
  `promotion_eligible=false`, and `production_execution_ready=false`.
- FR-20: The provider pack MUST NOT import MT5, calculate risk approval, create
  a `TradeIntent`, access an execution journal through a mutation interface,
  install a task, launch a process, access the public network, or submit,
  modify, or close an order.
- FR-21: A generated pack MUST remain
  `EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED`. It MUST NOT claim that a mounted
  directory is off-host/WORM, that Windows Credential Manager is correctly
  ACL-protected, or that provider conformance has passed.
- FR-22: The provider foundation and generator MUST be included in the exact
  decision and configured-tooling allowlists as appropriate and MUST remain
  absent from execution-order authority and read-only shadow source
  inventories unless a later approved spec requires them.

## Non-Functional Requirements

- NFR-1 Security: Secret values MUST never occur in CLI arguments, generated
  source/config, repository files, logs, exceptions, manifests, or result
  objects. Error output MUST use stable uppercase reason codes.
- NFR-2 Reliability: Every credential, clock, CAS, filesystem, parser, and
  binding failure MUST fail before a decision cycle can publish an IPC
  envelope.
- NFR-3 Determinism: Identical base release and canonical pack input MUST
  produce byte-identical overlay files and identical provider/template hashes.
- NFR-4 Resource bounds: Each input or generated file MUST be at most 4 MiB,
  aggregate generated bytes MUST be at most 16 MiB, and a lane set MUST contain
  between one and four exact M15 lanes.
- NFR-5 Performance: Offline generation and validation MUST each complete in
  under two seconds on the normal development host. A successful local
  credential lookup MUST complete in under 250 ms and a CAS round trip MUST
  respect an explicitly configured timeout no greater than two seconds.
- NFR-6 Concurrency: Concurrent identical CAS requests MUST converge on one
  request payload and one exact response; conflicting reuse of a request ID or
  path MUST reject.
- NFR-7 Portability: Offline generation, validation, and unit tests MUST run on
  macOS and Windows. Native credential materialization MUST reject every
  non-Windows platform before backend access.
- NFR-8 Regression: Focused tests MUST pass with normal Python and
  `PYTHONOPTIMIZE=2`; full tracked-project regression, compilation, dependency
  locks, SBOM, release-boundary tests, deterministic suite rebuild, and safety
  scans MUST remain green.

## Acceptance Criteria

### AC-1: Exact Credential Manager lookup (FR-1, FR-2, FR-3; NFR-1, NFR-7)

Given an injected Windows credential backend containing one exact allowlisted
256-bit key  
When the sealed key provider resolves its pinned key ID  
Then it returns the exact bytes only to the caller  
And the fingerprint matches  
And no enumeration, mutation, logging, disk write, shell, or subprocess occurs.

### AC-2: Credential misuse fails closed (FR-2, FR-3; NFR-1, NFR-2)

Given a non-Windows platform, unknown key ID, missing record, malformed
encoding, short key, backend failure, or fingerprint mismatch  
When key lookup runs  
Then it rejects with a stable reason code without exposing secret content.

### AC-3: Trusted UTC requires fresh attestation (FR-4; NFR-2)

Given a signed external clock attestation bound to the provider and host  
When system UTC is within one second and time has not regressed  
Then the provider returns aware UTC  
And stale, future, forged, excessive-drift, naive, or regressing observations
are rejected.

### AC-4: IPC checkpoint CAS succeeds exactly once (FR-5 through FR-8; NFR-6)

Given an independently controlled request/response mount with a current IPC
checkpoint  
When the client submits one successor with the exact predecessor  
Then one canonical request is created  
And one accepted signed acknowledgement and exact readback are returned  
And an identical retry is idempotent.

### AC-5: Producer cursor CAS succeeds exactly once (FR-5 through FR-8; NFR-6)

Given an independently controlled request/response mount with a current
producer cursor checkpoint  
When the client submits one successor with the exact predecessor  
Then the exact typed acknowledgement and readback are returned  
And no IPC checkpoint can be substituted into the cursor domain.

### AC-6: CAS ambiguity latches failure (FR-6, FR-7; NFR-2)

Given a missing, rejected, forged, stale, forked, rolled-back, path-indirected,
or readback-mismatched response  
When either CAS adapter is called  
Then it raises a stable failure before returning success  
And the existing queue or cursor store performs its reviewed critical-latch
behavior.

### AC-7: Cross-binding composition is exact (FR-9 through FR-11)

Given valid runtime, feed, IPC, provider, state, key, and clock bindings  
When the reviewed provider foundation materializes the service  
Then it returns one exact `BrokerlessDecisionProducerService` bound to the
runtime producer binding  
And one cycle may only publish a signed `DecisionSnapshot`.

### AC-8: Cross-binding drift is rejected before state access (FR-10, FR-11)

Given any service, lane, symbol, commit, config, model, data-contract,
calendar, account, server, environment, issuer, key, fingerprint, queue, or
provider hash mismatch  
When materialization is requested  
Then it rejects before opening SQLite, reading a credential, fetching a feed,
or issuing a CAS request.

### AC-9: Deterministic secret-free pack generation (FR-12, FR-13, FR-14,
FR-15, FR-16, FR-17; NFR-1, NFR-3)

Given an exact decision base release and canonical non-secret pack input  
When two independent output directories are generated  
Then their four files are byte-identical  
And all seven provider hashes are derived and exact  
And neither output contains a secret value or activation authority.

### AC-10: Generated factory is sealed and decision-only (FR-14, FR-19,
FR-20)

Given a valid generated pack and externally accepted runtime providers  
When the configured decision loader invokes `build`  
Then the result is sealed by the existing decision-service sealing function  
And the factory exposes no broker, risk, intent, permit, MT5, process, or order
capability.

### AC-11: Unsafe input or destination fails transactionally (FR-15 through
FR-18; NFR-1, NFR-4)

Given a secret-bearing, unknown-field, noncanonical, oversized, path-traversing,
symlink/reparse, existing-output, wrong-base, mixed-suite, incomplete-role, or
binding-inconsistent input  
When generation or validation runs  
Then it rejects with a stable reason  
And no existing file is overwritten or partial pack retained.

### AC-12: Validation has zero provider effects (FR-18 through FR-21)

Given a complete generated pack  
When offline validation runs with sentinels for credentials, filesystem state,
CAS, process, network, MT5, broker, and order effects  
Then every sentinel remains untouched  
And the result remains external-review-required and production-not-ready.

### AC-13: Release isolation remains exact (FR-22; NFR-8)

Given all release allowlists and the atomic five-role builder  
When release-boundary tests run  
Then the provider runtime foundation exists only where required by the
decision base and configured tooling  
And no execution or shadow authority is broadened.

### AC-14: Full regression and deterministic rebuild remain green (NFR-5,
NFR-8)

Given the complete implementation  
When focused, optimized, full, compilation, dependency, SBOM, security, and
independent atomic-suite rebuild checks run  
Then all checks pass within bounds  
And deployment remains blocked on exact Windows and external provider
acceptance.

## Edge Cases and Error Scenarios

- EC-1: Credential blob is valid UTF-16 but lacks the exact `hex:` envelope →
  reject.
- EC-2: Credential target differs only by case or Unicode normalization →
  reject rather than selecting an ambiguous record.
- EC-3: A key is replaced after initial lookup → the next lookup detects the
  pinned fingerprint mismatch and fails.
- EC-4: Clock attestation is exactly at its freshness boundary → accept; one
  microsecond older → reject.
- EC-5: System time moves backwards between pre- and post-provider checks →
  reject regression.
- EC-6: CAS response arrives exactly at expiry → reject; accepted responses
  must be observed before expiry.
- EC-7: Identical request file already exists → stable-read and accept only
  byte-identical content; otherwise reject replay conflict.
- EC-8: Response or readback is a directory, symlink, reparse point, changes
  during read, exceeds its size bound, or contains duplicate JSON keys →
  reject.
- EC-9: Remote response says `accepted=false` even with a valid signature →
  return exact rejection to the existing store, never synthesize success.
- EC-10: IPC and cursor domains share a root or provider ID → reject custody
  domain collision.
- EC-11: Queue/cursor database does not exist → reject; runtime may not
  provision it.
- EC-12: Signed feed directory is empty → valid provider returns no input;
  missing/unsafe directory or invalid packet fails.
- EC-13: Multiple lanes disagree on account/server/environment or use a
  different commit/config/model than the IPC binding → reject before effects.
- EC-14: Pack output fails on the third or fourth file → remove only files
  created by that invocation.
- EC-15: Pack input requests `LIVE`, embeds an arm/permit, or changes a safety
  lock → reject.
- EC-16: Native Credential Manager API is unavailable on Windows → reject
  without falling back to environment variables, files, or prompts.

## API Contracts

No HTTP, public-network, broker, MT5, order, task-installation, activation, or
credential-mutation API is introduced. The documentation-only validator marker
`GET /not-applicable` MUST NOT be implemented or exposed.

```typescript
interface WindowsDecisionCredentialReference {
  key_id: CanonicalId;
  target_name: CanonicalCredentialTarget;
  fingerprint_sha256: Hex64;
}

interface ExternalDirectoryCasEndpoint {
  provider_id: CanonicalId;
  request_directory: AbsoluteWindowsPath;
  response_directory: AbsoluteWindowsPath;
}

interface WindowsDecisionProviderPackInput {
  schema_version: "windows-decision-provider-pack-input-v1";
  pack_id: CanonicalId;
  runtime: {
    service_id: CanonicalId;
    max_cycles: number;
    poll_seconds: number;
    cycle_deadline_seconds: number;
    decision_producer_binding: DecisionProducerBinding;
  };
  decision_feed_binding: DecisionFeedBinding;
  decision_ipc_binding: DecisionIPCBinding;
  clock_binding: WindowsClockBinding;
  credential_target_prefix: CanonicalCredentialPrefix;
  credential_references: WindowsDecisionCredentialReference[];
  storage: {
    finalized_m15_directory: AbsoluteWindowsPath;
    decision_ipc_database: AbsoluteWindowsPath;
    producer_cursor_database: AbsoluteWindowsPath;
    clock_attestation_path: AbsoluteWindowsPath;
  };
  external_cas: {
    ipc: ExternalDirectoryCasEndpoint;
    producer: ExternalDirectoryCasEndpoint;
  };
  cas_timeout_seconds: number;
  safety: {
    order_capability: "DISABLED";
    live_allowed: false;
    safe_to_demo_auto_order: false;
    max_lot: 0.01;
    promotion_eligible: false;
    production_execution_ready: false;
  };
}

interface WindowsDecisionProviderPackResult {
  status: "EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED";
  pack_id: CanonicalId;
  pack_identity_sha256: Hex64;
  base_suite_identity_sha256: Hex64;
  decision_base_release_identity_sha256: Hex64;
  file_sha256: ExactFileInventory;
  credential_access_performed: false;
  provider_materialization_performed: false;
  cas_request_performed: false;
  runtime_process_started: false;
  mt5_initialized: false;
  broker_mutation_performed: false;
  production_execution_ready: false;
}
```

```python
class WindowsCredentialManagerKeyProvider:
    def __call__(self, key_id: str) -> bytes: ...

class AttestedTrustedUTCProvider:
    def __call__(self) -> datetime: ...

class DecisionIPCExternalCAS:
    def current(self) -> DecisionIPCCheckpoint | None: ...
    def compare_and_swap(
        self,
        expected_previous: str,
        proposed: DecisionIPCCheckpoint,
    ) -> DecisionIPCCASAcknowledgement: ...

class DecisionProducerExternalCAS:
    def current(self) -> DecisionProducerCheckpoint | None: ...
    def compare_and_swap(
        self,
        expected_previous: str,
        proposed: DecisionProducerCheckpoint,
    ) -> DecisionProducerCASAcknowledgement: ...

def build_windows_decision_provider_service(
    *,
    runtime_config: WindowsDecisionServiceRuntimeConfig,
    provider_config: WindowsDecisionProviderConfiguration,
) -> BrokerlessDecisionProducerService: ...

def prepare_windows_decision_provider_pack(
    *,
    base_suite_root: str | Path,
    decision_base_release: str | Path,
    pack_input_path: str | Path,
    output_root: str | Path,
) -> DecisionProviderPackValidation: ...

def validate_windows_decision_provider_pack(
    *,
    base_suite_root: str | Path,
    decision_base_release: str | Path,
    pack_root: str | Path,
) -> DecisionProviderPackValidation: ...
```

Command contract:

```text
python -I -S -B prepare_windows_decision_provider_pack.py \
  --base-suite-root <exact-suite-root> \
  --decision-base-release <exact-decision-base.zip> \
  --pack-input <secret-free-pack-input.json> \
  --output-root <new-overlay-root>
```

Exit code `0` means deterministic candidate bytes were created and external
acceptance remains required. Exit code `2` means the pack is untrusted and no
runtime authority was granted.

## Data Models

### `WindowsDecisionProviderConfiguration`

| Field | Type | Constraints |
|---|---|---|
| pack_id | canonical ID | Unique immutable provider pack |
| base_suite_identity_sha256 | SHA-256 | Exact atomic five-role suite |
| decision_base_release_identity_sha256 | SHA-256 | Exact decision role |
| decision_feed_binding | `DecisionFeedBinding` | Exact lane/source/account binding |
| decision_ipc_binding | `DecisionIPCBinding` | DEMO-only exact queue binding |
| decision_producer_binding | `DecisionProducerBinding` | Exact M15 lane/provenance binding |
| clock_binding | `WindowsClockBinding` | Exact host/authority/freshness binding |
| credential_target_prefix | string | Exact immutable Credential Manager prefix |
| credential_references | tuple | Unique key ID/target/fingerprint only |
| finalized_m15_directory | Windows path | Existing regular non-reparse directory |
| decision_ipc_database | Windows path | Existing preprovisioned regular file |
| producer_cursor_database | Windows path | Existing preprovisioned regular file |
| ipc_cas directories | Windows paths | Distinct request/response custody mount |
| cursor_cas directories | Windows paths | Distinct request/response custody mount |
| IPC/cursor provider IDs | canonical IDs | Distinct custody domains |
| clock_attestation_path | Windows path | Existing signed attestation file |
| CAS timeout | float | `(0, 2.0]` seconds |
| safety fields | fixed | All activation/live values denied |

### `ExternalCASRequest`

| Field | Type | Constraints |
|---|---|---|
| schema_version | enum | Domain-specific v1 |
| request_id | SHA-256-derived ID | Unique for exact proposal |
| provider_id | canonical ID | Exact configured provider |
| state_domain | enum | `DECISION_IPC` or `PRODUCER_CURSOR` |
| identity_sha256 | SHA-256 | Queue or producer binding |
| expected_previous_sha256 | SHA-256 | Exact CAS predecessor |
| proposed_object | canonical mapping | Exact checkpoint |
| proposed_sha256 | SHA-256 | Must match object |
| issued_at_utc | UTC datetime | Trusted clock |
| expires_at_utc | UTC datetime | At most two seconds |

### `ExternalCASResponse`

| Field | Type | Constraints |
|---|---|---|
| schema_version | enum | Domain-specific v1 |
| request_id | ID | Exact request |
| acknowledgement | typed mapping | Exact signed CAS acknowledgement |
| current_object | typed mapping | Exact post-CAS readback |
| responded_at_utc | UTC datetime | Before request expiry |

### Generated Overlay

| Path | Purpose |
|---|---|
| `reviewed_windows_factory.py` | Exact sealed factory only |
| `configured_providers/__init__.py` | Closed package marker |
| `configured_providers/decision_provider.py` | Generated non-secret provider config and foundation call |
| `config/windows_service_config.json` | Exact runtime config with derived seven-role bindings |

## Out of Scope

- OS-1: Provisioning, rotating, deleting, exporting, or displaying a
  Credential Manager value.
- OS-2: Implementing or operating the independent remote CAS/WORM authority,
  private custody signer, NTP service, or off-host storage.
- OS-3: Claiming that a local directory, test backend, or self-signed fixture
  is independent provider evidence.
- OS-4: Installing Task Scheduler definitions, service accounts, NTFS ACLs,
  VPN, firewall, RDP, MT5, or broker credentials.
- OS-5: Creating an external-launcher attestation, provider-conformance
  signature, validation receipt, pre-manual observation, stage authorization,
  environment arm, promotion permit, or operator approval.
- OS-6: Auto-provisioning IPC/cursor SQLite genesis during normal service
  startup.
- OS-7: Risk approval, `TradeIntent` construction, reconciliation, execution,
  order submission, manual-demo authorization, demo-auto activation, live
  activation, or lot scaling.
- OS-8: Provider packs for `STATUS_MONITOR` or `EXECUTION`; they require
  separate approved specs after the decision pack contract is green.
- OS-9: Frontend-dashboard integration; it remains deferred until demo-auto
  soak is running with authenticated read-only status data.
