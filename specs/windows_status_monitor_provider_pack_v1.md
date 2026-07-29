# Spec: Windows Status Monitor Provider Pack v1

**Author:** Codex with AI_SCALPER project owner  
**Date:** 2026-07-25  
**Status:** Approved  
**Reviewers:** AI_SCALPER project owner under the standing authorization to
continue the live-grade roadmap while preserving every execution and live
lock  
**Related specs:**
`specs/windows_external_status_monitor_v1.md`,
`specs/windows_shared_provider_primitives_v1.md`,
`specs/windows_configured_service_release_v1.md`,
`specs/windows_atomic_base_release_suite_v1.md`,
`specs/windows_three_service_provider_conformance_v2.md`

**Revision 2026-07-29:** checkpoint and incident request files are published
through a private, fully flushed staging file followed by one atomic
no-replace final-name operation. A directory watcher can never observe a
partially written `*.request.json` document.

## Context

The deterministic Status Monitor base release already contains the exact
status-only runtime, configured-release loader, twelve provider contracts,
off-host delivery envelope/outbox primitives, and shared read-only Windows
Credential Manager and trusted-clock primitives. It deliberately contains no
configured provider references, credential values, factory, task
installation, broker access, or order authority.

An operational configured Status Monitor still cannot be assembled from the
current repository. Its factory requires exact implementations for:

1. `ALERT_OUTBOX`;
2. `ALERT_TRANSPORT`;
3. `CHECKPOINT_ACK_VERIFIER`;
4. `CHECKPOINT_CAS`;
5. `HEARTBEAT_OUTBOX`;
6. `HEARTBEAT_TRANSPORT`;
7. `INCIDENT_ACK_VERIFIER`;
8. `INCIDENT_LATCH`;
9. `REMOTE_ACK_KEY_CUSTODY`;
10. `SENDER_KEY_CUSTODY`;
11. `STATUS_SNAPSHOT_SOURCE`; and
12. `TRUSTED_CLOCK`.

This feature adds a standard-library-only runtime foundation and one offline
generator/validator for a secret-free Status Monitor provider overlay. The
runtime reads exact pinned HMAC keys from Windows Credential Manager and uses
preprovisioned local SQLite files plus independently controlled directory
protocols. A local directory or test signer is never evidence of off-host
custody or provider acceptance.

Generation and validation are deny-only. They do not access credentials,
open provider state, create a database or directory, issue a provider request,
import the generated factory, start a process, initialize MT5, access a
broker, install a task, or submit an order.

## Functional Requirements

- FR-1: The Status Monitor base release MUST expose one reviewed provider
  foundation that imports only the monitor runtime, off-host delivery module,
  shared Windows provider primitives, and standard-library modules allowed by
  the exact release allowlist.
- FR-2: Runtime key custody MUST use
  `WindowsCredentialManagerKeyProvider`. The provider configuration MUST bind
  exactly seven distinct key IDs and fingerprints for clock authority,
  snapshot attestation, checkpoint custody, incident custody, heartbeat
  sender, alert sender, and remote delivery acknowledgement.
- FR-3: Every key ID and Credential Manager target MUST be unique under
  case-folding. Every target MUST equal `<target-prefix>/<key-id>`. Credential
  enumeration, write, update, deletion, export, logging, serialization, or
  fallback to a file/environment/prompt is forbidden.
- FR-4: Trusted UTC MUST use `AttestedTrustedUTCProvider` with one exact
  `WindowsClockBinding`, one preprovisioned attestation file, the pinned clock
  key, aware UTC, monotonicity, freshness, and absolute drift no greater than
  one second.
- FR-5: `STATUS_SNAPSHOT_SOURCE` MUST read only the exact successor file
  derived from the externally verified checkpoint sequence. Its canonical
  signed envelope MUST bind provider ID, monitor service ID, sequence,
  predecessor snapshot hash, exact snapshot mapping/hash, key ID, issue UTC,
  expiry UTC, and HMAC.
- FR-6: Snapshot parsing MUST reconstruct exact
  `ExternalStatusSnapshot`, `MonitoredServiceObservation`, and
  `MonitorHostObservation` values. A missing, stale, future, forged,
  malformed, oversized, duplicate-key, noncanonical, path-indirected,
  replayed, forked, identity-drifted, or unsafe snapshot MUST fail before
  monitor evaluation.
- FR-7: `CHECKPOINT_CAS` MUST use one current-checkpoint signed envelope plus
  create-exclusive request and signed-response directories. The request MUST
  bind provider ID, monitor service ID, exact predecessor checkpoint,
  proposed checkpoint, request ID, issued UTC, and expiry.
- FR-8: The checkpoint adapter MUST return only an exact
  `MonitorCheckpointAcknowledgement` after verifying the signed response,
  exact request, predecessor, proposal, provider ID, accepted state, and
  exact post-CAS readback. The checkpoint verifier MUST return true only for
  objects verified by that adapter instance.
- FR-9: `INCIDENT_LATCH` MUST create one idempotent request bound to the exact
  `ExternalStatusAssessment`, incident ID, provider ID, issue UTC, and expiry,
  and MUST accept only a signed exact `MonitorIncidentAcknowledgement`. The
  incident verifier MUST return true only for acknowledgements verified by
  that adapter instance. Checkpoint and incident requests MUST be written to
  invocation-owned private staging names, fully written, file-synced,
  stable-read, and then published under the final protocol name with one
  atomic no-replace operation. A watcher MUST NOT observe a partial final
  request, and cleanup MUST remove only the exact invocation-owned staging
  inode.
- FR-10: External checkpoint and incident adapters MUST never mint custody
  signatures, clear a latch, rewrite a response, synthesize success, or claim
  that local storage is independently controlled.
- FR-11: `HEARTBEAT_OUTBOX` and `ALERT_OUTBOX` MUST be exact
  `DeliveryOutbox` instances opened in require-existing mode. Their databases
  MUST be distinct, preprovisioned regular non-symlink/non-reparse SQLite WAL
  files with the exact reviewed schema and a successful integrity check.
- FR-12: `HEARTBEAT_TRANSPORT` and `ALERT_TRANSPORT` MUST be exact
  `DirectoryDropTransport` instances opened in require-existing mode. Their
  outbound and acknowledgement directories MUST already exist, be regular
  directories, and remain distinct across delivery domains.
- FR-13: The heartbeat and alert sender keys, destinations, outboxes, and
  transport directories MUST be distinct. One pinned remote acknowledgement
  key MAY verify both delivery channels, but it MUST be distinct from all
  sender and provider custody keys.
- FR-14: Materialization MUST validate every runtime/provider identity,
  release identity, provider contract/configuration/implementation hash,
  destination, key, path, timeout, and fixed safety value before opening a
  database, reading a credential, or issuing any request.
- FR-15: Every configured file and directory path MUST be an absolute
  normalized Windows path. Paths MUST be unique under case-folding and no
  configured provider root may be equal to, an ancestor of, or a descendant
  of another provider root.
- FR-16: Runtime materialization MUST reject missing, non-regular,
  symlink/reparse, permission-incompatible, unstable, or schema-invalid state.
  It MUST NOT auto-provision any directory, SQLite database, credential,
  attestation, snapshot, checkpoint, response, or acknowledgement.
- FR-17: The provider foundation MUST build exactly one
  `StatusMonitorDependencies` object and the generated factory MUST seal it
  only through `seal_windows_external_status_monitor_factory_result(...)`.
- FR-18: An offline generator MUST accept one exact atomic-suite Status
  Monitor base release, one canonical secret-free provider-pack input, and
  one new overlay directory. It MUST write exactly:
  `reviewed_windows_factory.py`,
  `configured_providers/__init__.py`,
  `configured_providers/status_monitor_provider.py`, and
  `config/windows_service_config.json`.
- FR-19: The generator MUST derive all twelve provider implementation and
  configuration hashes. Callers MUST NOT supply or override these hashes.
  Implementation hash schema v1 MUST transitively bind the exact bytes and
  archive paths of:
  `live_runtime/windows_status_monitor_provider_pack.py`,
  `live_runtime/windows_provider_primitives.py`, and
  `live_runtime/offhost_delivery.py`.
- FR-20: The runtime configuration MUST bind the exact base Status Monitor
  release identity and all twelve derived provider bindings. The generated
  provider module MUST contain only canonical non-secret configuration and a
  call to the reviewed provider foundation.
- FR-21: Generator input and generated output MUST reject passwords, account
  logins, key bytes, tokens, private keys, URLs, environment arms, promotion
  permits, approvals, live flags, and credential values.
- FR-22: Generation MUST validate canonical JSON, closed schemas, exact
  atomic-suite ancestry, release/member hashes, path policy, role
  completeness, cross-binding consistency, generated AST/import closure,
  secret scans, and safety locks before writing.
- FR-23: Generation MUST be deterministic and create-exclusive. A failure
  after output begins MUST remove only files created by that invocation and
  preserve every pre-existing file.
- FR-24: Offline validation MUST verify the generated pack without importing
  its factory, materializing a provider, reading credentials, opening SQLite,
  issuing external requests, starting a service, accessing MT5, or performing
  broker work.
- FR-25: A separately assembled configured candidate MUST retain the provider
  pack as immutable evidence, build the configured Status Monitor release
  through the generic configured-release boundary, and remain
  `EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED`.
- FR-26: Every generated, validated, and assembled result MUST preserve
  `status_only=true`, `order_capability=DISABLED`, `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `max_lot=0.01`,
  `promotion_eligible=false`, `provider_accepted=false`, and
  `production_execution_ready=false`.
- FR-27: The provider pack MUST NOT import MetaTrader5, an execution adapter,
  risk governor, permit, intent, reconciliation, subprocess, socket, HTTP,
  Task Scheduler mutation, or order primitives.
- FR-28: The provider foundation MUST be present only in the Status Monitor
  base release and configured operator tooling as appropriate. It MUST not be
  added to Decision, Execution, read-only shadow, or broker-order authority.

## Non-Functional Requirements

- NFR-1 Security: Secret values MUST never occur in CLI arguments, generated
  files, repository files, logs, exceptions, manifests, or result objects.
  Public failures MUST use stable uppercase reason codes.
- NFR-2 Reliability: Every signature, identity, sequence, filesystem, SQLite,
  clock, checkpoint, latch, outbox, transport, and acknowledgement ambiguity
  MUST fail before checkpoint advancement.
- NFR-3 Determinism: Identical exact base release and canonical input MUST
  produce byte-identical overlay files and identical twelve-role hashes.
- NFR-4 Resource bounds: Each input/generated/provider document MUST be at
  most 4 MiB; generated aggregate bytes MUST be at most 16 MiB; signed
  provider responses MUST be at most 4 MiB.
- NFR-5 Latency: Offline generation and validation SHOULD each complete in
  under two seconds on the development host. External checkpoint/incident
  response timeouts MUST be in `(0, 2.0]` seconds.
- NFR-6 Concurrency: Identical concurrent external requests MUST converge on
  one byte-identical request. Conflicting reuse of a request ID/path MUST
  reject. Final protocol filenames MUST become visible only after complete
  bytes are durable in the staging file. Verified-object caches MUST be lock
  protected and bounded.
- NFR-7 Portability: Offline generation, validation, and unit tests MUST run
  on macOS and Windows. Native credential materialization MUST reject all
  non-Windows platforms before backend access.
- NFR-8 Regression: Focused tests MUST pass normally and with
  `PYTHONOPTIMIZE=2`. Full tracked-project regression, compilation,
  dependency-lock, SBOM, release-boundary, deterministic-rebuild, and safety
  scans MUST remain green.

## Acceptance Criteria

### AC-1: Exact twelve-role configuration (FR-1, FR-14, FR-17, FR-20)

Given a canonical pack input and exact Status Monitor base release  
When offline generation runs  
Then the service configuration contains exactly twelve sorted provider roles  
And every contract hash matches the static monitor factory contract  
And every implementation/configuration hash is non-zero and derived.

### AC-2: Validation has zero provider effects (FR-22 through FR-24)

Given a valid generated pack and sentinels for credentials, SQLite, provider
directories, process, network, MT5, broker, task installation, and order
effects  
When offline validation runs  
Then every sentinel remains untouched  
And no generated factory is imported.

### AC-3: Shared credential and clock custody is exact (FR-2, FR-3, FR-4)

Given seven pinned Credential Manager references and one fresh signed clock
attestation  
When dependencies materialize on Windows  
Then only exact requested credentials are read  
And trusted UTC is aware, fresh, within one-second drift, and monotonic.

### AC-4: Signed successor snapshot is accepted (FR-5, FR-6)

Given checkpoint sequence `n` and one exact signed snapshot envelope for
`n+1` with the exact predecessor  
When the snapshot provider is invoked  
Then it returns one exact `ExternalStatusSnapshot` with verified source
attestation and matching content hash.

### AC-5: Snapshot ambiguity fails closed (FR-5, FR-6; NFR-2)

Given a replayed, forked, stale, future, forged, malformed, oversized,
noncanonical, duplicate-key, path-indirected, identity-drifted, or unsafe
snapshot file  
When the provider is invoked  
Then it raises a stable failure before evaluation or checkpoint mutation.

### AC-6: External checkpoint CAS succeeds exactly once (FR-7, FR-8, FR-10)

Given one verified predecessor checkpoint and exact successor  
When the adapter submits a request and receives an exact signed accepted
response/readback  
Then it returns one exact `MonitorCheckpointAcknowledgement`  
And an identical retry is idempotent  
And its verifier returns true for that exact acknowledgement.

### AC-7: External checkpoint ambiguity fails closed (FR-7, FR-8, FR-10)

Given a missing, expired, forged, rejected, forked, rolled-back,
path-indirected, or readback-mismatched checkpoint response  
When CAS runs  
Then it raises a stable failure and never synthesizes checkpoint progress.

### AC-8: Critical incident latches exactly once (FR-9, FR-10)

Given an exact critical `ExternalStatusAssessment`  
When incident latching receives one exact signed acknowledgement  
Then the returned typed acknowledgement is verifier-approved  
And retries converge on the same request  
And a concurrent directory watcher never observes partial final request bytes
And no clear/unlatch capability exists.

### AC-9: Preprovisioned outboxes and transports (FR-11, FR-12, FR-14,
FR-15, FR-16)

Given exact preprovisioned SQLite databases and delivery directories  
When materialization runs  
Then it opens exact outboxes/transports without creating a path or schema  
And missing, unsafe, overlapping, or invalid state rejects before credential
access or external request.

### AC-10: Delivery remains independently acknowledged (FR-11 through FR-13)

Given distinct heartbeat/alert outboxes, transports, sender keys, and
destinations plus the pinned remote acknowledgement key  
When a monitor cycle publishes artifacts  
Then each envelope uses its exact channel  
And checkpoint CAS occurs only after verified remote acknowledgements.

### AC-11: Deterministic secret-free generation (FR-18 through FR-23)

Given two new output directories and identical input/base bytes  
When generation runs twice  
Then all four generated files are byte-identical  
And neither pack contains secrets, activation authority, URLs, broker access,
or order authority.

### AC-12: Transactional generation failure (FR-21 through FR-23)

Given secret-bearing, unknown-field, noncanonical, oversized, unsafe-path,
wrong-base, incomplete-role, cross-binding-drifted, symlink/reparse, or
pre-existing output  
When generation fails  
Then no existing file is changed and no invocation-owned partial output
remains.

### AC-13: Transitive implementation binding (FR-19)

Given identical configuration and base suite except for one byte in the
shared primitives, outbox/transport module, or Status Monitor provider
foundation  
When provider hashes are derived  
Then all affected role implementation hashes change  
And a missing, duplicate, empty, or oversized foundation archive member is
rejected before output.

### AC-14: Configured candidate remains deny-only (FR-25, FR-26)

Given a validated pack, exact base suite, reviewed task definition, and
generic configured-release tooling  
When the Status Monitor candidate is assembled and validated  
Then it contains exact immutable evidence and configured release bytes  
And its status remains `EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED`  
And no provider is accepted or materialized.

### AC-15: Release isolation and regression remain exact (FR-27, FR-28; NFR-8)

Given all release allowlists and the atomic suite builder  
When release-boundary, focused, optimized, full, supply-chain, and safety
checks run  
Then every check passes  
And Decision/Execution/shadow/order authority is unchanged.

## Edge Cases and Error Scenarios

- EC-1: Any key ID or target differs only by case → reject ambiguity.
- EC-2: One key is assigned to two custody roles → reject domain collapse.
- EC-3: Credential fingerprint changes after construction → next lookup
  rejects; no key cache hides the drift.
- EC-4: Clock attestation is exactly at freshness boundary → accept; one
  microsecond older → reject.
- EC-5: Snapshot filename sequence differs from signed sequence → reject.
- EC-6: Snapshot signature is valid but `source_attestation_verified=false` →
  reject rather than upgrading an unsafe object.
- EC-7: First checkpoint uses a non-zero snapshot hash or later checkpoint
  uses zero → reject according to the exact checkpoint contract.
- EC-8: Create-exclusive request already exists → accept only byte-identical
  content; conflicting content rejects.
- EC-8a: A write, sync, publication, or cleanup failure swaps the staging or
  final path → fail closed, preserve the replacement object, and never
  delete anything not owned by the invocation.
- EC-9: Response arrives exactly at expiry → reject.
- EC-10: Response is accepted but readback differs from the proposal → reject.
- EC-11: Incident response is validly signed but references another
  assessment → reject.
- EC-12: Outbox database exists but lacks one reviewed column/index/constraint
  or fails integrity check → reject before key access.
- EC-13: A transport/outbox constructor is asked to provision state in
  configured mode → reject.
- EC-14: Any configured root is a symlink, reparse point, ancestor, descendant,
  duplicate, or case-only alias of another root → reject.
- EC-15: Heartbeat and alert share a database, directory, destination, sender
  key, or provider configuration hash → reject.
- EC-16: Generated output fails after file three → remove only the three files
  created by that invocation.
- EC-17: Input embeds `LIVE`, an arm, permit, login, password, URL, token, or
  secret-looking byte sequence → reject before output.
- EC-18: Native Windows APIs are unavailable → reject without fallback.

## API Contracts

No HTTP, public-network, broker, MT5, order, task-installation, activation, or
credential-mutation API is introduced. The documentation-only validator
marker `GET /not-applicable` MUST NOT be implemented or exposed.

```typescript
interface WindowsStatusMonitorProviderPackInput {
  schema_version: "windows-status-monitor-provider-pack-input-v1";
  pack_id: CanonicalId;
  runtime: ExternalMonitorConfigWithoutProviders;
  clock_binding: WindowsClockBinding;
  credential_target_prefix: CanonicalCredentialPrefix;
  credential_references: WindowsDecisionCredentialReference[];
  keys: {
    snapshot_key_id: CanonicalId;
    checkpoint_key_id: CanonicalId;
    incident_key_id: CanonicalId;
    heartbeat_sender_key_id: CanonicalId;
    alert_sender_key_id: CanonicalId;
    remote_ack_key_id: CanonicalId;
  };
  storage: {
    clock_attestation_path: AbsoluteWindowsPath;
    snapshot_directory: AbsoluteWindowsPath;
    checkpoint_current_path: AbsoluteWindowsPath;
    heartbeat_outbox_database: AbsoluteWindowsPath;
    alert_outbox_database: AbsoluteWindowsPath;
  };
  checkpoint: {
    provider_id: CanonicalId;
    request_directory: AbsoluteWindowsPath;
    response_directory: AbsoluteWindowsPath;
  };
  incident: {
    provider_id: CanonicalId;
    request_directory: AbsoluteWindowsPath;
    response_directory: AbsoluteWindowsPath;
  };
  delivery: {
    heartbeat_outbound_directory: AbsoluteWindowsPath;
    heartbeat_acknowledgement_directory: AbsoluteWindowsPath;
    alert_outbound_directory: AbsoluteWindowsPath;
    alert_acknowledgement_directory: AbsoluteWindowsPath;
  };
  provider_timeout_seconds: number;
  safety: {
    status_only: true;
    order_capability: "DISABLED";
    live_allowed: false;
    safe_to_demo_auto_order: false;
    max_lot: 0.01;
    promotion_eligible: false;
    production_execution_ready: false;
  };
}

interface WindowsStatusMonitorProviderPackResult {
  status: "EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED";
  pack_id: CanonicalId;
  pack_identity_sha256: Hex64;
  base_suite_identity_sha256: Hex64;
  status_monitor_base_release_identity_sha256: Hex64;
  file_sha256: ExactFileInventory;
  credential_access_performed: false;
  provider_materialization_performed: false;
  provider_request_performed: false;
  sqlite_open_performed: false;
  runtime_process_started: false;
  mt5_initialized: false;
  broker_mutation_performed: false;
  production_execution_ready: false;
}
```

```python
@dataclass(frozen=True)
class WindowsStatusMonitorProviderConfiguration: ...

class SignedStatusSnapshotDirectory:
    def __call__(
        self,
        checkpoint: MonitorCheckpoint,
    ) -> ExternalStatusSnapshot: ...

class ExternalMonitorCheckpointCAS:
    def current(self) -> MonitorCheckpoint: ...
    def verify(self, checkpoint: MonitorCheckpoint) -> bool: ...
    def compare_and_swap(
        self,
        expected: MonitorCheckpoint,
        proposed: MonitorCheckpoint,
    ) -> MonitorCheckpointAcknowledgement: ...
    def verify_acknowledgement(
        self,
        acknowledgement: MonitorCheckpointAcknowledgement,
    ) -> bool: ...

class ExternalMonitorIncidentLatch:
    def __call__(
        self,
        assessment: ExternalStatusAssessment,
    ) -> MonitorIncidentAcknowledgement: ...
    def verify_acknowledgement(
        self,
        acknowledgement: MonitorIncidentAcknowledgement,
    ) -> bool: ...

def build_windows_status_monitor_dependencies(
    *,
    runtime_config: ExternalMonitorConfig,
    provider_config: WindowsStatusMonitorProviderConfiguration,
) -> StatusMonitorDependencies: ...

def prepare_windows_status_monitor_provider_pack(
    *,
    base_suite_root: str | Path,
    status_monitor_base_release: str | Path,
    pack_input_path: str | Path,
    output_root: str | Path,
) -> StatusMonitorProviderPackValidation: ...

def validate_windows_status_monitor_provider_pack(
    *,
    base_suite_root: str | Path,
    status_monitor_base_release: str | Path,
    pack_root: str | Path,
) -> StatusMonitorProviderPackValidation: ...
```

Command contract:

```text
python -I -S -B prepare_windows_status_monitor_provider_pack.py \
  --base-suite-root <exact-suite-root> \
  --status-monitor-base-release <exact-status-monitor-base.zip> \
  --pack-input <secret-free-pack-input.json> \
  --output-root <new-overlay-root>
```

Exit code `0` means deterministic candidate bytes were created and external
acceptance remains required. Exit code `2` means the pack is untrusted and no
runtime authority was granted.

## Data Models

### `WindowsStatusMonitorProviderConfiguration`

| Field | Type | Constraints |
|---|---|---|
| pack/base identities | IDs/SHA-256 | Exact atomic suite and Status Monitor role |
| runtime binding hash | SHA-256 | Exact service configuration without provider hashes |
| clock binding/path | contract/path | Exact shared trusted-clock boundary |
| credential prefix/references | string/tuple | Seven unique non-secret references |
| role key IDs | IDs | Seven distinct custody domains |
| snapshot directory | Windows path | Existing read-only signed successor source |
| checkpoint current/request/response | Windows paths | Existing external CAS custody |
| incident request/response | Windows paths | Existing external latch custody |
| heartbeat/alert outbox databases | Windows paths | Existing distinct exact SQLite state |
| heartbeat/alert transport roots | Windows paths | Four existing distinct delivery roots |
| provider timeout | float | `(0, 2.0]` seconds |
| safety | constants | Status-only and every activation lock denied |

### `SignedStatusSnapshotEnvelope`

| Field | Type | Constraints |
|---|---|---|
| schema_version | enum | `windows-status-snapshot-envelope-v1` |
| provider/service IDs | IDs | Exact configured identities |
| sequence/predecessor | integer/SHA-256 | Exact checkpoint successor |
| snapshot/snapshot hash | mapping/SHA-256 | Canonical exact snapshot |
| key ID | ID | Exact snapshot attestation key |
| issued/expires UTC | aware datetime | Fresh and within provider timeout |
| hmac_sha256 | SHA-256 | Domain-separated canonical HMAC |

### `ExternalCheckpointRequest/Response`

The request binds exact provider/service IDs, predecessor and proposal
objects/hashes, deterministic request ID, issue UTC, and expiry. The response
binds the request hash, typed acknowledgement, exact current readback, key ID,
response UTC, and HMAC. Only accepted exact readback returns success.

### `ExternalIncidentRequest/Response`

The request binds exact provider/service IDs, incident/assessment IDs and
hashes, full canonical assessment, deterministic request ID, issue UTC, and
expiry. The response binds the request hash, typed acknowledgement, key ID,
response UTC, and HMAC.

### Generated Overlay

| Path | Purpose |
|---|---|
| `reviewed_windows_factory.py` | Exact sealed Status Monitor factory |
| `configured_providers/__init__.py` | Closed package marker |
| `configured_providers/status_monitor_provider.py` | Canonical non-secret config plus foundation call |
| `config/windows_service_config.json` | Exact runtime config with derived twelve-role bindings |

## Out of Scope

- OS-1: Provisioning, rotating, deleting, exporting, or displaying Credential
  Manager values.
- OS-2: Implementing or operating the independent snapshot producer,
  checkpoint/latch authority, off-host receiver, signer, NTP authority, or
  WORM storage.
- OS-3: Claiming that local test directories or fixture signatures prove
  independent custody/provider acceptance.
- OS-4: Auto-provisioning outbox SQLite files, provider directories,
  checkpoints, latches, snapshots, clock attestations, or acknowledgements
  during configured startup.
- OS-5: Installing Task Scheduler definitions, service accounts, NTFS ACLs,
  VPN/firewall/RDP policy, MT5, or broker credentials.
- OS-6: Provider conformance approval, launcher attestation, stage
  authorization, environment arm, promotion permit, operator approval,
  demo-auto activation, or live activation.
- OS-7: Risk approval, trade intent, execution, reconciliation, broker
  mutation, order submission/modification/closure, or lot scaling.
- OS-8: Provider packs for `EXECUTION`; that requires a separate approved spec
  and cannot inherit Status Monitor authority.
- OS-9: Frontend/dashboard integration; it remains deferred until authenticated
  read-only status data and a clean demo-auto soak exist.
