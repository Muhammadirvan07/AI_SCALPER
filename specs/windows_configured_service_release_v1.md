# Windows Configured Service Release v1

**Author:** Codex
**Date:** 2026-07-25
**Status:** Approved
**Reviewers:** AI_SCALPER project owner and ship-gate reviewer

## Metadata

- Target profiles:
  - `WINDOWS_DECISION_SERVICE_V1`
  - `WINDOWS_GATED_EXECUTION_SERVICE_V1`
  - `WINDOWS_EXTERNAL_STATUS_MONITOR_V1`
- Build authority: operator tooling only
- Order authority: none
- Demo-auto authority: none
- Live authority: none

## Context

The deterministic decision, execution, and external status-monitor base
releases intentionally contain no deployment-specific provider factory,
provider implementation, service config, or factory manifest. Each production
runner accepts a factory only when all of those files are members of the exact
release inventory. Copying them into an extracted release after build is
therefore correctly rejected.

This contract defines a second deterministic packaging step. It combines one
already verified base release with a secret-free, exact-hash configured overlay
and emits a new release identity. The base Git commit/tree and base release
identity remain visible and immutable. The configured identity is the identity
that an offline launcher issuer must review and attest.

The builder is a packaging and verification boundary. It does not import the
factory, resolve a credential, initialize MT5, install a task, consume an
authorization, or submit an order.

## Functional requirements

- FR-1: The builder MUST accept only one exact base release archive whose manifest,
   release identity, source inventory, member hashes, file set, and safety locks
   verify.
- FR-2: The configured overlay descriptor MUST use an exact schema, bind the base
   profile and identity, runtime mode, factory/config/manifest paths, provider
   source paths, reviewed static-template hash, Task Scheduler hash, and an
   exact file inventory.
- FR-3: Overlay files MUST be regular, non-symlink, bounded files. Paths MUST be
   canonical Windows-compatible POSIX release paths and MUST NOT collide with
   base members, even by case.
- FR-4: Factory source MUST be one top-level Python module. Provider sources MUST be
   under `configured_providers/`; factory manifest and service config MUST be
   under `config/`.
- FR-5: The factory manifest MUST be an exact
   `windows-service-factory-manifest-v1` object. It MUST bind the selected
   profile, exact factory/config paths and hashes, non-zero bootstrap binding,
   and canonical factory-contract hash.
- FR-6: Every overlay JSON file MUST be canonical UTF-8 JSON with one trailing LF,
   duplicate keys rejected, finite values only, and no embedded secret value.
- FR-7: Overlay Python MUST parse as Python 3.12 source, preserve complete local
   import closure, and reject direct MT5 imports, order primitives, dynamic
   code loading, subprocess/process launch, native extension loading, or
   probable embedded secrets.
- FR-8: The configured manifest MUST retain the base manifest schema/profile,
   commit/tree, safety locks, and base source bytes; add the exact configured
   binding and combined source inventory; preserve
   `production_execution_ready=false`; and compute a new identity from the
   complete unsigned configured manifest.
- FR-9: Archive member order, timestamps, permissions, compression, JSON
   serialization, and output bytes MUST be deterministic.
- FR-10: An independent verifier MUST reconstruct both base and configured
    identities, verify every member, and return a sealed deny-only report.
- FR-11: Output creation MUST be exclusive. Existing output or manifest paths MUST
    never be overwritten.
- FR-12: The CLI MUST expose no password, login, secret, token, private-key, order,
    permit, arm, or activation argument.
- FR-13: The base archive itself MUST be byte-identical to the canonical
    deterministic ZIP reconstructed from its verified members and manifest.
    Equal logical content with timestamp, permission, ordering, or compression
    drift MUST be rejected.
- FR-14: Except for the combined source inventory, configured binding, readiness
    blockers, and recomputed identity, every configured manifest field MUST
    inherit the nested base manifest exactly. Commit, tree, dependency,
    usage-policy, trust-boundary, or other base-field drift MUST fail closed.
- FR-15: The builder MUST run the independent configured-release verifier against
    the in-memory archive before either output is materialized.
- FR-16: The builder/verifier runtime MUST be distributed through a separate,
    exact, stdlib-only operator-tooling release. The generic read-only tooling
    release MUST retain its byte-level order-primitive prohibition; it MUST NOT
    be weakened merely because this verifier names denied primitives.
- FR-17: The roadmap-supported CLI MUST require one exact atomic five-role
    base-release suite root and MUST reject a base ZIP that is not the exact
    matching decision, execution, or status-monitor role member.
- FR-18: A suite-bound configured manifest MUST record the suite schema/profile,
    suite identity, suite-manifest hash, exact role, role archive hash, and
    role sidecar hash. Legacy configured releases MAY remain independently
    readable for diagnostics but MUST NOT pass pre-manual admission.

## Non-Functional Requirements

- NFR-1: Identical verified inputs MUST produce byte-identical ZIP, sidecar,
  and release-identity output on supported Windows CPython 3.12 hosts.
- NFR-2: All archive and regular-file reads MUST be bounded, stable, and
  fail closed on path indirection, truncation, replacement, or size drift.
- NFR-3: Build and verification MUST perform zero provider import, credential
  access, task installation, MT5 initialization, broker mutation, activation,
  permit issuance, or order submission.
- NFR-4: Validation MUST behave identically with normal Python execution and
  `PYTHONOPTIMIZE=2`; security enforcement MUST NOT depend on `assert`.
- NFR-5: The verifier MUST reject unknown schema fields and ambiguous legacy
  ancestry before pre-manual admission.

### Safety invariants

Every successful build and verification report MUST retain:

```text
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
production_execution_ready = false
broker_mutation_performed = false
provider_materialization_performed = false
credential_access_performed = false
task_installation_performed = false
```

The execution profile may retain `order_capability=GATED_PRESENT` because its
reviewed base release contains the sealed adapter. That fact does not grant
authority. The decision and status-monitor profiles MUST retain
`order_capability=DISABLED`; the monitor also remains status-only and has no
broker SDK or execution boundary.

## Acceptance criteria

### AC-1: Deterministic configured build (FR-1, FR-2, FR-8, FR-9)

Given identical verified base-suite and overlay bytes, when two configured
builds run independently, then their archives, manifests, and configured
identities are byte-identical.

### AC-2: Base tamper denial (FR-1, FR-10, FR-13, FR-14)

Given base archive tamper, duplicate or traversal members, identity drift,
extra members, source drift, profile mismatch, safety drift, non-deterministic
ZIP metadata, or nested-manifest drift, when verification runs, then it fails
closed without output.

### AC-3: Overlay boundary denial (FR-3, FR-4, FR-6)

Given a missing, extra, symlinked, case-colliding, noncanonical, duplicate-key,
hash-drifted, or size-drifted overlay file, when the build runs, then it fails
closed.

### AC-4: Factory binding denial (FR-5)

Given factory/config/manifest path drift, hash drift, contract drift, zero
bootstrap binding, or an unreviewed provider path, when validation runs, then
it fails closed.

### AC-5: Executable and secret surface denial (FR-7, FR-12)

Given secret material, private-key or token patterns, `MetaTrader5`,
`order_send`, `order_check`, dynamic code loading, subprocess, or native
loader use in overlay source, when the builder or CLI validates input, then it
rejects the candidate.

### AC-6: Static execution compatibility (FR-10, FR-15)

Given a valid execution configured archive, when the independent verifier and
existing static factory-manifest verifier inspect it, then both accept it
without importing the factory.

### AC-7: Decision authority remains absent (FR-8, FR-16)

Given a valid decision configured archive, when it is inspected, then it has
no execution capability and remains unusable without the separately reviewed
runtime loader and launcher attestation.

### AC-8: Zero side effects (FR-12, FR-15, FR-16)

Given build and verification tests, when all paths execute, then they prove
zero factory import, credential read, MT5 initialization, task installation,
provider materialization, and broker mutation.

### AC-9: Exclusive publication (FR-11)

Given an existing output or sidecar path, when a build attempts publication,
then it fails closed and preserves existing bytes.

### AC-10: Exact tooling closure (FR-16)

Given the operator-tooling release, when its inventory and source surface are
audited, then it contains exactly the allowlist, no external provider, and no
executable broker/order capability.

### AC-11: Exact five-role ancestry (FR-17, FR-18)

Given a suite-bound configured build, when ancestry is verified, then all five
base artifacts and the exact matching role are proven; when the base path is a
non-member, role is substituted, suites are mixed, a supporting role is
missing, or any suite manifest/archive/sidecar is tampered, then validation
fails closed.

## Edge Cases

- EC-1: A base ZIP with identical logical members but different timestamps,
  ordering, permissions, or compression is rejected.
- EC-2: A configured base path that resolves outside the suite root or through
  a symlink/reparse point is rejected.
- EC-3: A valid decision base archive presented as the execution role is
  rejected even when commit/tree match.
- EC-4: A suite supporting role not used by the three configured services is
  still mandatory and its tamper rejects admission.
- EC-5: A legacy configured archive without suite binding remains diagnostic
  readable but is rejected by pre-manual admission.
- EC-6: Concurrent output creation preserves the first complete output and
  rejects the later writer without overwrite.

## API Contracts

The feature is a local Python/CLI boundary and MUST NOT expose an HTTP API.
`GET /not-applicable` is a documentation-only validator marker and MUST NOT be
implemented.

```typescript
interface ConfiguredReleaseBuildRequest {
  baseReleaseSuiteRoot: string;
  baseReleaseArchive: string;
  overlayDescriptor: string;
  outputArchive: string;
}

interface ConfiguredReleaseVerificationReport {
  releaseProfile: string;
  configuredReleaseIdentitySha256: string;
  baseReleaseSuiteBound: boolean;
  baseReleaseSuiteIdentitySha256: string | null;
  baseReleaseSuiteRole: "DECISION" | "EXECUTION" | "STATUS_MONITOR" | null;
  liveAllowed: false;
  safeToDemoAutoOrder: false;
  maxLot: 0.01;
  productionExecutionReady: false;
}
```

## Data Models

| Field | Type | Constraints |
|---|---|---|
| `suite_identity_sha256` | string | Exactly 64 lowercase hexadecimal characters |
| `suite_manifest_sha256` | string | SHA-256 of exact canonical `BASE_RELEASE_SUITE.json` bytes |
| `role` | enum | Exactly `DECISION`, `EXECUTION`, or `STATUS_MONITOR` |
| `role_archive_sha256` | string | Must equal the verified suite role archive hash |
| `role_sidecar_sha256` | string | Must equal the verified suite role sidecar hash |
| `configured_release_identity_sha256` | string | Recomputed from the complete unsigned configured manifest |

## Output manifest binding

The configured release adds this object to the inherited base manifest:

```text
configured_release:
  schema_version
  overlay_id
  runtime_mode
  base_release_profile
  base_release_identity_sha256
  base_release_archive_sha256
  base_release_manifest_sha256
  base_release_manifest
  overlay_descriptor_sha256
  overlay_descriptor
  overlay_file_set_sha256
  factory_manifest_relative_path
  factory_source_relative_path
  service_config_relative_path
  provider_source_relative_paths
  reviewed_factory_template_sha256
  task_definition_sha256
  factory_contract_sha256
  bootstrap_binding_sha256
  live_allowed
  safe_to_demo_auto_order
  max_lot
  provider_materialization_performed
  credential_access_performed
  task_installation_performed
  broker_mutation_performed
  base_release_suite:
    schema_version
    suite_schema_version
    suite_release_profile
    suite_identity_sha256
    suite_manifest_sha256
    role
    role_archive_sha256
    role_sidecar_sha256
```

The top-level `release_identity_sha256` is recomputed after this object and the
combined source inventory are installed. Launcher policy and short-lived
attestation must bind this configured identity, not the base identity.

## Out of scope

- OS-1: Supplying concrete provider behavior or credentials.
- OS-2: Signing launcher attestations.
- OS-3: Registering Task Scheduler tasks or ACLs.
- OS-4: Provisioning Credential Manager, IPC/CAS, journal, WORM, news, clock,
  or MT5.
- OS-5: Enabling manual demo, demo-auto, live, promotion, or order submission.
