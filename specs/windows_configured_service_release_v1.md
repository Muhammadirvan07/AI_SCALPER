# Windows Configured Service Release v1

## Status

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

1. The builder MUST accept only one exact base release archive whose manifest,
   release identity, source inventory, member hashes, file set, and safety locks
   verify.
2. The configured overlay descriptor MUST use an exact schema, bind the base
   profile and identity, runtime mode, factory/config/manifest paths, provider
   source paths, reviewed static-template hash, Task Scheduler hash, and an
   exact file inventory.
3. Overlay files MUST be regular, non-symlink, bounded files. Paths MUST be
   canonical Windows-compatible POSIX release paths and MUST NOT collide with
   base members, even by case.
4. Factory source MUST be one top-level Python module. Provider sources MUST be
   under `configured_providers/`; factory manifest and service config MUST be
   under `config/`.
5. The factory manifest MUST be an exact
   `windows-service-factory-manifest-v1` object. It MUST bind the selected
   profile, exact factory/config paths and hashes, non-zero bootstrap binding,
   and canonical factory-contract hash.
6. Every overlay JSON file MUST be canonical UTF-8 JSON with one trailing LF,
   duplicate keys rejected, finite values only, and no embedded secret value.
7. Overlay Python MUST parse as Python 3.12 source, preserve complete local
   import closure, and reject direct MT5 imports, order primitives, dynamic
   code loading, subprocess/process launch, native extension loading, or
   probable embedded secrets.
8. The configured manifest MUST retain the base manifest schema/profile,
   commit/tree, safety locks, and base source bytes; add the exact configured
   binding and combined source inventory; preserve
   `production_execution_ready=false`; and compute a new identity from the
   complete unsigned configured manifest.
9. Archive member order, timestamps, permissions, compression, JSON
   serialization, and output bytes MUST be deterministic.
10. An independent verifier MUST reconstruct both base and configured
    identities, verify every member, and return a sealed deny-only report.
11. Output creation MUST be exclusive. Existing output or manifest paths MUST
    never be overwritten.
12. The CLI MUST expose no password, login, secret, token, private-key, order,
    permit, arm, or activation argument.
13. The base archive itself MUST be byte-identical to the canonical
    deterministic ZIP reconstructed from its verified members and manifest.
    Equal logical content with timestamp, permission, ordering, or compression
    drift MUST be rejected.
14. Except for the combined source inventory, configured binding, readiness
    blockers, and recomputed identity, every configured manifest field MUST
    inherit the nested base manifest exactly. Commit, tree, dependency,
    usage-policy, trust-boundary, or other base-field drift MUST fail closed.
15. The builder MUST run the independent configured-release verifier against
    the in-memory archive before either output is materialized.
16. The builder/verifier runtime MUST be distributed through a separate,
    exact, stdlib-only operator-tooling release. The generic read-only tooling
    release MUST retain its byte-level order-primitive prohibition; it MUST NOT
    be weakened merely because this verifier names denied primitives.

## Safety invariants

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

1. Two builds from identical base and overlay bytes produce byte-identical
   archives, manifests, and configured identities.
2. Base archive tamper, duplicate/traversal member, identity drift, extra
   member, source hash drift, profile mismatch, or safety drift fails closed.
3. Overlay missing/extra/symlink/case-colliding file, hash/size drift, unknown
   field, duplicate JSON key, or noncanonical JSON fails closed.
4. Factory/config/manifest path or hash drift, factory-contract drift, zero
   bootstrap hash, or unreviewed provider path fails closed.
5. Secret JSON, private-key/token pattern, `MetaTrader5`, `order_send`,
   `order_check`, dynamic import/eval/exec/compile, subprocess, or ctypes native
   loader use in overlay source fails closed.
6. A valid execution configured archive is accepted by the existing static
   execution factory-manifest verifier after extraction, without importing the
   factory.
7. A valid decision configured archive retains no execution capability and
   remains unusable until the separately reviewed decision runtime loader and
   launcher attestation exist.
8. Static build and verification tests prove zero factory import, credential
   read, MT5 initialization, task installation, and broker mutation.
9. Non-deterministic base ZIP metadata and any recomputed configured manifest
   that drifts from its nested base manifest fail closed.
10. Configured-release operator tooling contains exactly its allowlist,
    contains no broker/network/credential/task provider, and rejects executable
    broker/order calls while allowing static deny-rule names.

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
```

The top-level `release_identity_sha256` is recomputed after this object and the
combined source inventory are installed. Launcher policy and short-lived
attestation must bind this configured identity, not the base identity.

## Out of scope

- Supplying concrete provider behavior or credentials.
- Signing launcher attestations.
- Registering Task Scheduler tasks or ACLs.
- Provisioning Credential Manager, IPC/CAS, journal, WORM, news, clock, or MT5.
- Enabling manual demo, demo-auto, live, promotion, or order submission.
