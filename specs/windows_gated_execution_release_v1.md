# Windows GATED Execution Release v1

Status: concrete production composition bootstrap is present, but all external
authorities remain mandatory and no broker permission is granted.

## Invariants

- Source must be the repository root at a clean, tracked Git commit.
- The archive is built only from
  `config/windows_execution_service_allowlist.v1.json`.
- ZIP timestamps, member ordering, JSON serialization, file hashes, Git commit,
  and Git tree are deterministic and recorded in the manifest.
- Secrets, runtime state, evidence, history, CSV, database, backup, MQL5,
  file-bridge, and paper execution paths are rejected.
- Local Python imports must have an exact allowlisted closure.
- Windows direct requirements, hash-pinned resolved requirements, and the
  CPython 3.12/win_amd64 pylock must form one exact package/version closure.
- `live_runtime/mt5_adapter.py` is the only file allowed to contain MT5
  `order_check` or `order_send`; it must contain exactly one direct call to each.
  Aliases, indirect lookup, duplicate calls, or primitives in any other module
  fail the build. A raw MT5 module cannot cross an arbitrary helper, lambda, or
  identity-call boundary. Production ports require `mt5_module=None`; the exact
  reviewed adapter import/attestation edge is the only production source.
- The installed environment must pass the complete dependency-lock, wheel-tree,
  and RECORD verifier. `MetaTrader5==5.0.5735`, its wheel digest, site tree,
  RECORD, module relative path, and module file digest are bootstrap-config
  bindings.
- Before import, no `MetaTrader5` namespace entry may exist. After import, the
  top-level source package and every loaded native submodule must be exact
  `ModuleType` objects with standard import specs/loaders, regular non-reparse
  RECORD-owned origins, and matching file hashes. Namespace object identities
  and the complete public runtime surface (callables and constants) are sealed
  and re-attested before every adapter boundary. Additions, replacements, or
  monkeypatches fail closed.

## Immutable release state

- `order_capability = GATED_PRESENT`
- `live_allowed = false`
- `safe_to_demo_auto_order = false`
- `max_lot = 0.01`
- `production_execution_ready = false`

Activation requires all three independently verified controls:

1. signed stage authorization;
2. environment arm bound to the exact account/build;
3. valid promotion permit.

The manifest must also report unresolved external dependencies: a sealed
Credential Manager session, externally provisioned journal genesis and
off-host checkpoints, trusted risk-source/state receipts, signed news, stage
authorization, supervisor checkpoint, WORM audit, and signed runtime receipts.
These blockers cannot be converted into a pass by packaging code.

The bootstrap config persists only the reviewed account-alias hash. Raw alias,
login, and password-bearing MT5 initialization kwargs exist only in a
short-lived verifier-sealed credential session. A signed credential receipt
binds that session to server, environment, account identity, and the immutable
bootstrap identity. That bootstrap identity covers every behavior and trust
field in the immutable config; purpose-specific receipt and supervisor keys
must have distinct IDs and configured fingerprints. A journal database must already contain an externally
provisioned incarnation identity and must match a signed provisioning receipt;
the bootstrap will not create first-use journal genesis.

Each WORM receipt binds the currently verified journal snapshot and external
journal predecessor, risk source/state, supervisor checkpoint, signed news
head, stage authorization/replay head, and the current MT5 module namespace
attestation. Multi-cycle execution rechecks this
composite before and after every cycle and again after the final shutdown head;
a stale root latches the journal kill switch and stops the supervisor.
The risk-source hash, issuer, and key must be the exact latest source recorded
by the externally published risk high-water receipt; a concurrent custody-head
change aborts attestation.

One verified adapter is permitted per process. A second adapter observes an
already occupied import namespace and is intentionally rejected.

## Validation entrypoint

`validate_windows_gated_execution_service.py` imports and inspects the reviewed
bootstrap and ports without resolving credentials, initializing MT5, or sending
an order. Its default exit code is
non-zero while production inputs are absent. `--allow-blocked-report` changes
only the port-composition check exit code; it does not change readiness or any
safety lock.

## Acceptance

- Identical clean commits and allowlists produce byte-identical archives.
- Dirty or untracked source fails.
- Missing imports, secrets, forbidden paths, and order primitive drift fail.
- Unhashed, duplicate, target-drifted, or inconsistent dependency locks fail.
- Preloaded/forged native MT5 modules, non-RECORD origins, file tampering,
  namespace additions, callable monkeypatches, and production module injection
  fail.
- Validation reports `broker_mutation_performed = false` and
  `production_execution_ready = false`.
