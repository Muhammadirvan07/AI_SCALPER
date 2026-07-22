# Windows Decision Service Release v1

## Status

- Profile: `WINDOWS_DECISION_SERVICE_V1`
- Bundle class: `DECISION_ONLY_SERVICE`
- Order capability: `DISABLED`
- Production execution ready: `false`

## Purpose

Package the brokerless finalized-M15 decision process as a deterministic
Windows release that is cryptographically distinct from the GATED executor
release. The bundle may calculate a shared-core `DecisionSnapshot` and publish
that snapshot through the signed decision IPC producer. It cannot calculate a
risk approval, create a trade intent, connect to MT5, or submit an order.

## Required release contents

The exact allowlist contains only:

- `brokerless_decision_producer`, `decision_core`, `decision_ipc`, and immutable
  contracts;
- the exact market-status, regime, data-quality, strategy-selector, profile,
  and trend dependencies used by the shared decision core;
- a non-materializing Windows factory/config contract;
- a static validator and validate-only release runner;
- CPython 3.12 / `win_amd64` dependency locks for NumPy, pandas, TA, and their
  exact transitive closure.

The bundle must not contain execution policy, risk, permit, executor,
reconciliation, broker adapter/SDK, credential-store dependency, runtime
artifact, evidence state, market data cache, or secret material.

## Build contract

1. Source must be a clean Git repository root.
2. Every allowlisted byte must equal the selected commit.
3. The allowlist set is exact; additions and removals are rejected.
4. Every local Python import must be declared in the bundle.
5. Broker/execution/network imports, dynamic code loading, and broker mutation
   members are rejected by AST/content policy.
6. Direct and resolved dependencies must exactly match the dedicated hash lock
   and pylock target metadata.
7. Archive member order, timestamp, permissions, JSON serialization, and
   release identity are deterministic.

## External runtime contract

Runtime construction is outside the release. A reviewed external factory must
supply exact-hash implementations/configuration for:

- finalized M15 data;
- trusted UTC;
- decision IPC signing-key custody;
- decision IPC checkpoint CAS;
- producer cursor CAS;
- producer cursor acknowledgement verification.
- exact signed session-calendar closure verification.

The bundled factory template validates only role, contract, implementation,
configuration, custody-mode, and release-identity hashes. It has no provider
import/materialization or secret field.

## Acceptance criteria

- Two builds from the same clean commit produce byte-identical archives and
  release identities.
- Dirty source, untracked artifacts, symlinks, undeclared imports, dependency
  drift, secrets, broker modules, and order primitives fail closed.
- The validator reports all ports present while preserving
  `live_allowed=false`, `safe_to_demo_auto_order=false`, `max_lot=0.01`, and
  `production_execution_ready=false`.
- Validate-only verifies every extracted source hash and the exact external
  factory template without fetching data, opening IPC/cursor state, or
  materializing a provider.
- Non-validate runner invocation is rejected until an independently reviewed
  runtime factory and Windows service identity exist.

## External blockers

- `EXTERNAL_FINALIZED_M15_DATA_PROVIDER_REQUIRED`
- `EXTERNAL_SIGNED_SESSION_CALENDAR_VERIFIER_REQUIRED`
- `EXTERNAL_TRUSTED_CLOCK_PROVIDER_REQUIRED`
- `EXTERNAL_DECISION_IPC_KEY_CUSTODY_REQUIRED`
- `EXTERNAL_DECISION_IPC_CHECKPOINT_CAS_REQUIRED`
- `EXTERNAL_DECISION_CURSOR_CAS_REQUIRED`
- `EXTERNAL_DECISION_CURSOR_ACK_VERIFIER_REQUIRED`
- `EXTERNAL_DECISION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED`
- `EXTERNAL_WINDOWS_DECISION_SERVICE_IDENTITY_ATTESTATION_REQUIRED`
