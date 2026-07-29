# Windows LIVE Canary External Runtime Hook Lease v1

**Author:** Codex with the AI_SCALPER project owner
**Date:** 2026-07-30
**Status:** Approved for implementation under the project owner's standing
authorization
**Reviewers:** senior architecture, security, and ship-gate boundaries
**Related specs:**
`specs/windows_live_canary_execution_materialization_v1.md`,
`specs/windows_live_canary_execution_provider_pack_v1.md`, and
`specs/windows_gated_execution_release_v1.md`

## Context

The deterministic Windows LIVE Execution provider pack correctly embeds the
49-port LIVE configuration and calls the reviewed LIVE materializer. The
generated factory deliberately supplies no materialization hooks, however, so
every exact configured candidate necessarily stops at
`LIVE_EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED`. Source-bound packaging,
provider conformance, acceptance, custody, launch-session, and per-order
authorization code therefore cannot reach the already implemented production
bootstrap through the reviewed Windows launcher.

The Windows launcher already requires an independently pinned Execution
release identity and a short-lived RSA launcher attestation before importing a
reviewed factory. This feature adds a second, independent exact-hash boundary
for one externally reviewed Windows runtime-provider module. The launcher may
load that module only after static release validation and launcher trust pass,
then install its exact `WindowsLiveCanaryProviderMaterializationHooks` in one
context-local, single-consumption lease while the reviewed factory is invoked.
The generated four-file provider pack remains byte-compatible and its default
behavior remains fail-closed.

This is a composition boundary, not execution authority. The checked-in
central LIVE lock remains false. The feature does not provide broker
credentials, provider state, acceptance evidence, a launch session, per-order
authorization, Task Scheduler installation, or permission to submit an order.

## Functional Requirements

- FR-1: The implementation MUST preserve all generated LIVE provider-pack v1
  bytes and MUST preserve `LIVE_EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED`
  when no active lease exists.
- FR-2: The launcher MUST expose the optional pair
  `--live-runtime-provider` and
  `--expected-live-runtime-provider-sha256`; supplying only one MUST fail
  before any provider import.
- FR-3: `--validate-only` MUST remain provider-import-free and MUST reject the
  runtime-provider option pair as incompatible.
- FR-4: Before reading the external runtime provider, the launcher MUST verify
  the exact Execution release, factory manifest, independently pinned release
  identity, short-lived RSA launcher attestation, and current central LIVE
  policy.
- FR-5: The runtime-provider path MUST be an absolute local regular file
  outside the reviewed release root. It MUST reject a relative path, UNC/device
  path, alternate data stream, symlink, junction, reparse point, directory,
  missing file, and file larger than 4 MiB.
- FR-6: The launcher MUST perform a stable file read and MUST compare its
  lowercase SHA-256 with the independently supplied non-zero expected hash
  before parsing or importing the module.
- FR-7: The runtime-provider source MUST parse as Python and MUST reject
  duplicate builder definitions, wildcard imports, dynamic import/evaluation,
  `MetaTrader5`, `order_check`, `order_send`, process launch, Task Scheduler
  mutation, and top-level executable statements other than imports, constant
  assignments, class definitions, and function definitions.
- FR-8: The external module MUST export exactly one module-owned function named
  `build_live_canary_materialization_hooks` with one positional context
  parameter. Its return value MUST be an exact
  `WindowsLiveCanaryProviderMaterializationHooks`.
- FR-9: The builder context MUST be a sealed, non-secret object binding the
  external module SHA-256, release identity, release-root identity, factory
  contract/file hash, service-config hash, bootstrap-binding hash, and current
  trusted UTC observation.
- FR-10: The launcher MUST remove the temporary external module name from
  `sys.modules`, recheck module bytes and the central LIVE policy after builder
  invocation, and reject module-registry replacement or residual module
  installation.
- FR-11: A lease MUST be context-local, non-reentrant, bound to the exact
  factory context, consumable exactly once, and always cleared when the
  launcher leaves its lexical scope, including failure paths.
- FR-12: The LIVE materializer MUST use an explicitly supplied hooks object
  first. Only when its `hooks` parameter is `None` MAY it consume one matching
  active lease; absent, mismatched, replayed, or expired lease state MUST fail
  closed.
- FR-13: Central LIVE policy MUST be checked before lease creation, before and
  after external module import/build, at lease consumption, and through every
  existing materialization effect boundary. A relock MUST prevent the next
  effect.
- FR-14: `--materialize-only` MAY load the exact runtime provider and invoke
  provider-state hooks, but MUST still stop before
  `ProductionRuntimeBootstrap.materialize()`, MT5 import/initialization,
  runner construction, signal handlers, authorization consumption, or broker
  mutation.
- FR-15: A full bounded run MAY proceed only if the reviewed factory returns
  an exact sealed result. Existing production bootstrap, launch-session,
  per-order authorization, reconciliation, news, risk, journal, and MT5 guards
  MUST remain unchanged.
- FR-16: Success output for a runtime-enabled materialization probe or bounded
  run MUST include the exact external runtime-provider SHA-256. Static-only or
  legacy output MUST remain backward-compatible.
- FR-17: All new failures MUST expose stable uppercase non-secret reason codes
  and MUST NOT include source text, credential values, account login, password,
  permit, token, private key, broker payload, or provider exception text.
- FR-18: The Execution release allowlist and builder MUST bind the exact new
  consumer/loader bytes while continuing to reject unreviewed dynamic loaders
  everywhere else.

## Non-Functional Requirements

- NFR-1: Static source validation and exact-hash verification for a 4 MiB
  runtime-provider file MUST complete in less than 1 second on the project test
  host, excluding external RSA verification.
- NFR-2: Security decisions MUST be identical under normal Python and
  `PYTHONOPTIMIZE=2`; no decision may rely on `assert`.
- NFR-3: The implementation MUST use only Python 3.12 standard library and
  already allowlisted first-party modules; no dependency may be added.
- NFR-4: Parallel threads and nested contexts MUST NOT observe or consume
  another invocation's lease.
- NFR-5: Default unit, release-builder, generated-pack, configured-candidate,
  source-bound, provider-conformance, launcher, and full normal/optimized test
  behavior MUST remain backward-compatible.
- NFR-6: Focused tests MUST prove no MT5 import, process/task mutation,
  authorization consumption, network send, or broker mutation occurs during
  source validation, module loading, hook building, or materialize-only mode.

## Acceptance Criteria

### AC-1: Default generated pack remains closed (FR-1, FR-12, NFR-5)

Given the exact existing four-file LIVE provider pack and no active lease
When its generated factory is invoked under an enabled test policy
Then it fails with `LIVE_EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED`
And every generated provider-pack member remains byte-identical.

### AC-2: CLI pairing and validate-only purity (FR-2, FR-3, FR-17)

Given missing, partial, or validate-only runtime-provider options
When argument validation runs
Then it rejects with one stable reason code before reading or importing the
external module.

### AC-3: Trust and policy precedence (FR-4, FR-13, NFR-6)

Given invalid release trust, expired attestation, or a disabled central lock
When a runtime-enabled probe is requested
Then it rejects before the first external runtime-provider read or import.

### AC-4: Exact external source custody (FR-5, FR-6, FR-10)

Given a wrong hash, changing file, oversized file, path indirection, or path
inside the release root
When the loader verifies the external module
Then it rejects before AST parsing or module execution
And no module remains in `sys.modules`.

### AC-5: Static source restrictions (FR-7, FR-17, NFR-1)

Given source containing a forbidden top-level effect, dynamic loader,
`MetaTrader5`, broker order primitive, process launch, or task mutation
When static validation runs
Then it rejects within one second with a stable non-secret reason code
And executes no source byte.

### AC-6: Exact builder contract (FR-8, FR-9, FR-10)

Given valid exact source and a current trusted launcher context
When the external builder runs
Then it receives one sealed non-secret context
And returns an exact hooks object
And the temporary module is removed and exact source bytes are reverified.

### AC-7: Single-use context-local lease (FR-11, FR-12, NFR-4)

Given one exact hooks object and exact factory context
When the matching materializer consumes the lease
Then the first consumption returns that exact object
And replay, nested binding, mismatched context, and another thread all reject
without exposing the hooks.

### AC-8: Relock closes every new boundary (FR-13, NFR-6)

Given central policy changes from enabled to disabled after source read,
module import, builder call, lease creation, or lease consumption
When the next boundary is attempted
Then it fails with `CENTRAL_LIVE_LOCK_NOT_ENABLED`
And invokes no later provider or broker effect.

### AC-9: Materialize-only remains brokerless (FR-14, FR-16, NFR-6)

Given a valid trusted release, exact runtime-provider module, and factory
When `--materialize-only` completes
Then output includes the exact runtime-provider SHA-256
And bootstrap materialization, MT5, runner, authorization, and broker mutation
remain false.

### AC-10: Full runner behavior is unchanged (FR-15, FR-16, NFR-5)

Given a valid sealed factory result from a runtime-enabled LIVE provider
When the bounded runner starts
Then it follows the existing bootstrap, session, reconciliation, decision,
per-order authorization, MT5, heartbeat, and shutdown path
And output additionally binds the runtime-provider SHA-256.

### AC-11: Release and optimized closure (FR-18, NFR-2, NFR-3, NFR-5)

Given the completed implementation
When focused, release-builder, normal, optimized, compile, lint, dependency,
and ship-gate checks run
Then all checks pass without dependency drift, generated-pack drift, or a
central safety-lock change.

## Edge Cases

- EC-1: Empty or zero expected SHA-256 MUST reject before file access.
- EC-2: A case-only path alias, UNC path, device path, ADS path, or reparse
  transition during read MUST reject.
- EC-3: Non-UTF-8, syntax-invalid, or greater-than-4-MiB source MUST reject.
- EC-4: A module with no builder, two builders, imported builder, async
  builder, variadic signature, default argument, or wrong return type MUST
  reject.
- EC-5: A builder exception MUST be wrapped without preserving its message.
- EC-6: A builder that mutates `sys.modules`, the runtime source file, import
  guards, or central policy MUST reject before lease creation.
- EC-7: A lease bound to a different factory/service/bootstrap hash MUST not be
  consumed.
- EC-8: A second materializer call in the same scope MUST reject replay.
- EC-9: Concurrent leases in separate context/thread scopes MUST remain
  isolated.
- EC-10: Exception during reviewed factory import or invocation MUST clear the
  lease.
- EC-11: Runtime options without release trust documents MUST retain the
  existing release-trust rejection precedence.
- EC-12: Existing DEMO/DEMO_AUTO factory invocations MUST not observe or
  consume a LIVE lease.

## API Contracts

HTTP API: N/A — this is a local Windows launcher and Python composition
boundary; no network endpoint is introduced.

```typescript
interface WindowsLiveCanaryExternalRuntimeContextV1 {
  schema_version: "windows-live-canary-external-runtime-context-v1";
  runtime_provider_sha256: string;
  release_identity_sha256: string;
  release_root_sha256: string;
  factory_contract_sha256: string;
  factory_file_sha256: string;
  service_config_file_sha256: string;
  bootstrap_binding_sha256: string;
  observed_at_utc: string;
  live_allowed: false;
  safe_to_demo_auto_order: false;
  order_capability: "DISABLED";
}
```

```python
def build_live_canary_materialization_hooks(
    context: WindowsLiveCanaryExternalRuntimeContext,
) -> WindowsLiveCanaryProviderMaterializationHooks:
    """External reviewed module contract; no authority is created here."""

@contextmanager
def lease_windows_live_canary_materialization_hooks(
    hooks: WindowsLiveCanaryProviderMaterializationHooks,
    *,
    factory_context: WindowsServiceFactoryContext,
    runtime_provider_sha256: str,
):
    """Install one exact context-local, one-use hook lease."""
```

CLI extension:

```text
run_windows_gated_execution_service.py
  [existing required release-trust arguments]
  [--live-runtime-provider <absolute-external-python-file>
   --expected-live-runtime-provider-sha256 <sha256>]
  [--materialize-only]
```

## Data Models

### External runtime context

| Field | Type | Constraints |
|---|---|---|
| runtime provider SHA-256 | string | lowercase, non-zero, exact stable bytes |
| release identity | string | independently pinned Execution release |
| release/factory/service/bootstrap pins | string | exact validated context hashes |
| observed time | UTC datetime | current launcher clock observation |
| safety fields | constants | false/disabled; cannot grant authority |

### Hook lease

| Field | Type | Constraints |
|---|---|---|
| hooks | exact hooks object | never serialized or logged |
| factory binding | 5 SHA-256 tuple | exact context match required |
| runtime provider SHA-256 | string | external module identity |
| consumed | boolean | false to true exactly once |
| context token | private | context-local and always reset |

### External runtime provider file

| Field | Type | Constraints |
|---|---|---|
| path | Windows absolute file | external to release; regular; non-reparse |
| bytes | Python UTF-8 source | 1..4 MiB; stable read |
| SHA-256 | string | independently pinned; rechecked after build |
| builder | module-owned function | exact name/signature; exact hooks result |

## Out of Scope

- OS-1: Implementing the selected broker's 40 concrete runtime providers;
  this feature only creates their exact reviewed loading/lease boundary.
- OS-2: Enabling `execution_policy.LIVE_ALLOWED`; this remains a separate
  central unlock ceremony after all external evidence is accepted.
- OS-3: Creating provider conformance, acceptance, WORM/CAS custody,
  promotion, gate, human approval, launch-session, or per-order authority.
- OS-4: Installing or modifying a Windows scheduled task, ACL, service
  account, Credential Manager secret, MT5 terminal, or dependency environment.
- OS-5: Importing/initializing MT5, calling `order_check`/`order_send`, or
  submitting any real broker order during source validation, hook loading, or
  materialize-only mode.
- OS-6: Treating a valid external runtime-provider hash as provider acceptance,
  production readiness, execution authority, or proof of live trading.
