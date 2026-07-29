# Windows LIVE Canary Execution Materialization v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved for implementation
**Reviewers:** senior architecture, security, ship-gate
**Target:** Windows XM LIVE canary Execution service

## Context

The existing Windows Execution provider contract is intentionally frozen at
version 1. It describes 46 ports for `DEMO` and dormant `DEMO_AUTO`, binds the
`MT5_DEMO_SESSION` credential purpose, and preserves historical release
identities. The generated version-1 provider also supplies no materialization
hooks, so an installed configured release correctly stops at
`EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED`.

The production bootstrap now has a separate, sealed LIVE canary path. That
path requires an exact `LiveCanaryRuntimeCandidate`, an exact
`LiveCanaryRuntimeLaunchSession`, and three per-order callback ports in
addition to the original production ports. The Windows composition boundary
does not yet describe or materialize those requirements. Reusing or silently
changing the version-1 contract would make historical hashes ambiguous and
could confuse DEMO credentials with LIVE credentials.

This feature adds a distinct version-2 Windows LIVE canary materialization
boundary. It validates an exact 49-port, 12-credential, non-secret
configuration and can compose a sealed `WindowsServiceFactoryResult` only
when an independently reviewed Windows runtime supplies the exact sealed LIVE
source and all provider values while the centralized LIVE policy is enabled.
Static validation remains dormant and effect-free. This feature does not
enable the centralized policy, create authority, start a process, initialize
MT5, or send an order.

## Functional Requirements

- FR-1: The implementation MUST define a separate version-2 LIVE provider
  contract and MUST NOT change any version-1 provider contract, constant,
  canonical hash, parser behavior, or generated file.
- FR-2: The LIVE inventory MUST contain exactly the 46 version-1 port
  names in their existing order followed by
  `live_prepared_order_provider`, `live_order_authorization_provider`, and
  `live_execution_cycle_provider`.
- FR-3: The LIVE credential inventory MUST contain exactly 12 distinct
  purposes. It MUST replace `MT5_DEMO_SESSION` with `MT5_LIVE_SESSION` and
  MUST preserve the remaining 11 purpose positions and trust domains.
- FR-4: The LIVE contract MUST require the three LIVE canary callbacks and
  `promotion_evidence_key_provider`. It MUST materialize `stage_binding` as
  `None`, MUST leave every DEMO_AUTO-only port as `None`, and MUST reject a
  provider that attempts to supply either class of cross-mode value.
- FR-5: Static configuration MUST use exact fields, canonical lowercase
  non-zero SHA-256 values, exact provider order, exact contract hashes,
  purpose-bound credential references, a distinct signed-clock trust domain,
  one absolute local Windows clock-attestation path, `runtime_mode=LIVE`,
  `live_allowed=false`, `safe_to_demo_auto_order=false`,
  `production_execution_ready=false`, `promotion_eligible=false`,
  `order_capability=DISABLED`, and `max_lot=0.01`.
- FR-6: Parsing and static validation MUST NOT invoke credentials, clock,
  provider state, SQLite, network, MT5, task, process, permit, session, or
  broker effects.
- FR-7: Runtime materialization MUST reject a non-Windows platform, an
  invalid factory context, a service-config hash mismatch, a disabled or
  inconsistent centralized LIVE policy, or absent hooks before invoking the
  first external hook.
- FR-8: The first runtime hook MUST return an exact sealed
  `WindowsLiveCanaryRuntimeSource` containing one `ProductionRuntimeConfig`,
  one exact sealed `LiveCanaryRuntimeCandidate`, and one exact sealed
  `LiveCanaryRuntimeLaunchSession`.
- FR-9: The runtime source MUST bind the configuration source SHA-256,
  bootstrap safe-binding SHA-256, `environment=LIVE`, `mode=LIVE`, exact
  candidate content SHA-256, exact launch-session content SHA-256, and current
  non-execution launch authority. Mismatch, expiry, replay, replacement, or
  an unsealed object MUST fail before credential access.
- FR-10: Runtime materialization MUST re-evaluate the centralized LIVE
  policy before and after each external effect boundary. A relock MUST stop
  materialization before the next effect and before returning a factory
  result.
- FR-11: Credential access MUST occur only after the runtime source passes
  all static and sealed-source checks. Each credential MUST be retrieved only
  through its exact purpose-bound reference; key IDs, targets, and
  fingerprints MUST remain distinct across incompatible domains.
- FR-12: The signed clock provider MUST be callable, independently bound,
  and materialized before state providers. It MUST NOT reuse any Execution
  credential key ID or fingerprint.
- FR-13: The materializer MUST request only the LIVE-required runtime
  values. It MUST never request `stage_binding`, a DEMO_AUTO-only value, or
  `manual_approval_key_provider`. Every callable/component value MUST match
  its declared kind.
- FR-14: The materializer MUST construct `ProductionRuntimePorts` with
  `mt5_module=None`, construct `ProductionRuntimeBootstrap` with the exact
  LIVE candidate and launch session, and return only a sealed
  `WindowsServiceFactoryResult`.
- FR-15: The materializer MUST NOT import or initialize MetaTrader5,
  create a database or directory, start a task or process, issue or consume an
  order authorization, call `order_send`, or mutate a broker.
- FR-16: The factory result MUST bind the exact heartbeat outbox,
  transport destination, sender/remote credential identities, attested clock,
  service context, LIVE bootstrap, candidate, and launch session.
- FR-17: All failures MUST expose a stable uppercase non-secret reason
  code and MUST NOT include credential material, account login, token, permit,
  password, private key, or broker payload.
- FR-18: Version-2 source APIs MUST be additive local Python APIs. Existing
  version-1 import names and behavior MUST remain backward compatible.

## Non-Functional Requirements

- NFR-1: Static parsing and validation MUST complete in less than 250 ms
  for the maximum accepted 49-provider document on the project test host.
- NFR-2: Static configuration documents MUST be bounded to 4 MiB and
  provider/credential collections MUST be bounded before per-item processing.
- NFR-3: Validation MUST reject duplicate JSON keys at the file boundary,
  unknown fields, non-finite numbers, uppercase or zero hashes, case-folding
  identity collisions, UNC/device/ADS/traversal/reserved Windows paths, and
  ambiguous booleans or numbers.
- NFR-4: Security behavior MUST be identical under normal Python and
  `PYTHONOPTIMIZE=2`; no security decision may rely on `assert`.
- NFR-5: Tests MUST prove zero side effects with sentinels and MUST cover a
  central-policy relock at every ordered external hook boundary.
- NFR-6: The implementation MUST pass focused tests, the complete normal
  and optimized Python suites, compile checks, Ruff, dependency-lock
  verification, diff checks, and the project ship gate.
- NFR-7: The new module MUST use only standard-library and already
  allowlisted first-party runtime dependencies; no new package is permitted.
- NFR-8: Canonical identities MUST be deterministic for semantically
  identical validated input.

## Acceptance Criteria

### AC-1: Version-1 compatibility (FR-1, FR-18)

Given the committed version-1 Execution factory and provider fixtures
When the version-2 module is imported and all version-1 tests run
Then the version-1 46-port inventory, contract-set hash, parser behavior, and
generated pack bytes remain unchanged.

### AC-2: Exact LIVE inventory (FR-2, FR-3, FR-4)

Given the version-2 LIVE contract
When its inventory is inspected
Then it contains exactly 49 ordered ports, exactly 12 ordered credential
purposes beginning with `MT5_LIVE_SESSION`, and the three LIVE callbacks are
required.

### AC-3: Pure dormant configuration (FR-5, FR-6, NFR-1, NFR-2)

Given a canonical 49-port LIVE configuration and effect sentinels
When it is parsed and statically validated
Then it returns a deny-only validation receipt within 250 ms and every effect
sentinel remains untouched.

### AC-4: Exact schema and custody rejection (FR-2, FR-3, FR-5, FR-17)

Given an unknown, missing, duplicate, reordered, case-colliding,
contract-drifted, implementation-drifted, configuration-drifted, or
credential-purpose-drifted entry
When the LIVE configuration is parsed
Then parsing fails with a stable reason code before any effect.

### AC-5: Platform, context, and policy precedence (FR-7, FR-10)

Given valid static input and effect sentinels
When materialization is attempted off Windows, with a context/hash mismatch,
with the central LIVE lock disabled, or without hooks
Then it fails before the first runtime-source, credential, clock, or provider
hook.

### AC-6: Exact sealed source precedence (FR-8, FR-9, FR-10)

Given a Windows materialization request with a wrong source type, wrong source
hash, mismatched config/candidate/session, expired session, or unsealed object
When the runtime-source hook returns
Then materialization fails before credential access.

### AC-7: Ordered LIVE composition (FR-10, FR-11, FR-12, FR-13)

Given an exact current source and all valid LIVE providers
When materialization runs while the policy remains enabled
Then effects occur only in the order source, clock, credential backend, and
ordered required provider state; forbidden cross-mode providers are never
requested.

### AC-8: Sealed factory result (FR-14, FR-15, FR-16)

Given AC-7 inputs
When composition completes
Then the result is an exact sealed `WindowsServiceFactoryResult`, its bootstrap
holds the exact candidate/session and 49-port object with `mt5_module=None`,
and no MT5 import, broker submission, task installation, or process start
occurs.

### AC-9: Relock race closure (FR-10, FR-15, NFR-5)

Given a central policy that becomes disabled after any external effect
When materialization attempts its next boundary
Then it stops with `CENTRAL_LIVE_LOCK_NOT_ENABLED`, invokes no later hook, and
returns no factory result.

### AC-10: Runtime contract rejection (FR-4, FR-9, FR-13, FR-14)

Given a cross-mode value, a non-callable callable port, a null required
component, a stale source, or a bootstrap contract mismatch
When composition is attempted
Then it fails closed and does not seal a factory result.

### AC-11: Normal and optimized regression closure (NFR-4, NFR-6, NFR-7)

Given the completed implementation
When focused, complete normal, complete optimized, static, dependency, and
ship-gate checks run
Then automated checks pass without version-1 drift or a safety-lock change.

### AC-12: Honest release state (FR-5, FR-15)

Given all local acceptance criteria pass
When project progress and ship-gate documents are updated
Then they mark only this Windows materialization boundary complete and retain
external XM evidence, provider implementation, central unlock, Windows
acceptance, and first real canary as blockers.

## Edge Cases

- EC-1: A provider list of 48 or 50 entries, a reordered entry, or a
  case-folding duplicate MUST fail before credential parsing completes.
- EC-2: `MT5_DEMO_SESSION`, an unknown purpose, a reused key ID/target/
  fingerprint, or a clock-domain collision MUST fail before materialization.
- EC-3: `runtime_mode` other than exact `LIVE`, any true static readiness
  flag, a lot other than exact float `0.01`, or a capability other than
  `DISABLED` MUST fail static parsing.
- EC-4: A relative, UNC, device, ADS, traversal, reserved-name, or
  slash-mixed clock path MUST fail static parsing.
- EC-5: A non-Windows platform MUST precede service hashing and every
  external hook.
- EC-6: A central policy whose booleans or decision reasons are
  inconsistent MUST fail as locked.
- EC-7: A runtime-source hook exception MUST become a stable source
  unavailable reason without leaking its message.
- EC-8: An exact source object whose candidate or session has been
  replaced, expired, replayed, or rebound MUST fail before credentials.
- EC-9: A credential, clock, or provider hook exception MUST be wrapped in
  its domain-specific stable reason code without invoking later effects.
- EC-10: `stage_binding`, a DEMO_AUTO port, or
  `manual_approval_key_provider` supplied by the provider reader MUST fail;
  those names MUST never be requested in valid LIVE composition.
- EC-11: A relock after the last provider read but before bootstrap/result
  sealing MUST return no result.
- EC-12: An invalid heartbeat outbox, route, key provider, or credential
  binding MUST fail before result sealing.
- EC-13: A direct attempt to instantiate a sealed runtime source without
  the module seal MUST fail.
- EC-14: Re-running version-1 pack tests MUST produce no new file, hash,
  schema, or behavior difference.

## API Contracts

N/A — no HTTP endpoint, broker endpoint, command-line activation command, or
storage schema is introduced. There is intentionally no `POST /api/...`
surface for this local composition boundary.

```typescript
interface WindowsLiveCanaryExecutionProviderConfiguration {
  readonly schema_version: "windows-live-canary-execution-provider-configuration-v1";
  readonly pack_id: string;
  readonly runtime_mode: "LIVE";
  readonly base_suite_identity_sha256: Sha256;
  readonly execution_base_release_identity_sha256: Sha256;
  readonly production_config_sha256: Sha256;
  readonly service_config_file_sha256: Sha256;
  readonly credential_target_prefix: "AI_SCALPER/WINDOWS_SERVICE/LIVE_EXECUTION";
  readonly credential_references: readonly CredentialReference[12];
  readonly provider_bindings: readonly ProviderBinding[49];
  readonly clock_binding: WindowsClockBinding;
  readonly clock_attestation_path: AbsoluteLocalWindowsFile;
  readonly live_allowed: false;
  readonly safe_to_demo_auto_order: false;
  readonly max_lot: 0.01;
  readonly promotion_eligible: false;
  readonly production_execution_ready: false;
  readonly order_capability: "DISABLED";
}

interface WindowsLiveCanaryRuntimeSource {
  readonly config: ProductionRuntimeConfig;
  readonly live_candidate: LiveCanaryRuntimeCandidate;
  readonly live_launch_session: LiveCanaryRuntimeLaunchSession;
  readonly source_sha256: Sha256;
}

interface WindowsLiveCanaryProviderMaterializationHooks {
  readonly runtime_source_reader: Callable;
  readonly credential_backend_factory: Callable;
  readonly clock_attestation_reader: Callable;
  readonly provider_state_reader: Callable;
  readonly sqlite_opener: Callable;
  readonly mt5_importer: Callable;
  readonly network_sender: Callable;
}
```

```text
windows_live_canary_execution_provider_configuration_from_dict(
    payload: Mapping[str, object]
) -> WindowsLiveCanaryExecutionProviderConfiguration

windows_live_canary_execution_provider_configuration_from_json(
    payload: bytes
) -> WindowsLiveCanaryExecutionProviderConfiguration

validate_windows_live_canary_execution_provider_configuration(
    config: WindowsLiveCanaryExecutionProviderConfiguration,
    *,
    effect_probe: Callable[[str], object] | None = None,
) -> WindowsLiveCanaryExecutionProviderValidation

seal_windows_live_canary_runtime_source(
    *,
    config: ProductionRuntimeConfig,
    live_candidate: object,
    live_launch_session: object,
    source_sha256: str,
    now: datetime | None = None,
) -> WindowsLiveCanaryRuntimeSource

build_windows_live_canary_execution_factory_result(
    *,
    runtime_config: Mapping[str, object],
    factory_context: WindowsServiceFactoryContext,
    provider_config: WindowsLiveCanaryExecutionProviderConfiguration,
    hooks: WindowsLiveCanaryProviderMaterializationHooks | None = None,
    platform: str | None = None,
) -> WindowsServiceFactoryResult
```

Errors are local exceptions carrying one uppercase `reason_code`. Successful
static reports always state no readiness and no broker mutation.

## Data Models

| Model | Field | Type | Constraints |
|---|---|---|---|
| `LiveExternalProviderContract` | `port_name` | canonical identifier | Exact 49-item ordered set |
| `LiveExternalProviderContract` | `provider_kind` | enum | `CALLABLE` or `COMPONENT` |
| `LiveExternalProviderContract` | `call_contract` | string | Reviewed declaration, never evaluated |
| `LiveExternalProviderContract` | `required` | bool | LIVE runtime materialization requirement |
| `LiveExternalProviderContract` | `credential_purpose` | string or null | Exact distinct purpose binding |
| `ExecutionCredentialReference` | identity fields | strings | Exact target prefix, unique key/target/fingerprint |
| `ExecutionProviderBinding` | binding fields | strings/hashes | Exact order, kind, contract and custody |
| `WindowsLiveCanaryExecutionProviderConfiguration` | bindings and safety fields | immutable contract | 49 ports, 12 credentials, deny-only static flags |
| `WindowsLiveCanaryRuntimeSource` | `config` | exact object | LIVE configuration bound to candidate/session |
| `WindowsLiveCanaryRuntimeSource` | `live_candidate` | sealed exact object | Content and runtime bindings match config |
| `WindowsLiveCanaryRuntimeSource` | `live_launch_session` | sealed exact object | Current, launch-only, non-execution authority |
| `WindowsLiveCanaryExecutionProviderValidation` | counts/effects/safety | immutable receipt | Deny-only and zero effects |

## Out of Scope

- OS-1: Enabling `execution_policy.LIVE_ALLOWED` or changing any checked-in
  safety constant; those remain separate externally governed actions.
- OS-2: Generating, importing, or rotating Windows credentials, HMAC keys,
  private keys, permits, promotion evidence, clock attestations, or launch
  sessions.
- OS-3: Implementing the concrete Windows Credential Manager, WORM/CAS,
  risk, reconciliation, Decision IPC, news, heartbeat transport, or broker
  adapters. This feature defines and enforces their composition boundary.
- OS-4: Building the deterministic provider ZIP, configured candidate,
  installer, Task Scheduler definition, or Windows conformance evidence; those
  are subsequent release milestones built on this boundary.
- OS-5: Starting the Execution service, importing/initializing MT5, reading
  an XM account, consuming per-order authority, or placing a real or demo
  broker order.
- OS-6: Claiming the project is production-ready, statistically promoted,
  legally approved, safe for unrestricted trading, or 100% complete.
