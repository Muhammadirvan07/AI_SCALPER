# Spec: Windows Execution Factory Materialization Probe v1

**Author:** Codex with AI_SCALPER project owner  
**Date:** 2026-07-25  
**Status:** Approved for implementation  
**Reviewers:** senior architecture, security, ship-gate  
**Target:** Windows GATED Execution launcher

## Context

The Execution configured-candidate boundary can statically verify the exact
release, factory source, service configuration, provider pack, task
definition, and suite provenance without importing the reviewed factory. The
operational launcher then moves directly from that static boundary to a full
`WindowsGatedServiceRunner`, whose first lifecycle step calls
`ProductionRuntimeBootstrap.materialize()` and may import and initialize MT5.

An intermediate evidence boundary is required. The operator must be able to
prove on the target Windows host that the exact externally attested release
can import and invoke its reviewed factory, reconstruct its sealed provider
composition, and retain `mt5_module=None`, without materializing the
production bootstrap, initializing MT5, installing signal handlers, starting
a service loop, consuming stage authority, or touching a broker.

The existing `--validate-only` mode remains a pure static check. The new
`--materialize-only` mode intentionally crosses the reviewed provider
boundary and therefore requires the same short-lived external RSA launcher
attestation as an operational launch. It is evidence only and grants no
execution authority.

## Functional Requirements

- FR-1: `--validate-only` and `--materialize-only` MUST be mutually exclusive.
- FR-2: `--validate-only` MUST remain trust-, import-, provider-, credential-,
  MT5-, process-, network-, and broker-free.
- FR-3: `--materialize-only` MUST require the external release trust policy,
  independently pinned policy SHA-256, and short-lived launcher attestation
  before the reviewed factory is imported.
- FR-4: Execution trust verification and its post-factory freshness recheck
  MUST explicitly require release profile
  `WINDOWS_GATED_EXECUTION_SERVICE_V1`.
- FR-5: After trust verification, `--materialize-only` MUST use only
  `load_reviewed_windows_service_factory()` to verify, import, and invoke the
  exact configured factory.
- FR-6: The returned composition MUST retain `mt5_module=None`; any injected
  MT5 module fails closed.
- FR-7: `--materialize-only` MUST NOT construct
  `WindowsGatedServiceRunner`, install signal handlers, call
  `ProductionRuntimeBootstrap.materialize()`, import or initialize MT5, start
  a lifecycle loop, issue a heartbeat, consume an authorization, submit an
  order, or mutate broker state.
- FR-8: A successful materialization probe MUST emit canonical JSON with
  status `FACTORY_MATERIALIZED_BROKER_NOT_INITIALIZED`, exact release/factory/
  bootstrap hashes, the provider-effect boundary, and explicit false safety
  claims for bootstrap materialization, MT5 initialization, broker mutation,
  execution readiness, demo-auto, and live trading.
- FR-9: Factory/provider construction MAY read independently provisioned
  credential, key, clock, journal, checkpoint, or other provider state. The
  report MUST describe that boundary as provider-defined and MUST NOT falsely
  claim that those reads did or did not occur.
- FR-10: The normal bounded operational path MUST retain its existing
  behavior, except that its launcher attestation is now explicitly pinned to
  the Execution release profile.
- FR-11: Missing, wrong-profile, expired, changed, or invalid external trust
  MUST fail before factory import. Factory or provider failure MUST fail
  closed before bootstrap materialization.
- FR-12: All outcomes MUST preserve `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `max_lot=0.01`,
  `production_execution_ready=false`, and no granted execution authority.

## Non-Functional Requirements

- NFR-1: Rejections MUST use stable non-secret reason codes.
- NFR-2: Successful output MUST be UTF-8 JSON with sorted keys and must not
  contain credentials, account logins, raw keys, signatures, permits, tokens,
  or provider payloads.
- NFR-3: Security behavior MUST be identical under normal Python and
  `PYTHONOPTIMIZE=2`; no security check may rely on `assert`.
- NFR-4: Existing release allowlists and package boundaries MUST remain
  unchanged because the probe is implemented inside the already reviewed
  Execution launcher.
- NFR-5: Focused, optimized, complete regression, compilation, dependency,
  SBOM, and security checks MUST remain green.

## Acceptance Criteria

### AC-1: Static mode remains effect-free (FR-1, FR-2)

Given an exact configured Execution release  
When `--validate-only` runs  
Then the manifest and configuration are verified without trust-document
access, factory import, provider construction, bootstrap materialization, or
broker mutation.

### AC-2: Trust precedes factory materialization (FR-3, FR-4, FR-5, FR-11)

Given missing or invalid external launcher trust  
When `--materialize-only` runs  
Then it rejects before factory import.

Given valid external trust  
When the factory is loaded  
Then both verification and freshness recheck require the exact Execution
release profile.

### AC-3: Factory materializes while broker remains untouched (FR-5 through FR-9)

Given a valid exact configured factory and external launcher attestation  
When `--materialize-only` runs  
Then it returns
`FACTORY_MATERIALIZED_BROKER_NOT_INITIALIZED`, reports
`provider_materialized=true`, retains `mt5_module=None`, and never constructs
or runs the service runner or production bootstrap.

### AC-4: MT5 injection fails closed (FR-6, FR-7, FR-11)

Given a factory result whose bootstrap ports contain an MT5 module  
When `--materialize-only` evaluates the result  
Then it rejects before runner construction and broker access.

### AC-5: Operational path remains bounded and profile-pinned (FR-4, FR-10)

Given a valid operational launch  
When the bounded service runs  
Then existing lifecycle behavior is unchanged and the external trust
freshness check requires the Execution release profile.

### AC-6: Safety locks and regression remain intact (FR-12, NFR-3, NFR-5)

Given the completed implementation  
When focused, optimized, full regression, compile, dependency, SBOM, and
security checks run  
Then every check passes and all execution/live locks remain false.

## Edge Cases

- EC-1: Both mode flags are supplied: argument parsing rejects the request.
- EC-2: Trust documents are inside the mutable release: reject before import.
- EC-3: A Decision or Status Monitor launcher policy is supplied: reject the
  release-profile mismatch.
- EC-4: Trust expires during factory construction: the post-factory recheck
  rejects before any bootstrap materialization.
- EC-5: Factory returns an unsealed or incorrectly bound result: the existing
  exact loader rejects it.
- EC-6: Factory provider construction fails: report only a stable launcher
  rejection and never attempt the runner.
- EC-7: `mt5_module` is non-`None`: reject
  `SERVICE_FACTORY_MT5_INJECTION_FORBIDDEN`.
- EC-8: Provider construction reads preprovisioned state: the output records
  only the declared provider-effect boundary, never raw observations.

## Out of Scope

- Provisioning credentials, provider state, RSA private keys, or trust policy.
- Creating launcher attestations.
- Importing or initializing MetaTrader5.
- Starting Decision, Execution, or Status Monitor services.
- Manual-demo activation, DEMO_AUTO activation, soak admission, live permit,
  or any broker order.
