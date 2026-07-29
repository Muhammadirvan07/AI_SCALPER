# Windows Execution Provider-Bound Runtime Closure v1

**Author:** OpenAI Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved for implementation
**Reviewers:** senior architecture, security, and ship-gate

## Context

The Windows Execution runtime consumes an exact provider-bound LIVE launch
session v2. Its lightweight authority registry previously knew only a class
registered by an operator-side assembly module that was intentionally absent
from service releases. Consequently, an extracted Execution ZIP could import
the runtime but could not own the exact v2 session type needed to validate a
session supplied by the reviewed runtime-source hook.

Packaging the entire assembly graph would violate the established privilege
boundary: configured-candidate assemblers, source-bound verifiers, provider
conformance review, acceptance preparation, and WORM/CAS producers are
operator-only tooling. This feature extracts only the immutable session
contract into a minimal consumer module. The operator-side activation module
reuses and re-exports the same class, while the Execution runtime imports the
consumer module directly and remains unable to assemble authority.

## Goals

- Make the extracted Windows Execution ZIP self-contained for consuming and
  validating the exact provider-bound launch-session v2 class.
- Preserve one exact class identity and private session seal across the
  operator producer and Execution consumer.
- Bind the critical consumer closure and exact bytes in the deterministic
  release manifest.
- Prove isolated import under `python -I -S -B` without provider, credential,
  MT5, scheduler, network, WORM/CAS, process, or broker effects.
- Keep central LIVE policy and production readiness false.

## Functional Requirements

- FR-1: A dedicated
  `live_runtime/live_canary_provider_bound_runtime_session.py` module MUST own
  the exact `LiveCanaryProviderBoundRuntimeLaunchSession` v2 class.
- FR-2: The consumer module MUST register that exact class with the existing
  lightweight runtime authority registry and MUST preserve its private session
  seal, current-window check, canonical payload, XAUUSD/0.01 scope, one-position
  limit, and independent per-order authorization requirement.
- FR-3: The operator-side provider-bound activation module MUST import and
  re-export the consumer class rather than define a second class.
- FR-4: `production_bootstrap.py` MUST import the provider-bound predicate
  through the consumer module so class registration occurs whenever the
  Execution runtime loads.
- FR-5: The Execution allowlist MUST contain the consumer module and one
  isolated closure probe.
- FR-6: The Execution allowlist MUST NOT gain configured-candidate assemblers,
  source-bound verifiers, base-suite tooling, provider conformance review,
  provider acceptance preparation, admission assembly, custody assembly, or
  launch-session activation modules.
- FR-7: The builder MUST expose an immutable critical consumer-closure set
  containing central policy, canonical contracts, the authority registry, the
  v2 consumer contract, production bootstrap, and LIVE provider materializer.
- FR-8: The manifest MUST record sorted `{path,size_bytes,sha256}` entries,
  file count, canonical closure identity, `production_execution_ready=false`,
  `live_allowed=false`, and `order_capability=DISABLED`.
- FR-9: The isolated probe MUST validate a regular non-link/non-reparse root,
  import the v2 class, production authority consumer, and provider runtime
  source sealer, and reject an unsealed forged object.
- FR-10: Probe success MUST report closure availability only. It MUST NOT
  deserialize private authority, call assembly functions, read credentials,
  import MT5, access external evidence, mutate a task, launch a service, or
  submit an order.
- FR-11: The release profile, dependency locks, reviewed MT5 adapter primitive
  inventory, central policy constants, and production readiness MUST remain
  unchanged.
- FR-12: Existing configured candidates MUST naturally receive a new release
  identity; no previous identity may be relabeled or reused.
- FR-13: Tests MUST execute the probe from a temporary directory containing
  only files named by the Execution allowlist, in normal and optimized modes.
- FR-14: Package or probe success MUST NOT be interpreted as WORM/CAS custody,
  provider acceptance, demo soak, central unlock, broker acknowledgement, or
  LIVE trading authority.

## Non-Functional Requirements

- NFR-1: The consumer contract and probe MUST use Python 3.12 standard library
  and already-reviewed Execution runtime modules only.
- NFR-2: Identical clean commit/tree and allowlist inputs MUST produce
  byte-identical ZIP, sidecar, closure records, and identities.
- NFR-3: Normal and optimized Python MUST make identical accept/reject
  decisions; security behavior MUST not rely on `assert`.
- NFR-4: Focused tests MUST run without Windows, network, credentials, MT5,
  provider import, scheduler access, WORM/CAS, or production keys.
- NFR-5: The isolated closure probe MUST complete within ten seconds on the
  development host, including interpreter startup.
- NFR-6: Existing operator/service allowlist separation tests, activation
  tests, provider tests, full normal tests, and full optimized tests MUST pass.

## Acceptance Criteria

### AC-1: One exact producer-consumer class (FR-1, FR-2, FR-3, FR-4)

Given the operator activation module and Execution production bootstrap
When both import provider-bound launch authority
Then they reference the same registered v2 class and private seal
And a forged unsealed instance is rejected.

### AC-2: Minimal closure is packaged (FR-5, FR-6, FR-7, FR-13)

Given the project Execution allowlist
When only its named files are copied to an isolated release root
Then the closure probe imports successfully in normal and optimized modes
And every operator-only assembly or conformance module remains absent.

### AC-3: Manifest binds exact consumer bytes (FR-7, FR-8, FR-12)

Given two builds from the same clean commit
When their manifests and archives are compared
Then closure records and identity are byte-identical
And changing or removing a required consumer byte changes or rejects the
release identity.

### AC-4: Probe remains deny-only (FR-9, FR-10, FR-14)

Given the exact extracted Execution release
When `python -I -S -B` runs the probe
Then it reports the locked central policy and consumer schema
And performs no external or broker effect.

### AC-5: Safety and compatibility remain locked (FR-11, FR-14)

Given successful closure verification
When focused, optimized, dependency, static, separation, and full regression
gates run
Then production readiness and central LIVE authority remain false
And the reviewed adapter remains the only owner of broker order calls.

## Edge Cases

- EC-1: Consumer contract file is absent -> isolated probe rejects.
- EC-2: Consumer file is renamed with identical bytes -> required path rejects.
- EC-3: Authority registry expects the old producer module path -> registration
  rejects.
- EC-4: Producer defines a second v2 class -> exact identity tests reject.
- EC-5: Forged object has the class but lacks the private seal -> predicate
  rejects.
- EC-6: Operator-only tooling appears in a service allowlist -> separation
  tests reject.
- EC-7: Probe root/member is a symlink or Windows reparse point -> reject.
- EC-8: Central LIVE lock is true or policy decision differs -> probe rejects.
- EC-9: Consumer imports successfully but external authority is missing ->
  closure-only success, never readiness.
- EC-10: Optimized mode removes assertions -> behavior remains unchanged.

## API Contracts

HTTP API: N/A. The marker `POST /not-applicable` is documentation-only and
MUST NOT be implemented or exposed.

```python
REQUIRED_LIVE_CANARY_PROVIDER_BOUND_RUNTIME_CLOSURE: frozenset[str]

def live_canary_provider_bound_runtime_closure_manifest(
    sources: Mapping[str, bytes],
) -> dict[str, object]:
    """Return exact deny-only consumer-closure records."""

def is_live_canary_provider_bound_runtime_launch_session(
    value: object,
) -> bool:
    """Accept only the registered exact v2 class carrying its private seal."""

def main(argv: list[str] | None = None) -> int:
    """Verify isolated consumer imports and locked central policy."""
```

## Data Models

| Model | Required fields | Invariants |
|---|---|---|
| Provider-bound runtime session | v2 binding hashes, windows, scope, seal | XAUUSD; 0.01; launch-only; per-order authority required |
| Consumer closure manifest | schema, files, count, identity, safety | sorted exact records; derived hashes; readiness false |
| Closure file record | path, size, SHA-256 | exact packaged regular-file bytes |
| Probe result | status, schema count, policy, effects | consumer-only; locked; no external effects |

## Out of Scope

- OS-1: Constructing admission, custody, acceptance, or launch authority inside
  the Execution service release.
- OS-2: Building or accepting actual target-Windows provider evidence.
- OS-3: Uploading to WORM storage or operating an external CAS/nonce ledger.
- OS-4: Provisioning credentials, service accounts, ACLs, tasks, or MT5.
- OS-5: Enabling DEMO_AUTO or LIVE policy or sending any order.
- OS-6: Treating package availability as soak, promotion, approval, or canary
  proof.
