# Live Canary Production Runtime Integration v1

**Author:** OpenAI Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved for implementation
**Reviewers:** senior architecture, security, and ship-gate

## Context

AI_SCALPER now has a verifier-sealed `LiveCanaryRuntimeLaunchSession`. The
session can exist only after exact activation, prebootstrap, portable WORM/CAS
custody, one-use nonce reservation, independent pins, and a separately
reviewed central LIVE unlock. It authorizes a short-lived process/bootstrap
launch but explicitly does not authorize execution or broker mutation.

The existing `ProductionRuntimeConfig`, `ProductionRuntimeBootstrap`,
`ProductionRuntimeComposition`, and `RuntimeSupervisor` support DEMO and a
locked DEMO_AUTO path. `ProductionRuntimeConfig` rejects LIVE outright, and
the supervisor routes LIVE through a DEMO_AUTO stage-authorization branch
that can never succeed. This integration must make the sealed launch session
the mandatory startup authority for a LIVE observation process while keeping
all order actions unavailable. The checked-in central policy remains false,
so this code path is testable only with an in-process policy patch until the
external ship gate and unlock ceremony are complete.

## Goals

- Admit an exact LIVE production configuration only while the central LIVE
  policy is enabled and only when it is bound to the exact sealed candidate
  and runtime launch session.
- Revalidate session currentness before every effectful bootstrap,
  initialization, external-evidence, supervisor-start, and cycle boundary.
- Replace the impossible LIVE-to-DEMO_AUTO stage authorization mapping with
  the sealed LIVE launch session, without weakening DEMO or DEMO_AUTO.
- Keep LIVE cycle execution unavailable until a separate per-order LIVE
  execution specification and implementation are reviewed.
- Preserve stable, non-sensitive failure codes and existing DEMO artifact
  identities.

## Out of Scope

- OS-1: This change does not set checked-in `execution_policy.LIVE_ALLOWED`
  or `SAFE_TO_DEMO_AUTO_ORDER` to true.
- OS-2: This change does not create a LIVE order action, permit, promotion,
  environment arm, journal lease, broker request, or submission path.
- OS-3: This change does not provision Windows tasks, credentials, WORM/CAS,
  TLS, broker accounts, provider conformance, or selected-broker evidence.
- OS-4: This change does not bypass MT5 attestation, journal/risk/news/
  reconciliation custody, supervisor fencing, or kill-switch controls.
- OS-5: This change does not change DEMO or DEMO_AUTO canonical configuration
  payloads, receipt schemas, or execution behavior.

## Functional Requirements

- FR-1: `ProductionRuntimeConfig` MUST continue to accept exact DEMO/DEMO and
  DEMO/DEMO_AUTO pairs and MAY accept only the exact LIVE/LIVE pair when
  `execution_mode_policy_decision("LIVE") == (True, ())` and
  `SAFE_TO_DEMO_AUTO_ORDER=False`.
- FR-2: A LIVE `ProductionRuntimeConfig` MUST remain a non-authoritative
  candidate description: `live_allowed=false`,
  `safe_to_demo_auto_order=false`, and `order_capability=DISABLED`.
- FR-3: `ProductionRuntimeBootstrap` and static contract validation MUST take
  the exact `LiveCanaryRuntimeCandidate` and verifier-sealed
  `LiveCanaryRuntimeLaunchSession` as explicit keyword-only inputs for LIVE.
  Missing, extra-on-DEMO, subclassed, forged, or duck-typed inputs MUST fail.
- FR-4: The LIVE configuration's `config_sha256` MUST equal the exact
  candidate content hash. Every shared path, broker, account hash, server,
  currency, symbol map, journal, build, dependency, MT5, calendar, broker
  specification, champion, runtime trust-domain, and operational limit field
  MUST equal the candidate.
- FR-5: The launch session MUST bind the same candidate hash, live-stage
  binding, runtime profile, release manifest, and XAUUSD/0.01/one-position
  scope. It MUST remain launch-only and MUST not claim execution or broker
  mutation authority.
- FR-6: LIVE MUST require `ProductionRuntimePorts.stage_binding is None` and
  MUST never call the DEMO stage-authorization provider. DEMO and DEMO_AUTO
  MUST still require the exact `StageBinding` and existing stage provider.
- FR-7: Static validation and bootstrap construction MUST invoke no provider,
  filesystem, credential, MT5, network, scheduler, journal, or broker effect.
- FR-8: `materialize()` MUST obtain trusted UTC and validate the sealed LIVE
  session before the credential provider, filesystem preflight, journal open,
  MT5 installation verification, or any other materialization effect.
- FR-9: `ProductionRuntimeComposition` MUST revalidate the exact session
  before module attestation, credential/evidence verification, MT5
  initialization, supervisor start, and every runtime cycle.
- FR-10: The existing WORM audit root MUST bind LIVE startup authority by
  mapping `stage_binding_sha256` to the candidate live-stage hash,
  `stage_authorization_sha256` to the sealed session hash, and
  `stage_external_checkpoint_sha256` to the session's external checkpoint.
- FR-11: `RuntimeSupervisor` MUST accept a launch session only for mode LIVE.
  Before any supervisor checkpoint provider, lease claim, reconciliation, or
  decision provider call, it MUST revalidate current central policy, session
  seal, session expiry, candidate/config hash, and LIVE safety flags.
- FR-12: LIVE startup MUST not request or consume
  `RuntimeStageAuthorizationPorts`; the startup receipt MUST keep DEMO stage
  authorization fields empty.
- FR-13: A LIVE supervisor decision other than `NO_ACTION` MUST fail closed
  with `LIVE_EXECUTION_PATH_NOT_IMPLEMENTED` before any manual-demo or
  DEMO_AUTO execution callback can run.
- FR-14: Central relock, session expiry, candidate/config drift, scope drift,
  or session substitution at materialize/start/cycle time MUST fail closed.
- FR-15: Shutdown and fail-closed cleanup MUST remain possible after expiry or
  relock; an expired launch session must never block stopping the service.
- FR-16: Public failures MUST use stable uppercase reason codes and MUST not
  expose callback text, credentials, raw account identifiers, private keys,
  object addresses, or broker payloads.
- FR-17: The checked-in central LIVE lock MUST remain false, and the new LIVE
  branch MUST be unreachable in ordinary source execution.
- FR-18: No existing DEMO/DEMO_AUTO canonical payload or binding hash MAY
  change solely because this optional LIVE integration exists.

## Non-Functional Requirements

- NFR-1: Validation MUST use explicit conditions rather than `assert` and
  MUST behave identically under normal Python and `PYTHONOPTIMIZE=2`.
- NFR-2: The integration MUST use existing Python 3.12 contracts and standard
  library primitives; no new dependency is permitted.
- NFR-3: Session checks MUST precede effectful callbacks and be repeated near
  time-of-use boundaries to minimize expiry and central-relock races.
- NFR-4: Focused tests MUST run on non-Windows hosts without network, MT5,
  credentials, cloud storage, scheduler privileges, or broker access.
- NFR-5: Full normal and optimized repository regression MUST remain green.
- NFR-6: Changed files MUST pass compile, whitespace, static no-effect, and
  central-lock checks.
- NFR-7: Failure handling MUST remain deterministic and return only bounded,
  operator-safe reason codes.

## Acceptance Criteria

### AC-1: Checked-in policy keeps LIVE unreachable (FR-1, FR-2, FR-17)

Given an exact LIVE candidate and sealed launch session
When a LIVE production configuration is constructed under checked-in source
Then construction fails with `LIVE_MODE_POLICY_LOCKED`
And no external callback is invoked.

Given a test-only central unlock with DEMO_AUTO also true or wrong LIVE scope
When configuration or runtime validation runs
Then it fails closed.

### AC-2: Exact candidate and session are mandatory (FR-3, FR-4, FR-5)

Given test-only central unlock and one exact LIVE configuration
When static validation receives the matching candidate and session
Then it returns a deny-only contract report without invoking callbacks.

When either input is absent, forged, replaced, subclassed, or cross-bound
Then validation fails before callbacks.

### AC-3: DEMO behavior and hashes remain unchanged (FR-6, FR-18)

Given existing DEMO and DEMO_AUTO fixtures
When their configuration payloads, bootstrap reports, and tests run
Then they retain the same fields, hashes, stage-authorization requirements,
and behavior.

Given LIVE inputs on a DEMO bootstrap
When static validation runs
Then it rejects the mixed authority.

### AC-4: Session currentness precedes effects (FR-7, FR-8, FR-9, FR-14)

Given a LIVE bootstrap whose central policy is relocked or whose session is
expired
When `materialize`, `verify_external_evidence`, `initialize`, `start`, or
`run_cycle` is requested
Then the request fails before its first credential, filesystem, MT5,
reconciliation, decision, or broker callback.

### AC-5: LIVE WORM root binds the launch session (FR-9, FR-10, FR-12)

Given current external runtime evidence for one LIVE session
When evidence is verified
Then the WORM root binds the candidate live-stage hash, exact launch-session
hash, and exact external launch checkpoint
And no DEMO stage authorization provider is called.

### AC-6: Supervisor is observation-only (FR-11, FR-12, FR-13, FR-15)

Given a current exact launch session and a test-only central unlock
When the LIVE supervisor starts and receives `NO_ACTION`
Then it may record normal startup/cycle evidence without DEMO stage evidence.

When any execution action is returned
Then it fails with `LIVE_EXECUTION_PATH_NOT_IMPLEMENTED`
And no execution callback is called.

When stop or fail-closed cleanup runs after relock or expiry
Then cleanup remains available.

### AC-7: Static and optimized gates pass (FR-16, FR-17, FR-18; NFR-1, NFR-2, NFR-3, NFR-4, NFR-5, NFR-6, NFR-7)

Given the completed integration
When focused, related, full, optimized, static, and ship-gate checks run
Then safety behavior does not depend on assertions
And the central LIVE lock remains false
And no test or report claims an order was sent.

## Edge Cases

- EC-1: LIVE config with DEMO environment, LIVE environment with DEMO mode,
  central policy false, DEMO_AUTO simultaneously true, or expanded symbol
  scope -> reject.
- EC-2: Candidate/config mismatch in any path, server, account hash, currency,
  symbol, hash, key ID/fingerprint, operational limit, or champion pin ->
  reject before callbacks.
- EC-3: Directly constructed, copied, subclassed, memory-forged, expired, or
  cross-candidate launch session -> reject.
- EC-4: LIVE carries a DEMO `StageBinding`, or DEMO omits its stage binding ->
  reject.
- EC-5: Session is current at bootstrap construction but expires or central
  policy relocks before materialization, MT5 initialization, supervisor start,
  or cycle -> reject at the next boundary.
- EC-6: WORM receipt binds an older session, candidate stage, or checkpoint ->
  reject with the existing WORM root mismatch code.
- EC-7: LIVE decision requests MANUAL_DEMO_EXECUTE or DEMO_AUTO_EXECUTE ->
  latch fail-closed and never invoke either execution service.
- EC-8: Session error contains sensitive-looking chained text -> expose only
  the stable integration reason code.
- EC-9: Stop is requested after session expiry or central relock -> shutdown
  proceeds without requiring fresh launch authority.
- EC-10: Normal and optimized mode strip assertions -> all guards still run.

## Data Models

No new serializable production configuration schema is introduced. A LIVE
`ProductionRuntimeConfig` uses the existing `config_sha256` field as the exact
`LiveCanaryRuntimeCandidate.content_sha256`. The candidate therefore binds the
runtime profile and release manifest transitively without inserting a
short-lived launch nonce into stable configuration.

`LiveCanaryRuntimeLaunchSession` remains an in-memory verifier-sealed object.
It is supplied separately to bootstrap and supervisor because a fresh session
is required for each bounded process launch.

| Boundary | Stable binding | Ephemeral authority | Order authority |
| --- | --- | --- | --- |
| production config | exact candidate hash | none | disabled |
| production bootstrap | config + candidate | sealed launch session | disabled |
| runtime supervisor | binding config hash | same current session | unavailable |
| WORM audit root | candidate stage hash | session + checkpoint hashes | disabled |

```text
deny-only LIVE candidate + sealed launch session
                    |
                    v
      static exact production-config validation
                    |
                    v
  current session check before materialization effects
                    |
                    v
   composition evidence / initialize / supervisor start
                    |
                    v
        LIVE observation cycles: NO_ACTION only
                    |
                    v
 future separately specified per-order LIVE execution path
```

## API Contracts

No HTTP endpoint is added. In particular,
`POST /api/live-canary/production-runtime` is forbidden; the integration is
in-process only.

```python
ProductionRuntimeBootstrap(
    config,
    ports,
    *,
    live_candidate=None,
    live_launch_session=None,
)

validate_production_bootstrap_contract(
    config,
    ports,
    *,
    live_candidate=None,
    live_launch_session=None,
)

RuntimeSupervisor(
    ...,
    live_launch_session=None,
)
```

For `mode="LIVE"`, the candidate and session are mandatory. For every other
mode they must be absent. `stage_binding` and stage authorization remain
mandatory only for DEMO and DEMO_AUTO.

## Error Handling

Integration errors use `ProductionBootstrapError` or
`RuntimeSupervisorCriticalError` with stable uppercase codes. A
`LiveCanaryRuntimeLaunchSessionError` is translated to a bounded
`LIVE_CANARY_RUNTIME_LAUNCH_SESSION_INVALID` family code; its chained message
is never copied into the public error. Startup/cycle failures continue to use
the existing local critical latch and kill-switch behavior. Static validation
performs no latch or provider effect.

## Security and Privacy

- Only hashed account identity and non-secret canonical contracts enter the
  integration.
- Broker credentials, private keys, object URLs, provider tokens, and raw
  account IDs are never added to config or session APIs.
- The stable config binds the complete candidate while the ephemeral session
  proves the reviewed launch window; neither can substitute for the other.
- Repeated session checks fail on central relock and expiry at time of use.
- The lack of a LIVE execution action is deliberate defense in depth: even a
  started observation process cannot route an order through the supervisor.

## Observability

The contract report records that LIVE per-order execution is not implemented.
WORM roots bind the candidate stage, session, and checkpoint hashes. Startup
and cycle failures expose bounded reason codes. No new logger emits sensitive
objects; existing supervisor receipts continue to carry hashes only.

## Test Plan

- Unit tests build a complete sealed session from existing live-canary
  fixtures with temporary platform-local paths.
- Tests cover locked and test-unlocked config construction, exact static
  success, every shared candidate/config mismatch class, forged/missing/mixed
  inputs, and no provider calls during construction.
- Tests prove relock and expiry reject materialization before credential,
  filesystem, MT5, reconciliation, and decision callbacks.
- Supervisor tests prove session/current-policy checks precede its external
  startup and cycle providers and any non-NO_ACTION decision is unavailable.
- Existing production-bootstrap and runtime-supervisor suites run unchanged
  except assertions whose former requirement was that LIVE was unsupported.
- Focused and related suites run in normal and optimized modes.
- Full repository regression, compile checks, whitespace checks, central-lock
  inspection, and ship-gate audit run before commit.

## Rollout Plan

1. Land this source integration while checked-in LIVE remains false.
2. Extend the reviewed Windows LIVE configured release/factory so it supplies
   the exact candidate and freshly minted session without serializing seals.
3. Collect the actual independently eligible selected-broker demo-auto cohort,
   provider conformance, WORM/CAS, promotion, approval, Windows task, TLS,
   backup/restore, and monitoring evidence. For the current JP operating
   jurisdiction, this means the reviewed `phillip-commodity` lane, not XM.
4. Specify and implement the independent per-order LIVE execution boundary.
5. Perform a reviewed central-unlock ceremony and bounded XAUUSD 0.01 canary
   only after every external and manual ship gate passes.

## Rollback Plan

Restore or keep `execution_policy.LIVE_ALLOWED=False`, prevent new launch
sessions, stop any bounded observation process, preserve the consumed
capability/session/checkpoint hashes, latch fail-closed if runtime integrity is
uncertain, reconcile broker state, and require a new nonce/session before any
subsequent launch. Shutdown must remain available even if the old session is
expired.

## Open Questions

- The exact Windows provider responsible for transporting the nonserializable
  session into the service process remains an external deployment design.
- The per-order LIVE decision/permit composition is intentionally deferred to
  a separate spec after this observation-only integration passes all gates.
- Central unlock ownership and rollback authority remain manual,
  independently reviewed production decisions.
