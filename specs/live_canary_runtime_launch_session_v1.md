# Live Canary Runtime Launch Session v1

**Author:** OpenAI Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved for implementation
**Reviewers:** senior architecture, security, and ship-gate

## Context

AI_SCALPER has a verifier-sealed `LiveCanaryOneUseLaunchCapability` proving
that one external launcher nonce was reserved through signed WORM custody and
an independently retained CAS checkpoint. That capability is intentionally
non-authoritative while the checked-in central LIVE lock is false.

The next boundary must consume that short-lived prerequisite only after a
separately reviewed central unlock. It must re-read the exact current external
checkpoint and nonce state, bind the exact LIVE candidate and Windows launch
identity, and return a sealed process/bootstrap launch session. This session is
not an order authorization. Per-order permit, promotion, risk, news, journal,
reconciliation, environment-arm, MT5 preflight, and final submission guards
remain mandatory downstream.

The checked-in source continues to set `execution_policy.LIVE_ALLOWED=False`.
Tests may temporarily patch that constant in-process to prove both sides of
the composition boundary without launching a process, importing MT5, reading
credentials, or contacting a broker.

## Goals

- Convert one exact, still-current launch prerequisite into a sealed and
  short-lived process/bootstrap launch session only while the central LIVE
  policy is explicitly enabled.
- Revalidate the external CAS high-water checkpoint and consumed nonce before
  and after the trusted-time window.
- Preserve strict separation between launch authority and per-order execution
  authority.
- Expose stable, non-sensitive failure reason codes suitable for an operator
  runbook and automated ship gates.

## Out of Scope

- OS-1: This change does not set the checked-in central LIVE lock to true.
- OS-2: This change does not launch a process, access credentials, initialize MT5,
  schedule a Windows task, issue a permit, mutate a journal, or submit an order.
- OS-3: This change does not replace production bootstrap, supervisor, risk,
  promotion, news, reconciliation, or executor controls.
- OS-4: This change does not authorize symbols other than XAUUSD, lots other than
  0.01, or more than one concurrent position.

## Functional Requirements

- FR-1: `activate_live_canary_runtime_launch_session` MUST accept only the
  exact `LiveCanaryRuntimeCandidate`, verifier-sealed
  `LiveCanaryPrebootstrapAdmission`, verifier-sealed
  `LiveCanaryOneUseLaunchCapability`, and exact canonical
  `ExternalLauncherTrustPolicy` types.
- FR-2: The caller MUST independently pin the candidate, admission, launch
  capability, external checkpoint, launcher nonce, runtime profile, release
  manifest, live-stage binding, launcher trust policy, deployment host,
  service account, and task definition SHA-256 identities.
- FR-3: Candidate, admission, capability, checkpoint proposal, and caller pins
  MUST form one exact lineage. Cross-candidate, cross-release, cross-host,
  cross-service, cross-task, or cross-stage substitution MUST fail closed.
- FR-4: The central policy MUST be exactly `LIVE_ALLOWED=True`,
  `SAFE_TO_DEMO_AUTO_ORDER=False`, and
  `execution_mode_policy_decision("LIVE") == (True, ())` at both the start and
  completion of activation.
- FR-5: The central LIVE scope MUST remain exactly XAUUSD, lot 0.01, and one
  concurrent position. Symbol-set or lot-bound drift MUST fail closed.
- FR-6: Activation MUST start no earlier than the admission and capability
  checks, and MUST finish strictly before the capability and checkpoint
  proposal expiry. Trusted-clock regression MUST fail closed.
- FR-7: The external checkpoint provider MUST return strict canonical bytes
  for the exact current checkpoint whose canonical content hash equals both
  the launch capability and caller pin.
- FR-8: The current checkpoint proposal MUST bind the capability sequence,
  candidate, admission, launcher attestation, nonce, runtime release, host,
  service account, and task definition exactly.
- FR-9: The external nonce-seen provider MUST report exactly true for the
  reserved launcher nonce. False, non-boolean, exception, or different nonce
  MUST fail closed.
- FR-10: The external checkpoint MUST be read twice and remain byte-identical;
  the nonce MUST remain consumed on the second observation. A concurrent
  head advance, rollback, fork, or disappearance MUST prevent session issue.
- FR-11: `LiveCanaryRuntimeLaunchSession` MUST be verifier-sealed, immutable,
  canonical, short-lived, and bind every checked identity plus the two
  external-state observations.
- FR-12: A successful session MUST set `central_live_policy_enabled=true`,
  `bootstrap_authorized=true`, `process_launch_authorized=true`, and
  `live_allowed=true` while retaining `execution_authorized=false`,
  `broker_mutation_authorized=false`, and `order_capability=GATED_PRESENT`.
- FR-13: The session MUST state that an independent per-order authorization,
  signed promotion evidence, permit, risk decision, environment arm, durable
  journal lease, and final MT5 submission guard remain required.
- FR-14: A direct constructor, duck type, copied fields, subclass, or
  `object.__new__` lookalike MUST not satisfy the session seal predicate.
- FR-15: Public failures MUST expose stable uppercase reason codes and MUST
  not include callback exceptions, private keys, raw account IDs, object
  locations, credentials, or broker data.
- FR-16: The module MUST contain no network client, filesystem write,
  subprocess, scheduler, credential-store, MT5, journal, permit issuance,
  process launch, broker mutation, or order submission surface.
- FR-17: The checked-in central LIVE lock MUST remain false after
  implementation and all tests.
- FR-18: Immediately before session issue, activation MUST atomically consume
  the exact capability content hash in a thread-safe process-local replay
  registry. Repeated or concurrent activation of the same sealed capability
  MUST fail. Expired registry entries MAY be pruned; a failed final activation
  after consumption burns the capability.

## Non-Functional Requirements

- NFR-1: Implementation MUST use Python 3.12 standard-library primitives and
  existing immutable contracts only.
- NFR-2: Validation MUST not use `assert` and MUST behave identically under
  normal Python and `PYTHONOPTIMIZE=2`.
- NFR-3: External callbacks MUST be data-only, invoked synchronously, and have
  exceptions mapped to stable public reason codes.
- NFR-4: No callback may be invoked before exact sealed inputs, independent
  pins, central policy, and initial time checks succeed.
- NFR-5: Focused tests MUST run without Windows, network, credentials, cloud
  SDKs, MT5, scheduler privileges, or broker access.
- NFR-6: Related and full repository tests MUST remain green in normal and
  optimized modes.
- NFR-7: Static checks MUST prove the checked-in central lock remains false
  and the new module has no forbidden effect imports or calls.

## Acceptance Criteria

### AC-1: Central unlock is mandatory and mutually exclusive (FR-4, FR-5, FR-17)

Given exact sealed launch evidence while the checked-in policy is unchanged
When runtime launch activation is requested
Then activation fails with `CENTRAL_LIVE_LOCK_NOT_ENABLED`
And no external checkpoint or nonce callback is called.

Given a test-only central unlock with DEMO_AUTO also enabled or LIVE policy
scope drift
When activation is requested
Then activation fails before external callbacks.

### AC-2: Exact independent pins are mandatory (FR-1, FR-2, FR-3, FR-14)

Given a wrong sealed-object type, copied object, or one changed independent pin
When activation is requested
Then it fails before external callbacks with a stable binding reason code.

### AC-3: Current CAS head and nonce are revalidated (FR-6, FR-7, FR-8, FR-9, FR-10)

Given exact sealed evidence and a test-only central unlock
When the provider returns the current canonical checkpoint and consumed nonce
Then both observations match the capability and activation continues.

Given a missing, malformed, rolled-back, advanced, forked, or substituted head
or a nonce that is absent/non-boolean
When activation is requested
Then no session is emitted.

### AC-4: Successful session authorizes launch, not orders (FR-11, FR-12, FR-13, FR-14, FR-18)

Given every exact check succeeds within the launch window
When activation completes
Then a verifier-sealed `LiveCanaryRuntimeLaunchSession` is returned
And it authorizes only bootstrap and process launch
And execution and broker mutation remain unauthorized.

When the same exact capability is activated again or by concurrent callers
Then exactly one caller can receive a session and all others fail as replay.

### AC-5: Race, expiry, and policy relock fail closed (FR-4, FR-6, FR-10, FR-15)

Given a head change, nonce change, clock regression/expiry, or central policy
relock between the first and final observation
When activation completes
Then no session is emitted and the public error contains only a stable code.

### AC-6: Static and optimized safety remain clean (FR-15, FR-16, FR-17; NFR-1, NFR-2, NFR-3, NFR-4, NFR-5, NFR-6, NFR-7)

Given the implementation and rejection paths
When focused, related, full, optimized, and static checks run
Then results do not depend on stripped assertions
And no forbidden effect primitive is present
And the checked-in central LIVE lock remains false.

## Edge Cases

- EC-1: Directly constructed, subclassed, or memory-forged upstream evidence
  or session object -> reject.
- EC-2: Uppercase, zero, short, padded, non-string, or mismatched independent
  SHA-256 pin -> reject before callbacks.
- EC-3: Central LIVE true with DEMO_AUTO true, unsupported policy decision,
  expanded symbol set, or altered lot floor/ceiling -> reject.
- EC-4: Capability checked before admission, expired at start, expires during
  callbacks, or clock regresses -> reject.
- EC-5: Provider returns text, empty bytes, malformed JSON, non-canonical JSON,
  unknown fields, different checkpoint bytes, or raises -> reject safely.
- EC-6: Checkpoint sequence, candidate, admission, launcher attestation, nonce,
  release, host, service, task, request time, or expiry differs -> reject.
- EC-7: Nonce provider returns false, integer one, text true, or raises ->
  reject safely.
- EC-8: First observation succeeds but second checkpoint/nonce observation
  changes -> reject without a session.
- EC-9: Central policy is true at entry but false or structurally changed at
  completion -> reject without a session.
- EC-10: Callback exception contains a secret-looking value -> expose only the
  stable callback failure code.
- EC-11: Two threads finish external revalidation for the same capability at
  the same time -> one atomic registry winner and one replay rejection.

## Data Models

`LiveCanaryRuntimeLaunchSession` is an in-memory immutable capability. It is
not persisted by this module and cannot be reconstructed from canonical JSON.
Its seal proves that the exact external one-use reservation remained current
during a reviewed central-unlock window. A module-owned lock and expiry-pruned
registry ensure one session can be minted per exact sealed capability in the
launcher process; the upstream external CAS prevents recreating that sealed
capability from the same nonce in a different Windows launcher process.

| Field group | Type | Constraints |
| --- | --- | --- |
| timestamps | UTC datetime | checked twice, monotonic, before all expiries |
| lineage | SHA-256 strings | exact candidate, admission, capability, checkpoint, nonce, release, runtime, stage |
| Windows identity | SHA-256 strings | exact host, service account, and task pins |
| limits | symbol/float/integer | XAUUSD, 0.01 lot, one concurrent position |
| launch flags | boolean | central LIVE, bootstrap, and process launch true |
| order flags | boolean/string | execution and broker mutation false; `GATED_PRESENT` |

```text
sealed candidate + admission + one-use launch capability
                         |
                         v
             independent caller hash pins
                         |
                         v
        central LIVE policy exact and enabled (twice)
                         |
                         v
      current checkpoint + consumed nonce (read twice)
                         |
                         v
         sealed runtime launch session (short lived)
                         |
                         v
      future production bootstrap/supervisor composition
                         |
                         v
 per-order permit + promotion + risk + journal + MT5 guards
```

## API Contracts

No HTTP API is exposed. In particular, `POST /api/live-canary/runtime-launch`
is a forbidden surface; activation is an in-process Python capability boundary
only.

```python
activate_live_canary_runtime_launch_session(
    *,
    candidate,
    admission,
    launch_capability,
    expected_candidate_sha256,
    expected_admission_sha256,
    expected_launch_capability_sha256,
    expected_checkpoint_sha256,
    expected_launch_nonce_sha256,
    expected_runtime_profile_sha256,
    expected_release_manifest_sha256,
    expected_live_stage_binding_sha256,
    launcher_policy,
    expected_launcher_policy_sha256,
    expected_deployment_host_alias_sha256,
    expected_service_account_alias_sha256,
    expected_task_definition_sha256,
    external_checkpoint_provider,
    external_nonce_seen_provider,
    clock_provider,
) -> LiveCanaryRuntimeLaunchSession
```

The checkpoint provider returns `bytes`; the nonce provider accepts the exact
nonce hash and returns an exact `bool`; the clock provider returns an aware UTC
`datetime`. No callback receives a raw account identifier, credential, private
key, or broker mutation object.

## Error Handling

All public failures raise `LiveCanaryRuntimeLaunchSessionError` with a
sanitized `reason_code`. Type and binding failures occur before callbacks.
Callback exceptions are replaced with `EXTERNAL_CHECKPOINT_READ_FAILED` or
`EXTERNAL_NONCE_READ_FAILED`. The original exception is chained internally but
its message is not included in the public error text.

## Security and Privacy

- The module receives only public canonical evidence and hashed identities.
- Private signing keys, broker credentials, account numbers, object URLs, and
  provider tokens are never accepted.
- Exact type-and-seal predicates prevent reconstruction from copied JSON.
- Independent pins prevent a valid but unintended lane from being selected.
- Repeated policy and external-state observations narrow time-of-check versus
  time-of-use races before a downstream process is allowed to launch.
- An atomic process-local replay registry prevents duplicate session minting;
  its safety composes with the non-serializable seal and upstream external CAS.
- Session canonical data is safe for audit but still does not grant orders.

## Observability

Successful callers may record the session content hash, sequence, checkpoint,
nonce, candidate, release, host, service, task, and expiry. Failures expose
only the stable reason code. This module emits no logs itself so the caller can
apply existing redaction, WORM retention, and correlation policies.

## Test Plan

- Unit tests cover locked policy, mutually exclusive policy, scope drift,
  independent pin drift, exact success, direct construction, expiry, clock
  regression, malformed head, head rollback/advance, nonce absence/type,
  callback exceptions, second-read race, and final policy relock.
- Unit tests also cover sequential replay and concurrent activation, proving
  exactly one session is issued for one capability.
- Focused tests run in normal and optimized modes.
- Related live-canary admission/custody tests run in normal and optimized modes.
- Full repository tests run in normal and optimized modes.
- Static AST/text checks reject forbidden effect imports/calls and verify
  `execution_policy.LIVE_ALLOWED` remains false in checked-in source.

## Rollout Plan

1. Land this source-only boundary with central LIVE still false.
2. Integrate the sealed session as a mandatory input to the reviewed
   production bootstrap and runtime supervisor LIVE path.
3. Produce provider-backed Windows WORM/CAS evidence and a clean release.
4. Perform an independently reviewed central-unlock ceremony only after all
   production ship-gate controls pass.
5. Start one XAUUSD 0.01-lot canary under bounded supervision and immediate
   kill-switch/reconciliation monitoring.

## Rollback Plan

Keep `execution_policy.LIVE_ALLOWED=False` or restore it to false, stop the
bounded service, preserve the consumed nonce/checkpoint and session hash, latch
the existing kill switch, reconcile broker facts, and require a new launcher
nonce plus a new reviewed capability before any subsequent launch. A consumed
or expired capability is never reused.

## Open Questions

- Which production external provider will implement WORM object readback and
  atomic CAS on the Windows host remains an operator deployment decision.
- The exact production bootstrap field that binds
  `runtime_profile_sha256` will be finalized in the next composition spec.
- Central unlock approval, live account credentials, signed promotion
  evidence, and broker-side demo/live proof remain external ship blockers.
