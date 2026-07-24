# Spec: Windows Manual-Demo Entry Review v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-24
**Status:** Approved
**Reviewers:** AI_SCALPER project owner (standing authorization to continue the
roadmap while preserving all execution locks)
**Related specs:** `specs/windows_three_service_external_acceptance_v1.md`,
`specs/demo_auto_stage_authorization_v1.md`,
`specs/manual_demo_acceptance_tracker_v1.md`

## Context

The exact Windows three-service external-acceptance dossier contains ten gates.
Nine gates describe prerequisites that must exist before a controlled
manual-demo run: configured releases and providers, launcher and Task Scheduler
custody, IPC and monitor custody, Windows hardening and failure drills, and
minimum-lot XAUUSD risk feasibility. The tenth gate proves the result of the
manual-demo run itself: exactly ten controlled order lifecycles.

Consequently, the full dossier cannot be complete before manual-demo starts.
The existing verifier truthfully reports the tenth gate as missing, but no
typed boundary currently distinguishes that expected pre-run state from an
arbitrary incomplete dossier. The legacy manual-demo activation kit lists
blockers but is not bound to the signed three-service dossier. This gap can
cause operators to either wait for circular evidence or manually infer that an
unsafe partial dossier is sufficient.

This feature adds a report-only pre-manual-demo review. It verifies the same
signed public dossier and exact v3 operations bundle, requires all nine
pre-manual gates to be accepted, and requires the manual-demo result gate to be
absent because the run has not occurred. It may request a separate human
activation review, but it never authorizes manual-demo, installs a task, reads
a credential, initializes MT5, creates an approval, or sends an order.

## Functional Requirements

- FR-1: The system MUST reconstruct and verify the exact v3 three-service
  operations review bundle, externally pinned RSA trust policy, and signed
  public gate observations using the existing external-acceptance verifier.
- FR-2: The system MUST define the pre-manual gate inventory as every canonical
  `EXTERNAL_READINESS_BLOCKERS` item except
  `MANUAL_DEMO_10_CONTROLLED_ORDERS_REQUIRED`, with neither caller additions
  nor caller omissions.
- FR-3: The system MUST report the external preconditions complete only when
  every pre-manual gate is accepted and the only pending gate is
  `MANUAL_DEMO_10_CONTROLLED_ORDERS_REQUIRED` with reason `MISSING`.
- FR-4: The review MUST bind the exact plan, review bundle, trust policy,
  external assessment, three configured release identities, Git commit/tree,
  candidate, broker server, hashed account alias, account currency, XAUUSD
  broker symbol/specification, decision-IPC binding, and failure-drill
  manifest.
- FR-5: The result MUST set
  `manual_demo_activation_review_required=true` while keeping
  `manual_demo_authorized=false`, `activation_authorized=false`,
  `execution_enabled=false`, `ready_for_demo_auto_soak=false`,
  `safe_to_demo_auto_order=false`, `live_allowed=false`,
  `promotion_eligible=false`, `order_capability=DISABLED`, and
  `max_lot=0.01`.
- FR-6: A full post-manual dossier, a signed manual-demo observation, a failed
  manual-demo observation, or any manual-demo pending reason other than
  `MISSING` MUST be rejected from this pre-run boundary.
- FR-7: Missing, failed, future, expired, or expired-during-verification
  evidence for any pre-manual gate MUST produce a blocked assessment with
  deterministic pending reasons and MUST NOT request manual-demo activation
  review.
- FR-8: The result MUST identify exactly ten controlled manual-demo lifecycles
  as the next evidence target and MUST state that each lifecycle still needs
  separate stage authorization, per-intent human approval, risk, news,
  reconciliation, idempotency, and server-side protection checks.
- FR-9: The command MUST accept only the immutable review bundle, public trust
  policy, signed observation collection, externally pinned policy SHA-256,
  trusted canonical UTC, and an optional create-only output path.
- FR-10: The implementation MUST NOT contain a private-key loader, signature
  issuer, credential provider, provider materializer, scheduler installer,
  environment arm, permit issuer, policy unlock, MT5 adapter, `order_check`,
  `order_send`, or execution coordinator.
- FR-11: Strict public-file handling MUST reject symlink/reparse, irregular,
  empty, oversized, unstable, duplicate-key, non-finite, schema-drifted, or
  secret-like inputs before producing a review.
- FR-12: The new module and command MUST be present only in release-operator
  tooling and MUST be absent from decision, execution, status-monitor,
  read-only shadow, and other production-service allowlists.
- FR-13: Existing full external-acceptance semantics MUST remain unchanged; a
  pre-manual review MUST NOT claim that full external acceptance is complete.

## Non-Functional Requirements

- NFR-1: Identical validated inputs and trusted UTC MUST produce byte-identical
  canonical review payloads and SHA-256 values.
- NFR-2: Every timestamp MUST be timezone-aware UTC and the command MUST require
  canonical text with exactly six fractional digits and `Z`.
- NFR-3: Verification MUST use no network access and MUST perform no write
  unless an explicit output path is supplied.
- NFR-4: Optional output MUST be create-exclusive and MUST never overwrite an
  existing path.
- NFR-5: The focused tests MUST pass under normal Python and
  `PYTHONOPTIMIZE=2`; the complete project regression suite MUST remain green.
- NFR-6: The verifier MUST handle the maximum accepted public dossier within
  two seconds on the development test host, excluding filesystem scheduling
  variance.
- NFR-7: All error outcomes MUST use stable uppercase reason codes and must not
  expose secrets or raw account identifiers.

## Acceptance Criteria

### AC-1: Exact pre-manual dossier requests human review (FR-1, FR-2, FR-3, FR-4, FR-5, FR-8)

Given an exact v3 review bundle and valid signed observations for all nine
pre-manual gates
When the manual-demo entry verifier evaluates the dossier and no manual-demo
result observation exists
Then it reports
`PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS_COMPLETE_ACTIVATION_REVIEW_REQUIRED`
And it binds every exact release, broker, IPC, Git, and failure-drill identity
And every execution and activation flag remains false
And the next evidence target is exactly ten controlled lifecycles.

### AC-2: Missing pre-manual evidence remains blocked (FR-2, FR-7)

Given one or more pre-manual gate observations are absent
When the verifier evaluates the dossier
Then it reports `BLOCKED_PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS`
And it lists each pending pre-manual gate and deterministic reason
And `manual_demo_activation_review_required` is false.

### AC-3: Failed or stale pre-manual evidence remains blocked (FR-7)

Given a pre-manual observation is signed but failed, future, not yet valid,
expired, or expires during verification
When the verifier evaluates the dossier
Then the corresponding gate remains pending with the existing external
acceptance reason
And no manual-demo activation review is requested.

### AC-4: Full post-manual dossier uses the later boundary (FR-6, FR-13)

Given all ten external acceptance gates are accepted
When the pre-manual verifier evaluates the dossier
Then it rejects with `MANUAL_DEMO_RESULT_ALREADY_PRESENT`
And it does not reinterpret full external acceptance as pre-run evidence.

### AC-5: Manual-demo observation variants are rejected (FR-6)

Given the observation collection contains any observation for
`MANUAL_DEMO_10_CONTROLLED_ORDERS_REQUIRED`
When the pre-manual verifier evaluates the dossier
Then it rejects with `MANUAL_DEMO_RESULT_OBSERVATION_NOT_ALLOWED`
regardless of signed outcome or current validity.

### AC-6: Identity drift is rejected (FR-1, FR-4, FR-11)

Given a review bundle, policy, observation, or reconstructed plan has a
different plan, bundle, release, Git, account, server, symbol, IPC, or
failure-drill binding
When verification occurs
Then it rejects with the existing or pre-manual deterministic binding error
And no output file is created.

### AC-7: CLI output is immutable and deny-only (FR-5, FR-9, NFR-2, NFR-3, NFR-4)

Given a valid pre-manual dossier and canonical trusted UTC
When the command is run with a new output path
Then it writes exactly one canonical review
And a repeated run to the same path fails without changing the file
And the output contains no raw account or secret material.

### AC-8: Unsafe files and schemas are rejected (FR-11)

Given any public input is a symlink/reparse point, irregular, empty, oversized,
unstable, duplicate-key, non-finite, schema-drifted, or secret-like document
When the command reads the input
Then it exits non-zero with a deterministic rejection
And no assessment is produced.

### AC-9: No mutation surface exists (FR-10, FR-12)

Given the module, command, imports, arguments, and release allowlists
When static safety tests inspect them
Then no signing, secret, provider, scheduler-mutation, MT5, broker-order,
permit, arm, or policy-unlock surface exists
And the files appear only in operator tooling.

### AC-10: Regression and optimized behavior remain safe (FR-13, NFR-1, NFR-5, NFR-6)

Given the completed implementation
When focused, integration, optimized, compilation, release-policy, and full
regression checks run
Then all tests pass
And repeated valid assessment completes within the measurable threshold
And all checked-in execution locks remain unchanged.

## Edge Cases

- EC-1: The manual-demo result gate is missing while a pre-manual gate is also
  missing → return blocked; do not request activation review.
- EC-2: The manual-demo result gate has a signed `FAILED` outcome → reject the
  pre-run boundary because a result observation already exists.
- EC-3: The manual-demo result gate has a signed but expired `PASSED` outcome →
  reject the pre-run boundary; do not silently treat it as absent.
- EC-4: The external assessment reports a manual-demo reason other than
  `MISSING` without an observation hash → reject inconsistent provenance.
- EC-5: The trust policy or any observation is subclassed, forged, or bypasses
  the exact external verifier → reject exact-type, signature, or binding
  checks before deriving the pre-manual review.
- EC-6: XAUUSD is absent, duplicated, or accompanied by another canonical
  symbol in the plan → the existing v3 plan reconstruction rejects it.
- EC-7: Account alias is the all-zero SHA-256 or a raw login-like value appears
  in a public input → reject before rendering.
- EC-8: Trusted time regresses between the existing external verification
  clock reads → reject with `TRUSTED_CLOCK_REGRESSION`.
- EC-9: Trusted time is exactly an observation expiry → treat that
  pre-manual gate as expired and remain blocked.
- EC-10: Output already exists or is unsafe → fail create-only without
  modifying it.

## API Contracts

No HTTP or network API is introduced. The Python contract is:

```python
def assess_windows_manual_demo_entry_review(
    *,
    review_bundle: Mapping[str, object],
    trust_policy: ThreeServiceAcceptanceTrustPolicy,
    observations: Sequence[ThreeServiceAcceptanceObservation],
    expected_policy_sha256: str,
    clock_provider: Callable[[], datetime],
) -> WindowsManualDemoEntryReview: ...
```

The command contract is:

```text
python -B verify_windows_manual_demo_entry_review.py \
  --review-bundle <immutable-v3-review.json> \
  --trust-policy <public-policy.json> \
  --observations <signed-observations.json> \
  --expected-policy-sha256 <independently-pinned-sha256> \
  --checked-at-utc <YYYY-MM-DDTHH:MM:SS.ffffffZ> \
  [--output <new-json-path>]
```

The command MUST NOT accept account login, password, secret, private key,
signature, terminal path, volume, permit, approval, arm, task-install, provider
module, or execution arguments.

## Data Models

### `WindowsManualDemoEntryReview`

| Field | Type | Constraints |
|---|---|---|
| `plan_sha256` | SHA-256 | Exact reconstructed v3 plan |
| `review_bundle_sha256` | SHA-256 | Exact immutable v3 review bundle |
| `trust_policy_sha256` | SHA-256 | Exact externally pinned public policy |
| `external_assessment_sha256` | SHA-256 | Exact deny-only external assessment |
| `checked_at_utc` | UTC datetime | Inherited trusted assessment time |
| `decision_release_identity_sha256` | SHA-256 | Exact configured decision release |
| `execution_release_identity_sha256` | SHA-256 | Exact configured execution release |
| `status_monitor_release_identity_sha256` | SHA-256 | Exact configured monitor release |
| `git_commit` | 40-char hex | Exact clean source commit |
| `git_tree` | 40-char hex | Exact source tree |
| `candidate_id` | string | Exact reviewed candidate |
| `broker_server` | string | Exact reviewed DEMO server |
| `account_alias_sha256` | SHA-256 | Hashed account alias; raw login prohibited |
| `account_currency` | ISO-like string | Exactly three uppercase letters |
| `canonical_symbol` | enum | Exactly `XAUUSD` |
| `broker_symbol` | string | Exact reviewed broker symbol |
| `broker_specification_sha256` | SHA-256 | Exact XAUUSD specification |
| `decision_ipc_binding_sha256` | SHA-256 | Exact reviewed IPC binding |
| `failure_drill_manifest_sha256` | SHA-256 | Exact v3 drill manifest |
| `accepted_pre_manual_gates` | tuple[string] | Exact nine-gate inventory when complete |
| `pending_pre_manual_gates` | tuple[string] | Sorted incomplete pre-manual gates |
| `pending_reasons` | mapping | One deterministic reason per pending gate |
| `manual_demo_result_gate` | enum | Fixed result-gate code |
| `target_controlled_lifecycles` | integer | Exactly `10` |
| `required_per_intent_controls` | tuple[string] | Exact fixed downstream controls |
| `status` | enum | Complete-review-required or blocked |
| `external_preconditions_complete` | bool | Derived from the nine-gate partition |
| `manual_demo_activation_review_required` | bool | True only for exact complete pre-run state |
| safety fields | fixed | Every authority/execution/live/demo-auto flag false, capability disabled, lot `0.01` |

No persistent database model is added. The optional JSON output is immutable
review evidence only.

## Out of Scope

- OS-1: Issuing or validating the short-lived `ManualDemoReadinessReceipt`,
  stage authorization, per-intent human approval, permit, or environment arm;
  these remain separate trust authorities.
- OS-2: Enabling `manual_demo_enabled`, `SAFE_TO_DEMO_AUTO_ORDER`, or
  `LIVE_ALLOWED`; this feature only requests a later human review.
- OS-3: Installing or launching any Windows task or process.
- OS-4: Materializing external providers, resolving Credential Manager
  references, or accessing private signing material.
- OS-5: Initializing MT5 or checking, sending, modifying, cancelling, or
  closing broker orders or positions.
- OS-6: Recording the ten manual-demo lifecycles; the existing signed tracker
  owns that post-activation evidence.
- OS-7: Replacing full external acceptance after the ten lifecycles or
  authorizing demo-auto soak.
- OS-8: Changing the XAUUSD-only initial demo-auto scope, maximum lot, risk
  caps, statistical gates, or live rollout order.
