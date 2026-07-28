# Live Canary Prebootstrap Admission v1

**Author:** OpenAI Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved for implementation
**Reviewers:** senior architecture, security, and ship-gate

## Context

AI_SCALPER has a replay-protected, deny-only XAUUSD live-canary activation
evidence boundary. It authenticates an eligible demo-auto cohort, LIVE
promotion evidence, nine external gate receipts, three role-separated human
approvals, and one deployment signature. A successful validation is consumed
exactly once, but it does not yet bind a complete non-secret Windows runtime
candidate or the verified Execution source lineage used during demo.

The existing Windows Execution source-bound candidate is deliberately a DEMO
artifact. It must not be relabeled as a LIVE configuration. This feature adds
one pure-data prebootstrap boundary that:

1. validates a complete, immutable LIVE runtime candidate while keeping every
   execution lock false;
2. binds that candidate to the exact sealed DEMO Execution source-bound
   verification and champion lineage;
3. binds the candidate to the exact activation authorization and its already
   consumed verifier-sealed validation; and
4. emits a sealed deny-only admission report suitable for a later,
   separately reviewed Windows bootstrap release.

The admission is not an execution permit. It cannot initialize MT5, access a
credential, import a provider, create a process, mutate Task Scheduler, open a
network connection, or submit an order. The checked-in central LIVE lock must
remain false for this v1 boundary to succeed.

## Functional Requirements

- FR-1: `LiveCanaryRuntimeCandidate` MUST be an immutable canonical contract
  with exact candidate, broker, account, Windows path, source ancestry,
  journal, dependency, installed-environment, MT5 distribution, release,
  champion, symbol, runtime-control, and trust-domain fields.
- FR-2: The candidate MUST require `environment=LIVE`, `mode=LIVE`, exactly one
  `XAUUSD` symbol mapping, `max_lot=0.01`, and
  `max_concurrent_positions=1`.
- FR-3: The candidate MUST retain `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `execution_authorized=false`,
  `activation_authorized=false`, and `order_capability=DISABLED`.
- FR-4: All SHA-256 pins MUST be exact non-zero lowercase 64-character
  hexadecimal values. Git commit/tree pins MUST be exact non-zero lowercase
  40-character hexadecimal values. IDs and paths MUST be non-empty,
  canonical, and bounded.
- FR-5: The journal, supervisor, and dependency-lock paths MUST be absolute,
  pairwise appropriate, and the dependency-lock basename MUST be
  `pylock.windows-cp312.toml`. The canonical and broker symbols MUST be
  unique and the v1 inventory MUST contain only XAUUSD.
- FR-6: Credential-session, journal-provisioning, WORM-audit, supervisor,
  supervisor-checkpoint, risk-ledger, journal-checkpoint, and news-guard key
  IDs MUST be distinct. Their fingerprints plus the permit-secret
  fingerprint MUST also be distinct.
- FR-7: Admission MUST require an exact verifier-sealed
  `WindowsExecutionSourceBoundCandidateVerification`; direct construction,
  duck typing, and an unsealed lookalike MUST be rejected.
- FR-8: The candidate's DEMO source ancestry MUST exactly match the sealed
  source-bound archive, source identity, production-config source,
  bootstrap/stage bindings, configured release, base-suite role, Git
  commit/tree, model, and champion pins.
- FR-9: Admission MUST require exact `LiveCanaryTrustPolicy`,
  `LiveCanaryActivationAuthorization`, and verifier-sealed
  `LiveCanaryActivationValidation` objects.
- FR-10: Validation MUST be valid, consumed exactly once, empty of reason
  codes, and hash-bind the exact authorization, request, and activation
  binding supplied to admission.
- FR-11: The runtime candidate content SHA-256 MUST equal
  `authorization.request.binding.live_config_sha256`. Candidate account,
  server, journal, commit, dependency lock, broker specification, session
  calendar, runtime profile, release manifest, model, champion, symbol, and
  safety constraints MUST exactly equal the activation binding.
- FR-12: The activation binding policy hash MUST equal the exact trust-policy
  content SHA-256. Runtime key IDs and fingerprints MUST be disjoint from all
  promotion, gate, human-approval, deployment, and replay-checkpoint
  authorities in that policy.
- FR-13: Admission MUST use a caller-supplied trusted UTC clock. Time must be
  monotonic during assessment, cannot predate validation, and must remain
  strictly inside the activation request validity interval.
- FR-14: Admission MUST fail if checked-in `execution_policy.LIVE_ALLOWED` is
  not exactly false or if the policy decision for `LIVE` is anything other
  than denied solely by `LIVE_MODE_LOCKED`.
- FR-15: A successful sealed report MUST bind candidate, source-bound,
  trust-policy, authorization, request, activation binding, and validation
  hashes plus exact commit/tree, symbol, lot, position limit, and check time.
- FR-16: A successful report MUST use status
  `PREBOOTSTRAP_EVIDENCE_COMPLETE_CENTRAL_UNLOCK_REQUIRED` and retain all
  execution and activation fields false with order capability disabled.
- FR-17: Public failures MUST expose a stable uppercase reason code and MUST
  not leak credentials, key material, account identifiers, or tracebacks.
- FR-18: The module MUST contain no provider, credential-store, subprocess,
  socket, HTTP, SQLite, Task Scheduler, MT5 initialization, broker mutation,
  order, permit, or runtime-launch effect.

## Non-Functional Requirements

- NFR-1: Implementation MUST use Python 3.12 standard-library primitives and
  existing immutable project contracts only.
- NFR-2: Canonical serialization MUST use the repository `CanonicalContract`
  rules and must reject booleans where integer or numeric values are expected.
- NFR-3: All validation MUST be deterministic except for the explicit trusted
  clock and MUST be safe under `python -O` / `PYTHONOPTIMIZE=2`.
- NFR-4: Validation MUST not rely on `assert`, caller-selected authority
  hashes, mutable globals other than checking the single central lock, or
  private verifier seals copied into this module.
- NFR-5: Focused tests MUST run without Windows, MT5, network, credentials,
  providers, scheduler privileges, or broker access.
- NFR-6: Existing full repository tests MUST remain green in normal and
  optimized modes.

## Acceptance Criteria

### AC-1: Exact complete candidate is canonical and deny-only (FR-1, FR-2, FR-3, FR-4, FR-5, FR-6)

Given a complete XAUUSD LIVE runtime candidate
When it is constructed
Then its canonical hash is stable
And all safety/authority values remain disabled.

### AC-2: Sealed DEMO source ancestry is mandatory (FR-7, FR-8)

Given one independently verified Windows Execution source-bound candidate
When prebootstrap admission is assessed
Then every DEMO source, suite, configured-release, Git, model, and champion
pin is matched exactly
And an unsealed, substituted, or mismatched result is rejected.

### AC-3: One-use activation validation is bound exactly (FR-9, FR-10)

Given one valid activation authorization and its successful consumed
validation
When admission is assessed
Then authorization, request, binding, validation, and policy hashes match
exactly
And an invalid, replayed, forged, or cross-request validation is rejected.

### AC-4: LIVE candidate matches activation scope (FR-11)

Given a candidate and activation binding
When account, server, journal, release, runtime, dependency, broker, calendar,
model, champion, symbol, lot, or position scope differs
Then admission fails closed with a stable reason code.

### AC-5: Trust-domain separation remains complete (FR-12)

Given runtime trust keys and activation authority keys
When any key ID or fingerprint is reused across those boundaries
Then construction or admission rejects the candidate.

### AC-6: Trusted-time window is exact (FR-13)

Given a valid consumed validation
When assessment runs before validation, at/after request expiry, with a
non-UTC time, or across a regressing clock
Then no admission report is emitted.

### AC-7: Checked-in LIVE lock is still required (FR-14)

Given all external evidence is otherwise valid
When the central LIVE lock is not exactly false or its policy decision drifts
Then prebootstrap admission fails rather than granting authority.

### AC-8: Successful report remains non-authoritative (FR-15, FR-16, FR-17)

Given every exact input passes
When the report is emitted
Then it states that central unlock is still required
And `live_allowed`, `execution_authorized`, `activation_authorized`, and
`bootstrap_authorized` remain false with `order_capability=DISABLED`.

### AC-9: Effects and optimized-mode regression (FR-18; NFR-1 through NFR-6)

Given success and rejection paths
When focused, related, and full tests run normally and with optimization
Then results are equivalent
And static inspection finds no forbidden runtime or broker effect surface.

## Edge Cases

- EC-1: Zero/malformed hash, mixed-case Git SHA, blank ID, relative path, or
  wrong dependency-lock filename -> reject.
- EC-2: Journal and supervisor database paths are the same -> reject.
- EC-3: Duplicate symbol or trust-domain identity -> reject.
- EC-4: EURUSD, BTCUSD, multiple symbols, lot above/below 0.01, or more than
  one position -> reject.
- EC-5: Source-bound result belongs to another suite, release, source,
  champion, commit, or tree -> reject.
- EC-6: Validation is valid-looking but not verifier sealed -> reject.
- EC-7: Validation was consumed for another authorization or request ->
  reject.
- EC-8: Runtime candidate hash differs by one field from the activation's
  `live_config_sha256` -> reject.
- EC-9: Candidate reuses the deployment key or any gate/approval authority
  fingerprint -> reject.
- EC-10: Assessment starts inside the window but completes at expiry ->
  reject.
- EC-11: Checked-in LIVE policy unexpectedly becomes enabled -> this deny-only
  v1 boundary rejects and requires a new reviewed runtime gate.

## Data Models

`LiveCanaryRuntimeCandidate` is an immutable canonical value. Its identity is
the SHA-256 of all non-secret runtime inputs, source ancestry, trust-domain
pins, safety values, and schema version. It intentionally does not contain a
password, account login, private key, activation authorization, or its own
content hash.

`LiveCanaryPrebootstrapAdmission` is verifier-sealed. Its identity includes
all upstream content hashes and exact runtime scope, so replacing any
candidate, activation, validation, policy, source-bound artifact, commit,
tree, symbol, lot, position limit, or check time changes the report hash.

The relationship is:

```text
sealed DEMO source-bound verification ---+
                                          +--> sealed deny-only admission
LIVE runtime candidate -------------------+
                                          |
policy + authorization + validation ------+
```

No model contains a mutable execution flag. All authority fields are fixed
constructor-disabled values.

| Model | Field group | Type | Constraints |
| --- | --- | --- | --- |
| `LiveCanaryRuntimeCandidate` | identity and broker | strings | non-empty canonical IDs; LIVE server/account only |
| `LiveCanaryRuntimeCandidate` | source and release pins | SHA-256/Git SHA strings | exact lowercase, non-zero, source-bound matched |
| `LiveCanaryRuntimeCandidate` | paths and symbol map | strings/tuples | absolute paths; one unique XAUUSD mapping |
| `LiveCanaryRuntimeCandidate` | runtime limits | integers/floats | lot 0.01; one position; bounded tick/intent values |
| `LiveCanaryRuntimeCandidate` | trust inventory | IDs/fingerprints | exact, complete, and pairwise distinct |
| `LiveCanaryRuntimeCandidate` | safety | bool/string | all false; `DISABLED` capability |
| `LiveCanaryPrebootstrapAdmission` | upstream bindings | SHA-256 strings | exact candidate/source/policy/auth/request/validation hashes |
| `LiveCanaryPrebootstrapAdmission` | checked time | UTC datetime | monotonic and inside activation window |
| `LiveCanaryPrebootstrapAdmission` | status and safety | string/bool | central unlock required; no authority granted |

## API Contracts

HTTP API: N/A. The documentation-only validator marker
`GET /not-applicable` MUST NOT be implemented or exposed.

```python
@dataclass(frozen=True)
class LiveCanaryRuntimeCandidate(CanonicalContract):
    # Complete non-secret candidate and exact ancestry fields.
    ...

@dataclass(frozen=True)
class LiveCanaryPrebootstrapAdmission(CanonicalContract):
    candidate_sha256: str
    source_bound_sha256: str
    authorization_sha256: str
    validation_sha256: str
    checked_at: datetime
    status: str
    bootstrap_authorized: bool = False
    live_allowed: bool = False
    execution_authorized: bool = False
    activation_authorized: bool = False
    order_capability: str = "DISABLED"

def assess_live_canary_prebootstrap_admission(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    source_bound_verification: WindowsExecutionSourceBoundCandidateVerification,
    trust_policy: LiveCanaryTrustPolicy,
    authorization: LiveCanaryActivationAuthorization,
    validation: LiveCanaryActivationValidation,
    clock_provider: Callable[[], datetime],
) -> LiveCanaryPrebootstrapAdmission:
    """Return sealed deny-only evidence or fail with a stable reason code."""
```

## Out of Scope

- OS-1: Changing `execution_policy.LIVE_ALLOWED` or any release lock.
- OS-2: Constructing an effect-capable `ProductionRuntimeConfig` for LIVE.
- OS-3: Issuing an execution permit, stage authorization, credential session, or
  runtime launcher receipt.
- OS-4: Reading Windows Credential Manager, private keys, or broker credentials.
- OS-5: Importing/materializing MetaTrader5 or another provider.
- OS-6: Installing/starting a task, service, process, or watchdog.
- OS-7: Opening a journal, supervisor, replay, or risk SQLite database.
- OS-8: Accessing the network, reconciling a broker account, or submitting an order.
- OS-9: Claiming that actual XM evidence, approvals, Windows custody, soak duration,
  or live-trading readiness exists.
- OS-10: Pair expansion, lot scaling, or post-canary fifty-trade promotion.

## Assumptions

- The existing activation validation is produced only by
  `validate_and_consume_live_canary_activation` and therefore represents one
  atomic replay-registry consumption.
- Windows Execution source-bound v1 remains a DEMO lineage artifact and is
  used only as immutable ancestry, never relabeled as LIVE.
- A later separately specified boundary will authenticate portable Windows
  admission custody, revalidate mutable runtime heads, consume a distinct
  launch capability, and make any reviewed central-lock change.

## Risks and Mitigations

- **Risk:** A valid activation validation is reused as an execution permit.
  **Mitigation:** this report has no authority fields, contains no effect
  primitives, and succeeds only while the central LIVE lock is false.
- **Risk:** Caller supplies unrelated Windows provenance.
  **Mitigation:** require the exact verifier-sealed source-bound object and
  compare every exposed ancestry pin.
- **Risk:** Runtime keys reuse activation authority material.
  **Mitigation:** enforce key-ID and fingerprint disjointness across both
  inventories.
- **Risk:** Evidence expires between validation and admission.
  **Mitigation:** require start and completion inside the original activation
  request interval using a monotonic trusted UTC clock.
- **Risk:** Local tests are mistaken for broker readiness.
  **Mitigation:** documentation and report status explicitly require central
  unlock and retain every broker/execution capability as disabled.

## Open Questions

- Which independent Windows authority will sign and retain the portable
  prebootstrap admission in WORM storage?
- Which production release will introduce the one-use launch-capability
  registry and controlled central-lock ceremony?
- What exact XM LIVE server/account/broker-symbol facts will replace synthetic
  test fixtures after the 30-day/50-fill/20-XAU demo-auto cohort completes?
