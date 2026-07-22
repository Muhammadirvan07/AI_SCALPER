# Stage Readiness Authorization v1

Status: implemented, deny-only evidence boundary

Module: `live_runtime/stage_authorization.py`

Execution capability: **none**

## Purpose

This contract seals the evidence needed to review two future stage changes:

1. `MANUAL_DEMO`: controlled human-approved demo orders; and
2. `DEMO_AUTO`: unattended demo execution after the manual-demo acceptance
   run is complete.

It is not a broker permit, environment arm, order token, or runtime mode
switch. A valid result only means that a short-lived evidence package was
authenticated, matched the exact reviewed binding, approved by two distinct
humans, and consumed once. Every artifact and result keeps:

```text
execution_authorized = false
activation_authorized = false
safe_to_demo_auto_order = false
live_allowed = false
order_capability = "DISABLED"
```

No class in this module imports an MT5 client, sends an order, changes an
environment variable, modifies executor policy, or resets a kill switch.

## Trust boundaries

Separate trust roles and key IDs are defined for:

- manual-demo global readiness;
- the manual-demo aggregate (DEMO_AUTO only);
- promotion evidence (DEMO_AUTO only, existing promotion-evidence key);
- one separately allowlisted authority key for each automated acceptance
  domain (`RUNTIME`, `PARITY`, `SECURITY`, and `FAILURE_DRILL`);
- each human approver;
- the final stage authority; and
- the durable replay registry.

Production key policy must provision different secrets for these roles; the
module additionally proves that the two human approver key IDs do not alias
the same key material. HMAC keys contain at least 32 bytes. Key IDs may be
serialized; key material may not. HMAC messages are domain-separated:

```text
AI_SCALPER:MANUAL_DEMO_GLOBAL_READINESS:v1
AI_SCALPER:MANUAL_DEMO_AGGREGATE:v1
AI_SCALPER:STAGE_ACCEPTANCE_AUTHORITY:v1\n<DOMAIN>\n
AI_SCALPER:STAGE_READINESS_HUMAN_APPROVAL:v1
AI_SCALPER:STAGE_READINESS_AUTHORIZATION:v1
AI_SCALPER:STAGE_READINESS_REPLAY:v1
AI_SCALPER:STAGE_READINESS_REPLAY_CHECKPOINT:v1
```

Raw broker account values and raw human identities are prohibited. The
artifacts contain only `account_alias_sha256` and
`approver_identity_sha256`. Broker server is retained because exact server
binding is an operational control, not a credential.

## Exact stage binding

`StageBinding` is frozen and content-addressed. It requires:

| Field | Rule |
|---|---|
| `broker_id` | exact reviewed candidate identifier |
| `account_alias_sha256` | non-zero SHA-256; raw account prohibited |
| `server` | exact reviewed server |
| `environment` | exactly `DEMO` |
| `symbol` | canonical uppercase symbol |
| `strategy` | canonical uppercase strategy |
| `lane_id` | exactly `symbol:strategy:config_sha256` |
| `journal_sha256` | exact execution-journal binding |
| `commit_sha` | 7–64 lowercase hexadecimal characters |
| `config_sha256` | exact configuration hash |
| `dependency_lock_sha256` | exact dependency lock hash |
| `broker_spec_sha256` | exact canonical broker symbol specification hash |
| `session_calendar_sha256` | exact reviewed session/holiday calendar hash |
| `evidence_contract_sha256` | exact registered forward-evidence contract hash |
| `broker_profile_sha256` | exact broker profile hash |
| `runtime_profile_sha256` | exact runtime profile hash |
| `model_artifact_sha256` | exact frozen model hash |
| `acceptance_authority_policy_sha256` | exact immutable per-domain authority-key allowlist hash |
| `manual_demo_custodian_trust_sha256` | exact external manual-demo high-water custodian-key policy hash |

All 64-character hashes reject the all-zero sentinel. Any drift creates a new
binding and invalidates every old request, approval, and authorization.

## MANUAL_DEMO prerequisites

`ManualDemoReadinessReceipt` is an independent five-minute HMAC receipt bound
to the exact `StageBinding`. It requires non-zero receipt hashes for all of:

- `LEGAL`;
- `CLEAN_RELEASE`;
- `NEWS`;
- `WINDOWS`;
- `FAILURE_DRILL`;
- `SECURITY`;
- `RISK`; and
- `RECONCILIATION`.

It also binds the source validation receipt used by the readiness authority.
The final stage signer sees only content hashes; the independent source
validators remain responsible for their underlying evidence. Missing gates,
duplicate gates, unknown gates, a bad signature, a wrong binding, an expired
receipt, or a receipt that expires before the stage request all fail closed.

MANUAL_DEMO explicitly rejects tracker, promotion, and automated-runtime
claims. Those facts cannot exist until controlled manual execution has run.

## Additional DEMO_AUTO prerequisites

DEMO_AUTO requires all MANUAL_DEMO prerequisites plus the following.

### Manual-demo aggregate

`ManualDemoAggregateReceipt` is HMAC-signed and bound to account hash, server,
journal, commit, config, and lane. It binds the verified tracker head,
assessment hash, event count, and assessment time. Construction and
verification require:

- at least 10 clean completed controlled lifecycles;
- a non-empty contiguous tracker (`head_sequence == total_events`);
- `criteria_observed == true`;
- `failed_latched == false`;
- zero critical incidents;
- zero orphan positions;
- zero orphan orders; and
- zero unexplained positions.

Its maximum lifetime is 15 minutes, the assessment may not be more than 15
minutes old at issuance, and it must remain valid through stage expiry.
`issue_manual_demo_aggregate_receipt()` requires both the latest sealed
`ManualDemoAssessmentReceipt` and an exact `ManualDemoCustodyCheckpoint`
retrieved through an injected external high-water provider. The custody
checkpoint is signed by a configured custodian key whose ID and material must
be distinct from the local tracker key. Its trusted key fingerprint policy is
hashed into the aggregate. The issuer authenticates both receipts and requires
their tracker ID, binding, content hash, HMAC, sequence, head, and timestamps to
match the durable tracker's current head. An omitted checkpoint, a caller-local
checkpoint, an untrusted or reused key, a valid historical prefix, a tampered
receipt, rollback, fork, or coherently restored old database fails closed. The
aggregate permanently binds `external_custody_checkpoint_sha256` and
`custodian_trust_sha256` in addition to the tracker head and assessment. It
must equal `StageBinding.manual_demo_custodian_trust_sha256`; it also refuses a
failed or incomplete tracker.

### Promotion and acceptance evidence

The actual `PromotionEvidenceReceipt`, not just a caller-supplied boolean, is
required. The verifier authenticates its independent key and requires:

- mode `DEMO_AUTO`;
- exact account, server, journal, symbol, strategy, lane, commit, config, and
  model binding;
- exact content hash referenced by the stage request;
- exact evidence-store receipt reference; and
- exact parity receipt reference.

Four exact sealed `AcceptanceAuthorityReceipt` values are required exactly
once:

- `RUNTIME`;
- `PARITY`;
- `SECURITY`; and
- `FAILURE_DRILL`.

Each binds the exact stage binding, source evidence receipt hash, independent
validation receipt hash, authority key ID, acceptance UTC, and expiry UTC. The
receipt is constructor-sealed and HMAC-signed under a domain-separated key.
`AcceptanceAuthorityTrustPolicy` maps every domain to a non-empty, immutable
allowlist of key ID plus SHA-256 key-material fingerprint; neither an ID nor a
fingerprint may be reused across domains. The policy hash is part of
`StageBinding`, and both receipt issuance and consumption require provider key
material to match the bound fingerprint. Receipts may live for at most 30 days and
must cover the complete five-minute stage window. The `PARITY` evidence receipt
must equal the runtime-parity receipt sealed in the promotion evidence. Random
hash lookalikes, wrong-domain keys, wrong policy/binding, signature/content
tamper, and stale receipts fail both issuance and consumption.

## Dual human approval

The exact canonical `StageReadinessRequest` digest is approved by exactly two
`HumanApprovalAttestation` values. The approvers must have:

- distinct hashed identities;
- distinct signing key IDs;
- distinct signing-key material (different IDs may not alias one key);
- distinct roles;
- distinct approval nonces;
- valid HMAC signatures; and
- approval UTC inside the request window and not in the verifier's future.

The decision is fixed to `APPROVE_STAGE_ELIGIBILITY_REVIEW`. It does not approve
an order. Human names and email addresses never enter the artifact.

## Time and lifetime

Every time is timezone-aware UTC with offset zero. Naive or non-UTC datetimes
are rejected. `StageReadinessRequest` lifetime is positive and no greater than
five minutes. The final authorization inherits that window; it cannot extend
any input receipt. Validation uses a caller-supplied trusted UTC observation
and rejects not-yet-valid and expired data.

## Issuance

`issue_stage_readiness_authorization()` performs all applicable checks before
the stage authority signs:

1. exact request schema and time window;
2. signed global readiness and exact binding;
3. for DEMO_AUTO, clean signed manual tracker aggregate;
4. for DEMO_AUTO, signed exact promotion/evidence/parity binding;
5. fresh signed authority receipts under the exact bound per-domain trust policy;
6. two distinct valid human approvals; and
7. fixed deny-only fields.

Issuance raises `StageAuthorizationError` on any failed prerequisite. The
returned `StageReadinessAuthorization` remains evidence only.

## Validation and one-use consumption

`validate_and_consume_stage_readiness_authorization()` re-verifies every input
against a fresh `expected_binding` and explicit `expected_mode`; issuance is
not trusted merely because it occurred earlier. A MANUAL_DEMO artifact cannot
be substituted at a DEMO_AUTO boundary. If all checks pass, it atomically
consumes both:

- `authorization_id`; and
- `SHA256(request.nonce)`.

`StageAuthorizationReplayRegistry` uses SQLite WAL, `synchronous=FULL`, exact
schema/DDL/trigger verification, append-only event triggers, a contiguous hash
chain, per-event domain-separated HMAC, and a verified head. Its immutable
binding includes an exact `registry_id`, key ID, and SHA-256 fingerprint of the
high-entropy registry key. Authorization ID and nonce hash are independently
unique. A restart retains replay state. A second validation returns
`STAGE_AUTHORIZATION_REPLAYED` and is invalid.

The registry rejects partial schemas, DDL/trigger changes, sequence gaps,
chain changes, event changes, head changes, wrong key IDs, wrong HMAC keys, and
non-canonical UTC. A caller must treat `StageAuthorizationIntegrityError` as a
critical fail-closed condition.

`create_checkpoint()` emits a separately domain-separated HMAC
`StageReplayCheckpoint`. A signed `GENESIS` checkpoint anchors the empty registry
before the first production-runtime consumption; its count is zero, head/last
nonce are the zero hash, and ordered authorization/nonce digests are the canonical
empty-tuple digests. A non-genesis checkpoint binds registry identity,
registry key identity/fingerprint, event count, head, ordered authorization-ID
digest, ordered nonce-hash digest, and the last authorization/nonce. The
checkpoint is intended for the existing off-host immutable custody path.

On reopen, `expected_checkpoint` and its key provider must be supplied
together. The registry authenticates the checkpoint and requires its current
count to be at least the external high-water count. It then recomputes the
exact historical prefix at that sequence. A lower count is rollback; an equal
or longer chain with a different prefix is fork/rewrite. Both fail closed.
Thus deletion/recreation and full valid-file rollback are detected whenever
the last externally held checkpoint is supplied. Omitting the external
checkpoint deliberately forfeits that cross-file rollback guarantee and is
not acceptable for a production stage transition.

`verify_checkpoint(..., require_current=True)` additionally rejects a valid
historical prefix. The production supervisor uses this strict form both before
consumption and after it creates the new checkpoint, and requires the event count
to advance by exactly one with the authorization ID as the new tail.

## Validation result

`StageAuthorizationValidation` is constructor-sealed. A valid result requires
no reason codes and successful one-use consumption. It may report
`evidence_eligible_for_review=true`, but always reports all execution and
activation flags false. An invalid result is never consumed unless the only
failure is replay, in which case the prior consumption remains authoritative.

## Production-supervisor integration

This module is not wired directly as an executor permit. The separately reviewed
`live_runtime.runtime_supervisor` integration now:

1. consumes the exact sealed `MANUAL_DEMO` validation once at `DEMO` startup,
   before any per-intent manual approval is considered;
2. has an explicit `DEMO_AUTO` stage port, while the unchanged policy constant
   still hard-denies that mode before consumption;
3. re-checks account/server/environment/build/profile/runtime facts at the
   transition boundary;
4. preserves environment arm, permit, risk-governor, news, reconciliation,
   kill-switch, and order idempotency checks;
5. atomically persists the authorization ID/hash, sealed validation hash, prior
   external checkpoint hash, and new checkpoint hash in its HMAC-chained startup
   receipt;
6. requires a signed external checkpoint to equal the current registry head and
   creates a signed new head for off-host export before readiness; and
7. keeps LIVE as a separate, still-unimplemented promotion stage.

These artifacts still cannot change runtime mode and cannot submit an order.
`StageAuthorizationValidation` remains deny-only; runtime mode is an independent
reviewed binding and every manual demo order still needs its separate per-intent
approval, risk, reconciliation, news, health, and idempotency gates.

## Acceptance tests

The test suite covers:

- valid MANUAL_DEMO evidence that still has no capability;
- valid DEMO_AUTO evidence that still has no capability;
- missing readiness, tracker, promotion, and acceptance evidence;
- random-hash acceptance forgeries, wrong domain/key/policy/binding, authority
  signature/content tamper, and stale authority receipts;
- omitted, historical-prefix, or tampered externally-custodied manual tracker
  checkpoints;
- fewer than ten clean manual lifecycles and critical incidents;
- exact binding and parity mismatches;
- missing global and automated acceptance gates;
- wrong, tampered, duplicate, or future human approvals;
- tampered final/manual/promotion signatures;
- naive UTC, stale receipts, expiry, and TTL overflow;
- serialization without raw accounts/human identities;
- constructor sealing;
- restart-safe replay rejection;
- signed high-water restart and monotonic extension;
- full database rollback and equal-height fork detection;
- checkpoint signature, registry identity, and key-fingerprint binding;
- replay-registry schema/trigger tamper; and
- wrong replay HMAC key.
