# Live Canary Portable Launch Custody v1

**Author:** OpenAI Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved for implementation
**Reviewers:** senior architecture, security, and ship-gate

## Context

AI_SCALPER now has a sealed, deny-only live-canary prebootstrap admission. It
binds an exact non-secret LIVE candidate, the verified DEMO Execution source
ancestry, the externally approved activation, and its one-use validation. The
report deliberately stops before Windows custody, launcher reservation,
process creation, credential access, MT5 initialization, or broker mutation.

The next boundary must solve two different problems without weakening that
separation:

1. prove that the exact canonical admission bytes were read back from an
   independently controlled WORM object under an externally pinned RSA key;
2. atomically reserve the exact short-lived external launcher nonce once in an
   independent off-host CAS ledger; and
3. return a sealed launch prerequisite that still cannot start a process or
   authorize execution while the checked-in central LIVE lock is false.

The Windows host receives public policy data and signed canonical JSON only.
Private keys remain outside the repository and runtime host. External object
readback and CAS are supplied as narrow callbacks so the verifier is portable
across Windows storage providers without embedding an HTTP client, cloud SDK,
credential manager, or provider-specific implementation.

## Functional Requirements

- FR-1: `LiveCanaryPortableCustodyPolicy` MUST pin one RSA-3072-or-stronger
  custody authority, WORM repository alias hash, Windows host/service/task
  hashes, exact external launcher-policy hash, minimum retention, receipt age,
  and launch TTL.
- FR-2: The custody RSA key MUST use exponent 65537, canonical lowercase
  modulus encoding, exact public-key fingerprinting, and
  `RSASSA-PKCS1-v1_5-SHA256`.
- FR-3: The policy MUST remain non-authoritative with `live_allowed=false`,
  `execution_authorized=false`, `bootstrap_authorized=false`, and
  `order_capability=DISABLED`.
- FR-4: `LiveCanaryAdmissionCustodyReceipt` MUST bind the exact sealed
  prebootstrap admission, candidate, source-bound verification,
  authorization, validation, canonical object bytes, content length, WORM
  repository/object/version hashes, upload time, compliance retention time,
  policy, issuer, and RSA key.
- FR-5: Admission receipt input MUST be strict canonical UTF-8 JSON with no
  duplicate or unknown keys, bounded size, exact UTC text, and a valid
  domain-separated RSA signature.
- FR-6: Verification MUST call an external object-readback provider with only
  hashed repository/object/version identities and require byte-for-byte
  equality with `admission.canonical_json()`.
- FR-7: Receipt upload MUST not predate admission, be in the future, exceed the
  policy receipt-age limit, or expire its retention before the policy minimum.
- FR-8: `VerifiedLiveCanaryAdmissionCustody` MUST be verifier-sealed, bind all
  receipt/admission/object identities, and retain every authority flag false.
- FR-9: Launch reservation MUST require the exact sealed admission and custody
  verification, exact live candidate, exact activation authorization and
  consumed validation, exact external launcher policy, and exact
  verifier-sealed external launcher attestation.
- FR-10: Custody, launcher, activation, and runtime key IDs/fingerprints MUST
  remain disjoint. Host, service-account, and task hashes MUST match between
  custody and launcher policies.
- FR-11: The launcher attestation release identity MUST equal the candidate's
  exact LIVE release-manifest hash and its nonce MUST be the launch-reservation
  nonce.
- FR-12: Reservation MUST require a caller-supplied trusted UTC clock and
  remain inside both the activation request and launcher-attestation windows.
  The launch TTL MUST not exceed policy and MUST be at most 60 seconds.
- FR-13: The external checkpoint provider MUST return either no head or one
  strict canonical, policy-bound, RSA-authenticated checkpoint. Sequence one
  MUST use the zero predecessor; later sequence MUST increment the verified
  head exactly. The observed head MUST equal a predecessor hash retained and
  supplied through an independent channel; a missing head MUST match an exact
  zero predecessor pin.
- FR-14: Before CAS, the external nonce-seen provider MUST report false. The
  verifier MUST submit the expected predecessor hash plus canonical proposal
  bytes to one external atomic CAS callback.
- FR-15: CAS MUST return one signed checkpoint and one separately signed
  acknowledgement. Both MUST bind the exact proposal, nonce, sequence,
  predecessor, policy, authority, and time window.
- FR-16: After CAS, the external head readback MUST equal the committed
  checkpoint byte-for-byte and the external nonce-seen provider MUST report
  true. Any post-CAS mismatch burns the nonce and fails closed.
- FR-17: A successful `LiveCanaryOneUseLaunchCapability` MUST be sealed and
  state `launch_reservation_consumed_once=true` and
  `launch_prerequisite_verified=true` while retaining
  `central_unlock_required=true`, `process_launch_authorized=false`,
  `bootstrap_authorized=false`, `execution_authorized=false`,
  `live_allowed=false`, and `order_capability=DISABLED`.
- FR-18: Admission and external-launcher verifier outputs MUST expose
  module-owned seal predicates so a direct constructor, duck type, copied
  fields, or `object.__new__` lookalike cannot cross this boundary.
- FR-19: The checked-in `execution_policy.LIVE_ALLOWED` MUST remain exactly
  false and the `LIVE` policy decision MUST remain exactly
  `(False, ("LIVE_MODE_LOCKED",))` throughout verification.
- FR-20: Public failures MUST expose stable uppercase reason codes without
  leaking private keys, raw account identifiers, object locations, or
  provider exceptions.
- FR-21: The module MUST contain no private-key operation, network client,
  cloud SDK, credential store, subprocess, Task Scheduler, MT5 import,
  journal/risk database, process launch, broker mutation, permit issuance, or
  order submission surface.

## Non-Functional Requirements

- NFR-1: Implementation MUST use Python 3.12 standard-library primitives and
  existing immutable contracts only.
- NFR-2: All persisted/interchanged documents MUST use canonical JSON and
  content-addressed SHA-256 identities.
- NFR-3: Signature domains for admission receipt, launch checkpoint, and CAS
  acknowledgement MUST be different.
- NFR-4: Validation MUST not use `assert` and MUST behave identically under
  normal Python and `PYTHONOPTIMIZE=2`.
- NFR-5: External callbacks MUST have bounded, documented data-only
  interfaces. Exceptions MUST be mapped to stable public reason codes.
- NFR-6: Focused tests MUST run without Windows, network, credentials, cloud
  storage, MT5, scheduler privileges, or broker access.
- NFR-7: Related and full repository tests MUST remain green in normal and
  optimized modes.

## Acceptance Criteria

### AC-1: Exact public custody policy is canonical (FR-1, FR-2, FR-3)

Given an independently pinned RSA custody policy
When it is constructed
Then its modulus, exponent, fingerprint, WORM identity, launcher-policy pin,
retention, TTL, and Windows identities are exact
And it grants no runtime authority.

### AC-2: WORM admission bytes are independently authenticated (FR-4, FR-5, FR-6, FR-7, FR-8)

Given the exact sealed prebootstrap admission and one signed custody receipt
When the external object provider returns the stored object
Then the verifier accepts only byte-identical canonical admission JSON under
the expected WORM repository/object/version and retention policy
And returns a sealed deny-only custody verification.

### AC-3: Custody substitution and stale retention fail closed (FR-4, FR-5, FR-6, FR-7, FR-8, FR-20)

Given a wrong admission, candidate, source, authorization, validation, object,
version, signature, upload time, retention time, policy, or RSA key
When custody verification runs
Then it emits no verified custody result and exposes a stable reason code.

### AC-4: Exact launcher trust and key separation are mandatory (FR-9, FR-10, FR-11, FR-12)

Given one verified custody result and external launcher attestation
When candidate/release/host/service/task/nonce differs or a trust identity is
reused
Then launch reservation fails before external CAS.

### AC-5: First external reservation is atomic and one-use (FR-13, FR-14, FR-15, FR-16)

Given an empty external replay ledger and unseen signed launcher nonce
When reservation is consumed
Then the proposal uses sequence one and zero predecessor
And CAS acknowledgement, head readback, and nonce readback all match exactly.

### AC-6: Subsequent reservation extends one verified head (FR-13, FR-14, FR-15, FR-16)

Given a valid current signed checkpoint
When a distinct fresh launcher nonce is reserved
Then sequence increments by one and predecessor equals the current checkpoint
content hash and the independently supplied predecessor pin
And replacing or rolling back that head fails closed.

### AC-7: Replay, race, and post-CAS ambiguity burn safely (FR-14, FR-15, FR-16, FR-17, FR-20)

Given a previously seen nonce, rejected CAS, forged acknowledgement, wrong
readback head, absent nonce readback, expiry during CAS, or clock regression
When reservation runs
Then no capability is emitted and no retry can treat the ambiguous nonce as
unused.

### AC-8: Capability is sealed but non-authoritative (FR-17, FR-18, FR-19)

Given every exact custody and CAS check passes while LIVE remains locked
When a capability is returned
Then it proves only a one-use launch prerequisite
And cannot authorize bootstrap, process launch, execution, credentials, MT5,
broker mutation, or an order.

### AC-9: Static and optimized safety surface remains clean (FR-18, FR-19, FR-20, FR-21; NFR-1 through NFR-7)

Given implementation and rejection paths
When static, focused, related, full, and optimized checks run
Then no forbidden effect primitive exists
And results do not depend on stripped assertions.

## Edge Cases

- EC-1: RSA modulus below 3072 bits, even modulus, exponent other than 65537,
  fingerprint mismatch, or duplicate authority identity -> reject.
- EC-2: Non-canonical JSON, duplicate/unknown key, over-limit document,
  malformed UTC, zero hash, boolean integer, or invalid signature -> reject.
- EC-3: Object readback returns text, empty bytes, extra newline, different
  canonical admission, oversized data, or raises -> reject.
- EC-4: Receipt upload predates admission, is future/stale, retention is short,
  or verification finishes after retention -> reject.
- EC-5: Directly constructed or memory-forged admission, custody verification,
  launcher verification, or launch capability -> reject.
- EC-6: Launcher policy hash, release profile, release identity, host, service,
  task, attestation nonce, or authority overlaps -> reject before CAS.
- EC-7: Existing checkpoint has wrong policy, authority, signature, proposal,
  independently retained predecessor pin, lane binding, sequence, timestamps,
  nonce state, or safety fields -> reject.
- EC-8: CAS returns wrong types, malformed JSON, wrong predecessor, wrong
  sequence, wrong proposal, wrong nonce, or mismatched acknowledgement ->
  reject and treat the nonce as burned.
- EC-9: Clock starts before upstream verification, regresses, or reaches either
  expiry during readback/CAS -> reject.
- EC-10: Central LIVE lock becomes true or its denial reason changes -> reject
  and require a separately reviewed central-unlock implementation.

## Data Models

`LiveCanaryPortableCustodyPolicy` is a public immutable trust root. It contains
only an RSA public key and hashed deployment/storage identities.

`LiveCanaryAdmissionCustodyReceipt` is an externally signed claim that the
exact admission bytes are retained under WORM compliance mode. Its signature
does not grant launch or execution authority.

`VerifiedLiveCanaryAdmissionCustody` is verifier-sealed after RSA validation,
object readback, retention, exact lineage, and trusted-time checks.

`LiveCanaryLaunchReservationProposal` is the canonical data sent to the
external atomic CAS provider. It carries a short expiry and no secret.

`LiveCanaryLaunchReservationCheckpoint` and
`LiveCanaryLaunchReservationAcknowledgement` are separately domain-signed
external documents proving the new head and the compare-and-swap result.

`LiveCanaryOneUseLaunchCapability` is a sealed, short-lived prerequisite. Its
name describes one-use reservation semantics; its fixed safety fields make it
non-authoritative until a later reviewed composition consumes it together with
a legitimate central-unlock ceremony.

| Model | Field group | Type | Constraints |
| --- | --- | --- | --- |
| `LiveCanaryPortableCustodyPolicy` | RSA authority | strings/integer | RSA 3072-8192 bits, exponent 65537, exact fingerprint |
| `LiveCanaryPortableCustodyPolicy` | deployment/storage | SHA-256 strings | exact WORM, host, service, task, and launcher-policy pins |
| `LiveCanaryAdmissionCustodyReceipt` | admission/object | SHA-256/integer | exact admission bytes, non-empty object version, bounded size |
| `LiveCanaryAdmissionCustodyReceipt` | time/retention | UTC datetime | fresh upload and policy-minimum compliance retention |
| `VerifiedLiveCanaryAdmissionCustody` | verification | hashes/bool | verifier-sealed; custody true; all authority false |
| `LiveCanaryLaunchReservationProposal` | CAS lineage | hashes/integer | exact predecessor, monotonic sequence, unique signed nonce |
| `LiveCanaryLaunchReservationCheckpoint` | committed head | proposal/time/signature | exact proposal, bounded commit time, RSA authenticated |
| `LiveCanaryLaunchReservationAcknowledgement` | CAS result | hashes/time/signature | exact predecessor/new head/nonce/sequence, RSA authenticated |
| `LiveCanaryOneUseLaunchCapability` | prerequisite | hashes/time/bool | sealed, short-lived, reserved once, no process/execution authority |

```text
sealed prebootstrap admission
           |
           v
signed WORM receipt -- exact object readback
           |
           v
sealed custody verification
           |
           +-- verified external launcher attestation
           |
           v
proposal -- external atomic CAS --> signed checkpoint + signed ack
                                      |
                                      v
                         sealed one-use launch prerequisite
                         (all execution authority still false)
```

## API Contracts

HTTP API: N/A. The documentation-only validator marker
`GET /not-applicable` MUST NOT be implemented or exposed. External storage/CAS
integration is callback-based; no endpoint or cloud-provider client is
introduced.

```python
def verify_live_canary_admission_custody(
    receipt_payload: bytes,
    *,
    policy: LiveCanaryPortableCustodyPolicy,
    expected_policy_sha256: str,
    admission: LiveCanaryPrebootstrapAdmission,
    object_readback_provider: Callable[[str, str, str], bytes],
    clock_provider: Callable[[], datetime],
) -> VerifiedLiveCanaryAdmissionCustody:
    ...

def consume_live_canary_launch_reservation(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    admission: LiveCanaryPrebootstrapAdmission,
    custody_verification: VerifiedLiveCanaryAdmissionCustody,
    authorization: LiveCanaryActivationAuthorization,
    validation: LiveCanaryActivationValidation,
    custody_policy: LiveCanaryPortableCustodyPolicy,
    expected_custody_policy_sha256: str,
    launcher_policy: ExternalLauncherTrustPolicy,
    launcher_attestation: VerifiedExternalLauncherAttestation,
    external_checkpoint_provider: Callable[[], bytes | None],
    external_checkpoint_cas: Callable[[str, bytes], tuple[bytes, bytes]],
    external_nonce_seen_provider: Callable[[str], bool],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryOneUseLaunchCapability:
    ...
```

Callback payloads contain canonical UTF-8 JSON bytes only. The CAS provider
must atomically reject a stale predecessor or already-seen nonce before it
returns signed checkpoint/acknowledgement bytes.

## Out of Scope

- OS-1: Changing `execution_policy.LIVE_ALLOWED` or any checked-in release lock.
- OS-2: Holding or using an RSA private key on the AI_SCALPER host.
- OS-3: Implementing S3, Azure, GCS, HTTP, network, or credential clients.
- OS-4: Installing/starting Task Scheduler, a service, watchdog, or process.
- OS-5: Building an effect-capable `ProductionRuntimeConfig` for LIVE.
- OS-6: Reading broker credentials, importing MT5, reconciling positions, or
  submitting/modifying/cancelling an order.
- OS-7: Claiming actual WORM retention, external CAS, XM evidence, launcher
  issuance, host ACL, task installation, or live readiness from local tests.
- OS-8: Pair expansion, lot scaling, or post-canary promotion.

## Assumptions

- The independent WORM/CAS provider owns atomic predecessor and nonce
  enforcement and returns signed canonical documents after durable commit.
- External launcher trust remains the existing public-key-only prerequisite;
  it is not replaced by WORM custody.
- A later separately reviewed Windows bootstrap will revalidate this
  capability, current risk/news/journal/runtime heads, and central policy
  immediately before any process or broker effect.

## Risks and Mitigations

- **Risk:** A signed receipt is accepted without real storage.
  **Mitigation:** require byte-exact object readback through the independently
  configured provider.
- **Risk:** A launcher nonce is replayed on another host or release.
  **Mitigation:** bind host/service/task/release and atomically reserve the
  signed attestation nonce in external CAS.
- **Risk:** CAS succeeds but response/readback is lost or forged.
  **Mitigation:** require signed checkpoint, separate signed acknowledgement,
  exact head readback, and nonce-seen readback; ambiguity burns the nonce.
- **Risk:** Custody key can act as launcher authority.
  **Mitigation:** require distinct RSA identities and exact existing launcher
  policy/attestation.
- **Risk:** A sealed prerequisite is mistaken for live authority.
  **Mitigation:** all effect flags stay false and construction succeeds only
  while the central LIVE lock remains false.

## Open Questions

- Which independent production WORM/CAS provider and retention policy will be
  approved for the actual XM Windows host?
- Which exact external launcher policy, host/service/task identities, and
  release manifest will replace synthetic fixtures?
- Which later bootstrap release will consume this prerequisite while
  revalidating mutable runtime heads and performing the reviewed central-unlock
  ceremony?
