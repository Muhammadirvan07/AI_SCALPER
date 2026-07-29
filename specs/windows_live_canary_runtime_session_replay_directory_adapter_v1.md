# Windows LIVE Canary Runtime-Session Replay Directory Adapter v1

**Author:** Codex with the AI_SCALPER project owner
**Date:** 2026-07-30
**Status:** Approved for implementation under the project owner's standing authorization
**Reviewers:** senior architecture, security, and ship-gate boundaries
**Related specs:**
`specs/windows_live_canary_provider_bound_runtime_session_handoff_v1.md`,
`specs/windows_live_canary_external_cas_directory_adapter_v1.md`,
`specs/windows_execution_provider_bound_runtime_closure_v1.md`, and
`specs/windows_live_canary_external_runtime_hook_lease_v1.md`

## Context

The Windows Execution release can now verify a short-lived signed
provider-bound runtime-session handoff and requires one fresh challenge-bound
receipt from an independently controlled atomic replay ledger. The consumer
accepts a synchronous callback but intentionally contains no network client,
credential access, private key, or replay database.

The existing external-CAS directory adapter proves the repository's reviewed
filesystem transport pattern: exact absolute roots, stable regular-file
reads, private staging, durable publication, atomic no-replace visibility,
bounded polling, fresh request identities, and central-policy checks around
every external effect. The runtime-session replay callback needs a smaller
version of that pattern. It publishes the exact canonical request already
created by the handoff consumer and returns the exact response bytes for the
consumer's authoritative signature, challenge, time, and binding checks.

This feature adds only that Execution-side transport adapter. It does not
operate the external ledger, sign a handoff or receipt, provision an RSA key,
declare a handoff consumed, reconstruct a session, launch a process, initialize
MT5, or authorize an order. With the checked-in central LIVE lock false, the
adapter must reject before inspecting any caller-supplied directory.

## Functional Requirements

- FR-1: A dedicated
  `live_runtime/windows_live_canary_runtime_session_replay_directory_adapter.py`
  module MUST expose one exact
  `WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapter` callable compatible
  with the handoff consumer's `Callable[[bytes], bytes]` replay port.
- FR-2: Construction MUST require exact canonical public handoff-policy bytes,
  an independently supplied non-zero policy SHA-256 pin, one provider ID, one
  absolute request directory, one distinct absolute response directory, a
  trusted UTC clock provider, a monotonic clock, a sleeper, and a bounded
  response timeout.
- FR-3: The policy MUST be decoded by the existing exact handoff-policy
  consumer. The adapter MUST retain only public policy identity and binding
  values and MUST never accept a private key, secret, credential reference, or
  signer callback.
- FR-4: Construction and every invocation MUST require the checked-in central
  LIVE policy to be true, `SAFE_TO_DEMO_AUTO_ORDER=false`, and the exact LIVE
  policy decision to be allowed. With the checked-in lock false, rejection
  MUST precede path conversion, path lookup, clock, sleep, or publication.
- FR-5: Request and response roots MUST be absolute, existing, distinct,
  non-symlink, non-reparse directories. Their device/inode/mode/Windows
  attributes MUST be captured at construction and rechecked before and after
  every filesystem effect.
- FR-6: The callback input MUST be exact bytes no larger than 1 MiB and exact
  canonical single-LF UTF-8 JSON using schema
  `live-canary-provider-bound-runtime-session-consumption-request-v1`, with no
  duplicate/unknown keys, non-finite values, CR, trailing bytes, or field
  drift.
- FR-7: The request MUST bind the adapter's exact policy SHA-256, replay-ledger
  alias, Execution release, target host, installed environment, deployment
  host, service account, launcher task, and LIVE task. It MUST retain
  `central_unlock_required=true`, `session_reconstruction_authorized=true`,
  `direct_execution_authorized=false`, `broker_mutation_authorized=false`, and
  `order_capability=GATED_PRESENT`.
- FR-8: The request time and expiry MUST be canonical UTC, the expiry MUST be
  after the request time and no more than the policy's maximum replay-request
  TTL or five seconds later, and the trusted clock MUST be within the request
  window before publication.
- FR-9: The request identity MUST be the SHA-256 of the exact callback input.
  The final request name MUST be
  `<request-sha256>.runtime-session-replay-request.json`; the only accepted
  response name MUST be
  `<request-sha256>.runtime-session-replay-receipt.json`.
- FR-10: Publication MUST first create a request-root-local private staging
  regular file with create-exclusive mode, write all bytes, flush and sync the
  file, stable-read the exact staged bytes, and then make the final request
  visible through atomic no-replace publication.
- FR-11: A pre-existing final request MAY be reused only when its stable bytes
  equal the exact callback input. Different bytes, a pre-existing staging
  path, an ambiguous Windows rename result, or any path substitution MUST
  reject without overwriting evidence.
- FR-12: Publication MUST never expose partial final bytes. On POSIX, a private
  hard-link publication plus staging unlink is acceptable. On Windows, an
  exact no-replace rename is acceptable only when a pre-existing destination
  is distinguished from every other ambiguous error and all post-publication
  bytes are reverified.
- FR-13: The adapter MUST poll only the exact response name until the earlier
  of the request expiry or the configured monotonic timeout, with timeout no
  greater than two seconds and bounded poll intervals.
- FR-14: Response reads MUST open one exact regular non-symlink/non-reparse file
  without following links, read at most 1 MiB, compare pre-open/open/post-read/
  post-close metadata, recheck the response-root identity, and return only the
  exact stable bytes.
- FR-15: The response MUST be exact canonical single-LF UTF-8 JSON using schema
  `live-canary-provider-bound-runtime-session-consumption-receipt-v1`. The
  adapter MUST perform structural and request-hash prechecks, while the
  handoff consumer remains the sole authority for RSA signature, fresh
  challenge, consumption, time, and complete binding validation.
- FR-16: A response MUST bind the exact request SHA-256, policy SHA-256,
  handoff/session/candidate/nonce identities, challenge, replay-ledger alias,
  release/host/environment/service/task identities, and request expiry.
- FR-17: The trusted UTC clock and monotonic clock MUST never regress. A
  response observed at or after request expiry, after monotonic timeout, or
  after central-policy relock MUST reject.
- FR-18: One adapter instance MUST admit at most one active invocation. A
  concurrent or reentrant call MUST fail immediately with a stable busy reason
  before publishing another request.
- FR-19: Every callback, filesystem, clock, sleep, and parsing failure MUST be
  converted to a stable uppercase non-secret reason code. Exception text,
  document bytes, directory paths, account data, provider data, and response
  contents MUST not cross the public error boundary.
- FR-20: The adapter MUST contain no private-key operation, credential API,
  provider SDK, socket/network client, SQLite database, subprocess, Task
  Scheduler mutation, MT5 import/initialization, process launch, or broker
  order call.
- FR-21: The Windows Execution allowlist and critical provider-bound runtime
  closure MUST add exactly this adapter module. Operator producer, replay
  service, and private signing authorities MUST remain absent.
- FR-22: The isolated closure probe MUST import the adapter and prove that
  construction under the checked-in false central lock performs no path,
  clock, sleep, request, response, credential, network, MT5, process, task, or
  broker effect.
- FR-23: Successful transport MUST return receipt bytes only. It MUST NOT claim
  the handoff was accepted, create a session, set production readiness, grant
  per-order authority, or report broker acknowledgement.
- FR-24: Existing candidate/session/handoff, external-CAS, runtime hook,
  bootstrap, per-order, release-builder, allowlist-separation, and atomic-suite
  contracts MUST remain compatible except for naturally derived new Execution
  and closure identities.

## Non-Functional Requirements

- NFR-1: Implementation MUST use Python 3.12 standard-library primitives and
  existing first-party public policy/canonicalization code only.
- NFR-2: Static request validation and publication setup MUST complete in less
  than one second on the project test host, excluding configured response
  wait time and filesystem latency.
- NFR-3: The configured timeout MUST be finite, greater than zero, no more than
  two seconds, and no later than the request expiry.
- NFR-4: Normal Python and `PYTHONOPTIMIZE=2` MUST make identical security
  decisions; no security decision may rely on `assert`.
- NFR-5: Focused tests MUST require no Windows host, network, credentials,
  private key, external provider, Task Scheduler, MT5, broker account, or
  production evidence.
- NFR-6: Identical clean commit/tree and allowlist inputs MUST produce
  byte-identical Execution archives, closure records, and release identities.
- NFR-7: Focused and full normal/optimized tests, compilation, lint, type
  checking, dependency-lock verification, release separation, and repository
  hygiene MUST pass.

## Acceptance Criteria

### AC-1: Exact policy-bound request admission (FR-1, FR-2, FR-3, FR-4, FR-5, FR-6, FR-7, FR-8, FR-9)

Given exact canonical policy bytes, independent policy pin, safe distinct
directories, and one exact current replay request
When the adapter is constructed and invoked under an enabled central LIVE lock
Then the request schema, policy, target, safety, challenge, and time bindings
are accepted
And the request identity and exact deterministic filenames are derived only
from the callback bytes.

### AC-2: Durable atomic request publication (FR-5, FR-9, FR-10, FR-11, FR-12)

Given an empty request directory and one valid request
When the adapter publishes it
Then no watcher can observe a partial final file
And the staged, final, and callback bytes are exact
And an identical final request is idempotent while a conflicting or ambiguous
destination fails without overwrite.

### AC-3: Stable exact response handoff (FR-13, FR-14, FR-15, FR-16, FR-17)

Given a service that writes one exact response for the request identity
When the adapter polls the response directory
Then only the exact stable regular response is returned
And wrong request hash, wrong binding, noncanonical bytes, stale response,
root drift, metadata drift, or timeout rejects.

### AC-4: Central lock and concurrency isolation (FR-4, FR-17, FR-18, FR-22)

Given the checked-in central lock false, a relock during any effect, a
concurrent call, or a regressing clock
When construction or invocation occurs
Then it fails closed with a stable reason
And no unauthorized path lookup, request publication, response return, or
later effect occurs.

### AC-5: Transport never becomes authority (FR-3, FR-15, FR-20, FR-21, FR-23)

Given a structurally valid signed-looking response
When the adapter returns exact bytes to its caller
Then only the existing handoff consumer may validate its signature and fresh
challenge or construct a sealed session
And the adapter has no private-key, credential, replay-database, broker, or
order capability.

### AC-6: Minimal isolated Execution closure (FR-20, FR-21, FR-22, FR-24)

Given only exact files named by the Windows Execution allowlist
When the closure probe runs under `python -I -S -B`
Then the adapter and handoff consumer import successfully
And all operator/service/private authority modules remain excluded
And the probe still reports LIVE false, production readiness false, and broker
mutation not performed.

### AC-7: Adversarial and release parity (FR-19, FR-24; NFR-1, NFR-2, NFR-3, NFR-4, NFR-5, NFR-6, NFR-7)

Given malformed, duplicate, oversized, stale, substituted, raced, and
optimized-mode fixtures
When focused, downstream, full, dependency, static, hygiene, and deterministic
release gates run
Then all accept/reject decisions remain fail-closed and identical
And two clean builds from one commit/tree are byte-identical.

## Edge Cases and Error Scenarios

- EC-1: Empty, non-bytes, oversized, invalid UTF-8, CRLF, missing final LF,
  multiple LFs, trailing bytes, scalar JSON, duplicate key, non-finite number,
  missing field, extra field, or reordered noncanonical JSON MUST reject.
- EC-2: Zero/malformed policy pin, wrong policy schema, weak RSA key, reused
  authority, wrong replay-ledger alias, or any target-binding drift MUST reject
  before publication.
- EC-3: Relative, missing, same, symlinked, reparse, non-directory, or replaced
  request/response root MUST reject.
- EC-4: Request time in the future, request already expired, TTL greater than
  policy/five seconds, non-UTC clock, UTC regression, non-finite monotonic
  value, or monotonic regression MUST reject.
- EC-5: Existing staging file, final-request collision with different bytes,
  short write, fsync failure, link/rename ambiguity, directory-sync failure,
  or post-publication byte drift MUST reject without deleting foreign bytes.
- EC-6: Response missing until timeout, response symlink/reparse/directory,
  zero/oversized response, response replaced while open, short read, metadata
  drift, root swap, or close failure MUST reject.
- EC-7: Receipt schema drift, wrong request hash, policy, handoff, session,
  candidate, nonce, challenge, ledger, release, host, environment, service,
  task, expiry, or safety field MUST reject before return.
- EC-8: Receipt with forged signature or prior challenge MAY pass adapter
  structural transport checks but MUST still be rejected by the authoritative
  handoff consumer; the adapter MUST never label it valid.
- EC-9: A second simultaneous or reentrant invocation MUST reject before
  publication; a later invocation after release of the lock MAY proceed with a
  distinct request identity.
- EC-10: Central policy false at construction, relocked before/during/after
  publication, relocked while polling, or relocked before response return MUST
  reject without reporting success.
- EC-11: Callback and OS exception text containing secrets or paths MUST be
  replaced by a stable reason code.
- EC-12: Importing the module or probing it under the checked-in lock MUST NOT
  inspect directories, call a clock, sleep, publish a file, contact a network,
  access credentials, initialize MT5, start a process/task, or mutate a broker.

## API Contracts

HTTP API: N/A. The adapter uses a local, ACL-controlled request/response
directory boundary and introduces no endpoint. `GET /not-applicable` is a
documentation marker only and MUST NOT be implemented.

```typescript
type LowerHex64 = string;

interface RuntimeSessionReplayDirectoryRequestV1 {
  schema_version: "live-canary-provider-bound-runtime-session-consumption-request-v1";
  handoff_id: string;
  handoff_policy_sha256: LowerHex64;
  handoff_sha256: LowerHex64;
  candidate_sha256: LowerHex64;
  session_sha256: LowerHex64;
  handoff_nonce_sha256: LowerHex64;
  challenge_sha256: LowerHex64;
  replay_ledger_alias_sha256: LowerHex64;
  execution_release_identity_sha256: LowerHex64;
  target_host_identity_sha256: LowerHex64;
  installed_environment_sha256: LowerHex64;
  deployment_host_alias_sha256: LowerHex64;
  service_account_alias_sha256: LowerHex64;
  launcher_task_definition_sha256: LowerHex64;
  live_execution_task_definition_sha256: LowerHex64;
  requested_at_utc: string;
  expires_at_utc: string;
  central_unlock_required: true;
  session_reconstruction_authorized: true;
  direct_execution_authorized: false;
  broker_mutation_authorized: false;
  order_capability: "GATED_PRESENT";
}

interface RuntimeSessionReplayDirectoryReceiptV1 {
  schema_version: "live-canary-provider-bound-runtime-session-consumption-receipt-v1";
  request_sha256: LowerHex64;
  challenge_sha256: LowerHex64;
  consumed_once: true;
  signature_algorithm: "RSASSA-PKCS1-v1_5-SHA256";
  signature_rsa_pkcs1v15_sha256_hex: string;
}
```

```python
class WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapter:
    def __init__(
        self,
        *,
        provider_id: str,
        handoff_policy_payload: bytes,
        expected_handoff_policy_sha256: str,
        request_directory: str | Path,
        response_directory: str | Path,
        clock_provider: Callable[[], datetime],
        timeout_seconds: float,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None: ...

    def __call__(self, request_payload: bytes) -> bytes: ...
```

## Data Models

### Adapter configuration

| Field | Type | Constraint |
|---|---|---|
| `provider_id` | string | canonical identifier; public routing label only |
| `handoff_policy_payload` | bytes | exact canonical policy; at most 1 MiB |
| `expected_handoff_policy_sha256` | lower hex | independent, non-zero pin |
| `request_directory` | absolute path | existing stable regular directory |
| `response_directory` | absolute path | existing stable directory, distinct from request root |
| `clock_provider` | callback | aware exact UTC datetime; monotonic observations |
| `timeout_seconds` | number | finite `0 < timeout <= 2` |
| `sleeper` | callback | bounded poll sleep; no authority |
| `monotonic` | callback | finite non-regressing seconds |

### Published request

| Field | Type | Constraint |
|---|---|---|
| request identity | SHA-256 | exact callback bytes |
| final filename | string | exact request hash plus fixed suffix |
| payload | bytes | canonical request, byte-identical to callback input |
| publication | filesystem | create-exclusive staging, sync, atomic no-replace |

### Returned response

| Field | Type | Constraint |
|---|---|---|
| filename | string | exact request hash plus fixed receipt suffix |
| payload | bytes | stable canonical receipt, at most 1 MiB |
| request binding | SHA-256 | equals exact published request bytes |
| authority | none | bytes only; consumer performs authoritative verification |

### Safety and effects

| Claim | Required value |
|---|---|
| central checked-in default | `LIVE_ALLOWED=false` |
| adapter result | untrusted receipt bytes only |
| session reconstruction | not performed by adapter |
| private key / credential access | not performed |
| network / SQLite / Task Scheduler | not performed |
| MT5 / process / broker mutation | not performed |
| production execution readiness | false |

## Out of Scope

- OS-1: Enabling the central LIVE policy or changing any checked-in safety
  constant.
- OS-2: Operating or provisioning the handoff signer, replay-ledger service,
  RSA private keys, HSM/KMS, Windows Credential Manager, ACLs, service account,
  or off-host storage.
- OS-3: Defining the external service's atomic database, backup/restore,
  replication, WORM custody, TLS, authentication, or disaster recovery.
- OS-4: Producing authentic policy, signed handoff, signed receipt, provider
  acceptance, promotion, approvals, or deployment evidence.
- OS-5: Reconstructing a provider-bound runtime session, importing a concrete
  provider, materializing runtime ports, or launching Execution.
- OS-6: Initializing MT5, reading account credentials, preparing/submitting an
  order, interpreting broker acknowledgement, or reconciling positions.
- OS-7: Declaring demo-auto soak, LIVE canary, production readiness, or live
  trading complete.
