# Windows LIVE Canary Runtime Candidate Consumer Closure v1

**Author:** Codex with the AI_SCALPER project owner
**Date:** 2026-07-30
**Status:** Approved for implementation under the project owner's standing authorization
**Reviewers:** senior architecture, security, and ship-gate boundaries
**Related specs:**
`specs/live_canary_prebootstrap_admission_v1.md`,
`specs/windows_execution_provider_bound_runtime_closure_v1.md`,
`specs/windows_live_canary_execution_materialization_v1.md`, and
`specs/windows_live_canary_external_runtime_hook_lease_v1.md`

## Context

The extracted Windows Execution release now owns the exact provider-bound
runtime launch-session v2 consumer contract, while admission, acceptance,
custody, and activation producers remain operator-only. The same release does
not own the exact `LiveCanaryRuntimeCandidate` contract: that class still lives
inside `live_canary_prebootstrap_admission.py`, whose imports pull privileged
activation and source-bound assembly modules that are intentionally excluded
from the Execution allowlist.

The reviewed external LIVE runtime provider executes under an allowlist-only
import scope. It therefore cannot import the current candidate class from an
extracted Execution ZIP, cannot register the exact candidate type with the
lightweight runtime-authority registry, and cannot construct the exact
candidate required by `ProductionRuntimeBootstrap`. The newly implemented
external hook lease is consequently loadable, but no honest allowlist-only
runtime provider can complete the `WindowsLiveCanaryRuntimeSource` triple.

This feature extracts only the immutable, non-secret, deny-only candidate
contract and a strict canonical candidate-document loader into a minimal
consumer module. The operator-side prebootstrap module imports and re-exports
that exact class. Loading a candidate document grants no session, execution,
credential, process, or order authority; an exact sealed provider-bound launch
session and every downstream guard remain independently mandatory.

## Functional Requirements

- FR-1: A dedicated
  `live_runtime/live_canary_runtime_candidate.py` module MUST own the exact
  `LiveCanaryRuntimeCandidate` class and its field validation.
- FR-2: The candidate consumer module MUST register that exact class with the
  lightweight runtime-authority registry under its new module path.
- FR-3: The operator-side `live_canary_prebootstrap_admission.py` module MUST
  import and re-export the consumer class rather than define a second class.
- FR-4: `production_bootstrap.py` MUST import the candidate predicate through
  the consumer module so candidate registration occurs whenever the extracted
  Execution runtime loads.
- FR-5: Existing operator producer and consumer imports MUST resolve to one
  exact class identity, and existing candidate canonical payloads and content
  SHA-256 values MUST remain byte-compatible.
- FR-6: The consumer module MUST expose a strict loader for one canonical JSON
  document with schema
  `windows-live-canary-runtime-candidate-document-v1`, the exact candidate
  payload, and its exact non-zero content SHA-256.
- FR-7: The loader MUST require an independently supplied non-zero expected
  candidate SHA-256 and MUST compare it with both the document pin and the
  reconstructed candidate content SHA-256.
- FR-8: The loader MUST accept only exact UTF-8 canonical JSON with one final
  LF, no duplicate keys, no non-finite value, no trailing bytes, no extra or
  missing wrapper field, and a maximum size of 1 MiB.
- FR-9: The loader MUST require the closed candidate field inventory, convert
  only the two documented pair collections to exact tuples, reconstruct the
  exact candidate, and prove byte-identical canonical round-trip.
- FR-10: Loading or validating a candidate MUST NOT require central LIVE
  unlock and MUST preserve candidate values `live_allowed=false`,
  `activation_authorized=false`, `execution_authorized=false`,
  `safe_to_demo_auto_order=false`, and `order_capability=DISABLED`.
- FR-11: The Execution allowlist MUST add only the candidate consumer module
  and MUST continue to exclude activation, admission, source-bound,
  conformance, acceptance, custody, and launch-session producer modules.
- FR-12: The critical provider-bound runtime closure manifest MUST add the
  candidate consumer bytes, update its exact file count and identity, and keep
  all safety non-claims false or disabled.
- FR-13: The isolated closure probe MUST import the candidate class, strict
  loader, candidate predicate, provider-bound session class, production
  authority consumer, and runtime-source sealer from allowlist-only bytes.
- FR-14: The isolated probe MUST prove that an unregistered object, subclass,
  forged object, malformed document, or document with the wrong external pin
  cannot satisfy the candidate predicate or loader.
- FR-15: Existing prebootstrap, provider-bound launch, production-bootstrap,
  order-authorization, provider materialization, configured-candidate,
  source-bound, conformance, and release-builder contracts MUST remain
  backward-compatible except for naturally derived new Execution release
  identities.
- FR-16: New failures MUST expose stable uppercase non-secret reason codes and
  MUST NOT include candidate document bytes, filesystem paths, credentials,
  private keys, broker payloads, or provider exception text.
- FR-17: Package or loader success MUST NOT be interpreted as provider
  acceptance, launch-session authority, production readiness, central unlock,
  MT5 initialization, broker acknowledgement, or LIVE trading authority.

## Non-Functional Requirements

- NFR-1: The candidate consumer and loader MUST use Python 3.12 standard
  library and already allowlisted first-party primitives only.
- NFR-2: A maximum-size valid candidate document MUST parse, reconstruct, and
  verify in less than one second on the project test host.
- NFR-3: Normal Python and `PYTHONOPTIMIZE=2` MUST make identical security
  decisions; no decision may rely on `assert`.
- NFR-4: Candidate loading and isolated closure verification MUST perform no
  credential, private-key, SQLite, MT5, network, process, Task Scheduler,
  permit, authorization-consumption, or broker effect.
- NFR-5: Identical clean commit/tree and allowlist inputs MUST produce
  byte-identical Execution archives, closure records, and identities.
- NFR-6: Focused and full normal/optimized tests, compilation, lint, type
  checking, dependency-lock verification, release separation, and repository
  hygiene checks MUST pass.

## Acceptance Criteria

### AC-1: One exact producer-consumer candidate class (FR-1, FR-2, FR-3, FR-4, FR-5)

Given the operator prebootstrap module and the extracted Execution bootstrap
When both import LIVE runtime candidate authority
Then both reference one exact registered candidate class
And existing canonical candidate payloads and content hashes are unchanged.

### AC-2: Strict canonical candidate loading (FR-6, FR-7, FR-8, FR-9, FR-10)

Given one exact candidate document and an independent matching candidate pin
When the consumer loader reconstructs it
Then the result is the exact registered candidate class
And its canonical payload round-trips byte-identically
And every candidate authority and execution flag remains false or disabled.

### AC-3: Malformed, unpinned, and forged input rejection (FR-7, FR-8, FR-9, FR-14, FR-16)

Given a duplicate-key, non-canonical, oversized, extra-field, wrong-pin,
subclass, or forged candidate input
When parsing or candidate validation runs
Then it rejects with a stable non-secret reason code
And no external or broker effect occurs.

### AC-4: Minimal allowlist-only closure (FR-11, FR-12, FR-13, FR-17, NFR-4)

Given only files named by the Windows Execution allowlist
When the isolated closure probe runs under `python -I -S -B`
Then candidate and provider-bound session consumers import successfully
And all operator-only producer modules remain absent
And output continues to report LIVE, readiness, and order capability locked.

### AC-5: Performance and optimized parity (FR-8, FR-14, NFR-2, NFR-3)

Given valid and adversarial candidate documents
When parsing and closure checks run in normal and optimized Python
Then accept/reject results are identical
And a maximum-size accepted document completes within one second.

### AC-6: Downstream and release compatibility (FR-5, FR-12, FR-15, NFR-5, NFR-6)

Given the completed extraction and loader
When focused, downstream, release-builder, full, dependency, static, and
hygiene gates run
Then all gates pass without provider-pack/configured/source-bound contract
drift or central safety-lock change
And repeat clean builds are byte-identical.

## Edge Cases and Error Scenarios

- EC-1: Empty bytes, missing final LF, two final LFs, invalid UTF-8, or a JSON
  scalar MUST reject before candidate construction.
- EC-2: A duplicate wrapper or nested candidate key MUST reject.
- EC-3: `NaN`, infinity, a boolean where a number is required, or a malformed
  timestamp/hash/path/pair MUST reject.
- EC-4: A wrapper with a missing field, extra field, legacy schema, zero hash,
  wrong external pin, or mismatched embedded pin MUST reject.
- EC-5: A candidate payload with a missing, extra, reordered, duplicated, or
  case-colliding symbol/conversion pair MUST reject.
- EC-6: A candidate whose fixed environment/mode/symbol/lot/position/safety
  values drift MUST reject.
- EC-7: A valid candidate document larger than 1 MiB MUST reject before JSON
  decoding.
- EC-8: A direct constructor call remains allowed only for the deny-only data
  contract; it MUST NOT satisfy a launch-session or per-order authority check.
- EC-9: A forged object, subclass, or object carrying copied attributes MUST
  return false from the exact candidate predicate.
- EC-10: Removing or changing candidate consumer bytes in an extracted release
  MUST change or reject the closure and Execution release identity.
- EC-11: Adding an operator-only module to a service allowlist MUST fail the
  release-separation gate.
- EC-12: Central LIVE policy false MUST not prevent pure candidate parsing,
  while every bootstrap/materialization effect boundary remains locked.

## API Contracts

HTTP API: N/A — this is an offline Python consumer and release-closure
boundary. No HTTP endpoint or browser command is introduced.
The validator marker `POST /not-applicable` is documentation-only and MUST NOT
be implemented or exposed.

```typescript
interface WindowsLiveCanaryRuntimeCandidateDocumentV1 {
  schema_version: "windows-live-canary-runtime-candidate-document-v1";
  candidate: LiveCanaryRuntimeCandidateV1;
  candidate_sha256: LowerHex64;
}
```

```python
def canonical_live_canary_runtime_candidate_document(
    candidate: LiveCanaryRuntimeCandidate,
) -> bytes:
    """Return the only accepted canonical one-LF document bytes."""

def load_live_canary_runtime_candidate_document(
    payload: bytes,
    *,
    expected_candidate_sha256: str,
) -> LiveCanaryRuntimeCandidate:
    """Reconstruct one exact deny-only candidate from independently pinned bytes."""

def is_live_canary_runtime_candidate(value: object) -> bool:
    """Return true only for the registered exact candidate class."""
```

## Data Models

### Candidate document

| Field | Type | Constraints |
|---|---|---|
| `schema_version` | string | Exact v1 document schema |
| `candidate` | closed object | Exact canonical candidate payload |
| `candidate_sha256` | lower hex SHA-256 | Non-zero; equals independent pin and reconstructed content hash |

### Runtime candidate

| Field group | Type | Constraints |
|---|---|---|
| broker/account/server | non-secret identifiers and hashes | Exact, non-empty, canonical |
| local runtime paths | absolute strings | journal/supervisor distinct; dependency-lock basename exact |
| symbol mappings | ordered unique pairs | exactly one canonical `XAUUSD` LIVE symbol |
| source/release/model identities | lower-hex hashes | non-zero; exact lengths and cross-bindings retained |
| trust-domain identities | IDs and fingerprints | pairwise distinct where required |
| runtime limits | integers/floats | XAUUSD, 0.01 lot, one position, intent TTL at most one second |
| authority state | fixed constants | all false/disabled; no session or order authority |

### Critical closure record

| Field | Type | Constraints |
|---|---|---|
| path | POSIX relative path | exact candidate consumer member |
| size | positive integer | exact source byte count |
| SHA-256 | lower hex | exact source bytes |
| closure identity | lower hex | derived from sorted complete record set |

## Out of Scope

- OS-1: Serializing, signing, reconstructing, or activating a provider-bound
  runtime launch session; that requires a separate reviewed portable handoff.
- OS-2: Implementing the concrete 40-provider Windows runtime module or
  provisioning its 12 credential references.
- OS-3: Changing provider conformance/acceptance, WORM/CAS custody, replay
  consumption, launcher trust, central unlock, or per-order authorization.
- OS-4: Packaging operator-side activation, admission, source-bound,
  conformance, acceptance, or custody producers into a service release.
- OS-5: Initializing MT5, calling `order_check`/`order_send`, installing a
  Windows task, starting a service, or submitting a real broker order.
- OS-6: Treating a valid candidate document, closure probe, release archive,
  or external hash pin as production readiness or proof of live trading.
