# Spec: Phillip V6 LIVE-Canary WORM Gate Bridge V1

**Author:** Codex with AI_SCALPER project owner

**Date:** 2026-07-30

**Status:** Approved

**Reviewers:** project owner, security boundary, ship-gate

**Approval basis:** standing owner authorization to continue fail-closed
development without enabling broker mutation

**Related specs:** `phillip_commodity_v6_postrun_acceptance_v2.md`,
`live_canary_gate_receipt_operator_v1.md`,
`live_canary_activation_evidence_v1.md`

## Context

The Phillip Commodity V6 post-run contract can independently rebuild a
scheduled-run acceptance archive and verify a policy-pinned RSA custody
receipt. It emits a canonical deny-only custody assessment. The LIVE-canary
gate operator, however, currently treats `WORM_CUSTODY` like any generic file:
it hashes arbitrary bytes and asks a domain authority to sign the hash. Later
receipt-set, activation-request, and replay-consumption verification repeats
only that byte hash. It does not prove that the bytes are a valid Phillip V6
custody result, that the custodian policy was externally pinned, or that WORM
retention covers the gate lifetime.

This feature closes that gap with one deterministic five-member evidence ZIP
and mandatory semantic re-verification at every artifact boundary. The gate
authority remains independent and policy-pinned. The external RSA policy hash
is never trusted from the ZIP itself; the operator must supply the expected
hash independently whenever the evidence is issued or revalidated.

This bridge is evidence-only. It does not satisfy demo-auto cohort thresholds,
broker eligibility, human approvals, provider-bound admission, provider-bound
custody, replay consumption, launch-session creation, per-order authority, or
broker execution.

## Functional Requirements

- FR-1: The bridge MUST accept one exact Phillip V6 custody-request ZIP,
  canonical RSA custody policy, canonical signed custody receipt, canonical
  custody assessment, externally pinned custody-request SHA-256, externally
  pinned custody-policy SHA-256, and exact toolkit source commit/tree.
- FR-2: Construction MUST rerun the existing
  `verify_custody_receipt(...)` verifier and MUST require its regenerated
  assessment bytes to be byte-identical to the supplied assessment.
- FR-3: The evidence ZIP MUST contain exactly four source members and one
  manifest member in the inventory and order defined below.
- FR-4: The manifest MUST bind every source-member SHA-256 and size, the exact
  toolkit source commit/tree, custody request identity, acceptance identity,
  assessment identity, custodian policy and receipt identities, verified time,
  remote retention time, and deny-only safety values.
- FR-5: The ZIP MUST be deterministic for byte-identical inputs by using one
  fixed timestamp, fixed regular-file mode, fixed compression settings,
  canonical JSON, and exact member order.
- FR-6: Construction and verification MUST require regular, non-symlink,
  non-reparse, bounded files and MUST fail if a file identity or size changes
  during inspection.
- FR-7: ZIP parsing MUST reject duplicate names, directories, encrypted
  members, links, non-canonical paths, extra/missing/reordered members,
  oversized members, excessive expanded size, bad CRC, trailing bytes, or
  malformed canonical JSON.
- FR-8: Bridge verification MUST require an externally supplied non-zero
  lowercase custody-policy SHA-256 and MUST reject a hash obtained only from
  the evidence ZIP.
- FR-9: Bridge verification MUST rerun the existing custody-request,
  acceptance, RSA signature, remote-content, Object Lock `COMPLIANCE`,
  versioning, WORM, and retention checks from source members.
- FR-10: The assessment `verified_at_utc` MUST NOT be later than the gate
  observation time, and remote `retain_until_utc` MUST be at least the caller's
  `required_until` time.
- FR-11: `issue_live_canary_gate_receipt_artifact` MUST reject a generic
  `WORM_CUSTODY` file and MUST hash only a successfully verified bridge ZIP.
- FR-12: Receipt verification, receipt-set assembly, persisted receipt-set
  verification, activation-request preflight, request assembly, request
  verification, authorization consumption, inspection, and recovery MUST each
  rerun bridge verification with the independent policy pin.
- FR-13: The `WORM_CUSTODY` receipt evidence hash MUST equal the SHA-256 of the
  exact outer bridge ZIP bytes. No derived manifest hash may replace it.
- FR-14: The policy pin MUST be a required operator input for every complete
  nine-domain receipt-set or activation-source workflow. A single non-WORM
  gate operation MUST reject a supplied custody pin; a single WORM operation
  MUST require it.
- FR-15: Existing generic behavior MUST remain unchanged for the seven other
  non-legal domains, and `LEGAL_COMPLIANCE` MUST continue to use only exact
  broker-eligibility evidence.
- FR-16: Every output MUST use create-exclusive publication, flush and fsync,
  never overwrite a pre-existing path, and remove only the exact identity
  created by the failed invocation.
- FR-17: Every success and failure result MUST retain
  `order_capability=DISABLED`, `live_allowed=false`,
  `execution_authorized=false`, `activation_authorized=false`, and
  `broker_mutation=NOT_PERFORMED`.
- FR-18: The bridge MUST NOT import MT5, initialize a terminal, inspect broker
  credentials, access network, launch a process, mutate Task Scheduler, consume
  an activation nonce, mint a permit, or submit an order.
- FR-19: The bridge module, its two CLIs, and the existing V6 verifier dependency
  MUST be present only in the Windows deployment/operator tooling allowlist,
  never in Decision, Execution, Status Monitor, read-only shadow, or configured
  service release inventories.
- FR-20: Existing LIVE-canary binding, trust-policy, receipt, receipt-set,
  request, approval, authorization, replay, and execution schemas MUST remain
  byte-compatible.

### Exact Evidence ZIP Inventory

The deterministic archive order is:

1. `custody-assessment.json`;
2. `custody-policy.json`;
3. `custody-receipt.json`;
4. `custody-request.zip`;
5. `PHILLIP_V6_LIVE_CANARY_WORM_GATE_EVIDENCE.json`.

The manifest schema is
`phillip-v6-live-canary-worm-gate-evidence-v1`.

## Non-Functional Requirements

- NFR-S1: SHA-256 and reconstructed-byte comparisons MUST use constant-time
  comparison where practical.
- NFR-S2: The bridge MUST inherit the V6 custody verifier's RSA key-size,
  exponent, domain-separation, policy-schema, and retention constraints.
- NFR-S3: Every trust or content hash MUST be a lowercase non-zero 64-character
  SHA-256 value.
- NFR-R1: Verification MUST be fail-closed and side-effect-free except for
  private temporary files that are removed before return.
- NFR-R2: No failure may leave a published partial bridge ZIP.
- NFR-P1: A bounded bridge under 4 MiB SHOULD verify in under two seconds on
  the supported Windows CPython 3.12 runtime.
- NFR-C1: The implementation MUST use Python 3.12 standard library and existing
  reviewed AI_SCALPER modules only.
- NFR-C2: Focused tests, complete serial tests, optimized tests, compilation,
  release builders, static forbidden-effect checks, and scoped whitespace
  checks MUST pass before release.

## Acceptance Criteria

### AC-1: Deterministic bridge construction (FR-1, FR-2, FR-3, FR-4, FR-5)

Given exact valid custody request, policy, receipt, assessment, source pins,
and external hashes
When two independent bridge builds run to fresh destinations
Then both evidence ZIP files are byte-identical
And each manifest binds the same exact source and custody identities
And all safety fields remain deny-only.

### AC-2: Byte-identical assessment reconstruction (FR-2, FR-9)

Given a canonical assessment emitted by the existing custody verifier
When bridge construction or verification reruns the verifier
Then the regenerated assessment bytes exactly equal the supplied bytes
And any assessment field, whitespace, or hash mutation is rejected.

### AC-3: Independent policy pin (FR-8, FR-14, NFR-S3)

Given an internally coherent ZIP containing an attacker-selected RSA policy
and receipt
When verification receives a missing, zero, uppercase, malformed, or different
external policy SHA-256
Then verification fails before the evidence can satisfy `WORM_CUSTODY`
And no gate receipt or receipt set is published.

### AC-4: Retention covers the gate window (FR-9, FR-10)

Given otherwise valid custody evidence whose remote retention ends before the
gate receipt expiry or activation request expiry
When any issuance, set, request, or consumption boundary revalidates it
Then the operation fails with a stable retention rejection
And no downstream authorization is accepted.

### AC-5: WORM receipt issuance is semantic (FR-11, FR-13, FR-15)

Given a valid bridge ZIP and external policy pin
When the policy-pinned WORM gate authority issues its receipt
Then the receipt evidence hash equals the outer ZIP SHA-256
And arbitrary JSON, a custody request alone, or an assessment alone is rejected
for `WORM_CUSTODY`
And generic non-WORM gate behavior is unchanged.

### AC-6: Complete set revalidates the bridge (FR-12, FR-14)

Given nine valid receipts and exact evidence sources
When the set assembler or independent set verifier runs
Then it reruns semantic bridge verification with the external policy pin
And source, policy, signature, assessment, retention, or ZIP drift fails closed.

### AC-7: Activation and replay workflows cannot bypass custody (FR-12)

Given a persisted gate set and activation request
When request assembly, request verification, authorization consumption,
inspection, or recovery reloads the sources
Then the same external policy pin is required and the bridge is reverified
And replacing the WORM source after signing prevents continuation.

### AC-8: Strict archive and exclusive publication (FR-6, FR-7, FR-16)

Given an archive with duplicate, extra, reordered, linked, encrypted,
oversized, trailing, or mutated content, or a pre-existing destination
When build or verification runs
Then it fails without overwriting or deleting pre-existing bytes
And no partial archive remains.

### AC-9: No capability or release leakage (FR-17, FR-18, FR-19, FR-20)

Given help, success, failure, normal, optimized, and release-build execution
When the feature is inspected and tested
Then it performs no credential, network, process, scheduler, MT5, broker,
replay-consumption, permit, or order effect
And it exists only in the reviewed operator tooling release
And all pre-existing canonical schemas remain byte-compatible.

## Edge Cases and Error Scenarios

- EC-1: The request ZIP is valid but its externally supplied hash differs →
  bridge construction and verification fail before publication.
- EC-2: The policy and receipt are internally consistent but the external
  policy pin differs → verification fails; self-selected trust is forbidden.
- EC-3: The assessment was created for another request, acceptance, toolkit
  commit/tree, policy, receipt, or remote object → byte reconstruction fails.
- EC-4: `retain_until_utc` equals `required_until` → accepted; one microsecond
  earlier → rejected.
- EC-5: Assessment verification time is one microsecond after gate observation
  → rejected as future evidence.
- EC-6: ZIP contains duplicate names or a path such as `../policy.json` →
  rejected before extraction.
- EC-7: ZIP has valid members followed by trailing bytes → rejected.
- EC-8: A source path is replaced during stable read → rejected before output.
- EC-9: An existing output is a file, directory, symlink, or reparse point →
  preserved unchanged and construction fails.
- EC-10: A valid WORM bridge is reused as another gate domain's source → exact
  source-identity uniqueness still rejects the complete set.
- EC-11: A custody policy pin is passed to `SECURITY` or another single
  non-WORM gate → rejected as ambiguous operator input.
- EC-12: The complete activation workflow omits its policy pin → argument or
  preflight validation fails before credential lookup.

## API Contracts

```python
build_phillip_v6_live_canary_worm_gate_evidence(
    *,
    custody_request_archive: Path,
    expected_custody_request_archive_sha256: str,
    expected_toolkit_source_commit: str,
    expected_toolkit_source_tree: str,
    policy_path: Path,
    expected_policy_sha256: str,
    receipt_path: Path,
    assessment_path: Path,
    output: Path,
) -> dict[str, object]

verify_phillip_v6_live_canary_worm_gate_evidence(
    path: Path,
    *,
    expected_policy_sha256: str,
    observed_at: datetime | None,
    required_until: datetime,
) -> dict[str, object]
```

Artifact-level additions are keyword-only:

```python
issue_live_canary_gate_receipt_artifact(
    ...,
    worm_custody_policy_sha256: str | None = None,
) -> LiveCanaryGateReceipt

verify_live_canary_gate_receipt_artifact(
    ...,
    worm_custody_policy_sha256: str | None = None,
) -> LiveCanaryGateReceipt

assemble_live_canary_gate_receipt_set(
    ...,
    worm_custody_policy_sha256: str,
) -> dict[str, object]

verify_live_canary_gate_receipt_set(
    ...,
    worm_custody_policy_sha256: str,
) -> tuple[LiveCanaryGateReceipt, ...]
```

The two local CLIs are:

- `prepare_phillip_v6_live_canary_worm_gate_evidence.py`;
- `verify_phillip_v6_live_canary_worm_gate_evidence.py`.

All complete LIVE-canary source CLIs add the required argument
`--worm-custody-policy-sha256`. The single-receipt sign and verify CLIs require
it only when `--domain WORM_CUSTODY` is selected.

No HTTP endpoint is introduced. `POST /api/live-canary/worm-gate` is a
reserved negative sentinel and MUST remain absent.

## Data Models

### Bridge Manifest

| Field | Type | Constraints |
|---|---|---|
| schema_version | string | Exact bridge V1 schema |
| status | string | Exact evidence-ready status |
| candidate_id | string | Exact `phillip-commodity` |
| toolkit | object | Exact lowercase source commit/tree |
| custody_request | object | Exact archive and request identities |
| acceptance | object | Exact archive and bundle identities |
| custodian | object | Exact policy, key fingerprint, receipt identity |
| remote_object | object | Exact provider/object hashes, mode, size, retention, versioning/WORM flags |
| assessment | object | Exact file/identity hashes and verified time |
| members | array | Four sorted path/size/SHA-256 rows |
| safety | object | All capability and mutation values disabled |
| content_sha256 | SHA-256 | Canonical manifest hash excluding itself |

### Source and Trust Inputs

| Input | Trust source | Rule |
|---|---|---|
| custody-request ZIP hash | external operator pin | Must match exact member bytes |
| toolkit commit/tree | external operator pins | Must reconstruct nested acceptance |
| custody-policy hash | external operator pin | Required again at every boundary |
| RSA public key | pinned canonical policy | 3072–8192 bits, exponent 65537 |
| custody receipt | independent custodian signature | Domain-separated RSA PKCS#1 v1.5 SHA-256 |
| WORM gate receipt | LIVE-canary trust policy | Independent domain HMAC over outer ZIP hash |

### Safety Projection

| Field | Exact value |
|---|---|
| order_capability | `DISABLED` |
| live_allowed | `false` |
| safe_to_demo_auto_order | `false` |
| promotion_eligible | `false` |
| execution_authorized | `false` |
| activation_authorized | `false` |
| task_scheduler_mutation | `NOT_PERFORMED` |
| broker_mutation | `NOT_PERFORMED` |

## Out of Scope

- OS-1: Producing or fabricating the actual scheduled Windows V6.3 run.
- OS-2: Uploading evidence to a storage provider or configuring Object Lock.
- OS-3: Creating custodian identities, keys, policies, signatures, or receipts.
- OS-4: Waiving independent review or accepting self-asserted legal evidence.
- OS-5: Counting V6 diagnostic shadow cycles as demo-auto cohort fills.
- OS-6: Broker eligibility, LIVE-account discovery, legal/compliance approval,
  human activation approval, or activation nonce consumption.
- OS-7: Provider-bound admission, provider-bound WORM custody, CAS readback,
  launch session, per-order authority, MT5 initialization, or broker order.
- OS-8: Generalizing the Phillip V6 adapter to XM, FINEX, or another broker
  without a separately reviewed semantic evidence adapter.
- OS-9: Changing any existing canonical LIVE-canary schema or weakening any
  current gate.

## Dependencies

- `windows_operator/phillip_commodity_v6_postrun_acceptance.py` for exact
  request, acceptance, policy, RSA receipt, and assessment reconstruction.
- `live_runtime/live_canary_gate_receipt_artifacts.py` for stable source reads,
  gate issuance, set assembly, and independent set verification.
- `live_runtime/live_canary_activation_artifacts.py` and
  `live_runtime/live_canary_activation_cli_support.py` for downstream source
  revalidation.
- Windows Credential Manager remains the only gate-HMAC secret provider.
- Python 3.12 standard-library `hashlib`, `hmac`, `json`, `tempfile`, and
  `zipfile` only; no new package dependency.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Self-selected RSA policy inside ZIP | False custody trust | Require independent policy hash on every verification |
| Assessment copied from another run | Wrong evidence accepted | Byte-identically regenerate it from all four source members |
| Retention expires before gate | Evidence can disappear during authority window | Compare exact remote retention to each receipt/request required-until |
| ZIP ambiguity or decompression abuse | Parser bypass or resource exhaustion | Exact paths/order, bounded members/expansion, CRC and trailing-byte rejection |
| Later workflow hashes without semantics | Semantic check bypass | Thread policy pin through preflight, request, consumption, inspection, recovery |
| Operator package leaks into runtime | Enlarged production attack surface | Allowlist only the deployment/operator tooling release |
| Bridge mistaken for trading readiness | Premature live order | Persist deny-only safety and document all later independent gates |

## Success Metrics

- SM-1: 100% of `WORM_CUSTODY` artifact issuance attempts using arbitrary
  files fail closed.
- SM-2: 100% of tested policy, receipt, assessment, archive, retention, source,
  and ZIP mutations fail before gate acceptance.
- SM-3: Two independent builds from identical fixtures have the same SHA-256.
- SM-4: Every complete gate/request/consumption CLI requires the external
  custody-policy pin.
- SM-5: Focused normal and optimized tests, full regression, compilation,
  release builders, static checks, and whitespace checks pass.
- SM-6: No test or implementation path imports MT5, contacts a broker, consumes
  execution authority, or submits an order.

## Testing Strategy

- Unit tests build valid deterministic custody fixtures with the existing V6
  test helpers and verify build/verify round trips.
- Negative tests mutate each source, external pin, nested policy/receipt,
  assessment, retention boundary, archive inventory, and publication path.
- Artifact tests prove generic gates remain unchanged while WORM rejects raw
  evidence and requires semantic bridge validation.
- Receipt-set and activation-source tests prove the policy pin is threaded
  through every revalidation path.
- CLI tests cover help, success, missing pin, wrong-domain pin, existing output,
  and deny-only diagnostics.
- Release tests prove inclusion only in Windows operator tooling and exclusion
  from every service release.
- The focused suite runs in normal and optimized Python; the complete serial
  suite and compile/static gates run before commit and packaging.

## Rollout Plan

1. Validate this spec and add RED tests for deterministic bridge verification.
2. Implement the bridge module and two deny-only CLIs.
3. Make single WORM receipt issuance and verification semantic.
4. Thread the independent policy pin through set, request, and consumption
   boundaries.
5. Update operator documentation and the deployment-tooling allowlist.
6. Run focused normal/optimized tests and all ship gates.
7. Commit and push one source change only after all local gates pass.
8. Build a deterministic Windows operator artifact without claiming external
   evidence exists.
9. After the real scheduled V6 run, external custody receipt, cohort evidence,
   and remaining independent approvals exist, continue through later gates.

## Open Questions

None. This V1 deliberately supports only the exact Phillip Commodity V6
custody contract and remains deny-only.
