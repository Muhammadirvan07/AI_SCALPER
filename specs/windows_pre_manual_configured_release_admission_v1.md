# Spec: Windows Pre-Manual Configured-Release Admission v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-24
**Status:** Approved
**Reviewers:** AI_SCALPER project owner (standing authorization to continue the
roadmap while preserving all execution locks)
**Related specs:** `specs/windows_configured_service_release_v1.md`,
`specs/windows_three_service_demo_soak_operations_v3.md`,
`specs/windows_three_service_external_acceptance_v1.md`,
`specs/windows_manual_demo_entry_review_v1.md`

## Context

The configured-release verifier reconstructs one decision, execution, or
status-monitor ZIP without importing its provider. Separately, the pre-manual
entry verifier reconstructs the signed three-service operations bundle and
assesses the nine externally signed prerequisites that must precede controlled
manual demo. Both boundaries are strict, but the operator currently invokes
them independently.

Independent commands leave an artifact-substitution gap at the handoff. A
valid configured ZIP can be verified without proving that it is the exact ZIP
whose configured and base identities, archive hash, manifest hash, factory
contract, service configuration, Task Scheduler review, and Git source were
bound into the signed operations bundle. Conversely, the signed dossier can be
valid without re-reading the three ZIP files that will actually be extracted.
An operator can therefore select the wrong but individually valid archive.

This feature adds one report-only admission boundary. It reads each configured
archive exactly once using stable regular-file checks, independently verifies
its complete deterministic inventory, binds the verified bytes to the exact
three-service review, then performs the existing signed pre-manual assessment.
It never imports a configured provider, reads a credential, initializes MT5,
installs a task, launches a process, changes execution policy, or submits an
order.

## Functional Requirements

- FR-1: The admission verifier MUST reconstruct the exact v3 three-service
  operations review bundle before trusting any release identity from it.
- FR-2: The verifier MUST read the decision, execution, and status-monitor
  configured ZIP files as regular, non-symlink/non-reparse, non-empty,
  bounded, stable files and MUST pass those exact bytes to the existing
  configured-release verifier.
- FR-3: Each configured archive MUST match the role-specific base profile,
  configured release identity, base release identity, runtime mode, archive
  SHA-256, manifest SHA-256, Git commit, and Git tree bound by the verified
  operations plan.
- FR-4: Each configured archive MUST match the plan's factory-contract
  SHA-256, factory-manifest file SHA-256, runtime-configuration file SHA-256,
  and reviewed Task Scheduler definition SHA-256.
- FR-5: Decision, execution, and status-monitor role assignments MUST be exact
  and MUST NOT be caller-selectable, reorderable, or inferred from filenames.
- FR-6: After all three archives verify, the admission verifier MUST call the
  existing Windows pre-manual entry verifier with the exact review bundle,
  public trust policy, signed observations, externally pinned policy SHA-256,
  and trusted clock provider.
- FR-7: A complete result MUST bind the exact three archive hashes, three
  manifest hashes, base/configured identities, factory contracts, service
  configurations, task-definition hashes, review bundle, trust policy,
  pre-manual review SHA-256, checked time, Git commit/tree, broker binding, and
  accepted gate inventory.
- FR-8: Incomplete signed pre-manual evidence MAY produce a deterministic
  blocked admission report, but an invalid or mismatched archive, role,
  profile, identity, hash, Git source, factory, configuration, task, review,
  policy, or signature MUST reject the admission without an output.
- FR-9: A complete report MUST use status
  `PRE_MANUAL_CONFIGURED_RELEASE_ADMISSION_COMPLETE_ACTIVATION_REVIEW_REQUIRED`
  and MAY request a separate human manual-demo activation review only when the
  existing pre-manual review is complete.
- FR-10: Every report MUST retain `manual_demo_authorized=false`,
  `activation_authorized=false`, `execution_enabled=false`,
  `ready_for_demo_auto_soak=false`, `safe_to_demo_auto_order=false`,
  `live_allowed=false`, `promotion_eligible=false`,
  `order_capability=DISABLED`, and `max_lot=0.01`.
- FR-11: The CLI MUST accept only three configured-release paths, the immutable
  review bundle, public trust policy, signed observations, independently
  pinned policy SHA-256, trusted canonical UTC, and an optional create-only
  output path.
- FR-12: The implementation MUST NOT load a private key, sign evidence, accept
  a password/login/token/credential value, import a configured provider,
  materialize a factory, install or start a task, launch a service, initialize
  MT5, issue stage/permit/arm authority, mutate execution policy, or call a
  broker.
- FR-13: The module and CLI MUST exist only in release-operator tooling and
  MUST be absent from decision, execution, status-monitor, configured-service
  runtime, and read-only-shadow release inventories.
- FR-14: Optional output MUST be create-exclusive and MUST not be written if
  any input changes, fails verification, or mismatches the signed plan.
- FR-15: Existing configured-release, operations-bundle, external-acceptance,
  and pre-manual-entry semantics MUST remain unchanged.

## Non-Functional Requirements

- NFR-1: Identical archive bytes, signed public inputs, and trusted UTC MUST
  produce byte-identical canonical report content and SHA-256.
- NFR-2: Each archive MUST be at most 64 MiB and contain at most the limits
  already enforced by the configured-release verifier.
- NFR-3: Every timestamp MUST be timezone-aware UTC; the CLI MUST accept only
  canonical text containing six fractional digits and a trailing `Z`.
- NFR-4: The admission operation MUST perform no network, subprocess, broker,
  credential, scheduler, service-control, or environment-variable I/O.
- NFR-5: A maximum-size valid input set MUST complete in no more than five
  seconds on the development test host, excluding filesystem scheduling
  variance.
- NFR-6: Every rejection MUST use a stable uppercase reason code and MUST not
  expose archive contents, secrets, raw account identifiers, or signature
  material.
- NFR-7: Focused tests MUST pass under normal Python and
  `PYTHONOPTIMIZE=2`; the complete repository regression suite, compilation,
  release-boundary checks, dependency lock, and SBOM verification MUST remain
  green.

## Acceptance Criteria

### AC-1: Exact archives and exact signed dossier are admitted for review (FR-1 through FR-7, FR-9, FR-10)

Given three valid configured archives whose exact bytes and immutable
identities match one verified v3 operations bundle
And valid signed observations for all nine pre-manual gates
When the admission verifier evaluates the inputs at trusted UTC
Then it reports
`PRE_MANUAL_CONFIGURED_RELEASE_ADMISSION_COMPLETE_ACTIVATION_REVIEW_REQUIRED`
And binds every archive, manifest, release, factory, configuration, task, Git,
broker, review, policy, and gate identity
And all execution, activation, demo-auto, promotion, and live flags remain
false.

### AC-2: Missing signed evidence remains visibly blocked (FR-6, FR-8, FR-10)

Given all three exact configured archives are valid
And one or more pre-manual observations are missing, failed, future, or expired
When the admission verifier evaluates the inputs
Then it reports `BLOCKED_PRE_MANUAL_CONFIGURED_RELEASE_ADMISSION`
And retains the exact pending gates and reasons
And does not request activation review.

### AC-3: Configured archive substitution fails closed (FR-2 through FR-5, FR-8, FR-14)

Given an individually valid configured ZIP from a different role, build,
overlay, configured identity, or base identity
When it is supplied in any archive slot
Then admission rejects with a deterministic release-binding reason
And no report or output is produced.

### AC-4: Byte, manifest, and plan binding drift fails closed (FR-2 through FR-4, FR-8)

Given a configured archive or signed plan whose archive hash, manifest hash,
Git commit/tree, factory contract, factory-manifest hash, runtime-config hash,
or task-definition hash differs
When admission runs
Then it rejects before requesting human review.

### AC-5: Archive input is read atomically (FR-2, FR-14, NFR-2)

Given an archive path is a symlink/reparse point, directory, empty, oversized,
or changes between stat/open/read/fstat checks
When admission reads it
Then it rejects with a stable archive-input reason
And never verifies or hashes a different byte sequence.

### AC-6: Signed dossier integrity remains mandatory (FR-1, FR-6, FR-8, FR-15)

Given exact configured archives but a mismatched policy pin, invalid RSA
signature, wrong gate owner, changed review bundle, or noncanonical public
document
When admission runs
Then the existing strict verifier rejects it
And no weaker local boolean can replace the missing proof.

### AC-7: CLI is report-only and create-exclusive (FR-10, FR-11, FR-12, FR-13, FR-14, NFR-3, NFR-4)

Given valid admission inputs and a new output path
When the CLI runs
Then it writes one canonical deny-only report
And a second run to the same path fails without changing the first file
And its arguments/imports expose no authority, secret, task, process, MT5, or
broker-mutation surface.

### AC-8: Packaging isolates the verifier (FR-12, FR-13)

Given all release allowlists
When static release-boundary tests inspect them
Then the module and CLI occur only in operator tooling
And no production service can import or invoke the admission verifier.

### AC-9: Determinism and resource bounds hold (NFR-1, NFR-2, NFR-5)

Given repeated valid inputs
When admission runs more than once
Then canonical reports and content hashes are identical
And each run completes within the measurable bound.

### AC-10: Full safety regression remains green (FR-10, FR-15, NFR-7)

Given the completed implementation
When focused, optimized, compilation, release-policy, dependency, SBOM, and
full regression checks execute
Then every check passes
And checked-in execution locks remain unchanged.

## Edge Cases

- EC-1: The same archive path is supplied for two roles → role/profile or
  identity binding rejects it.
- EC-2: A valid base release ZIP is supplied instead of a configured ZIP →
  configured manifest verification rejects it.
- EC-3: ZIP bytes are valid but archive SHA-256 differs from the signed plan →
  reject `*_ARCHIVE_SHA256_MISMATCH`.
- EC-4: Manifest identity is valid but the manifest file hash differs from the
  signed plan → reject `*_MANIFEST_SHA256_MISMATCH`.
- EC-5: Configured and base identities match the plan but the factory manifest,
  service config, or Task Scheduler hash differs → reject the corresponding
  role binding.
- EC-6: The configured verifier returns the wrong profile or any runtime mode
  other than exact `DEMO_AUTO` → reject before signed-evidence assessment.
- EC-7: All archives match while the manual-demo result observation is already
  present → the existing pre-manual boundary rejects it.
- EC-8: One signed pre-manual observation expires while archive verification
  is running → the existing post-verification trusted-clock check leaves it
  pending or rejects clock regression.
- EC-9: Input changes after it was opened but retains the same length → stable
  file identity/mtime checks reject it.
- EC-10: Optional output exists, is a symlink, or has an unsafe parent → fail
  without overwrite.
- EC-11: A report object is directly constructed by a caller without the
  admission seal → reject construction.
- EC-12: A configured ZIP contains a provider with an unsafe import, dynamic
  code loading, native extension, embedded secret, or broker primitive →
  existing configured-release verification rejects it before admission.

## API Contracts

No HTTP, network, broker, scheduler, service-control, or signing API is
introduced.

```python
def assess_windows_pre_manual_configured_release_admission(
    *,
    decision_archive: str | Path,
    execution_archive: str | Path,
    status_monitor_archive: str | Path,
    review_bundle: Mapping[str, object],
    trust_policy: ThreeServiceAcceptanceTrustPolicy,
    observations: Sequence[ThreeServiceAcceptanceObservation],
    expected_policy_sha256: str,
    clock_provider: Callable[[], datetime],
) -> WindowsPreManualConfiguredReleaseAdmission: ...
```

Command contract:

```text
python -B verify_windows_pre_manual_configured_release_admission.py \
  --decision-release <decision-configured.zip> \
  --execution-release <execution-configured.zip> \
  --status-monitor-release <status-monitor-configured.zip> \
  --review-bundle <three-service-review-v3.json> \
  --trust-policy <public-policy.json> \
  --observations <pre-manual-observations.json> \
  --expected-policy-sha256 <externally-pinned-sha256> \
  --checked-at-utc <canonical-UTC-Z> \
  [--output <new-report.json>]
```

Exit code `0` means all immutable inputs were structurally and
cryptographically assessed; callers MUST inspect the report status. Exit code
`2` means admission failed and no report is trustworthy.

## Data Models

### `VerifiedConfiguredArchiveBinding`

| Field | Type | Constraints |
|---|---|---|
| role | enum | Decision, execution, or status monitor |
| release_profile | enum | Exact role-specific configured profile |
| runtime_mode | enum | Exactly `DEMO_AUTO` |
| archive_sha256 | SHA-256 | Exact stable ZIP bytes |
| manifest_sha256 | SHA-256 | Exact canonical manifest member |
| base_release_identity_sha256 | SHA-256 | Exact signed-plan base identity |
| release_identity_sha256 | SHA-256 | Exact signed-plan configured identity |
| factory_contract_sha256 | SHA-256 | Exact configured factory contract |
| factory_manifest_sha256 | SHA-256 | Exact factory-manifest file |
| runtime_configuration_sha256 | SHA-256 | Exact service-config file |
| task_definition_sha256 | SHA-256 | Exact reviewed task definition |
| git_commit | Git SHA | Exact common source commit |
| git_tree | Git SHA | Exact common source tree |

### `WindowsPreManualConfiguredReleaseAdmission`

| Field | Type | Constraints |
|---|---|---|
| checked_at_utc | UTC datetime | Exact signed assessment time |
| plan_sha256 | SHA-256 | Reconstructed operations plan |
| review_bundle_sha256 | SHA-256 | Exact signed bundle |
| trust_policy_sha256 | SHA-256 | Exact externally pinned policy |
| pre_manual_entry_review_sha256 | SHA-256 | Existing signed-evidence review |
| configured_archives | tuple | Exactly three role bindings |
| accepted_pre_manual_gates | tuple[string] | Sorted accepted gate inventory |
| pending_pre_manual_gates | tuple[string] | Sorted pending gate inventory |
| pending_reasons | mapping | Exact reason for every pending gate |
| status | enum | Complete-review-required or blocked |
| configured_archives_verified | bool | Always true for a report |
| external_preconditions_complete | bool | True only with all nine gates |
| manual_demo_activation_review_required | bool | True only for complete admission |
| safety fields | fixed | No execution, activation, promotion, or live authority |
| content_sha256 | derived | Canonical immutable report hash |

## Out of Scope

- OS-1: Creating, signing, or storing a trust policy, gate observation, private
  key, password, login, token, credential, permit, arm flag, or stage
  authorization.
- OS-2: Providing or accepting concrete provider behavior, importing provider
  modules, or materializing a factory.
- OS-3: Installing, editing, starting, or stopping Task Scheduler definitions,
  Windows services, processes, MT5 terminals, orders, or positions.
- OS-4: Enabling `SAFE_TO_DEMO_AUTO_ORDER`, `LIVE_ALLOWED`, production
  readiness, promotion, manual-demo authority, or demo-auto soak.
- OS-5: Replacing independent release receipt, launcher, ACL, provider,
  Windows hardening, risk-feasibility, failure-drill, or human review evidence.
- OS-6: Generating the tenth controlled-manual-demo observation or claiming
  that the ten lifecycles have occurred.
- OS-7: Building the later human-approved activation release.
- OS-8: Satisfying elapsed broker sessions, forward/OOS trade counts, demo
  soak duration/fills, statistical lane gates, live canary, or pair expansion.
