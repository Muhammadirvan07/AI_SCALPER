# Windows Base-Suite Configured-Release Binding v1

**Author:** OpenAI Codex  
**Date:** 2026-07-25  
**Status:** Approved  
**Reviewers:** AI_SCALPER owner through the approved Live-Grade v1 roadmap  
**Related specs:** `windows_atomic_base_release_suite_v1.md`,
`windows_base_release_suite_transfer_v1.md`,
`windows_configured_service_release_v1.md`,
`windows_pre_manual_configured_release_admission_v1.md`

## Context

AI_SCALPER creates one atomic five-role Windows base-release suite. The
configured-service builder and pre-manual admission boundary still verify the
decision, execution, and status-monitor releases individually. They require a
common Git commit/tree and exact signed identities, but they do not prove that
each configured release descended from the corresponding role in one exact
`BASE_RELEASE_SUITE.json`.

That leaves a provenance gap: individually valid base archives can be selected
outside the atomic suite. Common Git facts alone do not prove suite membership
or the presence and integrity of the read-only shadow and configured-release
tooling roles.

This feature adds a reusable offline base-suite verifier and makes suite
membership mandatory for the roadmap-supported configured-release CLI and
pre-manual admission. The configured archive records the suite identity,
manifest hash, and role. Pre-manual admission independently re-verifies all
five suite artifacts and rejects configured archives that do not descend from
their exact role records.

The feature grants no provider acceptance, credential access, service
activation, demo-auto authority, or broker capability.

## Functional Requirements

- FR-1: A reusable verifier MUST accept one existing base-suite root and MUST
  stable-read `BASE_RELEASE_SUITE.json` plus exactly five fixed archives and
  five fixed sidecars.
- FR-2: The verifier MUST reject a missing, non-directory, symlink/reparse,
  path-traversing, oversized, empty, unstable, or non-canonical input.
- FR-3: The suite manifest MUST have the exact v1 schema/profile, exact
  top-level keys, exact five-role order, exact fixed filenames, one common
  Git commit/tree, exact locked effects, exact locked safety values, and a
  valid recomputed suite identity.
- FR-4: Every archive and sidecar MUST match the size and SHA-256 recorded by
  the suite manifest. Every sidecar MUST be canonical JSON and MUST match its
  role record for release profile, commit, tree, release identity, source-file
  count, order capability, production readiness, and locked safety values.
- FR-5: Every ZIP MUST be deterministic and safe: regular DEFLATE members
  only, fixed timestamps and permissions, no duplicate/case-fold collision,
  traversal, directory, encrypted, unsupported compression, or unexpected
  manifest-member behavior. The embedded release manifest MUST equal its
  sidecar byte-for-byte.
- FR-6: The configured-service CLI MUST require
  `--base-release-suite-root`. It MUST reject a base archive that is not the
  exact decision, execution, or status-monitor archive named by the verified
  suite.
- FR-7: A suite-bound configured release MUST retain all existing configured
  validation and MUST add an exact binding containing suite schema, suite
  profile, suite identity, suite-manifest SHA-256, suite role, role archive
  SHA-256, and role sidecar SHA-256.
- FR-8: The configured-release verifier MUST validate the complete suite
  binding structure and expose it in its sealed report. Legacy configured
  releases MAY remain independently verifiable for diagnostics, but MUST NOT
  satisfy pre-manual admission.
- FR-9: Pre-manual configured-release admission MUST require one
  `base_release_suite_root`, independently verify all five artifacts, and
  require the three configured releases to bind the same suite identity and
  exact corresponding role records.
- FR-10: Pre-manual admission MUST reject a missing suite binding, a different
  suite, a mismatched suite role, archive hash, sidecar hash, profile,
  identity, commit, tree, or caller-supplied archive outside the verified
  suite ancestry.
- FR-11: The pre-manual report MUST bind the base-suite identity and manifest
  SHA-256. Those fields MUST participate in its content hash and sealed data
  model.
- FR-12: All new verification/build paths MUST retain
  `live_allowed=false`, `safe_to_demo_auto_order=false`, `max_lot=0.01`,
  `promotion_eligible=false`, and MUST NOT change
  `production_execution_ready=false`.
- FR-13: The feature MUST NOT import/materialize a provider, read a credential,
  access the network, install/start a task or service, initialize MT5, mutate a
  broker, issue a permit, arm an environment, or submit an order.
- FR-14: Existing configured-release verification behavior not related to
  suite provenance MUST remain unchanged. The exact Windows operational path
  documented for demo-auto MUST use the suite-bound CLI and admission.
- FR-15: Public failures MUST use stable reason codes and MUST NOT leak
  credentials, private evidence, or internal tracebacks.
- FR-16: A public read-only CLI MUST verify one existing suite against an
  independently pinned suite identity, full Git commit, and full Git tree.
  It MUST reject invalid or mismatched pins before emitting a success report,
  and it MUST be included in configured-release operator tooling.

## Non-Functional Requirements

- NFR-1: The implementation MUST use Python 3.12 standard-library primitives
  and existing local configured-release validation only.
- NFR-2: JSON MUST use canonical UTF-8 encoding with sorted keys, compact
  separators, `ensure_ascii=true`, `allow_nan=false`, and one trailing LF for
  files.
- NFR-3: File reads MUST use open/read/fstat consistency checks and bounded
  sizes.
- NFR-4: The verifier MUST be deterministic and read-only.
- NFR-5: The new source surface MUST contain no network, credential, scheduler,
  MT5, broker-order, signing-key, or activation primitive.
- NFR-6: Tests MUST run without Windows, MT5, network, credentials, providers,
  or broker access.

## Acceptance Criteria

### AC-1: Valid five-role suite verification (FR-1, FR-2, FR-3, FR-4, FR-5)

Given one valid atomic base-suite directory
When the verifier reads it
Then all five fixed artifacts and sidecars are revalidated
And the returned sealed report binds their exact hashes, identities, commit,
tree, safety, effects, and suite identity.
And the public CLI emits success only when the verified identity, commit, and
tree match three independently supplied pins.

### AC-2: Suite-bound configured release (FR-6, FR-7, FR-8)

Given a valid base suite, the exact decision base ZIP, and a valid reviewed
overlay
When the configured-release CLI runs with the suite root
Then the configured archive is deterministic
And its manifest binds the exact suite and decision role
And independent verification exposes the same suite binding.

### AC-3: Non-member and role substitution denial (FR-6, FR-10)

Given a valid suite but an archive copied from another suite or role
When configured construction or pre-manual admission is attempted
Then the operation fails before producing authority.

### AC-4: Complete ancestry at pre-manual admission (FR-9 through FR-11)

Given three exact suite-bound configured releases and the signed review dossier
When admission is assessed
Then all five base-suite artifacts are independently verified
And all three configured releases bind the matching roles in the same suite
And the report content hash includes the suite identity and manifest hash.

### AC-5: Legacy configured release denied by admission (FR-8, FR-9)

Given an individually valid configured release without a suite binding
When it is supplied to pre-manual admission
Then admission fails closed even if commit/tree and configured identities
otherwise match.

### AC-6: Tamper and instability denial (FR-2 through FR-5, FR-10)

Given a modified, missing, replaced, unstable, symlinked/reparse, malformed,
oversized, or non-canonical suite artifact
When verification occurs
Then it fails with a stable reason code and no report is emitted.

### AC-7: Safety and effects remain locked (FR-12, FR-13, FR-15)

Given any success or rejection
When the output and source surface are inspected
Then all safety locks remain unchanged
And no provider, credential, network, scheduler, service, MT5, broker,
activation, permit, or order effect occurred.

### AC-8: Regression and optimized mode (FR-14; NFR-6)

Given normal Python and `PYTHONOPTIMIZE=2`
When focused and full repository tests run
Then behavior is identical and all pre-existing unrelated tests pass.

## Edge Cases

- EC-1: Suite root or manifest is missing → reject.
- EC-2: Suite root, manifest, archive, or sidecar is a symlink/reparse point →
  reject.
- EC-3: Suite manifest has duplicate/unknown keys, invalid UTF-8, non-finite
  values, bad LF, or non-canonical bytes → reject.
- EC-4: Role order, filename, profile, identity, capability, safety, or
  readiness drifts → reject.
- EC-5: Archive member is encrypted, compressed, executable, path-traversing,
  duplicated, case-colliding, or has a non-deterministic timestamp → reject.
- EC-6: Embedded manifest differs from the sidecar → reject.
- EC-7: A suite artifact changes between stat/read/fstat → reject.
- EC-8: Configured base path names the right bytes through a symlink or path
  alias → reject.
- EC-9: Three configured releases bind two different suite identities →
  reject.
- EC-10: Suite identity matches but one configured role/hash does not → reject.
- EC-11: A legacy configured release has no suite binding → verification may
  report it as legacy, but pre-manual admission rejects it.
- EC-12: An external suite-identity, commit, or tree pin is malformed or does
  not match the verified suite → the CLI rejects without a partial report.

## API Contracts

HTTP API: N/A. The documentation-only validator marker
`GET /not-applicable` MUST NOT be implemented or exposed.

```python
@dataclass(frozen=True)
class VerifiedBaseReleaseSuite:
    root: pathlib.Path
    manifest_sha256: str
    suite_identity_sha256: str
    git_commit: str
    git_tree: str
    roles: tuple[VerifiedBaseReleaseSuiteRole, ...]

def verify_base_release_suite(
    suite_root: str | pathlib.Path,
) -> VerifiedBaseReleaseSuite:
    """Read-only verification of one exact five-role base suite."""

def build_configured_service_release(
    base_archive: str | pathlib.Path,
    overlay_root: str | pathlib.Path,
    descriptor_path: str | pathlib.Path,
    output_path: str | pathlib.Path,
    *,
    base_release_suite_root: str | pathlib.Path | None = None,
    manifest_output_path: str | pathlib.Path | None = None,
) -> dict[str, object]:
    """Build a configured release; the production CLI requires suite binding."""

def assess_windows_pre_manual_configured_release_admission(
    *,
    base_release_suite_root: str | pathlib.Path,
    decision_archive: str | pathlib.Path,
    execution_archive: str | pathlib.Path,
    status_monitor_archive: str | pathlib.Path,
    review_bundle: Mapping[str, object],
    trust_policy: ThreeServiceAcceptanceTrustPolicy,
    observations: Sequence[ThreeServiceAcceptanceObservation],
    expected_policy_sha256: str,
    clock_provider: Callable[[], datetime],
) -> WindowsPreManualConfiguredReleaseAdmission:
    """Verify suite ancestry and exact configured releases, then assess gates."""
```

CLI additions:

```text
python -I -S -B verify_windows_base_release_suite.py \
  --suite-root <exact-suite-root> \
  --expected-suite-identity-sha256 <externally-pinned-sha256> \
  --expected-git-commit <externally-pinned-full-commit> \
  --expected-git-tree <externally-pinned-full-tree>

python -B build_windows_configured_service_release.py \
  --base-release-suite-root <exact-suite-root> \
  --base-release <suite-role.zip> \
  --overlay-root <reviewed-overlay> \
  --descriptor <descriptor.json> \
  --output <configured.zip>

python -B verify_windows_pre_manual_configured_release_admission.py \
  --base-release-suite-root <exact-suite-root> \
  --decision-release <decision-configured.zip> \
  --execution-release <execution-configured.zip> \
  --status-monitor-release <status-monitor-configured.zip> \
  ...
```

Public reason-code families:

```text
BASE_RELEASE_SUITE_VERIFICATION_REJECTED: <STABLE_REASON>
WINDOWS_CONFIGURED_SERVICE_RELEASE_REJECTED: <STABLE_REASON>
WINDOWS_PRE_MANUAL_CONFIGURED_RELEASE_ADMISSION_REJECTED: <STABLE_REASON>
```

## Data Models

`configured_release.base_release_suite`:

| Field | Type | Constraint |
|---|---|---|
| schema_version | string | Fixed suite-binding v1 |
| suite_schema_version | string | Atomic base-suite v1 |
| suite_release_profile | string | Exact atomic suite profile |
| suite_identity_sha256 | SHA-256 | Recomputed suite identity |
| suite_manifest_sha256 | SHA-256 | Exact canonical manifest bytes |
| role | enum | DECISION / EXECUTION / STATUS_MONITOR |
| role_archive_sha256 | SHA-256 | Exact suite role archive |
| role_sidecar_sha256 | SHA-256 | Exact suite role sidecar |

The pre-manual report adds:

| Field | Type | Constraint |
|---|---|---|
| base_release_suite_identity_sha256 | SHA-256 | Exact common suite |
| base_release_suite_manifest_sha256 | SHA-256 | Exact verified manifest |
| base_release_suite_verified | bool | Always true for a report |

## Out of Scope

- OS-1: Provider implementation or provider acceptance.
- OS-2: Credential provisioning or access.
- OS-3: Task/service installation or launch.
- OS-4: MT5 initialization, account login, broker reads, or order submission.
- OS-5: Manual-demo authorization, demo-auto activation, live promotion, or lot
  scaling.
- OS-6: Dashboard integration; it remains after demo-auto soak works.
