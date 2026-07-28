# Windows Base-Release Suite Transfer v1

**Author:** OpenAI Codex
**Date:** 2026-07-28
**Status:** Approved
**Related specs:** `windows_atomic_base_release_suite_v1.md`,
`windows_base_suite_configured_release_binding_v1.md`

## Context

The atomic base-release builder publishes one directory containing five ZIP
archives, five canonical sidecars, and `BASE_RELEASE_SUITE.json`. Its internal
verification is strict, but copying eleven independent files to Windows has no
single transport identity. A partial copy, mixed directory, omitted sidecar,
or separately copied helper can therefore fail only after operator handling.

This feature wraps the exact verified directory in one deterministic ZIP. The
ZIP contains its own canonical transfer manifest and a PowerShell 5.1 helper.
The helper and Python verifier require an archive SHA-256, suite identity, full
Git commit, and full Git tree obtained through an independent channel. Values
read from the archive being verified are not independent pins.

The transfer boundary grants no provider acceptance, credential access,
Task Scheduler authority, MT5 initialization, demo-auto activation, broker
mutation, or order capability.

## Functional Requirements

- FR-1: The builder MUST accept one existing base-suite root, one new ZIP
  destination, and externally supplied suite identity, full Git commit, and
  full Git tree.
- FR-2: The builder MUST independently verify the complete eleven-file suite
  before reading it for packaging and MUST reject any pin mismatch.
- FR-3: The destination parent MUST exist, be a regular non-reparse directory,
  and remain the same filesystem object through publication. The destination
  MUST be outside the suite root and MUST not already exist.
- FR-4: The ZIP MUST contain exactly thirteen regular DEFLATE members: the
  eleven suite files beneath `base-release-suite-v1/`, one canonical
  `BASE_RELEASE_SUITE_TRANSFER.json`, and one
  `Verify-WindowsBaseReleaseSuiteTransfer.ps1`.
- FR-5: ZIP member order, timestamps, Unix modes, compression, paths, comments,
  and extra fields MUST be fixed and deterministic. Directory entries,
  encryption, path traversal, duplicates, case-fold collisions, unsupported
  compression, and reparse inputs MUST be rejected.
- FR-6: The canonical transfer manifest MUST bind every non-manifest member by
  path, exact size, and SHA-256. It MUST also bind the suite schema/profile,
  suite identity, suite-manifest SHA-256, Git commit/tree, role/file counts,
  verification contract, effects, and locked safety state.
- FR-7: `transfer_identity_sha256` MUST be SHA-256 over canonical transfer
  manifest fields excluding that identity.
- FR-8: The builder MUST stable-read every suite source before hashing and
  during ZIP construction. Source replacement or mutation MUST fail closed.
- FR-9: The builder MUST fully self-verify its private staged ZIP before an
  atomic no-replace publication and MUST remove only its own staging file on
  failure.
- FR-10: A public read-only Python verifier MUST require four external pins:
  transfer archive SHA-256, suite identity, full Git commit, and full Git tree.
- FR-11: The verifier MUST stable-open and hash the original archive, validate
  its exact ZIP/manifest/payload contract, materialize only the eleven suite
  files into a bounded private temporary root, run the existing complete suite
  verifier, compare all four pins, and remove the temporary root.
- FR-12: The configured-release tooling ZIP MUST include the transfer verifier
  and its exact stdlib-only verification closure so it runs under
  `python -I -S -B` after extraction.
- FR-13: The PowerShell 5.1 helper MUST verify the external archive hash,
  external suite/Git pins, extracted file/directory inventory, hashes, sizes,
  reparse state, and locked safety facts before invoking the bundled Python
  verifier under `-I -S -B`.
- FR-14: The helper MAY create and remove only a GUID-named private tooling
  extraction directory under the OS temporary directory. It MUST NOT overwrite
  the extracted transfer root or a pre-existing operator path.
- FR-15: Build and verification MUST expose no network, Git subprocess,
  provider import/materialization, credential, task/service, MT5, activation,
  permit, broker, or order primitive.
- FR-16: Success output MUST state the archive SHA-256, transfer identity,
  suite identity/manifest hash, Git commit/tree, role/member counts, and all
  safety locks. Public failures MUST use stable reason codes without traceback.

## Non-Functional Requirements

- NFR-1: Python implementation MUST use Python 3.12 standard-library
  primitives and the existing base-suite verifier only.
- NFR-2: JSON MUST be canonical UTF-8 with sorted keys, compact separators,
  `ensure_ascii=true`, `allow_nan=false`, and exactly one trailing LF.
- NFR-3: Archive and member reads MUST be bounded; a member MUST not exceed
  256 MiB, the archive MUST not exceed 1 GiB, and expanded content MUST not
  exceed 1.5 GiB.
- NFR-4: Two builds from the same exact suite and pins into different output
  filenames MUST be byte-identical.
- NFR-5: Verification MUST not depend on repository checkout state, network,
  credentials, MT5, Windows Task Scheduler, or broker availability.
- NFR-6: Normal and optimized test modes MUST exercise identical behavior.

## Acceptance Criteria

### AC-1: One-file deterministic transport

Given one valid externally pinned atomic base suite
When two transfer builds use distinct new output paths
Then each output directory contains exactly one ZIP
And both ZIP byte streams, archive hashes, and transfer identities are equal.

### AC-2: Complete independent verification

Given one valid transfer ZIP and four correct external pins
When the public verifier runs under `python -I -S -B`
Then all thirteen outer members and all eleven nested suite files verify
And all five nested roles pass the existing suite verifier
And success reports locked safety with no operational effect.

### AC-3: External pin denial

Given a valid transfer ZIP
When any archive, suite, commit, or tree pin is malformed or mismatched
Then verification fails before emitting a success report.

### AC-4: Transport tamper denial

Given an independently rehashed ZIP with an added, removed, replaced,
case-colliding, path-traversing, or metadata-drifted member
When verification runs with that new outer hash
Then the exact transfer contract still rejects it.

### AC-5: Nested-suite tamper denial

Given an outer manifest and payload inventory made internally consistent while
a nested archive, sidecar, manifest, safety value, or release identity is
invalid
When verification runs
Then the existing suite verifier rejects the transfer.

### AC-6: No overwrite or partial publication

Given an existing output, unsafe parent, source symlink/reparse point, source
mutation, build failure, or concurrent destination
When transfer construction runs
Then caller-owned bytes remain unchanged
And no successful output or partial staging artifact is reported.

### AC-7: PowerShell 5.1 operator verification

Given the outer ZIP was first matched to an independently delivered SHA-256
and expanded into a new root
When the included helper receives the same four pins and exact Python path
Then it verifies extracted inventory and executes only the bundled verifier
under `-I -S -B`
And it reports the nested suite root without installing or starting anything.

### AC-8: Safety invariants

Given any accepted or rejected transfer
When source, manifest, CLI, and helper surfaces are inspected
Then `live_allowed=false`, `safe_to_demo_auto_order=false`,
`promotion_eligible=false`, `max_lot=0.01`, and
`order_capability=DISABLED_AT_TRANSFER_BOUNDARY`
And production execution readiness remains false.

## Edge Cases

- EC-1: Archive or destination path is missing, symlinked, reparsed, oversized,
  or not a regular file/directory → reject.
- EC-2: Destination already exists or appears during publication → reject and
  preserve it.
- EC-3: Transfer manifest has duplicate/unknown keys, invalid UTF-8,
  non-finite data, wrong LF, or non-canonical bytes → reject.
- EC-4: ZIP has a directory member, comment, extra data, unsupported method,
  wrong timestamp/mode, duplicate offset, encryption flag, or unsafe path →
  reject.
- EC-5: Payload row order differs from the exact fixed path order → reject.
- EC-6: Payload size/hash differs from archive content → reject.
- EC-7: The nested configured-tooling ZIP lacks the transfer verifier → the
  PowerShell helper fails closed before reporting success.
- EC-8: PowerShell converts a one-item JSON list to a scalar → helper wraps
  every converted inventory in `@(... | ForEach-Object { $_ })`.
- EC-9: Temporary tooling root collision → reject; never overwrite.
- EC-10: Verification fails after temporary extraction → remove only the
  GUID-named private temporary root and preserve the transfer evidence.

## API Contracts

```python
def build_base_release_suite_transfer(
    suite_root: pathlib.Path,
    output: pathlib.Path,
    *,
    expected_suite_identity_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
) -> dict[str, object]:
    """Build and self-verify one deterministic transfer archive."""

def verify_base_release_suite_transfer(
    archive_path: str | pathlib.Path,
    *,
    expected_archive_sha256: str,
    expected_suite_identity_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
) -> VerifiedBaseReleaseSuiteTransfer:
    """Verify one transfer archive against four independent pins."""
```

```text
python -B build_windows_base_release_suite_transfer.py \
  --suite-root <verified-suite-root> \
  --output <new-transfer.zip> \
  --expected-suite-identity-sha256 <external-pin> \
  --expected-git-commit <external-pin> \
  --expected-git-tree <external-pin>

python -I -S -B verify_windows_base_release_suite_transfer.py \
  --archive <transfer.zip> \
  --expected-archive-sha256 <external-pin> \
  --expected-suite-identity-sha256 <external-pin> \
  --expected-git-commit <external-pin> \
  --expected-git-tree <external-pin>
```

Public error families:

```text
BASE_RELEASE_SUITE_TRANSFER_REJECTED: <STABLE_REASON>
BASE_RELEASE_SUITE_TRANSFER_VERIFICATION_REJECTED: <STABLE_REASON>
```

## Out of Scope

- Provider pack preparation, import, materialization, or conformance approval.
- Credential provisioning, ACL changes, task/service installation, or launch.
- MT5 initialization, market reads, broker writes, or order submission.
- Manual-demo authorization, demo-auto activation, soak, or live promotion.
- Claiming a macOS reference build is the exact Windows production build.
- Replacing independent custody of the four expected verification pins.
