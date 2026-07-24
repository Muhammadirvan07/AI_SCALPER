# Windows Atomic Base-Release Suite v1

**Author:** OpenAI Codex  
**Date:** 2026-07-25  
**Status:** Approved  
**Reviewers:** AI_SCALPER owner through the approved Live-Grade v1 roadmap  
**Related specs:** `windows_three_service_demo_soak_operations_v3.md`,
`mt5_readonly_decision_feed_publisher_v1.md`,
`architecture_foundation_completion_v1.md`

## Context

AI_SCALPER has deterministic builders for the decision, gated execution,
external status-monitor, read-only shadow, and configured-release operator
tooling archives. Those builders are currently invoked separately. A separate
command sequence can omit a role, mix artifacts from different Git commits,
or leave a partially published release directory after a later build fails.
The risk increased when the finalized-M15 MT5 publisher entered the read-only
shadow closure: the historical three-service ZIP set no longer represents the
complete base-release input required by pre-manual admission.

This feature creates one fail-closed, local-only orchestration boundary for the
five exact base artifacts. It does not replace any role-specific builder or
weaken their validation. It adds an atomic suite manifest that proves all
archives and sidecars came from one clean commit and tree and retain the
locked safety state.

The suite is build evidence only. Windows provider materialization,
credentials, Task Scheduler installation, MT5 initialization, broker access,
stage authorization, demo-auto activation, and live trading remain external
and explicitly blocked.

## Functional Requirements

- FR-1: The suite builder MUST require one clean Git worktree with no tracked,
  staged, or untracked changes before invoking any role builder.
- FR-2: The suite builder MUST require an output root outside the source
  repository, MUST reject a symlinked output root or parent, and MUST reject an
  output root that already exists.
- FR-3: The suite builder MUST build exactly five roles: `DECISION`,
  `EXECUTION`, `STATUS_MONITOR`, `READ_ONLY_SHADOW`, and
  `CONFIGURED_RELEASE_TOOLING`.
- FR-4: Each role MUST use its fixed existing builder, fixed versioned
  allowlist, and fixed archive filename. Caller-supplied role lists, builders,
  allowlists, or filenames MUST NOT be accepted by the CLI.
- FR-5: All role builders MUST write into a private staging directory on the
  same filesystem as the final output root. The final root MUST be published
  with one OS-level atomic no-replace rename only after every role and the
  suite manifest pass validation. An output root created concurrently MUST
  never be replaced, including when it is an empty directory.
- FR-6: The suite builder MUST stable-read every archive and sidecar produced
  in staging and MUST bind their exact sizes and SHA-256 values.
- FR-7: Every role sidecar MUST be strict canonical JSON and MUST contain the
  expected release profile, the same exact Git commit and tree, the expected
  role safety values, and a valid 64-lowercase-hex release identity.
- FR-8: Every role MUST retain `live_allowed=false`,
  `safe_to_demo_auto_order=false`, and `max_lot=0.01`. `EXECUTION` MUST report
  `order_capability=GATED_PRESENT`; all other roles MUST report
  `order_capability=DISABLED`. No role MAY report
  `production_execution_ready=true`.
- FR-9: The suite builder MUST emit one canonical
  `BASE_RELEASE_SUITE.json` containing fixed schema/profile values, Git
  commit/tree, all five role records, explicit packaging/runtime effect facts,
  and a
  `suite_identity_sha256` computed over the manifest excluding that identity.
- FR-10: The suite builder MUST re-check Git commit, tree, and clean worktree
  state after all staged artifacts are validated and immediately before the
  final atomic rename.
- FR-11: Any failure MUST remove the private staging directory, MUST leave the
  requested final output root absent, and MUST return one stable public reason
  code without leaking secret values or an internal traceback.
- FR-12: The suite builder MAY launch only the local `git` executable required
  by the existing deterministic builders to prove commit/tree/worktree facts.
  It MUST NOT perform network access, provider import or materialization,
  credential access, environment arming, task installation, runtime/service
  process launch, MT5 initialization, broker mutation, stage authorization, or
  permit issuance.
- FR-13: The CLI MUST require `--output-root`, MUST provide no order-enabling
  option, and MUST print the suite manifest path, suite identity, commit, tree,
  and each role archive SHA-256 on success.
- FR-14: Repeated successful builds from the same clean commit and tree into
  two distinct roots MUST produce byte-identical archives, sidecars, and suite
  manifests.
- FR-15: The suite manifest and each role sidecar MUST be included in the final
  output root. No source file, credential, runtime state, provider overlay, or
  validation artifact MAY be copied outside those fixed outputs.
- FR-16: The builder MUST reject a role result whose returned archive,
  sidecar, identity, file count, capability, or readiness fact disagrees with
  the bytes independently read from staging.

## Non-Functional Requirements

- NFR-1: The orchestration implementation MUST use only the Python 3.12
  standard library and existing repository builders.
- NFR-2: All JSON hashing MUST use UTF-8 canonical JSON with sorted keys,
  compact separators, `ensure_ascii=true`, and no non-finite number.
- NFR-3: Every staged archive and sidecar MUST be stable-read with
  open/read/fstat consistency checks before hashing.
- NFR-4: The suite MUST be deterministic across Windows and macOS for one
  clean Git commit and tree, subject to the existing role-builder contracts.
- NFR-5: Error cleanup MUST be bounded to the builder-created staging
  directory and MUST never recursively remove a caller-owned pre-existing
  path.
- NFR-6: The suite builder MUST expose zero callable network, credential,
  scheduler, service, MT5, broker, activation, or order primitives.
- NFR-7: Unit tests MUST cover every acceptance criterion and edge case without
  requiring network, credentials, MT5, or a broker account.

## Acceptance Criteria

### AC-1: Complete same-commit suite (FR-1, FR-3, FR-4, FR-6, FR-7, FR-8, FR-9)

Given a clean repository and five conformant deterministic role builders
When the suite is built into a new external output root
Then exactly five fixed ZIP files and five fixed sidecars are present
And every role binds the same Git commit and tree
And `BASE_RELEASE_SUITE.json` binds every archive and sidecar hash
And all safety locks remain false with maximum lot `0.01`.

### AC-2: Atomic publication (FR-2, FR-5, FR-10, FR-11; NFR-5)

Given a valid output parent and a final output root that does not exist
When all staged role artifacts and the suite manifest validate
Then the final root appears through one same-filesystem rename
And no staging directory remains.

### AC-3: Dirty source denial (FR-1, FR-11)

Given a repository with a tracked, staged, or untracked change
When suite construction is requested
Then construction fails with `BASE_RELEASE_SUITE_SOURCE_NOT_CLEAN`
And no role builder is invoked
And the final output root remains absent.

### AC-4: Role failure leaves no partial suite (FR-5, FR-11; NFR-5)

Given earlier role builders succeeded in private staging
When a later fixed role builder fails
Then construction returns `BASE_RELEASE_SUITE_ROLE_BUILD_FAILED`
And the complete private staging directory is removed
And the final output root remains absent.

### AC-5: Cross-commit or wrong-profile denial (FR-7, FR-10, FR-11, FR-16)

Given one role sidecar reports a different commit, tree, profile, identity, or
result fact
When staged outputs are validated
Then construction fails with `BASE_RELEASE_SUITE_ROLE_MISMATCH`
And no final suite is published.

### AC-6: Safety invariant denial (FR-8, FR-11, FR-16)

Given any role reports an enabled live/demo-auto flag, a lot other than
`0.01`, an unexpected order capability, or production execution readiness
When staged outputs are validated
Then construction fails with `BASE_RELEASE_SUITE_SAFETY_MISMATCH`
And no final suite is published.

### AC-7: Existing or unsafe destination denial (FR-2, FR-11)

Given an existing final root, a destination inside the repository, or a
symlinked output path component
When suite construction is requested
Then construction fails before any role build
And no caller-owned path is modified.

### AC-8: Source changes during construction (FR-10, FR-11)

Given the source commit, tree, or worktree status changes after staged role
validation
When the final source check runs
Then construction fails with `BASE_RELEASE_SUITE_SOURCE_CHANGED`
And the staged outputs are removed without publishing the final root.

### AC-9: Deterministic independent rebuild (FR-14; NFR-2, NFR-4)

Given two independent clean builds from the same commit and tree
When their five archives, five sidecars, and suite manifests are compared
Then every corresponding byte sequence and SHA-256 value is identical.

### AC-10: No operational effects (FR-12, FR-13, FR-15; NFR-6)

Given a successful or rejected suite build
When its effects and public CLI surface are inspected
Then the only allowed subprocess is local Git packaging inspection
And no provider, credential, task, runtime/service process, MT5, broker,
activation, permit, or order operation occurred
And no CLI option can enable one.

### AC-11: Result-to-byte mismatch denial (FR-6, FR-16)

Given a role builder returns metadata that differs from the independently
stable-read archive or sidecar bytes
When the role is validated
Then construction fails with `BASE_RELEASE_SUITE_ROLE_RESULT_MISMATCH`
And no final suite is published.

### AC-12: Strict manifest parsing (FR-7, FR-9, FR-11; NFR-2)

Given a sidecar or suite payload with duplicate keys, unknown top-level keys,
non-canonical encoding, non-finite values, or an invalid hash
When validation is attempted
Then construction fails with a stable manifest-validation reason
And no final suite is published.

## Edge Cases

- EC-1: Output parent does not exist → reject before creating staging.
- EC-2: Output parent is not a directory → reject before creating staging.
- EC-3: Output path contains `..`, a symlink, or resolves inside the repository
  → reject without mutation.
- EC-4: Staging directory creation fails → return a stable destination error;
  do not invoke builders.
- EC-5: A role archive or sidecar is missing, replaced, truncated, or changes
  during stable-read → reject and remove staging.
- EC-6: A sidecar contains duplicate JSON keys, invalid UTF-8, non-canonical
  JSON, unknown keys, an invalid profile, or an invalid SHA-256 → reject.
- EC-7: A builder returns a path outside the private staging directory →
  reject without reading or deleting that external path.
- EC-8: The execution role reports `DISABLED` or a non-execution role reports
  `GATED_PRESENT` → reject as a role safety mismatch.
- EC-9: A role reports `production_execution_ready=true` or omits an expected
  locked safety field → reject.
- EC-10: Final output root appears concurrently before atomic rename → reject,
  remove only private staging, and preserve the concurrent caller-owned root.
- EC-11: Atomic rename fails → remove private staging and leave any existing
  destination untouched.
- EC-12: Cleanup itself encounters an OS error → preserve the primary stable
  failure code and never broaden deletion beyond the known staging root.
- EC-13: Git is unavailable, HEAD is detached only, or commit/tree lookup fails
  → detached HEAD MAY build if clean and addressable; unavailable or invalid
  Git facts MUST reject.
- EC-14: Current source contains an untracked user directory such as
  `frontend-dashboard/` → reject as dirty; never read, copy, modify, or delete
  that directory.

## API Contracts

HTTP API: N/A — this local, offline CLI intentionally exposes no `GET /` or
`POST /` endpoint.

```typescript
type BaseReleaseRole =
  | "DECISION"
  | "EXECUTION"
  | "STATUS_MONITOR"
  | "READ_ONLY_SHADOW"
  | "CONFIGURED_RELEASE_TOOLING";

interface BaseReleaseRoleRecord {
  role: BaseReleaseRole;
  releaseProfile: string;
  archivePath: string;             // fixed basename, relative to suite root
  archiveSizeBytes: number;        // positive integer
  archiveSha256: string;           // 64 lowercase hex
  sidecarPath: string;             // fixed basename, relative to suite root
  sidecarSizeBytes: number;        // positive integer
  sidecarSha256: string;           // 64 lowercase hex
  releaseIdentitySha256: string;   // 64 lowercase hex
  sourceFileCount: number;         // positive integer
  orderCapability: "DISABLED" | "GATED_PRESENT";
  productionExecutionReady: false;
}

interface BaseReleaseSuiteManifest {
  schemaVersion: "ai-scalper-windows-base-release-suite-v1";
  releaseProfile: "WINDOWS_ATOMIC_BASE_RELEASE_SUITE_V1";
  gitCommit: string;               // 40 lowercase hex
  gitTree: string;                 // 40 lowercase hex
  roles: BaseReleaseRoleRecord[];  // exact fixed order, exactly five
  effects: {
    networkAccess: false;
    gitSubprocess: true;
    providerImport: false;
    providerMaterialization: false;
    credentialAccess: false;
    taskInstallation: false;
    runtimeProcessLaunch: false;
    mt5Initialization: false;
    brokerMutation: false;
    activation: false;
    permitIssuance: false;
  };
  safety: {
    liveAllowed: false;
    safeToDemoAutoOrder: false;
    maxLot: 0.01;
    promotionEligible: false;
  };
  suiteIdentitySha256: string;     // hash of all prior fields
}

interface BaseReleaseSuiteResult {
  outputRoot: string;
  manifestPath: string;
  suiteIdentitySha256: string;
  gitCommit: string;
  gitTree: string;
  roles: BaseReleaseRoleRecord[];
}
```

Python API:

```python
def build_base_release_suite(
    repo_root: pathlib.Path,
    output_root: pathlib.Path,
) -> dict[str, object]:
    """Build and atomically publish one exact five-role base suite."""
```

CLI:

```text
python -B build_windows_base_release_suite.py --output-root <external-new-dir>
```

Public errors:

```text
BASE_RELEASE_SUITE_REJECTED: BASE_RELEASE_SUITE_SOURCE_NOT_CLEAN
BASE_RELEASE_SUITE_REJECTED: BASE_RELEASE_SUITE_DESTINATION_INVALID
BASE_RELEASE_SUITE_REJECTED: BASE_RELEASE_SUITE_ROLE_BUILD_FAILED
BASE_RELEASE_SUITE_REJECTED: BASE_RELEASE_SUITE_ROLE_MISMATCH
BASE_RELEASE_SUITE_REJECTED: BASE_RELEASE_SUITE_ROLE_RESULT_MISMATCH
BASE_RELEASE_SUITE_REJECTED: BASE_RELEASE_SUITE_SAFETY_MISMATCH
BASE_RELEASE_SUITE_REJECTED: BASE_RELEASE_SUITE_MANIFEST_INVALID
BASE_RELEASE_SUITE_REJECTED: BASE_RELEASE_SUITE_SOURCE_CHANGED
BASE_RELEASE_SUITE_REJECTED: BASE_RELEASE_SUITE_PUBLICATION_FAILED
```

## Data Models

### Fixed role policy

| Role | Builder | Allowlist | Archive |
|---|---|---|---|
| `DECISION` | `build_decision_release` | `config/windows_decision_service_allowlist.v1.json` | `decision-base-v1.zip` |
| `EXECUTION` | `build_execution_release` | `config/windows_execution_service_allowlist.v1.json` | `execution-base-v1.zip` |
| `STATUS_MONITOR` | `build_status_monitor_release` | `config/windows_status_monitor_allowlist.v1.json` | `status-monitor-base-v1.zip` |
| `READ_ONLY_SHADOW` | `build_release` | `config/windows_shadow_service_allowlist.v1.json` | `read-only-shadow-base-v1.zip` |
| `CONFIGURED_RELEASE_TOOLING` | `build_configured_release_tooling` | `config/windows_configured_release_tooling_allowlist.v1.json` | `configured-release-tooling-v1.zip` |

### BaseReleaseRoleRecord

| Field | Type | Constraints |
|---|---|---|
| role | enum | One fixed unique role |
| release_profile | string | Exact expected profile for role |
| archive_path | string | Fixed single-component basename |
| archive_size_bytes | integer | `> 0` |
| archive_sha256 | string | 64 lowercase hex |
| sidecar_path | string | Fixed single-component basename |
| sidecar_size_bytes | integer | `> 0` |
| sidecar_sha256 | string | 64 lowercase hex |
| release_identity_sha256 | string | 64 lowercase hex |
| source_file_count | integer | `> 0` |
| order_capability | enum | Role-specific exact value |
| production_execution_ready | boolean | Always `false` |

### BaseReleaseSuiteManifest

| Field | Type | Constraints |
|---|---|---|
| schema_version | string | Fixed v1 value |
| release_profile | string | `WINDOWS_ATOMIC_BASE_RELEASE_SUITE_V1` |
| git_commit | string | 40 lowercase hex |
| git_tree | string | 40 lowercase hex |
| roles | array | Exact fixed order and length five |
| effects | object | Exact map; only local packaging `git_subprocess` is true |
| safety | object | Exact locked map, no unknown keys |
| suite_identity_sha256 | string | Canonical SHA-256 over preceding fields |

## Out of Scope

- OS-1: Building configured service overlays — requires accepted external
  provider evidence and remains a later gate.
- OS-2: Importing, materializing, or testing provider implementations — owned
  by provider conformance on the exact Windows host.
- OS-3: Reading or provisioning credentials — forbidden for a base build.
- OS-4: Installing Task Scheduler jobs, services, ACLs, or Windows identities
  — external operations evidence only.
- OS-5: Initializing MT5 or reading broker data — handled by read-only runtime,
  never by release packaging.
- OS-6: Issuing stage authorization, promotion permits, arm flags, or order
  approval — separate human-controlled authorities.
- OS-7: Executing manual-demo, demo-auto, live, or paper orders — no broker
  capability exists in this feature.
- OS-8: Replacing independent two-host/two-build reproducibility evidence —
  this suite creates comparable inputs but cannot attest independence.
- OS-9: Deleting or incorporating the user-owned untracked
  `frontend-dashboard/` directory — it remains excluded from the Python
  release work.
