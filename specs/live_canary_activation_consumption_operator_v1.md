# Spec: LIVE Canary Activation Consumption Operator V1

**Author:** Codex with AI_SCALPER project owner

**Date:** 2026-07-30

**Status:** Approved for implementation

**Reviewers:** project owner, security boundary, risk, operations, ship-gate

**Related specs:** `live_canary_activation_evidence_v1.md`,
`live_canary_activation_operator_v1.md`,
`live_canary_prebootstrap_admission_v1.md`

## Context

The operator release can now reconstruct a complete activation request, collect
three role-separated human approvals, and issue one short-lived deployment
authorization. The activation core already owns a durable HMAC-authenticated
SQLite replay registry and can atomically consume an authorization exactly
once. There is no file-bound Windows operator workflow, however, for pinning
the registry identity, establishing an externally retained genesis checkpoint,
performing the one-use consumption, recovering after post-commit publication
failure, or independently verifying the persisted event.

This feature supplies that missing bridge. It turns an authentic authorization
into a sealed deny-only validation and a signed successor replay checkpoint.
It does not change the central LIVE lock, launch a process, initialize MT5,
create an order capability, or call a broker. The resulting validation is only
an input to the separately reviewed prebootstrap chain.

## Functional Requirements

- FR-1: The system MUST represent one canonical target-host replay-registry
  profile binding the exact activation binding, trust policy, registry ID,
  absolute registry-path hash, registry key ID/fingerprint, and policy-pinned
  checkpoint key ID/fingerprint.
- FR-2: Profile construction MUST obtain registry and checkpoint secrets only
  from an injected provider, require at least 256 bits, compare both
  fingerprints in constant time, and reject reuse with every activation
  authority.
- FR-3: Profile use MUST require an independently supplied expected profile
  SHA-256 and exact absolute registry path whose normalized hash matches the
  profile.
- FR-4: Strict profile, checkpoint, initialization-receipt, validation, and
  consumption-receipt loaders MUST reject duplicate keys, BOM, NaN/Infinity,
  noncanonical bytes, extra/missing/wrong-typed fields, nested substitution,
  symlink/reparse input, unstable reads, and oversized files.
- FR-5: Initialization MUST require a nonexistent registry path under an
  existing regular non-link parent, create the existing exact SQLite registry,
  verify its DDL/integrity, and issue one signed genesis checkpoint with event
  count zero.
- FR-6: Initialization MUST emit one canonical sealed receipt binding the
  profile, genesis checkpoint, registry identity, and initialization time.
- FR-7: Consumption MUST require one exact current signed predecessor
  checkpoint extracted from an initialization or earlier consumption receipt.
  A stale, rolled-back, forked, future, unsigned, or non-current predecessor
  MUST fail before authorization consumption.
- FR-8: Consumption MUST independently load and re-verify the exact activation
  authorization, request, three approvals, cohort receipt, promotion receipt,
  broker eligibility, nine gate receipts, and original gate evidence before
  mutating the replay registry.
- FR-9: Consumption MUST invoke the existing
  `validate_and_consume_live_canary_activation` API exactly once and accept
  only `valid=true` plus `consumed_once=true`.
- FR-10: A successful consumption MUST append exactly one authenticated replay
  event, create a signed successor checkpoint at the consumed timestamp, and
  emit one sealed canonical consumption receipt binding predecessor,
  validation, successor, profile, authorization, and event count.
- FR-11: Repeating or concurrently racing the same authorization MUST produce
  exactly one successful registry event and never another successful receipt.
- FR-12: Independent verification MUST fully revalidate source evidence and
  authorization without consuming again, verify the current signed successor
  checkpoint, reconstruct the sealed validation from the exact registry event,
  and compare the complete receipt.
- FR-13: Recovery MUST be available only when the authorization was already
  consumed as the current registry head and publication is absent. It MUST
  reconstruct byte-identical receipt content without adding another event.
- FR-14: Recovery MUST reject an unconsumed authorization, a non-head event,
  mismatched predecessor, altered registry/profile/authorization, or an
  existing destination.
- FR-15: All output publication MUST be create-exclusive, fsync-backed, and
  preserve any pre-existing byte. Destination absence MUST be checked before
  credential access and before registry mutation.
- FR-16: The operator MUST tolerate a crash after durable consumption but
  before receipt publication by leaving the registry authoritative and making
  the recovery command deterministic.
- FR-17: Registry and checkpoint secrets MUST come only from an injected
  provider in library code and Windows Credential Manager in the CLI. Raw
  secret material MUST never be accepted through arguments, environment,
  JSON, files, output, or logs.
- FR-18: Every success/failure CLI result MUST report `Live allowed: false`,
  `Activation authorized: false`, `Order capability: DISABLED`, and
  `Broker mutation: NOT_PERFORMED`.
- FR-19: Malformed CLI input MUST return exit code 2 without reflecting caller
  values. Operational failure MUST be deterministic and leave no partial
  output.
- FR-20: Profile preparation, initialization, consumption, verification, and
  recovery MUST NOT change `execution_policy.LIVE_ALLOWED`, central policy,
  task/service state, environment arms, permits, launch capability, MT5, or
  broker state.
- FR-21: The CLI and consumption module MUST be packaged only in
  `WINDOWS_SHADOW_DEPLOYMENT_TOOLING_V1` and absent from Decision, Execution,
  Status Monitor, read-only shadow, and configured-service releases.
- FR-22: Existing activation schemas, HMAC domains, replay DDL/triggers,
  consumption behavior, and downstream exact-type checks MUST remain
  compatible.

## Non-Functional Requirements

- NFR-S1: All attacker-controlled hash and key-fingerprint comparisons MUST use
  constant-time comparison where applicable.
- NFR-S2: Public errors MUST use stable codes and MUST NOT contain account
  login, password, secret, human identity, arbitrary argument value, SQLite
  row content, or credential-provider detail.
- NFR-S3: Exact base-class checks MUST reject subclasses and duck types at
  every trust boundary.
- NFR-R1: Registry mutation MUST remain atomic under `BEGIN IMMEDIATE`, WAL,
  `synchronous=FULL`, exact immutable triggers, and existing path-identity
  checks.
- NFR-R2: Verification and recovery MUST be read-only with respect to the
  registry and MUST prove that event count did not change.
- NFR-R3: Output failure MUST never roll back, delete, replace, or rewrite an
  already committed registry event.
- NFR-P1: Read-only verification of one bounded receipt, excluding external
  credential latency, MUST average below 100 ms in focused tests.
- NFR-C1: The implementation MUST support CPython 3.12 normal and `-O` modes,
  use existing project dependencies only, and preserve deterministic Windows
  release construction.
- NFR-O1: Output MUST include public profile/authorization/validation/checkpoint
  hashes and event count while stating that secret material was not exported.

## Acceptance Criteria

### AC-1: Exact target-host profile (FR-1, FR-2, FR-3, FR-4)

Given exact binding/policy, target registry path, independently pinned key
identities/fingerprints, and Credential Manager keys
When the profile is prepared and loaded
Then every identity and path hash matches canonically
And key reuse, wrong fingerprint, malformed JSON, or another path fails closed.

### AC-2: Genesis initialization (FR-5, FR-6, FR-15)

Given a valid profile and nonexistent registry/output paths
When initialization runs
Then one exact registry and signed zero-event checkpoint receipt are created
And rerun, linked path, existing output, invalid parent, or partial setup is
rejected without overwriting evidence.

### AC-3: One-use consumption (FR-7, FR-8, FR-9, FR-10, FR-11)

Given a current authorization, all original evidence, valid genesis/current
checkpoint, and intact registry
When consumption runs
Then exactly one event is durably appended and one sealed deny-only receipt is
published with event count incremented by one
And repeat/concurrent consumption cannot succeed.

### AC-4: Current checkpoint and rollback protection (FR-7, FR-10)

Given signed genesis, current, stale-prefix, forked, and future checkpoints
When each is used as predecessor
Then only the exact signed current head is accepted before mutation
And the successor is signed by the independently policy-pinned checkpoint key.

### AC-5: Independent verification (FR-12, NFR-R2, NFR-P1)

Given a valid persisted consumption receipt and exact source inputs
When verification runs
Then it reconstructs the same sealed validation from the registry event,
revalidates every signature/evidence binding, verifies the current checkpoint,
and does not change event count.

### AC-6: Crash-safe recovery (FR-13, FR-14, FR-16, NFR-R3)

Given a durable successful event whose receipt publication never occurred
When recovery runs with the exact predecessor and source inputs
Then it writes byte-identical receipt content without another event
And any non-head, missing, substituted, or already-published case fails closed.

### AC-7: Safe CLI and secret boundary (FR-15, FR-17, FR-18, FR-19)

Given malformed arguments, missing credential, existing destination, tampered
source, or SQLite failure
When any subcommand runs
Then it exits 2, reflects no caller value or secret, preserves existing bytes,
and prints the locked safety state.

### AC-8: Release and effect isolation (FR-20, FR-21, FR-22)

Given static import/call inspection and all Windows release allowlists
When the feature is audited and releases are built twice
Then only the operator ZIP contains the workflow, service bundles contain no
operator surface, both builds are byte-identical, and no forbidden effect
occurs.

### AC-9: Optimized compatibility (NFR-C1)

Given focused and full repository tests
When run normally and with `-O`
Then all expected tests pass and existing activation/replay hashes remain
compatible.

## Edge Cases and Error Scenarios

- EC-1: Relative path, path traversal, parent symlink/reparse, registry
  symlink, non-regular database, changed inode, or path-hash case drift fails.
- EC-2: Profile key ID matches an activation authority or registry secret bytes
  match any authority/checkpoint secret even under another ID; preparation
  fails.
- EC-3: Genesis checkpoint has nonzero count/head/last values, wrong policy
  checkpoint identity, future issuance, or invalid signature; initialization
  verification fails.
- EC-4: Authorization expires exactly at consumption time, trusted clock drifts
  above 50 ms, or evidence expires before it; no event is appended.
- EC-5: Predecessor is a valid prefix but registry has a newer event; it is not
  current and consumption fails.
- EC-6: Output path exists before start; no Credential Manager or SQLite access
  occurs.
- EC-7: Output race is won after preflight but after consumption; publication
  fails, winning bytes survive, and recovery to a different new path succeeds.
- EC-8: SQLite event exists but authorization ID/hash/request/nonce differs;
  verification and recovery reject it.
- EC-9: The consumed authorization is valid but not the current head because a
  later authorization exists; recovery refuses to publish a stale receipt.
- EC-10: Validation/receipt subclass, altered safety field, extra nested field,
  duplicate key, NaN, BOM, or noncanonical newline fails strict loading.
- EC-11: Credential provider raises, returns non-bytes/text, short material, or
  wrong fingerprint; no new event/output is produced.
- EC-12: Two processes race on the same authorization and destination; one
  event and at most one valid receipt survive.

## API Contracts

```python
build_live_canary_replay_registry_profile(...) -> LiveCanaryReplayRegistryProfile
load_live_canary_replay_registry_profile(path) -> LiveCanaryReplayRegistryProfile
initialize_live_canary_replay_registry(...) -> LiveCanaryReplayRegistryInitializationReceipt
load_live_canary_replay_checkpoint_receipt(path) -> LiveCanaryReplayCheckpoint
consume_live_canary_activation_artifact(...) -> LiveCanaryActivationConsumptionReceipt
verify_live_canary_activation_consumption_artifact(...) -> LiveCanaryActivationConsumptionReceipt
recover_live_canary_activation_consumption_artifact(...) -> LiveCanaryActivationConsumptionReceipt
write_live_canary_activation_consumption_artifact_exclusive(path, payload) -> Path
verify_consumed_live_canary_activation(...) -> LiveCanaryActivationValidation
```

The CLI entrypoint is:

```text
manage_live_canary_activation_consumption.py
  prepare-profile | initialize | consume | verify | recover
```

No HTTP or WebSocket route is introduced. In particular,
`POST /internal/live-canary/consume` MUST NOT be registered.

## Data Models

| Contract | Required binding | Capability state |
|---|---|---|
| Replay registry profile | binding/policy/profile/absolute-path hash, registry and checkpoint authority | all false/disabled |
| Initialization receipt | profile hash plus signed zero-event checkpoint | all false/disabled |
| Activation validation | exact consumed authorization/request/binding and original event time | all false/disabled |
| Consumption receipt | profile, predecessor hash, validation, signed successor checkpoint, exact event count | all false/disabled |

Every JSON artifact is canonical UTF-8 with a final newline when persisted.
Secrets, raw account identifiers, passwords, and arbitrary credential-provider
details are excluded.

## Out of Scope

- OS-1: Changing or dynamically patching `execution_policy.LIVE_ALLOWED`.
- OS-2: Creating central-unlock, launch-session, per-order, permit, or
  environment-arm authority.
- OS-3: Starting Decision, Execution, Status Monitor, Task Scheduler, service,
  subprocess, MT5, network, or broker operations.
- OS-4: Uploading a checkpoint to external WORM/CAS custody or claiming that
  local persistence is off-host custody.
- OS-5: Constructing provider-bound prebootstrap/custody/session artifacts;
  those remain separately reviewed downstream steps.
- OS-6: Provisioning credentials or exporting secret material.
- OS-7: Claiming that a fixture/test registry is production evidence or that
  source completion makes live trading ready.
