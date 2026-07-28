# Phillip Commodity V6 Post-Run Acceptance v1

**Status:** Approved for implementation
**Scope:** first automatic V6.3 scheduler evidence handoff
**Authority:** none; read-only evidence packaging only

> Historical baseline only. New builds use
> `phillip_commodity_v6_postrun_acceptance_v2.md`, which additionally binds
> correlated Task Scheduler Operational event provenance.

## Purpose

Create one fail-closed, portable evidence boundary after the exact V6.3 task
has run automatically. The boundary converts a successful local health check
and its authenticated artifacts into one create-exclusive ZIP whose bytes can
be pinned and moved to independent off-host custody.

It must not confuse local authentication with independent custody. The bundle
therefore records both facts separately:

- `source_host_health_verifier_passed=true`;
- `independent_hmac_reverification_performed=false`;
- `offhost_custody.performed=false`;
- `offhost_custody.worm_retention_verified=false`.

## Fixed ancestry

- installed remediation commit:
  `14762eac7e991fee8818ee20816709066f457f06`;
- installed remediation tree:
  `727f5215b203796c584d7bf321edac2447e92a60`;
- frozen worker commit:
  `290cc23d9d87f93e914612afdfecfc481d2c232f`;
- frozen worker tree:
  `ef568ae39aa4c51d9afe738badbb86d2c45e9a58`;
- contract: `phillip-commodity-window-01-diagnostic-v5`;
- first scheduled boundary: `2026-07-30T06:45:00+09:00`;
- end boundary: `2026-09-22T00:16:00+09:00`.

## Functional requirements

### FR-1 — Exact toolkit transport

The toolkit ZIP MUST be deterministic and contain exactly:

1. `Invoke-PhillipCommodityV6PostRunAcceptance.ps1`;
2. `New-PhillipCommodityV6CustodyRequest.ps1`;
3. `Test-PhillipCommodityV6CustodyReceipt.ps1`;
4. `PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE.md`;
5. `phillip_commodity_v6_postrun_acceptance.py`;
6. `PHILLIP_COMMODITY_V6_POSTRUN_TOOLKIT.json`.

Verification MUST require independent outer archive SHA-256, source commit,
and source tree pins. Duplicate/case-colliding names, path traversal, archive
comments/trailers, ZIP64 substitution, encryption, symlinks, metadata drift,
unexpected members, or payload hash/size drift MUST fail.

### FR-2 — Installed checker binding

Before health execution, the wrapper MUST pin the installed V6.3 health
checker SHA-256. The checker independently validates the installation receipt,
Task Scheduler definition, prior disabled tasks, frozen worker, HMAC evidence,
signed checkpoint chain, live journal head, heartbeat, and current schedule
phase.

### FR-3 — No manual task start

The wrapper and Python tool MUST contain no task start, registration, enable,
disable, delete, MT5, credential, or order primitive. They may only query task
state and execute the existing read-only health checker.

### FR-4 — Post-boundary advancement

Collection MUST reject unless:

- observation and last run are at or after the first automatic boundary;
- the latest authenticated heartbeat is at or after that boundary;
- source event and committed manifest counts exceed installation values;
- the latest checkpoint differs from genesis and has a predecessor;
- V4 and V5 tasks remain `Disabled`;
- V6 is `Running`, or it is `Ready` with result `0`;
- health output contains the exact healthy/safety projection.

### FR-5 — Exact evidence pair

The latest checkpoint MUST name one exact audit/manifest pair. File hashes,
authenticated manifest hash, invocation identity, signing key identity,
heartbeat, event count, operational head, signed head, chain-from-genesis,
and all safety fields MUST agree across checkpoint, audit, and manifest.

### FR-6 — Acceptance archive

The output ZIP MUST be create-exclusive and contain exactly:

1. `audit-export.json`;
2. `audit-manifest.json`;
3. `evidence-checkpoint.json`;
4. `health-transcript.txt`;
5. `installation-receipt.json`;
6. `installed-task.xml`;
7. `PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE.json`.

The central manifest MUST bind every member hash/size, an evidence-set SHA-256,
a canonical bundle identity, toolkit ancestry, scheduler observation,
authenticated evidence projection, safety state, and external-custody state.

### FR-7 — External custody truthfulness

Local collection and verification MUST never change any custody or promotion
field to true. Independent Object Lock/WORM acknowledgement is a later external
gate and MUST use a separate receipt.

### FR-8 — Deterministic custody request

The toolkit MUST create one create-exclusive custody-request ZIP containing
exactly the unchanged acceptance ZIP and one canonical request manifest. The
manifest MUST bind the outer acceptance hash/size, inner bundle identity,
toolkit commit/tree, checkpoint HMAC, latest heartbeat, event count,
destination, request time, exact-byte verification, versioning, WORM,
Object Lock `COMPLIANCE`, and a retention floor. Equal explicit inputs MUST
produce equal output bytes. Nested acceptance verification MUST run again;
rehashed malformed nested ZIPs MUST fail.

The engineering retention floor is 365 days from the request and never before
`2027-09-21T15:16:00Z`. This floor is not a legal determination.

### FR-9 — Independent signed custody receipt

Receipt verification MUST require separately pinned canonical policy JSON and
canonical receipt JSON. Duplicate keys, noncanonical bytes, policy pin drift,
destination/storage-provider drift, exact-content hash/size drift,
remote-version absence, retention shortfall, future acknowledgement, expired
retention, or signature failure MUST reject before assessment publication.

The only supported public-key boundary is RSA 3072–8192 bit, exponent 65537,
`RSASSA-PKCS1-v1_5-SHA256`, under the reviewed domain separator. No private
key may be present in source or toolkit. A successful assessment MUST say that
the signed custodian attestation was accepted while preserving
`direct_storage_api_inspection_performed=false`.

Every create-exclusive output check MUST use no-follow filesystem inspection.
Regular files, directories, valid symlinks, and dangling symlinks all count as
pre-existing output and MUST be rejected without mutation. Exception cleanup
MUST remove only the exact regular file created by the current invocation.

## Safety invariants

Every toolkit manifest, acceptance manifest, collection result, and verifier
result MUST preserve:

```text
order_capability = DISABLED
live_allowed = false
safe_to_demo_auto_order = false
promotion_eligible = false
task_scheduler_mutation = NOT_PERFORMED
broker_mutation = NOT_PERFORMED
```

## Acceptance criteria

- AC-1: two clean builds from the same commit/tree are byte-identical;
- AC-2: exact toolkit verification succeeds only with all external pins;
- AC-3: a valid post-boundary fixture builds and re-verifies one bundle;
- AC-4: pre-boundary, non-advanced checkpoint, task/result drift, prior-task
  drift, transcript drift, audit/manifest mutation, or task XML mutation fails;
- AC-5: archive mutation, appended bytes, duplicate/case/path tricks, member
  substitution, source identity drift, or custody overclaim fails;
- AC-6: normal and optimized focused tests pass;
- AC-7: equal custody inputs produce byte-identical request ZIPs and a valid
  real-RSA fixture produces one create-exclusive deny-only assessment;
- AC-8: signature, binding, policy-pin, canonical-JSON, retention, nested-ZIP,
  or output-collision attacks fail without publishing an assessment;
- AC-9: complete regressions pass without changing any execution safety lock.
- AC-10: a dangling symlink at the toolkit, custody-request, or assessment
  output path is rejected and remains byte-for-byte/path-target unchanged.

## Operational sequence

1. wait for the automatic boundary;
2. verify the toolkit ZIP against archive/commit/tree pins;
3. run the wrapper once; do not start the task manually;
4. record archive SHA-256 and bundle identity;
5. re-verify the acceptance ZIP;
6. create and independently hash the custody-request ZIP;
7. send that exact request ZIP to independent Object Lock/WORM custody;
8. obtain canonical policy and RSA-signed acknowledgement receipt;
9. verify the policy pin, request, receipt, retention, and signature;
10. retain the deny-only assessment with all three external artifacts.
