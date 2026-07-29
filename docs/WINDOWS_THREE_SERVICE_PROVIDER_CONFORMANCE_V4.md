# Windows Three-Service Provider Conformance v4

Status: **LOCAL TOOLING COMPLETE / LIVE WINDOWS EVIDENCE NOT YET COLLECTED**

Provider-conformance v4 is the deny-only evidence boundary for the exact LIVE
Execution candidate. It combines:

- seven Decision provider bindings;
- 49 LIVE Execution provider bindings;
- twelve Status Monitor provider bindings; and
- exactly 68 fresh external `PASS` evidence records.

The Execution template must be the canonical
`live-execution-factory-template.json` member from the exact 17-member LIVE
source-bound archive. The v4 assembler invokes the authoritative ten-pin
verifier before reading the evidence manifest or publishing output. It derives
each LIVE provider binding hash from all seven template fields, including its
provider ID and purpose-bound credential reference.

Successful assembly or review does not accept a provider or permit trading:

```text
provider_accepted=false
activation_allowed=false
execution_enabled=false
task_install_allowed=false
credential_access_performed=false
provider_imported=false
provider_materialized=false
broker_mutation_performed=false
live_allowed=false
safe_to_demo_auto_order=false
promotion_eligible=false
order_capability=DISABLED
max_lot=0.01
```

## Required Windows artifacts

Keep all items under independent, non-overwriting custody:

- exact configured Decision factory-template JSON;
- exact LIVE Execution factory-template JSON from the LIVE candidate;
- exact configured Status Monitor factory-template JSON;
- one compact 68-record provider-evidence manifest;
- the exact LIVE source-bound candidate ZIP;
- the matching atomic five-role base-suite root;
- the matching canonical Execution base-release ZIP;
- independent SHA-256 pins for the LIVE-bound, nested source-bound, source,
  champion, model, training snapshot, champion config, and suite artifacts;
  and
- the full 40-character Git commit and tree pins.

Evidence timestamps may not be in the future and may be at most 24 hours old
when each input/review command runs. Each provider requires all six exact-true
conformance probes. Credential values, passwords, logins, tokens, private keys,
and account secrets must not be placed in any JSON file.

## Assemble the v4 input

Run from an extracted configured-release operator tooling bundle with isolated
stdlib Python:

```powershell
python -I -S -B .\prepare_windows_three_service_provider_conformance_input.py `
  --decision-factory-template <DECISION_FACTORY_TEMPLATE_JSON> `
  --execution-factory-template <LIVE_EXECUTION_FACTORY_TEMPLATE_JSON> `
  --status-monitor-factory-template <STATUS_MONITOR_FACTORY_TEMPLATE_JSON> `
  --evidence-manifest <LIVE_PROVIDER_EVIDENCE_MANIFEST_JSON> `
  --review-id <NON_SECRET_REVIEW_ID> `
  --operations-plan-sha256 <OPERATIONS_PLAN_SHA256> `
  --operations-review-bundle-sha256 <OPERATIONS_REVIEW_BUNDLE_SHA256> `
  --live-execution-source-bound-candidate <LIVE_SOURCE_BOUND_CANDIDATE_ZIP> `
  --base-suite-root <ATOMIC_BASE_SUITE_ROOT> `
  --execution-base-release <EXECUTION_BASE_RELEASE_ZIP> `
  --expected-live-bound-archive-sha256 <LIVE_BOUND_ARCHIVE_SHA256> `
  --expected-source-bound-archive-sha256 <SOURCE_BOUND_ARCHIVE_SHA256> `
  --expected-source-archive-sha256 <SOURCE_ARCHIVE_SHA256> `
  --expected-champion-archive-sha256 <CHAMPION_ARCHIVE_SHA256> `
  --expected-model-artifact-sha256 <MODEL_ARTIFACT_SHA256> `
  --expected-training-snapshot-sha256 <TRAINING_SNAPSHOT_SHA256> `
  --expected-config-sha256 <CHAMPION_CONFIG_SHA256> `
  --expected-git-commit <FULL_GIT_COMMIT> `
  --expected-git-tree <FULL_GIT_TREE> `
  --expected-suite-identity-sha256 <SUITE_IDENTITY_SHA256> `
  --output <NEW_PROVIDER_CONFORMANCE_INPUT_V4_JSON>
```

Success must print:

```text
Contract schema: windows-three-service-provider-conformance-input-v4
Providers: 68
Provider acceptance: false
Order capability: DISABLED
```

The output path must not already exist. A partial v4 group, a v3/v4 mixture,
or a legacy admission argument fails without falling back to another schema.

## Build and reconstruct the v4 review

Repeat independent ten-pin verification rather than trusting the input's
embedded hashes:

```powershell
python -I -S -B .\prepare_windows_three_service_provider_conformance_review.py `
  --input <PROVIDER_CONFORMANCE_INPUT_V4_JSON> `
  --output <NEW_PROVIDER_CONFORMANCE_REVIEW_V4_JSON> `
  --live-execution-source-bound-candidate <LIVE_SOURCE_BOUND_CANDIDATE_ZIP> `
  --base-suite-root <ATOMIC_BASE_SUITE_ROOT> `
  --execution-base-release <EXECUTION_BASE_RELEASE_ZIP> `
  --expected-live-bound-archive-sha256 <LIVE_BOUND_ARCHIVE_SHA256> `
  --expected-source-bound-archive-sha256 <SOURCE_BOUND_ARCHIVE_SHA256> `
  --expected-source-archive-sha256 <SOURCE_ARCHIVE_SHA256> `
  --expected-champion-archive-sha256 <CHAMPION_ARCHIVE_SHA256> `
  --expected-model-artifact-sha256 <MODEL_ARTIFACT_SHA256> `
  --expected-training-snapshot-sha256 <TRAINING_SNAPSHOT_SHA256> `
  --expected-config-sha256 <CHAMPION_CONFIG_SHA256> `
  --expected-git-commit <FULL_GIT_COMMIT> `
  --expected-git-tree <FULL_GIT_TREE> `
  --expected-suite-identity-sha256 <SUITE_IDENTITY_SHA256>
```

Success reports review schema
`windows-three-service-provider-conformance-review-v4`, exactly 68 providers,
and external signature still required. Preserve the input, review, evidence,
artifacts, independent pins, command transcript, and hashes together. Do not
rename or overwrite a failed attempt.

V1 through v3 remain separate compatibility contracts. A v3 DEMO source-bound
result cannot satisfy v4, and the LIVE result cannot satisfy v1 through v3.

The normative contract is
[`specs/windows_three_service_provider_conformance_v4.md`](../specs/windows_three_service_provider_conformance_v4.md).
