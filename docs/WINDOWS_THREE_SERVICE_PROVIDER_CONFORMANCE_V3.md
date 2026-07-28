# Windows Three-Service Provider Conformance v3

Status: **LOCAL TOOLING COMPLETE / WINDOWS EVIDENCE NOT YET COLLECTED**

Provider-conformance v3 is the required contract for every new candidate that
uses an Execution source-bound archive. It joins the existing three-service,
65-provider evidence review to the exact nine-pin verified Execution source,
configured candidate, atomic suite, Execution base release, Git commit, and
Git tree.

V3 does not grant provider acceptance or trading authority. Every successful
input and review retains:

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

## Required artifacts

Use artifacts from one exact clean Windows build and independent custody:

- Decision, Execution, and Status Monitor factory-template JSON files;
- the compact 65-record external provider-evidence manifest;
- the Execution source-bound candidate ZIP;
- the matching atomic five-role base-suite root;
- the matching Execution base-release ZIP; and
- the bound archive hash plus all eight source/champion/Git/suite pins.

The Execution template must be the exact canonical member of the source-bound
candidate and use runtime mode `DEMO`. A standalone `DEMO_AUTO` template is a
v2 compatibility input and cannot be silently promoted to v3.

## Assemble input on Windows

Run from the extracted configured-release operator tooling with isolated,
no-site Python:

```powershell
python -I -S -B .\prepare_windows_three_service_provider_conformance_input.py `
  --decision-factory-template <DECISION_FACTORY_TEMPLATE_JSON> `
  --execution-factory-template <SOURCE_BOUND_EXECUTION_FACTORY_TEMPLATE_JSON> `
  --status-monitor-factory-template <STATUS_MONITOR_FACTORY_TEMPLATE_JSON> `
  --evidence-manifest <PROVIDER_EVIDENCE_MANIFEST_JSON> `
  --review-id <NON_SECRET_REVIEW_ID> `
  --operations-plan-sha256 <OPERATIONS_PLAN_SHA256> `
  --operations-review-bundle-sha256 <OPERATIONS_REVIEW_BUNDLE_SHA256> `
  --execution-source-bound-candidate <SOURCE_BOUND_CANDIDATE_ZIP> `
  --base-suite-root <ATOMIC_BASE_SUITE_ROOT> `
  --execution-base-release <EXECUTION_BASE_RELEASE_ZIP> `
  --expected-bound-archive-sha256 <BOUND_ARCHIVE_SHA256> `
  --expected-source-archive-sha256 <SOURCE_ARCHIVE_SHA256> `
  --expected-champion-archive-sha256 <CHAMPION_ARCHIVE_SHA256> `
  --expected-model-artifact-sha256 <MODEL_ARTIFACT_SHA256> `
  --expected-training-snapshot-sha256 <TRAINING_SNAPSHOT_SHA256> `
  --expected-config-sha256 <CHAMPION_CONFIG_SHA256> `
  --expected-git-commit <FULL_GIT_COMMIT> `
  --expected-git-tree <FULL_GIT_TREE> `
  --expected-suite-identity-sha256 <SUITE_IDENTITY_SHA256> `
  --output <NEW_PROVIDER_CONFORMANCE_INPUT_V3_JSON>
```

Success must report exactly the v3 schema, 65 providers, and disabled order
capability. Any missing source argument rejects; it never falls back to v2.
Combining the v3 argument set with the legacy v1 admission hash also rejects.

## Build the deny-only review

Use the same source-bound artifact and pins again:

```powershell
python -I -S -B .\prepare_windows_three_service_provider_conformance_review.py `
  --input <PROVIDER_CONFORMANCE_INPUT_V3_JSON> `
  --output <NEW_PROVIDER_CONFORMANCE_REVIEW_V3_JSON> `
  --execution-source-bound-candidate <SOURCE_BOUND_CANDIDATE_ZIP> `
  --base-suite-root <ATOMIC_BASE_SUITE_ROOT> `
  --execution-base-release <EXECUTION_BASE_RELEASE_ZIP> `
  --expected-bound-archive-sha256 <BOUND_ARCHIVE_SHA256> `
  --expected-source-archive-sha256 <SOURCE_ARCHIVE_SHA256> `
  --expected-champion-archive-sha256 <CHAMPION_ARCHIVE_SHA256> `
  --expected-model-artifact-sha256 <MODEL_ARTIFACT_SHA256> `
  --expected-training-snapshot-sha256 <TRAINING_SNAPSHOT_SHA256> `
  --expected-config-sha256 <CHAMPION_CONFIG_SHA256> `
  --expected-git-commit <FULL_GIT_COMMIT> `
  --expected-git-tree <FULL_GIT_TREE> `
  --expected-suite-identity-sha256 <SUITE_IDENTITY_SHA256>
```

The review CLI independently repeats nine-pin source-bound verification. V3
input without the complete verifier group rejects. Supplying that group for a
v1/v2 input also rejects as version confusion.

Both outputs are canonical, bounded, and create-exclusive. They do not import
or materialize a provider, access credentials or private keys, initialize
MT5, use the network, install/start tasks or services, issue permits, or touch
the broker.

The normative contract is
[`specs/windows_three_service_provider_conformance_v3.md`](../specs/windows_three_service_provider_conformance_v3.md).
Versions 1 and 2 remain byte-compatible only for their documented historical
and compatibility workflows.
