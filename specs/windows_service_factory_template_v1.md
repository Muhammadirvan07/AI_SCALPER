# Windows Service Factory Template v1

## 1. Title and metadata

- Author: AI_SCALPER engineering
- Date: 2026-07-22
- Status: Approved for implementation
- Reviewers: senior architecture, security, ship-gate
- Target: Windows GATED execution-service release

## 2. Context

The GATED Windows release already has an exact-hash factory loader, a sealed
production bootstrap, and a static validation entrypoint.  It intentionally
does not contain a concrete production factory because the required broker,
receipt, checkpoint, clock, audit, and key providers are external authorities.
Treating the missing factory as an undifferentiated blocker makes it difficult
to review those authorities without accidentally materializing them.

This feature introduces a release-local, non-executable template contract.  It
defines every externally supplied `ProductionRuntimePorts` field, binds provider
implementations and non-secret configuration by SHA-256, permits secret-bearing
providers to refer only to Windows Credential Manager targets, and binds the
factory deployment to one Task Scheduler definition, host, release identity,
and least-privilege service identity.  Validation is deliberately static: it
must not import a provider, read a credential, initialize MT5, create a runtime
bootstrap, consume an authorization, or submit an order.

## 3. Functional requirements

- **FR-1:** The module MUST expose the exact required and optional externally
  supplied interfaces for `ProductionRuntimePorts` plus the heartbeat providers
  required by `WindowsServiceFactoryResult`. `mt5_module` MUST be excluded:
  `ProductionRuntimePorts` requires it to be `None`, and the bootstrap loads the
  exact installed module only after internal attestation.
- **FR-2:** Every provider binding MUST include an implementation SHA-256, a
  non-secret configuration SHA-256, and the canonical contract SHA-256 for its
  exact interface.
- **FR-3:** A secret-bearing provider MUST reference exactly one reviewed
  Windows Credential Manager reference whose purpose matches the provider
  contract.  Raw secret material and non-Credential-Manager secret sources MUST
  be rejected.
- **FR-4:** A non-secret provider MUST NOT carry a credential reference.
- **FR-5:** The Task Scheduler binding MUST bind the task path, task-definition
  hash, service-account SID hash, service-principal hash, host hash, launcher
  path hash, release-root path hash, release identity hash, ACL policy hash,
  limited run level, service-account logon type, and single-instance policy.
- **FR-6:** The template MUST bind the release profile, fixed factory module and
  attribute, production bootstrap binding, reviewed production config hash,
  reviewed service config hash, provider-set hash, credential-reference-set
  hash, Task Scheduler binding hash, and its own canonical template hash.
- **FR-7:** The generator MUST return canonical JSON bytes and MUST be
  deterministic for semantically identical input.
- **FR-8:** The validator MUST use an exact JSON schema, reject duplicate JSON
  object keys, reject unrecognized or missing providers, and return a sealed
  validation report that can never claim execution readiness.
- **FR-9:** Static validation MUST NOT import or invoke provider implementations,
  read Credential Manager, initialize MT5, materialize the production bootstrap,
  consume stage/permit evidence, or mutate broker state.
- **FR-10:** `live_allowed`, `safe_to_demo_auto_order`, and factory
  materialization MUST remain false; template order capability MUST remain
  `DISABLED`.
- **FR-11:** Once the foundation is present in the deterministic GATED release,
  the broad blocker `REVIEWED_WINDOWS_SERVICE_FACTORY_REQUIRED` MUST be replaced
  by `EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_REQUIRED`.
- **FR-12:** The template MUST bind the exact runtime mode. `DEMO` may omit the
  dormant DEMO_AUTO-only ports, while `DEMO_AUTO` MUST bind every IPC, session,
  permit, promotion, environment-arm, execution-cycle, and promotion-key port.

## 4. Non-functional requirements

- **NFR-1 Security:** All JSON mappings MUST use exact field sets; hashes MUST be
  lower-case SHA-256 values; IDs and Credential Manager target names MUST follow
  bounded canonical patterns.
- **NFR-2 Determinism:** Canonical output MUST use UTF-8, sorted keys, compact
  separators, and no platform-dependent formatting.
- **NFR-3 Auditability:** The template report MUST expose the template,
  provider-set, credential-set, Task Scheduler, bootstrap, production config,
  service config, and release identity hashes.
- **NFR-4 Fail closed:** Any parse, schema, purpose, identity, hash, provider,
  credential, or safety-lock mismatch MUST raise a domain validation error.
- **NFR-5 Non-materialization:** Unit tests MUST demonstrate zero calls to an
  injected import/provider/credential/MT5/materialization sentinel.
- **NFR-6 Compatibility:** The template module MUST use only the Python 3.12
  standard library and existing `live_runtime.contracts` helpers.
- **NFR-7 Resource bound:** Serialized template input MUST be at most 256 KiB;
  provider and credential lists MUST be bounded by the release-local contract
  inventory before per-item validation.

## 5. Acceptance criteria

- **AC-1 (FR-1, FR-2):** Given one binding for every required interface and a
  valid subset of optional interfaces, when a template is generated, then every
  binding's contract hash matches the release-local canonical interface.
- **AC-2 (FR-3, FR-4):** Given a secret provider without a matching Credential
  Manager reference, a purpose mismatch, a non-Credential-Manager source, or a
  credential attached to a non-secret provider, validation fails closed.
- **AC-3 (FR-5):** Given Task Scheduler identity or release-binding drift,
  validation fails closed; given the exact reviewed binding, its canonical hash
  is exposed in the report.
- **AC-4 (FR-6, FR-7):** Given the same inputs in different mapping/list order,
  generation produces byte-identical canonical JSON and the same template hash.
- **AC-5 (FR-8):** Given a duplicate key, unknown field, missing required
  provider, unknown provider, duplicate provider, or duplicate credential
  reference, validation fails closed.
- **AC-6 (FR-9, NFR-5):** Given sentinels that fail if called, static template
  generation/validation completes without importing, resolving, or invoking any
  external authority.
- **AC-7 (FR-10):** Given any attempt to set a readiness or activation lock true,
  validation fails; every successful report says `production_execution_ready`,
  `broker_component_materialized`, and `broker_mutation_performed` are false.
- **AC-8 (FR-11):** Given the project release validator and builder, their
  readiness blockers include
  `EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_REQUIRED`, exclude
  `REVIEWED_WINDOWS_SERVICE_FACTORY_REQUIRED`, and the factory-template module
  is in the exact release allowlist/import closure.
- **AC-9 (FR-12):** Given `runtime_mode=DEMO_AUTO`, omitting any DEMO_AUTO port
  fails closed; the same optional set may be omitted only for exact
  `runtime_mode=DEMO`.

## 6. Edge cases

- **EC-1:** Duplicate JSON keys are rejected before dataclass construction.
- **EC-2:** Case-only duplicate provider/reference IDs are rejected.
- **EC-3:** A Credential Manager target outside `AI_SCALPER/` is rejected.
- **EC-4:** A raw password, secret, token, private-key, or login field is rejected
  by exact-schema validation.
- **EC-5:** All-zero hashes and hashes with upper-case characters are rejected so
  placeholders cannot be mistaken for external configuration.
- **EC-6:** Optional provider bindings may be omitted, but an unknown interface
  may never be added.
- **EC-7:** Provider and credential arrays may arrive in arbitrary order; their
  canonical set hashes and final template bytes remain deterministic.
- **EC-8:** The fixed factory selector may not be changed by external input.
- **EC-9:** Credential key IDs are trust-domain distinct; case-only reuse is
  rejected.
- **EC-10:** Oversized JSON and provider/credential list flooding are rejected
  before any external authority could be consulted.

## 7. API contracts

```text
generate_windows_service_factory_template(
    payload: Mapping[str, object]
) -> bytes

validate_windows_service_factory_template(
    payload: Mapping[str, object] | bytes | str
) -> WindowsServiceFactoryTemplateValidationReport

provider_contracts() -> tuple[ExternalProviderContract, ...]
```

Errors are raised as `WindowsFactoryTemplateError` with stable, non-secret
reason codes.  No API accepts a provider callable or credential value.

## 8. Data models

| Entity | Required fields | Constraints |
| --- | --- | --- |
| `ExternalProviderContract` | port name, kind, call contract, required flag, credential purpose, contract hash | release-local immutable definition |
| `ExternalProviderBinding` | port name, provider ID, implementation hash, configuration hash, contract hash, optional credential reference ID | exact contract match |
| `WindowsCredentialManagerReference` | reference ID, target name, target-name hash, purpose, service-account SID hash, reference hash | source fixed to Windows Credential Manager |
| `TaskSchedulerIdentityBinding` | task path and hashes for task XML, account, host, launcher, release root, release identity, ACL | limited/service-account/ignore-new fixed policies |
| `WindowsServiceFactoryTemplate` | release/factory selectors, exact runtime mode, all binding hashes, safety locks, template hash | immutable, non-materializing |
| `WindowsServiceFactoryTemplateValidationReport` | all audit hashes, provider counts, blockers, safety facts | readiness always false |

## 9. Out of scope

- Implementing or importing a concrete provider module.
- Reading Windows Credential Manager or storing any credential material.
- Creating a `ProductionRuntimeBootstrap` or `WindowsServiceFactoryResult`.
- Registering or modifying a Windows Task Scheduler task.
- Enabling demo-auto/live, consuming an authorization, or placing an order.
- Replacing the required asymmetric/external release trust authority.
- Claiming operational readiness before external provider configuration,
  attestations, evidence gates, and soak requirements are complete.
