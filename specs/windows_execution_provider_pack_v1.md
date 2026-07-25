# Windows Execution Provider Pack v1

**Author:** AI_SCALPER engineering  
**Date:** 2026-07-25  
**Status:** Approved for implementation  
**Reviewers:** senior architecture, security, ship-gate  
**Target:** Windows GATED execution service

## Context

The execution base release already contains the pure production bootstrap,
exact MT5 adapter boundary, runtime supervisor, execution journal, risk
governor, reconciliation, stage authorization, and a static 46-port factory
template. It does not contain a concrete provider composition. Decision and
Status Monitor already have deterministic provider packs and immutable
configured candidates; Execution is the remaining local software boundary.

This feature supplies the first-party Execution provider foundation, an
offline deterministic pack generator/validator, and a suite-bound configured
candidate. It must compose every provider required by
`ProductionRuntimePorts` and `WindowsServiceFactoryResult`, while preserving
the existing activation gates. It must never manufacture external authority:
all credential, clock, journal/WORM, risk, checkpoint/CAS, news,
reconciliation, decision, stage, manual-approval, promotion, heartbeat, and
MT5 claims are read from independently provisioned and cryptographically
bound sources.

## Provider Inventory and Trust Domains

The authoritative inventory is
`live_runtime.windows_service_factory_template.provider_contracts()`.

- Exact total: 46 ports.
- Exact required set for `DEMO`: 37 ports.
- Exact optional set: 9 ports.
- `DEMO_AUTO` requires the eight ports in the authoritative
  `_DEMO_AUTO_PROVIDER_PORTS` set in addition to every required port.
- Twelve ports bind distinct Windows Credential Manager purposes:
  `MT5_DEMO_SESSION`, `BOOTSTRAP_EXTERNAL_RECEIPT_HMAC`,
  `RISK_LEDGER_HMAC`, `JOURNAL_CHECKPOINT_HMAC`,
  `SUPERVISOR_RECEIPT_HMAC`, `SUPERVISOR_CHECKPOINT_HMAC`,
  `NEWS_GUARD_HMAC`, `PROMOTION_PERMIT_HMAC`,
  `PROMOTION_EVIDENCE_HMAC`, `MANUAL_APPROVAL_HMAC`,
  `HEARTBEAT_SENDER_HMAC`, and `HEARTBEAT_REMOTE_ACK_HMAC`.

No credential key ID, target, fingerprint, issuer, provider ID, database,
directory, service identity, release identity, or account binding may be
reused across an incompatible trust domain.
The signed-clock authority is an independently provisioned trust domain; its
key ID and fingerprint MUST NOT reuse any of the twelve Execution Credential
Manager references.

## Functional Requirements

- FR-1: The pack MUST bind the exact authoritative
  provider inventory. Unknown, missing, duplicate, case-colliding, reordered,
  contract-drifted, or custody-drifted bindings fail closed.
- FR-2: `mt5_module` MUST remain `None`.
  MetaTrader5 may only be imported and attested by the existing production
  bootstrap after all pre-materialization checks pass.
- FR-3: v1 MUST support both `DEMO` and dormant
  `DEMO_AUTO` configuration. `DEMO_AUTO` materialization remains impossible
  while the centralized execution policy lock is false. A `DEMO` pack MUST
  reject DEMO_AUTO session/arm/permit/promotion configuration.
- FR-4: Secret-bearing ports MUST use exact,
  purpose-bound, read-only Windows Credential Manager references. Raw aliases,
  logins, passwords, HMAC keys, permits, tokens, arm values, or private keys
  MUST NOT appear in input, generated files, receipts, logs, or errors.
- FR-5: Every time-sensitive provider MUST use the shared
  attested, monotonic UTC primitive and one exact signed clock-attestation
  source. System time alone is not trusted.
- FR-6: Execution journal, supervisor database,
  risk ledger, replay/session ledgers, outboxes, and all external current heads
  MUST already exist with exact identity/schema/integrity. The provider pack
  MUST NOT create first-use identity, genesis, directory, database, or
  credential state.
- FR-7: Journal provisioning, WORM root, risk
  source/state, journal/supervisor checkpoints, reconciliation/deal/closure,
  runtime facts, signed news, decision input, stage authorization/replay,
  manual approval, promotion, and DEMO_AUTO authorities MUST be authenticated
  and bound to the exact account, server, environment, build, config, journal,
  lane, and predecessor heads required by their domain verifier.
- FR-8: Risk, journal, supervisor,
  stage-replay, session, and dispatch updates MUST use compare-and-swap or
  one-use acknowledgement protocols. Timeout, duplicate, stale predecessor,
  missing acknowledgement, inconsistent successor, or restart uncertainty
  fails closed and never retries a broker submission.
- FR-9: Reconciliation MUST read the exact MT5
  adapter already owned by the production composition. Broker receipts MUST be
  verifier-sealed; orphan positions, missing SL/TP, unknown tickets, history
  delay beyond policy, or unresolved submit uncertainty latches the existing
  kill switch.
- FR-10: Execution MUST consume only the authenticated
  Decision IPC contract. It MUST NOT calculate a new strategy decision,
  silently modify side/entry/SL/TP/lot, or accept an expired/duplicate intent.
- FR-11: `DEMO` execution MUST require a fresh externally issued
  manual approval and the existing manual-demo policy callback. Pack creation
  and configured-candidate assembly never issue or consume an approval.
- FR-12: DEMO_AUTO IPC, session lease/store, permit,
  promotion, arm, and execution-cycle providers MUST all be present and bound
  before runtime construction. Their presence does not enable policy, arm,
  stage authorization, or order capability.
- FR-13: The heartbeat outbox and transport MUST require
  pre-existing state, exact signed acknowledgement, and durable predecessor
  chaining. Delivery failure cannot be converted into service readiness.
- FR-14: Runtime factory construction MUST return only an
  exact `WindowsServiceFactoryResult` sealed by the existing entrypoint. The
  bootstrap configuration hash, provider-template hash, factory source hash,
  service configuration hash, release identity, and task binding MUST match.
- FR-15: The generator MUST create exactly:
  `config/windows_service_config.json`,
  `configured_providers/__init__.py`,
  `configured_providers/execution_provider.py`, and
  `reviewed_windows_factory.py`.
- FR-16: Pack generation/validation and candidate
  assembly/validation MUST NOT import a generated provider, read credentials,
  open SQLite, issue provider/CAS/network requests, import or initialize MT5,
  install a task, start a process, consume an authorization, or mutate a
  broker.
- FR-17: Foundation implementation hashes MUST bind the
  exact path and SHA-256 of every first-party Execution foundation member from
  the verified atomic base-suite Execution ZIP. Provider configuration hashes
  MUST bind exact non-secret per-port configuration.
- FR-18: Candidate assembly MUST preserve the
  original provider pack, use a distinct working overlay, build one configured
  Execution ZIP through the generic configured-release boundary, bind one
  reviewed task definition, and emit a create-exclusive canonical receipt.
- FR-19: Every successful local result MUST retain
  `live_allowed=false`, `safe_to_demo_auto_order=false`,
  `max_lot=0.01`, `promotion_eligible=false`, and
  `production_execution_ready=false`. Offline pack/candidate reports use
  `order_capability=DISABLED`; the immutable base Execution ZIP may continue
  to report dormant `GATED_PRESENT`.
- FR-20: A configured candidate MUST remain
  `provider_accepted=false` and
  `EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED`. Only independent signed Windows
  conformance evidence may advance the later pre-manual admission workflow.

## Non-Functional Requirements

- NFR-1: All validation errors MUST use stable non-secret reason
  codes. Missing or unavailable evidence is failure, never a default pass.
- NFR-2: Canonical JSON MUST be UTF-8, sorted, compact,
  newline-terminated; semantically identical input produces byte-identical
  pack and candidate output.
- NFR-3: Duplicate JSON keys, non-finite numbers, unknown
  fields, zero/upper-case hashes, ambiguous timestamps, path overlap,
  symlink/reparse input, unstable reads, and oversized documents fail closed.
- NFR-4: Each document MUST be at most 4 MiB, each pack at most
  16 MiB, and each candidate at most 256 MiB. Provider/source collections are
  bounded before per-item work.
- NFR-5: Runtime paths MUST be absolute canonical Windows paths
  on reviewed fixed volumes. UNC/device/ADS/traversal/reserved-name paths and
  case-insensitive path collisions are rejected.
- NFR-6: Inputs and generated artifacts MUST be scanned for
  private-key markers, common token formats, and sensitive field names.
- NFR-7: Tests MUST cover restart at every provider/CAS boundary,
  uncertain broker submit, duplicate input, stale head, and state rollback.
- NFR-8: Security behavior and tests MUST be identical
  under normal Python and `PYTHONOPTIMIZE=2`; security checks never rely on
  `assert`.
- NFR-9: All first-party imports MUST be present in the
  exact Execution release allowlist and operator-tooling closure.

## Acceptance Criteria

### AC-1: Exact provider inventory (FR-1, FR-4)

Given the authoritative Windows Execution factory contract  
When the provider configuration is parsed  
Then exactly 46 ports, 37 required ports, 9 optional ports, and 12
purpose-bound Credential Manager references are reconstructed.

### AC-2: Pure static construction (FR-14, FR-16)

Given effect sentinels for provider, credential, clock, SQLite, MT5, process,
network, task, and broker boundaries  
When configuration validation, pack generation, or candidate assembly runs  
Then every sentinel remains untouched.

### AC-3: Platform guard precedes effects (FR-2, NFR-1)

Given a valid provider configuration on a non-Windows platform  
When runtime materialization is requested  
Then it rejects with `WINDOWS_PLATFORM_REQUIRED` before every effect.

### AC-4: Credential and trust separation (FR-4, FR-5)

Given credential purpose, target, fingerprint, clock-key, or trust-domain
reuse drift  
When provider configuration is parsed  
Then parsing fails closed with a stable non-secret reason.

### AC-5: Signed external evidence (FR-7, FR-8)

Given missing, stale, tampered, replayed, predecessor-mismatched, or unsigned
external state  
When its provider attempts verification  
Then verification rejects without advancing any CAS or broker state.

### AC-6: Preprovisioned state only (FR-6, FR-13)

Given journal, risk, session, supervisor, or outbox state that is absent or
has an invalid schema or identity  
When provider materialization runs  
Then it rejects without creating first-use state.

### AC-7: Sealed DEMO composition (FR-2, FR-3, FR-10, FR-11, FR-12, FR-14)

Given exact DEMO production configuration, factory context, clock, provider,
heartbeat, and credential fixtures  
When the Execution materializer runs on Windows  
Then it returns an exact sealed `WindowsServiceFactoryResult` with 46 bound
roles and `mt5_module=None`; dormant `DEMO_AUTO` remains policy-locked.

### AC-8: Deterministic four-file pack (FR-15, FR-16, NFR-2)

Given identical canonical input and one exact atomic-suite Execution base  
When the provider pack is generated twice  
Then both outputs contain the same exact four secret-free files and identical
bytes, while static validation performs zero runtime effects.

### AC-9: Immutable configured candidate (FR-17, FR-18, FR-20)

Given a valid provider pack, exact task definition, and suite role  
When the configured candidate is assembled and validated  
Then the original pack is preserved byte-for-byte, task/provider tamper is
rejected, and the result remains deny-only.

### AC-10: Regression and release closure (NFR-6, NFR-8, NFR-9)

Given the completed local implementation  
When focused, full normal, full optimized, dependency-lock, SBOM, compile,
diff, and security checks run  
Then every automated check passes with no safety-lock drift.

### AC-11: Honest ship gate (FR-19, FR-20)

Given AC-1 through AC-10 evidence  
When ship-gate documentation is updated  
Then it may mark the local Execution pack composition slice as passing while
external acceptance, manual-demo, soak, and live trading remain blocked.

## Edge Cases

- EC-1: An unknown, missing, duplicate, case-colliding, or reordered provider
  binding MUST fail before provider access.
- EC-2: A credential reference with the wrong purpose, target prefix, key ID,
  or fingerprint MUST fail before its backend is read.
- EC-3: The independent signed-clock key ID or fingerprint reused by any
  Execution credential domain MUST fail configuration parsing.
- EC-4: A non-Windows host MUST fail before path, credential, clock, SQLite,
  provider, network, or MT5 effects.
- EC-5: A service-config file hash, production-config source hash, bootstrap
  binding, runtime mode, or factory context mismatch MUST fail before runtime
  provider construction.
- EC-6: DEMO_AUTO input while the centralized policy lock is false MUST fail
  before credential or provider access.
- EC-7: An optional DEMO_AUTO provider MUST remain unmaterialized in DEMO;
  externally configured manual-approval trust is the only conditional optional
  DEMO key provider.
- EC-8: Missing or invalid heartbeat outbox/transport/key providers MUST fail
  before a service result is sealed.
- EC-9: Output collision, symlink/reparse input, unstable read, duplicate JSON
  key, non-finite number, or oversized document MUST fail without overwrite.
- EC-10: Any attempt to inject an MT5 module, place an order during build, or
  enable a safety lock MUST fail closed.

## API Contracts

The feature exposes local Python APIs only; no HTTP endpoint is introduced.

```typescript
interface LocalExecutionProviderAPI {
  parse(payload: Readonly<Record<string, unknown>>):
    WindowsExecutionProviderConfiguration;
  build(
    runtimeConfig: Readonly<Record<string, unknown>>,
    context: WindowsServiceFactoryContext,
    providerConfig: WindowsExecutionProviderConfiguration,
  ): WindowsServiceFactoryResult;
}
```

```text
windows_execution_provider_configuration_from_dict(
    payload: Mapping[str, object]
) -> WindowsExecutionProviderConfiguration

build_windows_execution_factory_result(
    *,
    runtime_config: Mapping[str, object],
    factory_context: WindowsServiceFactoryContext,
    provider_config: WindowsExecutionProviderConfiguration,
) -> WindowsServiceFactoryResult

prepare_windows_execution_provider_pack(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    pack_input_path: str | Path,
    output_root: str | Path,
) -> WindowsExecutionProviderPackValidation

validate_windows_execution_provider_pack(...) ->
    WindowsExecutionProviderPackValidation

assemble_windows_execution_configured_candidate(...) ->
    WindowsExecutionConfiguredCandidate

validate_windows_execution_configured_candidate(...) ->
    WindowsExecutionConfiguredCandidate
```

Candidate assembly additionally consumes one canonical, non-secret
`windows-execution-configured-candidate-input-v1` document. It supplies the
reviewed `bootstrap_binding_sha256` and Task Scheduler identity hashes that
cannot be inferred safely from task XML. The assembler derives the task XML
hash, provider and credential drafts, configured release identity,
production-config hash, and service-config hash itself; caller-supplied
duplicates of those derived facts are forbidden.

## Data Models

| Model | Key fields | Constraints |
|---|---|---|
| `ExecutionCredentialReference` | `reference_id`, `key_id`, `target_name`, `purpose`, `fingerprint_sha256` | Exact purpose order, unique target/key/fingerprint, no secret material |
| `ExecutionProviderBinding` | `port_name`, `provider_id`, `provider_kind`, three SHA-256 bindings, optional credential reference | Exact authoritative order, kind, contract hash, and custody |
| `WindowsExecutionProviderConfiguration` | suite/release/config hashes, 46 provider bindings, 12 credential references, clock binding/path, locks | Immutable, canonical, DEMO or dormant DEMO_AUTO only |
| `WindowsExecutionProductionConfigSource` | exact `ProductionRuntimeConfig`, source SHA-256 | Source hash and bootstrap safe-binding must match reviewed context |
| `WindowsExecutionHeartbeatTransport` | `destination_id`, transport | Canonical destination and callable `deliver` port |
| `WindowsExecutionConfiguredCandidate` | suite/pack/configured release/task/template hashes, effects, locks | Exact 15-file receipt, deny-only, external conformance required |

## Out of Scope

- OS-1: Enabling the centralized DEMO_AUTO policy lock.
- OS-2: Issuing credentials, clock attestations, WORM roots, permits, approvals,
  promotion evidence, environment arms, or stage authorizations.
- OS-3: Registering Task Scheduler jobs or changing ACLs.
- OS-4: Starting a service, initializing MT5, or placing any order during build or
  validation.
- OS-5: Claiming provider acceptance, manual-demo completion, demo-auto soak
  completion, live readiness, or statistical promotion.
