# Windows Decision Service Release

AI_SCALPER now has a separate deterministic decision-process profile:
`WINDOWS_DECISION_SERVICE_V1`. It is not the executor bundle and does not
contain MT5, risk, permits, reconciliation, credentials, or order primitives.

## Build

Build only from a clean reviewed commit, with output outside the repository:

```powershell
python -B .\build_windows_decision_release.py `
  --allowlist .\config\windows_decision_service_allowlist.v1.json `
  --output C:\AI_SCALPER_RELEASES\windows-decision-service-v1.zip
```

The build fails if the worktree is dirty, an allowlisted byte differs from the
commit, the exact import closure changes, the dependency lock drifts, or any
broker/execution capability enters the bundle.

The manifest must report:

```text
release_profile: WINDOWS_DECISION_SERVICE_V1
order_capability: DISABLED
live_allowed: false
safe_to_demo_auto_order: false
max_lot: 0.01
production_execution_ready: false
runtime_factory: EXTERNAL_NOT_BUNDLED
```

## Static factory manifest

The external factory manifest is non-secret. It binds the release identity and
exact implementation/configuration hashes for seven provider roles:

- `FINALIZED_M15_DATA`
- `TRUSTED_CLOCK`
- `IPC_SIGNING_KEY_CUSTODY`
- `IPC_CHECKPOINT_CAS`
- `PRODUCER_CURSOR_CAS`
- `PRODUCER_CURSOR_ACK_VERIFIER`
- `SESSION_CALENDAR_VERIFIER`

The base release includes a reviewed implementation option for
`FINALIZED_M15_DATA`: `live_runtime/decision_feed.py`. It consumes a
create-exclusive per-lane stream of canonical HMAC-authenticated packets,
verifies exact broker/account/lane/source/calendar binding, sequence and
immediate predecessor, and reconstructs the exact
`FinalizedM15DecisionInput`. It has no MT5, network, credential lookup, risk,
permit, executor, or order surface. The broker-facing read-only publisher,
key custody, directory ACL, clock behavior, and real conformance evidence are
external provider responsibilities.

The feed is runtime transport only. A valid packet is not validation evidence,
does not make `source_aligned` or `data_fresh` semantically true, and cannot
bypass the producer's existing OHLC/gap/calendar/freshness/entry-window checks.
See `specs/signed_decision_feed_handoff_v1.md`.

Every lane binds an immutable session-calendar hash plus issuer/key identity.
The data input may bridge a weekend, holiday, or DST-shifted interval only with
one exact HMAC-authenticated closure receipt per gap. No weekday/timezone
heuristic and no synthetic padding bar is allowed.
The release allowlist requires the calendar verifier's exact implementation
and configuration hash binding, and the build manifest embeds the complete
provider-contract hash map. Omitting this provider makes static validation
fail; a generic data-provider declaration cannot substitute for it.

Producer cursor CAS acknowledgements are also HMAC-authenticated through a
sealed verifier port bound to the custody key fingerprint. Supplying a raw
truthy callback is rejected; the provider role's implementation and
configuration hashes remain pinned by this static factory manifest.

Generate/review the payload with independent deployment tooling using
`windows_decision_service_factory_contract()`. Do not place key values, broker
credentials, data, cursor databases, or IPC state in the manifest or Git.

## Create the configured identity

The ZIP above is a base release. A production process must not copy its factory
or providers into the extracted base directory. Bind the reviewed, secret-free
factory/config/provider overlay through
`build_windows_configured_service_release.py`, then independently verify the
result against both externally pinned identities. The configured identity—not
the base identity—is the identity that a future launcher attestation must bind.
See `docs/WINDOWS_CONFIGURED_SERVICE_RELEASE.md`.

Configured packaging does not add broker capability or activate the process.
The bundled decision runner now has an operational path, but it accepts only
an exact configured release, a release-local reviewed factory, and a valid
short-lived external RSA launcher attestation. Real provider implementations,
provider acceptance, service identity/ACLs, and launcher issuance remain
external gates.

## Validate the base release

After extracting the reviewed ZIP into an ACL-protected Windows directory:

```powershell
python -B .\run_windows_decision_service.py `
  --release-root C:\AI_SCALPER_DECISION_RELEASE `
  --factory-manifest C:\AI_SCALPER_PRIVATE\decision-factory.json `
  --expected-release-identity-sha256 <independently-reviewed-sha256> `
  --validate-only
```

Validate-only checks the complete extracted file set and hash inventory, then
validates the factory template. It does not fetch a candle, open or modify IPC,
open cursor state, resolve a key, import a provider, or contact a broker.

Operational invocation uses the same entrypoint without `--validate-only`:

```powershell
python -B .\run_windows_decision_service.py `
  --release-root C:\AI_SCALPER_DECISION_CONFIGURED `
  --factory-manifest C:\AI_SCALPER_DECISION_CONFIGURED\config\windows_factory_manifest.json `
  --expected-release-identity-sha256 <PINNED_CONFIGURED_RELEASE_IDENTITY> `
  --release-trust-policy C:\AI_SCALPER_PRIVATE\decision-launcher-policy.json `
  --expected-release-trust-policy-sha256 <PINNED_POLICY_SHA256> `
  --release-attestation C:\AI_SCALPER_PRIVATE\decision-launcher-attestation.json
```

The runner fails before factory import when the configured identity, external
trust documents, profile, host/service/task binding, factory inventory, or
provider contract is missing or changed. Passing that boundary proves only
runtime provenance; it does not supply provider acceptance, install a task,
grant broker authority, or unlock demo-auto/live policy.

## Separation rule

The executor and decision release must use different roots, service accounts,
factory manifests, state directories, and release identities. The decision
process publishes signed `DecisionSnapshot` envelopes only. The executor owns
risk, intent, preflight, broker mutation, and reconciliation; those modules are
forbidden from this bundle.
