# Windows Decision Service Runtime v1

## Status

- Release profile: `WINDOWS_DECISION_SERVICE_V1`
- Runtime class: brokerless finalized-M15 decision producer
- Order capability: `DISABLED`
- Live allowed: `false`
- Safe to demo-auto order: `false`
- Maximum lot: `0.01`

This contract makes the configured decision release runnable without adding
any execution authority. It does not make the host accepted, issue a launcher
attestation, materialize a real provider, install a task, or begin demo-auto
soak.

## Security boundary

1. Operational launch MUST require a configured deterministic decision
   release. A base release or an external/unbound factory manifest is rejected.
2. The configured release identity, complete extracted inventory, every source
   byte, nested base identity, overlay descriptor, factory source, service
   configuration, and provider source MUST remain release-bound.
3. A short-lived external RSA launcher attestation for
   `WINDOWS_DECISION_SERVICE_V1` MUST be verified before the factory module is
   imported or invoked.
4. The trust policy and attestation MUST be stable regular files outside the
   release root. They MUST bind the exact configured release, host alias,
   service-account alias, task definition, issuer, key, nonce, and validity
   window.
5. The reviewed factory import scope MUST allow only:
   - exact release-bound Python modules; and
   - Python standard-library modules outside `site-packages` and
     `dist-packages`.
   Dynamic import loaders, module-registry replacement, path indirection,
   extra release members, and changed files fail closed.
6. The factory MUST return an exact sealed
   `WindowsDecisionServiceFactoryResult`. Caller construction, subclasses,
   duck-typed services, or an unbound result are rejected.
7. The sealed result MUST contain an exact
   `BrokerlessDecisionProducerService`. Its immutable
   `DecisionProducerBinding` hash MUST equal the factory manifest bootstrap
   binding and its service ID MUST equal the service configuration.
8. The non-secret runtime configuration MUST bind:
   - one exact `DecisionProducerBinding`;
   - all seven decision provider contract/hash/custody bindings;
   - bounded cycle count, poll interval, and cycle deadline; and
   - all deny-only safety locks.
9. A cycle deadline failure MUST terminate the process boundary. Returning
   from the termination primitive is itself an error. The runner never
   retries a failed or timed-out cycle in the same process.
10. Validate-only MUST verify the configured release, manifest, runtime
    configuration, provider bindings, and safety locks without importing the
    factory, resolving a key, opening provider state, fetching market data, or
    publishing IPC.

## Runtime configuration

The exact canonical JSON object uses schema
`windows-decision-service-runtime-config-v1` and contains:

- `service_id`
- `max_cycles`
- `poll_seconds`
- `cycle_deadline_seconds`
- `decision_producer_binding`
- `providers`
- `order_capability = DISABLED`
- `live_allowed = false`
- `safe_to_demo_auto_order = false`
- `max_lot = 0.01`
- `schema_version`

No credential value, signing key, password, account login, URL, broker symbol,
or mutable runtime state belongs in this document.

## Runner behavior

Operational invocation requires:

- release-local factory manifest;
- exact configured release identity;
- external RSA trust policy and independently pinned policy SHA-256; and
- external short-lived launcher attestation.

The runner verifies trust, loads one exact reviewed factory, rechecks the
attestation, installs signal handlers, and executes the configured bounded
number of cycles. Output is a summary of decision-only cycle counts and lane
statuses. It never prints a decision key, provider secret, full market frame,
or IPC payload.

## Acceptance criteria

- AC-1: valid runtime config reconstructs the exact producer binding and seven
  provider bindings.
- AC-2: unknown/missing fields, naive timestamps, invalid hashes, relaxed
  safety values, service/binding mismatch, or bootstrap mismatch fail closed.
- AC-3: factory result construction is sealed and exact-type checked.
- AC-4: validate-only performs no provider import or runtime effect.
- AC-5: non-validate launch without a decision-profile attestation fails
  before factory import.
- AC-6: cross-profile policy/attestation use fails closed.
- AC-7: valid decision attestation plus exact configured factory can run one
  bounded `NO_INPUT` decision cycle without broker capability.
- AC-8: timeout, signal stop, factory tamper, config tamper, extra member,
  symlink/reparse point, unreviewed import, and module-registry mutation fail
  closed.
- AC-9: the deterministic decision release contains the runtime loader and
  asymmetric public verifier but no broker/risk/permit/executor module.
- AC-10: full normal and optimized repository regressions remain green and all
  activation locks remain unchanged.

## External blockers retained

- real provider implementations and configuration acceptance;
- Windows Credential Manager or external key/CAS custody;
- offline launcher-policy and attestation issuance;
- exact Windows/Python/NTFS/Task Scheduler/service-account acceptance;
- reviewed configured status-monitor release/provider and real off-host alert
  delivery acceptance;
- minimum-lot XAUUSD risk feasibility;
- ten controlled manual-demo order lifecycles; and
- manual demo-auto activation approval.
