# Trusted Risk Context Factory v1

## Status and scope

This contract defines the only production-oriented boundary that may translate
mutable runtime evidence into a `RiskContext`. It is deliberately deny-only:
it contains no MetaTrader import, network access, broker mutation, order call,
promotion action, or kill-switch reset. `live_allowed` and
`safe_to_demo_auto_order` are permanently `false` on every receipt and on the
sealed result.

The factory does not make demo-auto or live execution ready. Its output is an
input proof for later manual-demo orchestration. The existing risk governor
continues to hard-deny `DEMO_AUTO` and `LIVE` modes.

## Inputs and trust domains

Every call is bound to explicit expected values for account alias, broker
server, environment, canonical and broker symbol, mode, permit symbol set,
runtime account identity, broker specification, journal, commit, configuration,
model, promotion evidence, calibration data window, and signing-key IDs.

The factory requires these exact types:

- sealed `RiskStateReceipt` from the durable HMAC-chained risk ledger;
- signed `RuntimeFactReceipt`, including `RuntimeAccountFact`, broker spec,
  tick, runtime health, and journal identity;
- signed `ExposureReceipt` containing typed active broker orders, positions,
  their exact counts, and every reserved canonical symbol;
- signed `RiskCalibrationReceipt` containing median/p95 spread and p95
  slippage for one exact lane;
- sealed `MarketGuardDecision` carrying trusted news-signature provenance;
- sealed `PermitValidation` created by the permit verifier;
- sealed `USDRiskCapConversion` created from conservative broker quotes; and
- an aware UTC trusted clock plus independent key providers.

HMAC domains are separated for exposure and calibration receipts. Secrets must
contain at least 32 bytes. Hashes are canonical SHA-256 values.

## Freshness

- risk-state receipt: at most 1 second old;
- runtime facts: the existing signed one-second receipt window;
- exposure/reconciliation: positive lifetime no longer than 1 second;
- market guard: at most 1 second old;
- permit validation: checked at most 1 second ago and its signed permit must
  still be valid;
- USD conversion: at most 1 second old; and
- calibration: signed validity no longer than 24 hours and still current.

Future-dated evidence is rejected. The sealed wrapper expires at the earliest
expiry across all of these proofs, so combining individually valid artifacts
cannot create a longer authorization window.

## Exposure semantics

`BrokerExposure` records one exact active `ORDER` or `POSITION`: broker ID,
canonical symbol, broker symbol, side, and volume. IDs must be globally unique.
Receipt counts must exactly match the tuples. All observed symbols must be
reserved, and reconciliation must be explicitly clean. For the evaluated lane,
the observed broker symbol must equal the current broker specification.

The resulting `RiskContext.open_position_count` is conservative: active orders
and active positions are summed. A pending order therefore consumes the global
position allowance instead of disappearing from risk accounting.

## Calibration adequacy

Calibration is accepted only when all of the following hold:

- exact account/server/environment/symbol/broker-symbol binding;
- exact runtime identity, broker-spec, config, and data-window hashes;
- valid HMAC and key ID;
- at least 20 observed sessions;
- a window spanning at least 19 days;
- sample count no lower than session count;
- positive median and p95 spread;
- p95 spread greater than or equal to median spread; and
- non-negative p95 slippage.

The factory uses p95 slippage as both estimated and p95 slippage. This is a
conservative choice at the trust boundary.

## Cross-proof invariants

Before construction, the factory verifies:

- every signature or sealed type;
- exact account, server, environment, symbol, broker symbol, journal, and
  runtime identity across all applicable proofs;
- risk-ledger account currency equals the current broker account/spec currency;
- risk-ledger current equity is exactly equal to runtime account equity;
- runtime health is healthy, including journal integrity, heartbeat, clock,
  disk, audit export, backup, feed freshness, and unlatched kill switch;
- news, rollover, and feed state are all clear with no reason codes;
- permit signature/binding/time results are valid and match every expected
  build and lane value;
- reconciliation is clean and exposure counts/reservations are consistent;
- calibration is sufficiently observed and correctly ordered; and
- USD conversion is exact-account bound and fresh.

Any missing, mistyped, stale, replayed, tampered, unhealthy, or mismatched proof
raises `RiskContextVerificationError`; no partial context is returned.

## Output

Only `create_verified_risk_context()` can mint `VerifiedRiskContext`. The
wrapper contains the pure `RiskContext`, a sub-second expiry, and canonical
hashes for every proof:

- risk state;
- runtime facts;
- exposure;
- calibration;
- market guard;
- permit validation; and
- USD conversion.

Direct wrapper construction is rejected by a private seal. Downstream
production orchestration should accept the sealed wrapper rather than a raw
caller-constructed `RiskContext`. Integration with an executor is intentionally
out of scope for v1 and must be reviewed separately.

## Acceptance tests

Focused tests cover a successful synthetic manual-demo construction and reject:

- missing or wrong proof types;
- exposure, calibration, runtime, or risk-ledger signature tamper;
- stale or future replay;
- account, server, symbol, data-window, and mode/permit mismatch;
- risk-ledger/runtime equity disagreement;
- dirty reconciliation, incorrect counts/reservations, and broker-symbol drift;
- fewer than 20 calibration sessions; and
- stale USD conversion.
