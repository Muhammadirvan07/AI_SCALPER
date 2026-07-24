# Spec: Account-Currency Risk Caps and Locked Manual-Demo Readiness

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-22
**Status:** Approved
**Reviewers:** AI_SCALPER project owner (explicit continuation approval on 2026-07-22)
**Related specs:** `specs/phillip_multi_account_binding_probe.md`, `specs/phillip_lane_evidence_contract.md`

## Context

The current broker sizing and pure risk-governor paths compare the USD-denominated
absolute risk limits (`$0.20` for XAU and `$0.25` for FX) directly with values
returned by MetaTrader 5. MetaTrader 5 calculates profit, loss, margin, and account
equity in the account currency. This is dimensionally correct only for USD accounts.
For Phillip demo accounts denominated in JPY, the existing implementation therefore
treats the limits as approximately `JPY 0.20` and `JPY 0.25`. The behavior fails
closed, but it prevents valid conservative sizing and leaves an unsafe unit mismatch
in code that may later participate in manual-demo execution.

The execution foundation already contains permit, approval, account-fence,
idempotency, journal, reconciliation, and submission controls. However, the project
does not yet have a truthful operator-facing command that evaluates whether the
external prerequisites for a controlled manual-demo order have been met without
initializing MT5 or exposing an order path. This change adds that non-mutating
readiness boundary while preserving every current lock. It does not authorize or
submit any broker order.

## Functional Requirements

- FR-1: The system MUST interpret the XAU `$0.20` and FX `$0.25` absolute risk limits as USD values regardless of the broker account currency.
- FR-2: The system MUST convert a USD absolute risk limit into the broker account currency using a sealed broker quote before comparing it with account equity, broker-calculated stop loss, or broker-calculated margin for a non-USD account.
- FR-3: A direct `USD/ACCOUNT` conversion MUST use the broker bid, and an inverse `ACCOUNT/USD` conversion MUST use `1 / broker ask`, so conversion never increases the cap by using the less-conservative side of the spread.
- FR-4: The adapter MUST verify the conversion symbol's broker-reported base and profit currencies, exact configured symbol binding, positive bid/ask, and tick freshness before minting a conversion contract.
- FR-5: The pure risk governor MUST remain free of broker, filesystem, environment, credential, and network I/O.
- FR-6: A non-USD account with a missing, forged, mismatched, stale, or future-dated conversion contract MUST fail closed with a deterministic reason code and a zero normalized lot.
- FR-7: A USD account MUST use an identity conversion rate of exactly `1.0` and MUST retain existing USD sizing behavior.
- FR-8: Risk decisions and broker sizing quotes MUST bind the account currency, original USD cap, applied USD-to-account rate, converted account-currency cap, and conversion contract hash for audit and runtime parity.
- FR-9: The one-shot runtime service MUST pass the exact conversion contract used by the risk context into broker sizing and MUST reject a quote whose currency, USD cap, conversion rate, converted cap, or conversion hash differs.
- FR-10: The project MUST provide a manual-demo readiness command that evaluates tracked candidate, evidence-profile, and safety-policy state without initializing MT5, reading credentials, creating approvals or permits, invoking preflight, or submitting orders.
- FR-11: The readiness command MUST report `ready=false` while any required external, evidence, security, operational, conversion, or approval gate remains incomplete.
- FR-12: The readiness command and tracked readiness policy MUST preserve `execution_enabled=false`, `manual_demo_enabled=false`, `live_allowed=false`, `safe_to_demo_auto_order=false`, `order_capability=DISABLED`, and `max_lot=0.01`.
- FR-13: The readiness command MUST reject unknown candidates, malformed or duplicate-key policy JSON, and any policy that weakens a locked safety field.
- FR-14: The implementation MUST NOT expand the execution-approved symbol set, issue a promotion permit, create a manual-demo approval, access a login/password, enable terminal trading, call `order_check`, or call `order_send`.

## Non-Functional Requirements

- NFR-1: Currency conversion and readiness evaluation MUST be deterministic for identical validated inputs.
- NFR-2: Conversion facts used by the runtime MUST be no more than one second old relative to the trusted risk-evaluation timestamp and MUST NOT be future-dated.
- NFR-3: All conversion and readiness timestamps MUST be timezone-aware UTC.
- NFR-4: Every new monetary value MUST carry an unambiguous currency or USD semantic in its field name.
- NFR-5: Existing USD risk tests and all existing repository tests MUST continue to pass.
- NFR-6: The readiness command MUST complete without network access and MUST perform zero writes unless the operator explicitly supplies an output path; any optional output creation MUST be atomic and create-only.
- NFR-7: The readiness implementation MUST be included only in the release-operator tooling allowlist, not in the production shadow-service allowlist.

## Acceptance Criteria

### AC-1: Direct JPY conversion uses bid (FR-1, FR-2, FR-3, FR-4)

Given a JPY account, an allowlisted `USDJPY` broker symbol, a matching broker specification, and a fresh tick with bid `150.00` and ask `150.02`
When the adapter creates a USD risk-cap conversion
Then the conversion rate is exactly `150.00` JPY per USD
And the contract records the direct direction, broker symbol, tick timestamp, and a stable content hash.

### AC-2: Inverse conversion uses one over ask (FR-2, FR-3, FR-4)

Given an EUR account, an allowlisted `EURUSD` broker symbol, and a fresh tick with bid `1.1000` and ask `1.1002`
When the adapter creates a USD risk-cap conversion
Then the conversion rate is exactly `1 / 1.1002` EUR per USD
And the bid is not used as the inverse divisor.

### AC-3: JPY caps retain USD meaning (FR-1, FR-2, FR-8)

Given a valid sealed JPY conversion rate of `150.00` JPY per USD and sufficient equity
When the risk governor evaluates an FX intent and an XAU intent
Then their absolute account-currency caps are exactly `JPY 37.50` and `JPY 30.00` respectively
And the original USD caps remain exactly `$0.25` and `$0.20`.

### AC-4: Missing or stale non-USD conversion fails closed (FR-6, NFR-2)

Given a non-USD broker account and no valid conversion contract, or a contract older than one second
When the risk governor evaluates an intent
Then the decision is rejected with a deterministic conversion reason
And `normalized_lot`, `estimated_risk_cash`, and `estimated_margin_cash` are zero.

### AC-5: USD behavior remains compatible (FR-7, NFR-5)

Given a USD broker account and the existing valid USD test fixtures
When the risk governor and broker sizer evaluate the fixtures
Then the applied rate is exactly `1.0`
And the prior normalized lot, USD cap, and approval/rejection outcomes do not change.

### AC-6: Runtime rejects conversion binding drift (FR-8, FR-9)

Given a risk context bound to one sealed conversion contract
When broker sizing returns a quote with a different account currency, rate, converted cap, original USD cap, or conversion hash
Then the one-shot runtime returns `WAIT_SIZING`
And no intent is delegated to the execution coordinator.

### AC-7: Locked readiness reports current blockers (FR-10, FR-11, FR-12)

Given the current Phillip candidate and evidence profiles with registration and external operational gates incomplete
When the operator runs the manual-demo readiness command
Then it reports `ready=false`, `order_capability=DISABLED`, and sorted blocker codes
And it reports every hard lock without changing any repository or broker state.

### AC-8: Readiness cannot be used as an execution surface (FR-10, FR-14, NFR-7)

Given the readiness module and command source
When the security tests inspect imports, arguments, and callable dependencies
Then no MT5 adapter, executor, permit issuer, approval signer, `order_check`, or `order_send` path is present
And the command is absent from the shadow-service allowlist.

### AC-9: Lock weakening is rejected (FR-12, FR-13)

Given a readiness policy in which any execution lock is enabled, order capability is not `DISABLED`, or maximum lot exceeds `0.01`
When the evaluator loads the policy
Then it raises a validation error
And no readiness report or output file is created.

### AC-10: No order or unlock side effects (FR-14)

Given the complete focused and full test suites
When this feature is exercised
Then no broker order is submitted, no terminal mutation is attempted, no credential is read, no permit or approval is issued, and no execution policy lock changes.

## Edge Cases

- EC-1: The account currency is empty, non-alphabetic, or not exactly three uppercase characters → reject account or conversion binding before sizing.
- EC-2: Neither `USD/ACCOUNT` nor `ACCOUNT/USD` is explicitly configured → reject with conversion unavailable; do not discover an arbitrary symbol by fuzzy matching.
- EC-3: Both direct and inverse symbols are configured → reject the ambiguous conversion configuration rather than choosing silently.
- EC-4: Broker symbol metadata does not match the configured base/profit currencies → reject before reading or applying its tick.
- EC-5: Bid is zero, ask is zero, ask is below bid, tick is stale, or tick is future-dated → reject conversion and size zero.
- EC-6: Conversion currency differs from `BrokerSpec.account_currency` → reject with conversion mismatch and size zero.
- EC-7: A caller constructs a conversion object without the internal seal → raise `TypeError`.
- EC-8: Percent-of-equity cap is lower than the converted absolute cap → keep the lower percent cap in account currency.
- EC-9: The broker minimum lot still exceeds the correctly converted cap → return the existing wait status with zero lot.
- EC-10: Readiness input contains duplicate JSON keys, an unknown candidate, a missing candidate profile, a missing required gate, or an unknown gate state → reject or report blocked; never infer readiness.
- EC-11: An optional readiness output path already exists → fail without overwriting it.

## API Contracts

No HTTP API is introduced; in particular, there is no `GET /manual-demo-readiness`
or other network endpoint. The Python contracts are:

```python
def quote_usd_risk_cap_conversion(
    *, now: datetime | None = None
) -> USDRiskCapConversion: ...

def calculate_broker_sized_lot(
    *,
    canonical_symbol: str,
    broker_symbol: str,
    side: str,
    entry_price: float,
    stop_loss: float,
    equity: float,
    allowed_slippage_points: int,
    usd_risk_cap_conversion: USDRiskCapConversion | None,
    now: datetime | None = None,
) -> BrokerSizingQuote: ...

def evaluate_manual_demo_readiness(
    *,
    candidate_id: str,
    candidate_plan: Mapping[str, object],
    evidence_profiles: Mapping[str, object],
    readiness_policy: Mapping[str, object],
    evaluated_at_utc: datetime,
) -> ManualDemoReadinessReport: ...
```

The command contract is:

```text
python -B run_manual_demo_readiness.py --candidate <candidate-id> [--output <new-file>]
```

It MUST NOT accept execution, account-login, password, secret, arm, permit, approval,
terminal-path, or volume arguments.

## Data Models

### `USDRiskCapConversion`

| Field | Type | Constraint |
|---|---|---|
| `account_id` | string | Exact adapter account alias |
| `server` | string | Exact adapter broker server |
| `account_currency` | string | Exactly three uppercase alphabetic characters |
| `account_currency_per_usd` | float | Finite and greater than zero; exactly `1.0` for USD |
| `source` | enum | `ACCOUNT_CURRENCY_IDENTITY` or `MT5_BID_ASK` |
| `broker_symbol` | string | `USD` for identity or exact configured broker symbol |
| `direction` | enum | `IDENTITY`, `DIRECT`, or `INVERSE` |
| `bid` | float | Positive for broker quote; `1.0` for identity |
| `ask` | float | At least bid; `1.0` for identity |
| `captured_at_utc` | UTC datetime | Broker tick time or trusted identity timestamp |
| `content_sha256` | derived | Canonical immutable contract hash |

### Risk audit additions

`RiskDecision` and `BrokerSizingQuote` carry:

- `account_currency`
- `absolute_risk_cap_usd`
- `usd_to_account_currency_rate`
- `absolute_risk_cap_account_currency`
- `conversion_quote_sha256`

### `ManualDemoReadinessReport`

| Field | Type | Constraint |
|---|---|---|
| `candidate_id` | string | Exact tracked candidate identifier |
| `evaluated_at_utc` | UTC datetime | Required |
| `status` | enum | `BLOCKED` for the current implementation scope |
| `ready` | bool | MUST remain `false` while any gate is incomplete |
| `blocker_codes` | tuple[string] | Unique, uppercase, sorted, non-empty |
| `candidate_server` | string | Exact tracked server |
| `account_currency` | string | Exact tracked account currency |
| `safety` | immutable mapping | All hard lock values and maximum lot |
| `content_sha256` | derived | Canonical immutable contract hash |

## Out of Scope

- OS-1: Sending, checking, modifying, cancelling, or closing any broker order or position.
- OS-2: Enabling manual-demo, demo-auto, or live execution.
- OS-3: Creating, signing, storing, or distributing promotion permits or manual-demo approvals.
- OS-4: Reading or writing broker credentials, account logins, passwords, Windows Credential Manager entries, or environment arm tokens.
- OS-5: Registering Phillip evidence profiles or overriding human regulatory/calendar review.
- OS-6: Increasing the `$0.20` XAU cap, `$0.25` FX cap, `0.25%` equity cap, `0.01` maximum lot, or any other risk limit.
- OS-7: Adding XAUUSD, USDJPY, AUDUSD, crypto, or any other symbol to the execution-approved symbol set.
- OS-8: Replacing the required 20 broker sessions, 50 broker-forward trades, eight-week observation, 10 controlled manual-demo orders, 30-day demo soak, failure drills, news provider, reconciliation, or security gates.
- OS-9: Building the eventual operator process that consumes approvals and permits to call the existing execution coordinator.
