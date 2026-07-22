# Dormant DEMO_AUTO Dispatch Contract v1

## Status

This contract defines an activation-ready composition seam for demo automation.
It does not activate broker mutation. The checked-in release remains locked by:

- `SAFE_TO_DEMO_AUTO_ORDER = false`
- `LIVE_ALLOWED = false`
- `ORDER_CAPABILITY = DISABLED`

There is no command-line flag, environment-variable bypass, deployment switch, or
fallback from manual DEMO that can enable this path. A separately reviewed source
release must change the central execution policy before `DEMO_AUTO` can be
configured or started.

## Dispatch authority

`RuntimeSupervisorDecision.action = DEMO_AUTO_EXECUTE` is accepted only for a
decision with an exact `intent_id`. The supervisor may dispatch it only when all
of these sealed, mutually bound authorities are current at the dispatch boundary:

1. one-use, consumed decision IPC input;
2. current DEMO_AUTO session lease and external session checkpoint;
3. stage authorization and stage validation;
4. fresh promotion-evidence validation;
5. fresh promotion-permit validation;
6. fresh environment-arm observation;
7. current supervisor checkpoint and journal custody;
8. current risk source/checkpoint and signed news successor;
9. matching executor fence, account, server, lane, build, config, model, decision,
   risk event, intent, reconciliation, and execution receipt.

The tradable symbol is decided only by `execution_policy.validate_execution_symbol`.
The supervisor must not carry a private symbol allowlist.

## State-machine boundary

All externally fallible DEMO_AUTO controls are verified while the intent is still
`PREFLIGHT_PASSED`, immediately before the global submission reservation is
acquired. A failed final check transitions to `REJECTED` with durable evidence:

- `broker_submit_called = false`
- `reconciliation_required = false`
- `retry_allowed = false`

After `SUBMITTING`, the existing journal broker-exposure invariant is unchanged:
the slot cannot be released without typed broker or reconciliation evidence.

## Durable dispatch settlement and restart recovery

Every DEMO_AUTO session reservation is joined to the execution journal by the
exact session, intent, account, server, release, build, configuration, model,
and clean-generation binding. The durable reservation state is one of:

`ACTIVE -> ABORTED_BEFORE_SEND | COMPLETED | RECONCILIATION_REQUIRED -> RECONCILED`

An `ACTIVE` reservation is not proof that a broker call occurred. The final
submission guard therefore writes a privileged `SUBMISSION_LEASE_NOT_CONSUMED`
receipt only when the one-use broker submission lease was never consumed. A
before-send abort is accepted only when that receipt and the exact final guard
and authorization are present. A caller-provided “not sent” claim without this
journal proof is rejected.

Once the lease is consumed, any exception or missing execution receipt is
classified as `RECONCILIATION_REQUIRED`. Neither a process restart nor session
renewal may release that reservation. It becomes `RECONCILED` only after an
exact signed broker reconciliation receipt is durably joined to the journal.
The executor never resubmits the intent while this state is unresolved.

At startup, production bootstrap recovers every unresolved session reservation
from a sealed journal settlement before accepting new work:

- conclusive unused-lease proof produces `ABORTED_BEFORE_SEND`;
- an exact execution receipt produces `COMPLETED`;
- consumed or indeterminate submission authority produces
  `RECONCILIATION_REQUIRED`; and
- an exact reconciliation receipt produces `RECONCILED`.

Failure to persist the session-side settlement does not change broker truth;
the next startup repeats recovery from the append-only journal.

## Activation acceptance

A reviewed DEMO_AUTO release is incomplete until deployment supplies and verifies:

- Windows production decision-data provider and one-use IPC custody;
- current session capability store plus off-host CAS custody;
- permit, promotion, environment-arm, journal, risk, news, reconciliation, and
  supervisor checkpoint authorities;
- exact reviewed broker/account/server/symbol mapping and dependency attestations;
- clean failure-drill evidence for restart, disconnect, timeout, duplicate intent,
  partial fill, missing protection, orphan position, and clock drift;
- a fake-adapter acceptance run proving one dispatch and zero duplicate sends.

The checked-in policy must remain false until those external authorities are
available and a human-reviewed release explicitly enables the central policy.

## Demo-auto soak and live promotion

The demo-auto soak is an output of an activated DEMO_AUTO release, not an
activation prerequisite. After activation, the soak must collect at least 30 days
and 50 broker demo fills with zero duplicate, orphan, unexplained-position, or
critical-alert failures. Lane-specific roadmap evidence remains mandatory.

Completing demo soak does not enable live trading. Live stays a separate release
and approval gate, including the full promotion thresholds, regulatory review,
XAU canary sequencing, and a new explicit source-level policy decision.
