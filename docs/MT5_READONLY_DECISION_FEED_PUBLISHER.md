# MT5 Read-Only Decision-Feed Publisher

Status: **REFERENCE IMPLEMENTATION COMPLETE / WINDOWS ACCEPTANCE PENDING /
ORDER CAPABILITY DISABLED**

`live_runtime/mt5_decision_feed_publisher.py` is the broker-side adapter for
the signed finalized-M15 handoff. It belongs to
`WINDOWS_READ_ONLY_SHADOW_SERVICE_V1`, not to the brokerless decision service
and not to the gated execution service.

## Runtime boundary

```text
read-only demo terminal
  → exact account/server attestation
  → finalized current-boundary M15 bars
  → first eligible tick within ten seconds
  → independent session-gap receipts
  → signed append-only decision feed
  → brokerless decision consumer
```

The publisher receives a capability-reduced market facade, exact immutable
binding, sealed account-identity and calendar-receipt ports, trusted UTC, and
an already constructed signed-feed directory. It never receives terminal
initialization/login authority, key provisioning, risk approval, permit,
executor, reconciliation, or broker mutation methods.

Every cycle:

1. attests effective read-only account and terminal facts;
2. verifies exact `DEMO` server and keyed non-reversible account identity;
3. reads each lane independently and requires the current finalized M15
   boundary;
4. accepts only the first bid/ask tick strictly after close and no later than
   ten seconds;
5. obtains one exact pre-issued closure receipt for every internal M15 gap;
6. re-attests account/terminal facts after market reads;
7. rejects clock regression, future ticks, elapsed entry windows, or publish
   lag above the lane budget;
8. passes the earlier entry-window/publish-lag deadline to the feed, which
   re-reads trusted UTC immediately before a new create-exclusive write; and
9. publishes through the existing create-exclusive signed feed.

One lane data failure is isolated as `HOLD`; trusted clock, read-only
attestation, server, or account binding failure rejects the whole cycle before
publication. Public errors contain stable reason codes only.

## Windows acceptance still required

The implementation alone is not an accepted provider. Before it can supply a
demo-auto decision service, an independent Windows review must bind and test:

- exact terminal, demo account alias hash, server, symbol names, offsets, data
  contract, and calendar hash;
- separate Credential Manager custody for feed signing and keyed account
  identity;
- ACL-protected feed directory and service identities;
- independent trusted clock and session-closure receipt source;
- restart, replay, conflicting candle, feed rotation, disk-full, clock-drift,
  account-switch, key-loss, and latency drills;
- configured release identity, Task Scheduler definition, provider
  conformance evidence, and external signature.

Passing these checks still does not enable orders. The manual-demo gates,
ten controlled lifecycles, separate activation review, and demo-auto soak gate
remain mandatory.

The normative contract is
`specs/mt5_readonly_decision_feed_publisher_v1.md`.
