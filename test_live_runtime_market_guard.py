from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.market_guard import (
    NEWS_FEED_SCHEMA_VERSION,
    MarketGuardDecision,
    NewsEvent,
    NewsFeed,
    evaluate_market_guards,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)
NEWS_KEY = b"trusted-calendar-hmac-key-v1-32bytes!!"


class MarketGuardTests(unittest.TestCase):
    def feed(self, fetched_at=NOW, event_at=None, currency="USD", **overrides):
        signed = overrides.pop("_signed", True)
        if event_at is not None:
            events = (
                NewsEvent(
                    event_id="nfp",
                    currency=currency,
                    impact="HIGH",
                    scheduled_at=event_at,
                ),
            )
        else:
            events = (
                NewsEvent(
                    event_id="coverage-sentinel",
                    currency="EUR",
                    impact="LOW",
                    scheduled_at=fetched_at,
                ),
            )
        values = {
            "fetched_at": fetched_at,
            "events": events,
            "provider_name": "regulated-calendar-provider",
            "provider_healthy": True,
            "schema_version": NEWS_FEED_SCHEMA_VERSION,
            "coverage_start_at": fetched_at - timedelta(hours=1),
            "coverage_end_at": fetched_at + timedelta(hours=2),
            "signing_key_id": "calendar-key-v1",
        }
        values.update(overrides)
        feed = NewsFeed(**values)
        return feed.sign(NEWS_KEY) if signed else feed

    def evaluate(self, **kwargs):
        return evaluate_market_guards(
            news_signing_key_provider=lambda key_id: NEWS_KEY,
            **kwargs,
        )

    def test_news_blackout_boundaries_are_inclusive(self) -> None:
        event_at = NOW + timedelta(minutes=30)
        result = self.evaluate(
            symbol="XAUUSD",
            now=NOW,
            news_feed=self.feed(event_at=event_at),
            broker_rollover_at=NOW + timedelta(hours=5),
        )
        self.assertFalse(result.news_clear)
        self.assertIn("HIGH_IMPACT_NEWS_BLACKOUT", result.reason_codes)

        after = event_at + timedelta(minutes=15, microseconds=1)
        clear = self.evaluate(
            symbol="XAUUSD",
            now=after,
            news_feed=self.feed(fetched_at=after, event_at=event_at),
            broker_rollover_at=after + timedelta(hours=5),
        )
        self.assertTrue(clear.news_clear)

    def test_stale_news_feed_fails_closed(self) -> None:
        result = self.evaluate(
            symbol="EURUSD",
            now=NOW,
            news_feed=self.feed(fetched_at=NOW - timedelta(minutes=15, microseconds=1)),
            broker_rollover_at=NOW + timedelta(hours=5),
        )
        self.assertFalse(result.news_clear)
        self.assertFalse(result.feed_fresh)
        self.assertIn("NEWS_FEED_STALE", result.reason_codes)

    def test_unrelated_currency_does_not_block_but_rollover_does(self) -> None:
        news_clear = self.evaluate(
            symbol="AUDUSD",
            now=NOW,
            news_feed=self.feed(event_at=NOW, currency="JPY"),
            broker_rollover_at=NOW + timedelta(hours=5),
        )
        self.assertTrue(news_clear.news_clear)
        rollover = self.evaluate(
            symbol="USDJPY",
            now=NOW,
            news_feed=self.feed(),
            broker_rollover_at=NOW + timedelta(minutes=5),
        )
        self.assertFalse(rollover.rollover_clear)
        self.assertIn("ROLLOVER_BLACKOUT", rollover.reason_codes)

    def test_naive_timestamps_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.evaluate(
                symbol="XAUUSD",
                now=datetime(2026, 7, 15, 12, 0),
                news_feed=self.feed(),
                broker_rollover_at=NOW,
            )

    def test_legacy_fresh_but_empty_feed_fails_closed(self) -> None:
        result = self.evaluate(
            symbol="XAUUSD",
            now=NOW,
            news_feed=NewsFeed(fetched_at=NOW, events=()),
            broker_rollover_at=NOW + timedelta(hours=5),
        )
        self.assertTrue(result.feed_fresh)
        self.assertFalse(result.news_clear)
        self.assertIn("NEWS_FEED_EMPTY", result.reason_codes)
        self.assertIn("NEWS_FEED_UNTRUSTED", result.reason_codes)

    def test_provider_version_signature_and_coverage_are_hard_gates(self) -> None:
        cases = (
            ({"provider_healthy": False}, "NEWS_PROVIDER_UNHEALTHY"),
            ({"schema_version": "legacy-v0"}, "NEWS_FEED_VERSION_INVALID"),
            ({"_signed": False}, "NEWS_FEED_SIGNATURE_INVALID"),
            (
                {"coverage_start_at": NOW - timedelta(minutes=14, seconds=59)},
                "NEWS_FEED_COVERAGE_INSUFFICIENT",
            ),
            (
                {"coverage_end_at": NOW + timedelta(minutes=29, seconds=59)},
                "NEWS_FEED_COVERAGE_INSUFFICIENT",
            ),
        )
        for overrides, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason):
                result = self.evaluate(
                    symbol="XAUUSD",
                    now=NOW,
                    news_feed=self.feed(**overrides),
                    broker_rollover_at=NOW + timedelta(hours=5),
                )
                self.assertFalse(result.news_clear)
                self.assertIn(expected_reason, result.reason_codes)
                self.assertIn("NEWS_FEED_UNTRUSTED", result.reason_codes)

    def test_empty_feed_fails_even_with_other_trust_proofs(self) -> None:
        result = self.evaluate(
            symbol="XAUUSD",
            now=NOW,
            news_feed=self.feed(events=()),
            broker_rollover_at=NOW + timedelta(hours=5),
        )
        self.assertFalse(result.news_clear)
        self.assertIn("NEWS_FEED_EMPTY", result.reason_codes)

    def test_feed_boolean_and_signature_types_are_exact(self) -> None:
        for overrides in (
            {"provider_healthy": 1},
            {"signature_hmac_sha256": "short"},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises((TypeError, ValueError)):
                    self.feed(**overrides)

    def test_coverage_contract_rejects_partial_or_misrepresented_windows(self) -> None:
        with self.assertRaises(ValueError):
            NewsFeed(
                fetched_at=NOW,
                events=(),
                coverage_start_at=NOW - timedelta(hours=1),
            )
        with self.assertRaises(ValueError):
            self.feed(
                coverage_start_at=NOW + timedelta(minutes=1),
                coverage_end_at=NOW - timedelta(minutes=1),
            )
        with self.assertRaises(ValueError):
            self.feed(
                event_at=NOW + timedelta(hours=3),
                coverage_start_at=NOW - timedelta(hours=1),
                coverage_end_at=NOW + timedelta(hours=2),
            )
        with self.assertRaises(ValueError):
            self.feed(
                fetched_at=NOW,
                coverage_start_at=NOW + timedelta(minutes=1),
                coverage_end_at=NOW + timedelta(hours=2),
                events=(),
            )

    def test_signed_payload_covers_events_and_coverage(self) -> None:
        feed = self.feed()
        trusted = self.evaluate(
            symbol="XAUUSD",
            now=NOW,
            news_feed=feed,
            broker_rollover_at=NOW + timedelta(hours=5),
        )
        self.assertTrue(trusted.news_clear)
        self.assertEqual(feed.payload_sha256, trusted.news_feed_payload_sha256)
        self.assertEqual(
            feed.signature_hmac_sha256,
            trusted.news_feed_signature_hmac_sha256,
        )

        tampered_coverage = replace(
            feed,
            coverage_end_at=feed.coverage_end_at + timedelta(minutes=1),
        )
        rejected = self.evaluate(
            symbol="XAUUSD",
            now=NOW,
            news_feed=tampered_coverage,
            broker_rollover_at=NOW + timedelta(hours=5),
        )
        self.assertFalse(rejected.news_clear)
        self.assertIn("NEWS_FEED_SIGNATURE_INVALID", rejected.reason_codes)

        tampered_event = replace(
            feed,
            events=(
                replace(feed.events[0], impact="HIGH"),
            ),
        )
        rejected = self.evaluate(
            symbol="XAUUSD",
            now=NOW,
            news_feed=tampered_event,
            broker_rollover_at=NOW + timedelta(hours=5),
        )
        self.assertIn("NEWS_FEED_SIGNATURE_INVALID", rejected.reason_codes)

    def test_self_attested_or_unknown_key_cannot_verify(self) -> None:
        unsigned = self.feed(_signed=False)
        result = evaluate_market_guards(
            symbol="XAUUSD",
            now=NOW,
            news_feed=unsigned,
            broker_rollover_at=NOW + timedelta(hours=5),
            news_signing_key_provider=lambda key_id: NEWS_KEY,
        )
        self.assertFalse(result.news_clear)
        self.assertIn("NEWS_FEED_SIGNATURE_INVALID", result.reason_codes)

        signed = self.feed()
        unknown = evaluate_market_guards(
            symbol="XAUUSD",
            now=NOW,
            news_feed=signed,
            broker_rollover_at=NOW + timedelta(hours=5),
            news_signing_key_provider=lambda key_id: (_ for _ in ()).throw(KeyError(key_id)),
        )
        self.assertFalse(unknown.news_clear)
        self.assertIn("NEWS_FEED_SIGNATURE_INVALID", unknown.reason_codes)

    def test_guard_decision_is_sealed_and_carries_provenance(self) -> None:
        feed = self.feed()
        decision = self.evaluate(
            symbol="XAUUSD",
            now=NOW,
            news_feed=feed,
            broker_rollover_at=NOW + timedelta(hours=5),
        )
        self.assertEqual(feed.signing_key_id, decision.news_signing_key_id)
        self.assertEqual(feed.coverage_start_at, decision.news_coverage_start_at)
        self.assertEqual(feed.coverage_end_at, decision.news_coverage_end_at)

        with self.assertRaisesRegex(TypeError, "only be created"):
            MarketGuardDecision(
                evaluated_at=NOW,
                symbol="XAUUSD",
                news_clear=True,
                rollover_clear=True,
                feed_fresh=True,
                reason_codes=(),
                news_feed_payload_sha256=feed.payload_sha256,
                news_feed_signature_hmac_sha256=feed.signature_hmac_sha256,
                news_provider_name=feed.provider_name,
                news_signing_key_id=feed.signing_key_id,
                news_coverage_start_at=feed.coverage_start_at,
                news_coverage_end_at=feed.coverage_end_at,
                broker_rollover_at=NOW + timedelta(hours=5),
            )


if __name__ == "__main__":
    unittest.main()
