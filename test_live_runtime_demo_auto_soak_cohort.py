from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import unittest

import live_runtime.demo_auto_soak_projection as projection_module
import live_runtime.soak_tracker as soak_tracker_module
from live_runtime.contracts import canonical_json, canonical_sha256
from live_runtime.demo_auto_soak_cohort import (
    DemoAutoProjectedClosedFillProof,
    DemoAutoSoakCohortBinding,
    DemoAutoSoakCohortBindingError,
    DemoAutoSoakCohortIntegrityError,
    DemoAutoSoakCohortMemberBinding,
    DemoAutoSoakCohortReplayError,
    DemoAutoSoakLaneEvidence,
    aggregate_demo_auto_soak_cohort,
    verify_demo_auto_soak_cohort_receipt,
)
from live_runtime.demo_auto_soak_projection import (
    DemoAutoSoakProjectionCheckpoint,
    DemoAutoSoakProjectionEventReceipt,
)
from live_runtime.reconciliation import (
    ReconciliationResult,
    issue_broker_deal_receipt,
    issue_broker_reconciliation_receipt,
)
from live_runtime.soak_tracker import SoakAssessmentReceipt


UTC = timezone.utc
NOW = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
START = NOW - timedelta(days=30)
ACCOUNT = "a" * 64
JOURNAL = "b" * 64
COMMIT = "c" * 40
CONFIG = "d" * 64
MODEL = "f" * 64
BROKER_KEY_ID = "broker-reconciler-key-v1"
BROKER_SECRET = b"broker-reconciler-secret-material-32-bytes-minimum"
AGGREGATOR_KEY_ID = "cohort-aggregator-key-v1"
AGGREGATOR_SECRET = b"cohort-aggregator-secret-material-32-bytes-minimum"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def key_fingerprint(secret: bytes) -> str:
    return hashlib.sha256(secret).hexdigest()


def sign(domain: bytes, secret: bytes, payload: object) -> str:
    return hmac.new(
        secret,
        domain + canonical_json(payload).encode(),
        hashlib.sha256,
    ).hexdigest()


class Fixture:
    def __init__(
        self,
        *,
        counts: dict[str, int] | None = None,
        xau_lane_count: int = 1,
        deal_symbol_overrides: dict[str, str] | None = None,
        assessed_at: datetime = NOW,
    ) -> None:
        self.counts = counts or {
            "AUDUSD": 10,
            "EURUSD": 10,
            "USDJPY": 10,
            "XAUUSD": 20,
        }
        self.deal_symbol_overrides = deal_symbol_overrides or {}
        self.assessed_at = assessed_at
        symbols = ["AUDUSD", "EURUSD", "USDJPY"] + [
            "XAUUSD" for _ in range(xau_lane_count)
        ]
        lane_labels: list[tuple[str, str]] = []
        xau_seen = 0
        for symbol in symbols:
            if symbol == "XAUUSD":
                xau_seen += 1
                suffix = f"-{xau_seen}" if xau_lane_count > 1 else ""
            else:
                suffix = ""
            lane_labels.append((f"{symbol.lower()}-breakout{suffix}", symbol))
        self.assessment_secrets: dict[str, bytes] = {}
        self.projection_secrets: dict[str, bytes] = {}
        self.members: list[DemoAutoSoakCohortMemberBinding] = []
        for lane_id, symbol in lane_labels:
            assessment_key = f"assessment-{lane_id}"
            projection_key = f"projection-custody-{lane_id}"
            assessment_secret = (
                f"assessment-secret-{lane_id}-material-padding-32".encode()
            )
            projection_secret = (
                f"projection-secret-{lane_id}-material-padding-32".encode()
            )
            self.assessment_secrets[assessment_key] = assessment_secret
            self.projection_secrets[projection_key] = projection_secret
            self.members.append(
                DemoAutoSoakCohortMemberBinding(
                    lane_id=lane_id,
                    symbol=symbol,
                    broker_symbol=f"{symbol}.ps01",
                    account_currency="JPY",
                    strategy="BREAKOUT",
                    broker_spec_sha256=digest(f"broker-spec:{lane_id}"),
                    tracker_id=f"tracker-{lane_id}",
                    soak_binding_sha256=digest(f"soak-binding:{lane_id}"),
                    stage_binding_sha256=digest(f"stage-binding:{lane_id}"),
                    session_binding_sha256=digest(f"session-binding:{lane_id}"),
                    projection_ledger_id=f"projection-ledger-{lane_id}",
                    projection_binding_sha256=digest(
                        f"projection-binding:{lane_id}"
                    ),
                    assessment_key_id=assessment_key,
                    assessment_key_fingerprint_sha256=key_fingerprint(
                        assessment_secret
                    ),
                    projection_custody_issuer_id=f"custody-{lane_id}",
                    projection_custody_key_id=projection_key,
                    projection_custody_key_fingerprint_sha256=key_fingerprint(
                        projection_secret
                    ),
                    broker_provider_id="mt5-broker-reconciler",
                    broker_key_id=BROKER_KEY_ID,
                    broker_key_fingerprint_sha256=key_fingerprint(BROKER_SECRET),
                )
            )
        self.members.sort(key=lambda item: item.lane_id)
        self.binding = DemoAutoSoakCohortBinding(
            cohort_id="phillip-demo-auto-cohort-window-01",
            broker_id="phillip-jp",
            environment="DEMO",
            account_alias_sha256=ACCOUNT,
            broker_server="PhillipSecuritiesJP-PROD",
            journal_sha256=JOURNAL,
            commit_sha=COMMIT,
            config_sha256=CONFIG,
            dependency_lock_sha256=digest("dependency-lock"),
            runtime_profile_sha256=digest("runtime-profile"),
            release_manifest_sha256=digest("release-manifest"),
            session_calendar_sha256=digest("session-calendar"),
            broker_spec_set_sha256=canonical_sha256(
                tuple(
                    {
                        "lane_id": item.lane_id,
                        "canonical_symbol": item.symbol,
                        "broker_symbol": item.broker_symbol,
                        "account_currency": item.account_currency,
                        "broker_spec_sha256": item.broker_spec_sha256,
                    }
                    for item in self.members
                )
            ),
            model_artifact_sha256=MODEL,
            clean_generation=1,
            baseline_critical_incident_count=0,
            baseline_review_restart_count=0,
            members=tuple(self.members),
            xau_lane_ids=tuple(
                member.lane_id
                for member in self.members
                if member.symbol == "XAUUSD"
            ),
            aggregator_issuer_id="independent-cohort-aggregator",
            aggregator_key_id=AGGREGATOR_KEY_ID,
            aggregator_key_fingerprint_sha256=key_fingerprint(
                AGGREGATOR_SECRET
            ),
        )
        self.evidence: list[DemoAutoSoakLaneEvidence] = []
        self.next_source_sequence = 1
        for member in self.members:
            count = self._member_count(member)
            self.evidence.append(self._lane_evidence(member, count=count))
        self.evidence.sort(key=lambda item: item.lane_id)

    def _member_count(self, member: DemoAutoSoakCohortMemberBinding) -> int:
        if member.symbol != "XAUUSD":
            return self.counts.get(member.symbol, 0)
        xau_members = [item for item in self.members if item.symbol == "XAUUSD"]
        total = self.counts.get("XAUUSD", 0)
        quotient, remainder = divmod(total, len(xau_members))
        index = xau_members.index(member)
        return quotient + (1 if index < remainder else 0)

    def assessment_key(self, key_id: str) -> bytes:
        return self.assessment_secrets[key_id]

    def projection_key(self, key_id: str) -> bytes:
        return self.projection_secrets[key_id]

    @staticmethod
    def broker_key(key_id: str) -> bytes:
        if key_id != BROKER_KEY_ID:
            raise KeyError(key_id)
        return BROKER_SECRET

    @staticmethod
    def aggregator_key(key_id: str) -> bytes:
        if key_id != AGGREGATOR_KEY_ID:
            raise KeyError(key_id)
        return AGGREGATOR_SECRET

    def aggregate(self, **overrides):
        arguments = {
            "binding": self.binding,
            "lane_evidence": tuple(self.evidence),
            "assessment_key_provider": self.assessment_key,
            "projection_custody_key_provider": self.projection_key,
            "broker_key_provider": self.broker_key,
            "aggregator_key_provider": self.aggregator_key,
            "now": NOW,
        }
        arguments.update(overrides)
        return aggregate_demo_auto_soak_cohort(**arguments)

    def _assessment(
        self,
        member: DemoAutoSoakCohortMemberBinding,
        *,
        count: int,
        clean_generation: int = 1,
        incidents: int = 0,
        restarts: int = 0,
        demotion_latched: bool = False,
        clean_start: datetime = START,
        latest_event: datetime | None = None,
        assessed_at: datetime | None = None,
    ) -> SoakAssessmentReceipt:
        assessed = assessed_at or self.assessed_at
        latest = latest_event or (
            clean_start + timedelta(minutes=max(count, 1))
        )
        seconds = (assessed - clean_start).total_seconds()
        xau_count = count if member.symbol == "XAUUSD" else 0
        duration_met = seconds >= 30 * 86400
        fills_met = count >= 50
        xau_met = xau_count >= 20
        blockers = {"DENY_ONLY_TRACKER"}
        if not duration_met:
            blockers.add("CLEAN_DURATION_30_DAYS_REQUIRED")
        if not fills_met:
            blockers.add("CLOSED_FILLS_50_REQUIRED")
        if not xau_met:
            blockers.add("XAUUSD_CLOSED_FILLS_20_REQUIRED")
        if demotion_latched:
            blockers.add("CRITICAL_INCIDENT_DEMOTION_LATCHED")
        values = {
            "tracker_id": member.tracker_id,
            "broker_id": self.binding.broker_id,
            "environment": "DEMO",
            "account_alias_sha256": ACCOUNT,
            "broker_server": self.binding.broker_server,
            "journal_sha256": JOURNAL,
            "commit_sha": COMMIT,
            "config_sha256": CONFIG,
            "broker_spec_sha256": member.broker_spec_sha256,
            "model_artifact_sha256": MODEL,
            "lane_id": member.lane_id,
            "binding_sha256": member.soak_binding_sha256,
            "key_id": member.assessment_key_id,
            "event_count": count + 1,
            "head_hmac_sha256": digest(
                f"assessment-head:{member.lane_id}:{count}:{clean_generation}"
            ),
            "clean_generation": clean_generation,
            "clean_period_started_at_utc": clean_start,
            "latest_event_at_utc": latest,
            "assessed_at_utc": assessed,
            "clean_duration_seconds": seconds,
            "clean_duration_days": seconds / 86400,
            "closed_fills": count,
            "xauusd_closed_fills": xau_count,
            "duration_30_days_met": duration_met,
            "closed_fills_50_met": fills_met,
            "xauusd_fills_20_met": xau_met,
            "statistical_criteria_met": duration_met and fills_met and xau_met,
            "critical_incident_count": incidents,
            "review_restart_count": restarts,
            "demotion_latched": demotion_latched,
            "blocker_codes": tuple(sorted(blockers)),
            "schema_version": soak_tracker_module.ASSESSMENT_RECEIPT_SCHEMA_VERSION,
        }
        unsigned = SoakAssessmentReceipt(
            **values,
            receipt_hmac_sha256="0" * 64,
            _seal=soak_tracker_module._RECEIPT_SEAL,
        )
        signature = sign(
            soak_tracker_module._ASSESSMENT_HMAC_DOMAIN,
            self.assessment_secrets[member.assessment_key_id],
            unsigned.signing_payload,
        )
        return replace(
            unsigned,
            receipt_hmac_sha256=signature,
            _seal=soak_tracker_module._RECEIPT_SEAL,
        )

    def _checkpoint(
        self,
        member: DemoAutoSoakCohortMemberBinding,
        *,
        event_count: int,
        event_head_sha256: str,
        previous_checkpoint_sha256: str,
        issued_at: datetime,
    ) -> DemoAutoSoakProjectionCheckpoint:
        unsigned = DemoAutoSoakProjectionCheckpoint(
            ledger_id=member.projection_ledger_id,
            binding_sha256=member.projection_binding_sha256,
            event_count=event_count,
            event_head_sha256=event_head_sha256,
            previous_checkpoint_sha256=previous_checkpoint_sha256,
            issued_at_utc=issued_at,
            custody_issuer_id=member.projection_custody_issuer_id,
            custody_key_id=member.projection_custody_key_id,
            signature_hmac_sha256="0" * 64,
            _seal=projection_module._CHECKPOINT_SEAL,
        )
        signature = sign(
            projection_module._CHECKPOINT_DOMAIN,
            self.projection_secrets[member.projection_custody_key_id],
            unsigned.signing_dict,
        )
        return replace(
            unsigned,
            signature_hmac_sha256=signature,
            _seal=projection_module._CHECKPOINT_SEAL,
        )

    def _broker_receipts(
        self,
        *,
        symbol: str,
        broker_symbol: str,
        account_currency: str,
        at: datetime,
    ):
        sequence = self.next_source_sequence
        self.next_source_sequence += 1
        intent_id = f"intent-{sequence}"
        ticket = f"deal-{sequence}"
        result = ReconciliationResult(
            status="RECONCILED",
            matched_intents=(),
            uncertain_intents=(),
            closed_intents=(intent_id,),
            orphan_position_tickets=(),
            orphan_order_tickets=(),
            protection_failures=(),
            volume_failures=(),
            binding_failures=(),
            kill_switch_latched=False,
        )
        reconciliation = issue_broker_reconciliation_receipt(
            result=result,
            account_id_sha256=ACCOUNT,
            server=self.binding.broker_server,
            environment="DEMO",
            journal_sha256=JOURNAL,
            query_from_utc=at - timedelta(seconds=1),
            query_to_utc=at,
            source_time_utc=at,
            observed_at_utc=at,
            source_sequence=sequence,
            previous_receipt_sha256=digest(f"prior-reconciliation:{sequence}"),
            order_tickets=(),
            position_tickets=(),
            deal_tickets=(ticket,),
            closed_intent_deal_tickets={intent_id: (ticket,)},
            raw_payload_sha256=digest(f"raw:{sequence}"),
            provider_id="mt5-broker-reconciler",
            key_id=BROKER_KEY_ID,
            key=BROKER_SECRET,
        )
        deal = issue_broker_deal_receipt(
            reconciliation_receipt=reconciliation,
            intent_id=intent_id,
            deal_sequence=1,
            deal_ticket=ticket,
            order_ticket=f"order-{sequence}",
            position_ticket=f"position-{sequence}",
            canonical_symbol=symbol,
            broker_symbol=broker_symbol,
            account_currency=account_currency,
            entry_side="BUY",
            exit_side="SELL",
            volume=0.01,
            fill_price=100.0,
            profit_account_currency=10.0,
            commission_account_currency=-1.0,
            swap_account_currency=0.0,
            fee_account_currency=0.0,
            source_time_utc=at,
            raw_payload_sha256=digest(f"deal-raw:{sequence}"),
            key=BROKER_SECRET,
        )
        return reconciliation, deal

    def _projected_proof(
        self,
        member: DemoAutoSoakCohortMemberBinding,
        *,
        sequence: int,
        previous_event_sha256: str,
        previous_checkpoint_sha256: str,
        at: datetime,
        deal_symbol: str,
        existing_broker_receipts=None,
    ) -> DemoAutoProjectedClosedFillProof:
        if existing_broker_receipts is None:
            reconciliation, deal = self._broker_receipts(
                symbol=deal_symbol,
                broker_symbol=member.broker_symbol,
                account_currency=member.account_currency,
                at=at,
            )
        else:
            reconciliation, deal = existing_broker_receipts
        identity = canonical_sha256(
            {
                "provider_id": deal.provider_id,
                "account_alias_sha256": ACCOUNT,
                "server": self.binding.broker_server,
                "source_sequence": deal.source_sequence,
                "deal_ticket": deal.deal_ticket,
            }
        )
        payload_sha256 = digest(
            f"projection-payload:{member.lane_id}:{sequence}:{identity}"
        )
        event_id = f"projection-closed-fill-{member.lane_id}-{sequence}"
        upstream = digest(f"upstream:{member.lane_id}:{sequence}:{identity}")
        body = {
            "ledger_id": member.projection_ledger_id,
            "binding_sha256": member.projection_binding_sha256,
            "sequence": sequence,
            "event_id": event_id,
            "event_type": "CLOSED_FILL",
            "dedup_key": f"deal:{identity}",
            "occurred_at_utc": at.isoformat(timespec="microseconds").replace(
                "+00:00", "Z"
            ),
            "upstream_sha256": upstream,
            "payload_sha256": payload_sha256,
            "previous_event_sha256": previous_event_sha256,
        }
        event_sha = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        checkpoint = self._checkpoint(
            member,
            event_count=sequence,
            event_head_sha256=event_sha,
            previous_checkpoint_sha256=previous_checkpoint_sha256,
            issued_at=at,
        )
        event = DemoAutoSoakProjectionEventReceipt(
            ledger_id=member.projection_ledger_id,
            sequence=sequence,
            event_id=event_id,
            event_type="CLOSED_FILL",
            dedup_key=f"deal:{identity}",
            occurred_at_utc=at,
            upstream_sha256=upstream,
            previous_event_sha256=previous_event_sha256,
            event_sha256=event_sha,
            checkpoint_sha256=checkpoint.content_sha256,
        )
        return DemoAutoProjectedClosedFillProof(
            projection_event=event,
            projection_checkpoint=checkpoint,
            projection_payload_sha256=payload_sha256,
            reconciliation_receipt=reconciliation,
            deal_receipt=deal,
        )

    def _lane_evidence(
        self,
        member: DemoAutoSoakCohortMemberBinding,
        *,
        count: int,
    ) -> DemoAutoSoakLaneEvidence:
        genesis = self._checkpoint(
            member,
            event_count=0,
            event_head_sha256="0" * 64,
            previous_checkpoint_sha256="0" * 64,
            issued_at=START - timedelta(minutes=1),
        )
        activation_event = digest(f"activation-event:{member.lane_id}")
        activation = self._checkpoint(
            member,
            event_count=1,
            event_head_sha256=activation_event,
            previous_checkpoint_sha256=genesis.content_sha256,
            issued_at=START,
        )
        checkpoint_chain = [genesis, activation]
        proofs: list[DemoAutoProjectedClosedFillProof] = []
        previous_event = activation_event
        previous_checkpoint = activation.content_sha256
        deal_symbol = self.deal_symbol_overrides.get(member.lane_id, member.symbol)
        for index in range(count):
            at = START + timedelta(minutes=index + 1)
            proof = self._projected_proof(
                member,
                sequence=index + 2,
                previous_event_sha256=previous_event,
                previous_checkpoint_sha256=previous_checkpoint,
                at=at,
                deal_symbol=deal_symbol,
            )
            proofs.append(proof)
            checkpoint_chain.append(proof.projection_checkpoint)
            previous_event = proof.projection_event.event_sha256
            previous_checkpoint = proof.projection_checkpoint.content_sha256
        latest_event = START + timedelta(minutes=max(count, 1))
        assessment = self._assessment(
            member,
            count=count,
            latest_event=latest_event,
        )
        head = checkpoint_chain[-1]
        return DemoAutoSoakLaneEvidence(
            lane_id=member.lane_id,
            cohort_binding_sha256=self.binding.binding_sha256,
            assessment_receipt=assessment,
            projection_head_checkpoint=head,
            projection_checkpoint_chain=tuple(checkpoint_chain),
            closed_fill_proofs=tuple(proofs),
        )

    def replace_lane(
        self,
        lane_id: str,
        evidence: DemoAutoSoakLaneEvidence,
    ) -> tuple[DemoAutoSoakLaneEvidence, ...]:
        return tuple(
            sorted(
                (
                    evidence if item.lane_id == lane_id else item
                    for item in self.evidence
                ),
                key=lambda item: item.lane_id,
            )
        )


class DemoAutoSoakCohortTests(unittest.TestCase):
    def test_aggregate_50_fills_and_20_xau_across_lanes_is_deny_only(self):
        fixture = Fixture()
        receipt = fixture.aggregate()
        self.assertEqual(50, receipt.observed_closed_fills)
        self.assertEqual(20, receipt.observed_xauusd_closed_fills)
        self.assertEqual(50, receipt.qualified_closed_fills)
        self.assertEqual(20, receipt.qualified_xauusd_closed_fills)
        self.assertTrue(receipt.duration_30_days_met)
        self.assertTrue(receipt.cohort_criteria_met)
        self.assertEqual("CRITERIA_MET_DENY_ONLY", receipt.status)
        self.assertTrue(
            verify_demo_auto_soak_cohort_receipt(
                receipt,
                binding=fixture.binding,
                key_provider=fixture.aggregator_key,
                enforce_freshness=True,
                now=NOW,
            )
        )
        self.assertFalse(receipt.ready)
        self.assertFalse(receipt.promotion_eligible)
        self.assertFalse(receipt.lane_promotion_evidence)
        self.assertFalse(receipt.execution_enabled)
        self.assertFalse(receipt.activation_authorized)
        self.assertFalse(receipt.safe_to_demo_auto_order)
        self.assertFalse(receipt.live_allowed)
        self.assertEqual("DISABLED", receipt.order_capability)
        self.assertTrue(
            all(
                not evidence.assessment_receipt.statistical_criteria_met
                for evidence in fixture.evidence
                if evidence.assessment_receipt.lane_id != "xauusd-breakout"
            )
        )

    def test_thresholds_are_account_level_but_independent(self):
        fixture = Fixture(
            counts={"AUDUSD": 10, "EURUSD": 10, "USDJPY": 10, "XAUUSD": 19}
        )
        receipt = fixture.aggregate()
        self.assertEqual(49, receipt.qualified_closed_fills)
        self.assertEqual(19, receipt.qualified_xauusd_closed_fills)
        self.assertFalse(receipt.cohort_criteria_met)
        self.assertIn("CLOSED_FILLS_50_REQUIRED", receipt.blocker_codes)
        self.assertIn("XAUUSD_CLOSED_FILLS_20_REQUIRED", receipt.blocker_codes)

    def test_eurusd_deal_cannot_masquerade_as_xau_fill(self):
        probe = Fixture(counts={"AUDUSD": 0, "EURUSD": 0, "USDJPY": 0, "XAUUSD": 1})
        xau_lane = next(
            item.lane_id for item in probe.members if item.symbol == "XAUUSD"
        )
        fixture = Fixture(
            counts={"AUDUSD": 0, "EURUSD": 0, "USDJPY": 0, "XAUUSD": 1},
            deal_symbol_overrides={xau_lane: "EURUSD"},
        )
        with self.assertRaises(DemoAutoSoakCohortBindingError):
            fixture.aggregate()

    def test_unknown_missing_or_wrong_release_lane_is_rejected(self):
        fixture = Fixture()
        unknown = replace(fixture.evidence[0], lane_id="unknown-lane")
        evidence = tuple(sorted((unknown, *fixture.evidence[1:]), key=lambda item: item.lane_id))
        with self.assertRaises(DemoAutoSoakCohortBindingError):
            fixture.aggregate(lane_evidence=evidence)
        wrong_release = replace(
            fixture.binding,
            release_manifest_sha256=digest("another-release"),
        )
        with self.assertRaises(DemoAutoSoakCohortBindingError):
            fixture.aggregate(binding=wrong_release)

    def test_duplicate_broker_deal_across_two_xau_lanes_is_rejected(self):
        fixture = Fixture(
            counts={"AUDUSD": 0, "EURUSD": 0, "USDJPY": 0, "XAUUSD": 2},
            xau_lane_count=2,
        )
        xau_evidence = [
            item
            for item in fixture.evidence
            if fixture.binding.members[
                [member.lane_id for member in fixture.binding.members].index(item.lane_id)
            ].symbol
            == "XAUUSD"
        ]
        first_proof = xau_evidence[0].closed_fill_proofs[0]
        second_member = next(
            member
            for member in fixture.members
            if member.lane_id == xau_evidence[1].lane_id
        )
        duplicate = fixture._projected_proof(
            second_member,
            sequence=2,
            previous_event_sha256=digest("second-activation-event"),
            previous_checkpoint_sha256=digest("second-activation-checkpoint"),
            at=first_proof.reconciliation_receipt.observed_at_utc,
            deal_symbol="XAUUSD",
            existing_broker_receipts=(
                first_proof.reconciliation_receipt,
                first_proof.deal_receipt,
            ),
        )
        changed = replace(xau_evidence[1], closed_fill_proofs=(duplicate,))
        evidence = fixture.replace_lane(changed.lane_id, changed)
        with self.assertRaises(DemoAutoSoakCohortReplayError):
            fixture.aggregate(lane_evidence=evidence)

    def test_projection_checkpoint_chain_cannot_be_omitted_or_reordered(self):
        fixture = Fixture()
        original = fixture.evidence[0]
        missing = replace(
            original,
            projection_checkpoint_chain=(
                original.projection_checkpoint_chain[0],
                *original.projection_checkpoint_chain[2:],
            ),
        )
        with self.assertRaises(DemoAutoSoakCohortReplayError):
            fixture.aggregate(
                lane_evidence=fixture.replace_lane(original.lane_id, missing)
            )
        reordered = replace(
            original,
            closed_fill_proofs=tuple(reversed(original.closed_fill_proofs)),
        )
        with self.assertRaises(DemoAutoSoakCohortReplayError):
            fixture.aggregate(
                lane_evidence=fixture.replace_lane(original.lane_id, reordered)
            )

    def test_same_height_projection_fork_is_rejected_across_restart(self):
        fixture = Fixture(
            counts={"AUDUSD": 0, "EURUSD": 0, "USDJPY": 0, "XAUUSD": 0}
        )
        first = fixture.aggregate()
        original = fixture.evidence[0]
        genesis = original.projection_checkpoint_chain[0]
        forked_head = fixture._checkpoint(
            next(
                member
                for member in fixture.members
                if member.lane_id == original.lane_id
            ),
            event_count=1,
            event_head_sha256=digest("validly-signed-alternate-activation-head"),
            previous_checkpoint_sha256=genesis.content_sha256,
            issued_at=START,
        )
        forked = replace(
            original,
            projection_head_checkpoint=forked_head,
            projection_checkpoint_chain=(genesis, forked_head),
        )
        with self.assertRaises(DemoAutoSoakCohortReplayError):
            fixture.aggregate(
                lane_evidence=fixture.replace_lane(original.lane_id, forked),
                previous_receipt=first,
            )

    def test_restart_uses_cumulative_set_without_double_counting(self):
        fixture = Fixture()
        first = fixture.aggregate()
        second = fixture.aggregate(
            previous_receipt=first,
            now=NOW + timedelta(minutes=1),
        )
        self.assertEqual(50, second.observed_closed_fills)
        self.assertEqual(first.content_sha256, second.previous_receipt_sha256)
        self.assertEqual(first.deal_identity_owners, second.deal_identity_owners)

    def test_incident_or_generation_change_resets_and_permanently_latches_binding(self):
        fixture = Fixture()
        target = fixture.evidence[0]
        member = next(item for item in fixture.members if item.lane_id == target.lane_id)
        incident_assessment = fixture._assessment(
            member,
            count=0,
            clean_generation=2,
            incidents=1,
            restarts=0,
            demotion_latched=True,
            clean_start=NOW - timedelta(hours=1),
            latest_event=NOW - timedelta(minutes=1),
        )
        incident_evidence = replace(
            target,
            assessment_receipt=incident_assessment,
            closed_fill_proofs=(),
        )
        evidence = fixture.replace_lane(target.lane_id, incident_evidence)
        latched = fixture.aggregate(lane_evidence=evidence)
        self.assertTrue(latched.reset_required)
        self.assertEqual("RESET_REQUIRED", latched.status)
        self.assertEqual(0, latched.qualified_closed_fills)
        self.assertIn("MEMBER_INCIDENT_OR_GENERATION_DRIFT", latched.blocker_codes)
        still_latched = fixture.aggregate(
            previous_receipt=latched,
            now=NOW + timedelta(minutes=1),
        )
        self.assertTrue(still_latched.reset_required)
        self.assertIn("PREVIOUS_COHORT_DEMOTION_LATCHED", still_latched.blocker_codes)

    def test_tampered_assessment_projection_and_subclass_fail_closed(self):
        fixture = Fixture()
        original = fixture.evidence[0]
        tampered_assessment = replace(
            original.assessment_receipt,
            receipt_hmac_sha256="9" * 64,
            _seal=soak_tracker_module._RECEIPT_SEAL,
        )
        with self.assertRaises(DemoAutoSoakCohortIntegrityError):
            fixture.aggregate(
                lane_evidence=fixture.replace_lane(
                    original.lane_id,
                    replace(original, assessment_receipt=tampered_assessment),
                )
            )
        tampered_head = replace(
            original.projection_head_checkpoint,
            signature_hmac_sha256="8" * 64,
            _seal=projection_module._CHECKPOINT_SEAL,
        )
        with self.assertRaises(DemoAutoSoakCohortIntegrityError):
            fixture.aggregate(
                lane_evidence=fixture.replace_lane(
                    original.lane_id,
                    replace(original, projection_head_checkpoint=tampered_head),
                )
            )

        class ReceiptSubclass(SoakAssessmentReceipt):
            pass

        forged = object.__new__(ReceiptSubclass)
        forged.__dict__.update(original.assessment_receipt.__dict__)
        with self.assertRaises(TypeError):
            DemoAutoSoakLaneEvidence(
                lane_id=original.lane_id,
                cohort_binding_sha256=original.cohort_binding_sha256,
                assessment_receipt=forged,
                projection_head_checkpoint=original.projection_head_checkpoint,
                closed_fill_proofs=original.closed_fill_proofs,
            )

    def test_stale_assessment_and_stale_projection_head_are_rejected(self):
        stale = Fixture(
            counts={"AUDUSD": 0, "EURUSD": 0, "USDJPY": 0, "XAUUSD": 0},
            assessed_at=NOW - timedelta(minutes=6),
        )
        with self.assertRaises(DemoAutoSoakCohortIntegrityError):
            stale.aggregate(now=NOW)

    def test_previous_receipt_tamper_or_rollback_is_rejected(self):
        fixture = Fixture()
        first = fixture.aggregate()
        tampered = replace(
            first,
            receipt_hmac_sha256="7" * 64,
            _seal=__import__(
                "live_runtime.demo_auto_soak_cohort",
                fromlist=["_COHORT_RECEIPT_SEAL"],
            )._COHORT_RECEIPT_SEAL,
        )
        with self.assertRaises(DemoAutoSoakCohortIntegrityError):
            fixture.aggregate(previous_receipt=tampered)
        reduced = Fixture(
            counts={"AUDUSD": 9, "EURUSD": 10, "USDJPY": 10, "XAUUSD": 20}
        )
        with self.assertRaises(DemoAutoSoakCohortReplayError):
            reduced.aggregate(previous_receipt=first)


if __name__ == "__main__":
    unittest.main()
