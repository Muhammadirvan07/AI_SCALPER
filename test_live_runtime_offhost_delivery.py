from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from live_runtime.offhost_delivery import (
    DeliveryAcknowledgement,
    DeliveryEnvelope,
    DeliveryOutbox,
    DirectoryDropTransport,
    OffHostDeliverySupervisor,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
SENDER_KEY = b"s" * 32
REMOTE_KEY = b"r" * 32


class Transport:
    def __init__(self, acknowledgement=None, error=None):
        self.acknowledgement = acknowledgement
        self.error = error
        self.calls = []

    def deliver(self, envelope):
        self.calls.append(envelope.envelope_id)
        if self.error is not None:
            raise self.error
        return self.acknowledgement


def envelope():
    return DeliveryEnvelope.create(
        idempotency_key="heartbeat-20260721T120000Z",
        destination_id="ops-offhost-primary",
        artifact_type="HEARTBEAT",
        payload={"status": "HEALTHY", "sequence": 7},
        created_at_utc=NOW,
        sender_key_id="vps-heartbeat-key",
        secret=SENDER_KEY,
    )


def acknowledgement(item, *, secret=REMOTE_KEY, destination_id=None):
    return DeliveryAcknowledgement.create(
        envelope_id=item.envelope_id,
        destination_id=destination_id or item.destination_id,
        payload_sha256=item.payload_sha256,
        acknowledged_at_utc=NOW + timedelta(seconds=1),
        remote_key_id="offhost-receipt-key",
        secret=secret,
    )


class OffHostDeliveryTests(unittest.TestCase):
    def _outbox(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return DeliveryOutbox(Path(temporary.name) / "outbox.sqlite3")

    def test_ac13_valid_acknowledgement_is_durable_across_restart(self):
        outbox = self._outbox()
        item = envelope()
        outbox.enqueue(item)
        transport = Transport(acknowledgement(item))
        supervisor = OffHostDeliverySupervisor(
            outbox=outbox,
            remote_key_provider=lambda key_id: REMOTE_KEY,
        )
        report = supervisor.deliver_pending(transport, attempted_at=NOW + timedelta(seconds=1))
        self.assertEqual(report.acknowledged, (item.envelope_id,))
        reopened = DeliveryOutbox(outbox.path)
        self.assertEqual(reopened.pending(), ())
        self.assertEqual(reopened.get(item.envelope_id)["state"], "ACKNOWLEDGED")
        self.assertTrue(reopened.integrity_check())
        self.assertTrue(reopened.verify_records(lambda key_id: REMOTE_KEY))

    def test_ac13_duplicate_idempotency_returns_same_envelope(self):
        outbox = self._outbox()
        first = envelope()
        self.assertEqual(outbox.enqueue(first), first.envelope_id)
        self.assertEqual(outbox.enqueue(first), first.envelope_id)
        self.assertEqual(len(outbox.pending()), 1)

    def test_ac14_timeout_remains_pending_and_records_attempt(self):
        outbox = self._outbox()
        item = envelope()
        outbox.enqueue(item)
        supervisor = OffHostDeliverySupervisor(
            outbox=outbox,
            remote_key_provider=lambda key_id: REMOTE_KEY,
        )
        report = supervisor.deliver_pending(
            Transport(error=TimeoutError("remote timeout")),
            attempted_at=NOW + timedelta(seconds=1),
        )
        self.assertEqual(report.failed, (item.envelope_id,))
        state = outbox.get(item.envelope_id)
        self.assertEqual(state["state"], "PENDING")
        self.assertEqual(state["attempt_count"], 1)

    def test_ack_clock_is_checked_after_transport_returns(self):
        outbox = self._outbox()
        item = envelope()
        outbox.enqueue(item)
        remote_time = NOW + timedelta(seconds=10)
        supervisor = OffHostDeliverySupervisor(
            outbox=outbox,
            remote_key_provider=lambda key_id: REMOTE_KEY,
            clock_provider=lambda: remote_time,
        )
        report = supervisor.deliver_pending(
            Transport(
                DeliveryAcknowledgement.create(
                    envelope_id=item.envelope_id,
                    destination_id=item.destination_id,
                    payload_sha256=item.payload_sha256,
                    acknowledged_at_utc=remote_time,
                    remote_key_id="offhost-receipt-key",
                    secret=REMOTE_KEY,
                )
            )
        )
        self.assertEqual(report.acknowledged, (item.envelope_id,))
        self.assertTrue(outbox.verify_records(lambda key_id: REMOTE_KEY))

    def test_ac14_forged_or_mismatched_ack_remains_pending(self):
        for ack in (
            acknowledgement(envelope(), secret=b"x" * 32),
            acknowledgement(envelope(), destination_id="wrong-destination"),
        ):
            with self.subTest(destination=ack.destination_id):
                outbox = self._outbox()
                item = envelope()
                outbox.enqueue(item)
                supervisor = OffHostDeliverySupervisor(
                    outbox=outbox,
                    remote_key_provider=lambda key_id: REMOTE_KEY,
                )
                report = supervisor.deliver_pending(
                    Transport(ack), attempted_at=NOW + timedelta(seconds=1)
                )
                self.assertEqual(report.failed, (item.envelope_id,))
                self.assertEqual(outbox.get(item.envelope_id)["state"], "PENDING")

    def test_directory_drop_is_create_exclusive_and_requires_remote_ack(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            item = envelope()
            transport = DirectoryDropTransport(root / "out", root / "ack")
            with self.assertRaisesRegex(Exception, "ACKNOWLEDGEMENT_NOT_AVAILABLE"):
                transport.deliver(item)
            ack = acknowledgement(item)
            (root / "ack" / f"{item.envelope_id}.ack.json").write_text(
                json.dumps(ack.to_dict(), sort_keys=True),
                encoding="utf-8",
            )
            self.assertEqual(transport.deliver(item), ack)

    def test_acknowledged_row_tamper_is_detected_before_delivery(self):
        outbox = self._outbox()
        item = envelope()
        outbox.enqueue(item)
        supervisor = OffHostDeliverySupervisor(
            outbox=outbox,
            remote_key_provider=lambda key_id: REMOTE_KEY,
        )
        supervisor.deliver_pending(
            Transport(acknowledgement(item)), attempted_at=NOW + timedelta(seconds=1)
        )
        connection = sqlite3.connect(outbox.path)
        try:
            connection.execute(
                "UPDATE delivery_outbox SET acknowledgement_json='{}' WHERE envelope_id=?",
                (item.envelope_id,),
            )
            connection.commit()
        finally:
            connection.close()
        self.assertFalse(outbox.verify_records(lambda key_id: REMOTE_KEY))
        with self.assertRaisesRegex(Exception, "DELIVERY_OUTBOX_INTEGRITY_FAILURE"):
            supervisor.deliver_pending(Transport(), attempted_at=NOW + timedelta(seconds=2))


if __name__ == "__main__":
    unittest.main()
