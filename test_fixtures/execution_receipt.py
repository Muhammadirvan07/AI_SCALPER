"""Test-only construction through the real durable-consumption boundary."""

from __future__ import annotations

import hashlib
import tempfile
from datetime import datetime
from pathlib import Path

from live_runtime.journal import ExecutionJournal


class _BoundTestJournal(ExecutionJournal):
    def __init__(self, *args, test_journal_sha256: str | None = None, **kwargs):
        self._test_journal_sha256 = test_journal_sha256
        super().__init__(*args, **kwargs)

    @property
    def journal_sha256(self) -> str:
        if self._test_journal_sha256 is not None:
            return self._test_journal_sha256
        return super().journal_sha256


def mint_submission_consumption_proof(
    *,
    intent_id: str,
    consumed_at: datetime,
    journal_sha256: str | None = None,
):
    """Mint a sealed proof via an isolated real journal final guard.

    Tests needing a standalone broker receipt use this helper instead of
    bypassing the production receipt seal.  The database is discarded only
    after the one-use proof has been durably consumed.
    """

    with tempfile.TemporaryDirectory() as directory:
        journal = _BoundTestJournal(
            Path(directory) / "execution-proof.sqlite3",
            clock_provider=lambda: consumed_at,
            test_journal_sha256=journal_sha256,
        )
        journal.create_intent(
            intent_id=intent_id,
            decision_id=f"decision-{intent_id}",
            symbol="EURUSD",
            payload={"test_fixture": True},
            created_at=consumed_at,
        )
        owner = "test-receipt-adapter"
        fence = journal.claim_executor(owner, now=consumed_at, lease_seconds=60)
        with journal._transaction() as connection:
            connection.execute(
                "UPDATE intents SET state='SUBMITTING' WHERE intent_id=?",
                (intent_id,),
            )
        gate = hashlib.sha256(f"gate:{intent_id}".encode()).hexdigest()
        authorization = hashlib.sha256(
            f"authorization:{intent_id}".encode()
        ).hexdigest()
        request = hashlib.sha256(f"request:{intent_id}".encode()).hexdigest()
        with journal.final_submission_guard(
            intent_id,
            owner_id=owner,
            fence_token=fence,
            execution_gate_sha256=gate,
            authorization_sha256=authorization,
            broker_request_sha256=request,
            occurred_at=consumed_at,
        ) as lease:
            return lease.consume(
                journal_sha256=journal.journal_sha256,
                intent_id=intent_id,
                execution_gate_sha256=gate,
                authorization_sha256=authorization,
                broker_request_sha256=request,
            )
