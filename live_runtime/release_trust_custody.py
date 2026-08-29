"""Durable local replay custody for signed release-trust verification.

The store provides atomic checkpoint compare-and-swap and an all-history nonce
registry. It authenticates release provenance only and cannot enable trading.
Production must place the database under independent custody; local durability
alone is not independent authorization.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import threading
from typing import Callable

from .contracts import require_hash, require_utc
from .signed_release_trust import (
    ZERO_SHA256,
    ReleaseTrustCheckpoint,
    ReleaseTrustCustodyCommit,
    ReleaseTrustCustodyProposal,
    ReleaseTrustError,
    ReleaseTrustPolicy,
    decode_release_trust_checkpoint,
    issue_release_trust_custody_commit,
)


class ReleaseTrustCustodyStore:
    """SQLite-backed checkpoint and nonce registry with atomic CAS semantics."""

    def __init__(
        self,
        path: str | Path,
        *,
        policy: ReleaseTrustPolicy,
        custody_key_provider: Callable[[str], str | bytes],
        clock_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if type(policy) is not ReleaseTrustPolicy:
            raise TypeError("exact release trust policy is required")
        if not callable(custody_key_provider) or not callable(clock_provider):
            raise TypeError("custody key and clock providers must be callable")
        candidate = Path(path)
        parent = candidate.parent.resolve(strict=True)
        resolved = parent / candidate.name
        if candidate.exists() and (candidate.is_symlink() or not candidate.is_file()):
            raise ReleaseTrustError("CUSTODY_DATABASE_PATH_UNSAFE")
        self.path = resolved
        self.policy = policy
        self.custody_key_provider = custody_key_provider
        self.clock_provider = clock_provider
        self._lock = threading.RLock()
        try:
            self._connection = sqlite3.connect(
                str(resolved),
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS release_trust_head (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    checkpoint_json TEXT NOT NULL,
                    checkpoint_sha256 TEXT NOT NULL UNIQUE,
                    sequence INTEGER NOT NULL CHECK (sequence > 0)
                )"""
            )
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS release_trust_nonce (
                    nonce_sha256 TEXT PRIMARY KEY,
                    checkpoint_sha256 TEXT NOT NULL UNIQUE,
                    sequence INTEGER NOT NULL UNIQUE CHECK (sequence > 0),
                    reserved_at_utc TEXT NOT NULL
                )"""
            )
        except Exception as exc:
            raise ReleaseTrustError("CUSTODY_DATABASE_INITIALIZATION_FAILED") from exc

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "ReleaseTrustCustodyStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _clock(self) -> datetime:
        try:
            return require_utc("custody clock", self.clock_provider())
        except Exception as exc:
            raise ReleaseTrustError("CUSTODY_CLOCK_FAILED") from exc

    @staticmethod
    def _decode_row(row: tuple[object, ...] | None) -> ReleaseTrustCheckpoint | None:
        if row is None:
            return None
        checkpoint_json, expected_hash, expected_sequence = row
        if not isinstance(checkpoint_json, str):
            raise ReleaseTrustError("CUSTODY_CHECKPOINT_ROW_INVALID")
        checkpoint = decode_release_trust_checkpoint(checkpoint_json)
        if (
            checkpoint.content_sha256 != expected_hash
            or checkpoint.sequence != expected_sequence
        ):
            raise ReleaseTrustError("CUSTODY_CHECKPOINT_ROW_MISMATCH")
        return checkpoint

    def checkpoint_provider(self) -> ReleaseTrustCheckpoint | None:
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT checkpoint_json, checkpoint_sha256, sequence "
                    "FROM release_trust_head WHERE singleton = 1"
                ).fetchone()
                return self._decode_row(row)
            except ReleaseTrustError:
                raise
            except Exception as exc:
                raise ReleaseTrustError("CUSTODY_CHECKPOINT_READ_FAILED") from exc

    def nonce_seen(self, nonce_sha256: str) -> bool:
        normalized = require_hash("nonce_sha256", nonce_sha256)
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT 1 FROM release_trust_nonce WHERE nonce_sha256 = ?",
                    (normalized,),
                ).fetchone()
                return row is not None
            except Exception as exc:
                raise ReleaseTrustError("CUSTODY_NONCE_READ_FAILED") from exc

    def compare_and_swap(
        self,
        expected_predecessor: str,
        proposal: ReleaseTrustCustodyProposal,
    ) -> ReleaseTrustCustodyCommit:
        expected = require_hash("expected_predecessor", expected_predecessor)
        if type(proposal) is not ReleaseTrustCustodyProposal:
            raise ReleaseTrustError("CUSTODY_PROPOSAL_TYPE_INVALID")
        with self._lock:
            connection = self._connection
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT checkpoint_json, checkpoint_sha256, sequence "
                    "FROM release_trust_head WHERE singleton = 1"
                ).fetchone()
                current = self._decode_row(row)
                current_hash = current.content_sha256 if current is not None else ZERO_SHA256
                current_sequence = current.sequence if current is not None else 0
                if (
                    current_hash != expected
                    or proposal.predecessor_checkpoint_sha256 != expected
                    or proposal.sequence != current_sequence + 1
                    or proposal.trust_policy_sha256 != self.policy.content_sha256
                ):
                    raise ReleaseTrustError("CUSTODY_COMPARE_AND_SWAP_REJECTED")
                seen = connection.execute(
                    "SELECT 1 FROM release_trust_nonce WHERE nonce_sha256 = ?",
                    (proposal.accepted_nonce_sha256,),
                ).fetchone()
                if seen is not None:
                    raise ReleaseTrustError("CUSTODY_NONCE_REPLAY")
                now = self._clock()
                commit = issue_release_trust_custody_commit(
                    proposal,
                    policy=self.policy,
                    custody_secret=self.custody_key_provider(
                        self.policy.custody_key_id
                    ),
                    acknowledged_at=now,
                )
                checkpoint = commit.checkpoint
                connection.execute(
                    "INSERT INTO release_trust_nonce "
                    "(nonce_sha256, checkpoint_sha256, sequence, reserved_at_utc) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        proposal.accepted_nonce_sha256,
                        checkpoint.content_sha256,
                        checkpoint.sequence,
                        now.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                    ),
                )
                connection.execute(
                    "INSERT INTO release_trust_head "
                    "(singleton, checkpoint_json, checkpoint_sha256, sequence) "
                    "VALUES (1, ?, ?, ?) "
                    "ON CONFLICT(singleton) DO UPDATE SET "
                    "checkpoint_json=excluded.checkpoint_json, "
                    "checkpoint_sha256=excluded.checkpoint_sha256, "
                    "sequence=excluded.sequence",
                    (
                        checkpoint.canonical_json(),
                        checkpoint.content_sha256,
                        checkpoint.sequence,
                    ),
                )
                connection.execute("COMMIT")
                return commit
            except Exception:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise


__all__ = ["ReleaseTrustCustodyStore"]
