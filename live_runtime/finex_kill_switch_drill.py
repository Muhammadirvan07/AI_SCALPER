"""Signed FINEX kill-switch drill using an isolated execution journal.

The drill builds one synthetic, fully sealed submission candidate without any
broker transport.  It proves the atomic submission boundary observes a
persistent latch, exercises dual-control reset, rejects an unauthorized reset
and replay, then deliberately leaves the isolated journal latched.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path
import secrets
from typing import Callable, Mapping

from .contracts import (
    BrokerSpec,
    CanonicalContract,
    TradeIntent,
    _mint_decision_snapshot,
    canonical_json,
    canonical_sha256,
    require_hash,
    require_text,
    require_utc,
)
from .journal import ExecutionJournal, KillSwitchLatchedError
from .mt5_adapter import _mint_mt5_preflight, _mint_mt5_submission_guard
from .permit import (
    KillSwitchResetPermit,
    authorize_kill_switch_reset,
    reset_reason_sha256,
)
from .risk import RiskContext, evaluate_risk


SCHEMA_VERSION = "finex-kill-switch-drill-receipt-v1"
HMAC_DOMAIN = b"AI_SCALPER/FINEX_KILL_SWITCH_DRILL/V1"
DRILL_RECEIPT_MAX_AGE = timedelta(hours=1)
RESET_PERMIT_MAX_AGE = timedelta(minutes=5)
DRILL_KEY_NAME = "finex-kill-switch-drill-v1"
RISK_RESET_KEY_NAME = "finex-kill-switch-risk-reset-v1"
OPERATIONS_RESET_KEY_NAME = "finex-kill-switch-operations-reset-v1"
DRILL_INTENT_ID = "finex-kill-switch-drill-sentinel-v1"
INITIAL_LATCH_REASON = "FINEX_KILL_SWITCH_DRILL_INITIAL_LATCH"
INITIAL_LATCH_SOURCE = "FINEX_KILL_SWITCH_DRILL"
RESET_REASON = "FINEX_KILL_SWITCH_DRILL_DUAL_CONTROL_RESET"
FINAL_LATCH_REASON = "FINEX_KILL_SWITCH_DRILL_FINAL_SAFE_HOLD"
FINAL_LATCH_SOURCE = "FINEX_KILL_SWITCH_DRILL_FINAL_SAFE_HOLD"
EXPECTED_ACTIONS = ("LATCH", "RESET", "LATCH")
_RECEIPT_SEAL = object()


class FinexKillSwitchDrillError(RuntimeError):
    pass


def _secret(value: str | bytes, name: str) -> bytes:
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, bytes):
        encoded = value
    else:
        raise TypeError(f"{name} must be bytes or text")
    if len(encoded) < 32:
        raise ValueError(f"{name} must contain at least 32 bytes")
    return encoded


def _commit(value: str) -> str:
    normalized = require_text("commit_sha", value).lower()
    if len(normalized) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError("commit_sha must be a 40- or 64-character hexadecimal hash")
    return normalized


def _utc_from_text(value: object, name: str) -> datetime:
    text = require_text(name, value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise FinexKillSwitchDrillError(f"{name} is invalid") from exc
    if parsed.tzinfo is None:
        raise FinexKillSwitchDrillError(f"{name} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class FinexKillSwitchDrillReceipt(CanonicalContract):
    issuer_id: str
    key_id: str
    account_id_sha256: str
    server: str
    environment: str
    release_identity_sha256: str
    release_manifest_sha256: str
    commit_sha: str
    journal_sha256: str
    journal_state_sha256: str
    approver_key_ids: tuple[tuple[str, str], ...]
    drill_started_at_utc: datetime
    completed_at_utc: datetime
    valid_until_utc: datetime
    persistent_latch_verified: bool
    submission_boundary_blocked: bool
    unauthorized_reset_rejected: bool
    dual_control_reset_verified: bool
    authorization_replay_rejected: bool
    final_latch_verified: bool
    event_actions: tuple[str, ...]
    signature_hmac_sha256: str = ""
    schema_version: str = SCHEMA_VERSION
    authorization_granted: bool = False
    activation_authorized: bool = False
    execution_enabled: bool = False
    safe_to_demo_auto_order: bool = False
    live_allowed: bool = False
    order_capability: str = "DISABLED"
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RECEIPT_SEAL:
            raise TypeError("kill-switch drill receipts can only be created by the drill")
        for name in ("issuer_id", "key_id", "server"):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        object.__setattr__(
            self,
            "account_id_sha256",
            require_hash("account_id_sha256", self.account_id_sha256),
        )
        for name in (
            "release_identity_sha256",
            "release_manifest_sha256",
            "journal_sha256",
            "journal_state_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(self, "commit_sha", _commit(self.commit_sha))
        if self.server != "FinexBisnisSolusi-Demo" or self.environment != "DEMO":
            raise ValueError("kill-switch drill must bind the FINEX demo server")
        expected_approvers = ("RISK_OWNER", "OPERATIONS_OWNER")
        if tuple(role for role, _ in self.approver_key_ids) != expected_approvers:
            raise ValueError("kill-switch drill requires risk and operations approvers")
        key_ids = tuple(require_text("approver key_id", item) for _, item in self.approver_key_ids)
        if len(set(key_ids)) != 2 or self.key_id in key_ids:
            raise ValueError("kill-switch drill keys must have independent identities")
        started = require_utc("drill_started_at_utc", self.drill_started_at_utc)
        completed = require_utc("completed_at_utc", self.completed_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if not started <= completed < valid_until <= completed + DRILL_RECEIPT_MAX_AGE:
            raise ValueError("kill-switch drill receipt lifetime is invalid")
        proof_flags = (
            self.persistent_latch_verified,
            self.submission_boundary_blocked,
            self.unauthorized_reset_rejected,
            self.dual_control_reset_verified,
            self.authorization_replay_rejected,
            self.final_latch_verified,
        )
        if any(value is not True for value in proof_flags):
            raise ValueError("kill-switch drill receipt cannot contain unproven facts")
        if self.event_actions != EXPECTED_ACTIONS:
            raise ValueError("kill-switch drill event sequence is invalid")
        if self.signature_hmac_sha256:
            object.__setattr__(
                self,
                "signature_hmac_sha256",
                require_hash("signature_hmac_sha256", self.signature_hmac_sha256),
            )
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("kill-switch drill receipt schema is invalid")
        if (
            self.authorization_granted
            or self.activation_authorized
            or self.execution_enabled
            or self.safe_to_demo_auto_order
            or self.live_allowed
            or self.order_capability != "DISABLED"
        ):
            raise ValueError("kill-switch drill cannot grant trading capability")

    @property
    def signing_payload(self) -> bytes:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return canonical_json(payload).encode("utf-8")


def _prepare_submission_sentinel(
    journal: ExecutionJournal,
    *,
    account_id_sha256: str,
    server: str,
    occurred_at: datetime,
) -> tuple[int, object]:
    bar_closed = occurred_at.replace(
        minute=(occurred_at.minute // 15) * 15,
        second=0,
        microsecond=0,
    )
    decision = _mint_decision_snapshot(
        decision_run_id="finex-kill-switch-drill",
        symbol="EURUSD",
        side="BUY",
        strategy="KILL_SWITCH_SENTINEL",
        score=1,
        score_components={"sentinel": 1},
        entry_reference=1.1,
        stop_loss=1.09999,
        take_profit=1.10002,
        model_version="kill-switch-drill-v1",
        model_artifact_sha256="1" * 64,
        commit_sha="2" * 40,
        config_sha256="3" * 64,
        data_sha256="4" * 64,
        source_name="ISOLATED_SYNTHETIC_SENTINEL",
        source_aligned=True,
        data_fresh=True,
        bar_closed_at=bar_closed,
        created_at=occurred_at,
    )
    intent = TradeIntent(
        mode="DEMO",
        account_id=account_id_sha256,
        server=server,
        symbol="EURUSD",
        side="BUY",
        requested_lot=0.01,
        entry_reference=1.1,
        stop_loss=1.09999,
        take_profit=1.10002,
        created_at=occurred_at,
        expires_at=bar_closed + timedelta(seconds=10),
        decision=decision,
        permit_id="kill-switch-drill-no-execution-permit",
    )
    broker = BrokerSpec(
        account_id=account_id_sha256,
        broker_legal_name="PT Finex Bisnis Solusi Futures",
        server=server,
        environment="DEMO",
        symbol="EURUSD",
        broker_symbol="EURUSD",
        account_currency="USD",
        digits=5,
        point=0.00001,
        tick_size=0.00001,
        tick_value=1.0,
        contract_size=100000.0,
        volume_min=0.01,
        volume_max=50.0,
        volume_step=0.01,
        stops_level_points=0,
        freeze_level_points=0,
        margin_per_lot=1.0,
        session_calendar_sha256="5" * 64,
        captured_at=occurred_at,
    )
    risk = evaluate_risk(
        intent,
        broker,
        RiskContext(
            evaluated_at=occurred_at,
            mode="DEMO",
            account_id=account_id_sha256,
            server=server,
            equity=100.0,
            daily_start_equity=100.0,
            weekly_start_equity=100.0,
            high_water_equity=100.0,
            daily_pnl_cash=0.0,
            weekly_pnl_cash=0.0,
            open_position_count=0,
            entries_today=0,
            consecutive_losses=0,
            loss_latch_active=False,
            reserved_symbols=(),
            current_spread_points=1.0,
            median_spread_points=1.0,
            p95_spread_points=2.0,
            estimated_slippage_points=0.0,
            p95_slippage_points=1.0,
            news_clear=True,
            rollover_clear=True,
            data_fresh=True,
            source_aligned=True,
            permit_valid=True,
        ),
    )
    if not risk.allowed:
        raise FinexKillSwitchDrillError(
            "synthetic submission sentinel did not pass sealed risk evaluation"
        )
    request = {
        "symbol": "EURUSD",
        "volume": 0.01,
        "price": 1.1,
        "sl": 1.09999,
        "tp": 1.10002,
    }
    preflight = _mint_mt5_preflight(
        intent_id=DRILL_INTENT_ID,
        passed=True,
        reason="ISOLATED_KILL_SWITCH_DRILL",
        broker_symbol="EURUSD",
        intent_sha256=intent.content_sha256,
        broker_spec_sha256=broker.content_sha256,
        request=request,
        request_sha256=canonical_sha256(request),
        broker_retcode="DRILL_NO_TRANSPORT",
        checked_at_utc=occurred_at,
        valid_until_utc=occurred_at + timedelta(seconds=3),
        current_bid=1.09999,
        current_ask=1.1,
        tick_time_utc=occurred_at,
        allowed_deviation_points=1,
        estimated_stop_risk_cash=0.01,
        estimated_margin_cash=0.01,
    )
    guard = _mint_mt5_submission_guard(
        intent_id=DRILL_INTENT_ID,
        account_id=account_id_sha256,
        server=server,
        symbol="EURUSD",
        account_equity=100.0,
        active_order_count=0,
        active_position_count=0,
        broker_spec_sha256=broker.content_sha256,
        checked_at_utc=occurred_at,
    )
    journal.create_intent(
        intent_id=DRILL_INTENT_ID,
        decision_id=decision.snapshot_id,
        symbol=intent.symbol,
        payload={
            "intent": intent.to_canonical_dict(),
            "broker_spec": broker.to_canonical_dict(),
            "broker_spec_sha256": broker.content_sha256,
            "broker_comment": "AIS:FINEX-KILL-SWITCH-DRILL",
            "transport": "DISABLED",
        },
        created_at=occurred_at,
    )
    journal.record_risk_decision(DRILL_INTENT_ID, risk, occurred_at=occurred_at)
    journal.transition(DRILL_INTENT_ID, "RISK_APPROVED", occurred_at=occurred_at)
    journal.record_mt5_preflight(DRILL_INTENT_ID, preflight, occurred_at=occurred_at)
    journal.transition(DRILL_INTENT_ID, "PREFLIGHT_PASSED", occurred_at=occurred_at)
    capability = journal.authorize_submission_evidence(
        DRILL_INTENT_ID,
        risk_decision=risk,
        preflight=preflight,
        submission_guard=guard,
        broker_spec=broker,
        occurred_at=occurred_at,
    )
    token = journal.claim_executor(
        "finex-kill-switch-drill-executor",
        now=occurred_at,
        lease_seconds=60,
    )
    return token, capability


def _journal_state(journal: ExecutionJournal) -> dict[str, object]:
    return {
        "status": journal.kill_switch_status(),
        "history": journal.kill_switch_history(),
        "sentinel_state": journal.get_intent(DRILL_INTENT_ID).state,
    }


def run_isolated_kill_switch_drill(
    journal_path: str | Path,
    *,
    issuer_id: str,
    key_id: str,
    signing_key: str | bytes,
    risk_reset_key_id: str,
    risk_reset_key: str | bytes,
    operations_reset_key_id: str,
    operations_reset_key: str | bytes,
    account_id_sha256: str,
    server: str,
    release_identity_sha256: str,
    release_manifest_sha256: str,
    commit_sha: str,
    started_at_utc: datetime,
) -> FinexKillSwitchDrillReceipt:
    path = Path(journal_path)
    if path.exists() or path.is_symlink():
        raise FinexKillSwitchDrillError("kill-switch drill requires a new journal path")
    if not path.parent.exists() or not path.parent.is_dir():
        raise FinexKillSwitchDrillError("kill-switch drill journal parent is unavailable")
    started = require_utc("started_at_utc", started_at_utc)
    m15_boundary = started.replace(
        minute=(started.minute // 15) * 15,
        second=0,
        microsecond=0,
    )
    if started == m15_boundary:
        started += timedelta(seconds=1)
    account_hash = require_hash("account_id_sha256", account_id_sha256)
    release_hash = require_hash("release_identity_sha256", release_identity_sha256)
    manifest_hash = require_hash("release_manifest_sha256", release_manifest_sha256)
    commit = _commit(commit_sha)
    signer_secret = _secret(signing_key, "drill signing key")
    risk_secret = _secret(risk_reset_key, "risk reset key")
    operations_secret = _secret(operations_reset_key, "operations reset key")
    normalized_key_ids = (
        require_text("key_id", key_id),
        require_text("risk_reset_key_id", risk_reset_key_id),
        require_text("operations_reset_key_id", operations_reset_key_id),
    )
    fingerprints = tuple(
        hashlib.sha256(secret).hexdigest()
        for secret in (signer_secret, risk_secret, operations_secret)
    )
    if len(set(normalized_key_ids)) != 3 or len(set(fingerprints)) != 3:
        raise FinexKillSwitchDrillError(
            "drill signer, risk reset, and operations reset credentials must differ"
        )

    clock = [started]
    journal = ExecutionJournal(path, clock_provider=lambda: clock[0])
    token, capability = _prepare_submission_sentinel(
        journal,
        account_id_sha256=account_hash,
        server=server,
        occurred_at=started,
    )
    journal.latch_kill_switch(
        INITIAL_LATCH_REASON,
        source=INITIAL_LATCH_SOURCE,
        occurred_at=started,
    )

    restarted = ExecutionJournal(path, clock_provider=lambda: clock[0])
    first_status = restarted.kill_switch_status()
    persistent_latch = (
        first_status.get("latched") is True
        and first_status.get("reason") == INITIAL_LATCH_REASON
        and first_status.get("source") == INITIAL_LATCH_SOURCE
    )
    if not persistent_latch:
        raise FinexKillSwitchDrillError("kill-switch latch did not survive journal reopen")

    submission_blocked = False
    try:
        restarted.reserve_submission(
            DRILL_INTENT_ID,
            owner_id="finex-kill-switch-drill-executor",
            fence_token=token,
            submission_evidence=capability,
            occurred_at=started,
        )
    except KillSwitchLatchedError:
        submission_blocked = True
    if not submission_blocked:
        raise FinexKillSwitchDrillError("latched journal did not block submission")

    unauthorized_rejected = False
    try:
        restarted.reset_kill_switch(
            authorization=None,  # type: ignore[arg-type]
            reason=RESET_REASON,
            occurred_at=started,
        )
    except PermissionError:
        unauthorized_rejected = True
    if not unauthorized_rejected:
        raise FinexKillSwitchDrillError("unauthorized kill-switch reset was accepted")

    latched_at = _utc_from_text(first_status.get("latched_at_utc"), "latched_at_utc")
    permit = KillSwitchResetPermit(
        journal_sha256=restarted.journal_sha256,
        latched_at_utc=latched_at,
        reset_reason_sha256=reset_reason_sha256(RESET_REASON),
        approver_ids=("RISK_OWNER", "OPERATIONS_OWNER"),
        approver_key_ids=(
            ("RISK_OWNER", normalized_key_ids[1]),
            ("OPERATIONS_OWNER", normalized_key_ids[2]),
        ),
        issued_at=started,
        expires_at=started + RESET_PERMIT_MAX_AGE,
        nonce=secrets.token_hex(32),
    )
    permit = permit.sign("RISK_OWNER", normalized_key_ids[1], risk_secret)
    permit = permit.sign("OPERATIONS_OWNER", normalized_key_ids[2], operations_secret)
    clock[0] = started + timedelta(milliseconds=500)
    authorization = authorize_kill_switch_reset(
        permit,
        {
            "RISK_OWNER": (normalized_key_ids[1], risk_secret),
            "OPERATIONS_OWNER": (normalized_key_ids[2], operations_secret),
        },
        now=clock[0],
        expected_journal_sha256=restarted.journal_sha256,
        expected_latched_at_utc=latched_at,
        expected_reason=RESET_REASON,
        clock_provider=lambda: clock[0],
    )
    clock[0] = started + timedelta(seconds=1)
    restarted.reset_kill_switch(
        authorization=authorization,
        reason=RESET_REASON,
        occurred_at=clock[0],
    )
    dual_reset_verified = restarted.kill_switch_status().get("latched") is False
    if not dual_reset_verified:
        raise FinexKillSwitchDrillError("dual-control reset did not clear the latch")

    clock[0] = started + timedelta(seconds=2)
    restarted.latch_kill_switch(
        FINAL_LATCH_REASON,
        source=FINAL_LATCH_SOURCE,
        occurred_at=clock[0],
    )
    clock[0] = started + timedelta(seconds=2, milliseconds=500)
    replay_rejected = False
    try:
        restarted.reset_kill_switch(
            authorization=authorization,
            reason=RESET_REASON,
            occurred_at=clock[0],
        )
    except PermissionError:
        replay_rejected = True
    if not replay_rejected:
        raise FinexKillSwitchDrillError("reset authorization replay was accepted")

    completed = started + timedelta(seconds=2, milliseconds=500)
    state = _journal_state(restarted)
    final_status = state["status"]
    actions = tuple(item["action"] for item in state["history"])
    final_latch_verified = (
        final_status.get("latched") is True
        and final_status.get("reason") == FINAL_LATCH_REASON
        and final_status.get("source") == FINAL_LATCH_SOURCE
        and actions == EXPECTED_ACTIONS
        and state["sentinel_state"] == "PREFLIGHT_PASSED"
    )
    if not final_latch_verified:
        raise FinexKillSwitchDrillError("kill-switch drill final safe state is invalid")

    unsigned = FinexKillSwitchDrillReceipt(
        issuer_id=issuer_id,
        key_id=normalized_key_ids[0],
        account_id_sha256=account_hash,
        server=server,
        environment="DEMO",
        release_identity_sha256=release_hash,
        release_manifest_sha256=manifest_hash,
        commit_sha=commit,
        journal_sha256=restarted.journal_sha256,
        journal_state_sha256=canonical_sha256(state),
        approver_key_ids=(
            ("RISK_OWNER", normalized_key_ids[1]),
            ("OPERATIONS_OWNER", normalized_key_ids[2]),
        ),
        drill_started_at_utc=started,
        completed_at_utc=completed,
        valid_until_utc=completed + DRILL_RECEIPT_MAX_AGE,
        persistent_latch_verified=True,
        submission_boundary_blocked=True,
        unauthorized_reset_rejected=True,
        dual_control_reset_verified=True,
        authorization_replay_rejected=True,
        final_latch_verified=True,
        event_actions=EXPECTED_ACTIONS,
        _seal=_RECEIPT_SEAL,
    )
    signature = hmac.new(
        signer_secret,
        HMAC_DOMAIN + unsigned.signing_payload,
        hashlib.sha256,
    ).hexdigest()
    return replace(unsigned, signature_hmac_sha256=signature, _seal=_RECEIPT_SEAL)


def kill_switch_drill_receipt_from_mapping(
    value: Mapping[str, object],
) -> FinexKillSwitchDrillReceipt:
    expected = {field.name for field in fields(FinexKillSwitchDrillReceipt)}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise FinexKillSwitchDrillError("kill-switch drill receipt shape is invalid")
    data = dict(value)
    for name in ("drill_started_at_utc", "completed_at_utc", "valid_until_utc"):
        data[name] = _utc_from_text(data[name], name)
    approvers = data.get("approver_key_ids")
    actions = data.get("event_actions")
    if not isinstance(approvers, list) or any(
        not isinstance(item, list) or len(item) != 2 for item in approvers
    ):
        raise FinexKillSwitchDrillError("approver key bindings are invalid")
    if not isinstance(actions, list):
        raise FinexKillSwitchDrillError("event actions are invalid")
    data["approver_key_ids"] = tuple((str(item[0]), str(item[1])) for item in approvers)
    data["event_actions"] = tuple(str(item) for item in actions)
    return FinexKillSwitchDrillReceipt(**data, _seal=_RECEIPT_SEAL)


def verify_kill_switch_drill_receipt(
    receipt: FinexKillSwitchDrillReceipt,
    *,
    journal_path: str | Path,
    expected_account_id_sha256: str,
    expected_server: str,
    expected_release_identity_sha256: str,
    expected_release_manifest_sha256: str,
    expected_commit_sha: str,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> FinexKillSwitchDrillReceipt:
    if type(receipt) is not FinexKillSwitchDrillReceipt:
        raise FinexKillSwitchDrillError("KILL_SWITCH_DRILL_RECEIPT_NOT_SEALED")
    expected_signature = hmac.new(
        _secret(key_provider(receipt.key_id), "drill verification key"),
        HMAC_DOMAIN + receipt.signing_payload,
        hashlib.sha256,
    ).hexdigest()
    if not receipt.signature_hmac_sha256 or not hmac.compare_digest(
        receipt.signature_hmac_sha256, expected_signature
    ):
        raise FinexKillSwitchDrillError("KILL_SWITCH_DRILL_SIGNATURE_INVALID")
    bindings = (
        receipt.account_id_sha256
        == require_hash("expected_account_id_sha256", expected_account_id_sha256),
        receipt.server == expected_server,
        receipt.environment == "DEMO",
        receipt.release_identity_sha256
        == require_hash(
            "expected_release_identity_sha256", expected_release_identity_sha256
        ),
        receipt.release_manifest_sha256
        == require_hash(
            "expected_release_manifest_sha256", expected_release_manifest_sha256
        ),
        receipt.commit_sha == _commit(expected_commit_sha),
    )
    if not all(bindings):
        raise FinexKillSwitchDrillError("KILL_SWITCH_DRILL_BINDING_MISMATCH")
    trusted_now = require_utc("now", now)
    if not receipt.completed_at_utc <= trusted_now < receipt.valid_until_utc:
        raise FinexKillSwitchDrillError("KILL_SWITCH_DRILL_STALE_OR_FUTURE")
    path = Path(journal_path)
    if not path.exists() or not path.is_file() or path.is_symlink():
        raise FinexKillSwitchDrillError("KILL_SWITCH_DRILL_JOURNAL_UNAVAILABLE")
    journal = ExecutionJournal(path, clock_provider=lambda: trusted_now)
    state = _journal_state(journal)
    status = state["status"]
    actions = tuple(item["action"] for item in state["history"])
    state_valid = (
        journal.journal_sha256 == receipt.journal_sha256
        and canonical_sha256(state) == receipt.journal_state_sha256
        and status.get("latched") is True
        and status.get("reason") == FINAL_LATCH_REASON
        and status.get("source") == FINAL_LATCH_SOURCE
        and actions == EXPECTED_ACTIONS
        and state["sentinel_state"] == "PREFLIGHT_PASSED"
    )
    if not state_valid:
        raise FinexKillSwitchDrillError("KILL_SWITCH_DRILL_JOURNAL_STATE_INVALID")
    return receipt


__all__ = [
    "DRILL_KEY_NAME",
    "DRILL_RECEIPT_MAX_AGE",
    "FinexKillSwitchDrillError",
    "FinexKillSwitchDrillReceipt",
    "OPERATIONS_RESET_KEY_NAME",
    "RISK_RESET_KEY_NAME",
    "kill_switch_drill_receipt_from_mapping",
    "run_isolated_kill_switch_drill",
    "verify_kill_switch_drill_receipt",
]
