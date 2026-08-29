"""Signed, read-only FINEX terminal heartbeat evidence.

Only ``ReadOnlyMT5Facade`` is accepted. A report becomes ready after a short
sequence proves account binding, terminal safety, fresh ticks, bounded spread,
and stable broker specifications. Every artifact remains deny-only.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hmac
import math
import re
from typing import Any, Callable, Mapping, Sequence

from .account_identity import account_identity_sha256, payload_hmac_sha256
from .contracts import canonical_sha256
from .evidence_credentials import signing_key_fingerprint
from .mt5_readonly import ReadOnlyMT5Facade, attest_mt5_read_only


RECEIPT_SCHEMA = "finex-terminal-monitor-receipt-v2"
REPORT_SCHEMA = "finex-terminal-monitor-report-v2"
RECEIPT_DOMAIN = b"ai-scalper/finex-terminal-monitor/receipt/v2"
REPORT_DOMAIN = b"ai-scalper/finex-terminal-monitor/report/v2"
RECEIPT_MAX_AGE_SECONDS = 15
FUTURE_SKEW_SECONDS = 2
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")


class FinexTerminalMonitorError(RuntimeError):
    pass


def _mapping(value: object, name: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    converter = getattr(value, "_asdict", None)
    if callable(converter):
        converted = converter()
        if isinstance(converted, Mapping):
            return dict(converted)
    raise FinexTerminalMonitorError(f"{name} is unavailable")


def _now_utc(now_provider: Callable[[], datetime]) -> datetime:
    value = now_provider()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise FinexTerminalMonitorError("monitor clock must be timezone-aware")
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_utc(value: object, name: str) -> datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise FinexTerminalMonitorError(f"{name} is invalid") from exc
    if parsed.tzinfo is None:
        raise FinexTerminalMonitorError(f"{name} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _sha256(value: object, name: str) -> str:
    normalized = str(value or "").strip().lower()
    if _SHA256_RE.fullmatch(normalized) is None:
        raise FinexTerminalMonitorError(f"{name} must be SHA-256")
    return normalized


def _finite(value: object, name: str, *, positive: bool = False) -> float:
    if isinstance(value, bool):
        raise FinexTerminalMonitorError(f"{name} must be numeric")
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise FinexTerminalMonitorError(f"{name} must be numeric") from exc
    if not math.isfinite(result) or (positive and result <= 0):
        raise FinexTerminalMonitorError(f"{name} is outside the safe range")
    return result


def _body(payload: Mapping[str, object], field: str) -> dict[str, object]:
    body = dict(payload)
    body.pop(field, None)
    return body


def _sign(
    payload: Mapping[str, object], signing_key: bytes, *, field: str, domain: bytes
) -> str:
    return payload_hmac_sha256(_body(payload, field), signing_key, domain=domain)


def _spec(info: Mapping[str, object]) -> dict[str, object]:
    digits = info.get("digits")
    if isinstance(digits, bool) or not isinstance(digits, int) or not 0 <= digits <= 12:
        raise FinexTerminalMonitorError("symbol digits are invalid")
    spec = {
        "digits": digits,
        "point": _finite(info.get("point"), "point", positive=True),
        "tick_size": _finite(info.get("trade_tick_size"), "tick size", positive=True),
        "contract_size": _finite(
            info.get("trade_contract_size"), "contract size", positive=True
        ),
        "volume_min": _finite(info.get("volume_min"), "volume min", positive=True),
        "volume_max": _finite(info.get("volume_max"), "volume max", positive=True),
        "volume_step": _finite(info.get("volume_step"), "volume step", positive=True),
        "currency_profit": str(info.get("currency_profit") or "").strip().upper(),
        "currency_margin": str(info.get("currency_margin") or "").strip().upper(),
        "trade_calc_mode": info.get("trade_calc_mode"),
        "trade_stops_level": info.get("trade_stops_level"),
        "trade_freeze_level": info.get("trade_freeze_level"),
    }
    if spec["volume_min"] > spec["volume_max"] or spec["volume_step"] > spec["volume_max"]:
        raise FinexTerminalMonitorError("symbol volume constraints are invalid")
    if not spec["currency_profit"] or not spec["currency_margin"]:
        raise FinexTerminalMonitorError("symbol currencies are unavailable")
    for name in ("trade_calc_mode", "trade_stops_level", "trade_freeze_level"):
        value = spec[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise FinexTerminalMonitorError(f"{name} is invalid")
    return spec


def _symbol_sample(
    facade: ReadOnlyMT5Facade,
    canonical_symbol: str,
    broker_symbol: str,
    *,
    max_spread_bps: float,
) -> dict[str, object]:
    blockers: list[str] = []
    try:
        info = _mapping(facade.symbol_info(broker_symbol), "symbol info")
        if info.get("visible") is not True:
            blockers.append("SYMBOL_NOT_VISIBLE")
        mode = info.get("trade_mode")
        if isinstance(mode, bool) or not isinstance(mode, int) or mode <= 0:
            blockers.append("SYMBOL_TRADE_MODE_DISABLED")
        bid = _finite(info.get("bid"), "bid", positive=True)
        ask = _finite(info.get("ask"), "ask", positive=True)
        point = _finite(info.get("point"), "point", positive=True)
        if ask < bid:
            blockers.append("CROSSED_MARKET")
        spread_points = max(0.0, (ask - bid) / point)
        spread_bps = ((ask - bid) / ((ask + bid) / 2.0)) * 10_000.0
        if spread_bps > max_spread_bps:
            blockers.append("SPREAD_LIMIT_EXCEEDED")
        time_msc = info.get("time_msc")
        if isinstance(time_msc, bool):
            raise FinexTerminalMonitorError("tick timestamp is invalid")
        if isinstance(time_msc, (int, float)) and float(time_msc) > 0:
            tick_epoch = float(time_msc) / 1000.0
        else:
            tick_epoch = _finite(info.get("time"), "tick timestamp", positive=True)
        spec = _spec(info)
        return {
            "canonical_symbol": canonical_symbol,
            "broker_symbol": broker_symbol,
            "status": "READY_READ_ONLY" if not blockers else "HOLD",
            "blocker_codes": sorted(set(blockers)),
            "tick_time_raw_seconds": tick_epoch,
            "bid": bid,
            "ask": ask,
            "spread_points": round(spread_points, 6),
            "spread_bps": round(spread_bps, 6),
            "terminal_spec_observation": spec,
            "terminal_spec_observation_sha256": canonical_sha256(spec),
            "risk_tick_value": _finite(
                info.get("trade_tick_value"), "tick value", positive=True
            ),
        }
    except (FinexTerminalMonitorError, OSError, RuntimeError, TypeError, ValueError):
        return {
            "canonical_symbol": canonical_symbol,
            "broker_symbol": broker_symbol,
            "status": "HOLD",
            "blocker_codes": ["SYMBOL_SNAPSHOT_INVALID"],
            "tick_time_raw_seconds": None,
            "bid": None,
            "ask": None,
            "spread_points": None,
            "spread_bps": None,
            "terminal_spec_observation": None,
            "terminal_spec_observation_sha256": None,
            "risk_tick_value": None,
        }


def create_monitor_receipt(
    facade: ReadOnlyMT5Facade,
    *,
    session_id: str,
    sequence: int,
    expected_server: str,
    expected_account_identity_sha256: str,
    terminal_fence_sha256: str,
    symbol_map: Mapping[str, str],
    signing_key: bytes,
    account_identity_key: bytes,
    max_spread_bps: float,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    if type(facade) is not ReadOnlyMT5Facade:
        raise FinexTerminalMonitorError("exact read-only MT5 facade is required")
    if _SESSION_RE.fullmatch(str(session_id or "")) is None:
        raise FinexTerminalMonitorError("session_id is invalid")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise FinexTerminalMonitorError("sequence is invalid")
    server = str(expected_server or "").strip()
    if not server:
        raise FinexTerminalMonitorError("expected server is required")
    account_hash = _sha256(expected_account_identity_sha256, "account identity")
    fence_hash = _sha256(terminal_fence_sha256, "terminal fence")
    if not isinstance(symbol_map, Mapping) or not symbol_map:
        raise FinexTerminalMonitorError("symbol map is required")
    spread_limit = _finite(max_spread_bps, "max spread bps", positive=True)
    observed_at = _now_utc(now_provider)
    blockers: list[str] = []
    account_safe = False
    terminal_safe = False
    try:
        attest_mt5_read_only(facade, require_account_expert_disabled=False)
        account = _mapping(facade.account_info(), "account info")
        terminal = _mapping(facade.terminal_info(), "terminal info")
        observed_identity = account_identity_sha256(
            account,
            account_identity_key,
            environment="DEMO",
        )
        if str(account.get("server") or "") != server:
            blockers.append("ACCOUNT_SERVER_MISMATCH")
        if account.get("trade_mode") != facade.ACCOUNT_TRADE_MODE_DEMO:
            blockers.append("ACCOUNT_NOT_DEMO")
        if not hmac.compare_digest(observed_identity, account_hash):
            blockers.append("ACCOUNT_IDENTITY_MISMATCH")
        account_safe = not any(code.startswith("ACCOUNT_") for code in blockers)
        if terminal.get("connected") is not True:
            blockers.append("TERMINAL_DISCONNECTED")
        terminal_safe = not any(code.startswith("TERMINAL_") for code in blockers)
    except (OSError, RuntimeError, TypeError, ValueError):
        blockers.append("READ_ONLY_ATTESTATION_FAILED")
    samples = {
        str(canonical).upper(): _symbol_sample(
            facade,
            str(canonical).upper(),
            str(broker),
            max_spread_bps=spread_limit,
        )
        for canonical, broker in sorted(symbol_map.items())
    }
    for symbol, sample in samples.items():
        blockers.extend(f"{code}:{symbol}" for code in sample["blocker_codes"])
    blockers = sorted(set(blockers))
    receipt: dict[str, object] = {
        "schema": RECEIPT_SCHEMA,
        "candidate": "finex",
        "environment": "DEMO",
        "session_id": session_id,
        "sequence": sequence,
        "expected_server": server,
        "account_identity_sha256": account_hash,
        "terminal_fence_sha256": fence_hash,
        "observed_at": _utc_text(observed_at),
        "expires_at": _utc_text(observed_at + timedelta(seconds=RECEIPT_MAX_AGE_SECONDS)),
        "key_id": "wincred-" + signing_key_fingerprint(signing_key),
        "account_binding_safe": account_safe,
        "terminal_read_only_safe": terminal_safe,
        "symbol_samples": samples,
        "blocker_codes": blockers,
        "monitor_status": "READY_READ_ONLY" if not blockers else "HOLD",
        "authorization_granted": False,
        "registration_enabled": False,
        "promotion_eligible": False,
        "order_capability": "DISABLED",
    }
    receipt["receipt_hmac_sha256"] = _sign(
        receipt, signing_key, field="receipt_hmac_sha256", domain=RECEIPT_DOMAIN
    )
    return receipt


def verify_monitor_receipt(
    receipt: Mapping[str, object],
    *,
    signing_key: bytes,
    expected_session_id: str | None = None,
    expected_account_identity_sha256: str | None = None,
    expected_terminal_fence_sha256: str | None = None,
    require_ready: bool = True,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    if not isinstance(receipt, Mapping) or receipt.get("schema") != RECEIPT_SCHEMA:
        raise FinexTerminalMonitorError("terminal monitor receipt schema is invalid")
    expected = _sign(
        receipt, signing_key, field="receipt_hmac_sha256", domain=RECEIPT_DOMAIN
    )
    if not hmac.compare_digest(str(receipt.get("receipt_hmac_sha256") or ""), expected):
        raise FinexTerminalMonitorError("terminal monitor receipt signature is invalid")
    if receipt.get("candidate") != "finex" or receipt.get("environment") != "DEMO":
        raise FinexTerminalMonitorError("terminal monitor candidate binding is invalid")
    if expected_session_id is not None and receipt.get("session_id") != expected_session_id:
        raise FinexTerminalMonitorError("terminal monitor session binding is invalid")
    account_hash = _sha256(receipt.get("account_identity_sha256"), "account identity")
    fence_hash = _sha256(receipt.get("terminal_fence_sha256"), "terminal fence")
    if expected_account_identity_sha256 is not None and not hmac.compare_digest(
        account_hash, _sha256(expected_account_identity_sha256, "expected account identity")
    ):
        raise FinexTerminalMonitorError("terminal monitor account binding is invalid")
    if expected_terminal_fence_sha256 is not None and not hmac.compare_digest(
        fence_hash, _sha256(expected_terminal_fence_sha256, "expected terminal fence")
    ):
        raise FinexTerminalMonitorError("terminal monitor fence binding is invalid")
    observed_at = _parse_utc(receipt.get("observed_at"), "observed_at")
    expires_at = _parse_utc(receipt.get("expires_at"), "expires_at")
    now = _now_utc(now_provider)
    if observed_at > now + timedelta(seconds=FUTURE_SKEW_SECONDS):
        raise FinexTerminalMonitorError("terminal monitor receipt is from the future")
    if expires_at <= observed_at or expires_at > observed_at + timedelta(
        seconds=RECEIPT_MAX_AGE_SECONDS
    ):
        raise FinexTerminalMonitorError("terminal monitor receipt lifetime is invalid")
    if now >= expires_at:
        raise FinexTerminalMonitorError("terminal monitor receipt is expired")
    if any(
        receipt.get(name) is not False
        for name in ("authorization_granted", "registration_enabled", "promotion_eligible")
    ) or receipt.get("order_capability") != "DISABLED":
        raise FinexTerminalMonitorError("terminal monitor safety contract is invalid")
    samples = receipt.get("symbol_samples")
    blockers = receipt.get("blocker_codes")
    if not isinstance(samples, Mapping) or not samples or not isinstance(blockers, list):
        raise FinexTerminalMonitorError("terminal monitor receipt payload is invalid")
    if require_ready and (
        receipt.get("monitor_status") != "READY_READ_ONLY"
        or blockers
        or receipt.get("account_binding_safe") is not True
        or receipt.get("terminal_read_only_safe") is not True
    ):
        raise FinexTerminalMonitorError("terminal monitor receipt is not ready")
    return dict(receipt)


def assemble_monitor_report(
    receipts: Sequence[Mapping[str, object]],
    *,
    signing_key: bytes,
    minimum_samples: int = 3,
    max_sample_gap_seconds: float = 5.0,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    if isinstance(minimum_samples, bool) or not isinstance(minimum_samples, int):
        raise FinexTerminalMonitorError("minimum samples is invalid")
    gap_limit = _finite(max_sample_gap_seconds, "max sample gap", positive=True)
    if not receipts:
        raise FinexTerminalMonitorError("terminal monitor receipts are required")
    verified = [
        verify_monitor_receipt(
            receipt, signing_key=signing_key, require_ready=False, now_provider=now_provider
        )
        for receipt in receipts
    ]
    first = verified[0]
    session_id = str(first.get("session_id"))
    account_hash = str(first.get("account_identity_sha256"))
    fence_hash = str(first.get("terminal_fence_sha256"))
    blockers: list[str] = []
    required_samples = max(3, minimum_samples)
    if len(verified) < required_samples:
        blockers.append("INSUFFICIENT_MONITOR_SAMPLES")
    previous_time: datetime | None = None
    expected_specs: dict[str, object] | None = None
    tick_states: dict[str, list[tuple[float, float, float]]] = {}
    for index, receipt in enumerate(verified):
        if receipt.get("session_id") != session_id:
            blockers.append("SESSION_CHANGED")
        if receipt.get("account_identity_sha256") != account_hash:
            blockers.append("ACCOUNT_IDENTITY_CHANGED")
        if receipt.get("terminal_fence_sha256") != fence_hash:
            blockers.append("TERMINAL_FENCE_CHANGED")
        if receipt.get("sequence") != index:
            blockers.append("SEQUENCE_NOT_CONTIGUOUS")
        observed_at = _parse_utc(receipt.get("observed_at"), "observed_at")
        if previous_time is not None:
            gap = (observed_at - previous_time).total_seconds()
            if gap <= 0 or gap > gap_limit:
                blockers.append("SAMPLE_GAP_INVALID")
        previous_time = observed_at
        if receipt.get("monitor_status") != "READY_READ_ONLY":
            blockers.extend(str(code) for code in receipt.get("blocker_codes", []))
        samples = receipt.get("symbol_samples")
        if not isinstance(samples, Mapping):
            raise FinexTerminalMonitorError("terminal monitor samples are invalid")
        current_specs = {
            str(symbol): sample.get("terminal_spec_observation_sha256")
            for symbol, sample in samples.items()
            if isinstance(sample, Mapping)
        }
        if expected_specs is None:
            expected_specs = current_specs
        elif current_specs != expected_specs:
            blockers.append("TERMINAL_SPEC_OBSERVATION_CHANGED")
        for symbol, sample in samples.items():
            if not isinstance(sample, Mapping):
                continue
            raw_time = sample.get("tick_time_raw_seconds")
            bid = sample.get("bid")
            ask = sample.get("ask")
            if all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in (raw_time, bid, ask)):
                tick_states.setdefault(str(symbol), []).append(
                    (float(raw_time), float(bid), float(ask))
                )
    for symbol, states in tick_states.items():
        if any(current[0] < previous[0] for previous, current in zip(states, states[1:])):
            blockers.append(f"TICK_TIME_REGRESSED:{symbol}")
        if len(states) == len(verified) and len(set(states)) == 1:
            blockers.append(f"TICK_STREAM_STAGNANT:{symbol}")
    blockers = sorted(set(blockers))
    report: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "candidate": "finex",
        "environment": "DEMO",
        "session_id": session_id,
        "account_identity_sha256": account_hash,
        "terminal_fence_sha256": fence_hash,
        "sample_count": len(verified),
        "minimum_samples": required_samples,
        "max_sample_gap_seconds": gap_limit,
        "first_observed_at": verified[0]["observed_at"],
        "last_observed_at": verified[-1]["observed_at"],
        "expires_at": verified[-1]["expires_at"],
        "terminal_spec_observation_hashes": expected_specs or {},
        "receipts": verified,
        "blocker_codes": blockers,
        "monitor_status": "READY_READ_ONLY" if not blockers else "HOLD",
        "terminal_monitor_verified": not blockers,
        "authorization_granted": False,
        "registration_enabled": False,
        "promotion_eligible": False,
        "order_capability": "DISABLED",
        "key_id": "wincred-" + signing_key_fingerprint(signing_key),
    }
    report["report_hmac_sha256"] = _sign(
        report, signing_key, field="report_hmac_sha256", domain=REPORT_DOMAIN
    )
    return report


def verify_monitor_report(
    report: Mapping[str, object],
    *,
    signing_key: bytes,
    expected_account_identity_sha256: str,
    expected_terminal_fence_sha256: str,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    if not isinstance(report, Mapping) or report.get("schema") != REPORT_SCHEMA:
        raise FinexTerminalMonitorError("terminal monitor report schema is invalid")
    expected = _sign(report, signing_key, field="report_hmac_sha256", domain=REPORT_DOMAIN)
    if not hmac.compare_digest(str(report.get("report_hmac_sha256") or ""), expected):
        raise FinexTerminalMonitorError("terminal monitor report signature is invalid")
    if not hmac.compare_digest(
        _sha256(report.get("account_identity_sha256"), "account identity"),
        _sha256(expected_account_identity_sha256, "expected account identity"),
    ) or not hmac.compare_digest(
        _sha256(report.get("terminal_fence_sha256"), "terminal fence"),
        _sha256(expected_terminal_fence_sha256, "expected terminal fence"),
    ):
        raise FinexTerminalMonitorError("terminal monitor report binding is invalid")
    receipts = report.get("receipts")
    if not isinstance(receipts, list):
        raise FinexTerminalMonitorError("terminal monitor report receipts are invalid")
    rebuilt = assemble_monitor_report(
        receipts,
        signing_key=signing_key,
        minimum_samples=int(report.get("minimum_samples", 0)),
        max_sample_gap_seconds=float(report.get("max_sample_gap_seconds", 0)),
        now_provider=now_provider,
    )
    if canonical_sha256(_body(report, "report_hmac_sha256")) != canonical_sha256(
        _body(rebuilt, "report_hmac_sha256")
    ):
        raise FinexTerminalMonitorError("terminal monitor report content is invalid")
    if report.get("terminal_monitor_verified") is not True:
        raise FinexTerminalMonitorError("terminal monitor report is not ready")
    return dict(report)


__all__ = [
    "FinexTerminalMonitorError",
    "RECEIPT_MAX_AGE_SECONDS",
    "RECEIPT_SCHEMA",
    "REPORT_SCHEMA",
    "assemble_monitor_report",
    "create_monitor_receipt",
    "verify_monitor_receipt",
    "verify_monitor_report",
]
