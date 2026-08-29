from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from live_runtime.finex_terminal_fence import (
    FinexTerminalFenceError,
    create_terminal_fence,
    verify_terminal_fence,
)


NOW = datetime(2026, 8, 27, 15, 0, tzinfo=timezone.utc)
DISCOVERY_KEY = b"discovery-test-key" * 3
FENCE_KEY = b"terminal-fence-test-key" * 2


def _discovery() -> dict[str, object]:
    return {
        "candidate_id": "finex",
        "captured_at_utc": (NOW - timedelta(minutes=1))
        .replace(microsecond=123456)
        .isoformat()
        .replace("+00:00", "Z"),
        "payload_sha256": "a" * 64,
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "account": {
            "environment": "DEMO",
            "server": "FinexBisnisSolusi-Demo",
            "account_identity_sha256": "b" * 64,
            "trade_allowed": False,
            "trade_expert": False,
        },
        "terminal": {"trade_allowed": False, "tradeapi_disabled": True},
    }


class FinexTerminalFenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="finex-terminal-fence-")
        self.terminal = Path(self.temp.name) / "terminal64.exe"
        self.terminal.write_bytes(b"synthetic-terminal-binary")

    def tearDown(self) -> None:
        self.temp.cleanup()

    @patch("live_runtime.finex_terminal_fence.verify_discovery_receipt")
    def test_short_lived_fence_is_signed_and_deny_only(self, verify_discovery) -> None:
        receipt = create_terminal_fence(
            _discovery(),
            terminal_path=self.terminal.resolve(),
            discovery_key=DISCOVERY_KEY,
            fence_key=FENCE_KEY,
            algo_trading_off_attested=True,
            external_python_trading_disabled_attested=True,
            demo_account_attested=True,
            now_provider=lambda: NOW,
        )
        verified = verify_terminal_fence(
            receipt,
            _discovery(),
            terminal_path=self.terminal.resolve(),
            discovery_key=DISCOVERY_KEY,
            fence_key=FENCE_KEY,
            now_provider=lambda: NOW,
        )
        self.assertFalse(verified["authorization_granted"])
        self.assertEqual(verified["order_capability"], "DISABLED")
        self.assertEqual(verify_discovery.call_count, 2)

    @patch("live_runtime.finex_terminal_fence.verify_discovery_receipt")
    def test_expired_fence_is_rejected(self, _verify_discovery) -> None:
        receipt = create_terminal_fence(
            _discovery(),
            terminal_path=self.terminal.resolve(),
            discovery_key=DISCOVERY_KEY,
            fence_key=FENCE_KEY,
            algo_trading_off_attested=True,
            external_python_trading_disabled_attested=True,
            demo_account_attested=True,
            now_provider=lambda: NOW,
        )
        with self.assertRaises(FinexTerminalFenceError):
            verify_terminal_fence(
                receipt,
                _discovery(),
                terminal_path=self.terminal.resolve(),
                discovery_key=DISCOVERY_KEY,
                fence_key=FENCE_KEY,
                now_provider=lambda: NOW + timedelta(minutes=16),
            )

    @patch("live_runtime.finex_terminal_fence.verify_discovery_receipt")
    def test_tamper_and_unsafe_terminal_flags_are_rejected(self, _verify_discovery) -> None:
        unsafe = _discovery()
        unsafe["terminal"] = {"trade_allowed": True, "tradeapi_disabled": True}
        with self.assertRaises(FinexTerminalFenceError):
            create_terminal_fence(
                unsafe,
                terminal_path=self.terminal.resolve(),
                discovery_key=DISCOVERY_KEY,
                fence_key=FENCE_KEY,
                algo_trading_off_attested=True,
                external_python_trading_disabled_attested=True,
                demo_account_attested=True,
                now_provider=lambda: NOW,
            )

        receipt = create_terminal_fence(
            _discovery(),
            terminal_path=self.terminal.resolve(),
            discovery_key=DISCOVERY_KEY,
            fence_key=FENCE_KEY,
            algo_trading_off_attested=True,
            external_python_trading_disabled_attested=True,
            demo_account_attested=True,
            now_provider=lambda: NOW,
        )
        receipt["terminal_binary_sha256"] = "c" * 64
        with self.assertRaises(FinexTerminalFenceError):
            verify_terminal_fence(
                receipt,
                _discovery(),
                terminal_path=self.terminal.resolve(),
                discovery_key=DISCOVERY_KEY,
                fence_key=FENCE_KEY,
                now_provider=lambda: NOW,
            )


if __name__ == "__main__":
    unittest.main()

