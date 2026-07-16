from __future__ import annotations

import json
import io
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from live_runtime.mt5_readonly import MT5ReadOnlyAttestationError
from live_runtime.realtime_diagnostic import (
    DiagnosticIdentity,
    RealtimeDiagnosticError,
)
import run_realtime_diagnostic_shadow as cli

from test_live_runtime_realtime_diagnostic import BROKER_SYMBOLS, FakeMT5


def candidate_config(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "xm",
                        "environment": "DEMO",
                        "server": "XMTrading-MT5 3",
                        "broker_symbols_observed": BROKER_SYMBOLS,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


class RealtimeDiagnosticCLITests(unittest.TestCase):
    def test_acknowledgement_and_windows_are_mandatory(self) -> None:
        with self.assertRaisesRegex(
            RealtimeDiagnosticError,
            "acknowledge-diagnostic-only",
        ):
            cli.main([], platform_name="Windows")
        with self.assertRaisesRegex(RealtimeDiagnosticError, "must run on Windows"):
            cli.main(
                ["--acknowledge-diagnostic-only"],
                platform_name="Darwin",
            )

    def test_one_cycle_writes_non_promotional_summary_and_shuts_down(self) -> None:
        fake = FakeMT5()
        fake.initialize = lambda: True
        fake.shutdown_called = False

        def shutdown() -> None:
            fake.shutdown_called = True

        fake.shutdown = shutdown
        fake.last_error = lambda: (0, "ok")
        fixed_identity = DiagnosticIdentity(
            commit_sha="a" * 40,
            model_version="test-locked-v1",
            model_artifact_sha256="b" * 64,
            config_sha256="c" * 64,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "candidates.json"
            journal = root / "diagnostic.sqlite3"
            summary = root / "summary.json"
            candidate_config(config)
            with patch.object(cli, "_identity", return_value=fixed_identity):
                result = cli.main(
                    [
                        "--acknowledge-diagnostic-only",
                        "--config",
                        str(config),
                        "--journal",
                        str(journal),
                        "--summary",
                        str(summary),
                    ],
                    mt5_module=fake,
                    platform_name="Windows",
                )
            self.assertEqual(0, result)
            self.assertTrue(fake.shutdown_called)
            payload = json.loads(summary.read_text(encoding="utf-8"))
            self.assertEqual(
                "BROKER_REALTIME_DIAGNOSTIC_ONLY",
                payload["profile"],
            )
            self.assertFalse(payload["safety"]["promotion_eligible"])
            self.assertEqual("DISABLED", payload["safety"]["order_capability"])

    def test_entrypoint_formats_expected_attestation_rejection_without_traceback(
        self,
    ) -> None:
        error = MT5ReadOnlyAttestationError(
            "MT5_READ_ONLY_ATTESTATION_FAILED: "
            "terminal_tradeapi_disabled=False (expected True)",
            mismatches={
                "terminal_tradeapi_disabled": (False, True),
            },
        )
        stderr = io.StringIO()
        with patch.object(cli, "main", side_effect=error), redirect_stderr(stderr):
            result = cli.cli_entrypoint([])
        output = stderr.getvalue()
        self.assertEqual(2, result)
        self.assertIn("Disable automated trading through the external Python API", output)
        self.assertIn("no broker order was submitted", output)
        self.assertNotIn("Traceback", output)


if __name__ == "__main__":
    unittest.main()
