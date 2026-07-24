from __future__ import annotations

import json
import io
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from live_runtime.mt5_readonly import MT5ReadOnlyAttestationError
from live_runtime.realtime_diagnostic import (
    BROKER_DIAGNOSTIC_DOMAINS,
    DiagnosticJournal,
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
    def test_phillip_split_lanes_use_their_independently_observed_jst_offsets(self) -> None:
        plan = json.loads(cli.DEFAULT_CONFIG.read_text(encoding="utf-8"))
        candidates = {
            item["candidate_id"]: item for item in plan["candidates"]
        }
        observed_at = cli.datetime(2026, 7, 21, 9, 12, tzinfo=cli.timezone.utc)
        self.assertEqual(
            9 * 60 * 60,
            cli._broker_time_offset_seconds(
                candidates["phillip-commodity"],
                observed_at,
            ),
        )
        self.assertEqual(
            9 * 60 * 60,
            cli._broker_time_offset_seconds(candidates["phillip-fx"], observed_at),
        )
        self.assertIn(
            "AUDUSD.ps01, EURUSD.ps01, and USDJPY.ps01",
            candidates["phillip-fx"]["server_time_model"]["source"],
        )

    def test_default_artifacts_are_isolated_per_candidate(self) -> None:
        root = Path("C:/AI_SCALPER/runtime_state/diagnostic")
        xm_journal, xm_summary = cli._diagnostic_artifact_paths("xm", root=root)
        finex_journal, finex_summary = cli._diagnostic_artifact_paths(
            "finex", root=root
        )
        fbs_journal, fbs_summary = cli._diagnostic_artifact_paths("fbs", root=root)

        self.assertEqual(root / "xm-real-market.sqlite3", xm_journal)
        self.assertEqual(root / "xm-real-market-summary.json", xm_summary)
        self.assertEqual(root / "finex-real-market.sqlite3", finex_journal)
        self.assertEqual(root / "finex-real-market-summary.json", finex_summary)
        self.assertEqual(root / "fbs-real-market.sqlite3", fbs_journal)
        self.assertEqual(root / "fbs-real-market-summary.json", fbs_summary)
        self.assertEqual("fbs", cli._parser().parse_args([]).candidate)

    def test_phillip_split_domains_have_isolated_symbols_and_artifacts(self) -> None:
        root = Path("C:/AI_SCALPER/runtime_state/diagnostic")
        fx_journal, fx_summary = cli._diagnostic_artifact_paths(
            "phillip-fx",
            root=root,
            artifact_tag=cli.PHILLIP_FX_RUNNER_DOMAIN.artifact_tag,
        )
        commodity_journal, commodity_summary = cli._diagnostic_artifact_paths(
            "phillip-commodity",
            root=root,
            artifact_tag=cli.PHILLIP_COMMODITY_RUNNER_DOMAIN.artifact_tag,
        )
        self.assertEqual(("AUDUSD", "EURUSD", "USDJPY"), cli.PHILLIP_FX_RUNNER_DOMAIN.required_symbols)
        self.assertEqual(("XAUUSD",), cli.PHILLIP_COMMODITY_RUNNER_DOMAIN.required_symbols)
        self.assertEqual(root / "phillip-fx-fx-real-market.sqlite3", fx_journal)
        self.assertEqual(root / "phillip-fx-fx-real-market-summary.json", fx_summary)
        self.assertEqual(
            root / "phillip-commodity-commodity-real-market.sqlite3",
            commodity_journal,
        )
        self.assertEqual(
            root / "phillip-commodity-commodity-real-market-summary.json",
            commodity_summary,
        )
        for domain in (
            cli.PHILLIP_FX_RUNNER_DOMAIN,
            cli.PHILLIP_COMMODITY_RUNNER_DOMAIN,
        ):
            self.assertIn(
                (
                    domain.profile,
                    domain.schema_version,
                    domain.required_symbols,
                    domain.timeframe,
                ),
                BROKER_DIAGNOSTIC_DOMAINS,
            )

    def test_phillip_commodity_domain_runs_through_shared_broker_cycle(self) -> None:
        fake = FakeMT5()
        fake.rates["XAUUSD.ps01"] = fake.rates.pop(BROKER_SYMBOLS["XAUUSD"])
        fake.ticks["XAUUSD.ps01"] = fake.ticks.pop(BROKER_SYMBOLS["XAUUSD"])
        original_account_info = fake.account_info
        fake.account_info = lambda: {
            **original_account_info(),
            "server": "PhillipSecuritiesJP-PROD",
            "trade_expert": True,
        }
        fake.initialize = lambda path=None: True
        fake.shutdown = lambda: None
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
            config.write_text(
                json.dumps(
                    {
                        "candidates": [
                            {
                                "candidate_id": "phillip-commodity",
                                "environment": "DEMO",
                                "server": "PhillipSecuritiesJP-PROD",
                                "broker_symbols_observed": {
                                    "XAUUSD": "XAUUSD.ps01"
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(cli, "_identity", return_value=fixed_identity):
                result = cli.main(
                    [
                        "--acknowledge-diagnostic-only",
                        "--candidate",
                        "phillip-commodity",
                        "--config",
                        str(config),
                        "--journal",
                        str(root / "journal.sqlite3"),
                        "--summary",
                        str(root / "summary.json"),
                    ],
                    mt5_module=fake,
                    platform_name="Windows",
                    runner_domain=cli.PHILLIP_COMMODITY_RUNNER_DOMAIN,
                )
        self.assertEqual(0, result)

    def test_exact_terminal_path_is_forwarded_to_mt5_initialize(self) -> None:
        fake = FakeMT5()
        original_account_info = fake.account_info
        fake.account_info = lambda: {
            **original_account_info(),
            "trade_expert": True,
        }
        initialized_with: list[str | None] = []
        fake.initialize = lambda path=None: initialized_with.append(path) or True
        fake.shutdown = lambda: None
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
            candidate_config(config)
            with patch.object(cli, "_identity", return_value=fixed_identity):
                result = cli.main(
                    [
                        "--acknowledge-diagnostic-only",
                        "--candidate",
                        "xm",
                        "--terminal-path",
                        r"C:\Phillip MT5\terminal64.exe",
                        "--config",
                        str(config),
                        "--journal",
                        str(root / "journal.sqlite3"),
                        "--summary",
                        str(root / "summary.json"),
                    ],
                    mt5_module=fake,
                    platform_name="Windows",
                )
        self.assertEqual([r"C:\Phillip MT5\terminal64.exe"], initialized_with)

    def test_existing_journal_from_another_broker_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "diagnostic.sqlite3"
            observed_at = datetime(2026, 7, 18, 9, 0, tzinfo=timezone.utc)
            with DiagnosticJournal(database) as journal:
                journal.record_cycle(
                    cycle_id="xm-cycle",
                    observed_at=observed_at,
                    expected_server="XMTrading-MT5 3",
                    expected_account_identity_sha256="a" * 64,
                    symbol_status={symbol: "WAIT" for symbol in BROKER_SYMBOLS},
                    failures={},
                    closed_positions=(),
                )

            with DiagnosticJournal(database) as journal:
                with self.assertRaisesRegex(
                    RealtimeDiagnosticError,
                    "broker cohort",
                ):
                    journal.assert_broker_cohort(
                        expected_server="FinexBisnisSolusi-Demo",
                        expected_account_identity_sha256="b" * 64,
                    )

    def test_registered_xm_dst_offset_is_selected_by_utc_date(self) -> None:
        candidate = {
            "server_time_model": {
                "standard_utc_offset": "+02:00",
                "daylight_saving_utc_offset": "+03:00",
                "daylight_saving_rule": (
                    "LAST_SUNDAY_MARCH_TO_LAST_SUNDAY_OCTOBER"
                ),
            }
        }
        self.assertEqual(
            3 * 60 * 60,
            cli._broker_time_offset_seconds(
                candidate,
                cli.datetime(2026, 7, 16, tzinfo=cli.timezone.utc),
            ),
        )
        self.assertEqual(
            2 * 60 * 60,
            cli._broker_time_offset_seconds(
                candidate,
                cli.datetime(2026, 1, 16, tzinfo=cli.timezone.utc),
            ),
        )

    def test_registered_fixed_fbs_diagnostic_offset_is_selected(self) -> None:
        candidate = {
            "server_time_model": {
                "fixed_utc_offset": "+03:00",
                "source_status": "OPERATOR_RUNTIME_OBSERVED_DIAGNOSTIC_ONLY",
            }
        }
        self.assertEqual(
            3 * 60 * 60,
            cli._broker_time_offset_seconds(
                candidate,
                cli.datetime(2026, 7, 18, tzinfo=cli.timezone.utc),
            ),
        )

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
        original_account_info = fake.account_info
        fake.account_info = lambda: {
            **original_account_info(),
            "trade_expert": True,
        }
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
                        "--candidate",
                        "xm",
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
