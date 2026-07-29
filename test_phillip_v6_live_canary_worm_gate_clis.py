from __future__ import annotations

from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest

import prepare_phillip_v6_live_canary_worm_gate_evidence as prepare_cli
import verify_phillip_v6_live_canary_worm_gate_evidence as verify_cli
import test_live_runtime_phillip_v6_live_canary_worm_gate as fixture_module


class PhillipV6LiveCanaryWormGateCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixture = fixture_module.PhillipV6LiveCanaryWormGateTests(
            "test_ac1_deterministic_bridge_round_trips"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture

    def _prepare_argv(self, output: Path) -> list[str]:
        fixture = self.fixture
        return [
            "--custody-request",
            str(fixture.request),
            "--expected-custody-request-sha256",
            fixture.request_sha256,
            "--expected-toolkit-source-commit",
            fixture.fixture.source_commit,
            "--expected-toolkit-source-tree",
            fixture.fixture.source_tree,
            "--policy",
            str(fixture.policy),
            "--expected-policy-sha256",
            fixture.policy_sha256,
            "--receipt",
            str(fixture.receipt),
            "--assessment",
            str(fixture.assessment),
            "--output",
            str(output),
        ]

    def test_prepare_and_verify_clis_are_deny_only(self) -> None:
        output = self.root / "worm-gate.zip"
        text = io.StringIO()
        with redirect_stdout(text):
            status = prepare_cli.main(self._prepare_argv(output))
        self.assertEqual(0, status, text.getvalue())
        self.assertIn("PHILLIP_V6_LIVE_CANARY_WORM_GATE_EVIDENCE_READY", text.getvalue())
        self.assertIn("Order capability: DISABLED", text.getvalue())
        self.assertIn("Broker mutation: NOT_PERFORMED", text.getvalue())

        text = io.StringIO()
        with redirect_stdout(text):
            status = verify_cli.main(
                [
                    "--archive",
                    str(output),
                    "--expected-policy-sha256",
                    self.fixture.policy_sha256,
                    "--observed-at-utc",
                    "2026-07-29T22:02:00.000000Z",
                    "--required-until-utc",
                    "2027-09-30T00:00:00.000000Z",
                ]
            )
        self.assertEqual(0, status, text.getvalue())
        self.assertIn("PHILLIP_V6_LIVE_CANARY_WORM_GATE_EVIDENCE_VERIFIED", text.getvalue())
        self.assertIn("Live allowed: false", text.getvalue())

    def test_wrong_pin_and_existing_output_fail_closed(self) -> None:
        output = self.root / "existing.zip"
        output.write_bytes(b"preserve")
        text = io.StringIO()
        with redirect_stdout(text):
            status = prepare_cli.main(self._prepare_argv(output))
        self.assertEqual(2, status)
        self.assertEqual(b"preserve", output.read_bytes())
        self.assertIn("Order capability: DISABLED", text.getvalue())

        valid, _result = self.fixture._build("valid-cli-source.zip")
        text = io.StringIO()
        with redirect_stdout(text):
            status = verify_cli.main(
                [
                    "--archive",
                    str(valid),
                    "--expected-policy-sha256",
                    "f" * 64,
                    "--observed-at-utc",
                    "2026-07-29T22:02:00.000000Z",
                    "--required-until-utc",
                    "2027-09-30T00:00:00.000000Z",
                ]
            )
        self.assertEqual(2, status)
        self.assertIn("Broker mutation: NOT_PERFORMED", text.getvalue())


if __name__ == "__main__":
    unittest.main()
