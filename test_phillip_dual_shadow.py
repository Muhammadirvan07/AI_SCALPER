from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from live_runtime.phillip_dual_shadow import (
    PhillipDualShadowError,
    build_child_commands,
    validate_dual_terminal_paths,
)
import run_phillip_dual_shadow as cli


FX = r"C:\Program Files\Phillip MT5 FX\terminal64.exe"
COMMODITY = r"C:\Program Files\Phillip MT5 Commodity\terminal64.exe"


class FakeProcess:
    def __init__(self, return_codes: list[int | None]) -> None:
        self.return_codes = list(return_codes)
        self.terminated = False
        self.waited = False

    def poll(self):
        if len(self.return_codes) > 1:
            return self.return_codes.pop(0)
        return self.return_codes[0]

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.waited = True
        return 0

    def kill(self):
        self.terminated = True


class PhillipDualShadowTests(unittest.TestCase):
    def test_paths_must_be_distinct_absolute_existing_terminals(self) -> None:
        self.assertEqual(
            (FX, COMMODITY),
            validate_dual_terminal_paths(
                FX,
                COMMODITY,
                path_is_file=lambda _path: True,
            ),
        )
        for fx, commodity, message in (
            (FX, FX.lower(), "different installation directories"),
            ("relative\\terminal64.exe", COMMODITY, "absolute Windows path"),
            (FX.replace("terminal64.exe", "other.exe"), COMMODITY, "terminal64.exe"),
        ):
            with self.subTest(fx=fx, commodity=commodity):
                with self.assertRaisesRegex(PhillipDualShadowError, message):
                    validate_dual_terminal_paths(
                        fx,
                        commodity,
                        path_is_file=lambda _path: True,
                    )
        with self.assertRaisesRegex(PhillipDualShadowError, "does not exist"):
            validate_dual_terminal_paths(
                FX,
                COMMODITY,
                path_is_file=lambda path: path != COMMODITY,
            )

    def test_child_commands_are_fixed_isolated_and_credential_free(self) -> None:
        commands = build_child_commands(
            python_executable=r"C:\AI_SCALPER\.venv\Scripts\python.exe",
            repo_root=Path(r"C:\AI_SCALPER"),
            fx_terminal_path=FX,
            commodity_terminal_path=COMMODITY,
            poll_seconds=5.0,
        )
        self.assertEqual(2, len(commands))
        rendered = " ".join(value for command in commands for value in command)
        self.assertIn("run_phillip_fx_shadow.py", rendered)
        self.assertIn("run_phillip_commodity_shadow.py", rendered)
        self.assertIn("--candidate phillip-fx", rendered)
        self.assertIn("--candidate phillip-commodity", rendered)
        self.assertIn("--acknowledge-diagnostic-only", rendered)
        self.assertIn("--continuous", rendered)
        for forbidden in ("--password", "--login", "order_send", "--server"):
            self.assertNotIn(forbidden, rendered)

    def test_validate_only_does_not_spawn_children(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = cli.main(
                [
                    "--fx-terminal-path",
                    FX,
                    "--commodity-terminal-path",
                    COMMODITY,
                    "--acknowledge-diagnostic-only",
                    "--validate-only",
                ],
                platform_name="Windows",
                path_is_file=lambda _path: True,
                process_factory=lambda *_args, **_kwargs: self.fail("must not spawn"),
            )
        self.assertEqual(0, result)
        self.assertIn("PHILLIP_DUAL_TERMINAL_VALID", output.getvalue())
        self.assertIn("Order capability: DISABLED", output.getvalue())

    def test_child_exit_terminates_peer_fail_closed(self) -> None:
        children = [FakeProcess([1]), FakeProcess([None])]
        created: list[FakeProcess] = []

        def factory(*_args, **kwargs):
            self.assertFalse(kwargs["shell"])
            child = children[len(created)]
            created.append(child)
            return child

        result = cli.main(
            [
                "--fx-terminal-path",
                FX,
                "--commodity-terminal-path",
                COMMODITY,
                "--acknowledge-diagnostic-only",
            ],
            platform_name="Windows",
            path_is_file=lambda _path: True,
            process_factory=factory,
            sleep=lambda _seconds: None,
        )
        self.assertEqual(2, result)
        self.assertTrue(children[1].terminated)

    def test_non_windows_and_credential_arguments_are_rejected(self) -> None:
        with self.assertRaisesRegex(PhillipDualShadowError, "Windows"):
            cli.main(
                [
                    "--fx-terminal-path",
                    FX,
                    "--commodity-terminal-path",
                    COMMODITY,
                    "--acknowledge-diagnostic-only",
                ],
                platform_name="Darwin",
                path_is_file=lambda _path: True,
            )
        stderr = io.StringIO()
        with (
            patch.object(sys, "argv", ["run_phillip_dual_shadow.py", "--password", "forbidden"]),
            redirect_stderr(stderr),
        ):
            with self.assertRaises(SystemExit) as raised:
                cli.main()
        self.assertEqual(2, raised.exception.code)


if __name__ == "__main__":
    unittest.main()
