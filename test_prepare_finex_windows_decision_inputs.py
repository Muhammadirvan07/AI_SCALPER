from __future__ import annotations

import base64
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import prepare_finex_windows_decision_inputs as target


def _public_key() -> str:
    algorithm = b"ssh-ed25519"
    key = bytes(range(32))
    blob = struct.pack(">I", len(algorithm)) + algorithm
    blob += struct.pack(">I", len(key)) + key
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii")


class PrepareFinexWindowsDecisionInputsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="finex-decision-input-v2-")
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.output = self.root / "output"
        self.discovery = self.root / "discovery.json"
        self.manifest = self.root / "release-suite-manifest.json"
        self.ssh_keygen = self.root / "ssh-keygen.exe"
        self.ssh_keygen.write_bytes(b"pinned synthetic ssh-keygen executable")
        self.ssh_sha256 = hashlib.sha256(self.ssh_keygen.read_bytes()).hexdigest()
        self.discovery.write_text(
            json.dumps(
                {
                    "candidate_id": "finex",
                    "account": {
                        "environment": "DEMO",
                        "server": "FinexBisnisSolusi-Demo",
                        "account_identity_sha256": "d" * 64,
                    },
                    "symbols": {
                        symbol: {"status": "READY_READ_ONLY"}
                        for symbol in ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")
                    },
                }
            ),
            encoding="utf-8",
        )
        self.manifest.write_text(
            json.dumps(
                {
                    "git_commit": "a" * 40,
                    "git_tree": "b" * 40,
                    "suite_identity_sha256": "c" * 64,
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _args(self, *extra: str):
        return target._parser().parse_args(
            [
                "--repo-root",
                str(Path(__file__).resolve().parent),
                "--discovery",
                str(self.discovery),
                "--base-suite-manifest",
                str(self.manifest),
                "--state-root",
                str(self.state),
                "--output-root",
                str(self.output),
                *extra,
            ]
        )

    def _v2_options(self) -> list[str]:
        return [
            "--provider-schema", "v2",
            "--clock-authority-public-key", _public_key(),
            "--clock-source-host-identity-sha256", "1" * 64,
            "--clock-consumer-host-identity-sha256", "2" * 64,
            "--ssh-keygen-path", str(self.ssh_keygen.resolve()),
            "--ssh-keygen-sha256", self.ssh_sha256,
            "--downstream-permit-key-fingerprint-sha256", "3" * 64,
        ]

    @staticmethod
    def _fingerprints(key_targets: dict[str, str] | None = None) -> dict[str, str]:
        assert key_targets is not None
        return {key_id: f"{index + 1:064x}" for index, key_id in enumerate(key_targets)}

    def test_v2_uses_only_operator_supplied_public_clock_pins(self) -> None:
        args = self._args(*self._v2_options())
        with patch.object(
            target, "_ensure_credentials", side_effect=self._fingerprints
        ) as ensure_credentials:
            result = target._prepare(args)

        expected_targets = {
            key_id: target_name
            for key_id, target_name in target.KEY_TARGETS.items()
            if key_id not in {
                "finex-trusted-clock-v1",
                "finex-downstream-permit-v1",
            }
        }
        expected_targets["finex-trusted-clock-continuity-v1"] = (
            "AI_SCALPER/FINEX/DECISION/finex-trusted-clock-continuity-v1"
        )
        ensure_credentials.assert_called_once_with(expected_targets)
        self.assertEqual(expected_targets, target.V2_KEY_TARGETS)
        self.assertTrue(
            all("/EXECUTION/" not in item for item in expected_targets.values())
        )

        pack_path = self.output / "decision-provider-pack-input.json"
        pack = json.loads(pack_path.read_text(encoding="utf-8"))
        self.assertEqual(target.PACK_SCHEMA_VERSION_V2, pack["schema_version"])
        self.assertEqual("finex-decision-provider-pack-v9", pack["pack_id"])
        self.assertEqual(_public_key(), pack["clock_binding"]["authority_public_key"])
        self.assertEqual(self.ssh_sha256, pack["clock_binding"]["ssh_keygen_sha256"])
        self.assertEqual("1" * 64, pack["clock_binding"]["source_host_identity_sha256"])
        self.assertEqual("2" * 64, pack["clock_binding"]["consumer_host_identity_sha256"])
        key_ids = {item["key_id"] for item in pack["credential_references"]}
        self.assertNotIn("finex-trusted-clock-v1", key_ids)
        self.assertIn("finex-trusted-clock-continuity-v1", key_ids)
        self.assertEqual(
            "3" * 64,
            pack["decision_ipc_binding"]["permit_key_fingerprint_sha256"],
        )
        self.assertIn("clock", pack["external_cas"])
        self.assertFalse(Path(pack["storage"]["clock_attestation_path"]).exists())
        self.assertTrue(Path(pack["external_cas"]["clock"]["request_directory"]).is_dir())
        self.assertTrue(Path(pack["external_cas"]["clock"]["response_directory"]).is_dir())
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["live_allowed"])
        self.assertFalse(result["safe_to_demo_auto_order"])
        self.assertEqual("DISABLED", result["order_capability"])

    def test_v2_rejects_missing_or_mismatched_operator_pin_before_credentials(self) -> None:
        complete = self._v2_options()
        cases = [complete[:-2], [*complete[:-1], "F" * 64]]
        for index, values in enumerate(cases):
            with self.subTest(index=index):
                with patch.object(target, "_ensure_credentials") as credentials:
                    with self.assertRaises(target.PreparationError):
                        target._prepare(self._args(*values))
                    credentials.assert_not_called()

    def test_explicit_v1_preserves_hmac_clock_credential_contract(self) -> None:
        with (
            patch.object(target, "_ensure_credentials", side_effect=self._fingerprints),
            patch.object(target, "_machine_identity_sha256", return_value="e" * 64),
        ):
            target._prepare(self._args("--provider-schema", "v1"))

        pack = json.loads(
            (self.output / "decision-provider-pack-input.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(target.PACK_SCHEMA_VERSION, pack["schema_version"])
        self.assertEqual(
            "finex-trusted-clock-v1",
            pack["clock_binding"]["authority_key_id"],
        )
        self.assertNotIn("clock", pack["external_cas"])
        key_ids = {item["key_id"] for item in pack["credential_references"]}
        self.assertIn("finex-trusted-clock-v1", key_ids)
        self.assertNotIn("finex-trusted-clock-continuity-v1", key_ids)

    def test_cleanup_preserves_concurrent_injection(self) -> None:
        original = target._write_exclusive
        calls = 0

        def inject_then_fail(path: Path, payload: bytes):
            nonlocal calls
            calls += 1
            if calls == 2:
                (self.output / "concurrent-owner.txt").write_text(
                    "KEEP", encoding="ascii"
                )
                raise target.PreparationError("SYNTHETIC_FAILURE")
            return original(path, payload)

        with (
            patch.object(target, "_ensure_credentials", side_effect=self._fingerprints),
            patch.object(target, "_write_exclusive", side_effect=inject_then_fail),
            self.assertRaises(target.PreparationError),
        ):
            target._prepare(self._args(*self._v2_options()))
        self.assertEqual(
            "KEEP",
            (self.output / "concurrent-owner.txt").read_text(encoding="ascii"),
        )
        self.assertFalse(
            (self.output / "finex-finalized-m15-data-contract.json").exists()
        )

    def test_cleanup_preserves_replacement_root(self) -> None:
        original = target._write_exclusive
        displaced = self.root / "displaced-original-output"
        calls = 0

        def replace_then_fail(path: Path, payload: bytes):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.output.rename(displaced)
                self.output.mkdir()
                (self.output / "replacement-owner.txt").write_text(
                    "KEEP", encoding="ascii"
                )
                raise target.PreparationError("SYNTHETIC_FAILURE")
            return original(path, payload)

        with (
            patch.object(target, "_ensure_credentials", side_effect=self._fingerprints),
            patch.object(target, "_write_exclusive", side_effect=replace_then_fail),
            self.assertRaises(target.PreparationError),
        ):
            target._prepare(self._args(*self._v2_options()))
        self.assertEqual(
            "KEEP",
            (self.output / "replacement-owner.txt").read_text(encoding="ascii"),
        )
        self.assertTrue(
            (displaced / "finex-finalized-m15-data-contract.json").is_file()
        )

    def test_v1_prepared_input_matches_frozen_v8_hash(self) -> None:
        historical_state = Path(
            r"C:\Users\muham\AI_SCALPER_PRIVATE\finex\decision-state-v1"
        )
        pins = {
            "discovery": "5a31ec0cc7bfc1ea9e6392c1b5e66741d8687e2b9fb8d512960670ec0a040e1d",
            "calendar": "5297b74972c6b54332268589cbd115823c4324e1c24a20c8b8504656b53b29a8",
            "model": "51524beb470eecf93f2df395b461692301fc39e7726af6cfca93835d910eda50",
            "config": "590e441bb68e8be1fb1a86e67d10475e3493767d3d980f9e1af3867551f56c8e",
        }
        fingerprints = {
            "finex-decision-cursor-v1": "9b16f7e120466f2091c915b580423478ec0371b67cdd9a5f23588a098da1609f",
            "finex-decision-feed-v1": "c662906cd3db3b92de7eae0b538886825ac1a29949a410a0e68ef936dc41b9da",
            "finex-decision-ipc-custody-v1": "106ff2bc1bf7cc405c44072aa4b893363c59f0e9d72d05ad9f1a3745962de3c0",
            "finex-decision-signing-v1": "d44dba4dcba84484d2f194c4ce4c51d32cf3f8576220df3b9a1a9cefc867ce5f",
            "finex-downstream-permit-v1": "9a765aa1d3a958e5a45bb5f42adac5813fdbdabd28bc27c91148917eaedbed1c",
            "finex-session-calendar-v1": "bd1711acd7cee56fec9b122cd2922e9c69abedb536ddcd5fbd40095ba6f8c11d",
            "finex-trusted-clock-v1": "05b2fa4e0e78b14e86bfc3bd2a02d0bccb03b191d836eb1d0dc647d0b11bb375",
        }
        self.discovery.write_text(
            json.dumps({
                "candidate_id": "finex",
                "account": {
                    "environment": "DEMO",
                    "server": "FinexBisnisSolusi-Demo",
                    "account_identity_sha256": "b5e8ac94118041cbd2a58ce14f67b5558fb453ff46dceb92bf62979140471859",
                },
                "symbols": {symbol: {} for symbol in target.REQUIRED_SYMBOLS},
            }),
            encoding="utf-8",
        )
        self.manifest.write_text(
            json.dumps({
                "git_commit": "09ddd3c303cae97a4f205b17ef52937df3fe08f6",
                "git_tree": "d70f7f8a8caa9f5493fe8dbbe4a983a07164d86f",
                "suite_identity_sha256": "e7cdfc0e2f316bf996500918b7ce7148225b3d6c28692dd934b62d00e309cc05",
            }),
            encoding="utf-8",
        )
        original_hash = target._sha256_file
        original_mkdir = Path.mkdir

        def historical_hash(path: Path) -> str:
            if path == self.discovery.resolve():
                return pins["discovery"]
            return {
                "finex_trading_rules_schedule.v1.json": pins["calendar"],
                "strategy_selector.py": pins["model"],
                "finex_demo_auto_readiness.v1.json": pins["config"],
            }.get(path.name, original_hash(path))

        def no_historical_state_write(path: Path, *args, **kwargs):
            if path == historical_state or historical_state in path.parents:
                return None
            return original_mkdir(path, *args, **kwargs)

        args = self._args(
            "--provider-schema", "v1",
            "--state-root", str(historical_state),
        )
        with (
            patch.object(target, "_ensure_credentials", return_value=fingerprints),
            patch.object(target, "_machine_identity_sha256", return_value="3e1b2f66097b605ac03bfca690480a920386f3d393a1aceda062cdd4c0b3a00e"),
            patch.object(target, "_sha256_file", side_effect=historical_hash),
            patch.object(Path, "mkdir", new=no_historical_state_write),
        ):
            target._prepare(args)
        actual = hashlib.sha256(
            (self.output / "decision-provider-pack-input.json").read_bytes()
        ).hexdigest()
        self.assertEqual(
            "1a7162af676bdf200334385a11345747d72ac51e4fae0d760a5d10138bb7b3fb",
            actual,
        )


if __name__ == "__main__":
    unittest.main()
