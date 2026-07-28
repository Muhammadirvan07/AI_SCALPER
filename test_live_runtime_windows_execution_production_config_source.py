from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

from live_runtime.model_governance import RULE_CORE_MODEL_SOURCE_PATHS
from live_runtime.production_bootstrap import ProductionRuntimeConfig
from live_runtime.rule_core_model_artifact import (
    build_archive_bytes as build_champion_archive_bytes,
    canonical_json_bytes as champion_json_bytes,
)
from live_runtime.stage_authorization import StageBinding
from live_runtime.windows_execution_production_config_source import (
    CONFIG_MEMBER,
    FIXED_ZIP_MODE,
    FIXED_ZIP_TIMESTAMP,
    MANIFEST_MEMBER,
    SAFETY,
    STAGE_MEMBER,
    WindowsExecutionProductionConfigSourceError,
    WindowsExecutionProductionConfigSourceVerification,
    canonical_source_file,
    prepare_windows_execution_production_config_source,
    verify_windows_execution_production_config_source,
)
from live_runtime.windows_execution_provider_pack import (
    WindowsExecutionProductionConfigSource,
    load_windows_execution_production_config_source,
)


UTC = timezone.utc
COMMIT = "a" * 40
TREE = "b" * 40
REGISTERED = datetime(2026, 7, 3, 0, 0, tzinfo=UTC)
START = datetime(2026, 7, 1, 0, 0, tzinfo=UTC)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def champion_fixture(
    *,
    commit: str = COMMIT,
    tree: str = TREE,
) -> tuple[bytes, dict[str, object]]:
    sources = {
        path: f"# frozen {path}\n".encode("utf-8")
        for path in RULE_CORE_MODEL_SOURCE_PATHS
    }
    candidate = champion_json_bytes(
        {
            "schema_version": "broker-candidate-plan-v1",
            "execution_enabled": False,
            "credentials_allowed": False,
            "candidates": [
                {
                    "candidate_id": "phillip-commodity",
                    "environment": "DEMO",
                    "binding_scope": "COMMODITY",
                    "account_currency": "JPY",
                    "server": "PhillipSecuritiesJP-PROD",
                    "read_only_discovery_allowed": True,
                    "broker_symbols_observed": {"XAUUSD": "XAUUSD.ps01"},
                }
            ],
        }
    )
    rows = ["Datetime,Close,High,Low,Open,Volume"]
    for index in range(96):
        observed = START + timedelta(minutes=15 * index)
        rows.append(
            f"{observed.isoformat()},2000.5,2001.0,1999.0,2000.0,{100 + index}"
        )
    snapshot = ("\n".join(rows) + "\n").encode("utf-8")
    return build_champion_archive_bytes(
        source_members=sources,
        config_bytes=candidate,
        snapshot_bytes=snapshot,
        branch="agent/live-grade-phase3",
        commit=commit,
        tree=tree,
        registered_at=REGISTERED,
    )


def stage_fixture(
    champion: dict[str, object],
    *,
    commit: str = COMMIT,
    tree: str = TREE,
) -> StageBinding:
    config_sha = str(champion["config_sha256"])
    return StageBinding(
        broker_id="phillip-commodity",
        account_alias_sha256=digest("reviewed-demo-account"),
        server="PhillipSecuritiesJP-PROD",
        environment="DEMO",
        symbol="XAUUSD",
        strategy="BREAKOUT",
        lane_id=f"XAUUSD:BREAKOUT:{config_sha}",
        journal_sha256=digest("journal"),
        commit_sha=commit,
        config_sha256=config_sha,
        dependency_lock_sha256=digest("dependency-lock"),
        broker_spec_sha256=digest("broker-spec"),
        session_calendar_sha256=digest("session-calendar"),
        evidence_contract_sha256=digest("evidence-contract"),
        broker_profile_sha256=digest("broker-profile"),
        runtime_profile_sha256=digest("runtime-profile"),
        model_artifact_sha256=str(champion["model_artifact_sha256"]),
        champion_archive_sha256=str(champion["archive_sha256"]),
        champion_package_identity_sha256=str(
            champion["package_identity_sha256"]
        ),
        champion_training_snapshot_sha256=str(
            champion["training_snapshot_sha256"]
        ),
        champion_git_tree=tree,
        champion_runtime_binding_sha256=str(
            champion["runtime_binding_sha256"]
        ),
        acceptance_authority_policy_sha256=digest("acceptance-policy"),
        manual_demo_custodian_trust_sha256=digest("manual-custodian"),
    )


def config_fixture(root: Path, stage: StageBinding) -> ProductionRuntimeConfig:
    return ProductionRuntimeConfig(
        journal_database=root / "execution.sqlite3",
        supervisor_database=root / "supervisor.sqlite3",
        dependency_lock_file=root / "pylock.windows-cp312.toml",
        account_alias_sha256=stage.account_alias_sha256,
        broker_legal_name="Phillip Securities Japan, Ltd.",
        server=stage.server,
        environment=stage.environment,
        account_currency="JPY",
        session_calendar_sha256=stage.session_calendar_sha256,
        symbol_map=((stage.symbol, "XAUUSD.ps01"),),
        journal_sha256=stage.journal_sha256,
        broker_spec_sha256=stage.broker_spec_sha256,
        commit_sha=stage.commit_sha,
        config_sha256=stage.config_sha256,
        stage_binding_sha256=stage.binding_sha256,
        champion_archive_sha256=stage.champion_archive_sha256,
        champion_package_identity_sha256=(
            stage.champion_package_identity_sha256
        ),
        champion_training_snapshot_sha256=(
            stage.champion_training_snapshot_sha256
        ),
        champion_git_tree=stage.champion_git_tree,
        champion_runtime_binding_sha256=(
            stage.champion_runtime_binding_sha256
        ),
        manual_demo_custodian_trust_sha256=(
            stage.manual_demo_custodian_trust_sha256
        ),
        news_guard_provider_id="signed-news-v1",
        news_guard_key_id="signed-news-key-v1",
        news_guard_ruleset_sha256=digest("news-rules"),
        news_guard_blackout_window_sha256=digest("news-window"),
        supervisor_key_id="supervisor-key-v1",
        supervisor_checkpoint_key_id="supervisor-checkpoint-key-v1",
        risk_ledger_id="risk-ledger-v1",
        risk_ledger_key_id="risk-ledger-key-v1",
        risk_ledger_key_fingerprint_sha256=digest("risk-key"),
        journal_checkpoint_key_id="journal-checkpoint-key-v1",
        journal_checkpoint_key_fingerprint_sha256=digest("journal-key"),
        news_guard_key_fingerprint_sha256=digest("news-key"),
        permit_secret_fingerprint_sha256=digest("permit-key"),
        dependency_lock_sha256=stage.dependency_lock_sha256,
        installed_environment_sha256=digest("installed-environment"),
        mt5_site_packages_sha256=digest("site-packages"),
        mt5_site_packages_tree_sha256=digest("site-packages-tree"),
        mt5_distribution_record_sha256=digest("distribution-record"),
        mt5_module_file_sha256=digest("module-file"),
        mt5_module_relative_path_sha256=digest("module-relative-path"),
    )


def stage_document(stage: StageBinding) -> dict[str, object]:
    return {
        "schema_version": "stage-readiness-authorization-v3",
        "binding": stage.to_canonical_dict(),
        "binding_sha256": stage.binding_sha256,
    }


def rewrite_archive(
    data: bytes,
    *,
    replacements: dict[str, bytes] | None = None,
    extra: tuple[str, bytes] | None = None,
    duplicate: tuple[str, bytes] | None = None,
    timestamp: tuple[int, int, int, int, int, int] = FIXED_ZIP_TIMESTAMP,
) -> bytes:
    replacements = replacements or {}
    with zipfile.ZipFile(io.BytesIO(data), "r") as original:
        members = {name: original.read(name) for name in original.namelist()}
    members.update(replacements)
    if extra is not None:
        members[extra[0]] = extra[1]
    destination = io.BytesIO()
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = FIXED_ZIP_MODE << 16
            archive.writestr(info, members[name])
        if duplicate is not None:
            info = zipfile.ZipInfo(duplicate[0], timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = FIXED_ZIP_MODE << 16
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(info, duplicate[1])
    return destination.getvalue()


class WindowsExecutionProductionConfigSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.champion_bytes, self.champion = champion_fixture()
        self.stage = stage_fixture(self.champion)
        self.config = config_fixture(self.root, self.stage)
        self.config_path = self.root / "production-config.json"
        self.stage_path = self.root / "stage.json"
        self.champion_path = self.root / "champion.zip"
        self.config_path.write_bytes(
            canonical_source_file(self.config.reviewed_configuration_payload)
        )
        self.stage_path.write_bytes(
            canonical_source_file(stage_document(self.stage))
        )
        self.champion_path.write_bytes(self.champion_bytes)

    def pins(self) -> dict[str, str]:
        return {
            "expected_champion_archive_sha256": str(
                self.champion["archive_sha256"]
            ),
            "expected_model_artifact_sha256": str(
                self.champion["model_artifact_sha256"]
            ),
            "expected_training_snapshot_sha256": str(
                self.champion["training_snapshot_sha256"]
            ),
            "expected_config_sha256": str(self.champion["config_sha256"]),
            "expected_git_commit": COMMIT,
            "expected_git_tree": TREE,
        }

    def prepare(self, output: Path):
        return prepare_windows_execution_production_config_source(
            production_config_path=self.config_path,
            stage_binding_path=self.stage_path,
            champion_artifact_path=self.champion_path,
            output=output,
            **self.pins(),
        )

    def test_deterministic_archive_seven_pins_and_deny_only_manifest(self):
        first = self.root / "first.zip"
        second = self.root / "second.zip"
        first_result = self.prepare(first)
        second_result = self.prepare(second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first_result.archive_sha256, second_result.archive_sha256)
        verified = verify_windows_execution_production_config_source(
            first,
            expected_source_archive_sha256=first_result.archive_sha256,
            **self.pins(),
        )
        self.assertEqual(first_result, verified)
        self.assertEqual(SAFETY, verified.safety)
        self.assertFalse(verified.provider_accepted)
        self.assertFalse(verified.production_execution_ready)
        self.assertEqual("DISABLED", verified.order_capability)
        with zipfile.ZipFile(first, "r") as archive:
            self.assertEqual(
                (
                    MANIFEST_MEMBER,
                    CONFIG_MEMBER,
                    "evidence/rule-core-champion-artifact.zip",
                    STAGE_MEMBER,
                ),
                tuple(archive.namelist()),
            )
            manifest = json.loads(archive.read(MANIFEST_MEMBER))
        self.assertEqual(SAFETY, manifest["safety"])
        self.assertEqual(3, len(manifest["members"]))

    def test_loader_returns_exact_sealed_runtime_source(self):
        output = self.root / "source.zip"
        prepared = self.prepare(output)
        loaded = load_windows_execution_production_config_source(
            output,
            expected_source_archive_sha256=prepared.archive_sha256,
            **self.pins(),
        )
        self.assertIs(type(loaded), WindowsExecutionProductionConfigSource)
        self.assertIs(type(loaded.config), ProductionRuntimeConfig)
        self.assertEqual(prepared.archive_sha256, loaded.source_sha256)
        self.assertEqual(
            self.config.safe_binding_sha256,
            loaded.config.safe_binding_sha256,
        )
        with self.assertRaisesRegex(TypeError, "seven-pin loader seal"):
            WindowsExecutionProductionConfigSource(
                config=self.config,
                source_sha256=prepared.archive_sha256,
            )
        with self.assertRaises(TypeError):
            WindowsExecutionProductionConfigSourceVerification(
                archive_path=output,
                archive_sha256="1" * 64,
                archive_size_bytes=1,
                source_identity_sha256="2" * 64,
                production_config_source_sha256="3" * 64,
                bootstrap_binding_sha256="4" * 64,
                stage_binding_sha256="5" * 64,
                champion_archive_sha256="6" * 64,
                champion_package_identity_sha256="7" * 64,
                champion_model_artifact_sha256="8" * 64,
                champion_training_snapshot_sha256="9" * 64,
                champion_config_sha256="a" * 64,
                champion_git_commit="b" * 40,
                champion_git_tree="c" * 40,
                champion_runtime_binding_sha256="d" * 64,
                production_config_bytes=b"{}\n",
                stage_binding_bytes=b"{}\n",
            )

    def test_cross_binding_mismatch_rejects_before_output(self):
        payload = json.loads(self.config_path.read_text("utf-8"))
        payload["server"] = "Other-Demo-Server"
        self.config_path.write_bytes(canonical_source_file(payload))
        output = self.root / "must-not-exist.zip"
        with self.assertRaisesRegex(
            WindowsExecutionProductionConfigSourceError,
            "SOURCE_CONFIG_STAGE_MISMATCH",
        ):
            self.prepare(output)
        self.assertFalse(output.exists())

    def test_noncanonical_duplicate_json_and_wrong_champion_pin_reject(self):
        cases = (
            b'{"schema_version":"windows-production-bootstrap-v2",'
            b'"schema_version":"windows-production-bootstrap-v2"}\n',
            b'{"a":NaN}\n',
            b'{}',
        )
        for index, data in enumerate(cases):
            with self.subTest(index=index):
                self.config_path.write_bytes(data)
                with self.assertRaises(WindowsExecutionProductionConfigSourceError):
                    self.prepare(self.root / f"invalid-{index}.zip")
        self.config_path.write_bytes(
            canonical_source_file(self.config.reviewed_configuration_payload)
        )
        pins = self.pins()
        pins["expected_champion_archive_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            WindowsExecutionProductionConfigSourceError,
            "SOURCE_EXTERNAL_PIN_INVALID",
        ):
            prepare_windows_execution_production_config_source(
                production_config_path=self.config_path,
                stage_binding_path=self.stage_path,
                champion_artifact_path=self.champion_path,
                output=self.root / "wrong-pin.zip",
                **pins,
            )

        original = self.config.reviewed_configuration_payload
        for field, value in (
            ("mt5_distribution_version", "5.0.5734"),
            ("mt5_wheel_sha256", "f" * 64),
        ):
            with self.subTest(field=field):
                payload = dict(original)
                payload[field] = value
                self.config_path.write_bytes(canonical_source_file(payload))
                target = self.root / f"invalid-{field}.zip"
                with self.assertRaisesRegex(
                    WindowsExecutionProductionConfigSourceError,
                    "SOURCE_PRODUCTION_CONFIG_INVALID",
                ):
                    self.prepare(target)
                self.assertFalse(target.exists())

    def test_existing_output_and_symlink_input_are_preserved(self):
        output = self.root / "existing.zip"
        output.write_bytes(b"preserve-me")
        with self.assertRaisesRegex(
            WindowsExecutionProductionConfigSourceError,
            "SOURCE_DESTINATION_INVALID",
        ):
            self.prepare(output)
        self.assertEqual(b"preserve-me", output.read_bytes())
        linked = self.root / "linked-config.json"
        try:
            linked.symlink_to(self.config_path)
        except OSError:
            self.skipTest("symlink creation is unavailable")
        with self.assertRaisesRegex(
            WindowsExecutionProductionConfigSourceError,
            "SOURCE_INPUT_INVALID",
        ):
            prepare_windows_execution_production_config_source(
                production_config_path=linked,
                stage_binding_path=self.stage_path,
                champion_artifact_path=self.champion_path,
                output=self.root / "linked.zip",
                **self.pins(),
            )

    def test_adversarial_outer_archive_rejects_even_with_updated_outer_pin(self):
        output = self.root / "valid.zip"
        self.prepare(output)
        original = output.read_bytes()
        with zipfile.ZipFile(io.BytesIO(original), "r") as archive:
            manifest = archive.read(MANIFEST_MEMBER)
        malformed_manifest = json.dumps(json.loads(manifest)).encode("utf-8")
        cases = {
            "trailing": original + b"trailer",
            "extra": rewrite_archive(original, extra=("extra.txt", b"x")),
            "traversal": rewrite_archive(
                original,
                extra=("../outside.txt", b"x"),
            ),
            "casefold": rewrite_archive(
                original,
                extra=(CONFIG_MEMBER.upper(), b"{}\n"),
            ),
            "duplicate": rewrite_archive(
                original,
                duplicate=(CONFIG_MEMBER, b"{}\n"),
            ),
            "timestamp": rewrite_archive(
                original,
                timestamp=(1980, 1, 2, 0, 0, 0),
            ),
            "manifest": rewrite_archive(
                original,
                replacements={MANIFEST_MEMBER: malformed_manifest},
            ),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                path = self.root / f"{name}.zip"
                path.write_bytes(data)
                with self.assertRaises(
                    WindowsExecutionProductionConfigSourceError
                ):
                    verify_windows_execution_production_config_source(
                        path,
                        expected_source_archive_sha256=hashlib.sha256(
                            data
                        ).hexdigest(),
                        **self.pins(),
                    )

    def test_isolated_cli_prepares_and_verifies_with_stable_output(self):
        repository = Path(__file__).resolve().parent
        output = self.root / "cli-source.zip"
        pin_flags = (
            "--expected-champion-archive-sha256",
            str(self.champion["archive_sha256"]),
            "--expected-model-artifact-sha256",
            str(self.champion["model_artifact_sha256"]),
            "--expected-training-snapshot-sha256",
            str(self.champion["training_snapshot_sha256"]),
            "--expected-config-sha256",
            str(self.champion["config_sha256"]),
            "--expected-git-commit",
            COMMIT,
            "--expected-git-tree",
            TREE,
        )
        prepared = subprocess.run(
            (
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(
                    repository
                    / "prepare_windows_execution_production_config_source.py"
                ),
                "--production-config",
                str(self.config_path),
                "--stage-binding",
                str(self.stage_path),
                "--champion-artifact",
                str(self.champion_path),
                *pin_flags,
                "--output",
                str(output),
            ),
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(0, prepared.returncode, prepared.stderr)
        self.assertIn(
            "WINDOWS_EXECUTION_PRODUCTION_CONFIG_SOURCE_READY",
            prepared.stdout,
        )
        archive_sha = hashlib.sha256(output.read_bytes()).hexdigest()
        verified = subprocess.run(
            (
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(
                    repository
                    / "verify_windows_execution_production_config_source.py"
                ),
                "--archive",
                str(output),
                "--expected-source-archive-sha256",
                archive_sha,
                *pin_flags,
            ),
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(0, verified.returncode, verified.stderr)
        self.assertIn(
            "WINDOWS_EXECUTION_PRODUCTION_CONFIG_SOURCE_VERIFIED",
            verified.stdout,
        )
        self.assertIn("Order capability: DISABLED", verified.stdout)


if __name__ == "__main__":
    unittest.main()
