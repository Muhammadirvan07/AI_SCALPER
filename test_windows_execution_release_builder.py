from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from build_windows_execution_release import (
    DEFAULT_ALLOWLIST,
    READINESS_BLOCKERS,
    REQUIRED_SAFETY,
    REQUIRED_USAGE_POLICY,
    ReleaseBuildError,
    _gated_content_policy,
    _read_execution_sources,
    _validate_dependency_lock_set,
    build_execution_release,
    load_execution_allowlist,
)
from live_runtime.signed_release_trust import (
    HMAC_RELEASE_TRUST_PRODUCTION_READY,
    PRODUCTION_RELEASE_TRUST_REQUIREMENT,
    SIGNED_RELEASE_TRUST_ENABLED,
)
from run_windows_gated_execution_service import (
    SERVICE_READINESS_BLOCKERS,
    main as service_main,
)
from build_windows_release import MANIFEST_MEMBER
from validate_windows_gated_execution_service import (
    main as validate_main,
    validate_gated_execution_ports,
)


ADAPTER_SOURCE = """class Adapter:
    def __init__(self, mt5):
        self.mt5 = mt5

    def check(self, request):
        return self.mt5.order_check(request)

    def send(self, request):
        return self.mt5.order_send(request)
"""


class WindowsExecutionReleaseBuilderTests(unittest.TestCase):
    def _git(self, root: Path, *args: str) -> None:
        subprocess.run(("git", *args), cwd=root, check=True, capture_output=True)

    def _repo(
        self,
        base: Path,
        *,
        adapter_source: str = ADAPTER_SOURCE,
        validator_source: str = "import helper\n",
        helper_source: str = "VALUE = 1\n",
        extra_files: dict[str, str] | None = None,
        include_helper: bool = True,
    ) -> tuple[Path, Path]:
        root = base / "repo"
        root.mkdir()
        (root / "config").mkdir()
        (root / "live_runtime").mkdir()
        (root / "live_runtime" / "mt5_adapter.py").write_text(
            adapter_source, encoding="utf-8"
        )
        (root / "live_runtime" / "production_bootstrap.py").write_text(
            "class ProductionRuntimeBootstrap:\n    pass\n", encoding="utf-8"
        )
        (root / "live_runtime" / "mt5_module_attestation.py").write_text(
            "VALUE = 1\n", encoding="utf-8"
        )
        (root / "live_runtime" / "demo_auto_ipc_consumer.py").write_text(
            "class DemoAutoDecisionIPCConsumer:\n    pass\n", encoding="utf-8"
        )
        (root / "live_runtime" / "signed_release_trust.py").write_text(
            "SIGNED_RELEASE_TRUST_ENABLED = False\n"
            "HMAC_RELEASE_TRUST_PRODUCTION_READY = False\n",
            encoding="utf-8",
        )
        (root / "validate_windows_gated_execution_service.py").write_text(
            validator_source, encoding="utf-8"
        )
        (root / "helper.py").write_text(helper_source, encoding="utf-8")
        (root / "requirements-live-windows.txt").write_text(
            "ExampleRuntime==1.0\n", encoding="utf-8"
        )
        (root / "requirements-windows-cp312.lock.txt").write_text(
            "exampleruntime==1.0 --hash=sha256:" + "a" * 64 + "\n",
            encoding="utf-8",
        )
        (root / "pylock.windows-cp312.toml").write_text(
            """lock-version = "1.0"
requires-python = ">=3.12"

[tool.ai_scalper]
target-python = "3.12"
target-implementation = "CPython"
target-platform = "win_amd64"
target-architecture = "x86_64"
source-manifests = ["requirements-live-windows.txt"]

[[packages]]
name = "exampleruntime"
version = "1.0"
""",
            encoding="utf-8",
        )
        files = [
            "config/windows_execution_service_allowlist.v1.json",
            "live_runtime/mt5_adapter.py",
            "live_runtime/demo_auto_ipc_consumer.py",
            "live_runtime/mt5_module_attestation.py",
            "live_runtime/production_bootstrap.py",
            "live_runtime/signed_release_trust.py",
            "pylock.windows-cp312.toml",
            "requirements-live-windows.txt",
            "requirements-windows-cp312.lock.txt",
            "validate_windows_gated_execution_service.py",
        ]
        if include_helper:
            files.append("helper.py")
        for relative, source in (extra_files or {}).items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
            files.append(relative)
        allowlist = {
            "schema_version": "ai-scalper-windows-execution-service-allowlist-v1",
            "release_profile": "TEST_GATED_EXECUTION",
            "safety": dict(REQUIRED_SAFETY),
            "usage_policy": dict(REQUIRED_USAGE_POLICY),
            "files": sorted(files),
        }
        allowlist_path = root / "config" / "windows_execution_service_allowlist.v1.json"
        allowlist_path.write_text(json.dumps(allowlist, indent=2) + "\n", encoding="utf-8")
        self._git(root, "init", "-q")
        self._git(root, "config", "user.name", "Execution Release Test")
        self._git(root, "config", "user.email", "release@example.invalid")
        self._git(root, "add", ".")
        self._git(root, "commit", "-qm", "fixture")
        return root, allowlist_path

    def test_archive_is_exact_deterministic_and_truthfully_blocked(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            first = base / "first.zip"
            second = base / "second.zip"
            first_result = build_execution_release(root, allowlist, first)
            second_result = build_execution_release(root, allowlist, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(
                first_result["release_identity_sha256"],
                second_result["release_identity_sha256"],
            )
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    {
                        MANIFEST_MEMBER,
                        "config/windows_execution_service_allowlist.v1.json",
                        "helper.py",
                        "live_runtime/demo_auto_ipc_consumer.py",
                        "live_runtime/mt5_adapter.py",
                        "live_runtime/mt5_module_attestation.py",
                        "live_runtime/production_bootstrap.py",
                        "live_runtime/signed_release_trust.py",
                        "pylock.windows-cp312.toml",
                        "requirements-live-windows.txt",
                        "requirements-windows-cp312.lock.txt",
                        "validate_windows_gated_execution_service.py",
                    },
                    set(archive.namelist()),
                )
                manifest = json.loads(archive.read(MANIFEST_MEMBER))
            self.assertEqual(REQUIRED_SAFETY, manifest["safety"])
            self.assertEqual(REQUIRED_USAGE_POLICY, manifest["usage_policy"])
            self.assertFalse(manifest["production_execution_ready"])
            self.assertEqual(list(READINESS_BLOCKERS), manifest["readiness_blockers"])
            self.assertEqual(
                "PRESENT_NON_EXECUTABLE_EXTERNAL_CONFIGURATION_REQUIRED",
                manifest["foundation_status"]["demo_auto_ipc_consumer"],
            )
            self.assertIn(
                "HMAC_LOCAL_TEST_ONLY",
                manifest["foundation_status"]["signed_release_trust"],
            )
            self.assertEqual(
                {
                    "direct_requirement_count": 1,
                    "lock_files": [
                        "pylock.windows-cp312.toml",
                        "requirements-live-windows.txt",
                        "requirements-windows-cp312.lock.txt",
                    ],
                    "resolved_package_count": 1,
                    "target_platform": "win_amd64",
                    "target_python": "3.12",
                },
                manifest["dependency_lock_summary"],
            )
            self.assertEqual(
                [
                    {
                        "count": 1,
                        "path": "live_runtime/mt5_adapter.py",
                        "primitive": "order_check",
                    },
                    {
                        "count": 1,
                        "path": "live_runtime/mt5_adapter.py",
                        "primitive": "order_send",
                    },
                ],
                manifest["order_primitive_inventory"],
            )

    def test_dirty_or_untracked_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            (root / "runtime_state.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseBuildError, "dirty"):
                build_execution_release(root, allowlist, base / "release.zip")

    def test_order_primitive_alias_outside_adapter_is_rejected(self):
        for source in (
            "sender = mt5.order_send\n",
            "from MetaTrader5 import order_send\n",
            "import MetaTrader5 as order_send\n",
            'sender = getattr(mt5, "order_send")\n',
            'sender = getattr(mt5, "order_" + "send")\n',
            'sender = vars(mt5)["order_check"]\n',
            'suffix = input()\nsender = getattr(mt5, "order_" + suffix)\n',
            'name = input()\nsender = vars(mt5)[name]\n',
            'sender = vars(mt5)["".join(("order_", "send"))]\n',
            'import MetaTrader5 as broker\nname = input()\nsender = getattr(broker, name)\n',
            'name = input()\nsender = mt5.__dict__[name]\n',
            'code = "mt5.order_send({})"\neval(code)\n',
            'import MetaTrader5 as terminal\nname = input()\nsender = getattr(terminal, name)\n',
            'broker = mt5\nname = input()\nsender = getattr(broker, name)\n',
            'def grab(module, name):\n    return getattr(module, name)\nsuffix = input()\nsender = grab(mt5, "order_" + suffix)\n',
            'def identity(value):\n    return value\nbroker_alias = identity(mt5)\nname = input()\nsender = getattr(broker_alias, name)\n',
            'def grab(module, name):\n    return vars(module)[name]\nname = input()\nsender = grab(mt5, name)\n',
            'name = input()\nsender = (lambda module, field: getattr(module, field))(mt5, name)\n',
            'class Box:\n    pass\nbox = Box()\nbox.module = mt5\nname = input()\nsender = getattr(box.module, name)\n',
            'holder = [None]\nholder[0] = mt5\nname = input()\nsender = getattr(holder[0], name)\n',
            'alias = mt5 if True else None\nname = input()\nsender = getattr(alias, name)\n',
            'alias = mt5 or None\nname = input()\nsender = getattr(alias, name)\n',
            'def source():\n    return mt5\nalias = source()\nname = input()\nsender = getattr(alias, name)\n',
            'def source(alias=mt5):\n    return alias\nname = input()\nsender = getattr(source(), name)\n',
            'alias = (lambda: mt5)()\nname = input()\nsender = getattr(alias, name)\n',
            'alias = next(x for x in (mt5,))\nname = input()\nsender = getattr(alias, name)\n',
            'class Holder:\n    module = staticmethod(lambda: mt5)\nname = input()\nsender = getattr(Holder.module(), name)\n',
            'import functools\nalias = functools.partial(lambda: mt5)()\nname = input()\nsender = getattr(alias, name)\n',
            'import sys\nmodule = sys.modules["Meta" + "Trader5"]\nname = input()\nsender = getattr(module, name)\n',
        ):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as raw:
                base = Path(raw)
                root, allowlist = self._repo(base, helper_source=source)
                with self.assertRaisesRegex(ReleaseBuildError, "outside reviewed adapter"):
                    build_execution_release(root, allowlist, base / "release.zip")

    def test_service_namespace_guard_exception_is_exact_and_cannot_recover_mt5(self):
        reviewed = (
            "import sys\n"
            "if module_name in sys.modules:\n"
            "    sys.modules.pop(module_name, None)\n"
        )
        self.assertEqual(
            {"order_check": 0, "order_send": 0},
            _gated_content_policy(
                "live_runtime/windows_service_entrypoint.py",
                reviewed.encode("utf-8"),
            ),
        )
        for source in (
            'import sys\nmodule = sys.modules["MetaTrader5"]\n',
            'import sys\nsys.modules.pop("MetaTrader5", None)\n',
            "import sys\nname = input()\nsys.modules.pop(name, None)\n",
        ):
            with self.subTest(source=source), self.assertRaisesRegex(
                ReleaseBuildError, "outside reviewed adapter"
            ):
                _gated_content_policy(
                    "live_runtime/windows_service_entrypoint.py",
                    source.encode("utf-8"),
                )

    def test_service_module_registry_audit_exception_is_helper_scoped(self):
        reviewed = (
            "import sys\n"
            "def _snapshot_module_registry():\n"
            "    return tuple(sys.modules.items())\n"
            "def _verify_module_registry_delta():\n"
            "    return tuple(sys.modules.items())\n"
        )
        self.assertEqual(
            {"order_check": 0, "order_send": 0},
            _gated_content_policy(
                "live_runtime/windows_service_entrypoint.py",
                reviewed.encode("utf-8"),
            ),
        )
        with self.assertRaisesRegex(ReleaseBuildError, "outside reviewed adapter"):
            _gated_content_policy(
                "live_runtime/windows_service_entrypoint.py",
                (
                    "import sys\n"
                    "def recover_cached_module():\n"
                    "    return tuple(sys.modules.items())\n"
                ).encode("utf-8"),
            )

    def test_service_loader_rejects_unreviewed_dynamic_import_shapes(self):
        for source in (
            "import importlib\ndef load(name):\n    return importlib.import_module(name)\n",
            "from importlib import import_module\ndef load(name):\n    return import_module(name)\n",
            "import importlib\ndef load(name):\n    return importlib._bootstrap._gcd_import(name)\n",
            "import importlib\ndef load(name):\n    return importlib.util.find_spec(name)\n",
        ):
            with self.subTest(source=source), self.assertRaisesRegex(
                ReleaseBuildError, "dynamic import bypass"
            ):
                _gated_content_policy(
                    "live_runtime/windows_service_entrypoint.py",
                    source.encode("utf-8"),
                )

    def test_every_candidate_factory_module_rejects_dynamic_import_shapes(self):
        for path_text in (
            "reviewed_windows_factory.py",
            "live_runtime/reviewed_windows_factory.py",
        ):
            for source in (
                "import importlib\ndef build(name):\n    return importlib.import_module(name)\n",
                "from importlib import import_module\ndef build(name):\n    return import_module(name)\n",
                "import importlib\ndef build(name):\n    return importlib.machinery.SourceFileLoader(name, 'x.py')\n",
                "import importlib\ndef build(name):\n    return importlib.util.spec_from_file_location(name, 'x.py')\n",
            ):
                with self.subTest(path=path_text, source=source), self.assertRaisesRegex(
                    ReleaseBuildError, "dynamic import bypass"
                ):
                    _gated_content_policy(path_text, source.encode("utf-8"))

    def test_service_loader_allows_only_exact_factory_file_loader(self):
        reviewed = (
            "import importlib.util\n"
            "def _load_exact_factory_module(module_name, factory_file):\n"
            "    spec = importlib.util.spec_from_file_location(module_name, factory_file)\n"
            "    return importlib.util.module_from_spec(spec)\n"
        )
        self.assertEqual(
            {"order_check": 0, "order_send": 0},
            _gated_content_policy(
                "live_runtime/windows_service_entrypoint.py",
                reviewed.encode("utf-8"),
            ),
        )

    def test_adapter_requires_exactly_one_direct_call_per_primitive(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = ADAPTER_SOURCE + "\ndef alias(self):\n    return self.mt5.order_send\n"
            root, allowlist = self._repo(base, adapter_source=source)
            with self.assertRaisesRegex(
                ReleaseBuildError, "exactly one direct|indirect or dynamic"
            ):
                build_execution_release(root, allowlist, base / "release.zip")

    def test_adapter_rejects_hidden_import_alias_source(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = ADAPTER_SOURCE + """
def hidden_module_source():
    import MetaTrader5 as module
    return module

def hidden_sender(name):
    alias = hidden_module_source()
    return getattr(alias, name)
"""
            root, allowlist = self._repo(base, adapter_source=source)
            with self.assertRaisesRegex(
                ReleaseBuildError, "indirect or dynamic"
            ):
                build_execution_release(root, allowlist, base / "release.zip")

    def test_adapter_import_is_allowed_only_in_attested_load_boundary(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = ADAPTER_SOURCE + """
def initialize(self):
    import MetaTrader5 as module
    self.mt5 = module
"""
            root, allowlist = self._repo(base, adapter_source=source)
            with self.assertRaisesRegex(
                ReleaseBuildError, "indirect or dynamic"
            ):
                build_execution_release(root, allowlist, base / "release.zip")

    def test_adapter_rejects_module_recovery_from_static_method_alias(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = ADAPTER_SOURCE + """
def hidden_sender(self, name):
    method = getattr(self.mt5, "copy_ticks_range")
    module = method.__self__
    return getattr(module, name)
"""
            root, allowlist = self._repo(base, adapter_source=source)
            with self.assertRaisesRegex(
                ReleaseBuildError, "indirect or dynamic"
            ):
                build_execution_release(root, allowlist, base / "release.zip")

    def test_paper_mql_bridge_runtime_and_secret_inputs_are_rejected(self):
        cases = {
            "paper_executor.py": "VALUE = 1\n",
            "mql5/AI_SCALPER.mq5": "CTrade trade;\n",
            "runtime_state/orders.json": "{}\n",
            "config/private.json": '{"api_key": "real-secret"}\n',
        }
        for index, (relative, source) in enumerate(cases.items()):
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as raw:
                base = Path(raw)
                root, allowlist = self._repo(
                    base,
                    extra_files={relative: source},
                )
                with self.assertRaises(ReleaseBuildError):
                    build_execution_release(root, allowlist, base / f"release-{index}.zip")

    def test_local_import_closure_is_exact(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base, include_helper=False)
            with self.assertRaisesRegex(ReleaseBuildError, "local import"):
                build_execution_release(root, allowlist, base / "release.zip")

    def test_dependency_lock_must_be_hash_pinned_and_exact(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            (root / "requirements-windows-cp312.lock.txt").write_text(
                "exampleruntime==1.0\n", encoding="utf-8"
            )
            self._git(root, "add", ".")
            self._git(root, "commit", "-qm", "drift dependency lock")
            with self.assertRaisesRegex(ReleaseBuildError, "hash pinned"):
                build_execution_release(root, allowlist, base / "release.zip")

    def test_project_allowlist_has_complete_import_closure_and_exact_primitives(self):
        allowlist = load_execution_allowlist(DEFAULT_ALLOWLIST)
        sources, inventory = _read_execution_sources(
            DEFAULT_ALLOWLIST.parents[1],
            allowlist["files"],
            set(allowlist["files"]),
        )
        self.assertEqual(set(allowlist["files"]), set(sources))
        self.assertEqual(
            ["order_check", "order_send"],
            [item["primitive"] for item in inventory],
        )
        dependency_summary = _validate_dependency_lock_set(sources)
        self.assertEqual(5, dependency_summary["direct_requirement_count"])
        self.assertEqual(14, dependency_summary["resolved_package_count"])

    def test_validator_is_deny_by_default_and_never_claims_readiness(self):
        report = validate_gated_execution_ports()
        self.assertEqual("PASS", report["port_validation"])
        self.assertFalse(report["production_execution_ready"])
        self.assertEqual(
            "PRESENT_BLOCKED_EXTERNAL_PROVIDERS", report["bootstrap_status"]
        )
        self.assertNotIn(
            "PRODUCTION_EXECUTOR_BOOTSTRAP_ABSENT", report["readiness_blockers"]
        )
        self.assertNotIn(
            "DEMO_AUTO_DECISION_IPC_CONSUMER_REQUIRED",
            report["readiness_blockers"],
        )
        self.assertIn(
            "EXTERNAL_DEMO_AUTO_IPC_CONFIGURATION_REQUIRED",
            report["readiness_blockers"],
        )
        self.assertIn(
            "DOWNSTREAM_DECISION_TO_INTENT_ONE_USE_JOURNAL_BINDING_REQUIRED",
            report["readiness_blockers"],
        )
        self.assertIn(
            PRODUCTION_RELEASE_TRUST_REQUIREMENT,
            report["readiness_blockers"],
        )
        self.assertIn(
            "EXTERNAL_SUPERVISOR_CHECKPOINT_REQUIRED",
            report["readiness_blockers"],
        )
        self.assertFalse(report["broker_mutation_performed"])
        self.assertEqual("GATED_PRESENT", report["safety"]["order_capability"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(3, validate_main([]))
            self.assertEqual(0, validate_main(["--allow-blocked-report"]))

    def test_service_is_hard_blocked_before_factory_load_by_nonproduction_hmac_trust(self):
        self.assertFalse(SIGNED_RELEASE_TRUST_ENABLED)
        self.assertFalse(HMAC_RELEASE_TRUST_PRODUCTION_READY)
        self.assertIn(PRODUCTION_RELEASE_TRUST_REQUIREMENT, SERVICE_READINESS_BLOCKERS)
        self.assertNotIn(
            "DEMO_AUTO_DECISION_IPC_CONSUMER_REQUIRED", SERVICE_READINESS_BLOCKERS
        )
        with patch(
            "run_windows_gated_execution_service.load_reviewed_windows_service_factory",
            side_effect=AssertionError("factory must not be loaded"),
        ), contextlib.redirect_stderr(io.StringIO()) as stderr:
            result = service_main(
                [
                    "--factory-manifest",
                    "unused.json",
                    "--expected-release-identity-sha256",
                    "a" * 64,
                ]
            )
        self.assertEqual(2, result)
        self.assertIn(PRODUCTION_RELEASE_TRUST_REQUIREMENT, stderr.getvalue())

    def test_validator_fails_closed_when_execution_policy_drifts(self):
        with patch("execution_policy.EXECUTION_MAX_LOT", 0.02):
            report = validate_gated_execution_ports()
        self.assertEqual("FAIL", report["port_validation"])
        self.assertIn(
            "execution_policy:EXECUTION_MAX_LOT_0_01",
            report["missing_ports"],
        )
        self.assertFalse(report["production_execution_ready"])

    def test_validator_reports_missing_foundation_instead_of_crashing(self):
        original_import = __import__(
            "validate_windows_gated_execution_service"
        ).importlib.import_module

        def controlled_import(name: str):
            if name == "live_runtime.demo_auto_ipc_consumer":
                raise ImportError("missing reviewed consumer")
            return original_import(name)

        with patch(
            "validate_windows_gated_execution_service.importlib.import_module",
            side_effect=controlled_import,
        ):
            report = validate_gated_execution_ports()
        self.assertEqual("FAIL", report["port_validation"])
        self.assertEqual("ABSENT", report["foundation_status"]["demo_auto_ipc_consumer"])
        self.assertIn(
            "live_runtime.demo_auto_ipc_consumer:IMPORT_ImportError",
            report["missing_ports"],
        )
        self.assertFalse(report["production_execution_ready"])


if __name__ == "__main__":
    unittest.main()
