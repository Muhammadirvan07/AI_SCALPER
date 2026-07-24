from __future__ import annotations

import hashlib
from importlib.machinery import ExtensionFileLoader, ModuleSpec, SourceFileLoader
from pathlib import Path
import tempfile
from types import ModuleType
import sys
import unittest
from unittest.mock import patch

from live_runtime.dependency_lock import MT5_WHEEL_SHA256
from live_runtime.mt5_module_attestation import (
    MT5ModuleAttestationError,
    VerifiedMT5Installation,
    VerifiedMT5ModuleAttestation,
    module_relative_path_sha256,
    require_clean_mt5_import_namespace,
    verify_imported_mt5_module,
    verify_mt5_installed_environment,
)
from live_runtime.mt5_adapter import MT5Adapter, MT5UnavailableError


def digest(value: str | bytes) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class MT5ModuleAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.site_packages = self.root / "Lib" / "site-packages"
        self.module_directory = self.site_packages / "MetaTrader5"
        self.module_directory.mkdir(parents=True)
        self.module_file = self.module_directory / "__init__.py"
        self.module_bytes = b"# exact locked MetaTrader5 test module\n"
        self.module_file.write_bytes(self.module_bytes)
        self.module_relative = "MetaTrader5/__init__.py"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def installed_receipt(self, **distribution_changes):
        distribution = {
            "name": "metatrader5",
            "version": "5.0.5735",
            "wheel_sha256": MT5_WHEEL_SHA256,
            "site_packages_tree_sha256": digest("mt5-wheel-tree"),
            "record_sha256": digest("mt5-record"),
            "hashed_file_count": 1,
            "generated_file_count": 0,
            "owned_site_files": (
                {
                    "path": self.module_relative,
                    "sha256": digest(self.module_bytes),
                    "size": len(self.module_bytes),
                },
            ),
        }
        distribution.update(distribution_changes)
        return {
            "lock_sha256": digest("dependency-lock"),
            "install_manifest_sha256": digest("install-manifest"),
            "installed_environment_sha256": digest("installed-environment"),
            "site_packages": str(self.site_packages.resolve()),
            "distribution_receipts": (distribution,),
        }

    def installation(self, **distribution_changes) -> VerifiedMT5Installation:
        with patch(
            "live_runtime.mt5_module_attestation.verify_installed_lock",
            return_value=self.installed_receipt(**distribution_changes),
        ):
            return verify_mt5_installed_environment(self.root / "pylock.toml")

    def imported_module(self, *, origin: Path | None = None) -> ModuleType:
        path = (origin or self.module_file).resolve()
        loader = SourceFileLoader("MetaTrader5", str(path))
        specification = ModuleSpec(
            "MetaTrader5", loader, origin=str(path), is_package=True
        )
        module = ModuleType("MetaTrader5")
        module.__package__ = "MetaTrader5"
        module.__version__ = "5.0.5735"
        module.__file__ = str(path)
        module.__loader__ = loader
        module.__spec__ = specification
        def initialize(**_kwargs):
            return True

        initialize.__module__ = "MetaTrader5"
        module.initialize = initialize
        module.ORDER_TYPE_BUY = 0
        return module

    @staticmethod
    def verify(module, installation, *, extra_registry=None):
        registry = {"MetaTrader5": module}
        registry.update(extra_registry or {})
        return verify_imported_mt5_module(
            module, installation, module_registry=registry
        )

    def test_pure_fixture_mints_exact_record_owned_module_attestation(self):
        installation = self.installation()
        attestation = self.verify(self.imported_module(), installation)
        self.assertIs(type(installation), VerifiedMT5Installation)
        self.assertIs(type(attestation), VerifiedMT5ModuleAttestation)
        self.assertEqual("5.0.5735", attestation.distribution_version)
        self.assertEqual(MT5_WHEEL_SHA256, attestation.wheel_sha256)
        self.assertEqual(self.module_relative, attestation.module_relative_path)
        self.assertEqual(digest(self.module_bytes), attestation.module_file_sha256)
        self.assertEqual(
            module_relative_path_sha256(self.module_relative),
            attestation.module_relative_path_sha256,
        )

    def test_attestation_contracts_cannot_be_constructed_directly(self):
        fields = {
            "dependency_lock_sha256": digest("lock"),
            "install_manifest_sha256": digest("manifest"),
            "installed_environment_sha256": digest("environment"),
            "site_packages_sha256": digest("site"),
            "distribution_name": "metatrader5",
            "distribution_version": "5.0.5735",
            "wheel_sha256": MT5_WHEEL_SHA256,
            "site_packages_tree_sha256": digest("tree"),
            "record_sha256": digest("record"),
            "owned_site_files": (),
            "_site_packages": self.site_packages,
        }
        with self.assertRaises(TypeError):
            VerifiedMT5Installation(**fields)

    def test_wrong_type_name_package_version_and_spec_fail_closed(self):
        installation = self.installation()
        cases = []
        cases.append((object(), "TYPE"))

        wrong_name = self.imported_module()
        wrong_name.__name__ = "attacker"
        cases.append((wrong_name, "NAME"))

        wrong_package = self.imported_module()
        wrong_package.__package__ = "attacker"
        cases.append((wrong_package, "PACKAGE"))

        wrong_version = self.imported_module()
        wrong_version.__version__ = "5.0.9999"
        cases.append((wrong_version, "VERSION"))

        wrong_spec = self.imported_module()
        wrong_spec.__spec__ = None
        cases.append((wrong_spec, "SPEC"))

        for candidate, reason in cases:
            with self.subTest(reason=reason), self.assertRaises(
                MT5ModuleAttestationError
            ):
                self.verify(candidate, installation)

    def test_origin_must_be_record_owned_regular_non_reparse_file(self):
        installation = self.installation()
        outside = self.root / "attacker.py"
        outside.write_bytes(self.module_bytes)
        with self.assertRaisesRegex(
            MT5ModuleAttestationError, "ESCAPED_SITE_PACKAGES"
        ):
            self.verify(self.imported_module(origin=outside), installation)

        unowned = self.module_directory / "attacker.py"
        unowned.write_bytes(self.module_bytes)
        with self.assertRaisesRegex(MT5ModuleAttestationError, "NOT_OWNED"):
            self.verify(self.imported_module(origin=unowned), installation)

        link = self.module_directory / "linked.py"
        try:
            link.symlink_to(self.module_file)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        module = self.imported_module()
        lexical_link = link.parent.resolve() / link.name
        loader = SourceFileLoader("MetaTrader5", str(lexical_link))
        module.__file__ = str(lexical_link)
        module.__loader__ = loader
        module.__spec__ = ModuleSpec(
            "MetaTrader5", loader, origin=str(lexical_link), is_package=True
        )
        with self.assertRaisesRegex(MT5ModuleAttestationError, "REPARSE_POINT"):
            self.verify(module, installation)

    def test_record_hash_tamper_is_rejected(self):
        installation = self.installation()
        module = self.imported_module()
        self.module_file.write_bytes(b"tampered after installed-lock verification")
        with self.assertRaisesRegex(MT5ModuleAttestationError, "RECORD_HASH"):
            self.verify(module, installation)

    def test_valid_top_level_cannot_hide_forged_preloaded_native_submodule(self):
        installation = self.installation()
        top_level = self.imported_module()
        forged_file = self.root / "forged_core.py"
        forged_file.write_bytes(b"def initialize(): return True\n")
        loader = SourceFileLoader("MetaTrader5._core", str(forged_file.resolve()))
        forged = ModuleType("MetaTrader5._core")
        forged.__package__ = "MetaTrader5"
        forged.__file__ = str(forged_file.resolve())
        forged.__loader__ = loader
        forged.__spec__ = ModuleSpec(
            "MetaTrader5._core",
            loader,
            origin=str(forged_file.resolve()),
        )
        forged.initialize = lambda: True
        registry = {
            "MetaTrader5": top_level,
            "MetaTrader5._core": forged,
        }
        with self.assertRaisesRegex(
            MT5ModuleAttestationError, "IMPORT_NAMESPACE_PRELOADED"
        ):
            require_clean_mt5_import_namespace(registry)
        with self.assertRaisesRegex(
            MT5ModuleAttestationError, "ESCAPED_SITE_PACKAGES"
        ):
            verify_imported_mt5_module(
                top_level, installation, module_registry=registry
            )

    def test_record_owned_native_extension_and_reexported_callable_are_sealed(self):
        core_file = self.module_directory / "_core.cp312-win_amd64.pyd"
        core_bytes = b"test-only native extension fixture"
        core_file.write_bytes(core_bytes)
        owned = (
            {
                "path": self.module_relative,
                "sha256": digest(self.module_bytes),
                "size": len(self.module_bytes),
            },
            {
                "path": "MetaTrader5/_core.cp312-win_amd64.pyd",
                "sha256": digest(core_bytes),
                "size": len(core_bytes),
            },
        )
        installation = self.installation(owned_site_files=owned)
        top_level = self.imported_module()
        core_loader = ExtensionFileLoader(
            "MetaTrader5._core", str(core_file.resolve())
        )
        core = ModuleType("MetaTrader5._core")
        core.__package__ = "MetaTrader5"
        core.__file__ = str(core_file.resolve())
        core.__loader__ = core_loader
        core.__spec__ = ModuleSpec(
            "MetaTrader5._core",
            core_loader,
            origin=str(core_file.resolve()),
        )

        def initialize():
            return True

        initialize.__module__ = "MetaTrader5._core"
        core.initialize = initialize
        top_level.initialize = initialize
        registry = {"MetaTrader5": top_level, "MetaTrader5._core": core}
        attestation = verify_imported_mt5_module(
            top_level, installation, module_registry=registry
        )
        self.assertEqual(
            ("MetaTrader5", "MetaTrader5._core"),
            tuple(item.module_name for item in attestation.namespace_modules),
        )

        core.initialize = lambda: True
        top_level.initialize = core.initialize
        changed = verify_imported_mt5_module(
            top_level, installation, module_registry=registry
        )
        self.assertNotEqual(attestation.content_sha256, changed.content_sha256)

    def test_public_callable_or_constant_monkeypatch_changes_sealed_surface(self):
        installation = self.installation()
        module = self.imported_module()
        original = self.verify(module, installation)
        module.initialize = lambda **_kwargs: True
        changed = self.verify(module, installation)
        self.assertNotEqual(
            original.public_runtime_surface_sha256,
            changed.public_runtime_surface_sha256,
        )
        self.assertNotEqual(original.content_sha256, changed.content_sha256)
        before_constant = changed
        module.ORDER_TYPE_BUY = 99
        changed_constant = self.verify(module, installation)
        self.assertNotEqual(
            before_constant.public_runtime_surface_sha256,
            changed_constant.public_runtime_surface_sha256,
        )

    def adapter(self, installation, **changes):
        values = {
            "account_alias": "reviewed-demo-account",
            "broker_legal_name": "Reviewed Broker Ltd.",
            "expected_login": 123456,
            "expected_server": "Reviewed-Demo-Server",
            "environment": "DEMO",
            "session_calendar_sha256": digest("calendar"),
            "symbol_map": {"EURUSD": "EURUSD.demo"},
            "mt5_installation": installation,
            "expected_installed_environment_sha256": (
                installation.installed_environment_sha256
            ),
            "expected_module_file_sha256": digest(self.module_bytes),
            "expected_module_relative_path_sha256": (
                module_relative_path_sha256(self.module_relative)
            ),
        }
        values.update(changes)
        return MT5Adapter(**values)

    def test_verified_adapter_forbids_injected_module_even_if_it_looks_valid(self):
        installation = self.installation()
        with self.assertRaisesRegex(MT5UnavailableError, "injection is forbidden"):
            self.adapter(installation, mt5_module=self.imported_module())

    def test_adapter_import_attests_before_broker_initialize_and_rechecks_file(self):
        installation = self.installation()
        module = self.imported_module()
        calls = []
        module.initialize = lambda **_kwargs: calls.append("initialize") or True
        adapter = self.adapter(installation)
        real_import = __import__

        def official_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "MetaTrader5":
                sys.modules["MetaTrader5"] = module
                return module
            return real_import(name, globals, locals, fromlist, level)

        with patch.dict(sys.modules, {}, clear=False), patch(
            "builtins.__import__", side_effect=official_import
        ):
            sys.modules.pop("MetaTrader5", None)
            attestation = adapter.load_and_attest_module()
            self.assertIs(type(attestation), VerifiedMT5ModuleAttestation)
            self.assertEqual([], calls)
            self.module_file.write_bytes(b"changed after module import")
            with self.assertRaisesRegex(MT5ModuleAttestationError, "RECORD_HASH"):
                adapter.verify_module_attestation()
            sys.modules.pop("MetaTrader5", None)

    def test_installed_receipt_requires_exact_version_wheel_and_record_files(self):
        for changes, reason in (
            ({"version": "5.0.9999"}, "VERSION"),
            ({"wheel_sha256": digest("attacker-wheel")}, "WHEEL"),
            ({"owned_site_files": ()}, "owned site files"),
        ):
            with self.subTest(reason=reason), self.assertRaises(
                (MT5ModuleAttestationError, TypeError, ValueError)
            ):
                self.installation(**changes)


if __name__ == "__main__":
    unittest.main()
