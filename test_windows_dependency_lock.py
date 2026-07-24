from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import tomllib
import unittest
from unittest import mock

from build_windows_dependency_sbom import (
    build_dependency_sbom,
    canonical_sbom_bytes,
)
from live_runtime.dependency_lock import (
    BOOTSTRAP_REQUIREMENTS_FILE,
    BOOTSTRAP_REQUIREMENTS,
    DEPENDENCY_SBOM,
    DependencyLockError,
    INSTALL_MANIFEST,
    LIVE_REQUIREMENTS_FILE,
    MT5_WHEEL_SHA256,
    PIP_VENDOR_WHEEL,
    PIP_VENDOR_WHEEL_SHA256,
    RUNTIME_REQUIREMENTS_FILE,
    TA_VENDOR_WHEEL,
    TA_VENDOR_WHEEL_SHA256,
    prepare_isolated_venv_install,
    require_safe_dependency_verification_runtime,
    require_current_windows_runtime,
    seal_dependency_console_scripts,
    validate_release_wheelhouse,
    validate_windows_dependency_lock,
    verify_installed_lock,
)
from live_runtime.evidence_bootstrap import (
    CONFIG_FILES,
    DEPENDENCY_FILES,
    PROFILE_FILES,
    EvidenceBootstrapError,
    build_ruleset,
)


class _FakeDistribution:
    def __init__(
        self,
        *,
        name: str,
        version: str,
        site_packages: Path,
        record_path: Path,
    ) -> None:
        self.metadata = {"Name": name}
        self.version = version
        self._site_packages = site_packages
        self._record_path = record_path

    def read_text(self, filename: str) -> str | None:
        if filename != "RECORD":
            return None
        return self._record_path.read_text(encoding="utf-8")

    def locate_file(self, path: str) -> Path:
        return self._site_packages / path


class WindowsDependencyLockTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path.cwd()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.lock = self.root / "pylock.windows-cp312.toml"
        shutil.copy2(self.repo / "pylock.windows-cp312.toml", self.lock)
        wheel = self.root / TA_VENDOR_WHEEL
        wheel.parent.mkdir(parents=True)
        shutil.copy2(self.repo / TA_VENDOR_WHEEL, wheel)
        pip_wheel = self.root / PIP_VENDOR_WHEEL
        pip_wheel.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.repo / PIP_VENDOR_WHEEL, pip_wheel)
        for relative in (
            LIVE_REQUIREMENTS_FILE,
            BOOTSTRAP_REQUIREMENTS_FILE,
            RUNTIME_REQUIREMENTS_FILE,
        ):
            shutil.copy2(self.repo / relative, self.root / relative)
        manifest = self.root / INSTALL_MANIFEST
        manifest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.repo / INSTALL_MANIFEST, manifest)
        shutil.copy2(self.repo / DEPENDENCY_SBOM, self.root / DEPENDENCY_SBOM)
        self._installed_manifest: dict[str, object] | None = None

    def _replace(self, old: str, new: str) -> None:
        text = self.lock.read_text(encoding="utf-8")
        self.assertIn(old, text)
        self.lock.write_text(text.replace(old, new, 1), encoding="utf-8")

    def _rewrite_manifest(self, mutate) -> None:
        manifest_path = self.root / INSTALL_MANIFEST
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        mutate(payload)
        body = {
            key: value
            for key, value in payload.items()
            if key != "payload_sha256"
        }
        payload["payload_sha256"] = hashlib.sha256(
            json.dumps(
                body,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        raw = (
            json.dumps(
                payload,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        manifest_path.write_bytes(raw)
        lock_payload = tomllib.loads(self.lock.read_text(encoding="utf-8"))
        old_binding = lock_payload["tool"]["ai_scalper"]["install-manifest"]
        old = (
            f'install-manifest = {{ path = "{INSTALL_MANIFEST}", '
            f"size = {old_binding['size']}, hashes = {{ sha256 = "
            f"\"{old_binding['hashes']['sha256']}\" }} }}"
        )
        new = (
            f'install-manifest = {{ path = "{INSTALL_MANIFEST}", '
            f"size = {len(raw)}, hashes = {{ sha256 = "
            f"\"{hashlib.sha256(raw).hexdigest()}\" }} }}"
        )
        self._replace(old, new)

    def _rewrite_sbom(self, mutate, *, canonical: bool = True) -> None:
        sbom_path = self.root / DEPENDENCY_SBOM
        payload = json.loads(sbom_path.read_text(encoding="utf-8"))
        mutate(payload)
        if canonical:
            raw = canonical_sbom_bytes(payload)
        else:
            raw = json.dumps(
                payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        sbom_path.write_bytes(raw)
        lock_payload = tomllib.loads(self.lock.read_text(encoding="utf-8"))
        old_binding = lock_payload["tool"]["ai_scalper"]["dependency-sbom"]
        old = (
            f'dependency-sbom = {{ path = "{DEPENDENCY_SBOM}", '
            f"size = {old_binding['size']}, hashes = {{ sha256 = "
            f"\"{old_binding['hashes']['sha256']}\" }} }}"
        )
        new = (
            f'dependency-sbom = {{ path = "{DEPENDENCY_SBOM}", '
            f"size = {len(raw)}, hashes = {{ sha256 = "
            f"\"{hashlib.sha256(raw).hexdigest()}\" }} }}"
        )
        self._replace(old, new)

    @staticmethod
    def _record_digest(data: bytes) -> str:
        return (
            "sha256="
            + base64.urlsafe_b64encode(hashlib.sha256(data).digest())
            .rstrip(b"=")
            .decode("ascii")
        )

    def _fake_distribution(
        self,
        *,
        name: str,
        version: str,
        site_packages: Path,
    ) -> tuple[_FakeDistribution, Path, Path]:
        slug = name.lower().replace("-", "_").replace(".", "_")
        package_file = site_packages / slug / "payload.bin"
        package_file.parent.mkdir(parents=True, exist_ok=True)
        package_data = f"{name}=={version}".encode("utf-8")
        package_file.write_bytes(package_data)

        dist_info = site_packages / f"{slug}-{version}.dist-info"
        dist_info.mkdir(parents=True, exist_ok=True)
        metadata_file = dist_info / "METADATA"
        metadata_data = (
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
        ).encode("utf-8")
        metadata_file.write_bytes(metadata_data)
        installer_file = dist_info / "INSTALLER"
        installer_data = b"pip\n"
        installer_file.write_bytes(installer_data)
        requested_file = dist_info / "REQUESTED"
        requested_data = b""
        requested_file.write_bytes(requested_data)
        record_file = dist_info / "RECORD"
        stream = io.StringIO()
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(
            (
                package_file.relative_to(site_packages).as_posix(),
                self._record_digest(package_data),
                str(len(package_data)),
            )
        )
        writer.writerow(
            (
                metadata_file.relative_to(site_packages).as_posix(),
                self._record_digest(metadata_data),
                str(len(metadata_data)),
            )
        )
        writer.writerow(
            (
                installer_file.relative_to(site_packages).as_posix(),
                self._record_digest(installer_data),
                str(len(installer_data)),
            )
        )
        writer.writerow(
            (
                requested_file.relative_to(site_packages).as_posix(),
                self._record_digest(requested_data),
                str(len(requested_data)),
            )
        )
        writer.writerow((record_file.relative_to(site_packages).as_posix(), "", ""))
        record_file.write_text(stream.getvalue(), encoding="utf-8")
        return (
            _FakeDistribution(
                name=name,
                version=version,
                site_packages=site_packages,
                record_path=record_file,
            ),
            package_file,
            record_file,
        )

    def _fake_installed_environment(
        self,
    ) -> tuple[list[_FakeDistribution], dict[str, Path], dict[str, Path], Path]:
        environment_root = self.root / "installed-venv"
        if environment_root.exists():
            shutil.rmtree(environment_root)
        site_packages = environment_root / "Lib" / "site-packages"
        site_packages.mkdir(parents=True, exist_ok=True)
        (environment_root / "pyvenv.cfg").write_text(
            "home = C:\\Python312\n"
            "include-system-site-packages = false\n"
            "version = 3.12.10\n"
            "executable = C:\\Python312\\python.exe\n"
            "command = C:\\Python312\\python.exe -m venv "
            "--without-pip C:\\AI_SCALPER\\.venv-release\n",
            encoding="utf-8",
        )
        scripts = environment_root / "Scripts"
        scripts.mkdir(exist_ok=True)
        for filename in (
            "activate",
            "activate.bat",
            "Activate.ps1",
            "deactivate.bat",
            "python.exe",
            "pythonw.exe",
        ):
            (scripts / filename).write_bytes(
                ("synthetic-venv-core:" + filename).encode("utf-8")
            )
        payload = tomllib.loads(self.lock.read_text(encoding="utf-8"))
        requirements = {
            str(package["name"]): str(package["version"])
            for package in payload["packages"]
        } | BOOTSTRAP_REQUIREMENTS
        distributions: list[_FakeDistribution] = []
        package_files: dict[str, Path] = {}
        record_files: dict[str, Path] = {}
        for name, version in sorted(requirements.items()):
            distribution, package_file, record_file = self._fake_distribution(
                name=name,
                version=version,
                site_packages=site_packages,
            )
            distributions.append(distribution)
            package_files[name] = package_file
            record_files[name] = record_file
        manifest_packages: dict[str, dict[str, object]] = {}
        for distribution in distributions:
            name = str(distribution.metadata["Name"]).lower().replace("_", "-")
            rows = list(
                csv.reader(
                    io.StringIO(
                        distribution.read_text("RECORD") or ""
                    ),
                    strict=True,
                )
            )
            site_files: list[dict[str, object]] = []
            record_path = ""
            for recorded_path, hash_value, size_value in rows:
                if recorded_path.endswith(".dist-info/RECORD"):
                    record_path = recorded_path
                    continue
                if PurePosixPath(recorded_path).name in {
                    "INSTALLER",
                    "REQUESTED",
                }:
                    continue
                encoded = hash_value.removeprefix("sha256=")
                padded = encoded + ("=" * ((4 - len(encoded) % 4) % 4))
                site_files.append(
                    {
                        "path": recorded_path,
                        "sha256": base64.urlsafe_b64decode(padded).hex(),
                        "size": int(size_value),
                    }
                )
            site_files.sort(key=lambda entry: str(entry["path"]))
            manifest_packages[name] = {
                "name": name,
                "version": distribution.version,
                "wheel_filename": f"{name}-{distribution.version}-py3-none-any.whl",
                "wheel_size": 1,
                "wheel_sha256": "0" * 64,
                "record_path": record_path,
                "wheel_record_sha256": "1" * 64,
                "site_packages_file_count": len(site_files),
                "site_packages_tree_sha256": hashlib.sha256(
                    json.dumps(
                        site_files,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("utf-8")
                ).hexdigest(),
                "console_scripts": [],
            }
        self._installed_manifest = {
            "schema_version": "windows-wheel-tree-v1",
            "target": {
                "python": "3.12",
                "implementation": "CPython",
                "platform": "win_amd64",
                "architecture": "x86_64",
            },
            "packages": manifest_packages,
            "payload_sha256": "2" * 64,
            "manifest_sha256": "3" * 64,
        }
        return distributions, package_files, record_files, environment_root

    def _verify_fake_environment(
        self,
        distributions: list[_FakeDistribution],
        environment_root: Path,
    ) -> dict[str, object]:
        self.assertIsNotNone(self._installed_manifest)
        lock_receipt = validate_windows_dependency_lock(self.lock)
        with (
            mock.patch(
                "live_runtime.dependency_lock.validate_windows_dependency_lock",
                return_value=lock_receipt,
            ),
            mock.patch(
                "live_runtime.dependency_lock.metadata.distributions",
                return_value=iter(distributions),
            ),
            mock.patch(
                "live_runtime.dependency_lock._active_environment_paths",
                return_value=(
                    environment_root.resolve(),
                    (environment_root / "Lib" / "site-packages").resolve(),
                ),
            ),
            mock.patch(
                "live_runtime.dependency_lock._load_install_manifest",
                return_value=self._installed_manifest,
            ),
            mock.patch(
                "live_runtime.dependency_lock.require_safe_dependency_verification_runtime",
            ),
        ):
            return verify_installed_lock(self.lock)

    def _add_fake_console_script(
        self,
        *,
        record_files: dict[str, Path],
        environment_root: Path,
        package_name: str,
        script_name: str,
    ) -> Path:
        script = environment_root / "Scripts" / f"{script_name}.exe"
        script_data = b"mutable-windows-console-wrapper"
        script.write_bytes(script_data)
        record = record_files[package_name]
        rows = list(
            csv.reader(io.StringIO(record.read_text(encoding="utf-8")), strict=True)
        )
        rows.insert(
            -1,
            [
                f"../../Scripts/{script.name}",
                self._record_digest(script_data),
                str(len(script_data)),
            ],
        )
        stream = io.StringIO()
        csv.writer(stream, lineterminator="\n").writerows(rows)
        record.write_text(stream.getvalue(), encoding="utf-8")
        self.assertIsNotNone(self._installed_manifest)
        manifest_packages = self._installed_manifest["packages"]
        self.assertIsInstance(manifest_packages, dict)
        manifest_packages[package_name]["console_scripts"] = [script_name]
        return script

    def test_release_lock_binds_target_direct_pins_and_mt5_wheel(self):
        receipt = validate_windows_dependency_lock(self.lock)
        self.assertEqual(14, receipt["package_count"])
        self.assertEqual("3.12", receipt["target_python"])
        self.assertEqual("win_amd64", receipt["target_platform"])
        self.assertEqual("5.0.5735", receipt["metatrader5_version"])
        self.assertEqual(MT5_WHEEL_SHA256, receipt["metatrader5_wheel_sha256"])
        self.assertEqual(TA_VENDOR_WHEEL_SHA256, receipt["ta_wheel_sha256"])
        self.assertEqual(PIP_VENDOR_WHEEL_SHA256, receipt["pip_wheel_sha256"])
        self.assertRegex(str(receipt["source_manifest_sha256"]), r"^[0-9a-f]{64}$")
        self.assertRegex(str(receipt["install_manifest_sha256"]), r"^[0-9a-f]{64}$")
        self.assertEqual(DEPENDENCY_SBOM, receipt["dependency_sbom_file"])
        self.assertEqual(15, receipt["dependency_sbom_package_count"])
        self.assertRegex(
            str(receipt["dependency_sbom_sha256"]),
            r"^[0-9a-f]{64}$",
        )
        self.assertRegex(
            str(receipt["dependency_sbom_components_sha256"]),
            r"^[0-9a-f]{64}$",
        )

    def test_dependency_sbom_is_exact_deterministic_lock_inventory(self):
        committed = (self.root / DEPENDENCY_SBOM).read_bytes()
        first = canonical_sbom_bytes(build_dependency_sbom(self.lock))
        second = canonical_sbom_bytes(build_dependency_sbom(self.lock))
        self.assertEqual(committed, first)
        self.assertEqual(first, second)
        payload = json.loads(first)
        self.assertNotIn("serialNumber", payload)
        self.assertNotIn("timestamp", payload.get("metadata", {}))
        self.assertEqual(
            [
                "jaraco-classes",
                "jaraco-context",
                "jaraco-functools",
                "keyring",
                "metatrader5",
                "more-itertools",
                "numpy",
                "pandas",
                "pip",
                "python-dateutil",
                "pytz",
                "pywin32-ctypes",
                "six",
                "ta",
                "tzdata",
            ],
            [component["name"] for component in payload["components"]],
        )
        for component in payload["components"]:
            self.assertEqual(component["bom-ref"], component["purl"])
            self.assertTrue(component["purl"].startswith("pkg:pypi/"))
            self.assertRegex(
                component["hashes"][0]["content"],
                r"^[0-9a-f]{64}$",
            )

    def test_dependency_sbom_missing_tampered_or_semantically_rewritten_is_rejected(self):
        sbom_path = self.root / DEPENDENCY_SBOM
        sbom_path.unlink()
        with self.assertRaisesRegex(DependencyLockError, "dependency SBOM is unavailable"):
            validate_windows_dependency_lock(self.lock)

        shutil.copy2(self.repo / DEPENDENCY_SBOM, sbom_path)
        sbom_path.write_bytes(sbom_path.read_bytes() + b" ")
        with self.assertRaisesRegex(DependencyLockError, "dependency SBOM size drift"):
            validate_windows_dependency_lock(self.lock)

        shutil.copy2(self.repo / DEPENDENCY_SBOM, sbom_path)
        self._rewrite_sbom(
            lambda payload: payload["components"][0].update(
                {"version": "3.4.0-rewritten"}
            )
        )
        with self.assertRaisesRegex(DependencyLockError, "semantic drift"):
            validate_windows_dependency_lock(self.lock)

    def test_dependency_sbom_noncanonical_encoding_is_rejected_even_when_rebound(self):
        self._rewrite_sbom(lambda payload: None, canonical=False)
        with self.assertRaisesRegex(
            DependencyLockError,
            "canonical encoding drift",
        ):
            validate_windows_dependency_lock(self.lock)

    def test_live_manifest_cannot_inherit_or_add_development_dependencies(self):
        manifest = self.root / LIVE_REQUIREMENTS_FILE
        manifest.write_text(
            manifest.read_text(encoding="utf-8")
            + "\nyfinance==0.2.66\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            DependencyLockError,
            r"live dependency source manifest drift",
        ):
            validate_windows_dependency_lock(self.lock)

    def test_locked_package_set_cannot_reintroduce_yfinance(self):
        self._replace(
            'name = "jaraco-classes"',
            'name = "yfinance"',
        )
        with self.assertRaisesRegex(
            DependencyLockError,
            r"locked dependency set drift",
        ):
            validate_windows_dependency_lock(self.lock)

    def test_install_manifest_is_content_addressed_and_tamper_evident(self):
        manifest = self.root / INSTALL_MANIFEST
        manifest.write_bytes(manifest.read_bytes() + b" ")
        with self.assertRaisesRegex(
            DependencyLockError,
            r"install manifest (?:size|SHA-256) drift",
        ):
            validate_windows_dependency_lock(self.lock)

    def test_hashed_install_requirements_must_match_the_selected_wheels(self):
        requirements = self.root / RUNTIME_REQUIREMENTS_FILE
        requirements.write_text(
            requirements.read_text(encoding="utf-8").replace(
                PIP_VENDOR_WHEEL_SHA256[:16],
                "0" * 16,
            )
            + "# drift\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            DependencyLockError,
            r"hashed requirements file drift",
        ):
            validate_windows_dependency_lock(self.lock)

    def test_manifest_must_bind_each_package_to_its_exact_selected_wheel(self):
        lock_payload = tomllib.loads(self.lock.read_text(encoding="utf-8"))
        numpy_package = next(
            package
            for package in lock_payload["packages"]
            if package["name"] == "numpy"
        )
        wrong_wheel = numpy_package["wheels"][0]

        def mutate(payload):
            entry = payload["packages"]["pandas"]
            entry["wheel_filename"] = PurePosixPath(
                wrong_wheel["url"]
            ).name
            entry["wheel_size"] = wrong_wheel["size"]
            entry["wheel_sha256"] = wrong_wheel["hashes"]["sha256"]

        self._rewrite_manifest(mutate)
        with self.assertRaisesRegex(
            DependencyLockError,
            r"install manifest wheel binding drift: pandas",
        ):
            validate_windows_dependency_lock(self.lock)

    def test_target_or_direct_pin_drift_is_rejected(self):
        self._replace('target-platform = "win_amd64"', 'target-platform = "any"')
        with self.assertRaisesRegex(DependencyLockError, "target drift"):
            validate_windows_dependency_lock(self.lock)
        shutil.copy2(self.repo / "pylock.windows-cp312.toml", self.lock)
        self._replace(
            'name = "numpy"\nversion = "2.5.1"',
            'name = "numpy"\nversion = "2.5.0"',
        )
        with self.assertRaisesRegex(DependencyLockError, "direct dependency pin drift"):
            validate_windows_dependency_lock(self.lock)

    def test_mt5_artifact_or_any_artifact_hash_drift_is_rejected(self):
        self._replace(MT5_WHEEL_SHA256, "0" * 64)
        with self.assertRaisesRegex(DependencyLockError, "MetaTrader5 wheel SHA-256"):
            validate_windows_dependency_lock(self.lock)
        shutil.copy2(self.repo / "pylock.windows-cp312.toml", self.lock)
        self._replace(
            "47a024b51d0239c0dd8c8540c6c7f484be3b8fcf0b2d85c13825780d3b3f3acd",
            "not-a-sha256",
        )
        with self.assertRaisesRegex(DependencyLockError, "artifact SHA-256"):
            validate_windows_dependency_lock(self.lock)

    def test_every_release_dependency_requires_a_locked_wheel(self):
        text = self.lock.read_text(encoding="utf-8")
        start = text.index('[[packages]]\nname = "jaraco-classes"')
        end = text.index("\n\n[[packages]]", start)
        block = text[start:end]
        without_wheel = "\n".join(
            line for line in block.splitlines()
            if not line.startswith("wheels =")
        )
        self.lock.write_text(
            text[:start] + without_wheel + text[end:],
            encoding="utf-8",
        )
        with self.assertRaisesRegex(DependencyLockError, "no locked wheel"):
            validate_windows_dependency_lock(self.lock)

    def test_vendored_ta_wheel_is_required_and_content_addressed(self):
        wheel = self.root / TA_VENDOR_WHEEL
        wheel.write_bytes(wheel.read_bytes() + b"tamper")
        with self.assertRaisesRegex(
            DependencyLockError,
            "local artifact (?:size|SHA-256) drift",
        ):
            validate_windows_dependency_lock(self.lock)
        shutil.copy2(self.repo / TA_VENDOR_WHEEL, wheel)
        self._replace(
            f'path = "{TA_VENDOR_WHEEL}"',
            'path = "vendor/wheels/unreviewed.whl"',
        )
        with self.assertRaisesRegex(DependencyLockError, "unapproved local artifact"):
            validate_windows_dependency_lock(self.lock)

    def test_vendored_pip_bootstrap_is_required_and_content_addressed(self):
        wheel = self.root / PIP_VENDOR_WHEEL
        wheel.write_bytes(wheel.read_bytes() + b"tamper")
        with self.assertRaisesRegex(
            DependencyLockError,
            r"local artifact (?:size|SHA-256) drift: pip",
        ):
            validate_windows_dependency_lock(self.lock)
        shutil.copy2(self.repo / PIP_VENDOR_WHEEL, wheel)
        self._replace(
            f'path = "{PIP_VENDOR_WHEEL}"',
            (
                'url = "https://files.pythonhosted.org/packages/unreviewed/'
                'pip-26.1.2-py3-none-any.whl"'
            ),
        )
        with self.assertRaisesRegex(DependencyLockError, "pip bootstrap wheel drift"):
            validate_windows_dependency_lock(self.lock)

    def test_runtime_guard_requires_64_bit_windows_cpython_312(self):
        require_current_windows_runtime(
            platform_name="win32",
            machine="AMD64",
            python_version=(3, 12),
            python_implementation="CPython",
            pointer_bits=64,
        )
        invalid = (
            {"platform_name": "darwin"},
            {"machine": "arm64"},
            {"python_version": (3, 13)},
            {"python_implementation": "PyPy"},
            {"pointer_bits": 32},
        )
        defaults = {
            "platform_name": "win32",
            "machine": "AMD64",
            "python_version": (3, 12),
            "python_implementation": "CPython",
            "pointer_bits": 64,
        }
        for override in invalid:
            with self.subTest(override=override):
                with self.assertRaises(DependencyLockError):
                    require_current_windows_runtime(**(defaults | override))

    def test_installed_guard_requires_no_site_and_no_bytecode_startup(self):
        require_safe_dependency_verification_runtime(
            isolated=True,
            no_site=True,
            dont_write_bytecode=True,
        )
        with self.assertRaisesRegex(DependencyLockError, r"python -I"):
            require_safe_dependency_verification_runtime(
                isolated=False,
                no_site=True,
                dont_write_bytecode=True,
            )
        with self.assertRaisesRegex(DependencyLockError, r"python -S"):
            require_safe_dependency_verification_runtime(
                isolated=True,
                no_site=False,
                dont_write_bytecode=True,
            )
        with self.assertRaisesRegex(DependencyLockError, r"python -B"):
            require_safe_dependency_verification_runtime(
                isolated=True,
                no_site=True,
                dont_write_bytecode=False,
            )

    def test_isolated_venv_prefix_is_restored_without_importing_site(self):
        environment_root = self.root / "release-venv"
        site_packages = environment_root / "Lib" / "site-packages"
        site_packages.mkdir(parents=True)
        original_prefix = __import__("sys").prefix
        original_exec_prefix = __import__("sys").exec_prefix
        try:
            with (
                mock.patch(
                    "live_runtime.dependency_lock.require_safe_dependency_verification_runtime",
                ),
                mock.patch(
                    "live_runtime.dependency_lock._active_environment_paths",
                    return_value=(environment_root, site_packages),
                ),
            ):
                self.assertEqual(
                    str(environment_root),
                    prepare_isolated_venv_install(),
                )
                self.assertEqual(str(environment_root), __import__("sys").prefix)
                self.assertEqual(
                    str(environment_root),
                    __import__("sys").exec_prefix,
                )
        finally:
            __import__("sys").prefix = original_prefix
            __import__("sys").exec_prefix = original_exec_prefix

    def test_installed_environment_requires_exact_set_and_verified_record_files(self):
        distributions, _, _, environment_root = self._fake_installed_environment()
        receipt = self._verify_fake_environment(distributions, environment_root)
        self.assertEqual(14, receipt["locked_package_count"])
        self.assertEqual(15, receipt["installed_distribution_count"])
        self.assertEqual(60, receipt["hashed_file_count"])
        self.assertEqual(30, receipt["generated_file_count"])
        self.assertEqual(75, receipt["site_packages_file_count"])
        self.assertEqual(6, receipt["scripts_file_count"])
        self.assertEqual(82, receipt["environment_file_count"])
        self.assertRegex(str(receipt["pyvenv_sha256"]), r"^[0-9a-f]{64}$")
        self.assertEqual(
            str((environment_root / "Lib" / "site-packages").resolve()),
            receipt["site_packages"],
        )
        self.assertRegex(
            str(receipt["installed_environment_sha256"]),
            r"^[0-9a-f]{64}$",
        )

    def test_installed_record_detects_content_and_size_tampering(self):
        distributions, package_files, _, environment_root = (
            self._fake_installed_environment()
        )
        pandas_file = package_files["pandas"]
        original = pandas_file.read_bytes()
        pandas_file.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        with self.assertRaisesRegex(
            DependencyLockError,
            r"RECORD hash mismatch: pandas:",
        ):
            self._verify_fake_environment(distributions, environment_root)

        pandas_file.write_bytes(original + b"x")
        with self.assertRaisesRegex(
            DependencyLockError,
            r"RECORD size mismatch: pandas:",
        ):
            self._verify_fake_environment(distributions, environment_root)

    def test_rewritten_payload_and_record_cannot_replace_the_locked_wheel_tree(self):
        distributions, package_files, record_files, environment_root = (
            self._fake_installed_environment()
        )
        pandas_file = package_files["pandas"]
        replacement = b"pandas==2.3.4"
        self.assertEqual(len(pandas_file.read_bytes()), len(replacement))
        pandas_file.write_bytes(replacement)
        rows = list(
            csv.reader(
                io.StringIO(record_files["pandas"].read_text(encoding="utf-8")),
                strict=True,
            )
        )
        rows[0][1] = self._record_digest(replacement)
        rows[0][2] = str(len(replacement))
        stream = io.StringIO()
        csv.writer(stream, lineterminator="\n").writerows(rows)
        record_files["pandas"].write_text(stream.getvalue(), encoding="utf-8")
        with self.assertRaisesRegex(
            DependencyLockError,
            r"wheel-tree manifest mismatch: pandas",
        ):
            self._verify_fake_environment(distributions, environment_root)

    def test_unowned_startup_and_executable_site_files_are_rejected(self):
        for relative in (
            "sitecustomize.py",
            "rogue-startup.pth",
            "rogue_extension.pyd",
        ):
            with self.subTest(relative=relative):
                distributions, _, _, environment_root = (
                    self._fake_installed_environment()
                )
                path = environment_root / "Lib" / "site-packages" / relative
                path.write_bytes(b"raise SystemExit('unowned')\n")
                with self.assertRaisesRegex(
                    DependencyLockError,
                    r"(?:forbidden|unowned) site-packages file",
                ):
                    self._verify_fake_environment(distributions, environment_root)

    def test_unowned_venv_root_file_and_system_site_enablement_are_rejected(self):
        distributions, _, _, environment_root = self._fake_installed_environment()
        (environment_root / "rogue-runtime.dll").write_bytes(b"unowned")
        with self.assertRaisesRegex(
            DependencyLockError,
            r"venv file inventory mismatch",
        ):
            self._verify_fake_environment(distributions, environment_root)

        distributions, _, _, environment_root = self._fake_installed_environment()
        configuration = environment_root / "pyvenv.cfg"
        configuration.write_text(
            configuration.read_text(encoding="utf-8").replace(
                "include-system-site-packages = false",
                "include-system-site-packages = true",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            DependencyLockError,
            r"must disable system site-packages",
        ):
            self._verify_fake_environment(distributions, environment_root)

    def test_blank_hash_bytecode_record_entry_is_rejected(self):
        distributions, _, record_files, environment_root = (
            self._fake_installed_environment()
        )
        site_packages = environment_root / "Lib" / "site-packages"
        bytecode_path = site_packages / "pandas" / "__pycache__" / "payload.pyc"
        bytecode_path.parent.mkdir(parents=True)
        bytecode_path.write_bytes(b"untrusted bytecode")
        record = record_files["pandas"]
        rows = list(
            csv.reader(io.StringIO(record.read_text(encoding="utf-8")), strict=True)
        )
        rows.insert(
            -1,
            [
                bytecode_path.relative_to(site_packages).as_posix(),
                "",
                "",
            ],
        )
        stream = io.StringIO()
        csv.writer(stream, lineterminator="\n").writerows(rows)
        record.write_text(stream.getvalue(), encoding="utf-8")
        with self.assertRaisesRegex(
            DependencyLockError,
            r"bytecode is forbidden",
        ):
            self._verify_fake_environment(distributions, environment_root)

    def test_console_wrapper_and_record_rewrite_is_rejected_until_sealed(self):
        distributions, _, record_files, environment_root = (
            self._fake_installed_environment()
        )
        script = self._add_fake_console_script(
            record_files=record_files,
            environment_root=environment_root,
            package_name="pandas",
            script_name="pandas-tool",
        )
        replacement = b"rewritten-windows-console-wrap"
        script.write_bytes(replacement)
        rows = list(
            csv.reader(
                io.StringIO(record_files["pandas"].read_text(encoding="utf-8")),
                strict=True,
            )
        )
        script_row = next(row for row in rows if row[0].endswith(script.name))
        script_row[1] = self._record_digest(replacement)
        script_row[2] = str(len(replacement))
        stream = io.StringIO()
        csv.writer(stream, lineterminator="\n").writerows(rows)
        record_files["pandas"].write_text(stream.getvalue(), encoding="utf-8")
        with self.assertRaisesRegex(
            DependencyLockError,
            r"console scripts are not sealed",
        ):
            self._verify_fake_environment(distributions, environment_root)

    def test_sealing_removes_console_wrappers_and_record_rows(self):
        distributions, _, record_files, environment_root = (
            self._fake_installed_environment()
        )
        script = self._add_fake_console_script(
            record_files=record_files,
            environment_root=environment_root,
            package_name="pandas",
            script_name="pandas-tool",
        )
        self.assertIsNotNone(self._installed_manifest)
        lock_receipt = validate_windows_dependency_lock(self.lock)
        with (
            mock.patch(
                "live_runtime.dependency_lock.validate_windows_dependency_lock",
                return_value=lock_receipt,
            ),
            mock.patch(
                "live_runtime.dependency_lock.metadata.distributions",
                return_value=iter(distributions),
            ),
            mock.patch(
                "live_runtime.dependency_lock._active_environment_paths",
                return_value=(
                    environment_root.resolve(),
                    (environment_root / "Lib" / "site-packages").resolve(),
                ),
            ),
            mock.patch(
                "live_runtime.dependency_lock._load_install_manifest",
                return_value=self._installed_manifest,
            ),
            mock.patch(
                "live_runtime.dependency_lock.require_safe_dependency_verification_runtime",
            ),
        ):
            receipt = seal_dependency_console_scripts(self.lock)
        self.assertEqual(1, receipt["rewritten_record_count"])
        self.assertEqual(1, receipt["removed_record_row_count"])
        self.assertEqual(1, receipt["removed_console_script_count"])
        self.assertFalse(script.exists())
        self.assertNotIn(
            "Scripts/",
            record_files["pandas"].read_text(encoding="utf-8"),
        )
        verified = self._verify_fake_environment(distributions, environment_root)
        self.assertRegex(
            str(verified["installed_environment_sha256"]),
            r"^[0-9a-f]{64}$",
        )

    def test_release_wheelhouse_requires_the_exact_flat_selected_set(self):
        wheelhouse = self.root / "wheelhouse"
        wheelhouse.mkdir()
        pip_bytes = b"locked-pip-wheel"
        runtime_bytes = b"locked-runtime-wheel"
        (wheelhouse / "pip-26.1.2-py3-none-any.whl").write_bytes(pip_bytes)
        (wheelhouse / "runtime-1.0-py3-none-any.whl").write_bytes(runtime_bytes)
        manifest = {
            "manifest_sha256": "a" * 64,
            "packages": {
                "pip": {
                    "wheel_filename": "pip-26.1.2-py3-none-any.whl",
                    "wheel_size": len(pip_bytes),
                    "wheel_sha256": hashlib.sha256(pip_bytes).hexdigest(),
                },
                "runtime": {
                    "wheel_filename": "runtime-1.0-py3-none-any.whl",
                    "wheel_size": len(runtime_bytes),
                    "wheel_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
                },
            },
        }
        with (
            mock.patch(
                "live_runtime.dependency_lock.validate_windows_dependency_lock",
                return_value={"lock_sha256": "b" * 64},
            ),
            mock.patch(
                "live_runtime.dependency_lock._load_install_manifest",
                return_value=manifest,
            ),
        ):
            receipt = validate_release_wheelhouse(self.lock, wheelhouse)
            self.assertEqual(2, receipt["wheel_count"])
            self.assertEqual(
                str(wheelhouse.resolve() / "pip-26.1.2-py3-none-any.whl"),
                receipt["pip_wheel"],
            )
            (wheelhouse / "unexpected.whl").write_bytes(b"unexpected")
            with self.assertRaisesRegex(
                DependencyLockError,
                "unexpected file",
            ):
                validate_release_wheelhouse(self.lock, wheelhouse)

    def test_forbidden_record_signature_metadata_is_rejected(self):
        distributions, _, record_files, environment_root = (
            self._fake_installed_environment()
        )
        site_packages = environment_root / "Lib" / "site-packages"
        signature = (
            site_packages
            / "pandas-2.3.3.dist-info"
            / "RECORD.jws"
        )
        signature_data = b"untrusted-record-signature"
        signature.write_bytes(signature_data)
        rows = list(
            csv.reader(
                io.StringIO(record_files["pandas"].read_text(encoding="utf-8")),
                strict=True,
            )
        )
        rows.insert(
            -1,
            [
                signature.relative_to(site_packages).as_posix(),
                self._record_digest(signature_data),
                str(len(signature_data)),
            ],
        )
        stream = io.StringIO()
        csv.writer(stream, lineterminator="\n").writerows(rows)
        record_files["pandas"].write_text(stream.getvalue(), encoding="utf-8")
        with self.assertRaisesRegex(
            DependencyLockError,
            "generated metadata is forbidden",
        ):
            self._verify_fake_environment(distributions, environment_root)

    def test_missing_or_malformed_installed_record_is_rejected(self):
        distributions, _, record_files, environment_root = (
            self._fake_installed_environment()
        )
        record_files["metatrader5"].unlink()
        with self.assertRaisesRegex(
            DependencyLockError,
            r"wheel RECORD is unreadable: metatrader5",
        ):
            self._verify_fake_environment(distributions, environment_root)

        distributions, _, record_files, environment_root = (
            self._fake_installed_environment()
        )
        record_files["metatrader5"].write_text(
            "metatrader5/payload.bin,sha256=not-base64,10\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            DependencyLockError,
            r"RECORD SHA-256 is malformed: metatrader5:",
        ):
            self._verify_fake_environment(distributions, environment_root)

    def test_unexpected_distribution_or_bootstrap_version_drift_is_rejected(self):
        distributions, _, _, environment_root = self._fake_installed_environment()
        site_packages = environment_root / "Lib" / "site-packages"
        unexpected, _, _ = self._fake_distribution(
            name="setuptools",
            version="80.0.0",
            site_packages=site_packages,
        )
        with self.assertRaisesRegex(
            DependencyLockError,
            r"unexpected=setuptools",
        ):
            self._verify_fake_environment(
                distributions + [unexpected],
                environment_root,
            )

        pip_distribution = next(
            distribution
            for distribution in distributions
            if distribution.metadata["Name"] == "pip"
        )
        pip_distribution.version = "26.1.1"
        with self.assertRaisesRegex(
            DependencyLockError,
            r"pip=26.1.1 \(expected 26.1.2\)",
        ):
            self._verify_fake_environment(distributions, environment_root)

    def test_ruleset_hashes_the_validated_lock_and_rejects_invalid_lock(self):
        work_repo = self.root / "repo"
        for relative in set(CONFIG_FILES + DEPENDENCY_FILES + PROFILE_FILES):
            destination = work_repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.repo / relative, destination)
        first = build_ruleset(work_repo)["dependency_lock_sha256"]
        path = work_repo / "pylock.windows-cp312.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                'resolver = "uv 0.11.29"',
                'resolver = "uv 0.11.29 reviewed"',
                1,
            ),
            encoding="utf-8",
        )
        second = build_ruleset(work_repo)["dependency_lock_sha256"]
        self.assertNotEqual(first, second)
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                MT5_WHEEL_SHA256,
                "0" * 64,
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            EvidenceBootstrapError,
            "dependency lock validation failed",
        ):
            build_ruleset(work_repo)


if __name__ == "__main__":
    unittest.main()
