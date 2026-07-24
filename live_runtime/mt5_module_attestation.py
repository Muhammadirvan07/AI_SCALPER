"""Sealed attestation for the official MetaTrader5 installed module.

This module deliberately does not import :mod:`MetaTrader5`.  The adapter is
the only reviewed import boundary.  Here we verify the already-imported module
against the exact Windows dependency-lock receipt and its wheel ``RECORD``
ownership before any broker initialization is allowed.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
import hashlib
from importlib.machinery import ExtensionFileLoader, ModuleSpec, SourceFileLoader
import marshal
from pathlib import Path, PurePosixPath
import stat
import sys
from types import CodeType
from types import ModuleType
from typing import Mapping, Sequence

from .contracts import (
    CanonicalContract,
    canonical_sha256,
    require_hash,
    require_int,
    require_text,
)
from .dependency_lock import (
    DIRECT_REQUIREMENTS,
    MT5_WHEEL_SHA256,
    verify_installed_lock,
)


MT5_DISTRIBUTION_NAME = "metatrader5"
MT5_MODULE_NAME = "MetaTrader5"
MT5_DISTRIBUTION_VERSION = DIRECT_REQUIREMENTS[MT5_DISTRIBUTION_NAME]
MT5_INSTALLATION_SCHEMA_VERSION = "verified-mt5-installation-v1"
MT5_MODULE_ATTESTATION_SCHEMA_VERSION = "verified-mt5-module-attestation-v1"

_INSTALLATION_SEAL = object()
_MODULE_ATTESTATION_SEAL = object()


class MT5ModuleAttestationError(RuntimeError):
    """Raised when installed or imported MT5 identity cannot be proven."""


def _is_mt5_namespace(name: object) -> bool:
    return isinstance(name, str) and (
        name == MT5_MODULE_NAME or name.startswith(MT5_MODULE_NAME + ".")
    )


def require_clean_mt5_import_namespace(
    module_registry: Mapping[str, object] | None = None,
) -> None:
    """Reject preloaded top-level or native MT5 modules before official import."""

    registry = sys.modules if module_registry is None else module_registry
    occupied = sorted(name for name in registry if _is_mt5_namespace(name))
    if occupied:
        raise MT5ModuleAttestationError("MT5_IMPORT_NAMESPACE_PRELOADED")


def _path_sha256(path: Path) -> str:
    canonical = str(path).replace("\\", "/").casefold().encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def module_relative_path_sha256(value: str) -> str:
    """Return the stable digest used to bind an installed module path."""

    relative = _safe_relative_path(value)
    return hashlib.sha256(relative.encode("utf-8")).hexdigest()


def _safe_relative_path(value: object) -> str:
    text = str(value or "")
    pure = PurePosixPath(text)
    if (
        not text
        or "\\" in text
        or "\x00" in text
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise MT5ModuleAttestationError("MT5_RECORD_RELATIVE_PATH_INVALID")
    return pure.as_posix()


def _regular_non_reparse(path: Path, *, label: str) -> None:
    try:
        details = path.lstat()
    except OSError as exc:
        raise MT5ModuleAttestationError(f"{label}_UNAVAILABLE") from exc
    reparse = bool(
        getattr(details, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )
    if path.is_symlink() or reparse:
        raise MT5ModuleAttestationError(f"{label}_REPARSE_POINT_FORBIDDEN")


def _hash_regular_file(path: Path, *, label: str) -> tuple[int, str]:
    _regular_non_reparse(path, label=label)
    try:
        details = path.stat()
        if not stat.S_ISREG(details.st_mode):
            raise MT5ModuleAttestationError(f"{label}_NOT_REGULAR_FILE")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
    except MT5ModuleAttestationError:
        raise
    except OSError as exc:
        raise MT5ModuleAttestationError(f"{label}_UNREADABLE") from exc
    return details.st_size, digest.hexdigest()


@dataclass(frozen=True)
class MT5RecordOwnedFile(CanonicalContract):
    relative_path: str
    file_sha256: str
    size: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "relative_path", _safe_relative_path(self.relative_path)
        )
        object.__setattr__(
            self,
            "file_sha256",
            require_hash("file_sha256", self.file_sha256),
        )
        require_int("size", self.size, minimum=1)


@dataclass(frozen=True)
class MT5NamespaceModuleAttestation(CanonicalContract):
    module_name: str
    module_relative_path: str
    module_relative_path_sha256: str
    module_origin_sha256: str
    module_file_sha256: str
    module_file_size: int
    loader_type: str
    runtime_identity_sha256: str

    def __post_init__(self) -> None:
        name = require_text("module_name", self.module_name)
        if not _is_mt5_namespace(name):
            raise ValueError("module is outside the MetaTrader5 namespace")
        object.__setattr__(self, "module_name", name)
        relative = _safe_relative_path(self.module_relative_path)
        object.__setattr__(self, "module_relative_path", relative)
        for field_name in (
            "module_relative_path_sha256",
            "module_origin_sha256",
            "module_file_sha256",
            "runtime_identity_sha256",
        ):
            object.__setattr__(
                self,
                field_name,
                require_hash(field_name, getattr(self, field_name)),
            )
        if module_relative_path_sha256(relative) != self.module_relative_path_sha256:
            raise ValueError("module relative path digest drift")
        require_int("module_file_size", self.module_file_size, minimum=1)
        object.__setattr__(
            self, "loader_type", require_text("loader_type", self.loader_type)
        )


@dataclass(frozen=True)
class VerifiedMT5Installation(CanonicalContract):
    """Exact installed environment and MetaTrader5 wheel ownership receipt."""

    dependency_lock_sha256: str
    install_manifest_sha256: str
    installed_environment_sha256: str
    site_packages_sha256: str
    distribution_name: str
    distribution_version: str
    wheel_sha256: str
    site_packages_tree_sha256: str
    record_sha256: str
    owned_site_files: tuple[MT5RecordOwnedFile, ...]
    schema_version: str = MT5_INSTALLATION_SCHEMA_VERSION
    _site_packages: InitVar[str | Path | None] = None
    _seal: InitVar[object | None] = None

    def __post_init__(
        self,
        _site_packages: str | Path | None,
        _seal: object | None,
    ) -> None:
        if _seal is not _INSTALLATION_SEAL:
            raise TypeError(
                "VerifiedMT5Installation can only be minted from the installed lock"
            )
        for name in (
            "dependency_lock_sha256",
            "install_manifest_sha256",
            "installed_environment_sha256",
            "site_packages_sha256",
            "wheel_sha256",
            "site_packages_tree_sha256",
            "record_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if self.distribution_name != MT5_DISTRIBUTION_NAME:
            raise ValueError("MT5 distribution name drift")
        if self.distribution_version != MT5_DISTRIBUTION_VERSION:
            raise ValueError("MT5 distribution version drift")
        if self.wheel_sha256 != MT5_WHEEL_SHA256:
            raise ValueError("MT5 wheel SHA-256 drift")
        if self.schema_version != MT5_INSTALLATION_SCHEMA_VERSION:
            raise ValueError("MT5 installation schema drift")
        files = tuple(self.owned_site_files)
        if not files or any(type(item) is not MT5RecordOwnedFile for item in files):
            raise TypeError("MT5 owned site files must be exact receipts")
        keys = [item.relative_path.casefold() for item in files]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError("MT5 owned site files must be unique and sorted")
        object.__setattr__(self, "owned_site_files", files)
        if _site_packages is None:
            raise TypeError("verified site-packages path is required")
        root = Path(_site_packages)
        _regular_non_reparse(root, label="MT5_SITE_PACKAGES")
        try:
            resolved = root.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise MT5ModuleAttestationError("MT5_SITE_PACKAGES_UNAVAILABLE") from exc
        if not resolved.is_dir() or _path_sha256(resolved) != self.site_packages_sha256:
            raise MT5ModuleAttestationError("MT5_SITE_PACKAGES_BINDING_MISMATCH")
        object.__setattr__(self, "_verified_site_packages", resolved)

    @property
    def verified_site_packages(self) -> Path:
        return self._verified_site_packages


@dataclass(frozen=True)
class VerifiedMT5ModuleAttestation(CanonicalContract):
    """Identity proof for the exact imported official module object."""

    installation_sha256: str
    dependency_lock_sha256: str
    installed_environment_sha256: str
    distribution_name: str
    distribution_version: str
    wheel_sha256: str
    site_packages_tree_sha256: str
    record_sha256: str
    module_name: str
    module_version: str
    module_relative_path: str
    module_relative_path_sha256: str
    module_origin_sha256: str
    module_file_sha256: str
    module_file_size: int
    namespace_modules: tuple[MT5NamespaceModuleAttestation, ...]
    public_runtime_surface_sha256: str
    schema_version: str = MT5_MODULE_ATTESTATION_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _MODULE_ATTESTATION_SEAL:
            raise TypeError(
                "VerifiedMT5ModuleAttestation can only be minted by verification"
            )
        for name in (
            "installation_sha256",
            "dependency_lock_sha256",
            "installed_environment_sha256",
            "wheel_sha256",
            "site_packages_tree_sha256",
            "record_sha256",
            "module_relative_path_sha256",
            "module_origin_sha256",
            "module_file_sha256",
            "public_runtime_surface_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if self.distribution_name != MT5_DISTRIBUTION_NAME:
            raise ValueError("MT5 distribution name drift")
        if self.distribution_version != MT5_DISTRIBUTION_VERSION:
            raise ValueError("MT5 distribution version drift")
        if self.wheel_sha256 != MT5_WHEEL_SHA256:
            raise ValueError("MT5 wheel SHA-256 drift")
        if self.module_name != MT5_MODULE_NAME:
            raise ValueError("MT5 module name drift")
        if self.module_version != MT5_DISTRIBUTION_VERSION:
            raise ValueError("MT5 module version drift")
        relative = _safe_relative_path(self.module_relative_path)
        object.__setattr__(self, "module_relative_path", relative)
        if module_relative_path_sha256(relative) != self.module_relative_path_sha256:
            raise ValueError("MT5 module relative path digest drift")
        require_int("module_file_size", self.module_file_size, minimum=1)
        namespace = tuple(self.namespace_modules)
        if (
            not namespace
            or any(type(item) is not MT5NamespaceModuleAttestation for item in namespace)
            or [item.module_name for item in namespace]
            != sorted(item.module_name for item in namespace)
            or len({item.module_name for item in namespace}) != len(namespace)
            or namespace[0].module_name != MT5_MODULE_NAME
        ):
            raise ValueError("MT5 namespace attestation is incomplete or unordered")
        object.__setattr__(self, "namespace_modules", namespace)
        if self.schema_version != MT5_MODULE_ATTESTATION_SCHEMA_VERSION:
            raise ValueError("MT5 module attestation schema drift")


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise MT5ModuleAttestationError(f"{label}_INVALID")
    return value


def _installation_from_verified_receipt(
    receipt: Mapping[str, object],
) -> VerifiedMT5Installation:
    distributions = receipt.get("distribution_receipts")
    if not isinstance(distributions, Sequence) or isinstance(
        distributions, (str, bytes, bytearray)
    ):
        raise MT5ModuleAttestationError("INSTALLED_DISTRIBUTION_RECEIPTS_MISSING")
    candidates = [
        _mapping(item, label="INSTALLED_DISTRIBUTION_RECEIPT")
        for item in distributions
        if isinstance(item, Mapping) and item.get("name") == MT5_DISTRIBUTION_NAME
    ]
    if len(candidates) != 1:
        raise MT5ModuleAttestationError("MT5_DISTRIBUTION_RECEIPT_NOT_UNIQUE")
    distribution = candidates[0]
    if distribution.get("version") != MT5_DISTRIBUTION_VERSION:
        raise MT5ModuleAttestationError("MT5_DISTRIBUTION_VERSION_MISMATCH")
    if distribution.get("wheel_sha256") != MT5_WHEEL_SHA256:
        raise MT5ModuleAttestationError("MT5_WHEEL_SHA256_MISMATCH")
    raw_files = distribution.get("owned_site_files")
    if not isinstance(raw_files, Sequence) or isinstance(
        raw_files, (str, bytes, bytearray)
    ):
        raise MT5ModuleAttestationError("MT5_RECORD_OWNERSHIP_MISSING")
    files = tuple(
        sorted(
            (
                MT5RecordOwnedFile(
                    relative_path=str(_mapping(item, label="MT5_RECORD_FILE").get("path")),
                    file_sha256=str(
                        _mapping(item, label="MT5_RECORD_FILE").get("sha256")
                    ),
                    size=_mapping(item, label="MT5_RECORD_FILE").get("size"),
                )
                for item in raw_files
            ),
            key=lambda item: item.relative_path.casefold(),
        )
    )
    site_packages = Path(str(receipt.get("site_packages") or ""))
    try:
        resolved_site_packages = site_packages.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise MT5ModuleAttestationError("MT5_SITE_PACKAGES_UNAVAILABLE") from exc
    return VerifiedMT5Installation(
        dependency_lock_sha256=str(receipt.get("lock_sha256") or ""),
        install_manifest_sha256=str(
            receipt.get("install_manifest_sha256") or ""
        ),
        installed_environment_sha256=str(
            receipt.get("installed_environment_sha256") or ""
        ),
        site_packages_sha256=_path_sha256(resolved_site_packages),
        distribution_name=str(distribution.get("name") or ""),
        distribution_version=str(distribution.get("version") or ""),
        wheel_sha256=str(distribution.get("wheel_sha256") or ""),
        site_packages_tree_sha256=str(
            distribution.get("site_packages_tree_sha256") or ""
        ),
        record_sha256=str(distribution.get("record_sha256") or ""),
        owned_site_files=files,
        _site_packages=resolved_site_packages,
        _seal=_INSTALLATION_SEAL,
    )


def verify_mt5_installed_environment(
    dependency_lock_file: str | Path,
) -> VerifiedMT5Installation:
    """Run the full Windows lock verifier and seal the MT5 distribution view."""

    receipt = verify_installed_lock(dependency_lock_file)
    if not isinstance(receipt, Mapping):
        raise MT5ModuleAttestationError("INSTALLED_ENVIRONMENT_RECEIPT_INVALID")
    return _installation_from_verified_receipt(receipt)


def _require_path_chain(root: Path, origin: Path) -> str:
    if not origin.is_absolute():
        raise MT5ModuleAttestationError("MT5_MODULE_ORIGIN_NOT_ABSOLUTE")
    try:
        relative = origin.relative_to(root)
    except ValueError as exc:
        raise MT5ModuleAttestationError("MT5_MODULE_ORIGIN_ESCAPED_SITE_PACKAGES") from exc
    _regular_non_reparse(root, label="MT5_SITE_PACKAGES")
    current = root
    for part in relative.parts:
        current = current / part
        _regular_non_reparse(current, label="MT5_MODULE_PATH")
    return _safe_relative_path(relative.as_posix())


def _attest_namespace_module(
    name: str,
    module: object,
    installation: VerifiedMT5Installation,
) -> MT5NamespaceModuleAttestation:
    if type(module) is not ModuleType:
        raise MT5ModuleAttestationError("MT5_NAMESPACE_MODULE_TYPE_MISMATCH")
    if module.__name__ != name or not _is_mt5_namespace(name):
        raise MT5ModuleAttestationError("MT5_NAMESPACE_MODULE_NAME_MISMATCH")
    package = module.__package__
    if not isinstance(package, str) or not (
        package == MT5_MODULE_NAME or package.startswith(MT5_MODULE_NAME + ".")
    ):
        raise MT5ModuleAttestationError("MT5_MODULE_PACKAGE_MISMATCH")
    specification = module.__spec__
    if type(specification) is not ModuleSpec:
        raise MT5ModuleAttestationError("MT5_MODULE_SPEC_MISMATCH")
    if specification.name != name:
        raise MT5ModuleAttestationError("MT5_MODULE_SPEC_NAME_MISMATCH")
    loader = specification.loader
    if type(loader) not in {SourceFileLoader, ExtensionFileLoader}:
        raise MT5ModuleAttestationError("MT5_MODULE_LOADER_TYPE_MISMATCH")
    if module.__loader__ is not loader:
        raise MT5ModuleAttestationError("MT5_MODULE_LOADER_BINDING_MISMATCH")
    origin_text = specification.origin
    file_text = module.__file__
    if not isinstance(origin_text, str) or not isinstance(file_text, str):
        raise MT5ModuleAttestationError("MT5_MODULE_ORIGIN_MISSING")
    try:
        origin_path = Path(origin_text)
        module_file_path = Path(file_text)
        if not origin_path.is_absolute() or not module_file_path.is_absolute():
            raise MT5ModuleAttestationError("MT5_MODULE_ORIGIN_NOT_ABSOLUTE")
        _require_path_chain(installation.verified_site_packages, origin_path)
        _require_path_chain(installation.verified_site_packages, module_file_path)
        origin = origin_path.resolve(strict=True)
        module_file = module_file_path.resolve(strict=True)
    except MT5ModuleAttestationError:
        raise
    except (OSError, RuntimeError) as exc:
        raise MT5ModuleAttestationError("MT5_MODULE_ORIGIN_UNAVAILABLE") from exc
    if origin != module_file:
        raise MT5ModuleAttestationError("MT5_MODULE_FILE_SPEC_MISMATCH")
    loader_origin = Path(str(loader.path))
    _require_path_chain(installation.verified_site_packages, loader_origin)
    loader_path = loader_origin.resolve(strict=True)
    if loader.name != name or loader_path != origin:
        raise MT5ModuleAttestationError("MT5_MODULE_LOADER_ORIGIN_MISMATCH")
    relative = _require_path_chain(installation.verified_site_packages, origin)
    owned = {
        item.relative_path.casefold(): item for item in installation.owned_site_files
    }.get(relative.casefold())
    if owned is None:
        raise MT5ModuleAttestationError("MT5_MODULE_NOT_OWNED_BY_DISTRIBUTION_RECORD")
    size, file_sha256 = _hash_regular_file(origin, label="MT5_MODULE_ORIGIN")
    if size != owned.size or file_sha256 != owned.file_sha256:
        raise MT5ModuleAttestationError("MT5_MODULE_RECORD_HASH_MISMATCH")
    return MT5NamespaceModuleAttestation(
        module_name=name,
        module_relative_path=relative,
        module_relative_path_sha256=module_relative_path_sha256(relative),
        module_origin_sha256=_path_sha256(origin),
        module_file_sha256=file_sha256,
        module_file_size=size,
        loader_type=f"{type(loader).__module__}.{type(loader).__qualname__}",
        runtime_identity_sha256=hashlib.sha256(
            f"{name}\x00{id(module)}".encode("utf-8")
        ).hexdigest(),
    )


def _public_runtime_surface(
    namespace: Sequence[tuple[str, ModuleType]],
) -> str:
    surface: list[dict[str, object]] = []
    try:
        for module_name, namespace_module in namespace:
            for attribute, value in sorted(vars(namespace_module).items()):
                if attribute.startswith("_"):
                    continue
                if callable(value):
                    code = getattr(value, "__code__", None)
                    code_sha256 = (
                        hashlib.sha256(marshal.dumps(code)).hexdigest()
                        if type(code) is CodeType
                        else None
                    )
                    details: dict[str, object] = {
                        "attribute": attribute,
                        "code_sha256": code_sha256,
                        "kind": "CALLABLE",
                        "module": module_name,
                        "owner_module": str(getattr(value, "__module__", "")),
                        "owner_name": str(getattr(value, "__name__", "")),
                        "owner_qualname": str(
                            getattr(value, "__qualname__", "")
                        ),
                        "runtime_identity_sha256": hashlib.sha256(
                            f"{module_name}\x00{attribute}\x00{id(value)}".encode(
                                "utf-8"
                            )
                        ).hexdigest(),
                        "type": (
                            f"{type(value).__module__}."
                            f"{type(value).__qualname__}"
                        ),
                    }
                elif value is None or type(value) in {bool, int, float, str}:
                    details = {
                        "attribute": attribute,
                        "kind": "SCALAR",
                        "module": module_name,
                        "type": type(value).__name__,
                        "value": value,
                    }
                elif type(value) is bytes:
                    details = {
                        "attribute": attribute,
                        "kind": "BYTES",
                        "module": module_name,
                        "size": len(value),
                        "value_sha256": hashlib.sha256(value).hexdigest(),
                    }
                else:
                    raise MT5ModuleAttestationError(
                        "MT5_PUBLIC_RUNTIME_SURFACE_UNSUPPORTED_VALUE"
                    )
                surface.append(details)
    except Exception as exc:
        raise MT5ModuleAttestationError(
            "MT5_PUBLIC_RUNTIME_SURFACE_UNREADABLE"
        ) from exc
    if not surface:
        raise MT5ModuleAttestationError("MT5_PUBLIC_RUNTIME_SURFACE_EMPTY")
    return canonical_sha256(tuple(surface))


def verify_imported_mt5_module(
    module: object,
    installation: VerifiedMT5Installation,
    *,
    module_registry: Mapping[str, object] | None = None,
) -> VerifiedMT5ModuleAttestation:
    """Verify the imported top level, native submodules, and callable surface."""

    if type(installation) is not VerifiedMT5Installation:
        raise TypeError("installation must be exact VerifiedMT5Installation")
    if type(module) is not ModuleType:
        raise MT5ModuleAttestationError("MT5_MODULE_TYPE_MISMATCH")
    if module.__name__ != MT5_MODULE_NAME:
        raise MT5ModuleAttestationError("MT5_MODULE_NAME_MISMATCH")
    if str(module.__version__) != MT5_DISTRIBUTION_VERSION:
        raise MT5ModuleAttestationError("MT5_MODULE_VERSION_MISMATCH")
    registry = sys.modules if module_registry is None else module_registry
    if registry.get(MT5_MODULE_NAME) is not module:
        raise MT5ModuleAttestationError("MT5_TOP_LEVEL_REGISTRY_IDENTITY_MISMATCH")
    namespace = tuple(
        sorted(
            (
                (name, candidate)
                for name, candidate in registry.items()
                if _is_mt5_namespace(name)
            ),
            key=lambda item: item[0],
        )
    )
    if not namespace or namespace[0] != (MT5_MODULE_NAME, module):
        raise MT5ModuleAttestationError("MT5_IMPORT_NAMESPACE_INCOMPLETE")
    namespace_attestations = tuple(
        _attest_namespace_module(name, candidate, installation)
        for name, candidate in namespace
    )
    top_level = namespace_attestations[0]
    return VerifiedMT5ModuleAttestation(
        installation_sha256=installation.content_sha256,
        dependency_lock_sha256=installation.dependency_lock_sha256,
        installed_environment_sha256=installation.installed_environment_sha256,
        distribution_name=installation.distribution_name,
        distribution_version=installation.distribution_version,
        wheel_sha256=installation.wheel_sha256,
        site_packages_tree_sha256=installation.site_packages_tree_sha256,
        record_sha256=installation.record_sha256,
        module_name=module.__name__,
        module_version=str(module.__version__),
        module_relative_path=top_level.module_relative_path,
        module_relative_path_sha256=top_level.module_relative_path_sha256,
        module_origin_sha256=top_level.module_origin_sha256,
        module_file_sha256=top_level.module_file_sha256,
        module_file_size=top_level.module_file_size,
        namespace_modules=namespace_attestations,
        public_runtime_surface_sha256=_public_runtime_surface(namespace),
        _seal=_MODULE_ATTESTATION_SEAL,
    )


__all__ = [
    "MT5_DISTRIBUTION_NAME",
    "MT5_DISTRIBUTION_VERSION",
    "MT5_MODULE_NAME",
    "MT5ModuleAttestationError",
    "MT5RecordOwnedFile",
    "MT5NamespaceModuleAttestation",
    "VerifiedMT5Installation",
    "VerifiedMT5ModuleAttestation",
    "module_relative_path_sha256",
    "require_clean_mt5_import_namespace",
    "verify_imported_mt5_module",
    "verify_mt5_installed_environment",
]
