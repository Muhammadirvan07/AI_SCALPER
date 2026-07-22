"""Independent signed comparison of two clean Windows release builds."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
import hmac
import json
import re
from typing import Callable, Mapping

from .contracts import require_hash, require_text, require_utc


PYTHON_312 = re.compile(r"^3\.12(?:\.[0-9]+)?$")


class ReproducibilityError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = str(reason_code or "").strip().upper()
        super().__init__(self.reason_code)


def _key(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        value = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        value = secret
    else:
        raise TypeError("reproducibility key must be str or bytes")
    if len(value) < 32:
        raise ValueError("reproducibility key must contain at least 32 bytes")
    return value


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _git_object_hash(field: str, value: object) -> str:
    try:
        digest = require_hash(field, value, minimum_length=40)
    except ValueError as exc:
        raise ReproducibilityError(
            f"{field.upper()}_FULL_HASH_REQUIRED"
        ) from exc
    if len(digest) not in {40, 64}:
        raise ReproducibilityError(f"{field.upper()}_FULL_HASH_REQUIRED")
    return digest


@dataclass(frozen=True)
class ReproducibilityObservation:
    build_id: str
    host_alias_sha256: str
    os_name: str
    python_version: str
    clean_checkout: bool
    git_commit: str
    git_tree: str
    archive_sha256: str
    manifest_sha256: str
    release_identity_sha256: str
    observed_at_utc: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "build_id", require_text("build_id", self.build_id))
        object.__setattr__(
            self,
            "host_alias_sha256",
            require_hash("host_alias_sha256", self.host_alias_sha256),
        )
        os_name = require_text("os_name", self.os_name, upper=True)
        if os_name != "WINDOWS":
            raise ReproducibilityError("WINDOWS_HOST_REQUIRED")
        object.__setattr__(self, "os_name", os_name)
        version = require_text("python_version", self.python_version)
        if PYTHON_312.fullmatch(version) is None:
            raise ReproducibilityError("CPYTHON_3_12_REQUIRED")
        object.__setattr__(self, "python_version", version)
        if self.clean_checkout is not True:
            raise ReproducibilityError("CLEAN_CHECKOUT_REQUIRED")
        for field in ("git_commit", "git_tree"):
            object.__setattr__(
                self, field, _git_object_hash(field, getattr(self, field))
            )
        for field in (
            "archive_sha256",
            "manifest_sha256",
            "release_identity_sha256",
        ):
            object.__setattr__(
                self, field, require_hash(field, getattr(self, field))
            )
        require_utc("observed_at_utc", self.observed_at_utc)


@dataclass(frozen=True)
class WindowsReproducibilityReceipt:
    first_build_id: str
    second_build_id: str
    first_host_alias_sha256: str
    second_host_alias_sha256: str
    git_commit: str
    git_tree: str
    archive_sha256: str
    manifest_sha256: str
    release_identity_sha256: str
    issued_at_utc: datetime
    signer_key_id: str
    signature_hmac_sha256: str = ""
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    promotion_eligible: bool = False
    max_lot: float = 0.01
    schema_version: str = "windows-release-reproducibility-v1"

    def __post_init__(self) -> None:
        if self.first_build_id == self.second_build_id:
            raise ReproducibilityError("BUILD_ID_REPLAY")
        for field in ("first_build_id", "second_build_id", "signer_key_id"):
            object.__setattr__(self, field, require_text(field, getattr(self, field)))
        for field in (
            "first_host_alias_sha256",
            "second_host_alias_sha256",
            "archive_sha256",
            "manifest_sha256",
            "release_identity_sha256",
        ):
            object.__setattr__(self, field, require_hash(field, getattr(self, field)))
        for field in ("git_commit", "git_tree"):
            object.__setattr__(
                self, field, _git_object_hash(field, getattr(self, field))
            )
        require_utc("issued_at_utc", self.issued_at_utc)
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = require_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if (
            self.live_allowed
            or self.safe_to_demo_auto_order
            or self.promotion_eligible
            or self.max_lot != 0.01
        ):
            raise ValueError("reproducibility receipt safety locks changed")
        if self.schema_version != "windows-release-reproducibility-v1":
            raise ValueError("reproducibility schema mismatch")

    @property
    def signing_payload(self) -> bytes:
        payload = dict(self.__dict__)
        payload.pop("signature_hmac_sha256")
        payload["issued_at_utc"] = self.issued_at_utc.isoformat().replace("+00:00", "Z")
        return _canonical(payload)

    @property
    def receipt_id(self) -> str:
        return "release_repro_" + hashlib.sha256(self.signing_payload).hexdigest()[:32]

    def sign(self, secret: str | bytes) -> "WindowsReproducibilityReceipt":
        signature = hmac.new(_key(secret), self.signing_payload, hashlib.sha256).hexdigest()
        return replace(self, signature_hmac_sha256=signature)

    def verify(self, secret: str | bytes) -> bool:
        if not self.signature_hmac_sha256:
            return False
        expected = hmac.new(_key(secret), self.signing_payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature_hmac_sha256)


def issue_reproducibility_receipt(
    first: ReproducibilityObservation,
    second: ReproducibilityObservation,
    *,
    issued_at: datetime,
    signer_key_id: str,
    secret: str | bytes,
) -> WindowsReproducibilityReceipt:
    if type(first) is not ReproducibilityObservation or type(
        second
    ) is not ReproducibilityObservation:
        raise TypeError("two exact ReproducibilityObservation values are required")
    if first.build_id == second.build_id:
        raise ReproducibilityError("BUILD_ID_REPLAY")
    comparisons = (
        ("GIT_COMMIT_MISMATCH", first.git_commit, second.git_commit),
        ("GIT_TREE_MISMATCH", first.git_tree, second.git_tree),
        ("ARCHIVE_SHA256_MISMATCH", first.archive_sha256, second.archive_sha256),
        ("MANIFEST_SHA256_MISMATCH", first.manifest_sha256, second.manifest_sha256),
        (
            "RELEASE_IDENTITY_SHA256_MISMATCH",
            first.release_identity_sha256,
            second.release_identity_sha256,
        ),
    )
    for reason, left, right in comparisons:
        if left != right:
            raise ReproducibilityError(reason)
    issued = require_utc("issued_at", issued_at)
    if issued < max(first.observed_at_utc, second.observed_at_utc):
        raise ReproducibilityError("ISSUED_BEFORE_BUILD_OBSERVATION")
    return WindowsReproducibilityReceipt(
        first_build_id=first.build_id,
        second_build_id=second.build_id,
        first_host_alias_sha256=first.host_alias_sha256,
        second_host_alias_sha256=second.host_alias_sha256,
        git_commit=first.git_commit,
        git_tree=first.git_tree,
        archive_sha256=first.archive_sha256,
        manifest_sha256=first.manifest_sha256,
        release_identity_sha256=first.release_identity_sha256,
        issued_at_utc=issued,
        signer_key_id=signer_key_id,
    ).sign(secret)


def verify_reproducibility_receipt(
    receipt: WindowsReproducibilityReceipt,
    *,
    key_provider: Callable[[str], str | bytes],
    checked_at: datetime,
) -> bool:
    # A subclass could otherwise replace ``verify`` and forge release trust.
    if type(receipt) is not WindowsReproducibilityReceipt:
        raise TypeError("receipt must be exact WindowsReproducibilityReceipt")
    if not callable(key_provider):
        raise TypeError("key_provider must be callable")
    checked = require_utc("checked_at", checked_at)
    if checked < receipt.issued_at_utc:
        return False
    try:
        return receipt.verify(key_provider(receipt.signer_key_id))
    except (KeyError, TypeError, ValueError):
        return False


__all__ = [
    "ReproducibilityError",
    "ReproducibilityObservation",
    "WindowsReproducibilityReceipt",
    "issue_reproducibility_receipt",
    "verify_reproducibility_receipt",
]
