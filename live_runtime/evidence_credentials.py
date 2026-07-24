"""Windows Credential Manager custody for validation-evidence HMAC keys.

The secret value is never accepted as a CLI argument, printed, or persisted in
the repository.  ``keyring`` is imported lazily so development and unit tests
on macOS do not require a Windows credential backend.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import sys
from typing import Any


EVIDENCE_KEY_SERVICE = "AI_SCALPER_PHASE3_EVIDENCE"
_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class EvidenceCredentialError(RuntimeError):
    pass


def signing_key_fingerprint(signing_key: bytes) -> str:
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise EvidenceCredentialError("evidence signing key is invalid")
    return hashlib.sha256(signing_key).hexdigest()[:16]


class WindowsEvidenceKeyStore:
    """Small adapter over the OS credential vault with an injectable backend."""

    def __init__(
        self,
        *,
        backend: Any | None = None,
        platform: str | None = None,
        service: str = EVIDENCE_KEY_SERVICE,
    ) -> None:
        effective_platform = sys.platform if platform is None else platform
        if effective_platform != "win32":
            raise EvidenceCredentialError(
                "evidence key custody requires Windows Credential Manager"
            )
        if backend is None:
            try:
                import keyring
            except ImportError as exc:
                raise EvidenceCredentialError(
                    "keyring is required on the Windows evidence host"
                ) from exc
            selected = keyring.get_keyring()
            selected_type = type(selected)
            if (
                selected_type.__module__ != "keyring.backends.Windows"
                or selected_type.__name__ != "WinVaultKeyring"
            ):
                raise EvidenceCredentialError(
                    "Windows Credential Manager backend is required"
                )
            backend = selected
        if any(
            not callable(getattr(backend, name, None))
            for name in ("get_password", "set_password")
        ):
            raise EvidenceCredentialError("credential backend is unavailable")
        self._backend = backend
        self._service = str(service).strip()
        if not self._service:
            raise EvidenceCredentialError("credential service is required")

    @staticmethod
    def _name(key_name: str) -> str:
        normalized = str(key_name or "").strip()
        if _KEY_NAME_RE.fullmatch(normalized) is None:
            raise EvidenceCredentialError("credential key name is invalid")
        return normalized

    @staticmethod
    def _decode(value: object) -> bytes:
        text = str(value or "")
        if not text.startswith("hex:"):
            raise EvidenceCredentialError("stored evidence credential is invalid")
        try:
            key = bytes.fromhex(text[4:])
        except ValueError as exc:
            raise EvidenceCredentialError("stored evidence credential is invalid") from exc
        if len(key) < 32:
            raise EvidenceCredentialError("stored evidence credential is too short")
        return key

    def load(self, key_name: str) -> bytes:
        name = self._name(key_name)
        value = self._backend.get_password(self._service, name)
        if value is None:
            raise EvidenceCredentialError("evidence credential is not provisioned")
        return self._decode(value)

    def ensure(self, key_name: str) -> tuple[bytes, bool]:
        """Return the existing key or provision one new 256-bit key."""

        name = self._name(key_name)
        existing = self._backend.get_password(self._service, name)
        if existing is not None:
            return self._decode(existing), False
        generated = secrets.token_bytes(32)
        self._backend.set_password(self._service, name, "hex:" + generated.hex())
        persisted = self.load(name)
        if persisted != generated:
            raise EvidenceCredentialError("credential verification failed after provisioning")
        return persisted, True


__all__ = [
    "EVIDENCE_KEY_SERVICE",
    "EvidenceCredentialError",
    "WindowsEvidenceKeyStore",
    "signing_key_fingerprint",
]
