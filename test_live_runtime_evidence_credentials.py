from __future__ import annotations

import unittest

from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)


class _Backend:
    def __init__(self, *, read_error: bool = False, write_error: bool = False) -> None:
        self.read_error = read_error
        self.write_error = write_error
        self.value: str | None = None

    def get_password(self, service: str, name: str) -> str | None:
        if self.read_error:
            raise OSError("sensitive backend detail")
        return self.value

    def set_password(self, service: str, name: str, value: str) -> None:
        if self.write_error:
            raise OSError("sensitive backend detail")
        self.value = value


class EvidenceCredentialFailureTests(unittest.TestCase):
    def test_backend_read_failure_is_sanitized(self) -> None:
        store = WindowsEvidenceKeyStore(
            backend=_Backend(read_error=True),
            platform="win32",
        )
        with self.assertRaisesRegex(
            EvidenceCredentialError,
            "credential backend read failed",
        ) as caught:
            store.load("finex-demo-discovery-v1")
        self.assertNotIn("sensitive backend detail", str(caught.exception))

    def test_backend_write_failure_is_sanitized(self) -> None:
        store = WindowsEvidenceKeyStore(
            backend=_Backend(write_error=True),
            platform="win32",
        )
        with self.assertRaisesRegex(
            EvidenceCredentialError,
            "credential backend write failed",
        ) as caught:
            store.ensure("finex-demo-discovery-v1")
        self.assertNotIn("sensitive backend detail", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
