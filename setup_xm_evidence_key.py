"""Provision the XM diagnostic evidence key in Windows Credential Manager."""

from live_runtime.evidence_bootstrap import KEY_NAME
from live_runtime.evidence_credentials import (
    WindowsEvidenceKeyStore,
    signing_key_fingerprint,
)


def main() -> int:
    key, created = WindowsEvidenceKeyStore().ensure(KEY_NAME)
    print("Evidence credential status: " + ("CREATED" if created else "EXISTS"))
    print("Key name: " + KEY_NAME)
    print("Key fingerprint: " + signing_key_fingerprint(key))
    print("Secret value: NOT_PRINTED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
