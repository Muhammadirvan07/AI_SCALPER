"""Windows CLI for a sanitized, unbound MT5 demo candidate probe."""

from __future__ import annotations

import argparse
import json

from live_runtime.mt5_binding_probe import (
    MT5BindingProbeError,
    probe_candidate_binding,
)
from live_runtime.mt5_readonly import (
    MT5ReadOnlyCapabilityError,
    ReadOnlyMT5Facade,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read safe MT5 demo binding facts; accepts no credentials"
    )
    parser.add_argument("--candidate", default="fbs")
    args = parser.parse_args()

    try:
        import MetaTrader5 as mt5

        if not mt5.initialize():
            print("MT5_BINDING_PROBE_FAILED: terminal initialization failed")
            return 1
        try:
            result = probe_candidate_binding(
                ReadOnlyMT5Facade(mt5),
                candidate_id=args.candidate,
            )
        finally:
            mt5.shutdown()
    except (MT5BindingProbeError, MT5ReadOnlyCapabilityError, ImportError) as exc:
        print(f"MT5_BINDING_PROBE_FAILED: {exc}")
        print("Safety lock remains active; no broker order was submitted.")
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
