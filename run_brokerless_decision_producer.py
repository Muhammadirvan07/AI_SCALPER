"""Validate the brokerless decision-only producer service contract.

Runtime construction intentionally remains external: a reviewed deployment
must inject read-only data, trusted UTC, IPC publication, and checkpoint CAS
ports.  This command cannot connect to a broker or activate execution.
"""

from __future__ import annotations

import argparse
import inspect

import live_runtime.brokerless_decision_producer as producer_service


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the non-executable brokerless decision producer"
    )
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--acknowledge-decision-only", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    if not args.acknowledge_decision_only:
        print(
            "DECISION_PRODUCER_REJECTED: explicit decision-only acknowledgement is required"
        )
        return 2
    if not args.validate_only:
        print(
            "DECISION_PRODUCER_REJECTED: external reviewed runtime ports are required"
        )
        return 2
    source = inspect.getsource(producer_service)
    forbidden = ("MetaTrader5", "order_send", "order_check", "initialize(")
    if any(value in source for value in forbidden):
        print("DECISION_PRODUCER_REJECTED: broker mutation surface detected")
        return 2
    print("BROKERLESS_DECISION_PRODUCER_VALID")
    print("Timeframe: M15")
    print("Read-only provider: EXTERNAL_CONFIGURATION_REQUIRED")
    print("Signed session calendar: EXTERNAL_CONFIGURATION_REQUIRED")
    print(
        "Trusted UTC, HMAC cursor verification, and external cursor CAS: "
        "EXTERNAL_CONFIGURATION_REQUIRED"
    )
    print("Broker mutation capability: DISABLED")
    print("Promotion evidence: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
