"""Build the deterministic Windows GATED execution-service release.

This pipeline is deliberately separate from the read-only Windows release
builder.  It permits the two reviewed MetaTrader order primitives only at the
sealed adapter boundary and preserves every activation lock as fail-closed.
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tomllib
from typing import Any, Iterable, Mapping

from build_windows_release import (
    MAX_SOURCE_FILE_BYTES,
    MAX_TOTAL_SOURCE_BYTES,
    ReleaseBuildError,
    _canonical_json,
    _create_archive,
    _git,
    _json_contains_secret,
    _normalize_relative_path,
    _sha256,
    _validate_git_release_source,
    _verify_local_import_closure,
    _write_exclusive,
)
from live_runtime.live_grade_gate_catalog import (
    catalog_report,
    classify_gate_codes,
)


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_ALLOWLIST = REPO_ROOT / "config" / "windows_execution_service_allowlist.v1.json"
ALLOWLIST_SCHEMA = "ai-scalper-windows-execution-service-allowlist-v1"
MANIFEST_SCHEMA = "ai-scalper-windows-execution-service-manifest-v1"
ALLOWLIST_NAME_PATTERN = re.compile(
    r"windows_execution_service_allowlist\.v[1-9][0-9]*\.json"
)
ALLOWLIST_FIELDS = {
    "files",
    "release_profile",
    "safety",
    "schema_version",
    "usage_policy",
}
REQUIRED_SAFETY = {
    "live_allowed": False,
    "safe_to_demo_auto_order": False,
    "max_lot": 0.01,
    "order_capability": "GATED_PRESENT",
}
ACTIVATION_REQUIRES = (
    "SIGNED_STAGE_AUTHORIZATION",
    "ENVIRONMENT_ARM",
    "PROMOTION_PERMIT",
)
READINESS_BLOCKERS = (
    "ASYMMETRIC_PUBLIC_VERIFICATION_OR_EXTERNAL_LAUNCHER_ATTESTATION_REQUIRED",
    "EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_REQUIRED",
    "EXTERNAL_DEMO_AUTO_IPC_CONFIGURATION_REQUIRED",
    "EXTERNAL_DEMO_AUTO_SESSION_CUSTODY_REQUIRED",
    "EXTERNAL_CREDENTIAL_SESSION_RECEIPT_REQUIRED",
    "EXTERNAL_DECISION_DATA_PROVIDER_REQUIRED",
    "EXTERNAL_EXECUTION_CYCLE_PROVIDER_REQUIRED",
    "EXTERNAL_JOURNAL_CHECKPOINT_REQUIRED",
    "EXTERNAL_JOURNAL_CHECKPOINT_CAS_EXPORTER_REQUIRED",
    "EXTERNAL_JOURNAL_PROVISIONING_RECEIPT_REQUIRED",
    "EXTERNAL_MANUAL_APPROVAL_PROVIDER_REQUIRED",
    "EXACT_INSTALLED_MT5_MODULE_ATTESTATION_REQUIRED",
    "EXTERNAL_PERMIT_SECRET_PROVIDER_REQUIRED",
    "EXTERNAL_PROMOTION_EVIDENCE_TRUST_REQUIRED",
    "EXTERNAL_RECONCILIATION_PROVIDER_REQUIRED",
    "EXTERNAL_RISK_SOURCE_AND_STATE_RECEIPTS_REQUIRED",
    "EXTERNAL_RISK_CHECKPOINT_CAS_EXPORTER_REQUIRED",
    "EXTERNAL_RUNTIME_FACT_PROVIDER_REQUIRED",
    "EXTERNAL_SIGNED_NEWS_RECEIPT_REQUIRED",
    "EXTERNAL_STAGE_AUTHORIZATION_REQUIRED",
    "EXTERNAL_SUPERVISOR_CHECKPOINT_REQUIRED",
    "EXTERNAL_TRUSTED_CLOCK_PROVIDER_REQUIRED",
    "EXTERNAL_WORM_AUDIT_RECEIPT_REQUIRED",
    "SIGNED_RUNTIME_RECEIPTS_REQUIRED",
)
REQUIRED_USAGE_POLICY = {
    "bundle_class": "GATED_EXECUTION_SERVICE",
    "execution_context": "WINDOWS_TASK_SCHEDULER_SERVICE_ACCOUNT",
    "network_capable_tooling_present": True,
    "broker_mutation_capability": "GATED_PRESENT",
    "production_service_execution_allowed": False,
    "runtime_materialization_required": True,
    "validation_entrypoint": "validate_windows_gated_execution_service.py",
    "activation_requires": list(ACTIVATION_REQUIRES),
}
REQUIRED_ADAPTER = "live_runtime/mt5_adapter.py"
REQUIRED_BOOTSTRAP = "live_runtime/production_bootstrap.py"
REQUIRED_MT5_ATTESTATION = "live_runtime/mt5_module_attestation.py"
REQUIRED_ENTRYPOINT = "validate_windows_gated_execution_service.py"
REQUIRED_SERVICE_ENTRYPOINT = "run_windows_gated_execution_service.py"
REQUIRED_SERVICE_RUNTIME = "live_runtime/windows_service_entrypoint.py"
REQUIRED_DECISION_IPC = "live_runtime/decision_ipc.py"
REQUIRED_DEMO_AUTO_IPC_CONSUMER = "live_runtime/demo_auto_ipc_consumer.py"
REQUIRED_DEMO_AUTO_RISK_INTENT_PIPELINE = (
    "live_runtime/demo_auto_risk_intent_pipeline.py"
)
REQUIRED_DEMO_AUTO_SESSION_CAPABILITY = (
    "live_runtime/demo_auto_session_capability.py"
)
REQUIRED_DEMO_AUTO_SOAK_PROJECTION = (
    "live_runtime/demo_auto_soak_projection.py"
)
REQUIRED_DEMO_AUTO_SOAK_COHORT = "live_runtime/demo_auto_soak_cohort.py"
REQUIRED_DEMO_AUTO_SOAK_TRACKER = "live_runtime/soak_tracker.py"
REQUIRED_LIVE_GRADE_GATE_CATALOG = "live_runtime/live_grade_gate_catalog.py"
REQUIRED_SIGNED_RELEASE_TRUST = "live_runtime/signed_release_trust.py"
REQUIRED_ASYMMETRIC_RELEASE_TRUST = "live_runtime/asymmetric_release_trust.py"
REQUIRED_FACTORY_TEMPLATE = "live_runtime/windows_service_factory_template.py"
REQUIRED_CONFIG = "config/windows_execution_service_allowlist.v1.json"
REQUIRED_DEPENDENCY_FILES = {
    "pylock.windows-cp312.toml",
    "requirements-live-windows.txt",
    "requirements-windows-cp312.lock.txt",
}
ORDER_PRIMITIVES = ("order_check", "order_send")
REVIEWED_MT5_STATIC_ATTRIBUTES = frozenset(
    {
        "ACCOUNT_TRADE_MODE_DEMO",
        "ACCOUNT_TRADE_MODE_REAL",
        "COPY_TICKS_ALL",
        "ORDER_FILLING_FOK",
        "ORDER_FILLING_IOC",
        "ORDER_TIME_GTC",
        "ORDER_TYPE_BUY",
        "ORDER_TYPE_SELL",
        "SYMBOL_FILLING_FOK",
        "SYMBOL_FILLING_IOC",
        "TRADE_ACTION_DEAL",
        "TRADE_RETCODE_CANCEL",
        "TRADE_RETCODE_DONE",
        "TRADE_RETCODE_DONE_PARTIAL",
        "TRADE_RETCODE_INVALID",
        "TRADE_RETCODE_INVALID_EXPIRATION",
        "TRADE_RETCODE_INVALID_ORDER",
        "TRADE_RETCODE_INVALID_PRICE",
        "TRADE_RETCODE_INVALID_STOPS",
        "TRADE_RETCODE_INVALID_VOLUME",
        "TRADE_RETCODE_LIMIT_ORDERS",
        "TRADE_RETCODE_LIMIT_VOLUME",
        "TRADE_RETCODE_MARKET_CLOSED",
        "TRADE_RETCODE_NO_MONEY",
        "TRADE_RETCODE_ORDER_CHANGED",
        "TRADE_RETCODE_PLACED",
        "TRADE_RETCODE_PRICE_CHANGED",
        "TRADE_RETCODE_PRICE_OFF",
        "TRADE_RETCODE_REJECT",
        "TRADE_RETCODE_REQUOTE",
        "TRADE_RETCODE_TOO_MANY_REQUESTS",
        "TRADE_RETCODE_TRADE_DISABLED",
        "copy_ticks_range",
    }
)
REVIEWED_MT5_DIRECT_METHODS = frozenset(
    {
        "account_info",
        "history_deals_get",
        "initialize",
        "last_error",
        "order_calc_margin",
        "order_calc_profit",
        "order_check",
        "order_send",
        "orders_get",
        "positions_get",
        "shutdown",
        "symbol_info",
        "symbol_info_tick",
    }
)

FORBIDDEN_DIRECTORY_NAMES = {
    ".git",
    ".venv",
    "__pycache__",
    "backups",
    "data",
    "history",
    "logs",
    "runtime_snapshots",
    "runtime_state",
    "validation_artifacts",
    "venv",
}
FORBIDDEN_SUFFIXES = {
    ".bak",
    ".backup",
    ".csv",
    ".db",
    ".env",
    ".gz",
    ".history",
    ".journal",
    ".key",
    ".log",
    ".mq5",
    ".mqh",
    ".p12",
    ".patch",
    ".pem",
    ".pfx",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".zip",
}
FORBIDDEN_BASENAMES = {
    ".env",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "mt5_bridge_reader.py",
    "mt5_executor_dry_run.py",
    "paper_executor.py",
    "paper_forward_runner.py",
    "paper_trade_monitor.py",
}
FORBIDDEN_PREFIXES = ("mql5/", "vps_package/")
SECRET_BYTE_PATTERNS = (
    re.compile(rb"-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[oprsu]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
MQL_ORDER_PATTERNS = (
    re.compile(rb"\bTRADE_ACTION_[A-Z0-9_]+\b"),
    re.compile(rb"\bCTrade\b"),
    re.compile(rb"\.(?:Buy|Sell)\s*\("),
)


def _gated_path_policy(path_text: str) -> None:
    folded = path_text.casefold()
    if folded.startswith(FORBIDDEN_PREFIXES):
        raise ReleaseBuildError(f"MQL5/file bridge path is forbidden: {path_text}")
    path = PurePosixPath(path_text)
    parts = tuple(part.casefold() for part in path.parts)
    if any(
        part in FORBIDDEN_DIRECTORY_NAMES or part in {"mql5", "vps_package"}
        for part in parts[:-1]
    ):
        raise ReleaseBuildError(f"runtime or private directory is forbidden: {path_text}")
    basename = parts[-1]
    if (
        basename in FORBIDDEN_BASENAMES
        or basename.startswith(".env.")
        or basename.startswith("paper_")
        or "bridge" in basename
    ):
        raise ReleaseBuildError(f"paper/file-bridge path is forbidden: {path_text}")
    tokens = {token for token in re.split(r"[^a-z0-9]+", basename) if token}
    if tokens.intersection({"backup", "bridge", "history", "paper"}):
        raise ReleaseBuildError(f"private/legacy artifact is forbidden: {path_text}")
    if path.suffix.casefold() in FORBIDDEN_SUFFIXES:
        raise ReleaseBuildError(f"release file type is forbidden: {path_text}")
    if path.suffix.casefold() == ".json" and parts[0] not in {"config", "vendor"}:
        raise ReleaseBuildError(
            f"JSON is allowed only as reviewed config/vendor metadata: {path_text}"
        )
    if path.suffix.casefold() == ".whl" and parts[:2] != ("vendor", "wheels"):
        raise ReleaseBuildError(f"wheel must be under vendor/wheels: {path_text}")


def _is_exact_adapter_call(node: ast.Call, primitive: str) -> bool:
    function = node.func
    return (
        isinstance(function, ast.Attribute)
        and function.attr == primitive
        and isinstance(function.value, ast.Attribute)
        and function.value.attr == "mt5"
        and isinstance(function.value.value, ast.Name)
        and function.value.value.id == "self"
    )


def _static_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_string(node.left)
        right = _static_string(node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.JoinedStr):
        pieces: list[str] = []
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                piece = _static_string(value.value)
            else:
                piece = _static_string(value)
            if piece is None:
                return None
            pieces.append(piece)
        return "".join(pieces)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and _static_string(node.func.value) is not None
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], (ast.List, ast.Tuple))
    ):
        separator = _static_string(node.func.value)
        pieces = [_static_string(item) for item in node.args[0].elts]
        if separator is not None and all(piece is not None for piece in pieces):
            return separator.join(piece for piece in pieces if piece is not None)
    return None


_ORDER_CAPABLE_NAMES = {
    "broker_module",
    "metatrader5",
    "mt5",
    "mt5_module",
}
_ORDER_CAPABLE_ATTRIBUTES = {
    "broker_module",
    "mt5",
    "mt5_module",
}
_REFLECTION_BUILTINS = {"getattr", "hasattr", "setattr", "delattr", "vars"}
_REFLECTION_SPECIAL_METHODS = {
    "__delattr__",
    "__getattribute__",
    "__setattr__",
}


def _assigned_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.List, ast.Tuple)):
        return {
            name
            for item in target.elts
            for name in _assigned_names(item)
        }
    return set()


def _is_metatrader_import_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Name) and node.func.id == "__import__":
        return bool(node.args and _static_string(node.args[0]) == "MetaTrader5")
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "import_module"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "importlib"
        and bool(node.args)
        and _static_string(node.args[0]) == "MetaTrader5"
    )


def _is_order_capable_expression(node: ast.AST, tainted_names: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id.casefold() in tainted_names
    if isinstance(node, ast.Attribute):
        return (
            node.attr.casefold() in _ORDER_CAPABLE_ATTRIBUTES
            or _is_order_capable_expression(node.value, tainted_names)
        )
    if isinstance(node, ast.Subscript):
        return _is_order_capable_expression(node.value, tainted_names)
    if isinstance(node, ast.Call):
        if _is_metatrader_import_call(node):
            return True
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"getattr", "hasattr"}
            and len(node.args) >= 2
            and _is_order_capable_expression(node.args[0], tainted_names)
            and _static_string(node.args[1]) == "copy_ticks_range"
        ):
            return True
        if isinstance(node.func, ast.Name) and node.func.id in {"globals", "locals"}:
            # A namespace mapping can expose an imported/bound MetaTrader
            # object.  Propagate taint only if the mapping is later reflected;
            # calling locals() for ordinary exception cleanup remains valid.
            return True
        return (
            isinstance(node.func, ast.Name)
            and node.func.id == "type"
            and bool(node.args)
            and _is_order_capable_expression(node.args[0], tainted_names)
        )
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        return any(
            _is_order_capable_expression(item, tainted_names)
            for item in node.elts
        )
    if isinstance(node, ast.Dict):
        return any(
            _is_order_capable_expression(item, tainted_names)
            for item in (*node.keys, *node.values)
            if item is not None
        )
    return False


def _order_capable_names(tree: ast.AST) -> set[str]:
    tainted = set(_ORDER_CAPABLE_NAMES)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.casefold() == "metatrader5":
                    tainted.add((alias.asname or alias.name).casefold())
        elif isinstance(node, ast.ImportFrom) and str(node.module or "").casefold() == "metatrader5":
            for alias in node.names:
                tainted.add((alias.asname or alias.name).casefold())
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            arguments = (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
            if node.args.vararg is not None:
                arguments += (node.args.vararg,)
            if node.args.kwarg is not None:
                arguments += (node.args.kwarg,)
            for argument in arguments:
                folded = argument.arg.casefold()
                if folded in _ORDER_CAPABLE_NAMES:
                    tainted.add(folded)

    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            targets: tuple[ast.AST, ...] = ()
            value: ast.AST | None = None
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                if isinstance(node, ast.Assign):
                    targets = tuple(node.targets)
                else:
                    targets = (node.target,)
                value = node.value
            if value is None or not _is_order_capable_expression(value, tainted):
                continue
            for target in targets:
                for name in _assigned_names(target):
                    folded = name.casefold()
                    if folded not in tainted:
                        tainted.add(folded)
                        changed = True
    return tainted


def _dynamic_order_reflection(node: ast.AST, tainted_names: set[str]) -> bool:
    if isinstance(node, ast.Attribute):
        return (
            node.attr == "__dict__"
            and _is_order_capable_expression(node.value, tainted_names)
        )
    if not isinstance(node, ast.Call):
        return False
    if isinstance(node.func, ast.Name):
        name = node.func.id
        if name in {"eval", "exec"}:
            return True
        if name in _REFLECTION_BUILTINS and node.args:
            target_is_order_capable = _is_order_capable_expression(
                node.args[0], tainted_names
            )
            if not target_is_order_capable:
                return False
            if name in {"setattr", "delattr", "vars"}:
                return True
            attribute = _static_string(node.args[1]) if len(node.args) >= 2 else None
            return attribute is None
    if isinstance(node.func, ast.Attribute):
        if (
            node.func.attr == "attrgetter"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "operator"
        ):
            return True
        if node.func.attr in _REFLECTION_SPECIAL_METHODS:
            return _is_order_capable_expression(
                node.func.value, tainted_names
            ) or bool(
                node.args
                and _is_order_capable_expression(node.args[0], tainted_names)
            )
    return False


def _passes_mt5_module_into_unreviewed_call(
    node: ast.AST,
    tainted_names: set[str],
    *,
    path_text: str,
) -> bool:
    """Forbid arbitrary wrapper/lambda/identity indirection of the MT5 module.

    Python reflection is too dynamic for a finite blacklist.  The release
    therefore permits a raw MetaTrader module value only in static-literal
    inspection and at the one reviewed composition constructor boundary.
    """

    if not isinstance(node, ast.Call):
        return False
    tainted_positional = [
        argument
        for argument in node.args
        if _is_order_capable_expression(argument, tainted_names)
    ]
    tainted_keywords = [
        keyword
        for keyword in node.keywords
        if _is_order_capable_expression(keyword.value, tainted_names)
    ]
    if not tainted_positional and not tainted_keywords:
        return False
    if (
        isinstance(node.func, ast.Name)
        and node.func.id in {"getattr", "hasattr"}
        and len(node.args) >= 2
        and _is_order_capable_expression(node.args[0], tainted_names)
        and _static_string(node.args[1]) is not None
        and not tainted_keywords
        and len(tainted_positional) == 1
    ):
        return False
    if (
        isinstance(node.func, ast.Name)
        and node.func.id == "callable"
        and len(node.args) == 1
        and len(tainted_positional) == 1
        and not tainted_keywords
    ):
        return False
    if (
        path_text == REQUIRED_ADAPTER
        and isinstance(node.func, ast.Name)
        and node.func.id == "verify_imported_mt5_module"
        and len(node.args) == 2
        and len(tainted_positional) == 1
        and tainted_positional[0] is node.args[0]
        and not tainted_keywords
    ):
        return False
    if (
        path_text == REQUIRED_BOOTSTRAP
        and isinstance(node.func, ast.Name)
        and node.func.id == "MT5Adapter"
        and not tainted_positional
        and len(tainted_keywords) == 1
        and tainted_keywords[0].arg == "mt5_module"
    ):
        return False
    return True


def _plain_assignment_target(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_plain_assignment_target(item) for item in node.elts)
    return False


def _stores_mt5_module_in_unreviewed_target(
    node: ast.AST,
    tainted_names: set[str],
    *,
    path_text: str,
) -> bool:
    targets: tuple[ast.AST, ...]
    value: ast.AST | None
    if isinstance(node, ast.Assign):
        targets, value = tuple(node.targets), node.value
    elif isinstance(node, (ast.AnnAssign, ast.NamedExpr, ast.AugAssign)):
        targets, value = (node.target,), node.value
    else:
        return False
    if value is None or not _is_order_capable_expression(value, tainted_names):
        return False
    for target in targets:
        if _plain_assignment_target(target):
            continue
        if (
            path_text == REQUIRED_ADAPTER
            and isinstance(target, ast.Attribute)
            and target.attr == "mt5"
            and isinstance(target.value, ast.Name)
            and target.value.id == "self"
        ):
            continue
        return True
    return False


def _is_self_mt5(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "mt5"
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    )


def _is_reviewed_service_factory_module_name(node: ast.AST) -> bool:
    """Match only the exact reviewed factory namespace selectors.

    The Windows service loader must inspect ``sys.modules`` to reject a
    preloaded or newly injected factory module.  The execution release scanner
    otherwise forbids raw namespace access because it could be used to recover
    the MetaTrader module and bypass the reviewed adapter.  Keep this exception
    deliberately narrower than a general ``sys.modules`` allowance.
    """

    return (
        isinstance(node, ast.Name)
        and node.id == "module_name"
        or isinstance(node, ast.Attribute)
        and node.attr == "factory_module"
        and isinstance(node.value, ast.Name)
        and node.value.id == "manifest"
    )


def _is_reviewed_service_sys_modules_reference(
    node: ast.Attribute,
    parent: Mapping[ast.AST, ast.AST],
) -> bool:
    """Allow only the exact factory guard and module-audit traversal shapes."""

    owner: ast.AST | None = node
    while owner is not None and not isinstance(
        owner, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        owner = parent.get(owner)
    owner_name = owner.name if isinstance(owner, ast.FunctionDef) else None

    direct_parent = parent.get(node)
    if isinstance(direct_parent, ast.Compare):
        return (
            len(direct_parent.ops) == 1
            and isinstance(direct_parent.ops[0], (ast.In, ast.NotIn))
            and len(direct_parent.comparators) == 1
            and direct_parent.comparators[0] is node
            and _is_reviewed_service_factory_module_name(direct_parent.left)
        )
    if (
        isinstance(direct_parent, ast.Attribute)
        and direct_parent.value is node
        and direct_parent.attr == "pop"
    ):
        call = parent.get(direct_parent)
        return (
            isinstance(call, ast.Call)
            and call.func is direct_parent
            and 1 <= len(call.args) <= 2
            and not call.keywords
            and _is_reviewed_service_factory_module_name(call.args[0])
            and (
                len(call.args) == 1
                or isinstance(call.args[1], ast.Constant)
                and call.args[1].value is None
            )
        )
    if (
        owner_name in {"_snapshot_module_registry", "_verify_module_registry_delta"}
        and isinstance(direct_parent, ast.Attribute)
        and direct_parent.value is node
        and direct_parent.attr == "items"
    ):
        call = parent.get(direct_parent)
        return (
            isinstance(call, ast.Call)
            and call.func is direct_parent
            and not call.args
            and not call.keywords
        )
    return False


def _service_dynamic_import_guard_violation(
    tree: ast.AST,
    *,
    path_text: str,
) -> bool:
    """Keep low-level import bypasses out of every release module.

    A future reviewed factory is selected by its signed runtime manifest, so
    the release builder cannot safely identify it by one hard-coded filename.
    Dynamic loaders are therefore denied across the complete allowlisted
    source set.  The only exceptions are the exact service file-loader helpers
    and the deny-only validation entrypoint's fixed module inventory imports.
    """
    parent = {
        child: node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }

    def owner_name(node: ast.AST) -> str | None:
        owner: ast.AST | None = node
        while owner is not None and not isinstance(
            owner, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            owner = parent.get(owner)
        return owner.name if isinstance(owner, ast.FunctionDef) else None

    def reviewed_validator_import(node: ast.Call) -> bool:
        if path_text != REQUIRED_ENTRYPOINT:
            return False
        if owner_name(node) != "validate_gated_execution_ports":
            return False
        if node.keywords or len(node.args) != 1:
            return False
        argument = node.args[0]
        return (
            isinstance(argument, ast.Name)
            and argument.id == "module_name"
            or isinstance(argument, ast.Constant)
            and argument.value == "execution_policy"
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "importlib":
            if any(alias.name in {"__import__", "import_module", "reload"} for alias in node.names):
                return True
        if isinstance(node, ast.Attribute):
            if node.attr in {"_bootstrap", "_bootstrap_external", "machinery"}:
                return True
            if (
                node.attr in {"find_spec", "module_from_spec", "spec_from_file_location", "spec_from_loader"}
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "util"
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "importlib"
            ):
                call = parent.get(node)
                if not (
                    path_text == REQUIRED_SERVICE_RUNTIME
                    and
                    isinstance(call, ast.Call)
                    and call.func is node
                    and owner_name(node) == "_load_exact_factory_module"
                    and node.attr in {"module_from_spec", "spec_from_file_location"}
                ):
                    return True
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in {
            "__import__",
            "import_module",
        }:
            return True
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"__import__", "import_module", "reload"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "importlib"
        ):
            if node.func.attr == "import_module" and reviewed_validator_import(node):
                continue
            return True
    return False


def _raw_mt5_reference_violation(tree: ast.AST, *, path_text: str) -> bool:
    """Deny raw MT5 references unless their complete parent shape is reviewed."""

    parent = {
        child: node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    import_aliases = {
        (alias.asname or alias.name).casefold()
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name.casefold() == "metatrader5"
    }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "modules"
            and isinstance(node.value, ast.Name)
            and node.value.id == "sys"
        ):
            if path_text == REQUIRED_MT5_ATTESTATION:
                continue
            if path_text == REQUIRED_SERVICE_RUNTIME and (
                _is_reviewed_service_sys_modules_reference(node, parent)
            ):
                continue
            else:
                return True
        if isinstance(node, ast.Import):
            if any(alias.name.casefold() == "metatrader5" for alias in node.names):
                owner: ast.AST | None = node
                while owner is not None and not isinstance(
                    owner, (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    owner = parent.get(owner)
                if not (
                    path_text == REQUIRED_ADAPTER
                    and len(node.names) == 1
                    and node.names[0].name == "MetaTrader5"
                    and node.names[0].asname == "module"
                    and isinstance(owner, ast.FunctionDef)
                    and owner.name == "load_and_attest_module"
                ):
                    return True
        elif (
            isinstance(node, ast.ImportFrom)
            and str(node.module or "").casefold() == "metatrader5"
        ):
            return True
        elif isinstance(node, ast.Call) and _is_metatrader_import_call(node):
            return True

        if isinstance(node, ast.Name) and node.id.casefold() in (
            {"metatrader5", "mt5", "mt5_module"} | import_aliases
        ):
            direct_parent = parent.get(node)
            if path_text == REQUIRED_ADAPTER:
                assignment = direct_parent
                if (
                    isinstance(assignment, (ast.Assign, ast.AnnAssign))
                    and assignment.value is node
                    and any(
                        _is_self_mt5(target)
                        for target in (
                            assignment.targets
                            if isinstance(assignment, ast.Assign)
                            else (assignment.target,)
                        )
                    )
                ):
                    continue
                if (
                    isinstance(direct_parent, ast.Call)
                    and isinstance(direct_parent.func, ast.Name)
                    and direct_parent.func.id == "verify_imported_mt5_module"
                    and direct_parent.args
                    and direct_parent.args[0] is node
                ):
                    continue
            if path_text == REQUIRED_BOOTSTRAP and (
                isinstance(direct_parent, ast.AnnAssign)
                and direct_parent.target is node
                and direct_parent.value is None
            ):
                continue
            return True

        raw_attribute = (
            _is_self_mt5(node)
            or isinstance(node, ast.Attribute)
            and node.attr.casefold() == "mt5_module"
        )
        if not raw_attribute:
            continue
        direct_parent = parent.get(node)
        if path_text == REQUIRED_ADAPTER and _is_self_mt5(node):
            if (
                isinstance(direct_parent, (ast.Assign, ast.AnnAssign))
                and (
                    node in direct_parent.targets
                    if isinstance(direct_parent, ast.Assign)
                    else direct_parent.target is node
                )
            ):
                continue
            if (
                isinstance(direct_parent, ast.Compare)
                and direct_parent.left is node
                and len(direct_parent.ops) == 1
                and isinstance(direct_parent.ops[0], (ast.Is, ast.IsNot))
                and len(direct_parent.comparators) == 1
                and isinstance(direct_parent.comparators[0], ast.Constant)
                and direct_parent.comparators[0].value is None
            ):
                continue
            if (
                isinstance(direct_parent, ast.Attribute)
                and direct_parent.value is node
                and direct_parent.attr in REVIEWED_MT5_DIRECT_METHODS
                and isinstance(parent.get(direct_parent), ast.Call)
                and parent[direct_parent].func is direct_parent
            ):
                continue
            if (
                isinstance(direct_parent, ast.Call)
                and isinstance(direct_parent.func, ast.Name)
                and direct_parent.func.id in {"getattr", "hasattr"}
                and len(direct_parent.args) >= 2
                and direct_parent.args[0] is node
                and _static_string(direct_parent.args[1])
                in REVIEWED_MT5_STATIC_ATTRIBUTES
            ):
                continue
        if path_text == REQUIRED_BOOTSTRAP and isinstance(
            direct_parent, ast.keyword
        ):
            constructor = parent.get(direct_parent)
            if (
                direct_parent.arg == "mt5_module"
                and isinstance(constructor, ast.Call)
                and isinstance(constructor.func, ast.Name)
                and constructor.func.id == "MT5Adapter"
            ):
                continue
        if (
            path_text == REQUIRED_BOOTSTRAP
            and isinstance(node, ast.Attribute)
            and node.attr == "mt5_module"
            and isinstance(direct_parent, ast.Compare)
            and direct_parent.left is node
            and len(direct_parent.ops) == 1
            and isinstance(direct_parent.ops[0], (ast.Is, ast.IsNot))
            and len(direct_parent.comparators) == 1
            and isinstance(direct_parent.comparators[0], ast.Constant)
            and direct_parent.comparators[0].value is None
        ):
            continue
        if (
            path_text == REQUIRED_ADAPTER
            and _is_self_mt5(node)
            and isinstance(direct_parent, ast.Call)
            and isinstance(direct_parent.func, ast.Name)
            and direct_parent.func.id == "verify_imported_mt5_module"
            and direct_parent.args
            and direct_parent.args[0] is node
        ):
            continue
        return True
    return False


def _python_order_primitive_counts(path_text: str, data: bytes) -> dict[str, int]:
    try:
        tree = ast.parse(data.decode("utf-8"), filename=path_text)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ReleaseBuildError(f"invalid Python release input: {path_text}") from exc

    if _service_dynamic_import_guard_violation(tree, path_text=path_text):
        raise ReleaseBuildError(
            f"unreviewed dynamic import bypass in service loader: {path_text}"
        )

    attribute_counts = {primitive: 0 for primitive in ORDER_PRIMITIVES}
    exact_call_counts = {primitive: 0 for primitive in ORDER_PRIMITIVES}
    indirect: list[str] = []
    dynamic_reflection = False
    unreviewed_module_pass = False
    unreviewed_module_storage = False
    raw_mt5_reference_violation = _raw_mt5_reference_violation(
        tree, path_text=path_text
    )
    tainted_names = _order_capable_names(tree)
    for node in ast.walk(tree):
        static_value = _static_string(node)
        if static_value in ORDER_PRIMITIVES:
            indirect.append(static_value)
        if isinstance(node, ast.Name) and node.id in ORDER_PRIMITIVES:
            indirect.append(node.id)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name.rsplit(".", 1)[-1] in ORDER_PRIMITIVES:
                    indirect.append(alias.name.rsplit(".", 1)[-1])
                if alias.asname in ORDER_PRIMITIVES:
                    indirect.append(str(alias.asname))
        if isinstance(node, ast.Attribute) and node.attr in ORDER_PRIMITIVES:
            attribute_counts[node.attr] += 1
        if _dynamic_order_reflection(node, tainted_names):
            dynamic_reflection = True
        if _passes_mt5_module_into_unreviewed_call(
            node, tainted_names, path_text=path_text
        ):
            unreviewed_module_pass = True
        if _stores_mt5_module_in_unreviewed_target(
            node, tainted_names, path_text=path_text
        ):
            unreviewed_module_storage = True
        if isinstance(node, ast.Call):
            for primitive in ORDER_PRIMITIVES:
                if _is_exact_adapter_call(node, primitive):
                    exact_call_counts[primitive] += 1
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in ORDER_PRIMITIVES
            ):
                indirect.append(str(node.args[1].value))
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value in ORDER_PRIMITIVES
        ):
            indirect.append(str(node.slice.value))

    if path_text != REQUIRED_ADAPTER:
        found = (
            sum(attribute_counts.values())
            + len(indirect)
            + int(dynamic_reflection)
            + int(unreviewed_module_pass)
            + int(unreviewed_module_storage)
            + int(raw_mt5_reference_violation)
        )
        if found:
            raise ReleaseBuildError(
                f"order primitive or alias outside reviewed adapter: {path_text}"
            )
        return {primitive: 0 for primitive in ORDER_PRIMITIVES}

    if (
        indirect
        or dynamic_reflection
        or unreviewed_module_pass
        or unreviewed_module_storage
        or raw_mt5_reference_violation
    ):
        raise ReleaseBuildError(
            "indirect or dynamic order primitive reflection is forbidden in adapter"
        )
    for primitive in ORDER_PRIMITIVES:
        if attribute_counts[primitive] != 1 or exact_call_counts[primitive] != 1:
            raise ReleaseBuildError(
                "reviewed adapter must contain exactly one direct "
                f"self.mt5.{primitive}(...) call"
            )
    return exact_call_counts


def _gated_content_policy(path_text: str, data: bytes) -> dict[str, int]:
    for pattern in SECRET_BYTE_PATTERNS:
        if pattern.search(data):
            raise ReleaseBuildError(f"probable embedded secret in {path_text}")
    if PurePosixPath(path_text).suffix.casefold() in {".mq5", ".mqh"}:
        for pattern in MQL_ORDER_PATTERNS:
            if pattern.search(data):
                raise ReleaseBuildError(
                    f"MQL5/file-bridge order primitive is forbidden: {path_text}"
                )
    counts = {primitive: 0 for primitive in ORDER_PRIMITIVES}
    if path_text.endswith(".py"):
        counts = _python_order_primitive_counts(path_text, data)
    if path_text.casefold().endswith(".json"):
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReleaseBuildError(f"invalid JSON release input: {path_text}") from exc
        secret_path = _json_contains_secret(payload)
        if secret_path is not None:
            raise ReleaseBuildError(
                f"sensitive JSON value is forbidden: {path_text}:{secret_path}"
            )
    return counts


def load_execution_allowlist(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError(f"invalid execution release allowlist: {path}") from exc
    if not isinstance(payload, dict) or set(payload) != ALLOWLIST_FIELDS:
        raise ReleaseBuildError("execution release allowlist root fields drift")
    if payload.get("schema_version") != ALLOWLIST_SCHEMA:
        raise ReleaseBuildError("unsupported execution release allowlist schema")
    if payload.get("safety") != REQUIRED_SAFETY:
        raise ReleaseBuildError("execution safety locks do not match immutable policy")
    if payload.get("usage_policy") != REQUIRED_USAGE_POLICY:
        raise ReleaseBuildError("execution usage policy does not match immutable policy")
    profile = payload.get("release_profile")
    if not isinstance(profile, str) or not profile.strip():
        raise ReleaseBuildError("execution release profile is missing")
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        raise ReleaseBuildError("execution release files must be a non-empty list")
    normalized = [_normalize_relative_path(item) for item in files]
    if len(normalized) != len(set(normalized)):
        raise ReleaseBuildError("duplicate execution release path")
    if len(normalized) != len({item.casefold() for item in normalized}):
        raise ReleaseBuildError("case-insensitive execution release path collision")
    for item in normalized:
        _gated_path_policy(item)
    required = {
        REQUIRED_ADAPTER,
        REQUIRED_BOOTSTRAP,
        REQUIRED_MT5_ATTESTATION,
        REQUIRED_ENTRYPOINT,
        REQUIRED_DEMO_AUTO_IPC_CONSUMER,
        REQUIRED_DEMO_AUTO_RISK_INTENT_PIPELINE,
        REQUIRED_DEMO_AUTO_SESSION_CAPABILITY,
        REQUIRED_DEMO_AUTO_SOAK_COHORT,
        REQUIRED_DEMO_AUTO_SOAK_PROJECTION,
        REQUIRED_DEMO_AUTO_SOAK_TRACKER,
        REQUIRED_LIVE_GRADE_GATE_CATALOG,
        REQUIRED_SIGNED_RELEASE_TRUST,
        REQUIRED_ASYMMETRIC_RELEASE_TRUST,
        REQUIRED_FACTORY_TEMPLATE,
        REQUIRED_CONFIG,
        *REQUIRED_DEPENDENCY_FILES,
    }
    if not required.issubset(normalized):
        raise ReleaseBuildError(
            "execution allowlist is missing bootstrap, adapter, MT5 attestation, "
            "DEMO_AUTO IPC/risk-intent/session/soak projection/cohort foundations, "
            "readiness gate catalog, signed release-trust foundation, static factory template, "
            "validator, or embedded config"
        )
    result = dict(payload)
    result["files"] = normalized
    result["_raw_sha256"] = _sha256(raw)
    return result


def _normalized_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _dependency_lines(data: bytes, path_text: str) -> list[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseBuildError(f"dependency file is not UTF-8: {path_text}") from exc
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _validate_dependency_lock_set(source_bytes: Mapping[str, bytes]) -> dict[str, Any]:
    missing = REQUIRED_DEPENDENCY_FILES.difference(source_bytes)
    if missing:
        raise ReleaseBuildError(
            "execution dependency lock set is incomplete: " + ", ".join(sorted(missing))
        )
    direct_pattern = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s]+)$")
    locked_pattern = re.compile(
        r"^([A-Za-z0-9_.-]+)==([^\s]+) --hash=sha256:([0-9a-f]{64})$"
    )
    direct: dict[str, str] = {}
    for line in _dependency_lines(
        source_bytes["requirements-live-windows.txt"],
        "requirements-live-windows.txt",
    ):
        match = direct_pattern.fullmatch(line)
        if match is None:
            raise ReleaseBuildError("direct Windows requirement is not exactly pinned")
        name = _normalized_distribution_name(match.group(1))
        if name in direct:
            raise ReleaseBuildError(f"duplicate direct Windows requirement: {name}")
        direct[name] = match.group(2)

    resolved: dict[str, str] = {}
    for line in _dependency_lines(
        source_bytes["requirements-windows-cp312.lock.txt"],
        "requirements-windows-cp312.lock.txt",
    ):
        match = locked_pattern.fullmatch(line)
        if match is None:
            raise ReleaseBuildError("resolved Windows requirement is not hash pinned")
        name = _normalized_distribution_name(match.group(1))
        if name in resolved:
            raise ReleaseBuildError(f"duplicate resolved Windows requirement: {name}")
        resolved[name] = match.group(2)
    if not direct or any(resolved.get(name) != version for name, version in direct.items()):
        raise ReleaseBuildError("direct requirements and resolved Windows lock drift")

    try:
        pylock = tomllib.loads(source_bytes["pylock.windows-cp312.toml"].decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseBuildError("Windows pylock is invalid") from exc
    tool = pylock.get("tool")
    intent = tool.get("ai_scalper") if isinstance(tool, dict) else None
    expected_target = {
        "target-python": "3.12",
        "target-implementation": "CPython",
        "target-platform": "win_amd64",
        "target-architecture": "x86_64",
    }
    if (
        pylock.get("lock-version") != "1.0"
        or pylock.get("requires-python") != ">=3.12"
        or not isinstance(intent, dict)
        or any(intent.get(key) != value for key, value in expected_target.items())
        or intent.get("source-manifests") != ["requirements-live-windows.txt"]
    ):
        raise ReleaseBuildError("Windows pylock target metadata drift")
    packages = pylock.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ReleaseBuildError("Windows pylock package closure is missing")
    pylock_versions: dict[str, str] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise ReleaseBuildError("Windows pylock package entry is invalid")
        raw_name = package.get("name")
        version = package.get("version")
        if not isinstance(raw_name, str) or not isinstance(version, str):
            raise ReleaseBuildError("Windows pylock package identity is invalid")
        name = _normalized_distribution_name(raw_name)
        if name in pylock_versions:
            raise ReleaseBuildError(f"duplicate Windows pylock package: {name}")
        pylock_versions[name] = version
    if pylock_versions != resolved:
        raise ReleaseBuildError("resolved requirements and Windows pylock closure drift")
    return {
        "direct_requirement_count": len(direct),
        "resolved_package_count": len(resolved),
        "target_python": "3.12",
        "target_platform": "win_amd64",
        "lock_files": sorted(REQUIRED_DEPENDENCY_FILES),
    }


def _read_execution_sources(
    root: Path,
    paths: Iterable[str],
    tracked: set[str],
    *,
    commit: str | None = None,
) -> tuple[dict[str, bytes], list[dict[str, Any]]]:
    result: dict[str, bytes] = {}
    total_bytes = 0
    inventory: list[dict[str, Any]] = []
    resolved_root = root.resolve()
    for path_text in paths:
        if path_text not in tracked:
            raise ReleaseBuildError(f"allowlisted file is not tracked: {path_text}")
        _gated_path_policy(path_text)
        path = root / Path(path_text)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ReleaseBuildError(f"allowlisted file is unavailable: {path_text}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ReleaseBuildError(f"allowlisted path is not a regular file: {path_text}")
        current = root
        for part in PurePosixPath(path_text).parts[:-1]:
            current = current / part
            try:
                if stat.S_ISLNK(current.lstat().st_mode):
                    raise ReleaseBuildError(
                        f"symlinked release path component is forbidden: {path_text}"
                    )
            except OSError as exc:
                raise ReleaseBuildError(
                    f"allowlisted path component is unavailable: {path_text}"
                ) from exc
        try:
            path.resolve(strict=True).relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise ReleaseBuildError(f"allowlisted path escapes source root: {path_text}") from exc
        if commit is None and metadata.st_size > MAX_SOURCE_FILE_BYTES:
            raise ReleaseBuildError(f"allowlisted file is too large: {path_text}")
        if commit is not None:
            # Build from the immutable Git blob. Git may materialize CRLF in a
            # clean Windows checkout, so raw worktree equality is neither
            # portable nor needed for a commit-addressed release.
            data = bytes(_git(root, "show", f"{commit}:{path_text}", binary=True))
        else:
            try:
                data = path.read_bytes()
            except OSError as exc:
                raise ReleaseBuildError(
                    f"allowlisted file cannot be read: {path_text}"
                ) from exc
        if len(data) > MAX_SOURCE_FILE_BYTES:
            raise ReleaseBuildError(f"allowlisted file is too large: {path_text}")
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_SOURCE_BYTES:
            raise ReleaseBuildError("release source exceeds total size limit")
        counts = _gated_content_policy(path_text, data)
        for primitive in ORDER_PRIMITIVES:
            if counts[primitive]:
                inventory.append(
                    {"path": path_text, "primitive": primitive, "count": counts[primitive]}
                )
        result[path_text] = data
    _verify_local_import_closure(root, result)
    expected = [
        {"path": REQUIRED_ADAPTER, "primitive": primitive, "count": 1}
        for primitive in ORDER_PRIMITIVES
    ]
    if sorted(inventory, key=lambda item: item["primitive"]) != expected:
        raise ReleaseBuildError("reviewed order primitive inventory drift")
    return result, expected


def build_execution_release(
    root: Path,
    allowlist_path: Path,
    output_path: Path,
    *,
    manifest_output_path: Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    allowlist_path = allowlist_path.resolve()
    try:
        allowlist_relative = allowlist_path.relative_to(root).as_posix()
    except ValueError as exc:
        raise ReleaseBuildError("execution allowlist must be inside source repository") from exc
    if (
        PurePosixPath(allowlist_relative).parent.as_posix() != "config"
        or ALLOWLIST_NAME_PATTERN.fullmatch(PurePosixPath(allowlist_relative).name) is None
    ):
        raise ReleaseBuildError("execution allowlist must be the versioned execution config")
    resolved_output = output_path.resolve()
    sidecar = (
        output_path.with_suffix(output_path.suffix + ".manifest.json")
        if manifest_output_path is None
        else manifest_output_path
    ).resolve()
    for destination in (resolved_output, sidecar):
        try:
            destination.relative_to(root)
        except ValueError:
            pass
        else:
            raise ReleaseBuildError("release outputs must be outside source repository")

    commit, tree, tracked = _validate_git_release_source(root)
    allowlist = load_execution_allowlist(allowlist_path)
    if allowlist_relative not in allowlist["files"]:
        raise ReleaseBuildError("execution allowlist must include itself")
    sources, primitive_inventory = _read_execution_sources(
        root, allowlist["files"], tracked, commit=commit
    )
    allowlist["_raw_sha256"] = _sha256(sources[allowlist_relative])
    dependency_lock_summary = _validate_dependency_lock_set(sources)
    full_gate_report = catalog_report()
    full_pending_gate_catalog = {
        "schema_version": full_gate_report["schema_version"],
        "pending_gate_count": full_gate_report["pending_gate_count"],
        "pending_gates": list(full_gate_report["pending_gates"]),
        "pending_by_category": {
            category: list(full_gate_report["pending_by_category"][category])
            for category in (
                "EXTERNAL_CONFIGURATION",
                "TEMPORAL_EVIDENCE",
                "MANUAL_APPROVAL",
            )
        },
        "production_execution_ready": False,
    }
    try:
        embedded = json.loads(sources[allowlist_relative].decode("utf-8"))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError("embedded execution allowlist is invalid") from exc
    expected_embedded = {field: allowlist[field] for field in ALLOWLIST_FIELDS}
    if (
        embedded != expected_embedded
        or _sha256(sources[allowlist_relative]) != allowlist["_raw_sha256"]
    ):
        raise ReleaseBuildError("loaded execution allowlist does not match commit")

    manifest_base: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA,
        "release_profile": allowlist["release_profile"],
        "git_commit": commit,
        "git_tree": tree,
        "allowlist_sha256": allowlist["_raw_sha256"],
        "safety": dict(allowlist["safety"]),
        "usage_policy": dict(allowlist["usage_policy"]),
        "activation_requires": list(ACTIVATION_REQUIRES),
        "order_primitive_inventory": primitive_inventory,
        "dependency_lock_summary": dependency_lock_summary,
        "production_execution_ready": False,
        "readiness_blockers": list(READINESS_BLOCKERS),
        "readiness_blockers_by_category": {
            category: list(codes)
            for category, codes in classify_gate_codes(
                READINESS_BLOCKERS
            ).items()
        },
        "full_pending_gate_catalog": full_pending_gate_catalog,
        "demo_auto_gate_semantics": {
            "soak_output_gate_codes": [
                "DEMO_AUTO_SOAK_30_DAYS_REQUIRED",
                "DEMO_AUTO_SOAK_50_CLOSED_FILLS_REQUIRED",
                "DEMO_AUTO_SOAK_20_XAUUSD_CLOSED_FILLS_REQUIRED",
            ],
            "soak_output_is_demo_auto_entry_prerequisite": False,
            "purpose": "POST_ACTIVATION_SOAK_AND_LIVE_PROMOTION_EVIDENCE",
        },
        "decision_process": {
            "bundle_membership": "SEPARATE_NOT_INCLUDED",
            "foundation": "BROKERLESS_DECISION_PRODUCER_PRESENT",
            "external_data_configuration": "REQUIRED",
        },
        "foundation_status": {
            "demo_auto_ipc_consumer": (
                "PRESENT_NON_EXECUTABLE_EXTERNAL_CONFIGURATION_REQUIRED"
            ),
            "demo_auto_risk_intent_pipeline": (
                "PRESENT_LOCKED_NON_EXECUTABLE_ONE_USE_JOURNAL_BOUND"
            ),
            "demo_auto_session_capability": (
                "PRESENT_DORMANT_RENEWABLE_EXTERNAL_CAS_CUSTODY_REQUIRED"
            ),
            "demo_auto_soak_projection": (
                "PRESENT_NON_AUTHORITY_OUTPUT_ONLY_EXTERNAL_CUSTODY_REQUIRED"
            ),
            "demo_auto_soak_cohort": (
                "PRESENT_DENY_ONLY_ACCOUNT_LEVEL_30_DAY_50_FILL_20_XAU_AGGREGATOR"
            ),
            "demo_auto_soak_tracker": (
                "PRESENT_DENY_ONLY_POST_ACTIVATION_EVIDENCE_ACCOUNTING"
            ),
            "live_grade_gate_catalog": (
                "PRESENT_DENY_BY_DEFAULT_CATEGORY_CLASSIFICATION"
            ),
            "brokerless_decision_producer": (
                "SEPARATE_DECISION_PROCESS_NOT_BUNDLED_"
                "EXTERNAL_DATA_CONFIGURATION_REQUIRED"
            ),
            "signed_release_trust": (
                "PRESENT_HMAC_LOCAL_TEST_ONLY_PRODUCTION_ASYMMETRIC_OR_"
                "EXTERNAL_LAUNCHER_REQUIRED"
            ),
            "asymmetric_release_trust": (
                "PRESENT_RSA3072_PUBLIC_VERIFY_EXTERNAL_ATTESTATION_REQUIRED"
            ),
            "windows_service_factory_template": (
                "PRESENT_STATIC_NON_MATERIALIZING_EXTERNAL_PROVIDER_"
                "CONFIGURATION_REQUIRED"
            ),
        },
        "source_files": [
            {
                "path": path_text,
                "size_bytes": len(sources[path_text]),
                "sha256": _sha256(sources[path_text]),
            }
            for path_text in sorted(sources)
        ],
    }
    identity = _sha256(_canonical_json(manifest_base))
    manifest = {**manifest_base, "release_identity_sha256": identity}
    manifest_bytes = _canonical_json(manifest) + b"\n"
    archive_bytes = _create_archive(sources, manifest_bytes)
    _write_exclusive(resolved_output, archive_bytes)
    try:
        _write_exclusive(sidecar, manifest_bytes)
    except Exception:
        try:
            resolved_output.unlink()
        except OSError:
            pass
        raise
    try:
        if (
            str(_git(root, "rev-parse", "HEAD")) != commit
            or str(_git(root, "rev-parse", "HEAD^{tree}")) != tree
            or _git(
                root,
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                binary=True,
            )
        ):
            raise ReleaseBuildError("release source changed during construction")
    except Exception:
        for destination in (resolved_output, sidecar):
            try:
                destination.unlink()
            except OSError:
                pass
        raise
    return {
        "archive": str(resolved_output),
        "archive_sha256": _sha256(archive_bytes),
        "manifest": str(sidecar),
        "release_identity_sha256": identity,
        "file_count": len(sources),
        "production_execution_ready": False,
        "order_capability": "GATED_PRESENT",
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build deterministic Windows GATED execution-service release"
    )
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = build_execution_release(
            REPO_ROOT,
            args.allowlist,
            args.output,
            manifest_output_path=args.manifest_output,
        )
    except ReleaseBuildError as exc:
        print(f"EXECUTION_RELEASE_REJECTED: {exc}")
        return 2
    print(f"Execution release written: {result['archive']}")
    print(f"Release SHA-256: {result['archive_sha256']}")
    print(f"Release identity: {result['release_identity_sha256']}")
    print(f"Manifest: {result['manifest']}")
    print(f"Files: {result['file_count']}")
    print("Order capability: GATED_PRESENT")
    print("Production execution ready: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
