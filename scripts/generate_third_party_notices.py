#!/usr/bin/env python3
"""Generate deterministic dependency attribution from reviewed local inputs.

Python metadata is read from an explicitly supplied clean interpreter.  Node
metadata is read from package-lock.json.  The output is an inventory aid, not
a legal conclusion or a substitute for upstream license texts.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_NODE_LOCK = ROOT / "frontend-dashboard" / "package-lock.json"
DEFAULT_OUTPUT = ROOT / "THIRD_PARTY_NOTICES.md"
FRONTEND_SECTION = "## Frontend dependencies\n"
PLATFORM_SPECIFIC_PYTHON_PACKAGES = {"colorama", "uvloop"}


class NoticeGenerationError(RuntimeError):
    """The attribution inventory could not be generated safely."""


PYTHON_INVENTORY_HELPER = r"""
import importlib.metadata as metadata
import json
import sys

excluded = {"ai-scalper-backend", "pip", "setuptools", "wheel"}
packages = []
for distribution in metadata.distributions():
    name = str(distribution.metadata.get("Name") or "").strip()
    if not name or name.casefold() in excluded:
        continue
    license_value = str(
        distribution.metadata.get("License-Expression")
        or distribution.metadata.get("License")
        or ""
    ).strip()
    if not license_value:
        classifiers = [
            value.removeprefix("License :: ").strip()
            for value in (distribution.metadata.get_all("Classifier") or [])
            if value.startswith("License :: ")
        ]
        license_value = "; ".join(classifiers)
    project_urls = []
    for value in distribution.metadata.get_all("Project-URL") or []:
        _, separator, url = value.partition(",")
        if separator and url.strip():
            project_urls.append(url.strip())
    home_page = str(distribution.metadata.get("Home-page") or "").strip()
    packages.append(
        {
            "name": name,
            "version": distribution.version,
            "license": license_value or "NOT_DECLARED_IN_METADATA",
            "url": project_urls[0] if project_urls else home_page,
        }
    )
print(
    json.dumps(
        {
            "python_version": ".".join(map(str, sys.version_info[:2])),
            "packages": sorted(packages, key=lambda item: item["name"].casefold()),
        },
        sort_keys=True,
    )
)
"""


def _markdown(value: object) -> str:
    return str(value).replace("\n", " ").replace("\r", " ").replace("|", "\\|").strip()


def _python_inventory(executable: Path) -> dict[str, Any]:
    if not executable.is_file():
        raise NoticeGenerationError(f"clean Python executable not found: {executable}")
    completed = subprocess.run(
        [str(executable), "-I", "-B", "-c", PYTHON_INVENTORY_HELPER],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()[-1:] or ["unknown error"]
        raise NoticeGenerationError(f"Python metadata collection failed: {detail[0]}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise NoticeGenerationError("Python metadata collector returned invalid JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("packages"), list):
        raise NoticeGenerationError("Python metadata collector returned an invalid schema")
    return payload


def _node_inventory(lock_path: Path) -> tuple[int, list[dict[str, str]]]:
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NoticeGenerationError(f"cannot read Node lockfile: {lock_path}") from exc
    packages = payload.get("packages")
    lock_version = payload.get("lockfileVersion")
    if not isinstance(lock_version, int) or not isinstance(packages, dict):
        raise NoticeGenerationError("Node lockfile has an unsupported schema")
    rows: list[dict[str, str]] = []
    for package_path, metadata in packages.items():
        if not package_path or not isinstance(metadata, dict):
            continue
        version = metadata.get("version")
        license_value = metadata.get("license")
        if not isinstance(version, str) or not version:
            continue
        name = str(metadata.get("name") or package_path.rsplit("node_modules/", 1)[-1])
        rows.append(
            {
                "name": name,
                "version": version,
                "license": (
                    str(license_value).strip()
                    if isinstance(license_value, str) and license_value.strip()
                    else "NOT_DECLARED_IN_LOCKFILE"
                ),
                "scope": "development" if metadata.get("dev") is True else "runtime",
                "path": str(package_path),
            }
        )
    rows.sort(key=lambda item: (item["name"].casefold(), item["version"], item["path"]))
    return lock_version, rows


def render_notice(python_payload: dict[str, Any], lock_version: int, node_rows: list[dict[str, str]]) -> str:
    python_rows = python_payload["packages"]
    python_unknown = sum(row["license"] == "NOT_DECLARED_IN_METADATA" for row in python_rows)
    node_unknown = sum(row["license"] == "NOT_DECLARED_IN_LOCKFILE" for row in node_rows)
    lines = [
        "# Third-Party Notices",
        "",
        "This file is a deterministic dependency-attribution inventory generated from a clean Python environment and the committed frontend lockfile. License strings are copied from installed distribution metadata or `package-lock.json`; they are not a legal interpretation and do not replace upstream license texts.",
        "",
        "The repository does not currently contain a project `LICENSE`. Selecting the AI_SCALPER project license remains an owner decision. Before redistribution, the owner must review every undeclared or ambiguous entry and bundle any full license or notice text required by the upstream project.",
        "",
        "Regenerate with:",
        "",
        "```bash",
        "python3 scripts/generate_third_party_notices.py --python /path/to/clean/root/bin/python",
        "python3 scripts/generate_third_party_notices.py --python /path/to/clean/root/bin/python --check",
        "```",
        "",
        f"Inventory summary: Python {python_payload['python_version']}, {len(python_rows)} Python distributions ({python_unknown} without declared license metadata), npm lockfile v{lock_version}, {len(node_rows)} locked Node package entries ({node_unknown} without declared license metadata).",
        "",
        "## Python dependencies",
        "",
        "| Package | Version | License metadata | Project URL |",
        "|---|---:|---|---|",
    ]
    for row in python_rows:
        url = _markdown(row.get("url") or "NOT_DECLARED_IN_METADATA")
        lines.append(
            f"| {_markdown(row['name'])} | {_markdown(row['version'])} | {_markdown(row['license'])} | {url} |"
        )
    lines.extend(
        [
            "",
            "## Frontend dependencies",
            "",
            "Multiple rows for one package are intentional when the lockfile contains distinct versions or nested paths.",
            "",
            "| Package | Version | Scope | License metadata | Lockfile path |",
            "|---|---:|---|---|---|",
        ]
    )
    for row in node_rows:
        lines.append(
            f"| {_markdown(row['name'])} | {_markdown(row['version'])} | {_markdown(row['scope'])} | {_markdown(row['license'])} | `{_markdown(row['path'])}` |"
        )
    return "\n".join(lines) + "\n"


def _python_package_names(notice: str) -> set[str]:
    try:
        python_section = notice.split("## Python dependencies\n", 1)[1].split(FRONTEND_SECTION, 1)[0]
    except IndexError as exc:
        raise NoticeGenerationError("third-party notice has an unsupported section layout") from exc
    names = {
        columns[1].strip().casefold()
        for line in python_section.splitlines()
        if line.startswith("|") and len(columns := line.split("|")) >= 3 and columns[1].strip() not in {"Package", "---"}
    }
    return names - PLATFORM_SPECIFIC_PYTHON_PACKAGES


def _check_notice(current: str, rendered: str, output: Path) -> None:
    try:
        current_frontend = FRONTEND_SECTION + current.split(FRONTEND_SECTION, 1)[1]
        rendered_frontend = FRONTEND_SECTION + rendered.split(FRONTEND_SECTION, 1)[1]
    except IndexError as exc:
        raise NoticeGenerationError("third-party notice has an unsupported section layout") from exc
    if current_frontend != rendered_frontend:
        raise NoticeGenerationError(f"frontend third-party notice is stale: {output}")
    if _python_package_names(current) != _python_package_names(rendered):
        raise NoticeGenerationError(f"Python third-party package inventory is stale: {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True, help="Python executable from the reviewed clean environment")
    parser.add_argument("--node-lock", type=Path, default=DEFAULT_NODE_LOCK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="fail if the existing output is stale")
    args = parser.parse_args()
    rendered = render_notice(*(_python_inventory(args.python), *_node_inventory(args.node_lock)))
    if args.check:
        try:
            current = args.output.read_text(encoding="utf-8")
        except OSError as exc:
            raise NoticeGenerationError(f"notice output unavailable: {args.output}") from exc
        _check_notice(current, rendered, args.output)
        print(f"THIRD_PARTY_NOTICES_CURRENT: {args.output}")
        return 0
    args.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"THIRD_PARTY_NOTICES_WRITTEN: {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except NoticeGenerationError as exc:
        print(f"THIRD_PARTY_NOTICES_REJECTED: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
