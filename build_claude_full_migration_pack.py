#!/usr/bin/env python3
"""
Build AI_SCALPER full migration pack for Claude.

Run from:
/Users/muhammadirvan/Documents/AI_SCALPER

Default:
- Includes .py, .json, .md, .txt, .yml, .yaml, .toml, .ini, .cfg, .sh, .csv only if explicitly requested.
- Excludes venv, cache, git, large binary artifacts.

Usage:
  python build_claude_full_migration_pack.py
  python build_claude_full_migration_pack.py --include-data
  python build_claude_full_migration_pack.py --include-data --include-logs
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import zipfile
from datetime import datetime
from pathlib import Path

PROJECT_NAME = "AI_SCALPER"

DEFAULT_INCLUDE_SUFFIXES = {
    ".py", ".json", ".md", ".txt", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".sh",
}

DATA_SUFFIXES = {".csv"}
LOG_SUFFIXES = {".log"}

EXCLUDE_DIR_NAMES = {
    "venv",
    ".venv",
    "__pycache__",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".ipynb_checkpoints",
    "node_modules",
}

EXCLUDE_FILE_NAMES = {
    ".DS_Store",
}

MAX_FILE_SIZE_MB_DEFAULT = 10
MAX_FILE_SIZE_MB_WITH_DATA = 50


MIGRATION_README = """# AI_SCALPER Full Project Context

This ZIP was generated from the user's local AI_SCALPER folder.

Read these first:
1. `MIGRATION_STATUS_SUMMARY.md`
2. `MIGRATION_MANIFEST.json`
3. `decision_engine.py`
4. `data_collector.py`
5. `phase4_soft_observation_gate.py`
6. `demo_readiness_evaluator.py`
7. `offline_dashboard_report.json`
8. `paper_quality_rules.json`
9. `phase4_clean_sample_gate.json`
10. `phase4_soft_observation_gate.json`

Safety rules:
- Do not enable live trading.
- Do not set live_allowed=True.
- Do not raise max_lot above 0.01.
- Do not enable demo auto-order without a separate manual unlock plan.
- Do not treat soft observation as execution permission.
"""


MIGRATION_STATUS_SUMMARY = """# AI_SCALPER Migration Status Summary

## Current mode

DEMO_OBSERVATION_ONLY_READY / PAPER_ONLY / DRY_RUN_SIMULATOR.

Hard locks:
- live_allowed=False
- max_lot=0.01
- safe_to_demo_auto_order=False
- safe_to_demo_observe=True

## Latest known project state

- Quality: NOT_READY
- Action: STOP_AND_REVIEW_PHASE_4
- Closed orders: 52/50
- Winrate: 36.54%
- Profit factor: 1.3758
- Clean samples: 0
- Soft observation: active
- Soft sample: EURUSD MOMENTUM_PULLBACK score 4.0, creates_order=False
- Bridge orders: 0
- Demo outbox orders: 0
- Exec approved: EURUSD
- Exec blocked: GBPUSD
- Shadow: BTCUSD

## Current safe loop

```bash
while true; do
  python data_collector.py --mode full || python data_collector.py full || DATA_COLLECTOR_MODE=FULL python data_collector.py
  python decision_engine.py
  python phase4_soft_observation_gate.py
  python paper_forward_runner.py
  python forward_test_dashboard.py
  python demo_readiness_evaluator.py
  sleep 900
done
```

## Interpretation

The system is not stuck. It is blocking orders because the quality status is NOT_READY and execution guard is strict.

Soft observation is intentionally looser:
- EURUSD
- allowed strategy
- score >= 4
- diagnostic only
- creates_order=False

Execution stays strict:
- EURUSD only
- score >= 5
- confirmations >= 3
- market usable
- replay valid/restored
- clean sample gate
- no auto-order until manual review
"""


CLAUDE_HANDOFF_PROMPT = """Saya mengupload full migration pack proyek AI_SCALPER.

Gunakan bahasa Indonesia. Jawaban harus tegas, ringkas, langsung aksi.

Aturan wajib:
- Jangan buka live trading.
- Jangan set live_allowed=True.
- Jangan naikkan max_lot di atas 0.01.
- Jangan aktifkan demo auto-order tanpa rencana manual terpisah.
- Jangan patch kalau saya hanya minta cek/lanjut/loop.
- Kalau patch diperlukan, buat patch aman dan jelas.

Fokus sekarang:
FULL + SOFT OBSERVATION loop M15.
Soft observation boleh mencatat EURUSD score >= 4 sebagai diagnostic sample saja.
Soft observation tidak boleh membuat MT5 order atau demo outbox.
Execution clean gate tetap ketat.

Kalau saya bilang:
- cek: baca status terminal/file dan ringkas.
- lanjut: lanjutkan dari status terakhir.
- simpan: simpan progres terakhir.
"""


def should_exclude_dir(path: Path) -> bool:
    return any(part in EXCLUDE_DIR_NAMES for part in path.parts)


def should_include_file(path: Path, include_data: bool, include_logs: bool) -> bool:
    if path.name in EXCLUDE_FILE_NAMES:
        return False
    suffix = path.suffix.lower()
    if suffix in DEFAULT_INCLUDE_SUFFIXES:
        return True
    if include_data and suffix in DATA_SUFFIXES:
        return True
    if include_logs and suffix in LOG_SUFFIXES:
        return True
    return False


def safe_read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def build_quick_status(root: Path) -> dict:
    files = [
        "demo_readiness_evaluator.json",
        "phase4_soft_observation_gate.json",
        "phase4_clean_sample_gate.json",
        "offline_dashboard_report.json",
        "bridge_status.json",
        "mt5_demo_bridge_outbox.json",
        "paper_quality_rules.json",
        "paper_forward_runs.json",
    ]
    status = {}
    for name in files:
        path = root / name
        if path.exists():
            data = safe_read_json(path)
            if data is not None:
                status[name] = data
    return status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--include-data", action="store_true", help="Include CSV data files.")
    parser.add_argument("--include-logs", action="store_true", help="Include .log files.")
    parser.add_argument("--output-dir", default=".", help="Output directory.")
    args = parser.parse_args()

    root = Path.cwd().resolve()

    if not (root / "decision_engine.py").exists():
        print("ERROR: Run this script from the AI_SCALPER project folder containing decision_engine.py")
        print(f"Current folder: {root}")
        return 1

    now = datetime.now()
    stamp = now.strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    zip_path = output_dir / f"AI_SCALPER_FULL_PROJECT_CONTEXT_{stamp}.zip"
    max_mb = MAX_FILE_SIZE_MB_WITH_DATA if args.include_data else MAX_FILE_SIZE_MB_DEFAULT
    max_bytes = max_mb * 1024 * 1024

    manifest = {
        "generated_at": now.isoformat(),
        "project_name": PROJECT_NAME,
        "project_root": str(root),
        "python": sys.version,
        "platform": platform.platform(),
        "include_data": args.include_data,
        "include_logs": args.include_logs,
        "max_file_size_mb": max_mb,
        "excluded_dirs": sorted(EXCLUDE_DIR_NAMES),
        "included_files": [],
        "skipped_files": [],
        "quick_status_files": {},
    }

    quick_status = build_quick_status(root)
    manifest["quick_status_files"] = {
        name: {
            "type": type(data).__name__,
            "top_level_keys": list(data.keys())[:40] if isinstance(data, dict) else None,
            "length": len(data) if hasattr(data, "__len__") else None,
        }
        for name, data in quick_status.items()
    }

    temp_extra_files = {
        "MIGRATION_README.md": MIGRATION_README,
        "MIGRATION_STATUS_SUMMARY.md": MIGRATION_STATUS_SUMMARY,
        "CLAUDE_HANDOFF_PROMPT.txt": CLAUDE_HANDOFF_PROMPT,
    }

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for arcname, content in temp_extra_files.items():
            z.writestr(arcname, content)

        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root)

            if path.is_dir():
                continue

            if should_exclude_dir(rel):
                manifest["skipped_files"].append({
                    "path": str(rel),
                    "reason": "excluded_dir",
                })
                continue

            if path == zip_path:
                continue

            if not should_include_file(path, args.include_data, args.include_logs):
                manifest["skipped_files"].append({
                    "path": str(rel),
                    "reason": "suffix_not_included",
                })
                continue

            try:
                size = path.stat().st_size
            except OSError:
                manifest["skipped_files"].append({
                    "path": str(rel),
                    "reason": "stat_failed",
                })
                continue

            if size > max_bytes:
                manifest["skipped_files"].append({
                    "path": str(rel),
                    "reason": f"file_too_large_over_{max_mb}MB",
                    "size_bytes": size,
                })
                continue

            z.write(path, arcname=str(rel))
            manifest["included_files"].append({
                "path": str(rel),
                "size_bytes": size,
                "suffix": path.suffix.lower(),
            })

        z.writestr("MIGRATION_MANIFEST.json", json.dumps(manifest, indent=2))

    print("DONE")
    print(f"Output: {zip_path}")
    print(f"Included files: {len(manifest['included_files'])}")
    print(f"Skipped files: {len(manifest['skipped_files'])}")
    print("")
    print("Upload this ZIP to Claude:")
    print(zip_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
