from __future__ import annotations

from pathlib import Path
import re
import unittest
import zipfile


REPO_ROOT = Path(__file__).resolve().parent
EA_PATHS = (
    REPO_ROOT / "mql5" / "AI_SCALPER_DemoBridgeReader.mq5",
    REPO_ROOT / "vps_package" / "AI_SCALPER_DemoBridgeReader.mq5",
)
VPS_ARCHIVE = REPO_ROOT / "AI_SCALPER_VPS_DEMO_PACKAGE.zip"
VPS_ARCHIVE_EA = "vps_package/AI_SCALPER_DemoBridgeReader.mq5"
VPS_ARCHIVE_README = "vps_package/README_SETUP_DEMO_MT5.txt"


FORBIDDEN_ORDER_PATTERNS = {
    "Trade library": r"#include\s*<Trade/",
    "CTrade object": r"\bCTrade\b",
    "direct order API": r"\bOrderSend(?:Async)?\s*\(",
    "trade request structure": r"\bMqlTradeRequest\b",
    "deal action": r"\bTRADE_ACTION_(?:DEAL|PENDING)\b",
    "buy method": r"\.\s*Buy(?:Limit|Stop)?\s*\(",
    "sell method": r"\.\s*Sell(?:Limit|Stop)?\s*\(",
    "position open method": r"\.\s*PositionOpen\s*\(",
    "position close method": r"\.\s*PositionClose\s*\(",
}


class LegacyMql5SafetyTests(unittest.TestCase):
    def test_distributed_sources_are_byte_identical(self):
        self.assertEqual(EA_PATHS[0].read_bytes(), EA_PATHS[1].read_bytes())

    def test_legacy_reader_has_no_order_capability(self):
        for path in EA_PATHS:
            source = path.read_text(encoding="utf-8")
            for label, pattern in FORBIDDEN_ORDER_PATTERNS.items():
                with self.subTest(path=path, primitive=label):
                    self.assertIsNone(re.search(pattern, source, flags=re.IGNORECASE))

    def test_vps_archive_contains_only_the_inert_reader(self):
        with zipfile.ZipFile(VPS_ARCHIVE) as archive:
            members = set(archive.namelist())
            archived_source = archive.read(VPS_ARCHIVE_EA)
            archived_readme = archive.read(VPS_ARCHIVE_README).decode("utf-8")
        self.assertEqual(
            {
                "vps_package/",
                VPS_ARCHIVE_EA,
                VPS_ARCHIVE_README,
            },
            members,
        )
        self.assertFalse(any(name.casefold().endswith(".json") for name in members))
        self.assertEqual(EA_PATHS[0].read_bytes(), archived_source)
        source = archived_source.decode("utf-8")
        for label, pattern in FORBIDDEN_ORDER_PATTERNS.items():
            with self.subTest(archive=VPS_ARCHIVE.name, primitive=label):
                self.assertIsNone(re.search(pattern, source, flags=re.IGNORECASE))
        self.assertIn("Keep Algo Trading OFF.", archived_readme)
        self.assertIn("safe_to_demo_auto_order=false", archived_readme)

    def test_only_non_safety_operational_inputs_remain(self):
        source = EA_PATHS[0].read_text(encoding="utf-8")
        input_names = set(
            re.findall(
                r"^\s*input\s+\w+\s+(Inp[A-Za-z0-9_]+)\s*=",
                source,
                flags=re.MULTILINE,
            )
        )
        self.assertEqual(
            {"InpOutboxFileName", "InpCheckIntervalSeconds"},
            input_names,
        )

    def test_reader_requires_the_locked_zero_order_state(self):
        source = EA_PATHS[0].read_text(encoding="utf-8")
        required_guards = (
            'TryJsonBool(json, "demo_only", demo_only)',
            'TryJsonBool(json, "paper_only", paper_only)',
            'TryJsonBool(json, "live_allowed", live_allowed)',
            'TryJsonBool(json, "safe_to_demo_auto_order", safe_to_demo_auto_order)',
            'TryJsonInt(json, "order_count", order_count)',
            "if(live_allowed)",
            "if(safe_to_demo_auto_order)",
            "if(order_count != 0)",
            "const double EXPECTED_MAX_LOT = 0.01;",
            "MathAbs(max_lot - EXPECTED_MAX_LOT)",
        )
        for guard in required_guards:
            with self.subTest(guard=guard):
                self.assertIn(guard, source)

        self.assertNotRegex(source, r"\bExecute[A-Za-z0-9_]*Order\s*\(")


if __name__ == "__main__":
    unittest.main()
