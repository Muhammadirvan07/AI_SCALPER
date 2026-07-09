import json
import os
from datetime import datetime, timezone


PAPER_QUALITY_RULES_FILE = "paper_quality_rules.json"
DATA_COLLECTOR_STATUS_FILE = "data_collector_status.json"
REPLAY_CANDIDATE_GUARD_FILE = "replay_candidate_guard.json"
OFFLINE_DASHBOARD_REPORT_FILE = "offline_dashboard_report.json"
ACTIVE_PAIRS_FILE = "active_pairs.json"
ACTIVE_PAIR_ROTATOR_REPORT_FILE = "active_pair_rotator_report.json"

MAX_ACTIVE_PAIRS = 5
MIN_ACTIVE_PAIRS = 1
REQUIRE_REPLAY_APPROVAL = True

# =========================
# PHASE 4C QUALITY-FIRST ROTATION
# =========================
# Replay approval is useful, but Phase 4 quality must be stronger.
# If quality guard says a symbol is RESTRICT with negative net, do not use it as main active pair.
PHASE4C_QUALITY_FIRST_ROTATION = True
PHASE4C_BLOCK_RESTRICT_NEGATIVE_NET_AS_MAIN = True
PHASE4C_MAIN_ALLOWED_STATUSES = {"PRIORITY", "WATCH"}
PHASE4C_SECONDARY_ALLOWED_STATUSES = {"INSUFFICIENT_SAMPLE"}
PHASE4C_FORCE_MAIN_SYMBOLS = ["EURUSD"]
PHASE4C_MAX_MAIN_PAIRS = 1
PHASE4C_MAX_SECONDARY_PAIRS = 0

# Main lane only uses replay-approved symbols.
# Exploration lane can add extra paper-only symbols to collect more samples.
ENABLE_EXPLORATION_CANDIDATES = False
MAX_EXPLORATION_PAIRS = 3
EXPLORATION_REQUIRE_REPLAY_APPROVAL = False
EXPLORATION_ALLOWED_STATUSES = {"PRIORITY", "WATCH", "INSUFFICIENT_SAMPLE"}
EXPLORATION_BLOCKED_STATUSES = {"BLOCK", "RESTRICT"}
EXPLORATION_TAG = "PHASE4_SYMBOL_EXPLORATION"

DEFAULT_ACTIVE_PAIRS = ["EURUSD"]

SYMBOL_PRIORITY_STATUS = {
    "PRIORITY": 100,
    "WATCH": 70,
    "INSUFFICIENT_SAMPLE": 45,
    "RESTRICT": 20,
    "BLOCK": -999,
}

PREFERRED_SYMBOLS = [
    "EURUSD",
    "GBPUSD",
    "NZDUSD",
    "BTCUSD",
    "XAUUSD",
    "USDJPY",
    "AUDUSD",
    "USDCAD",
    "EURJPY",
    "GBPJPY",
    "AUDJPY",
    "CADJPY",
    "CHFJPY",
    "USDCHF",
    "EURGBP",
]


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def normalize_symbol(symbol):
    return str(symbol or "").strip().upper()


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def get_available_symbols_from_data_collector():
    status = load_json(DATA_COLLECTOR_STATUS_FILE, {})
    symbols = []

    if isinstance(status, dict):
        selected_symbols = status.get("selected_symbols", [])
        if isinstance(selected_symbols, list):
            symbols.extend(selected_symbols)

        success_items = status.get("success_items", [])
        if isinstance(success_items, list):
            for item in success_items:
                if isinstance(item, dict):
                    symbols.append(item.get("symbol"))

    symbols = [normalize_symbol(symbol) for symbol in symbols]
    symbols = [symbol for symbol in symbols if symbol]

    return list(dict.fromkeys(symbols))


def get_symbol_rules():
    rules = load_json(PAPER_QUALITY_RULES_FILE, {})
    symbol_rules = rules.get("symbol_rules", {})

    if not isinstance(symbol_rules, dict):
        return {}

    return symbol_rules


def extract_approved_symbols_from_items(items):
    approved = []

    if not isinstance(items, list):
        return approved

    for item in items:
        if not isinstance(item, dict):
            continue

        symbol = normalize_symbol(item.get("symbol"))
        status = str(item.get("status", "")).upper()

        if not symbol:
            continue

        if status == "APPROVED_REPLAY_CANDIDATE" or "APPROVED" in status:
            approved.append(symbol)

    return approved



def get_approved_replay_symbols():
    approved = []

    replay_guard = load_json(REPLAY_CANDIDATE_GUARD_FILE, {})
    if isinstance(replay_guard, dict):
        for key in ["approved_symbols", "approved_replay_symbols"]:
            value = replay_guard.get(key)
            if isinstance(value, list):
                approved.extend(normalize_symbol(symbol) for symbol in value)

        for key in ["approved", "approved_candidates", "approved_replay_candidates"]:
            approved.extend(extract_approved_symbols_from_items(replay_guard.get(key)))

        symbols_section = replay_guard.get("symbols")
        if isinstance(symbols_section, dict):
            for symbol, value in symbols_section.items():
                if isinstance(value, dict):
                    status = str(value.get("status", "")).upper()
                    if status == "APPROVED_REPLAY_CANDIDATE" or "APPROVED" in status:
                        approved.append(symbol)

    dashboard = load_json(OFFLINE_DASHBOARD_REPORT_FILE, {})
    if isinstance(dashboard, dict):
        replay_section = dashboard.get("replay_candidate_guard") or dashboard.get("replay_guard") or {}
        if isinstance(replay_section, dict):
            approved.extend(extract_approved_symbols_from_items(replay_section.get("approved_symbols")))
            approved.extend(extract_approved_symbols_from_items(replay_section.get("approved")))
            approved.extend(extract_approved_symbols_from_items(replay_section.get("approved_candidates")))

            raw_approved = replay_section.get("approved_symbols")
            if isinstance(raw_approved, list):
                for item in raw_approved:
                    if isinstance(item, str):
                        approved.append(item)
                    elif isinstance(item, dict):
                        approved.append(item.get("symbol"))

    approved = [normalize_symbol(symbol) for symbol in approved]
    approved = [symbol for symbol in approved if symbol]

    return list(dict.fromkeys(approved))


def score_symbol(symbol, rule, approved_replay_symbols=None):
    approved_replay_symbols = approved_replay_symbols or []
    replay_approved = symbol in approved_replay_symbols

    status = str(rule.get("status", "INSUFFICIENT_SAMPLE")).upper()
    closed = safe_int(rule.get("closed_orders"), 0)
    winrate = safe_float(rule.get("winrate_percent"), 0.0)
    profit_factor = safe_float(rule.get("profit_factor"), 0.0)
    net_profit = safe_float(rule.get("net_profit_usd"), 0.0)
    min_score_required = safe_int(rule.get("min_score_required"), 4)
    allow_new_entries = bool(rule.get("allow_new_entries", True))

    base_score = SYMBOL_PRIORITY_STATUS.get(status, 0)

    if REQUIRE_REPLAY_APPROVAL and not replay_approved:
        return {
            "symbol": symbol,
            "status": status,
            "score": -500,
            "selected": False,
            "reason": "Not selected because symbol is not approved by replay candidate guard.",
            "closed_orders": closed,
            "winrate_percent": winrate,
            "profit_factor": profit_factor,
            "net_profit_usd": net_profit,
            "min_score_required": min_score_required,
            "allow_new_entries": allow_new_entries,
            "replay_approved": replay_approved,
        }

    if not allow_new_entries or status == "BLOCK":
        return {
            "symbol": symbol,
            "status": status,
            "score": -999,
            "selected": False,
            "reason": "Blocked by Phase 4 quality rule.",
            "closed_orders": closed,
            "winrate_percent": winrate,
            "profit_factor": profit_factor,
            "net_profit_usd": net_profit,
            "min_score_required": min_score_required,
            "allow_new_entries": allow_new_entries,
            "replay_approved": replay_approved,
        }

    score = base_score

    # Reward sample size, but do not overfit to tiny samples.
    score += min(closed, 20) * 1.5

    # Reward stable winrate.
    if winrate >= 55:
        score += 25
    elif winrate >= 45:
        score += 15
    elif winrate >= 40:
        score += 5
    elif closed >= 10:
        score -= 10

    # Reward PF, capped so 999 from tiny samples does not dominate.
    capped_pf = min(profit_factor, 3.0)
    score += capped_pf * 8

    # Reward net profit.
    score += net_profit * 5

    # Slight penalty for stricter required score.
    if min_score_required > 4:
        score -= (min_score_required - 4) * 10

    # Light preference order to keep known stable majors near the top.
    if symbol in PREFERRED_SYMBOLS:
        preference_rank = PREFERRED_SYMBOLS.index(symbol)
        score += max(10 - preference_rank, 0)

    reason = (
        f"{status}: closed={closed}, WR={winrate:.2f}%, "
        f"PF={profit_factor:.4f}, net=${net_profit:.4f}, "
        f"min_score={min_score_required}."
    )

    return {
        "symbol": symbol,
        "status": status,
        "score": round(score, 4),
        "selected": False,
        "reason": reason,
        "closed_orders": closed,
        "winrate_percent": winrate,
        "profit_factor": profit_factor,
        "net_profit_usd": net_profit,
        "min_score_required": min_score_required,
        "allow_new_entries": allow_new_entries,
        "replay_approved": replay_approved,
    }


def get_rule_status(rule):
    return str(rule.get("status", rule.get("guard_status", "UNKNOWN"))).upper()


def get_rule_net_profit(rule):
    return safe_float(
        rule.get("net_profit_usd", rule.get("net_profit", rule.get("net", 0.0))),
        0.0,
    )


def is_restrict_negative_net(rule):
    return get_rule_status(rule) == "RESTRICT" and get_rule_net_profit(rule) < 0


def is_quality_allowed_main_symbol(symbol, rule):
    symbol = normalize_symbol(symbol)

    if not PHASE4C_QUALITY_FIRST_ROTATION:
        return True, "Quality-first rotation is disabled."

    if symbol in PHASE4C_FORCE_MAIN_SYMBOLS:
        return True, f"{symbol} is force-selected as Phase 4C main symbol."

    status = get_rule_status(rule)

    if PHASE4C_BLOCK_RESTRICT_NEGATIVE_NET_AS_MAIN and is_restrict_negative_net(rule):
        return False, f"{symbol} blocked as main pair: status RESTRICT with negative net profit."

    if status not in PHASE4C_MAIN_ALLOWED_STATUSES:
        return False, f"{symbol} blocked as main pair: status {status} is not allowed for Phase 4C main rotation."

    return True, f"{symbol} allowed as main pair by Phase 4C quality-first rotation."


def is_quality_allowed_secondary_symbol(symbol, rule):
    symbol = normalize_symbol(symbol)

    if not PHASE4C_QUALITY_FIRST_ROTATION:
        return True, "Quality-first rotation is disabled."

    status = get_rule_status(rule)

    if PHASE4C_BLOCK_RESTRICT_NEGATIVE_NET_AS_MAIN and is_restrict_negative_net(rule):
        return False, f"{symbol} blocked as secondary pair: status RESTRICT with negative net profit."

    if status not in PHASE4C_SECONDARY_ALLOWED_STATUSES:
        return False, f"{symbol} blocked as secondary pair: status {status} is not allowed for Phase 4C secondary rotation."

    return True, f"{symbol} allowed as secondary pair by Phase 4C quality-first rotation."


def score_exploration_symbol(symbol, rule, available_symbols=None, approved_replay_symbols=None):
    available_symbols = available_symbols or []
    approved_replay_symbols = approved_replay_symbols or []

    symbol = normalize_symbol(symbol)
    status = str(rule.get("status", "INSUFFICIENT_SAMPLE")).upper()
    closed = safe_int(rule.get("closed_orders"), 0)
    winrate = safe_float(rule.get("winrate_percent"), 0.0)
    profit_factor = safe_float(rule.get("profit_factor"), 0.0)
    net_profit = safe_float(rule.get("net_profit_usd"), 0.0)
    min_score_required = safe_int(rule.get("min_score_required"), 4)
    allow_new_entries = bool(rule.get("allow_new_entries", True))
    replay_approved = symbol in approved_replay_symbols
    data_available = symbol in available_symbols if available_symbols else True

    if not ENABLE_EXPLORATION_CANDIDATES:
        score = -999
        reason = "Exploration candidates disabled."
    elif not data_available:
        score = -800
        reason = "No fresh data available from data_collector_status.json."
    elif EXPLORATION_REQUIRE_REPLAY_APPROVAL and not replay_approved:
        score = -700
        reason = "Exploration requires replay approval but symbol is not approved."
    elif status in EXPLORATION_BLOCKED_STATUSES or not allow_new_entries:
        score = -600
        reason = f"Exploration blocked by symbol status {status} or allow_new_entries={allow_new_entries}."
    elif status not in EXPLORATION_ALLOWED_STATUSES:
        score = -300
        reason = f"Exploration status {status} is not allowed."
    else:
        score = SYMBOL_PRIORITY_STATUS.get(status, 0)
        score += min(closed, 10) * 1.0

        if status == "INSUFFICIENT_SAMPLE":
            score += 18

        if winrate >= 55:
            score += 18
        elif winrate >= 45:
            score += 10
        elif winrate >= 35:
            score += 3
        elif closed >= 5:
            score -= 10

        score += min(profit_factor, 3.0) * 5
        score += net_profit * 4

        if replay_approved:
            score += 15

        if symbol in PREFERRED_SYMBOLS:
            preference_rank = PREFERRED_SYMBOLS.index(symbol)
            score += max(12 - preference_rank, 0)

        reason = (
            f"{EXPLORATION_TAG}: status={status}, closed={closed}, WR={winrate:.2f}%, "
            f"PF={profit_factor:.4f}, net=${net_profit:.4f}, replay_approved={replay_approved}."
        )

    return {
        "symbol": symbol,
        "status": status,
        "score": round(score, 4),
        "selected": False,
        "reason": reason,
        "closed_orders": closed,
        "winrate_percent": winrate,
        "profit_factor": profit_factor,
        "net_profit_usd": net_profit,
        "min_score_required": min_score_required,
        "allow_new_entries": allow_new_entries,
        "replay_approved": replay_approved,
        "data_available": data_available,
        "exploration_tag": EXPLORATION_TAG,
    }



def build_exploration_candidates(symbol_rules, available_symbols, approved_replay_symbols, main_symbols):
    if not ENABLE_EXPLORATION_CANDIDATES:
        return [], []

    candidate_symbols = set(symbol_rules.keys())

    if available_symbols:
        candidate_symbols = candidate_symbols.intersection(set(available_symbols))

    candidate_symbols = candidate_symbols.difference(set(main_symbols))

    scored = []
    for symbol in sorted(candidate_symbols):
        normalized = normalize_symbol(symbol)
        rule = symbol_rules.get(normalized, {})
        if not isinstance(rule, dict):
            rule = {}
        scored.append(score_exploration_symbol(normalized, rule, available_symbols, approved_replay_symbols))

    scored = sorted(scored, key=lambda item: item["score"], reverse=True)

    selected = [
        item for item in scored
        if item["score"] > 0
        and item.get("allow_new_entries", True)
        and item.get("data_available", True)
    ][:MAX_EXPLORATION_PAIRS]

    selected_symbols = [item["symbol"] for item in selected]

    for item in scored:
        item["selected"] = item["symbol"] in selected_symbols

    return selected_symbols, scored


def build_rotated_active_pairs():
    symbol_rules = get_symbol_rules()
    available_symbols = get_available_symbols_from_data_collector()
    approved_replay_symbols = get_approved_replay_symbols()

    candidate_symbols = set(symbol_rules.keys())

    # Kalau data_collector_status ada, prioritaskan symbol yang memang tersedia datanya.
    if available_symbols:
        candidate_symbols = candidate_symbols.intersection(set(available_symbols))

    # Phase 4 safety: jangan pilih active pair yang pasti akan ditolak replay guard.
    if REQUIRE_REPLAY_APPROVAL and approved_replay_symbols:
        candidate_symbols = candidate_symbols.intersection(set(approved_replay_symbols))

    if not candidate_symbols:
        if REQUIRE_REPLAY_APPROVAL and approved_replay_symbols:
            candidate_symbols = set(approved_replay_symbols)
        else:
            candidate_symbols = set(DEFAULT_ACTIVE_PAIRS)

    scored = []

    for symbol in sorted(candidate_symbols):
        normalized = normalize_symbol(symbol)
        rule = symbol_rules.get(normalized, {})

        if not isinstance(rule, dict):
            rule = {}

        scored.append(score_symbol(normalized, rule, approved_replay_symbols))

    scored = sorted(scored, key=lambda item: item["score"], reverse=True)

    quality_rotation_notes = []
    main_active_pairs = []

    if PHASE4C_QUALITY_FIRST_ROTATION:
        for forced_symbol in PHASE4C_FORCE_MAIN_SYMBOLS:
            forced_symbol = normalize_symbol(forced_symbol)
            forced_rule = symbol_rules.get(forced_symbol, {})

            if REQUIRE_REPLAY_APPROVAL and approved_replay_symbols and forced_symbol not in approved_replay_symbols:
                quality_rotation_notes.append(
                    f"{forced_symbol} was force-main candidate but skipped because it is not replay-approved."
                )
                continue

            if available_symbols and forced_symbol not in available_symbols:
                quality_rotation_notes.append(
                    f"{forced_symbol} was force-main candidate but skipped because fresh data is unavailable."
                )
                continue

            if forced_symbol not in main_active_pairs:
                main_active_pairs.append(forced_symbol)
                quality_rotation_notes.append(f"{forced_symbol} selected as forced Phase 4C main pair.")

            if len(main_active_pairs) >= PHASE4C_MAX_MAIN_PAIRS:
                break

        for item in scored:
            symbol = normalize_symbol(item["symbol"])
            if symbol in main_active_pairs:
                continue

            rule = symbol_rules.get(symbol, {})
            allowed_main, main_reason = is_quality_allowed_main_symbol(symbol, rule)
            item["phase4c_main_allowed"] = allowed_main
            item["phase4c_main_reason"] = main_reason

            if not allowed_main:
                quality_rotation_notes.append(main_reason)
                continue

            if item["score"] <= 0 or not item["allow_new_entries"]:
                continue

            if REQUIRE_REPLAY_APPROVAL and not item.get("replay_approved", False):
                continue

            main_active_pairs.append(symbol)
            quality_rotation_notes.append(main_reason)

            if len(main_active_pairs) >= PHASE4C_MAX_MAIN_PAIRS:
                break

        secondary_active_pairs = []
        for item in scored:
            symbol = normalize_symbol(item["symbol"])
            if symbol in main_active_pairs or symbol in secondary_active_pairs:
                continue

            rule = symbol_rules.get(symbol, {})
            allowed_secondary, secondary_reason = is_quality_allowed_secondary_symbol(symbol, rule)
            item["phase4c_secondary_allowed"] = allowed_secondary
            item["phase4c_secondary_reason"] = secondary_reason

            if not allowed_secondary:
                quality_rotation_notes.append(secondary_reason)
                continue

            if item["score"] <= 0 or not item["allow_new_entries"]:
                continue

            if REQUIRE_REPLAY_APPROVAL and not item.get("replay_approved", False):
                continue

            secondary_active_pairs.append(symbol)
            quality_rotation_notes.append(secondary_reason)

            if len(secondary_active_pairs) >= PHASE4C_MAX_SECONDARY_PAIRS:
                break

        selected_symbols = main_active_pairs + secondary_active_pairs
    else:
        selected = [
            item for item in scored
            if item["score"] > 0
            and item["allow_new_entries"]
            and (not REQUIRE_REPLAY_APPROVAL or item.get("replay_approved", False))
        ]
        selected_symbols = [item["symbol"] for item in selected[:MAX_ACTIVE_PAIRS]]

        if len(selected_symbols) < MIN_ACTIVE_PAIRS:
            fallback_pool = approved_replay_symbols if REQUIRE_REPLAY_APPROVAL and approved_replay_symbols else DEFAULT_ACTIVE_PAIRS
            for fallback_symbol in fallback_pool:
                normalized_fallback = normalize_symbol(fallback_symbol)
                if normalized_fallback not in selected_symbols:
                    selected_symbols.append(normalized_fallback)
                if len(selected_symbols) >= MIN_ACTIVE_PAIRS:
                    break

        selected_symbols = selected_symbols[:MAX_ACTIVE_PAIRS]
        main_active_pairs = list(selected_symbols)
        secondary_active_pairs = []

    if not selected_symbols:
        fallback_pool = [symbol for symbol in DEFAULT_ACTIVE_PAIRS if not approved_replay_symbols or symbol in approved_replay_symbols]
        selected_symbols = fallback_pool[:MIN_ACTIVE_PAIRS]
        main_active_pairs = list(selected_symbols)
        secondary_active_pairs = []
        quality_rotation_notes.append("Fallback selected because quality-first rotation produced no active pairs.")

    for item in scored:
        item["selected"] = item["symbol"] in main_active_pairs

    if PHASE4C_QUALITY_FIRST_ROTATION:
        # Phase 4C is quality-first: do not allow exploration pairs to leak back in.
        exploration_symbols = []
        exploration_scored = []
    else:
        exploration_symbols, exploration_scored = build_exploration_candidates(
            symbol_rules,
            available_symbols,
            approved_replay_symbols,
            main_active_pairs,
        )

    combined_active_pairs = []
    for symbol in main_active_pairs + exploration_symbols:
        normalized = normalize_symbol(symbol)
        if normalized and normalized not in combined_active_pairs:
            combined_active_pairs.append(normalized)

    combined_active_pairs = combined_active_pairs[:MAX_ACTIVE_PAIRS]

    report = {
        "generated_at": utc_now_iso(),
        "mode": "PHASE_4_ACTIVE_PAIR_ROTATOR",
        "source_rules": PAPER_QUALITY_RULES_FILE,
        "source_data_collector": DATA_COLLECTOR_STATUS_FILE,
        "source_replay_guard": REPLAY_CANDIDATE_GUARD_FILE,
        "source_dashboard_replay_guard": OFFLINE_DASHBOARD_REPORT_FILE,
        "require_replay_approval": REQUIRE_REPLAY_APPROVAL,
        "max_active_pairs": MAX_ACTIVE_PAIRS,
        "min_active_pairs": MIN_ACTIVE_PAIRS,
        "available_symbols_from_data_collector": available_symbols,
        "approved_replay_symbols": approved_replay_symbols,
        "selected_active_pairs": combined_active_pairs,
        "main_active_pairs": main_active_pairs,
        "secondary_active_pairs": secondary_active_pairs,
        "exploration_active_pairs": exploration_symbols,
        "phase4c_quality_first_rotation": {
            "enabled": PHASE4C_QUALITY_FIRST_ROTATION,
            "force_main_symbols": PHASE4C_FORCE_MAIN_SYMBOLS,
            "max_main_pairs": PHASE4C_MAX_MAIN_PAIRS,
            "max_secondary_pairs": PHASE4C_MAX_SECONDARY_PAIRS,
            "main_allowed_statuses": sorted(PHASE4C_MAIN_ALLOWED_STATUSES),
            "secondary_allowed_statuses": sorted(PHASE4C_SECONDARY_ALLOWED_STATUSES),
            "block_restrict_negative_net_as_main": PHASE4C_BLOCK_RESTRICT_NEGATIVE_NET_AS_MAIN,
            "notes": quality_rotation_notes,
        },
        "enable_exploration_candidates": ENABLE_EXPLORATION_CANDIDATES,
        "max_exploration_pairs": MAX_EXPLORATION_PAIRS,
        "exploration_require_replay_approval": EXPLORATION_REQUIRE_REPLAY_APPROVAL,
        "exploration_tag": EXPLORATION_TAG,
        "scored_symbols": scored,
        "exploration_scored_symbols": exploration_scored,
        "live_allowed": False,
        "execution_mode": "PAPER_ONLY",
        "note": (
            "This rotator only updates active_pairs.json for paper validation. "
            "It does not bypass decision_engine, Phase 4 rules, executor guards, or live lock."
        ),
    }

    active_pairs_payload = {
        "generated_at": report["generated_at"],
        "mode": report["mode"],
        "active_pairs": combined_active_pairs,
        "main_active_pairs": main_active_pairs,
        "secondary_active_pairs": secondary_active_pairs,
        "exploration_active_pairs": exploration_symbols,
        "exploration_tag": EXPLORATION_TAG,
        "source": ACTIVE_PAIR_ROTATOR_REPORT_FILE,
        "live_allowed": False,
        "execution_mode": "PAPER_ONLY",
        "note": (
            "Main pairs are replay-approved. Exploration pairs are paper-only candidates for sample collection. "
            "Decision engine and executor guards remain responsible for final approval."
        ),
    }

    return active_pairs_payload, report


def print_report(report):
    print("\n=== ACTIVE PAIR ROTATOR ===")
    print(f"Generated at : {report['generated_at']}")
    print(f"Mode         : {report['mode']}")
    print(f"Live allowed : {report['live_allowed']}")
    print(f"Execution    : {report['execution_mode']}")
    print(f"Replay filter: {report.get('require_replay_approval', False)}")
    print(f"Replay OK    : {', '.join(report.get('approved_replay_symbols', [])) or 'none'}")
    print(f"Main pairs   : {', '.join(report.get('main_active_pairs', [])) or 'none'}")
    print(f"Secondary    : {', '.join(report.get('secondary_active_pairs', [])) or 'none'}")
    print(f"Exploration  : {', '.join(report.get('exploration_active_pairs', [])) or 'none'}")

    phase4c = report.get("phase4c_quality_first_rotation", {})
    print(f"Phase4C QFR  : {phase4c.get('enabled', False)}")
    notes = phase4c.get("notes", [])
    if notes:
        print("Phase4C notes:")
        for note in notes:
            print(f"- {note}")
    print(f"Selected     : {', '.join(report['selected_active_pairs'])}")
    print(f"Explore mode : {report.get('enable_exploration_candidates', False)} | Tag: {report.get('exploration_tag', '-')}")

    print("\nMain scored symbols:")
    for item in report["scored_symbols"]:
        selected_mark = "✅" if item["selected"] else "  "
        replay_mark = "R+" if item.get("replay_approved", False) else "R-"
        print(
            f"{selected_mark} {item['symbol']:8s} | "
            f"{replay_mark:2s} | "
            f"{item['status']:19s} | "
            f"Score: {item['score']:8.2f} | "
            f"Closed: {item['closed_orders']:3d} | "
            f"WR: {item['winrate_percent']:6.2f}% | "
            f"PF: {item['profit_factor']:8.4f} | "
            f"Net: ${item['net_profit_usd']}"
        )

    print("\nExploration scored symbols:")
    exploration_items = report.get("exploration_scored_symbols", [])
    if not exploration_items:
        print("- none")
    for item in exploration_items:
        selected_mark = "🧪" if item.get("selected", False) else "  "
        replay_mark = "R+" if item.get("replay_approved", False) else "R-"
        print(
            f"{selected_mark} {item['symbol']:8s} | "
            f"{replay_mark:2s} | "
            f"{item['status']:19s} | "
            f"Score: {item['score']:8.2f} | "
            f"Closed: {item['closed_orders']:3d} | "
            f"WR: {item['winrate_percent']:6.2f}% | "
            f"PF: {item['profit_factor']:8.4f} | "
            f"Net: ${item['net_profit_usd']} | "
            f"Reason: {item.get('reason', '')}"
        )

    print(f"\nSaved active pairs report to: {ACTIVE_PAIR_ROTATOR_REPORT_FILE}")
    print(f"Updated active pairs file to: {ACTIVE_PAIRS_FILE}")


def main():
    active_pairs_payload, report = build_rotated_active_pairs()

    save_json(ACTIVE_PAIRS_FILE, active_pairs_payload)
    save_json(ACTIVE_PAIR_ROTATOR_REPORT_FILE, report)

    print_report(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
