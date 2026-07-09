from pathlib import Path

FILE_PATH = Path("decision_engine.py")

text = FILE_PATH.read_text()

# ============================================================
# 1. Ensure Phase5Q print block exists after Phase5P print block
# ============================================================
phase5p_print_block = '''    print("\\nPhase 5P Controlled Phase5A Score Commit:")
    print(f"- Enabled       : {ENABLE_PHASE5P_CONTROLLED_SCORE_COMMIT}")
    print(f"- Mode          : {PHASE5P_MODE}")
    print(f"- Symbols       : {', '.join(sorted(PHASE5P_ALLOWED_SYMBOLS))}")
    print(f"- Max boost     : {PHASE5P_MAX_SCORE_BOOST}")
    print(f"- Tag           : {PHASE5P_TAG}")
'''

phase5q_print_block = '''    print("\\nPhase 5P Controlled Phase5A Score Commit:")
    print(f"- Enabled       : {ENABLE_PHASE5P_CONTROLLED_SCORE_COMMIT}")
    print(f"- Mode          : {PHASE5P_MODE}")
    print(f"- Symbols       : {', '.join(sorted(PHASE5P_ALLOWED_SYMBOLS))}")
    print(f"- Max boost     : {PHASE5P_MAX_SCORE_BOOST}")
    print(f"- Tag           : {PHASE5P_TAG}")

    print("\\nPhase 5Q Crypto No-Strategy Preview Classifier:")
    print(f"- Enabled       : {ENABLE_PHASE5Q_CRYPTO_NO_STRATEGY_PREVIEW}")
    print(f"- Mode          : {PHASE5Q_MODE}")
    print(f"- Lookback      : {PHASE5Q_LOOKBACK_CANDLES} candles")
    print(f"- Min vol       : {PHASE5Q_MIN_VOLATILITY_PERCENT:.6f}%")
    print(f"- Max zero vol  : {PHASE5Q_MAX_ZERO_VOLUME_RATIO_FOR_PREVIEW:.2f}")
    print(f"- Min shift     : {PHASE5Q_MICRO_MOMENTUM_MIN_CLOSE_SHIFT_PERCENT:.6f}%")
'''

if "Phase 5Q Crypto No-Strategy Preview Classifier:" not in text:
    if phase5p_print_block not in text:
        raise SystemExit("ERROR: Phase5P print block not found.")
    text = text.replace(phase5p_print_block, phase5q_print_block)


# ============================================================
# 2. Fix Phase5I / Phase5J / Phase5K block and add Phase5Q call
# ============================================================
old_decision_block = '''    phase5i_no_strategy_market_state = classify_phase5i_no_strategy_market_state(
    symbol,
    selected_strategy,
    volatility_percent,
    )
    phase5j_market_session_allowed, phase5j_market_session_guard = evaluate_phase5j_market_session_guard(symbol)
    
    phase5k_market_reopen_allowed, phase5k_market_reopen_warmup_guard = evaluate_phase5k_market_reopen_warmup_guard(
    symbol,
    phase5j_market_session_guard,
    )
'''

new_decision_block = '''    phase5i_no_strategy_market_state = classify_phase5i_no_strategy_market_state(
        symbol,
        selected_strategy,
        volatility_percent,
    )

    phase5j_market_session_allowed, phase5j_market_session_guard = evaluate_phase5j_market_session_guard(symbol)

    phase5k_market_reopen_allowed, phase5k_market_reopen_warmup_guard = evaluate_phase5k_market_reopen_warmup_guard(
        symbol,
        phase5j_market_session_guard,
    )

    phase5q_crypto_no_strategy_preview = build_phase5q_crypto_no_strategy_preview_classifier(
        symbol,
        selected_strategy,
        volatility_percent,
        phase5j_market_session_guard,
        phase5k_market_reopen_warmup_guard,
        phase5i_no_strategy_market_state,
    )
'''

if "phase5q_crypto_no_strategy_preview = build_phase5q_crypto_no_strategy_preview_classifier(" not in text:
    if old_decision_block not in text:
        raise SystemExit("ERROR: Phase5I/5J/5K block not found.")
    text = text.replace(old_decision_block, new_decision_block)


# ============================================================
# 3. Add Phase5Q to WAIT payload
# ============================================================
old_wait_payload = '''            "phase5l_market_open_readiness": phase5l_market_open_readiness,
            "phase5p_controlled_score_commit": phase5p_controlled_score_commit,
            "phase5o_crypto_weekend_near_ready": phase5o_crypto_weekend_near_ready,
'''

new_wait_payload = '''            "phase5l_market_open_readiness": phase5l_market_open_readiness,
            "phase5o_crypto_weekend_near_ready": phase5o_crypto_weekend_near_ready,
            "phase5p_controlled_score_commit": phase5p_controlled_score_commit,
            "phase5q_crypto_no_strategy_preview": phase5q_crypto_no_strategy_preview,
'''

if '"phase5q_crypto_no_strategy_preview": phase5q_crypto_no_strategy_preview,' not in text:
    if old_wait_payload not in text:
        raise SystemExit("ERROR: WAIT payload block not found.")
    text = text.replace(old_wait_payload, new_wait_payload)


# ============================================================
# 4. Add Phase5Q to READY payload
# ============================================================
old_ready_payload = '''        "phase5l_market_open_readiness": phase5l_market_open_readiness,
        "phase5o_crypto_weekend_near_ready": phase5o_crypto_weekend_near_ready,
        "phase5p_controlled_score_commit": phase5p_controlled_score_commit,
'''

new_ready_payload = '''        "phase5l_market_open_readiness": phase5l_market_open_readiness,
        "phase5o_crypto_weekend_near_ready": phase5o_crypto_weekend_near_ready,
        "phase5p_controlled_score_commit": phase5p_controlled_score_commit,
        "phase5q_crypto_no_strategy_preview": phase5q_crypto_no_strategy_preview,
'''

if text.count('"phase5q_crypto_no_strategy_preview": phase5q_crypto_no_strategy_preview,') < 2:
    if old_ready_payload not in text:
        raise SystemExit("ERROR: READY payload block not found.")
    text = text.replace(old_ready_payload, new_ready_payload, 1)


# ============================================================
# 5. Add Phase5Q to MT5 order payload
# ============================================================
old_mt5_payload = '''        "phase5l_market_open_readiness": trade_decision.get("phase5l_market_open_readiness", {}),
'''

new_mt5_payload = '''        "phase5l_market_open_readiness": trade_decision.get("phase5l_market_open_readiness", {}),
        "phase5o_crypto_weekend_near_ready": trade_decision.get("phase5o_crypto_weekend_near_ready", {}),
        "phase5p_controlled_score_commit": trade_decision.get("phase5p_controlled_score_commit", {}),
        "phase5q_crypto_no_strategy_preview": trade_decision.get("phase5q_crypto_no_strategy_preview", {}),
'''

if '"phase5q_crypto_no_strategy_preview": trade_decision.get("phase5q_crypto_no_strategy_preview", {}),' not in text:
    if old_mt5_payload not in text:
        raise SystemExit("ERROR: MT5 payload Phase5L block not found.")
    text = text.replace(old_mt5_payload, new_mt5_payload)


# ============================================================
# 6. Add Phase5Q terminal print after Phase5P print
# ============================================================
old_phase5p_terminal = '''    phase5p_controlled_score_commit = item.get("phase5p_controlled_score_commit", {})
    if isinstance(phase5p_controlled_score_commit, dict) and phase5p_controlled_score_commit:
        print(
            f"{indent}Phase5P controlled score commit: "
            f"status={phase5p_controlled_score_commit.get('status', 'UNKNOWN')} | "
            f"original={phase5p_controlled_score_commit.get('original_score', 'n/a')} | "
            f"committed={phase5p_controlled_score_commit.get('committed_score', 'n/a')} | "
            f"boost={phase5p_controlled_score_commit.get('score_boost', 'n/a')} | "
            f"reason={phase5p_controlled_score_commit.get('reason', '')}"
        )
'''

new_phase5p_terminal = '''    phase5p_controlled_score_commit = item.get("phase5p_controlled_score_commit", {})
    if isinstance(phase5p_controlled_score_commit, dict) and phase5p_controlled_score_commit:
        print(
            f"{indent}Phase5P controlled score commit: "
            f"status={phase5p_controlled_score_commit.get('status', 'UNKNOWN')} | "
            f"original={phase5p_controlled_score_commit.get('original_score', 'n/a')} | "
            f"committed={phase5p_controlled_score_commit.get('committed_score', 'n/a')} | "
            f"boost={phase5p_controlled_score_commit.get('score_boost', 'n/a')} | "
            f"reason={phase5p_controlled_score_commit.get('reason', '')}"
        )

    phase5q_crypto_no_strategy_preview = item.get("phase5q_crypto_no_strategy_preview", {})
    if isinstance(phase5q_crypto_no_strategy_preview, dict) and phase5q_crypto_no_strategy_preview:
        print(
            f"{indent}Phase5Q crypto no-strategy preview: "
            f"status={phase5q_crypto_no_strategy_preview.get('status', 'UNKNOWN')} | "
            f"direction={phase5q_crypto_no_strategy_preview.get('direction_preview', 'n/a')} | "
            f"confidence={phase5q_crypto_no_strategy_preview.get('confidence', 'n/a')} | "
            f"shift={phase5q_crypto_no_strategy_preview.get('close_shift_percent', 'n/a')} | "
            f"range_atr={phase5q_crypto_no_strategy_preview.get('range_atr_ratio', 'n/a')} | "
            f"reason={phase5q_crypto_no_strategy_preview.get('reason', '')}"
        )
'''

if "Phase5Q crypto no-strategy preview:" not in text:
    if old_phase5p_terminal not in text:
        raise SystemExit("ERROR: Phase5P terminal print block not found.")
    text = text.replace(old_phase5p_terminal, new_phase5p_terminal)


# ============================================================
# 7. Improve Phase5K crypto weekend passed reason
# ============================================================
old_phase5k_reason = '''    if crypto_weekend_allowed:
        guard["reason"] = (
            f"Market reopen warmup guard passed with BTCUSD crypto weekend relaxation: "
            f"active candles {active_count} >= required {min_active_candles_required}."
        )
'''

new_phase5k_reason = '''    if crypto_weekend_allowed:
        guard["reason"] = (
            f"Market reopen warmup guard passed with BTCUSD crypto weekend relaxation: "
            f"active candles {active_count} >= required {min_active_candles_required}, "
            f"active ratio {active_ratio:.2f} >= required {min_active_ratio_required:.2f}."
        )
'''

if old_phase5k_reason in text:
    text = text.replace(old_phase5k_reason, new_phase5k_reason)


# ============================================================
# 8. Optional: add Phase5Q fields to decision health snapshot
# ============================================================
old_snapshot_assign = '''        phase5g = decision.get("phase5g_pre_score_diagnostics", {})
        phase5h = decision.get("phase5h_strategy_score_explainability", {})
        volatility_debug = decision.get("volatility_debug", {})
'''

new_snapshot_assign = '''        phase5g = decision.get("phase5g_pre_score_diagnostics", {})
        phase5h = decision.get("phase5h_strategy_score_explainability", {})
        phase5o = decision.get("phase5o_crypto_weekend_near_ready", {})
        phase5p = decision.get("phase5p_controlled_score_commit", {})
        phase5q = decision.get("phase5q_crypto_no_strategy_preview", {})
        volatility_debug = decision.get("volatility_debug", {})
'''

if "phase5q = decision.get(\"phase5q_crypto_no_strategy_preview\", {})" not in text:
    if old_snapshot_assign in text:
        text = text.replace(old_snapshot_assign, new_snapshot_assign)


old_strategy_diag = '''                "phase5h_status": phase5h.get("status", "UNKNOWN") if isinstance(phase5h, dict) else "UNKNOWN",
                "score_gap": phase5g.get("score_gap", None) if isinstance(phase5g, dict) else None,
                "missing_components": phase5h.get("missing_components", []) if isinstance(phase5h, dict) else [],
'''

new_strategy_diag = '''                "phase5h_status": phase5h.get("status", "UNKNOWN") if isinstance(phase5h, dict) else "UNKNOWN",
                "phase5o_status": phase5o.get("status", "UNKNOWN") if isinstance(phase5o, dict) else "UNKNOWN",
                "phase5p_status": phase5p.get("status", "UNKNOWN") if isinstance(phase5p, dict) else "UNKNOWN",
                "phase5q_status": phase5q.get("status", "UNKNOWN") if isinstance(phase5q, dict) else "UNKNOWN",
                "near_ready": phase5o.get("status", "") == PHASE5O_NEAR_READY_STATUS if isinstance(phase5o, dict) else False,
                "score_committed": phase5p.get("status", "") == "COMMITTED" if isinstance(phase5p, dict) else False,
                "no_strategy_preview": phase5q.get("status", "") in {
                    PHASE5Q_PREVIEW_STATUS_MICRO_MOMENTUM,
                    PHASE5Q_PREVIEW_STATUS_RANGE_COMPRESSION,
                } if isinstance(phase5q, dict) else False,
                "score_gap": phase5g.get("score_gap", None) if isinstance(phase5g, dict) else None,
                "missing_components": phase5h.get("missing_components", []) if isinstance(phase5h, dict) else [],
'''

if '"phase5q_status": phase5q.get("status", "UNKNOWN")' not in text:
    if old_strategy_diag in text:
        text = text.replace(old_strategy_diag, new_strategy_diag)


FILE_PATH.write_text(text)

print("✅ decision_engine.py patched successfully.")
print("Next commands:")
print("python -m py_compile decision_engine.py")
print("python decision_engine.py")
