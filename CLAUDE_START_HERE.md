# CLAUDE START HERE - AI_SCALPER

Baca file ini dulu sebelum mengubah apa pun.

## Bahasa & gaya
Gunakan bahasa Indonesia. Jawaban harus tegas, ringkas, langsung aksi.

## Project path
/Users/muhammadirvan/Documents/AI_SCALPER

## Aturan wajib
- Jangan buka live trading.
- Jangan set live_allowed=True.
- Jangan naikkan max_lot di atas 0.01.
- Jangan aktifkan demo auto-order tanpa rencana manual terpisah.
- Jangan promote GBPUSD.
- Jangan promote BTCUSD dari shadow ke execution tanpa review.
- Jangan kirim soft observation ke MT5 outbox.
- Jangan count soft observation sebagai clean execution sample.
- Jangan patch kalau user hanya minta cek/lanjut/loop.

## Status terakhir
- Mode: DEMO_OBSERVATION_ONLY_READY
- Quality: NOT_READY
- Action: STOP_AND_REVIEW_PHASE_4
- Winrate: 36.54%
- Profit factor: 1.3758
- Clean samples: 0
- Soft observation active: EURUSD MOMENTUM_PULLBACK score 4.0
- safe_to_demo_observe=True
- safe_to_demo_auto_order=False
- live_allowed=False
- max_lot=0.01
- Exec approved: EURUSD
- Exec blocked: GBPUSD
- Shadow: BTCUSD

## Current focus
FULL + SOFT OBSERVATION LOOP M15.

## Current loop
python data_collector.py --mode full
python decision_engine.py
python phase4_soft_observation_gate.py
python paper_forward_runner.py
python forward_test_dashboard.py
python demo_readiness_evaluator.py
sleep 900

## Yang boleh dilakukan sekarang
- Review logic.
- Cari bug yang membuat market freshness terlalu ketat.
- Review soft observation.
- Bantu buat diagnostic aman.
- Bantu refactor tanpa mengubah safety lock.

## Yang tidak boleh dilakukan
- Mengaktifkan auto-order.
- Membuka live.
- Mengubah max lot.
- Menghapus Phase4R lock.
- Membuat soft sample menjadi order.

## Format patch wajib
Kalau memberi patch, gunakan format:

PROPOSED CHANGE
Problem:
Files touched:
Patch summary:
Safety impact:
Test command:
Rollback command:

## Required skills/checklist for every patch/improvement/fix

For every patch, improvement, bug fix, refactor, or diff review, use these skills/checklists:

- code-reviewer
- pr-review-expert
- senior-backend
- senior-architect
- focused-fix
- ship-gate
- adversarial-reviewer
- ai-security
- financial-analyst
- tech-debt-tracker
- runbook-generator

Every proposed change must include:
- Problem
- Root cause
- Files touched
- Patch summary
- Safety impact
- Trading/financial risk impact
- Test command
- Rollback command
- Ship / No-Ship decision

Hard safety rules:
- Do not set live_allowed=True.
- Do not raise max_lot above 0.01.
- Do not enable demo auto-order.
- Do not create MT5 orders.
- Do not send soft observation to outbox.
- Do not promote GBPUSD.
- Do not promote BTCUSD from shadow.
- Do not unlock Phase4R without manual review.
