#!/usr/bin/env python3
"""auditor/spike_frontload.py - focused single-function spike: does front-loading spec-side test data
(frontload.py) cut WALL TIME and/or lift ACCURACY (gate-GREEN), across four authors?

Authors: m3-nothink, m3-think, m27-fast, deepseek-pro. Conditions: baseline vs front-loaded (doctest
anchors + type-derived edge inputs). Reps per cell give a coverage rate and a wall average on ONE
function - a fast feasibility read, not a corpus statistic. The mutation gate (capped subprocess) is
the sole arbiter; coverage = gate-GREEN = non-vacuity, NOT correctness.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author as author_mod  # noqa: E402
import coverage_exp as ce  # noqa: E402
import frontload as fl  # noqa: E402
from gate_subprocess import _gate_subprocess  # noqa: E402
from run import BudgetTracker  # noqa: E402

MODELS = [
    {"label": "m3_nothink", "model": "minimax-m3",        "thinking": {"type": "disabled"}, "free": True},
    {"label": "m3_think",   "model": "minimax-m3",        "thinking": None,                 "free": True},
    {"label": "m27_fast",   "model": "minimax-m27-fast",  "thinking": None,                 "free": True},
    {"label": "deepseek",   "model": "deepseek-v4-pro",   "thinking": None,                 "free": False},
]
_TEMPS = [0.3, 0.5, 0.7]  # per-rep temperature spread (sampling diversity on one function)


def load_entry(manifest: Path, qualname: str) -> tuple[dict, str]:
    m = json.loads(manifest.read_text())
    f = next(x for x in m["functions"] if x["qualname"] == qualname)
    return f, m.get("target", manifest.parent.name)


async def _cell(entry: dict, target: str, shape: str, mcfg: dict, front: str | None, rep: int,
                run_dir: Path, *, sem: asyncio.Semaphore, gate_sem: asyncio.Semaphore,
                budget: BudgetTracker, max_tokens: int, timeout: int, gate_cap: int) -> dict:
    model = mcfg["model"]
    cond = "frontload" if front else "baseline"
    label = f"{mcfg['label']}_{cond}_r{rep}"
    async with sem:
        reservation = budget.reserve() if not mcfg["free"] else 0.0
        if reservation is None:
            return {"model": mcfg["label"], "cond": cond, "rep": rep, "budget_stopped": True}
        t0 = time.time()
        r = await asyncio.to_thread(
            author_mod._author_independent, entry, model, author_mod._battery_model(model),
            target=target, max_tokens=max_tokens, shape=shape, stream=ce._wants_stream(model),
            temperature=_TEMPS[rep % len(_TEMPS)], thinking=mcfg["thinking"], timeout=timeout,
            front_load=front, trace_meta={"config": label})
    wall = round(time.time() - t0, 1)
    if "error" in r:
        if not mcfg["free"]:
            budget.settle(reservation, 0.0)
        return {"model": mcfg["label"], "cond": cond, "rep": rep, "error": r["error"], "wall": wall}
    if not mcfg["free"]:
        budget.settle(reservation, r["cost"])
    cdir = run_dir / "oracles" / label
    cdir.mkdir(parents=True, exist_ok=True)
    mod = f"orc_{label}"
    (cdir / f"{mod}.py").write_text(r["code"])
    async with gate_sem:
        v = await asyncio.to_thread(_gate_subprocess, mod, str(cdir), gate_cap, entry["qualname"])
    return {"model": mcfg["label"], "cond": cond, "rep": rep,
            "green": bool(v.get("green")), "strict_green": bool(v.get("strict_green")),
            "gate_failed": bool(v.get("gate_failed")), "out_tok": r["out_tok"],
            "cost": r["cost"], "wall": wall}


async def run(entry: dict, target: str, shape: str, run_dir: Path, *, reps: int, concurrency: int,
              max_tokens: int, timeout: int, gate_cap: int, budget_cap: float) -> dict:
    front = fl.frontload_block(entry)
    (run_dir).mkdir(parents=True, exist_ok=True)
    (run_dir / "frontload_block.txt").write_text(front or "(empty)")
    budget = BudgetTracker(budget_cap)
    sem = asyncio.Semaphore(concurrency)
    gate_sem = asyncio.Semaphore(max(2, (os.cpu_count() or 4) - 2))
    cells = [_cell(entry, target, shape, m, f, rep, run_dir, sem=sem, gate_sem=gate_sem, budget=budget,
                   max_tokens=max_tokens, timeout=timeout, gate_cap=gate_cap)
             for m in MODELS for f in (None, front) for rep in range(reps)]
    results = await asyncio.gather(*cells)
    ce._atomic_write_json(run_dir / "cells.json", results)
    return report(results, reps, front)


def report(results: list[dict], reps: int, front: str) -> dict:
    table = {}
    for m in MODELS:
        for cond in ("baseline", "frontload"):
            rows = [r for r in results if r["model"] == m["label"] and r.get("cond") == cond]
            verdicts = [r for r in rows if "green" in r]
            greens = sum(r["green"] for r in verdicts)
            walls = [r["wall"] for r in rows if "wall" in r]
            toks = [r["out_tok"] for r in verdicts]
            table[f"{m['label']}/{cond}"] = {
                "green": f"{greens}/{len(verdicts)}",
                "green_rate": round(greens / len(verdicts), 3) if verdicts else None,
                "mean_wall_s": round(statistics.mean(walls), 1) if walls else None,
                "mean_out_tok": round(statistics.mean(toks)) if toks else None,
                "errors": sum(1 for r in rows if r.get("error")),
                "cost_usd": round(sum(r.get("cost", 0.0) for r in rows), 4)}
    # front-load deltas per model (frontload - baseline)
    deltas = {}
    for m in MODELS:
        b, f = table[f"{m['label']}/baseline"], table[f"{m['label']}/frontload"]
        if b["mean_out_tok"] is not None and f["mean_out_tok"] is not None:
            deltas[m["label"]] = {
                "d_green_rate": round((f["green_rate"] or 0) - (b["green_rate"] or 0), 3),
                "d_mean_out_tok": f["mean_out_tok"] - b["mean_out_tok"],
                "d_mean_wall_s": round((f["mean_wall_s"] or 0) - (b["mean_wall_s"] or 0), 1)}
    return {"reps": reps, "frontload_chars": len(front), "table": table, "frontload_delta": deltas}


def main() -> int:
    ap = argparse.ArgumentParser(description="single-function front-load spike (4 authors)")
    ap.add_argument("--manifest", type=Path, default=Path("targets/packaging/manifest.json"))
    ap.add_argument("--qualname", default="canonicalize_name")
    ap.add_argument("--shape", default="value")
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--max-tokens", type=int, default=16000)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--gate-cap", type=int, default=40)
    ap.add_argument("--budget-cap", type=float, default=3.0)
    ap.add_argument("--report-only", action="store_true")
    args = ap.parse_args()
    if args.report_only:
        results = json.loads((args.run_dir / "cells.json").read_text())
        front = (args.run_dir / "frontload_block.txt").read_text()
        print(json.dumps(report(results, args.reps, front), indent=2))
        return 0
    entry, target = load_entry(args.manifest, args.qualname)
    print(f"[spike] {target}:{args.qualname} shape={args.shape} reps={args.reps} "
          f"models={[m['label'] for m in MODELS]}", flush=True)
    summary = asyncio.run(run(entry, target, args.shape, args.run_dir, reps=args.reps,
                              concurrency=args.concurrency, max_tokens=args.max_tokens,
                              timeout=args.timeout, gate_cap=args.gate_cap, budget_cap=args.budget_cap))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
